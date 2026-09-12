//! One-time CPU dispatch and backend-owned batches for fixed 40-byte SHA-256.

use std::hint::black_box;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Available calculation strategies; unsupported strategies are never executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum HashBackend {
    /// Portable reference implementation.
    Scalar,
    /// Intel/AMD SHA extensions, interleaving independent messages.
    ShaNi,
    /// Eight independent messages in AVX2 vectors.
    Avx2,
    /// Sixteen independent messages in AVX-512 vectors.
    Avx512,
    /// AArch64 SHA2 extensions, interleaving independent messages.
    ArmSha2,
    /// Four independent messages in NEON vectors.
    Neon,
}

impl std::fmt::Display for HashBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Scalar => "scalar",
            Self::ShaNi => "sha-ni",
            Self::Avx2 => "avx2",
            Self::Avx512 => "avx512",
            Self::ArmSha2 => "arm-sha2",
            Self::Neon => "neon",
        })
    }
}

type Kernel = unsafe fn(&[[u8; 40]], &[u32; 5], &mut [(u32, u8)]);

/// A validated CPU capability and fixed kernel pointer, copied into worker threads.
#[derive(Clone, Copy, Debug)]
pub struct HashEngine {
    backend: HashBackend,
    batch_size: usize,
    kernel: Kernel,
}

impl std::fmt::Display for HashEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} x{}", self.backend, self.batch_size)
    }
}

impl HashEngine {
    /// Detect supported kernels, including x1/x2/x4 hardware-SHA variants.
    ///
    /// Call during initialization, never inside a hashing loop. The x86 detection
    /// macros include operating-system vector-state support for AVX backends.
    pub fn supported() -> Vec<Self> {
        let mut engines = vec![Self {
            backend: HashBackend::Scalar,
            batch_size: 1,
            kernel: scalar,
        }];
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("sha")
                && std::is_x86_feature_detected!("ssse3")
                && std::is_x86_feature_detected!("sse4.1")
            {
                for (batch_size, kernel) in [
                    (1, crate::sha256_shani::hash_batch::<1> as Kernel),
                    (2, crate::sha256_shani::hash_batch::<2> as Kernel),
                    (4, crate::sha256_shani::hash_batch::<4> as Kernel),
                ] {
                    engines.push(Self {
                        backend: HashBackend::ShaNi,
                        batch_size,
                        kernel,
                    });
                }
            }
            if std::is_x86_feature_detected!("avx2") {
                engines.push(Self {
                    backend: HashBackend::Avx2,
                    batch_size: 8,
                    kernel: crate::sha256_avx2::hash_batch,
                });
            }
            if crate::sha256_simd::is_avx512_supported() {
                engines.push(Self {
                    backend: HashBackend::Avx512,
                    batch_size: 16,
                    kernel: avx512,
                });
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            if crate::sha256_cpu::arm_sha2_supported() {
                for (batch_size, kernel) in [
                    (1, crate::sha256_arm::hash_batch::<1> as Kernel),
                    (2, crate::sha256_arm::hash_batch::<2> as Kernel),
                    (4, crate::sha256_arm::hash_batch::<4> as Kernel),
                ] {
                    engines.push(Self {
                        backend: HashBackend::ArmSha2,
                        batch_size,
                        kernel,
                    });
                }
            }
            if std::arch::is_aarch64_feature_detected!("neon") {
                engines.push(Self {
                    backend: HashBackend::Neon,
                    batch_size: 4,
                    kernel: crate::sha256_neon::hash_batch,
                });
            }
        }
        engines
    }

    /// Select once per process by the median of three short throughput samples.
    ///
    /// Hardware SHA is evaluated before vector emulation, but neither SIMD width
    /// nor instruction-set names determine the winner. The returned kernel is
    /// fixed for the lifetime of the search; CPU detection and timing stay cold.
    pub fn auto() -> Result<Self, &'static str> {
        Self::auto_for_threads(std::thread::available_parallelism().map_or(1, usize::from))
    }

    /// Calibrate once using the requested worker count, including mixed-core CPUs.
    ///
    /// The first call fixes the process-wide engine; subsequent calls reuse it.
    /// Measure concurrency as well as instruction throughput: the best hardware
    /// SHA buffer count can differ between one core and an SMT/mixed-core load.
    pub fn auto_for_threads(threads: usize) -> Result<Self, &'static str> {
        if threads == 0 {
            return Err("SHA-256 worker count must be positive");
        }
        static SELECTED: OnceLock<Result<HashEngine, &'static str>> = OnceLock::new();
        *SELECTED.get_or_init(|| {
            let engines = Self::supported();
            for engine in &engines {
                engine.self_check()?;
                sample_rate(*engine, threads, Duration::from_millis(10))?;
            }
            let mut scores = vec![[0.0_f64; 3]; engines.len()];
            for sample in [0, 1, 2] {
                for offset in 0..engines.len() {
                    let i = (offset + sample) % engines.len();
                    scores[i][sample] =
                        sample_rate(engines[i], threads, Duration::from_millis(30))?;
                }
            }
            let mut best = 0;
            let mut best_rate = 0.0;
            for (i, values) in scores.iter_mut().enumerate() {
                values.sort_by(f64::total_cmp);
                if values[1] > best_rate {
                    best_rate = values[1];
                    best = i;
                }
            }
            Ok(engines[best])
        })
    }

    /// Return the selected instruction strategy without CPU detection.
    pub fn backend(self) -> HashBackend {
        self.backend
    }

    /// Return the number of independent messages computed by one kernel call.
    pub fn batch_size(self) -> usize {
        self.batch_size
    }

    /// Measure this engine's combined rate over `threads` workers (hashes/second),
    /// reusing the calibration harness. Used by the search's device auto-selection
    /// to race CPU against GPU throughput on the actual machine.
    pub fn sample_rate_hz(self, threads: usize) -> Result<f64, &'static str> {
        sample_rate(self, threads, Duration::from_millis(60))
    }

    /// Compare every lane against scalar using a known vector and varied bytes.
    pub fn self_check(self) -> Result<(), &'static str> {
        for pattern in [0, 1, 0x7f, 0x80, 0xff] {
            let model = if pattern == 0 {
                *b"VMware Virtual I"
            } else {
                [pattern; 16]
            };
            let sv = if pattern == 0 {
                0x1800u32.to_le_bytes()
            } else {
                [pattern; 4]
            };
            let mut batch = HashBatch::new(self, &model, &sv);
            for lane in 0..self.batch_size {
                if pattern == 0 {
                    batch
                        .serial_mut(lane)
                        .copy_from_slice(b"00000000000000000001");
                } else {
                    for (i, byte) in batch.serial_mut(lane).iter_mut().enumerate() {
                        *byte = pattern.wrapping_add((lane * 23 + i * 7) as u8);
                    }
                }
            }
            batch.hash();
            for (input, output) in batch.inputs.iter().zip(batch.outputs()) {
                if *output != crate::sha256::hash_40(input) {
                    return Err("SHA-256 backend disagrees with scalar");
                }
                if pattern == 0 && *output != (0x0B49EC2E, 0x35) {
                    return Err("SHA-256 known-vector self-check failed");
                }
            }
        }
        Ok(())
    }
}

/// Prepared inputs, immutable shared suffix, and reusable output storage.
///
/// Only serial bytes are mutable, so all backends have the same suffix contract
/// and safe callers cannot invalidate the precomputed W[5..9] values. Allocation
/// happens at construction; `hash` neither allocates nor detects CPU features.
pub struct HashBatch {
    engine: HashEngine,
    inputs: Vec<[u8; 40]>,
    constant_words: [u32; 5],
    outputs: Vec<(u32, u8)>,
}

impl HashBatch {
    /// Prepare a batch with one shared model and sector-value suffix.
    pub fn new(engine: HashEngine, model: &[u8; 16], sector_value: &[u8; 4]) -> Self {
        let mut input = [b'0'; 40];
        input[20..36].copy_from_slice(model);
        input[36..40].copy_from_slice(sector_value);
        Self {
            engine,
            inputs: vec![input; engine.batch_size],
            constant_words: precompute_constant_words(model, sector_value),
            outputs: vec![(0, 0); engine.batch_size],
        }
    }

    /// Number of active messages, determined by the selected backend.
    pub fn len(&self) -> usize {
        self.engine.batch_size
    }

    /// Batches are never empty.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Mutate the 20-byte serial field of one lane; panics for an invalid lane.
    #[inline]
    pub fn serial_mut(&mut self, lane: usize) -> &mut [u8; 20] {
        (&mut self.inputs[lane][..20]).try_into().unwrap()
    }

    /// Hash all active inputs using the previously validated kernel pointer.
    #[inline]
    pub fn hash(&mut self) {
        // Engine construction validates CPU support; this owner fixes both slice
        // lengths and keeps the suffix in sync with its precomputed words.
        unsafe { (self.engine.kernel)(&self.inputs, &self.constant_words, &mut self.outputs) }
    }

    /// Read `(sid_lo, sid_hi)` for each active lane after `hash`.
    #[inline]
    pub fn outputs(&self) -> &[(u32, u8)] {
        &self.outputs
    }
}

/// Precompute the SHA-256 big-endian words for a shared model/sector-value suffix.
pub fn precompute_constant_words(model: &[u8; 16], sector_value: &[u8; 4]) -> [u32; 5] {
    let mut words = [0; 5];
    for (word, bytes) in words[..4].iter_mut().zip(model.as_chunks::<4>().0) {
        // Input bytes are consumed big-endian by SHA-256, even though the sector
        // value itself was serialized little-endian by RouterOS.
        *word = u32::from_be_bytes(*bytes);
    }
    words[4] = u32::from_be_bytes(*sector_value);
    words
}

unsafe fn scalar(inputs: &[[u8; 40]], _: &[u32; 5], outputs: &mut [(u32, u8)]) {
    outputs[0] = crate::sha256::hash_40(&inputs[0]);
}

#[cfg(target_arch = "x86_64")]
unsafe fn avx512(inputs: &[[u8; 40]], words: &[u32; 5], outputs: &mut [(u32, u8)]) {
    let result = crate::sha256_simd::hash_40_x16(inputs.try_into().unwrap(), words);
    for ((output, sid_lo), sid_hi) in outputs.iter_mut().zip(result.sid_lo).zip(result.sid_hi) {
        *output = (sid_lo, sid_hi);
    }
}

fn sample_rate(
    engine: HashEngine,
    threads: usize,
    duration: Duration,
) -> Result<f64, &'static str> {
    use std::sync::{mpsc, Condvar, Mutex};
    let (ready_tx, ready_rx) = mpsc::channel();
    let gate = (Mutex::new((false, None::<Instant>)), Condvar::new());
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..threads {
            let ready = ready_tx.clone();
            let gate = &gate;
            match std::thread::Builder::new().spawn_scoped(scope, move || {
                let mut batch =
                    HashBatch::new(engine, b"VMware Virtual I", &0x1800u32.to_le_bytes());
                let (lock, wake) = gate;
                let _ = ready.send(());
                drop(ready);
                let state = wake
                    .wait_while(lock.lock().unwrap(), |state| !state.0)
                    .unwrap();
                let start = state.1;
                drop(state);
                let Some(start) = start else {
                    return (0, 0.0);
                };
                let mut calls = 0_u64;
                loop {
                    for _ in 0..256 {
                        batch.serial_mut(0)[19] = calls as u8;
                        black_box(&mut batch).hash();
                        black_box(batch.outputs());
                        calls += 1;
                    }
                    if start.elapsed() >= duration {
                        break;
                    }
                }
                (
                    calls * engine.batch_size as u64,
                    start.elapsed().as_secs_f64(),
                )
            }) {
                Ok(handle) => handles.push(handle),
                Err(_) => {
                    // Release already-created workers before scope joins them.
                    *gate.0.lock().unwrap() = (true, None);
                    gate.1.notify_all();
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err("cannot create SHA-256 calibration workers");
                }
            }
        }
        drop(ready_tx);
        for _ in 0..threads {
            if ready_rx.recv().is_err() {
                *gate.0.lock().unwrap() = (true, None);
                gate.1.notify_all();
                for handle in handles {
                    let _ = handle.join();
                }
                return Err("SHA-256 calibration worker did not initialize");
            }
        }
        *gate.0.lock().unwrap() = (true, Some(Instant::now()));
        gate.1.notify_all();
        let mut count = 0_u64;
        let mut elapsed = 0.0_f64;
        let mut failed = false;
        for handle in handles {
            match handle.join() {
                Ok((hashes, seconds)) => {
                    count += hashes;
                    elapsed = elapsed.max(seconds);
                }
                Err(_) => failed = true,
            }
        }
        if failed {
            Err("SHA-256 calibration worker panicked")
        } else {
            Ok(count as f64 / elapsed)
        }
    })
}
