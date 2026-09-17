//! GPU collision-search backends (CUDA on NVIDIA, Metal on Apple).
//!
//! The GPU replaces the CPU's `HashBatch` hot loop wholesale: one kernel thread per
//! candidate index generates the serial, hashes it, and compares it against every
//! target on-device (fixed-mix and full-mbr_val-sweep modes both), so the PCIe/Unified
//! Memory link only ever carries a handful of hit records. Every reported hit is then
//! re-hashed and re-verified by the CPU scalar path, preserving the search's
//! trust-but-verify contract.
//!
//! Both backends compile the generated kernel source at runtime (NVRTC /
//! `newLibraryWithSource`), so no GPU SDK is needed to build. By default (feature
//! `gpu-auto`) `build.rs` compiles the CUDA backend when a local CUDA toolkit is
//! detected and the Metal backend on macOS; `--features cuda`/`--features metal`
//! force them explicitly, and `--no-default-features` builds CPU-only.

mod kernel_source;

// CUDA: forced by feature "cuda", or auto-enabled by the default "gpu-auto" feature
// when build.rs detected a local CUDA toolkit (cfg gpu_cuda_toolchain).
#[cfg(any(feature = "cuda", all(feature = "gpu-auto", gpu_cuda_toolchain)))]
pub(crate) mod cuda;
// Metal: the toolchain ships with every macOS SDK, so macOS targets compile the
// backend under gpu-auto (default) or an explicit "metal".
#[cfg(all(target_os = "macos", any(feature = "metal", feature = "gpu-auto")))]
pub(crate) mod metal;

/// One collision candidate reported by a GPU kernel. Values are advisory only — the
/// CPU search driver independently re-hashes the index before accepting a hit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GpuHit {
    /// u64 candidate index, same counter the CPU search walks.
    pub index: u64,
    /// First reversed digest word, as `sha256::hash_40` returns it.
    pub sid_lo: u32,
    /// High digest byte, as `sha256::hash_40` returns it.
    pub sid_hi: u8,
    /// Index into the run's target list that matched.
    pub target_idx: u32,
}

/// Per-run constants baked into the generated kernel source. Must describe exactly
/// the serial construction and match mode of the search that will use the kernel.
#[derive(Clone)]
pub(crate) struct GpuKernelSpec {
    /// Candidate alphabet (`search --alphabet`); `alphabet.len()` is the counting base.
    pub alphabet: Vec<u8>,
    /// `true` for `--pad end` (space-padding) candidates, `false` for `--pad start`.
    pub pad_end: bool,
    /// `true` for full-mbr_val-sweep matching, `false` for fixed-mix matching.
    pub sweep: bool,
    /// Big-endian SHA-256 words of the shared model+sector_val suffix (W[5..9]).
    pub w5_9: [u32; 5],
    /// Target-array capacity of the params struct (the run's real target count).
    pub capacity: usize,
}

/// One kernel launch: a `[base, base+n)` candidate-index range (wrapping) plus the
/// target list to compare against. Fewer targets than the spec's capacity is fine
/// (self-check passes probe-sized lists); more is a caller bug and truncates.
#[derive(Clone)]
pub(crate) struct GpuRun {
    pub base: u64,
    pub n: u64,
    /// `(lo, hi)` pairs — fixed mode: `(need_lo, need_hi)`; sweep mode: `(tv_lo, tv_hi)`.
    pub targets: Vec<(u32, u32)>,
}

/// A compiled device ready to execute runs of one kernel spec.
pub(crate) trait GpuDevice: Send {
    /// Human-readable device identification for banners and diagnostics.
    fn name(&self) -> String;
    /// Launch the kernel for `run` (blocking) and return the reported hits.
    fn run(&mut self, run: &GpuRun) -> Result<Vec<GpuHit>, String>;
}

/// Self-check contract: run every `(base, n)` range against `targets` and require the
/// union of reported hits to equal `expect` exactly. `expect` is derived on the CPU
/// from `sha256::hash_40` over probe serials built with the same spec parameters, so
/// agreement proves the whole on-device pipeline (serial generation, padding, hash,
/// match logic) against the scalar reference.
pub(crate) struct GpuSelfCheck {
    pub runs: Vec<(u64, u64)>,
    pub targets: Vec<(u32, u32)>,
    pub expect: Vec<GpuHit>,
}

/// Size in bytes of one serialized hit record (mirrors `HitRecord` in the kernel).
const HIT_RECORD_LEN: usize = 24;

/// Serialize a run into the kernel's little-endian `Params` image:
/// `u64 base, u64 n, u32 num_targets, u32 tv_lo[cap], u32 tv_hi[cap], u32 bitmap[16]`.
///
/// The bitmap is the exact necessary-condition prefilter for the baked match mode, so
/// candidates that cannot possibly match any target cost one indexed load:
/// - fixed: bit `need_hi` (values outside 256..512 can never equal `(sid_hi|0x100)`);
/// - sweep: bit `sid_hi` set iff some target has `tv_hi` in [256,512) and
///   `((sid_hi ^ tv_hi) & 0xFF) < 32` — precisely `required_hi < 32`, which any
///   feasible `mix_hi` (max `0x7FF * 0x3FF800F >> 32` = 31) must satisfy.
pub(crate) fn pack_run_params(spec: &GpuKernelSpec, run: &GpuRun) -> Vec<u8> {
    let cap = spec.capacity;
    let active = run.targets.len().min(cap);
    let mut words: Vec<u32> = Vec::with_capacity(9 + 2 * cap + 16);
    words.push(run.base as u32);
    words.push((run.base >> 32) as u32);
    words.push(run.n as u32);
    words.push((run.n >> 32) as u32);
    words.push(active as u32);
    let mut lo = vec![0u32; cap];
    let mut hi = vec![0u32; cap];
    for (i, &(l, h)) in run.targets.iter().take(cap).enumerate() {
        lo[i] = l;
        hi[i] = h;
    }
    let mut bitmap = [0u32; 16];
    if spec.sweep {
        for s in 0u32..256 {
            let feasible = run
                .targets
                .iter()
                .any(|&(_, tv_hi)| (256..512).contains(&tv_hi) && ((s ^ tv_hi) & 0xFF) < 32);
            if feasible {
                bitmap[(s >> 5) as usize] |= 1u32 << (s & 31);
            }
        }
    } else {
        for &(_, need_hi) in run.targets.iter() {
            if (256..512).contains(&need_hi) {
                bitmap[(need_hi >> 5) as usize] |= 1u32 << (need_hi & 31);
            }
        }
    }
    words.extend_from_slice(&lo);
    words.extend_from_slice(&hi);
    words.extend_from_slice(&bitmap);
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// Decode `count` hit records from a little-endian record buffer.
pub(crate) fn decode_hits(bytes: &[u8], count: usize) -> Vec<GpuHit> {
    let take = count.min(kernel_source::MAX_HITS);
    (0..take)
        .filter_map(|i| {
            let rec = bytes.get(i * HIT_RECORD_LEN..(i + 1) * HIT_RECORD_LEN)?;
            let index = u64::from_le_bytes(rec[0..8].try_into().ok()?);
            let sid_lo = u32::from_le_bytes(rec[8..12].try_into().ok()?);
            let sid_hi = rec[12];
            let target_idx = u32::from_le_bytes(rec[16..20].try_into().ok()?);
            Some(GpuHit {
                index,
                sid_lo,
                sid_hi,
                target_idx,
            })
        })
        .collect()
}

/// Execute a self-check against a device: all runs share one target list, and the
/// combined hits must equal `expect` exactly (set comparison keyed by
/// index/target_idx — duplicate reports of the same hit are a mismatch).
pub(crate) fn self_check(dev: &mut dyn GpuDevice, check: &GpuSelfCheck) -> Result<(), String> {
    let mut got: Vec<GpuHit> = Vec::new();
    for &(base, n) in &check.runs {
        got.extend(
            dev.run(&GpuRun {
                base,
                n,
                targets: check.targets.clone(),
            })
            .map_err(|e| format!("self-check kernel run failed: {e}"))?,
        );
    }
    let key = |h: &GpuHit| (h.index, h.target_idx);
    let mut expect = check.expect.clone();
    got.sort_by_key(key);
    expect.sort_by_key(key);
    if got == expect {
        Ok(())
    } else {
        Err(format!(
            "GPU digests disagree with the scalar reference (expected {} hit(s), got {}) — \
             refusing to search with this device",
            expect.len(),
            got.len()
        ))
    }
}

/// Compile the kernel for every usable GPU in the system, warning (not failing) about
/// individual devices that are present but unusable. Returns the ready devices.
#[cfg_attr(
    not(any(
        feature = "cuda",
        all(feature = "gpu-auto", gpu_cuda_toolchain),
        all(target_os = "macos", any(feature = "metal", feature = "gpu-auto")),
    )),
    allow(unused_mut)
)]
pub(crate) fn compile_devices(spec: &GpuKernelSpec) -> Vec<Box<dyn GpuDevice>> {
    let mut devices: Vec<Box<dyn GpuDevice>> = Vec::new();
    #[cfg(any(feature = "cuda", all(feature = "gpu-auto", gpu_cuda_toolchain)))]
    for result in cuda::enumerate(spec) {
        match result {
            Ok(dev) => devices.push(dev),
            Err((name, error)) => eprintln!("Warning: CUDA device {name} unusable: {error}"),
        }
    }
    #[cfg(all(target_os = "macos", any(feature = "metal", feature = "gpu-auto")))]
    for result in metal::enumerate(spec) {
        match result {
            Ok(dev) => devices.push(dev),
            Err((name, error)) => eprintln!("Warning: Metal device {name} unusable: {error}"),
        }
    }
    let _ = spec; // (unused when no backend is compiled in)
    devices
}

/// Measure a device's throughput (hashes/second) with back-to-back chunks of `run`'s
/// size until at least ~200ms have elapsed, so CPU-vs-GPU auto selection races real
/// measured rates instead of hardware assumptions (an Apple M4's ARM-SHA2 CPU beats
/// its own GPU; an NVIDIA dGPU wins by an order of magnitude). Any hits found during
/// sampling are returned so the caller can run the normal verify-and-report path —
/// a real collision must never be silently dropped just because it landed in the
/// measurement window.
pub(crate) fn sample_rate(dev: &mut dyn GpuDevice, run: &GpuRun) -> (f64, Vec<GpuHit>) {
    let mut probed = run.clone();
    let start = std::time::Instant::now();
    let mut hashed = 0u64;
    let mut chunks = 0u64;
    let mut hits = Vec::new();
    while start.elapsed().as_millis() < 200 || chunks < 2 {
        probed.base = run.base.wrapping_add(chunks.saturating_mul(run.n));
        match dev.run(&probed) {
            Ok(found) => {
                hashed += run.n;
                hits.extend(found);
            }
            Err(_) => return (0.0, hits),
        }
        chunks += 1;
    }
    (hashed as f64 / start.elapsed().as_secs_f64(), hits)
}

/// Whether this binary contains any GPU backend at all (for `--device` diagnostics).
pub(crate) fn backend_compiled_in() -> bool {
    cfg!(any(
        feature = "cuda",
        all(feature = "gpu-auto", gpu_cuda_toolchain),
        all(
            target_os = "macos",
            any(feature = "metal", feature = "gpu-auto")
        ),
    ))
}
