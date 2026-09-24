//! CUDA backend (NVIDIA GPUs), built on `cudarc` with runtime NVRTC compilation.
//!
//! `cudarc` lazy-loads the driver (`nvcuda`) and NVRTC shared libraries and
//! **panics** when they can't be found — including when the installed toolkit's
//! NVRTC library name doesn't match the cudarc build's version-specific search
//! list, or the toolkit's `bin` directory isn't on `PATH`. Every entry point that
//! can trigger a lazy load therefore runs under `catch_unwind` and surfaces the
//! failure as a per-device `Err` (warning + CPU fallback) instead of a crash.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use cudarc::driver::safe::{
    CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg,
};
use cudarc::nvrtc::safe::{compile_ptx_with_opts, CompileOptions};

use super::kernel_source::{self, Flavor};
use super::{decode_hits, pack_run_params, GpuDevice, GpuHit, GpuKernelSpec, GpuRun};

/// One initialized CUDA device: compiled kernel plus persistent device buffers.
pub(crate) struct CudaGpu {
    stream: Arc<CudaStream>,
    func: CudaFunction,
    params: CudaSlice<u8>,
    hits: CudaSlice<u8>,
    count: CudaSlice<u32>,
    spec: GpuKernelSpec,
    name: String,
}

/// One `Result` per CUDA device present; `Err` carries the device tag and reason.
/// Panics from cudarc's lazy library loading are caught and reported as errors.
pub(crate) fn enumerate(spec: &GpuKernelSpec) -> Vec<Result<Box<dyn GpuDevice>, (String, String)>> {
    let count = match catch_unwind(CudaContext::device_count) {
        Ok(Ok(n)) if n > 0 => n as usize,
        Ok(Ok(_)) => return Vec::new(),
        Ok(Err(e)) => return vec![Err(("driver".to_string(), e.to_string()))],
        Err(panic) => {
            return vec![Err((
                "driver".to_string(),
                format!("CUDA driver library unavailable: {}", panic_text(panic)),
            ))]
        }
    };
    (0..count)
        .map(|ordinal| {
            catch_unwind(AssertUnwindSafe(|| build(spec, ordinal)))
                .unwrap_or_else(|panic| {
                    Err(format!("initialization panicked: {}", panic_text(panic)))
                })
                .map_err(|e| (format!("cuda[{ordinal}]"), e))
        })
        .collect()
}

/// Extract a human-readable message from a caught panic payload.
fn panic_text(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = panic.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = panic.downcast_ref::<String>() {
        text.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Initialize device `ordinal` and compile the kernel for it.
fn build(spec: &GpuKernelSpec, ordinal: usize) -> Result<Box<dyn GpuDevice>, String> {
    let ctx = CudaContext::new(ordinal).map_err(|e| format!("context init: {e}"))?;
    let product = ctx
        .name()
        .unwrap_or_else(|_| format!("CUDA device {ordinal}"));
    let (major, minor) = ctx
        .compute_capability()
        .map_err(|e| format!("compute capability query: {e}"))?;
    // CompileOptions wants a 'static arch string; one small leak per device at startup.
    let arch: &'static str = Box::leak(format!("compute_{major}{minor}").into_boxed_str());
    let source = kernel_source::kernel_source(spec, Flavor::Cuda);
    let ptx = compile_ptx_with_opts(
        &source,
        CompileOptions {
            arch: Some(arch),
            ..Default::default()
        },
    )
    .map_err(|e| format!("NVRTC compile: {e}"))?;
    let module = ctx
        .load_module(ptx)
        .map_err(|e| format!("module load: {e}"))?;
    let func = module
        .load_function("mtsc_search")
        .map_err(|e| format!("kernel lookup: {e}"))?;
    let stream = ctx.default_stream();
    let params = stream
        .alloc_zeros::<u8>(params_len(spec))
        .map_err(|e| format!("params alloc: {e}"))?;
    let hits = stream
        .alloc_zeros::<u8>(kernel_source::MAX_HITS * 24)
        .map_err(|e| format!("hit buffer alloc: {e}"))?;
    let count = stream
        .alloc_zeros::<u32>(1)
        .map_err(|e| format!("counter alloc: {e}"))?;
    Ok(Box::new(CudaGpu {
        stream,
        func,
        params,
        hits,
        count,
        spec: spec.clone(),
        name: format!("cuda[{ordinal}] {product}"),
    }))
}

/// Serialized `Params` size for a kernel compiled with this capacity.
fn params_len(spec: &GpuKernelSpec) -> usize {
    // u64 base + u64 n + u32 num_targets + 2×u32[capacity] + u32[16] bitmap.
    20 + 8 * spec.capacity + 64
}

impl GpuDevice for CudaGpu {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn run(&mut self, run: &GpuRun) -> Result<Vec<GpuHit>, String> {
        let bytes = pack_run_params(&self.spec, run);
        if bytes.len() > self.params.len() {
            return Err("target list exceeds compiled kernel capacity".to_string());
        }
        self.stream
            .memcpy_htod(&bytes, &mut self.params)
            .map_err(|e| format!("params upload: {e}"))?;
        self.stream
            .memcpy_htod(&[0u32], &mut self.count)
            .map_err(|e| format!("counter reset: {e}"))?;
        // One thread per RUN consecutive candidates (see kernel_source::RUN).
        let threads = u32::try_from(run.n.div_ceil(kernel_source::RUN))
            .map_err(|_| "chunk too large for one launch".to_string())?;
        unsafe {
            self.stream
                .launch_builder(&self.func)
                .arg(&self.params)
                .arg(&mut self.hits)
                .arg(&mut self.count)
                .launch(LaunchConfig::for_num_elems(threads))
        }
        .map_err(|e| format!("kernel launch: {e}"))?;
        self.stream
            .synchronize()
            .map_err(|e| format!("kernel sync: {e}"))?;
        let count = self
            .stream
            .clone_dtoh(&self.count)
            .map_err(|e| format!("counter readback: {e}"))?;
        let reported = count.first().copied().unwrap_or(0) as usize;
        if reported == 0 {
            return Ok(Vec::new());
        }
        if reported > kernel_source::MAX_HITS {
            eprintln!(
                "Warning: GPU chunk reported {} hits; only the first {} were recorded",
                reported,
                kernel_source::MAX_HITS
            );
        }
        let records = self
            .stream
            .clone_dtoh(&self.hits)
            .map_err(|e| format!("hit readback: {e}"))?;
        Ok(decode_hits(&records, reported))
    }
}
