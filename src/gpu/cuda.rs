//! CUDA backend (NVIDIA GPUs), built on `cudarc` with runtime NVRTC compilation.
//!
//! The CUDA toolkit is needed only at runtime: `cudarc` dynamic-loads the driver
//! (`nvcuda`) and NVRTC libraries, and the kernel is compiled to PTX for the exact
//! compute capability of each device when the search starts. A machine with a driver
//! but no toolkit reports the missing library and the search falls back to CPU.

use cudarc::driver::safe::{
    CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg,
};
use cudarc::nvrtc::safe::{compile_ptx_with_opts, CompileOptions};
use std::sync::Arc;

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
pub(crate) fn enumerate(spec: &GpuKernelSpec) -> Vec<Result<Box<dyn GpuDevice>, (String, String)>> {
    let count = match CudaContext::device_count() {
        Ok(n) if n > 0 => n as usize,
        Ok(_) => return Vec::new(),
        Err(e) => return vec![Err(("driver".to_string(), e.to_string()))],
    };
    (0..count)
        .map(|ordinal| build(spec, ordinal).map_err(|e| (format!("cuda[{ordinal}]"), e)))
        .collect()
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
