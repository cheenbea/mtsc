//! Metal backend (Apple GPUs), built on `objc2-metal` with runtime shader compilation.
//!
//! Uses the system default Metal device (the discrete GPU on dual-GPU Macs, the
//! integrated GPU otherwise) and shared-storage buffers, so params upload and hit
//! readback are plain memory writes around each command buffer.

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_foundation::NSString;
use objc2_metal::{
    MTLBuffer, MTLCommandBuffer, MTLCommandEncoder, MTLCommandQueue, MTLCompileOptions,
    MTLComputeCommandEncoder, MTLComputePipelineState, MTLCreateSystemDefaultDevice, MTLDevice,
    MTLLibrary, MTLResourceOptions, MTLSize,
};

use super::kernel_source::{self, Flavor};
use super::{decode_hits, pack_run_params, GpuDevice, GpuHit, GpuKernelSpec, GpuRun};

// MTLCreateSystemDefaultDevice is exported by CoreGraphics on macOS.
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {}

/// Raw Objective-C handle bundle for one device's compiled pipeline and buffers.
///
/// objc2 only derives `Send` for protocol traits that declare it (e.g. `MTLDevice`),
/// and the buffer/queue/pipeline protocols don't. Metal objects themselves are
/// thread-safe at the framework level, and this bundle is created before the worker
/// thread spawns and only ever touched by that one owning worker afterwards, so
/// moving it across the spawn boundary is sound.
struct MetalHandles {
    queue: Retained<ProtocolObject<dyn MTLCommandQueue>>,
    pipeline: Retained<ProtocolObject<dyn MTLComputePipelineState>>,
    params: Retained<ProtocolObject<dyn MTLBuffer>>,
    hits: Retained<ProtocolObject<dyn MTLBuffer>>,
    count: Retained<ProtocolObject<dyn MTLBuffer>>,
}

// SAFETY: see the struct documentation above.
unsafe impl Send for MetalHandles {}

/// One initialized Metal device: compiled pipeline plus persistent shared buffers.
pub(crate) struct MetalGpu {
    handles: MetalHandles,
    spec: GpuKernelSpec,
    params_len: usize,
    threadgroup: MTLSize,
    name: String,
}

/// One entry for the system default device; absent when no Metal GPU exists.
pub(crate) fn enumerate(spec: &GpuKernelSpec) -> Vec<Result<Box<dyn GpuDevice>, (String, String)>> {
    match MTLCreateSystemDefaultDevice() {
        Some(device) => vec![build(spec, device).map_err(|e| ("metal[0]".to_string(), e))],
        None => Vec::new(),
    }
}

/// Compile the kernel and prepare the device's persistent buffers.
fn build(
    spec: &GpuKernelSpec,
    device: Retained<ProtocolObject<dyn MTLDevice>>,
) -> Result<Box<dyn GpuDevice>, String> {
    let product = device.name().to_string();
    let source = kernel_source::kernel_source(spec, Flavor::Metal);
    let library = device
        .newLibraryWithSource_options_error(
            &NSString::from_str(&source),
            Some(&MTLCompileOptions::new()),
        )
        .map_err(|e| format!("shader compile: {}", e.localizedDescription()))?;
    let function = library
        .newFunctionWithName(&NSString::from_str("mtsc_search"))
        .ok_or_else(|| "kernel function not found after compile".to_string())?;
    let pipeline = device
        .newComputePipelineStateWithFunction_error(&function)
        .map_err(|e| format!("pipeline state: {}", e.localizedDescription()))?;
    let queue = device
        .newCommandQueue()
        .ok_or_else(|| "command queue creation failed".to_string())?;

    let len = 20 + 8 * spec.capacity + 64; // u64 base + u64 n + u32 + 2×u32[cap] + u32[16]
    let params = alloc(&device, len, "params")?;
    let hits = alloc(&device, kernel_source::MAX_HITS * 24, "hit records")?;
    let count = alloc(&device, 4, "hit counter")?;

    // Threadgroup size makes no measurable difference for this pure-ALU kernel
    // (verified 32..256 on an M4); stay within the device cap, power-of-two.
    let tg_width = device.maxThreadsPerThreadgroup().width.clamp(1, 256);
    Ok(Box::new(MetalGpu {
        handles: MetalHandles {
            queue,
            pipeline,
            params,
            hits,
            count,
        },
        spec: spec.clone(),
        params_len: len,
        threadgroup: MTLSize {
            width: tg_width,
            height: 1,
            depth: 1,
        },
        name: format!("metal[0] {product}"),
    }))
}

/// Allocate a shared-storage buffer of `len` bytes.
fn alloc(
    device: &ProtocolObject<dyn MTLDevice>,
    len: usize,
    what: &str,
) -> Result<Retained<ProtocolObject<dyn MTLBuffer>>, String> {
    device
        .newBufferWithLength_options(len as _, MTLResourceOptions::empty())
        .ok_or_else(|| format!("{what} buffer allocation failed"))
}

impl GpuDevice for MetalGpu {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn run(&mut self, run: &GpuRun) -> Result<Vec<GpuHit>, String> {
        let bytes = pack_run_params(&self.spec, run);
        if bytes.len() > self.params_len {
            return Err("target list exceeds compiled kernel capacity".to_string());
        }
        // Shared-storage buffers: CPU writes before commit and reads after
        // waitUntilCompleted are coherent without didModifyRange/synchronize.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.handles.params.contents().as_ptr() as *mut u8,
                bytes.len(),
            );
            *(self.handles.count.contents().as_ptr() as *mut u32) = 0;
        }

        let command = self
            .handles
            .queue
            .commandBuffer()
            .ok_or_else(|| "command buffer creation failed".to_string())?;
        let encoder = command
            .computeCommandEncoder()
            .ok_or_else(|| "compute encoder creation failed".to_string())?;
        encoder.setComputePipelineState(&self.handles.pipeline);
        unsafe {
            encoder.setBuffer_offset_atIndex(Some(&self.handles.params), 0, 0);
            encoder.setBuffer_offset_atIndex(Some(&self.handles.hits), 0, 1);
            encoder.setBuffer_offset_atIndex(Some(&self.handles.count), 0, 2);
        }
        // One thread per RUN consecutive candidates (see kernel_source::RUN).
        encoder.dispatchThreads_threadsPerThreadgroup(
            MTLSize {
                width: run.n.div_ceil(kernel_source::RUN) as _,
                height: 1,
                depth: 1,
            },
            self.threadgroup,
        );
        encoder.endEncoding();
        command.commit();
        command.waitUntilCompleted();
        if let Some(error) = command.error() {
            return Err(format!("GPU execution: {}", error.localizedDescription()));
        }

        let reported = unsafe { *(self.handles.count.contents().as_ptr() as *const u32) } as usize;
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
        let records = unsafe {
            std::slice::from_raw_parts(
                self.handles.hits.contents().as_ptr() as *const u8,
                kernel_source::MAX_HITS * 24,
            )
        };
        Ok(decode_hits(records, reported))
    }
}
