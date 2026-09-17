//! Build-time GPU toolchain detection for the default `gpu-auto` feature.
//!
//! `cargo build` (default features) compiles the CUDA backend when a local CUDA
//! toolkit is present and the Metal backend when targeting macOS; without a
//! toolchain the build is CPU-only. Force explicitly with `--features cuda`
//! (NVIDIA) / `--features metal` (Apple), or build lean CPU-only binaries with
//! `--no-default-features`. Everyone compiles locally from source — there is no
//! cloud/CI build, so detection always reflects the building machine.
//!
//! Detection result reaches the code as the `gpu_cuda_toolchain` cfg (see the
//! module gates in `src/gpu/mod.rs`); the Metal backend needs no probe because
//! the Metal toolchain ships with every macOS SDK.

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    for var in ["CUDA_PATH", "CUDA_HOME", "CUDA_ROOT"] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    println!("cargo:rustc-check-cfg=cfg(gpu_cuda_toolchain)");

    if let Some(root) = detect_cuda_toolkit() {
        println!("cargo:rustc-cfg=gpu_cuda_toolchain");
        println!(
            "cargo:warning=CUDA toolkit detected at {}: enabling the CUDA GPU backend \
             (default feature gpu-auto; --no-default-features builds CPU-only)",
            root.display()
        );
    }
}

/// Find a CUDA toolkit: `$CUDA_PATH`/`$CUDA_HOME`/`$CUDA_ROOT` pointing at a root
/// whose `bin` holds nvcc, or an `nvcc` executable directly on `PATH`.
fn detect_cuda_toolkit() -> Option<PathBuf> {
    for var in ["CUDA_PATH", "CUDA_HOME", "CUDA_ROOT"] {
        if let Ok(root) = env::var(var) {
            let root = PathBuf::from(root);
            if has_nvcc(&root.join("bin")) {
                return Some(root);
            }
        }
    }
    if let Ok(path) = env::var("PATH") {
        for dir in env::split_paths(&path) {
            if has_nvcc(&dir) {
                // .../CUDA/vX.Y/bin -> report the toolkit root above `bin`
                return Some(dir.parent().unwrap_or(Path::new("/")).to_path_buf());
            }
        }
    }
    None
}

/// Whether `dir` contains the nvcc executable for this host.
fn has_nvcc(dir: &Path) -> bool {
    dir.join("nvcc").is_file() || dir.join("nvcc.exe").is_file()
}
