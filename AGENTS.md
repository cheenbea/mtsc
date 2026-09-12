# AGENTS.md

Machine-executable rules for all AI tools working on this Rust project.

## Project

`mtsc` — RouterOS serial generator + key conversion CLI tool. Computes serials from an existing license (any level, L1-L6 -- the SOFTWARE ID computation and collision-search process don't depend on `nlevel`) via SOFTWARE ID collision search; custom model strings supported.

## Architecture

```
src/
├── main.rs              CLI entry (clap subcommands) + multi-threaded search logic
├── lib.rs               SHA-256 calculation library used by the CLI
├── sha256_backend.rs    CPU detection, once-only calibration, backend-owned batches
├── sha256_cpu.rs        AArch64 detection + fail-closed macOS sysctl fallback
├── sha256_shani.rs      SHA-NI x1/x2/x4 multi-buffer kernels (x86_64)
├── sha256_avx2.rs       AVX2 x8 kernel (x86_64)
├── sha256_arm.rs        ARM SHA2 x1/x2/x4 kernels (aarch64)
├── sha256_neon.rs       NEON x4 kernel (aarch64)
├── sha256_constants.rs  Shared constants (ROUND_CONSTANTS + INITIAL_HASH_VALUES)
├── sha256.rs            MikroTik custom SHA-256 (scalar, production) + arbitrary-length digest
├── sha256_simd.rs       AVX-512 SIMD 16-way parallel SHA-256
├── software_id.rs       Base-35 encode/decode + sector_val rounding
├── targets.rs           Load collision targets and derive MBR mixes
├── mbr_table.rs         Validate identity/marker lookup table overrides
├── convert.rs           signature_hex ↔ Key text conversion (MTBase64) + metadata decode
├── curve25519.rs        EC-KCDSA local license verification (curve25519-dalek-based, §8.32)
└── gpu/                 Optional GPU collision-search backends (cargo feature-gated)
    ├── mod.rs           Shared types, params packing, bitmap prefilter, self-check, rate sampling
    ├── kernel_source.rs One C core rendered as CUDA C or MSL (per-run constants baked as literals)
    ├── cuda.rs          NVIDIA backend (cudarc + runtime NVRTC compile; feature "cuda")
    └── metal.rs         Apple backend (objc2-metal + runtime shader compile; feature "metal", macOS only)

keys.toml                External key configuration (loaded at runtime, no recompile needed)
mbr-table.toml           Embedded complete MBR lookup table; optional validated runtime overrides
```

## Commands

```bash
# Search for collisions
mtsc search --disk-size <N> --unit <g|m|k|b> --threads <threads> [--count <count>] [--from <from_M>] [--model <model>] [--keys <keys.toml>] [--identity <identity_hex>] [--bus <ide|nvme|scsi>] [--pad <start|end>] [--alphabet <symbols>] [--mbr-table <path>] [--device <auto|cpu|gpu>]
  --disk-size  Disk size magnitude, paired with --unit; optional for scsi only if --model is supplied
  --unit       Unit: g (gigabytes, default), m (megabytes), k (kilobytes), b (bytes) -- min size is 64M in any unit
  --threads    Thread count (CPU pool only; ignored in GPU mode)
  --count      Collision count (default 1, 0 = unlimited collection)
  --from       Resume from N million hashes (matches the M value in progress output)
  --model      Custom Model (default ROS<N><unit>, e.g. ROS100G, ROS128M)
  --keys       Specify keys.toml path
  --identity   Fix a 20-hex-char MBR identity (0x100-0x109); omitted search identity sweeps all 2048 mbr_val values
  --bus        Disk bus: ide (default, covers ide0/sata0), nvme (same rounding), or scsi (sector_val=0)
  --pad        start: left-pad with alphabet[0]; end (default): right-pad natural serial with spaces
  --alphabet   Ordered unique ASCII alphanumeric symbols (at least 2); default 0123456789
  --mbr-table  Validated runtime overrides for the embedded complete identity/marker lookup table
  --device     Hash device: auto (default; races GPU fleet vs CPU throughput and picks the measured winner), cpu, or gpu (error if no usable device)

# Verify a serial
mtsc check --serial <value> --disk-size <N> --unit <g|m|k|b> [--model <model>] [--keys <keys.toml>] [--identity <identity_hex>] [--bus <ide|nvme|scsi>] [--license <license.key>]
  --license    Compare a .key file's (or raw signature_hex file's) embedded SOFTWARE ID against the one computed above
  --identity   Unlike search, check still defaults to the standard all-zero identity
  # Short numeric serials are checked with both zero- and space-padding; identical byte inputs are deduplicated.

# Conversion (prints a unified metadata, signature hex, and key-text report to stdout)
mtsc sig2key <128-char-hex>     # signature → Key text
mtsc key2sig <file.key-or-text> # Key text or path → signature

# Algorithm self-check
mtsc verify

# Shell completion (bash/zsh/fish/powershell/elvish)
mtsc completions <shell>
```

## Build

```bash
cargo build --release   # Portable; CPU-specific kernels selected once at startup
cargo build --release --features cuda    # NVIDIA GPU backend (runtime NVRTC; toolkit not needed to build)
cargo build --release --features metal   # Apple GPU backend (macOS only)
RUSTFLAGS='-C target-cpu=native' cargo build --release   # Optional machine-local build
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features cuda -- -D warnings   # With a GPU backend enabled
cargo fmt --check   # format check
```

## Documentation Style

- Command-line examples in `docs/` and `AGENTS.md` use **long-form flags** (`--disk-size`, not `-s`) for readability -- short flags are fine in interactive/muscle-memory use but obscure meaning for a reader seeing the command cold.

## Private Data Handling

`keys.toml` is gitignored (never reaches the public repo), but chat/tool-output transcripts are a
separate leak surface. Entries marked `private = true` in `keys.toml` are under an explicit
disclosure restriction from the user (currently: the 99 real-hardware CCR1009 licenses imported
2026-09-07, plus `WUB2-EYCK`, `HCC0-4FJR`, `XU4M-NJ40`):

- Never paste their `identity`, `model`, `serial`, or `signature_hex` field values into a chat
  response or tool-call diff (Edit old_string/new_string included) — refer to them only by
  `software_id`.
- Entries **without** `private = true` are not covered by this restriction and may be discussed/
  quoted normally (as has been done throughout this project's docs/investigation notes).
- When adding a new `[[key]]` entry sourced from the user's own private license inventory (as
  opposed to a publicly-documented forum post etc.), default to `private = true` and follow the
  same non-disclosure handling above unless the user says otherwise.

## Code Rules

- Single source of constants: `sha256_constants.rs`, shared by all SHA-256 implementations
- Backend-owned batch size; do not assume 16 lanes in search code
- CPU feature detection and calibration are startup-only; hashing kernels must not repeat them
- Keep generated logs, performance samples, environment dumps, and build artifacts out of Git
- Keep Git-tracked library/CLI code production-only; do not commit automated tests or standalone benchmark suites
- Put all future local test scripts, harnesses, fixtures, benchmark programs, logs, and results under the gitignored `/tests/<task>/` directory; keep test-specific build output there too (for Rust harnesses, set `CARGO_TARGET_DIR` accordingly)
- Do not embed test modules in `src/`, scatter test files elsewhere, or add local test targets to the production Cargo manifest or CI
- Never force-add files from `/tests/`; before committing, check staged paths for test files and artifacts
- Preserve production runtime verification: `mtsc verify`, `HashEngine::self_check`, and full SOFTWARE ID verification of search hits
- GPU backends are opt-in cargo features, compile kernels at runtime (no GPU SDK at build time), must pass the startup self-check against scalar digests, and every GPU hit is re-hashed on the CPU scalar path before being reported
- GPU kernels mirror the CPU search's exact semantics: u64-wrapping candidate index, same base-N counting and padding transforms, and identical fixed/sweep match formulas (`src/gpu/kernel_source.rs` documents the mirroring)
- CI builds all six Linux/Windows/macOS × x86_64/aarch64 targets, runs Clippy and formatting checks, and packages artifacts; do not use `target-cpu=native` for distributed binaries; GPU features stay OFF in CI builds (kernels JIT at runtime anyway)
- Consistent naming: `sid_lo`/`sid_hi` (not hash_lo/d4), `max_collisions` (not target_count)
- All public functions must have `///` doc comments
- SHA-256 implementations must annotate the reason for byte-order conversions
- New collision targets go into keys.toml configuration, never hardcoded in source
- No built-in default targets -- `load_targets` exits with an error if keys.toml is missing or empty
- Search results must self-verify (recompute the full SOFTWARE ID and print it)
- `decode()` returns `Result`, errors on invalid characters
- Production code must not use `assert!` (use `eprintln!` + `process::exit` instead)
- `cargo clippy` zero warnings (except `dead_code`)
- `cargo fmt` unified formatting

## Key Constants

```
MBR mix (10-zeros): mbr_val = 0x0BD, mix = 0x0BD × 0x3FF800F
SHA-256 IV: [0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F, ...]
Base-35 table: "TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE"
```

## SIMD Optimizations

- `_mm512_i32gather_epi32` replaces 16 scalar gathers (W[0..4] loading)
- Circular buffer W[16] fuses message schedule with compression (4KB→1KB stack)
- `_mm512_ternarylogic_epi32` single-instruction Ch(0xCA)/Maj(0xE8)
- `_mm512_shuffle_epi8` SIMD byte-order conversion
- bswap mask hoisted to function top for reuse
- BCD incremental counter + W[5..9] precomputation
- Full-width sid_hi lookup pre-filter (512 entries, including the required bit 8); sweep matching bypasses fixed-identity prefilter

## GPU Acceleration

- One C core (`kernel_source.rs`) renders as CUDA C (NVRTC, arch from `compute_capability`) or MSL (`newLibraryWithSource`); per-run constants (alphabet, base, padding, match mode, W[5..9], IV, K) are baked as source literals
- Whole pipeline on-device: index → serial → padding → MikroTik SHA-256 → target compare → hit record; only hit records cross the bus
- Each thread owns `RUN`=16 consecutive candidates: u64 division once, digit-carry increments after (64-bit division measured 46% of M4 runtime before this split)
- `--device auto` races measured GPU fleet rate vs CPU engine rate (`HashEngine::sample_rate_hz`) — the winner genuinely flips by machine (RTX 3060 ≈ 2 GH/s vs 137 MH/s CPU; M4 CPU 474 MH/s beats its 200 MH/s GPU)
- Fixed-mode bitmap keyed by `(sid_hi|0x100)` (bits 256..511); sweep-mode bitmap keyed by raw `sid_hi` holding the exact necessary condition `tv_hi ∈ [256,512) && ((sid_hi^tv_hi)&0xFF) < 32` (i.e. `mix_hi < 32`)

## Dependencies

- `clap` 4.x — CLI framework (derive mode)
- `clap_complete` 4.x — shell completion script generation (`completions` subcommand)
- `cudarc` 0.19 (optional, feature `cuda`) — CUDA driver + NVRTC runtime loading; no GPU SDK needed at build time
- `objc2-metal`/`objc2-foundation`/`objc2` 0.x (optional, feature `metal`, macOS) — maintained Metal bindings (the older `metal` crate is deprecated)
- `serde` 1.x and `toml` 1.x — structured key configuration and MBR table parsing
- `curve25519-dalek` 4.x — audited Curve25519 field/point arithmetic for EC-KCDSA local license
  verification (`LICENSE-VALID` output); see `docs/investigation/license-internals.md` §8.32 for why this one
  isn't hand-implemented
- SHA-256 and MTBase64 are hand-implemented (MikroTik-proprietary variants, no library
  equivalent exists to depend on)
