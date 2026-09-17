# MikroTik RouterOS Serial Collision Generator

`mtsc` is a CLI tool that computes a valid RouterOS serial number from an existing license. For any disk size, it searches for a collision serial whose SOFTWARE ID matches a known signature, so that the existing license activates without mass production. The technique and tool are not L6-specific -- any RouterOS license level (L1-L6) works the same way, since the SOFTWARE ID computation and collision-search process are identical regardless of `nlevel`. A custom disk model string can also be specified.

## Features

- **CPU-selected SHA-256 backends**: scalar, SHA-NI x1/x2/x4, AVX2 x8, AVX-512 x16, ARM SHA2 x1/x2/x4, and NEON x4. Startup detects support and calibrates once at the requested thread count; no feature detection occurs in the hashing loop.
- **Optional GPU acceleration** (CUDA on NVIDIA, Metal on Apple): the whole candidate pipeline runs on-device and every hit is re-verified on the CPU; `--device auto` races GPU against CPU throughput and picks the measured winner
- **Hand-implemented MikroTik crypto primitives**: SHA-256 and MTBase64 have no MikroTik-compatible library equivalent, so both are hand-implemented; standard Curve25519 EC-KCDSA verification uses the audited `curve25519-dalek` crate instead of hand-rolled field/point arithmetic (see `docs/investigation/license-internals.md` §8.32 for why)
- **External key configuration**: add new signatures via `keys.toml` without recompiling
- **Flexible search**: configurable serial alphabet and padding, plus a full 2048-value MBR identity search with an embedded lookup table
- **Resume search**: `--from` parameter resumes from a saved progress point
- **Shell completion**: `completions` subcommand generates bash/zsh/fish/powershell/elvish scripts

## Build

```bash
# GPU support is automatic when the local toolchain exists: a CUDA toolkit
# (nvcc) enables the NVIDIA backend, macOS enables the Metal backend; kernels
# compile at runtime so no GPU SDK is needed to build. Without a toolchain
# the build is CPU-only.
cargo build --release

# Force a backend explicitly, or build lean CPU-only binaries
cargo build --release --features cuda    # NVIDIA (Windows/Linux)
cargo build --release --features metal   # Apple GPUs (macOS)
cargo build --release --no-default-features

# Optional machine-local build; do not distribute it to older CPUs
RUSTFLAGS='-C target-cpu=native' cargo build --release
```

## Downloads

Download available binaries from [GitHub Releases](https://github.com/feewg/ros-serialgen/releases).
Supports Linux, Windows, and macOS on x86_64 and ARM64.

## Usage

### Search for collisions

`-s` takes a magnitude, `-u` sets its unit (`g` gigabytes/default, `m` megabytes, `k` kilobytes, `b` bytes). Minimum size is 64 MB regardless of unit (`-s 1 -u g`, `-s 64 -u m`, `-s 65536 -u k`, `-s 67108864 -u b`).

```bash
# Find 1 collision (default), 100 GB
mtsc search -s 100 -t 16

# Sub-1GB sizes: 128 / 256 / 512 MB
mtsc search -s 128 -u m -t 16
mtsc search -s 256 -u m -t 16
mtsc search -s 512 -u m -t 16

# Find 4 collisions (one per SOFTWARE ID)
mtsc search -s 6 -t 16 -c 4

# Unlimited collection (Ctrl+C to exit)
mtsc search -s 6 -t 16 -c 0

# Custom Model
mtsc search -s 200 -t 16 -m MyDisk

# Resume from the 50000M progress point
mtsc search -s 42 -t 8 -f 50000

# Specify keys.toml
mtsc search -s 100 -t 16 -k /path/to/keys.toml

# Hash on a GPU instead of the CPU pool (build on a machine with the CUDA
# toolkit, or on macOS, and GPU support compiles in automatically).
# auto (default) races GPU vs CPU throughput and picks the measured winner -- an
# NVIDIA card wins by an order of magnitude; Apple Silicon's ARM-SHA2 CPU usually
# beats its own GPU, and auto picks the CPU there.
mtsc search --disk-size 100 --threads 1 --device gpu
mtsc search --disk-size 100 --device cpu
```

By default, search right-pads the natural serial with spaces (`--pad end`) and searches all 2048 MBR values. Use the reported serial **together with its identity and marker**; an identity from another result will not reproduce the same SOFTWARE ID.

To reproduce the old zero-padded, all-zero-identity search:

```bash
mtsc search --disk-size 100 --threads 16 --pad start --identity 00000000000000000000
```

`--alphabet 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ` enables alphanumeric candidates without disabling the selected CPU backend. See the [command reference](docs/reference/command-reference.md) for padding, MBR table overrides, and resume behavior.

### Verify a known serial

```bash
mtsc check --serial 00000000090681934458 -s 24 -m cheerlon
```

`check` accepts the same `-s`/`-u` disk size flags as `search`. Short numeric serials are checked with both zero-padding and space-padding; identical 20-byte inputs are checked only once. Unlike `search`, an omitted `--identity` still means the all-zero identity.

On a match, prints the SOFTWARE ID, License Key, and MBR HEX. With `--bus scsi`, disk size is optional, but omitting it requires an explicit `--model`.

Pass `-l/--license` with a `.key` file (or a raw 128-char signature_hex file) to compare its
embedded SOFTWARE ID against the one computed from serial/model/disk-size/identity/bus:

```bash
mtsc check --serial 00000000090681934458 -s 24 -m cheerlon -l license.key
```

### Conversion

```bash
# signature hex → Key text
mtsc sig2key <128-char-hex>

# Key text → signature hex
mtsc key2sig license.key
```

Both commands print decoded metadata, the signature hex, and the equivalent key text to stdout. `key2sig` also accepts literal key text. To save a `.key` file, copy only its `BEGIN`/`END` key block, not the entire report.

### Algorithm self-check

```bash
mtsc verify
```

### Shell completion

Generates a completion script for the given shell and prints it to stdout.

```bash
# bash
mtsc completions bash > /etc/bash_completion.d/mtsc

# zsh
mtsc completions zsh > "${fpath[1]}/_mtsc"

# fish
mtsc completions fish > ~/.config/fish/completions/mtsc.fish

# powershell / elvish also supported
mtsc completions powershell
mtsc completions elvish
```

## Adding new keys

Edit `keys.toml` and append an entry; no recompilation needed:

```toml
[[key]]
software_id = "XXXX-XXXX"
signature_hex = "..."
```

More keys = faster search (linear speedup).

## Project structure

```
├── Cargo.toml
├── keys.toml                External key configuration (gitignored)
├── keys.example.toml        Template with placeholder entry
├── README.md
├── CLAUDE.md / AGENTS.md    AI tool instructions
├── src/
│   ├── main.rs              CLI entry + multi-threaded search engine
│   ├── lib.rs               Reusable calculation layer for the CLI
│   ├── sha256_backend.rs    CPU dispatch, startup calibration, dynamic batch owner
│   ├── sha256_cpu.rs        AArch64 detection and macOS sysctl compatibility
│   ├── sha256_shani.rs      SHA-NI x1/x2/x4 multi-buffer kernels
│   ├── sha256_avx2.rs       AVX2 x8 kernel
│   ├── sha256_arm.rs        ARM SHA2 x1/x2/x4 kernels
│   ├── sha256_neon.rs       NEON x4 kernel
│   ├── sha256_constants.rs  MikroTik SHA-256 shared constants (IV + K)
│   ├── sha256.rs            MikroTik custom SHA-256 (scalar, production)
│   ├── sha256_simd.rs       AVX-512 SIMD 16-way parallel SHA-256
│   ├── software_id.rs       Base-35 encode/decode + sector_val rounding
│   ├── targets.rs           Load collision targets and derive MBR mixes
│   ├── mbr_table.rs         Validate identity/marker lookup table overrides
│   ├── convert.rs           signature_hex ↔ Key text conversion (MTBase64) + metadata decode
│   └── curve25519.rs        EC-KCDSA local license verification (curve25519-dalek-based)
└── docs/                    Documentation -- see docs/README.md for the full index
    ├── README.md            Documentation index
    ├── quick-start.md       End-to-end walkthrough
    ├── guides/              Step-by-step install walkthroughs (x86, NanoPi R5S)
    ├── reference/           Algorithm & CLI reference (architecture, command-reference, ...)
    ├── database/            Verified collision results, per bus/model
    └── investigation/       Reverse-engineering notes, experiment log
```

## Performance

Startup calibration selects a supported CPU backend at the requested thread
count; SIMD width alone does not determine performance. See
[backend design](docs/reference/sha256-backends.md) and the
[historical performance measurements](docs/benchmarks/README.md). Those
measurements are not full application search speed or expected collision time.

## Dependencies

- `clap` 4.x — CLI framework (derive mode)
- `clap_complete` 4.x — shell completion script generation (`completions` subcommand)
- `serde` 1.x and `toml` 1.x — structured key configuration and MBR table parsing
- `curve25519-dalek` 4.x — audited Curve25519 field/point arithmetic, used only for EC-KCDSA
  local license verification (`LICENSE-VALID` output field); see `docs/investigation/license-internals.md`
  §8.32 for why this isn't hand-implemented like SHA-256/MTBase64
- SHA-256 and MTBase64 are hand-implemented (MikroTik-proprietary variants with no library
  equivalent to depend on)

## Documentation

See [docs/README.md](docs/README.md) for the full documentation index. Highlights:

- [Quick Start](docs/quick-start.md) — deploy a licensed VM in 10 minutes
- [Deployment Guide](docs/guides/x86-install.md) — complete PVE setup reference
- [Command Reference](docs/reference/command-reference.md) — every mtsc subcommand and flag explained
- [Collision Database](docs/database/collision-database.md) — verified serial/model combinations
- [Architecture](docs/reference/architecture.md) — algorithm and security analysis
- [License Internals](docs/investigation/license-internals.md) — SOFTWARE ID / MBR deep dive
- [Experiments](docs/investigation/experiments.md) — verification experiment log
- [Toolchain](docs/reference/toolchain.md) — tools and reverse-engineering notes
