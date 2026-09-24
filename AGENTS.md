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
└── curve25519.rs        EC-KCDSA local license verification (curve25519-dalek-based, §8.32)

keys.toml                External key configuration (loaded at runtime, no recompile needed)
mbr-table.toml           Embedded complete MBR lookup table; optional validated runtime overrides
```

## Commands

```bash
# Search for collisions
mtsc search --size <N> --unit <g|m|k|b> --threads <threads> [--count <count>] [--from <from_M>] [--model <model>] [--keys <keys.toml>] [--identity <identity_hex>] [--bus <ide|nvme|scsi>] [--pad <start|end>] [--mbr-table <path>]
  --size       Disk size magnitude, paired with --unit; optional for scsi only if --model is supplied
  --unit       Unit: g (gigabytes, default), m (megabytes), k (kilobytes), b (bytes) -- min size is 64M in any unit
  --threads    Thread count
  --count      Collision count (default 1, 0 = unlimited collection)
  --from       Resume from N million hashes (matches the M value in progress output)
  --model      Custom Model (default ROS<N><unit>, e.g. ROS100G, ROS128M)
  --keys       Specify keys.toml path
  --identity   Fix a 20-hex-char MBR identity (0x100-0x109); omitted search identity sweeps all 2048 mbr_val values
  --bus        Disk bus: ide (default, covers ide0/sata0), nvme (same rounding), or scsi (sector_val=0)
  --pad        start: left-pad with '0'; end (default): right-pad natural serial with spaces
  --mbr-table  Validated runtime overrides for the embedded complete identity/marker lookup table

Candidate alphabet is fixed at base 36 (digits then uppercase letters, `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ`) -- not configurable, no `--alphabet` flag.

# Verify a serial
mtsc check --serial <value> --size <N> --unit <g|m|k|b> [--model <model>] [--keys <keys.toml>] [--identity <identity_hex>] [--bus <ide|nvme|scsi>] [--license <license.key>]
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
RUSTFLAGS='-C target-cpu=native' cargo build --release   # Optional machine-local build
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --check   # format check
```

## Testing

- `cargo test --release` — 97 tests passed, 1 ignored (`main::tests::test_real_disk_all_targets_sweep_vs_feasibility_check_agree`, a heavy/optional sweep-vs-feasibility cross-check, needs a local `keys.toml`), 0 failed as of 2026-09-13.
- `main::tests::test_hash_engine_self_check_passes_for_every_supported_backend` / `test_hash_batch_matches_scalar_reference_extra_patterns` — cross-validate every `HashEngine` backend the CPU actually supports against the scalar reference; this makes `sha256_backend.rs`'s runtime `HashEngine::self_check()` (already called from `auto_for_threads` before real work) also run under `cargo test`/CI.
- **Known coverage gap**: `HashEngine::supported()` is architecture-gated, so the above tests only exercise whatever backends match the machine `cargo test` runs on. `scalar`/`sha-ni`/`avx2`/`avx512` are real-hardware-verified on x86_64 CI (confirmed on an AVX-512F/BW + SHA-NI + AVX2 host). `arm-sha2`/`neon` have only been verified once, manually, via QEMU user-mode emulation (`aarch64-unknown-linux-gnu` cross-compiled, run under `qemu-aarch64-static -cpu max`) during PR #5's review — **not on real ARM hardware, and not wired into any CI job** (`.github/workflows/build-release.yml`'s `build` job builds/lints the three aarch64 targets but never runs `cargo test` for them). Treat `arm-sha2`/`neon` as unverified-by-CI until an aarch64 test runner (or emulated CI step) is added.
- `sha256::tests::test_6g_known_hash` — 6G VMware known hash value
- `software_id::tests::test_encode_decode_roundtrip` — encode/decode roundtrip
- `software_id::tests::test_decode_invalid_char` — invalid character error
- `software_id::tests::test_round_sectors` — 5 rounding verification cases
- `convert::tests::test_roundtrip_synthetic` — sig ↔ key conversion verification
- `main::tests` — disk size parsing/validation, write_candidate/increment_candidate (base-36 `SEARCH_ALPHABET`), software_id, model, input_buf, check_match, E2E, identity parsing/mix resolution
- `targets::tests` — `mix_from_identity` (matches standard for all-zero, deterministic, differs for non-zero)
- `curve25519::tests` — EC-KCDSA verify against `TI09-7WK3`'s real, hardware-activation-confirmed
  signature (must return `true`), plus rejection tests for a tampered signature/payload/wrong
  public key (must return `false`) -- see `docs/investigation/license-internals.md` §8.32

## Documentation Style

- The CLI accepts **long-form flags only** (`--size`, `--unit`, `--threads`, etc.) -- there are no short flags, not even clap's auto `-h`/`-V`; use `--help`/`--version` instead. Command-line examples in `docs/` and `AGENTS.md` always use the long form.

## Private Data Handling

`keys.toml` is gitignored (never reaches the public repo), but chat/tool-output transcripts are a
separate leak surface. Entries marked `private = true` in `keys.toml` are under an explicit
disclosure restriction from the user (currently: the 99 real-hardware CCR1009 licenses imported
2026-09-07, plus `WUB2-EYCK`, `HCC0-4FJR`, `XU4M-NJ40`):

- Never paste their `identity`, `model`, `serial`, or `signature` field values into a chat
  response or tool-call diff (Edit old_string/new_string included) — refer to them only by
  `softwareId`.
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
- CI builds all six Linux/Windows/macOS × x86_64/aarch64 targets, runs Clippy and formatting checks, and packages artifacts; do not use `target-cpu=native` for distributed binaries
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

## Dependencies

- `clap` 4.x — CLI framework (derive mode)
- `clap_complete` 4.x — shell completion script generation (`completions` subcommand)
- `serde` 1.x and `toml` 1.x — structured key configuration and MBR table parsing
- `curve25519-dalek` 4.x — audited Curve25519 field/point arithmetic for EC-KCDSA local license
  verification (`LICENSE-VALID` output); see `docs/investigation/license-internals.md` §8.32 for why this one
  isn't hand-implemented
- `data-encoding` 2.x — hex (`HEXUPPER`/`HEXLOWER_PERMISSIVE`) and MTBase64 (`Specification` with
  `BitOrder::LeastSignificantFirst`); replaced a hand-rolled decoder that had no padding
  position/count or trailing-bits validation at all (see
  `docs/reference/mtsc-cli-plan.md`'s "Replace hand-rolled MTBase64 with the `data-encoding`
  crate" section, and `convert::tests::test_base64_negative_corpus_documents_old_vs_new_behavior`
  for the specific accept/reject differences this closed)
- SHA-256 is hand-implemented (MikroTik-proprietary variant, no library equivalent exists to
  depend on); MTBase64's *alphabet/bit-order* is proprietary but its *codec mechanics* are now
  `data-encoding`-backed, not hand-rolled
