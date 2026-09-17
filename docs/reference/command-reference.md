# Command Reference

Every `mtsc` subcommand and flag, explained. Use this when you need to know exactly what a parameter does before running it.

For PVE/QEMU deployment commands (`qm`, `qemu-img`, `qemu-nbd`, `dd`, `lvcreate`, etc.), see the inline explanations in [deployment-guide.md](../guides/x86-install.md).

---

## `mtsc search`

```bash
mtsc search --disk-size 100 --unit g --threads 16 --count 0 --keys keys.toml
mtsc search --disk-size 128 --unit m --threads 16 --count 0 --keys keys.toml
```

| Option | Meaning |
|---|---|
| `--disk-size <N>` | Disk size magnitude, paired with `--unit`. **Required for `ide`/`nvme`**; determines `sector_val` and must match the disk you'll create. Optional for `scsi`, whose `sector_val` is always `0`. |
| `--unit <unit>` | Unit for `--disk-size`: `g` (GiB, default), `m` (MiB), `k` (KiB), or `b` (raw bytes). Case-insensitive. |
| `--threads <N>` | Number of search threads. Defaults to all available CPU cores if omitted. |
| `--model <name>` | Disk model string, truncated or space-padded to 16 bytes for hashing. Defaults to `ROS<N><unit>` (e.g. `ROS100G`, `ROS128M`) when a size is supplied. **Required when `--bus scsi` is used without `--disk-size`.** |
| `--keys <path>` | Path to `keys.toml`. Defaults to `./keys.toml` if omitted; missing or empty target configuration is an error. |
| `--count <N>` | Number of collisions to find before stopping. `1` (default) stops at the first hit; `0` imposes no hit-count limit (Ctrl+C stops the search). |
| `--from <N>` | Start at candidate index `N × 1,000,000`, matching the `M` progress unit. Default `0`. Indices use `u64`; this is not a promise to enumerate every string in `alphabet_len^20`. Keep model, size, bus, alphabet order, padding, identity mode, and targets unchanged when resuming. |
| `--identity <hex>` | Fix the 10-byte MBR identity seed (`0x100-0x109`), supplied as exactly 20 hex characters. **If omitted, search covers all 2048 `mbr_val` values for each candidate**, not just the all-zero identity. |
| `--mbr-table <path>` | Identity/marker lookup table for sweep mode only (no `--identity`). Defaults to `./mbr-table.toml` if present, otherwise the embedded complete table. Valid partial entries override the embedded table; missing entries retain their embedded defaults. Invalid entries are rejected with warnings and leave the defaults intact, including identities/markers that do not reproduce their declared `mbr_val` and marker. |
| `--pad <start\|end>` | Default `end`: use the candidate's natural symbol length and **right-pad with spaces** to 20 bytes (`123` becomes `123` plus 17 spaces). `start` left-pads to 20 bytes with `alphabet[0]` (`0` for the default alphabet). |
| `--alphabet <symbols>` | Ordered candidate alphabet; default `0123456789`. Must contain at least two distinct, non-repeated ASCII letters/digits. Order defines base-N counting and the first symbol is the zero/left-padding symbol. For example, `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ` selects base 36. |
| `--bus <ide\|scsi\|nvme>` | `ide` (default) covers `ide0` and `sata0`/AHCI. `nvme` uses the same size-dependent sector rounding as `ide`. `scsi` covers `scsi0`/`virtio-scsi-pci`, **not `sata0`**, and forces `sector_val=0`. SCSI activation is confirmed on x86_64; ARM64 virtualization-detection caveats remain in [license-internals.md §8](../investigation/license-internals.md#8-arm32-keyman-on-virtio-scsi-a-platform-specific-investigation). |
| `--device <auto\|cpu\|gpu>` | Hash device for the search, in a binary built with GPU support — automatic when the build machine has the toolchain (CUDA toolkit for NVIDIA, macOS for Metal), forceable with `--features cuda`/`--features metal`. `auto` (default) self-checks every GPU against scalar digests, then races the GPU fleet's measured throughput against the CPU engine's and picks the winner. `gpu` requires a usable device; `cpu` skips GPU probing. GPU hits are always re-hashed on the CPU before being reported. |

### Compatibility with older collision tables

Existing zero-padded serial/all-zero-identity tables use the old search convention. Reproduce it explicitly:

```bash
mtsc search --disk-size 100 --unit g --threads 16 --count 0 --keys keys.toml --identity 00000000000000000000 --pad start

# SCSI needs a model, but not a disk size
mtsc search --bus scsi --model RouterOS-SCSI --threads 16 --keys keys.toml
```

Default sweep results include `identity` and `marker`. **Deploy those exact values with the printed serial**, rather than copying the old `00000000000000000000BDE800000000` MBR header. When checking a hit, pass its identity explicitly; `check` does not inherit `search`'s sweep default. Keep a full 20-byte zero-padded serial intact when reproducing an older table entry.

If `alphabet_len^20` fits in `u64`, search stops and reports exhaustion instead of repeating candidates. Otherwise, the `u64` candidate index wraps to zero after `u64::MAX`. An overflowing `--from` offset or one beyond a finite candidate space is rejected.

Candidate generation supports every CPU backend: scalar, SHA-NI, AVX2, AVX-512, ARM SHA2, and NEON as supported by the CPU/OS. Startup calibration selects the backend once for the requested thread count; backend-owned batches are retained for both padding modes and custom alphabets. This does not guarantee identical end-to-end throughput for different alphabets or sweep/fixed-identity modes. In GPU mode (`--device gpu`, or `auto` picking a GPU), one host thread per device drives 16M-candidate on-device chunks and `--threads` is ignored. See [SHA-256 backends](sha256-backends.md).

### Minimum disk size per unit

Sizes use powers of 1024. Each unit has a separate integer minimum, enforcing at least 64 MiB at startup (the process exits with an error if violated). This also applies to a size explicitly supplied for `scsi`, even though its hash ignores size:

| Unit | Minimum `--disk-size` value |
|---|---|
| `g` | `1` (1 GiB; integer magnitudes cannot express 64 MiB) |
| `m` | `64` (64 MiB) |
| `k` | `65536` (64 MiB in KiB) |
| `b` | `67108864` (64 MiB in bytes) |

Decimal sizes are not supported (`--disk-size` is an integer) -- fractional GiB values must be expressed in a smaller unit instead, e.g. `--disk-size 1536 --unit m` for 1.5 GiB. This avoids floating-point rounding errors in the byte-exact `sector_val` calculation.

Progress uses millions of candidate hashes, with a nominal interval of 10,000M (10 billion), e.g. `10000M hashes, 5s, 0 found`. Sweeping 2048 `mbr_val` values reuses each candidate's hash; it does not multiply the `--from` index by 2048. Wall-clock intervals vary by backend and workload; the [historical backend measurements](../benchmarks/README.md) are not full search throughput.

## `mtsc check`

```bash
mtsc check --serial 00000000090681934458 --disk-size 24 --unit g --model cheerlon
```

| Option | Meaning |
|---|---|
| `--serial <value>` | Serial to verify. **Required.** For a pure-digit serial shorter than 20 bytes, computes both left-zero-padding and right-space-padding and labels the results. Alphanumeric serials are right-space-padded. If both forms yield identical 20-byte input, only one result is printed; an already-20-byte serial is unchanged. |
| `--disk-size <N>` | Required for `ide`/`nvme`; optional for `scsi`, whose `sector_val` is always `0`. |
| `--unit <unit>` | `g` (GiB, default), `m` (MiB), `k` (KiB), or `b` (bytes); same supplied-size minimums as `search`. |
| `--model <name>` | Defaults to `ROS<N><unit>` when size is supplied. Required for `--bus scsi` without `--disk-size`. |
| `--keys <path>` | Path to `keys.toml`; defaults to `./keys.toml`. |
| `--identity <hex>` | Exactly 20 hex characters for the 10-byte MBR identity seed. **Default remains all zeros**, unlike `search`; no sweep is performed. Pass a search result's identity explicitly. |
| `--bus <ide\|scsi\|nvme>` | Same meanings and platform caveats as `search`; default `ide`. |
| `--license <path>` | Compare the computed SOFTWARE ID with the embedded ID from a `.key` file or a raw 128-character signature-hex file. This compares IDs, not the hardware's eventual activation state. |

Prints the computed SOFTWARE ID for each distinct padding variant. A configured target match also prints its License Key and MBR hex. The MBR header uses the selected identity and its **derived marker**, followed by four zero reserved bytes; it does not hardcode `BDE8` for nonzero identities. See [identity/marker formula](identity-marker-formula.md).

```bash
# Recheck a sweep result with its identity (supply the serial exactly as printed)
mtsc check --serial <serial> --disk-size 100 --unit g --model ROS100G --identity <identity-from-search> --license license.key

# No size needed for SCSI, but the model is mandatory
mtsc check --serial 123 --bus scsi --model RouterOS-SCSI
```

## `mtsc sig2key <signature_hex>`

Positional argument: a 128-character hex string (64 bytes) -- the signature from the [Signature Table](../database/collision-database.md#signature-table).

Both conversion commands print the same report to **stdout**: `Software ID`, `Router OS Version`, `License Level`, `Nonce Hash`, `Signature`, local EC-KCDSA `License valid`, the full 64-byte `MBR Signature (hex)`, and the equivalent `License` key-text block. Warnings/errors go to stderr. The `Signature` metadata field is only the trailing 32-byte signature scalar; use `MBR Signature (hex)` when you need the complete 128-character blob.

**Stdout is not a bare `.key` or hex file.** Copy only the complete `BEGIN`/`END MIKROTIK SOFTWARE KEY` block (without the `License:` label) for a `.key` file, or only the `MBR Signature (hex)` value for raw hex. See [license metadata decoding](../investigation/license-internals.md#821-signature-metadata-decryption-mt_transform) and [license-internals.md §8.32](../investigation/license-internals.md).

## `mtsc key2sig <key_file_or_text>`

Accepts either an existing `.key` file path or literal MikroTik key text as one quoted positional argument, including the complete `-----BEGIN...` block. If the argument names an existing file, its contents are read; otherwise the argument itself is parsed as key text. Prints the same unified stdout report as `sig2key`.

```bash
mtsc key2sig license.key
mtsc key2sig '<complete MikroTik key text>'
```

## `mtsc verify`

```bash
mtsc verify
```

No arguments, no `keys.toml` needed -- this is a self-contained sanity check, unrelated to real signatures or collision search.

Runs the full SOFTWARE ID pipeline (custom SHA-256 -> MBR mix XOR -> Base-35 encode) against two fixed, hardcoded (serial, model, sector_val) test vectors, then checks that the result round-trips correctly through `encode -> decode -> re-encode`. Also prints the startup-selected hash engine and batch width: scalar, SHA-NI, AVX2, AVX-512, ARM SHA2, or NEON according to CPU/OS support and once-only calibration. It is not an AVX-512-only acceleration check.

Run this once after building, or after moving to a different machine/CPU, before trusting `search` output.

## `mtsc completions <shell>`

Prints a completion script to stdout for `bash`, `zsh`, `fish`, `powershell`, or `elvish`.

```bash
mtsc completions bash
```

Use `mtsc --help` or `mtsc <subcommand> --help` for the CLI's full option list and supported short aliases; examples here use long options.
