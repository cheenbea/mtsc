//! RouterOS L6 Serial Generator — computes serials from existing licenses + key conversion tool
//!
//! Selects a CPU-supported SHA-256 backend once at startup; each backend owns
//! its batch size, with portable scalar calculation retained as the reference.

mod convert;
mod curve25519;
// Shared GPU plumbing stays compiled even without backend features (backends are
// cfg-gated); uninstantiated pieces (e.g. Flavor::Metal off macOS) are allowed-dead,
// mirroring `sha256_constants`'s pattern.
#[allow(dead_code)]
mod gpu;
mod mbr_table;
// The binary's license verifier uses K; the shared library additionally uses the IV.
#[allow(dead_code)]
mod sha256_constants;
use mtsc::sha256;
use mtsc::sha256_backend::{precompute_constant_words, HashBatch, HashEngine};
mod software_id;
mod targets;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

// ---- Constants ----

/// Space padding byte in SHA-256 input (RouterOS convention)
const SPACE_PADDING: u8 = 0x20;
/// Serial field length (20 ASCII bytes, including serial padding)
const SERIAL_LEN: usize = 20;
/// Model field length (16 bytes, space-padded)
const MODEL_LEN: usize = 16;
/// Total SHA-256 input length: serial(20) + model(16) + sector_val(4)
const INPUT_LEN: usize = SERIAL_LEN + MODEL_LEN + 4;
/// Progress report interval (every 10,000M = 10 billion hashes)
const PROGRESS_INTERVAL: u64 = 10_000_000_000;

// ---- CLI definition ----

#[derive(Parser)]
#[command(name = "mtsc")]
#[command(about = "RouterOS L6 Serial Generator — collision search & key conversion")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Search collision serial for a disk size
    Search {
        /// Disk size magnitude (paired with --unit). Required for --bus ide/nvme; optional
        /// (and ignored) for --bus scsi, where sector_val is always forced to 0.
        #[arg(short = 's', long = "disk-size")]
        disk_size: Option<u64>,
        /// Disk size unit: g (gigabytes, default), m (megabytes), k (kilobytes), or b (bytes)
        #[arg(short = 'u', long, value_enum, ignore_case = true, default_value = "g")]
        unit: SizeUnit,
        /// Thread count
        #[arg(short, long)]
        threads: Option<usize>,
        /// Model name (default: ROS<size><unit>, e.g. ROS100G, ROS128M)
        #[arg(short, long)]
        model: Option<String>,
        /// keys.toml path
        #[arg(short, long)]
        keys: Option<String>,
        /// Number of collisions to find (default: 1, 0 = unlimited)
        #[arg(short = 'c', long, default_value = "1")]
        count: usize,
        /// Start from N million hashes (resume from progress output)
        #[arg(short = 'f', long, default_value = "0")]
        from: u64,
        /// Non-standard 20-hex-char MBR identity seed (0x100-0x109), e.g. from a real
        /// device's captured MBR. Default: sweep all 2048 possible mbr_val values per
        /// candidate serial instead of a single fixed identity (see --mbr-table).
        #[arg(short = 'i', long)]
        identity: Option<String>,
        /// Disk bus type: ide (default, verified against real hardware -- also covers
        /// sata0/AHCI, which uses the identical encoding), nvme (same sector_val rounding
        /// as ide), or scsi (scsi0/virtio-scsi-pci specifically, NOT sata0 -- forces
        /// sector_val=0; see docs/license-internals.md §8.11-8.20; end-to-end activation
        /// confirmed on x86_64, §8.18).
        #[arg(
            short = 'b',
            long,
            value_enum,
            ignore_case = true,
            default_value = "ide"
        )]
        bus: BusType,
        /// Path to the mbr_val -> identity/marker lookup table, used only when --identity is
        /// NOT given (full mbr_val sweep mode). Default: ./mbr-table.toml if present,
        /// otherwise an embedded complete table. Any mbr_val missing from this file is
        /// filled in from the embedded default, so an incomplete file is never a hard error.
        #[arg(long = "mbr-table")]
        mbr_table: Option<String>,
        /// Where padding goes for a numeric candidate serial shorter than 20 bytes: start
        /// (left-pad with '0', e.g. "123" -> "00000000000000000123") or end (default,
        /// right-pad with spaces using the natural digit count, e.g. "123" ->
        /// "123                 "). `end` matches real hardware's actual behavior
        /// (confirmed via a live RouterOS boot test, docs/license-internals.md §8.62) --
        /// use `start` only if you specifically need the old zero-padded numeric-string
        /// assumption.
        #[arg(long = "pad", value_enum, ignore_case = true, default_value = "end")]
        pad: PadPosition,
        /// Ordered, distinct ASCII letters/digits for base-N counting (at least 2 symbols).
        /// The first symbol is the zero/left-pad symbol. All alphabets use the selected
        /// CPU backend. Search stops at alphabet_len^20 if it fits in u64; otherwise
        /// the u64 index wraps to zero after u64::MAX (only the u64-indexed subset is searched).
        /// Example: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" for base 36.
        #[arg(long = "alphabet", default_value = "0123456789")]
        alphabet: String,
        /// Hash device for the collision search: auto (default) uses a GPU whose kernel
        /// compiles and passes the startup self-check, falling back to the CPU thread
        /// pool otherwise; gpu requires a usable GPU; cpu skips GPU probing entirely.
        /// GPU support compiles automatically when the build machine has the toolchain
        /// (CUDA toolkit, or macOS for Metal); force with `--features cuda`/`--features
        /// metal`, or build CPU-only with `--no-default-features`.
        #[arg(
            long = "device",
            value_enum,
            ignore_case = true,
            default_value = "auto"
        )]
        device: DeviceChoice,
    },
    /// Convert signature_hex to Key text
    Sig2key {
        /// 128-char hex string (64 bytes)
        signature_hex: String,
    },
    /// Convert Key text to signature_hex -- accepts either a path to a .key file, or the
    /// key text itself (any of the three forms `key_text_to_signature` accepts) as a literal
    /// string argument
    Key2sig {
        /// Path to a .key file, or the key text itself as a literal string (may start with
        /// "-----BEGIN..."; allow_hyphen_values lets this be passed without a `--` separator)
        #[arg(allow_hyphen_values = true)]
        key_file_or_text: String,
    },
    /// Verify SOFTWARE ID computation with known test vectors
    Verify,
    /// Check a serial against known signatures
    Check {
        /// Serial number (20-digit string)
        #[arg(long)]
        serial: String,
        /// Disk size magnitude (paired with --unit). Required for --bus ide/nvme; optional
        /// (and ignored) for --bus scsi, where sector_val is always forced to 0.
        #[arg(short = 's', long = "disk-size")]
        disk_size: Option<u64>,
        /// Disk size unit: g (gigabytes, default), m (megabytes), k (kilobytes), or b (bytes)
        #[arg(short = 'u', long, value_enum, ignore_case = true, default_value = "g")]
        unit: SizeUnit,
        /// Model name (default: ROS<size><unit>, e.g. ROS100G, ROS128M, ROS67108864B)
        #[arg(short, long)]
        model: Option<String>,
        /// keys.toml path
        #[arg(short, long)]
        keys: Option<String>,
        /// Non-standard 20-hex-char MBR identity seed (0x100-0x109), e.g. from a real
        /// device's captured MBR. Default: standard all-zero identity used by collision search.
        #[arg(short = 'i', long)]
        identity: Option<String>,
        /// Disk bus type: ide (default, verified against real hardware -- also covers
        /// sata0/AHCI, which uses the identical encoding), nvme (same sector_val rounding
        /// as ide), or scsi (scsi0/virtio-scsi-pci specifically, NOT sata0 -- forces
        /// sector_val=0; see docs/license-internals.md §8.11-8.20; end-to-end activation
        /// confirmed on x86_64, §8.18).
        #[arg(
            short = 'b',
            long,
            value_enum,
            ignore_case = true,
            default_value = "ide"
        )]
        bus: BusType,
        /// Path to a .key license file (or a raw 128-char signature_hex file) to compare
        /// against the SOFTWARE ID computed from serial/model/disk-size/identity/bus above.
        #[arg(short = 'l', long)]
        license: Option<String>,
    },
    /// Generate a shell completion script (bash/zsh/fish/powershell/elvish) and print it to stdout
    Completions {
        /// Target shell
        shell: Shell,
    },
}

/// Disk bus type -- see `docs/license-internals.md` §8 for why this matters.
///
/// `keyman` uses entirely different code paths to read serial/model depending on how the
/// disk is presented to the guest kernel. `sata0`/AHCI disks use QEMU's `ide-hd` device --
/// the same device model as real `ide0` -- and are confirmed to use the identical encoding
/// (§8.20), so `Ide` covers both. `Scsi` covers `scsi0`/`virtio-scsi-pci` specifically
/// (SCSI INQUIRY + VPD page 0x80, sector_val forced to 0) -- confirmed correct and fully
/// activatable end-to-end on x86_64 (§8.14, §8.18-8.19); on ARM64 a separate
/// virtualization-detection issue in `keyman` can still block activation (§8.15-8.17).
#[derive(Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
enum BusType {
    /// Real ATA/IDE-presented disk (QEMU `ide0`), or `sata0`/AHCI (confirmed identical
    /// encoding, §8.20). Standard, verified encoding.
    Ide,
    /// SCSI-subsystem-presented disk (`scsi0`/`virtio-scsi-pci` -- NOT `sata0`, which uses
    /// `Ide`'s encoding instead, §8.20). Forces sector_val=0 -- see §8.11-8.19.
    Scsi,
    /// NVMe-presented disk. Uses the identical sector_val rounding as `Ide` (disk size
    /// matters, standard rounding rule) -- distinct from `Scsi`, which forces sector_val=0.
    Nvme,
}

impl BusType {
    /// Whether disk size is meaningless for this bus (sector_val is forced to a fixed
    /// value regardless of size) -- currently only `Scsi`.
    fn size_irrelevant(self) -> bool {
        matches!(self, BusType::Scsi)
    }
}

/// Where padding goes when a numeric candidate serial is shorter than `SERIAL_LEN` bytes
/// during `search`: at the `Start` (padding character is `'0'`) or at the `End` (padding
/// character is a space, using the candidate's natural digit count with no leading
/// zeros). `End` is the default -- confirmed as real hardware's actual behavior via a
/// live RouterOS boot test (docs/investigation/license-internals.md §8.62), where
/// `Start` (the old default) reflects the numeric-string convention this tool originally
/// assumed before that real-hardware confirmation. See `leading_pad_to_space_padded` for
/// the `Start` -> `End` transform.
#[derive(Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
enum PadPosition {
    /// Pad at the start with '0' (left-pad).
    Start,
    /// Pad at the end with spaces (right-pad), using the candidate's natural digit count.
    /// Default -- see this enum's doc comment for why.
    End,
}

/// Where the collision search hashes: the CPU thread pool or a GPU (CUDA on NVIDIA,
/// Metal on Apple). GPU kernels implement the whole per-candidate pipeline on-device
/// and every reported hit is re-verified by the CPU scalar path.
#[derive(Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
enum DeviceChoice {
    /// GPU when a compiled-in backend finds a device that passes the startup
    /// self-check; CPU thread pool otherwise. Default.
    Auto,
    /// CPU thread pool only, no GPU probing.
    Cpu,
    /// GPU only; exit with an error when no usable device exists.
    Gpu,
}

/// Disk size unit, paired with the `--disk-size` magnitude
#[derive(Clone, Copy, clap::ValueEnum)]
enum SizeUnit {
    /// Gigabytes (1024^3 bytes)
    G,
    /// Megabytes (1024^2 bytes)
    M,
    /// Kilobytes (1024^1 bytes)
    K,
    /// Raw bytes
    B,
}

impl SizeUnit {
    /// Number of bytes in one unit
    fn bytes_per_unit(self) -> u64 {
        match self {
            SizeUnit::G => 1024 * 1024 * 1024,
            SizeUnit::M => 1024 * 1024,
            SizeUnit::K => 1024,
            SizeUnit::B => 1,
        }
    }

    /// Uppercase letter used in size labels (e.g. "128M", "100G", "65536K", "67108864B") and default model names
    fn label_char(self) -> char {
        match self {
            SizeUnit::G => 'G',
            SizeUnit::M => 'M',
            SizeUnit::K => 'K',
            SizeUnit::B => 'B',
        }
    }

    /// Minimum allowed magnitude for this unit -- all equivalent to 64M
    fn min_magnitude(self) -> u64 {
        match self {
            SizeUnit::G => 1,
            SizeUnit::M => 64,
            SizeUnit::K => 64 * 1024,
            SizeUnit::B => 64 * 1024 * 1024,
        }
    }
}

/// Reject disk sizes below the minimum for their unit (all equivalent to 64M). Exits the process on violation.
fn validate_disk_size(magnitude: u64, unit: SizeUnit) {
    let min = unit.min_magnitude();
    if magnitude < min {
        eprintln!(
            "Error: disk size {}{} is below the minimum for unit '{}' (must be >= {}{})",
            magnitude,
            unit.label_char(),
            unit.label_char(),
            min,
            unit.label_char()
        );
        std::process::exit(1);
    }
}

/// Compute exact disk size in bytes and a display label (e.g. "128M", "100G", "65536K", "67108864B")
fn disk_size_bytes_and_label(magnitude: u64, unit: SizeUnit) -> (u64, String) {
    let bytes = magnitude * unit.bytes_per_unit();
    let label = format!("{}{}", magnitude, unit.label_char());
    (bytes, label)
}

/// Resolve `--disk-size`/`--unit` against the selected bus, enforcing that they're required
/// for buses where disk size actually affects sector_val (ide/nvme) while remaining optional
/// (and ignored) for buses where it doesn't (scsi -- sector_val is always forced to 0).
/// Exits the process if disk_size is missing on a bus that needs it.
fn resolve_disk_size(disk_size: Option<u64>, unit: SizeUnit, bus: BusType) -> (u64, String) {
    match disk_size {
        Some(magnitude) => {
            validate_disk_size(magnitude, unit);
            disk_size_bytes_and_label(magnitude, unit)
        }
        None if bus.size_irrelevant() => (0, "N/A (scsi, size ignored)".to_string()),
        None => {
            eprintln!(
                "Error: --disk-size is required for --bus ide/nvme (only optional for --bus scsi)"
            );
            std::process::exit(1);
        }
    }
}

/// Parse a 20-hex-char `--identity` argument into the 10-byte MBR identity seed.
/// Exits the process on malformed input (wrong length or non-hex characters).
fn parse_identity_hex(s: &str) -> [u8; 10] {
    if s.len() != 20 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        eprintln!(
            "Error: --identity must be exactly 20 hex characters (10 bytes), got '{}' ({} chars)",
            s,
            s.len()
        );
        std::process::exit(1);
    }
    let mut out = [0u8; 10];
    for i in 0..10 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

/// Resolve the mix to use: either derived from a custom `--identity`, or the standard
/// all-zero-identity mix used by collision search.
fn resolve_mix(identity: Option<&str>) -> (u32, u32) {
    match identity {
        Some(hex) => targets::mix_from_identity(&parse_identity_hex(hex)),
        None => targets::mbr_mix(),
    }
}

// ---- Search context ----

/// Context shared across search threads (avoids excessive parameters)
struct SearchContext {
    model_bytes: [u8; MODEL_LEN],
    sv_bytes: [u8; 4],
    targets: Arc<Vec<targets::Target>>,
    /// `Some` only in full-mbr_val-sweep mode (no `--identity` given); `targets` above is
    /// left empty in that case. See `sweep_check_match`.
    raw_targets: Option<Arc<Vec<targets::RawTarget>>>,
    /// `Some` only in full-mbr_val-sweep mode -- pairs with `raw_targets`.
    mbr_table: Option<Arc<mbr_table::MbrTable>>,
    /// Where padding goes for numeric candidate serials shorter than `SERIAL_LEN` bytes
    /// -- see `PadPosition`.
    pad: PadPosition,
    /// Alphabet candidate serials are drawn from -- see `validate_alphabet`. `alphabet[0]`
    /// doubles as the "zero"/pad-with symbol for `PadPosition::End`'s leading-run strip.
    alphabet: Vec<u8>,
    /// Cached `alphabet == b"0123456789"` -- lets the hot loop pick the fast
    /// `write_serial`/`increment_bcd` path (identical to this tool's original behavior)
    /// without re-comparing the alphabet on every iteration.
    is_default_alphabet: bool,
    mix_lo: u32,
    mix_hi: u32,
    max_collisions: usize,
    stop: Arc<AtomicBool>,
    found_count: Arc<AtomicUsize>,
    start: Instant,
}

impl SearchContext {
    /// Encode an index without changing the counter's fixed-width representation.
    #[inline]
    fn write_candidate(&self, serial: &mut [u8; SERIAL_LEN], index: u64) {
        if self.is_default_alphabet {
            write_serial(serial, index);
        } else {
            write_candidate(serial, index as u128, &self.alphabet);
        }
    }

    /// Advance the fixed-width counter, never a space-padded hashing buffer.
    #[inline]
    fn increment_candidate(&self, serial: &mut [u8; SERIAL_LEN]) {
        if self.is_default_alphabet {
            increment_bcd(serial);
        } else {
            increment_candidate(serial, &self.alphabet);
        }
    }

    /// Produce all 20 serial bytes while preserving the model/sector suffix.
    #[inline]
    fn pad_candidate(&self, serial: &[u8; SERIAL_LEN]) -> [u8; SERIAL_LEN] {
        match self.pad {
            PadPosition::Start => *serial,
            PadPosition::End => leading_pad_to_space_padded(serial, self.alphabet[0]),
        }
    }
}

/// Exclusive candidate limit when the whole 20-symbol space fits in a u64.
/// Otherwise the original u64 counter and its wrap-to-zero semantics apply.
fn candidate_space_limit(alphabet_len: usize) -> Option<u64> {
    (alphabet_len as u64).checked_pow(SERIAL_LEN as u32)
}

/// Convert a million-candidate resume offset without silently overflowing/repeating.
fn resolve_start_serial(from: u64, limit: Option<u64>) -> Result<u64, &'static str> {
    let start = from
        .checked_mul(1_000_000)
        .ok_or("--from is too large (million-candidate offset overflows u64)")?;
    if limit.is_some_and(|limit| start >= limit) {
        return Err("--from is outside the alphabet's 20-symbol candidate space (exhausted)");
    }
    Ok(start)
}

/// Require an explicit model when no size is available for a default model name.
fn resolve_model(
    model: Option<String>,
    disk_size: Option<u64>,
    size_label: &str,
) -> Result<String, &'static str> {
    match model {
        Some(model) => Ok(model),
        None if disk_size.is_some() => Ok(format!("ROS{size_label}")),
        None => Err("--model is required when --disk-size is omitted (--bus scsi)"),
    }
}

// ---- Common utility functions ----

/// Compute the SOFTWARE ID string from sid_lo + sid_hi
///
/// Eliminates duplicate logic in check_match / cmd_check / cmd_verify.
fn compute_software_id(sid_lo: u32, sid_hi: u8, mix_lo: u32, mix_hi: u32) -> String {
    let final_lo = sid_lo ^ mix_lo;
    let final_hi = ((sid_hi as u32) | 0x100) ^ mix_hi;
    software_id::encode(((final_hi as u64) << 32) | (final_lo as u64))
}

/// Write a u64 as 20-byte ASCII decimal (zero-padded), avoiding format! heap allocation
#[inline(always)]
fn write_serial(buf: &mut [u8; SERIAL_LEN], mut n: u64) {
    for i in (0..SERIAL_LEN).rev() {
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
}

/// Increment the BCD buffer by 1 (only modifies the changed low digits)
///
/// Silently wraps to zero on all-9s overflow (requires 10^20 iterations, unreachable in practice).
#[inline(always)]
fn increment_bcd(buf: &mut [u8; SERIAL_LEN]) {
    for i in (0..SERIAL_LEN).rev() {
        if buf[i] < b'9' {
            buf[i] += 1;
            return;
        }
        buf[i] = b'0';
    }
}

/// Strip a leading run of `pad_byte` (keeping at least one symbol), left-justify, and
/// right-pad with spaces to fill the rest. Works with any alphabet's zero symbol;
/// for the default alphabet, `pad_byte = b'0'`. E.g.:
/// `"00000000000000000123"` -> `"123                 "`.
#[inline(always)]
fn leading_pad_to_space_padded(buf: &[u8; SERIAL_LEN], pad_byte: u8) -> [u8; SERIAL_LEN] {
    let first_significant = buf
        .iter()
        .position(|&b| b != pad_byte)
        .unwrap_or(SERIAL_LEN - 1);
    let mut out = [SPACE_PADDING; SERIAL_LEN];
    let sig_len = SERIAL_LEN - first_significant;
    out[..sig_len].copy_from_slice(&buf[first_significant..]);
    out
}

/// Write `n` as a `SERIAL_LEN`-byte string in the given `alphabet`'s base (`alphabet.len()`),
/// right-justified, left-padded with `alphabet[0]` -- the arbitrary-base generalization of
/// `write_serial` (which is exactly this function specialized to `alphabet = b"0123456789"`).
/// `alphabet` must be non-empty (checked by the caller, `validate_alphabet`).
#[inline(always)]
fn write_candidate(buf: &mut [u8; SERIAL_LEN], mut n: u128, alphabet: &[u8]) {
    let base = alphabet.len() as u128;
    for i in (0..SERIAL_LEN).rev() {
        buf[i] = alphabet[(n % base) as usize];
        n /= base;
    }
}

/// Increment a candidate buffer by 1 in the given `alphabet`'s base -- the arbitrary-base
/// generalization of `increment_bcd`. Silently wraps to all-`alphabet[0]` on overflow of the
/// whole buffer; search stops before repeating a finite small-alphabet space.
#[inline(always)]
fn increment_candidate(buf: &mut [u8; SERIAL_LEN], alphabet: &[u8]) {
    let base = alphabet.len();
    for i in (0..SERIAL_LEN).rev() {
        let idx = alphabet
            .iter()
            .position(|&c| c == buf[i])
            .expect("buffer byte must be a member of the search alphabet");
        if idx + 1 < base {
            buf[i] = alphabet[idx + 1];
            return;
        }
        buf[i] = alphabet[0];
    }
}

/// Validate and return a `search --alphabet` value as bytes, or exit with an error.
///
/// Requires: non-empty, at least 2 distinct symbols (a 1-symbol "alphabet" can't count),
/// every symbol a distinct ASCII alphanumeric character (matching `is_valid_serial`'s
/// charset, minus `-` which wouldn't make sense as a counting digit).
fn validate_alphabet(alphabet: &str) -> Vec<u8> {
    let bytes = alphabet.as_bytes().to_vec();
    if bytes.len() < 2 {
        eprintln!(
            "Error: --alphabet must have at least 2 symbols (got {:?})",
            alphabet
        );
        std::process::exit(1);
    }
    if !bytes.iter().all(|b| b.is_ascii_alphanumeric()) {
        eprintln!(
            "Error: --alphabet '{}' must contain only ASCII letters/digits",
            alphabet
        );
        std::process::exit(1);
    }
    let mut sorted = bytes.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != bytes.len() {
        eprintln!(
            "Error: --alphabet '{}' contains duplicate symbols",
            alphabet
        );
        std::process::exit(1);
    }
    bytes
}

/// Valid Serial characters: `[0-9A-Za-z-]`
fn is_valid_serial(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Valid Model characters: `[0-9A-Za-z- ]` (including space)
fn is_valid_model(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b' ')
}

/// Build the serial byte array (20 bytes), left-padding pure digits with '0'
/// (e.g. `"123"` → `"00000000000000000123"`). This is one of two real-world-observed
/// padding conventions -- see `build_serial_bytes_space_pad` for the other. Neither is
/// universally correct on its own: some real serials are stored literally zero-padded,
/// while §8.62's live RouterOS boot test showed a real disk's short numeric serial is
/// space-padded by `keyman` at read time, not zero-padded. `cmd_check` computes both
/// and reports whichever ones differ, rather than guessing a single convention.
fn build_serial_bytes_zero_pad(serial: &str) -> [u8; SERIAL_LEN] {
    let sb = serial.as_bytes();
    warn_serial_len(serial, sb);
    let is_numeric = !sb.is_empty() && sb.iter().all(|b| b.is_ascii_digit());
    if is_numeric {
        let mut bytes = [b'0'; SERIAL_LEN];
        let copy_len = sb.len().min(SERIAL_LEN);
        let offset = SERIAL_LEN - copy_len;
        bytes[offset..].copy_from_slice(&sb[..copy_len]);
        bytes
    } else {
        build_serial_bytes_space_pad(serial)
    }
}

/// Build the serial byte array (20 bytes): left-justify the serial text, right-pad with
/// spaces (e.g. `"123"` → `"123                 "`, `"ABCD"` → `"ABCD                "`).
///
/// Confirmed as keyman's own real behavior via disassembly (the 20-byte buffer is
/// zero-filled, then every remaining zero byte is unconditionally replaced with a space)
/// and via a real end-to-end RouterOS boot test: changing a live QEMU USB device's
/// `serial=` property from a pre-padded 20-digit value to a short 7-digit numeric value
/// ("2142239") produced the SOFTWARE ID matching this space-pad computation, not
/// zero-pad (docs/investigation/license-internals.md §8.62) -- see
/// `build_serial_bytes_zero_pad`'s doc comment for why both are still computed.
fn build_serial_bytes_space_pad(serial: &str) -> [u8; SERIAL_LEN] {
    let sb = serial.as_bytes();
    warn_serial_len(serial, sb);
    let mut bytes = [SPACE_PADDING; SERIAL_LEN];
    let copy_len = sb.len().min(SERIAL_LEN);
    bytes[..copy_len].copy_from_slice(&sb[..copy_len]);
    bytes
}

/// Shared invalid-character/length warnings for both serial-padding conventions.
fn warn_serial_len(serial: &str, sb: &[u8]) {
    if !is_valid_serial(serial) {
        eprintln!("Warning: serial '{}' contains invalid characters", serial);
    }
    if sb.len() > SERIAL_LEN {
        eprintln!(
            "Warning: serial '{}' truncated to {} bytes",
            serial, SERIAL_LEN
        );
    }
}

/// Build the model byte array (space-padded to 16 bytes)
fn build_model_bytes(model: &str) -> [u8; MODEL_LEN] {
    let mut bytes = [SPACE_PADDING; MODEL_LEN];
    let mb = model.as_bytes();
    if !is_valid_model(model) {
        eprintln!("Warning: model '{}' contains invalid characters", model);
    }
    if mb.len() > MODEL_LEN {
        eprintln!(
            "Warning: model '{}' truncated to {} bytes",
            model, MODEL_LEN
        );
    }
    let copy_len = mb.len().min(MODEL_LEN);
    bytes[..copy_len].copy_from_slice(&mb[..copy_len]);
    bytes
}

/// Convert an exact disk size in bytes to sector_val
fn disk_bytes_to_sector_val(total_bytes: u64) -> u32 {
    software_id::round_sectors(((total_bytes / 512) >> 11) as u32)
}

/// Resolve sector_val for the given bus type.
///
/// `ide` uses the standard, real-hardware-verified rounding rule (`disk_bytes_to_sector_val`).
/// `scsi` forces `sector_val=0` regardless of disk size -- confirmed against 7 real boot tests
/// on a single 1GiB ARM64 VM (docs/license-internals.md §8.11-8.13), not yet verified at other
/// disk sizes.
fn sector_val_for_bus(bus: BusType, total_bytes: u64) -> u32 {
    match bus {
        BusType::Ide | BusType::Nvme => disk_bytes_to_sector_val(total_bytes),
        BusType::Scsi => 0,
    }
}

/// Build the SHA-256 input buffer (serial + model + sector_val)
fn build_input_buf(
    serial: &[u8; SERIAL_LEN],
    model_bytes: &[u8; MODEL_LEN],
    sv_bytes: &[u8; 4],
) -> [u8; INPUT_LEN] {
    let mut buf = [SPACE_PADDING; INPUT_LEN];
    buf[..SERIAL_LEN].copy_from_slice(serial);
    buf[SERIAL_LEN..SERIAL_LEN + MODEL_LEN].copy_from_slice(model_bytes);
    buf[SERIAL_LEN + MODEL_LEN..].copy_from_slice(sv_bytes);
    buf
}

// ---- Main entry ----

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Search {
            disk_size,
            unit,
            threads,
            model,
            keys,
            count,
            from,
            identity,
            bus,
            mbr_table,
            pad,
            alphabet,
            device,
        } => cmd_search(
            disk_size, unit, threads, model, keys, count, from, identity, bus, mbr_table, pad,
            alphabet, device,
        ),
        Commands::Sig2key { signature_hex } => cmd_sig2key(&signature_hex),
        Commands::Key2sig { key_file_or_text } => cmd_key2sig(&key_file_or_text),
        Commands::Verify => cmd_verify(),
        Commands::Check {
            serial,
            disk_size,
            unit,
            model,
            keys,
            identity,
            bus,
            license,
        } => cmd_check(
            &serial, disk_size, unit, model, keys, identity, bus, license,
        ),
        Commands::Completions { shell } => {
            generate(shell, &mut Cli::command(), "mtsc", &mut io::stdout());
        }
    }
}

// ---- search command ----

/// Execute the collision search
#[allow(clippy::too_many_arguments)] // Direct CLI plumbing, kept separate from hot-loop state.
fn cmd_search(
    disk_size: Option<u64>,
    unit: SizeUnit,
    threads: Option<usize>,
    model: Option<String>,
    keys: Option<String>,
    count: usize,
    from: u64,
    identity: Option<String>,
    bus: BusType,
    mbr_table_path: Option<String>,
    pad: PadPosition,
    alphabet: String,
    device: DeviceChoice,
) {
    let (total_bytes, size_label) = resolve_disk_size(disk_size, unit, bus);
    let sector_val = sector_val_for_bus(bus, total_bytes);
    let model = resolve_model(model, disk_size, &size_label).unwrap_or_else(|error| {
        eprintln!("Error: {error}");
        std::process::exit(1);
    });
    let num_threads = threads.unwrap_or_else(|| {
        thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });
    let alphabet_bytes = validate_alphabet(&alphabet);
    let is_default_alphabet = alphabet_bytes == b"0123456789";
    let candidate_limit = candidate_space_limit(alphabet_bytes.len());
    let start_serial = resolve_start_serial(from, candidate_limit).unwrap_or_else(|error| {
        eprintln!("Error: {error}");
        std::process::exit(1);
    });
    println!("Alphabet: '{}' (base {})", alphabet, alphabet_bytes.len());
    if let Some(limit) = candidate_limit {
        println!("Candidate space: {limit} serials; stops at exhaustion (no repeats)");
    } else {
        println!("Candidate index: u64; wraps to zero after u64::MAX");
    }

    verify_6g();

    // No --identity given: sweep all 2048 mbr_val values per candidate serial instead of a
    // single fixed identity (decided 2026-09-07, see docs/reference/mtsc-cli-plan.md).
    let sweep_mode = identity.is_none();

    let ctx = if sweep_mode {
        let raw_targets = targets::load_raw_targets(keys.as_deref());
        let table = mbr_table::MbrTable::load(mbr_table_path.as_deref());

        Arc::new(SearchContext {
            model_bytes: build_model_bytes(&model),
            sv_bytes: sector_val.to_le_bytes(),
            targets: Arc::new(Vec::new()),
            raw_targets: Some(Arc::new(raw_targets)),
            mbr_table: Some(Arc::new(table)),
            pad,
            alphabet: alphabet_bytes,
            is_default_alphabet,
            mix_lo: 0,
            mix_hi: 0,
            max_collisions: count,
            stop: Arc::new(AtomicBool::new(false)),
            found_count: Arc::new(AtomicUsize::new(0)),
            start: Instant::now(),
        })
    } else {
        let (mix_lo, mix_hi) = resolve_mix(identity.as_deref());
        let fixed_targets = targets::load_targets(keys.as_deref(), (mix_lo, mix_hi));

        Arc::new(SearchContext {
            model_bytes: build_model_bytes(&model),
            sv_bytes: sector_val.to_le_bytes(),
            targets: Arc::new(fixed_targets),
            raw_targets: None,
            mbr_table: None,
            pad,
            alphabet: alphabet_bytes,
            is_default_alphabet,
            mix_lo,
            mix_hi,
            max_collisions: count,
            stop: Arc::new(AtomicBool::new(false)),
            found_count: Arc::new(AtomicUsize::new(0)),
            start: Instant::now(),
        })
    };

    // Device selection happens after the targets exist: the GPU spec bakes the run's
    // alphabet/padding/match mode and needs the target count for its capacity.
    let gpu_devices = select_gpu_devices(&ctx, device, num_threads);
    let engine_desc = if gpu_devices.is_empty() {
        // One process-wide CPU selection, shared by fixed/sweep and every alphabet/padding mode.
        let engine = HashEngine::auto_for_threads(num_threads).unwrap_or_else(|error| {
            eprintln!("FATAL: {error}");
            std::process::exit(1);
        });
        engine.to_string()
    } else {
        gpu_devices
            .iter()
            .map(|dev| dev.name())
            .collect::<Vec<_>>()
            .join(" + ")
    };

    if sweep_mode {
        print_sweep_search_banner(
            &size_label,
            &model,
            sector_val,
            num_threads,
            ctx.raw_targets
                .as_deref()
                .map(|v| v.as_slice())
                .unwrap_or(&[]),
            count,
            start_serial,
            &engine_desc,
            gpu_devices.len(),
            bus,
            pad,
        );
    } else {
        print_search_banner(
            &size_label,
            &model,
            sector_val,
            num_threads,
            &ctx.targets,
            count,
            start_serial,
            &engine_desc,
            gpu_devices.len(),
            identity.as_deref(),
            bus,
            pad,
        );
    }

    let handles: Vec<_> = if gpu_devices.is_empty() {
        // Plain CPU thread pool; each thread strides the candidate space by its batch.
        let engine = HashEngine::auto_for_threads(num_threads).unwrap_or_else(|error| {
            eprintln!("FATAL: {error}");
            std::process::exit(1);
        });
        (0..num_threads)
            .map(|tid| {
                let ctx = Arc::clone(&ctx);
                thread::spawn(move || {
                    search_batch(tid, num_threads, start_serial, &ctx, engine);
                })
            })
            .collect()
    } else {
        // One host thread per GPU device drives huge on-device chunks; the CPU just
        // verifies and reports hits. HashEngine::auto_for_threads memoizes, so the
        // CPU description above costs nothing extra here.
        let device_count = gpu_devices.len();
        gpu_devices
            .into_iter()
            .enumerate()
            .map(|(did, dev)| {
                let ctx = Arc::clone(&ctx);
                thread::spawn(move || {
                    search_gpu(did, device_count, start_serial, &ctx, dev);
                })
            })
            .collect()
    };

    let mut worker_failed = false;
    for h in handles {
        worker_failed |= h.join().is_err();
    }
    if worker_failed {
        eprintln!("FATAL: search worker panicked");
        std::process::exit(1);
    }
    if let Some(limit) = candidate_limit {
        if !ctx.stop.load(Ordering::Relaxed) {
            println!("Candidate space exhausted at index {limit} (exclusive); no serials repeated");
        }
    }

    let total = ctx.found_count.load(Ordering::Relaxed);
    println!(
        "\nDone. {} collisions found in {}s",
        total,
        ctx.start.elapsed().as_secs()
    );
}

/// Print search startup info
#[allow(clippy::too_many_arguments)] // Presentation of the resolved CLI inputs.
fn print_search_banner(
    disk_label: &str,
    model: &str,
    sector_val: u32,
    num_threads: usize,
    targets: &[targets::Target],
    count: usize,
    start_serial: u64,
    engine_desc: &str,
    gpu_devices: usize,
    identity: Option<&str>,
    bus: BusType,
    pad: PadPosition,
) {
    let mode_str = if count == 0 {
        "unlimited".to_string()
    } else {
        format!("find {}", count)
    };

    println!("=== RouterOS L6 Serial Generator ===");
    println!(
        "Disk: {}  Model: {}  SV: 0x{:X}",
        disk_label, model, sector_val
    );
    match bus {
        BusType::Ide => {
            println!("Bus: ide (verified against real hardware; also covers sata0/AHCI)")
        }
        BusType::Nvme => {
            println!("Bus: nvme (same sector_val rounding as ide)")
        }
        BusType::Scsi => {
            println!("Bus: scsi (scsi0/virtio-scsi-pci only, NOT sata0; sector_val forced to 0)");
            println!("  WARNING: this encoding is validated against 7 real boot tests on a single");
            println!(
                "  1GiB ARM64 VM only (docs/license-internals.md §8.11-8.13). sector_val=0 has"
            );
            println!("  not been confirmed at other disk sizes -- verify any hit on real hardware");
            println!("  before relying on it.");
        }
    }
    match identity {
        Some(hex) => println!(
            "Identity: {} (custom, non-standard mix)",
            hex.to_uppercase()
        ),
        None => println!("Identity: 00000000000000000000 (standard, all-zero mix)"),
    }
    match pad {
        PadPosition::Start => println!("Serial pad: start (left-pad with alphabet's first symbol)"),
        PadPosition::End => {
            println!("Serial pad: end (right-pad with spaces, natural digit count, default)")
        }
    }
    if gpu_devices > 0 {
        println!(
            "Devices: {}  Targets: {}  Mode: {}  Engine: {}",
            gpu_devices,
            targets.len(),
            mode_str,
            engine_desc
        );
        println!("Threads: GPU mode (one host thread per device; --threads ignored)");
    } else {
        println!(
            "Threads: {}  Targets: {}  Mode: {}  Engine: {}",
            num_threads,
            targets.len(),
            mode_str,
            engine_desc
        );
    }
    if start_serial > 0 {
        println!(
            "Start: {}M (serial {})",
            start_serial / 1_000_000,
            start_serial
        );
    }
    println!();

    for t in targets {
        println!(
            "  {} need_lo=0x{:08X} need_hi=0x{:03X}",
            t.name, t.need_lo, t.need_hi
        );
    }
    println!("\nSearching...\n");
}

/// Print search startup info for full-mbr_val-sweep mode (no fixed `--identity`)
#[allow(clippy::too_many_arguments)] // Presentation of the resolved CLI inputs.
fn print_sweep_search_banner(
    disk_label: &str,
    model: &str,
    sector_val: u32,
    num_threads: usize,
    targets: &[targets::RawTarget],
    count: usize,
    start_serial: u64,
    engine_desc: &str,
    gpu_devices: usize,
    bus: BusType,
    pad: PadPosition,
) {
    let mode_str = if count == 0 {
        "unlimited".to_string()
    } else {
        format!("find {}", count)
    };

    println!("=== RouterOS L6 Serial Generator (mbr_val full-space sweep) ===");
    println!(
        "Disk: {}  Model: {}  SV: 0x{:X}",
        disk_label, model, sector_val
    );
    match bus {
        BusType::Ide => {
            println!("Bus: ide (verified against real hardware; also covers sata0/AHCI)")
        }
        BusType::Nvme => println!("Bus: nvme (same sector_val rounding as ide)"),
        BusType::Scsi => {
            println!("Bus: scsi (scsi0/virtio-scsi-pci only, NOT sata0; sector_val forced to 0)")
        }
    }
    println!(
        "Identity: sweeping all 2048 mbr_val values per candidate serial (no fixed --identity)"
    );
    match pad {
        PadPosition::Start => println!("Serial pad: start (left-pad with alphabet's first symbol)"),
        PadPosition::End => {
            println!("Serial pad: end (right-pad with spaces, natural digit count, default)")
        }
    }
    if gpu_devices > 0 {
        println!(
            "Devices: {}  Targets: {}  Mode: {}  Engine: {}",
            gpu_devices,
            targets.len(),
            mode_str,
            engine_desc
        );
        println!("Threads: GPU mode (one host thread per device; --threads ignored)");
    } else {
        println!(
            "Threads: {}  Targets: {}  Mode: {}  Engine: {}",
            num_threads,
            targets.len(),
            mode_str,
            engine_desc
        );
    }
    if start_serial > 0 {
        println!(
            "Start: {}M (serial {})",
            start_serial / 1_000_000,
            start_serial
        );
    }
    println!();

    for t in targets {
        println!(
            "  {} tv_lo=0x{:08X} tv_hi=0x{:02X}",
            t.name, t.tv_lo, t.tv_hi
        );
    }
    println!("\nSearching...\n");
}

// ---- Search engines ----

/// Search with a previously selected backend and its native batch size.
/// Small alphabets stop at their 20-symbol limit; wider ones retain u64 wrapping.
fn search_batch(
    tid: usize,
    num_threads: usize,
    start_serial: u64,
    ctx: &SearchContext,
    engine: HashEngine,
) {
    let mut hashes = HashBatch::new(engine, &ctx.model_bytes, &ctx.sv_bytes);
    let batch = hashes.len() as u64;
    let step = (num_threads as u64) * batch;
    let offset = (tid as u64) * batch;
    let limit = candidate_space_limit(ctx.alphabet.len());
    let mut base = if let Some(limit) = limit {
        match start_serial.checked_add(offset) {
            Some(base) if base < limit => base,
            _ => return,
        }
    } else {
        start_serial.wrapping_add(offset)
    };
    let mut base_serial = [ctx.alphabet[0]; SERIAL_LEN];
    ctx.write_candidate(&mut base_serial, base);
    let sweep_mode = ctx.raw_targets.is_some();
    // Full-width target comparison: values outside 256..512 cannot match.
    let mut hi_lookup = [false; 512];
    if !sweep_mode {
        for t in ctx.targets.iter() {
            if (256..512).contains(&t.need_hi) {
                hi_lookup[t.need_hi as usize] = true;
            }
        }
    }

    loop {
        if ctx.stop.load(Ordering::Relaxed) {
            return;
        }
        let active = limit.map_or(batch, |limit| batch.min(limit - base)) as usize;
        let mut lane_serial = base_serial;
        for lane in 0..hashes.len() {
            // Kernels always hash a full native batch. Fill every serial completely;
            // unused tail lanes are harmless duplicates and their results are ignored.
            *hashes.serial_mut(lane) = ctx.pad_candidate(&lane_serial);
            if lane + 1 < active {
                if base.wrapping_add(lane as u64) == u64::MAX {
                    lane_serial.fill(ctx.alphabet[0]);
                } else {
                    ctx.increment_candidate(&mut lane_serial);
                }
            }
        }
        hashes.hash();
        for (lane, &(sid_lo, sid_hi)) in hashes.outputs().iter().take(active).enumerate() {
            let index = base.wrapping_add(lane as u64);
            if sweep_mode {
                sweep_check_match(index, sid_lo, sid_hi, ctx);
            } else if hi_lookup[(sid_hi as usize) | 0x100] {
                check_match(index, sid_lo, sid_hi, ctx);
            }
        }

        let previous_base = base;
        if let Some(limit) = limit {
            match base.checked_add(step) {
                Some(next) if next < limit => base = next,
                _ => return,
            }
        } else {
            base = base.wrapping_add(step);
        }
        // Numeric and character counters must agree across both kinds of carry.
        if step <= 256 && base >= previous_base {
            for _ in 0..step {
                ctx.increment_candidate(&mut base_serial);
            }
        } else {
            ctx.write_candidate(&mut base_serial, base);
        }
        if tid == 0 && (base / PROGRESS_INTERVAL) != (previous_base / PROGRESS_INTERVAL) {
            report_progress(base, &ctx.start, &ctx.found_count);
        }
    }
}

// ---- GPU search ----

/// Candidate indices per GPU kernel launch. Large enough to amortize launch and
/// readback overhead, small enough for responsive stop/progress checks on any
/// current GPU (16M candidates at ≥64M hashes/s → ≤250ms per chunk).
const GPU_CHUNK: u64 = 1 << 24;

/// Chunk size for the auto-mode throughput race (a few launches, ≥200ms).
const GPU_SAMPLE_CHUNK: u64 = 1 << 25;

/// Build the kernel spec describing this run's serial construction and match mode.
fn gpu_kernel_spec(ctx: &SearchContext) -> gpu::GpuKernelSpec {
    let capacity = ctx
        .raw_targets
        .as_ref()
        .map_or(ctx.targets.len(), |raw| raw.len())
        .max(gpu_probe_indices().len());
    gpu::GpuKernelSpec {
        alphabet: ctx.alphabet.clone(),
        pad_end: matches!(ctx.pad, PadPosition::End),
        sweep: ctx.raw_targets.is_some(),
        w5_9: precompute_constant_words(&ctx.model_bytes, &ctx.sv_bytes),
        capacity,
    }
}

/// Probe indices for the GPU startup self-check: small values, a mid-range value, and
/// the two largest u64 indices. The second self-check run additionally wraps past
/// u64::MAX back to index 0, so 0 must NOT be a probe (it would hit its target twice
/// and fail the exact-set comparison).
fn gpu_probe_indices() -> [u64; 6] {
    [1, 2, 17, 999, u64::MAX - 1, u64::MAX]
}

/// Build the GPU self-check contract from scalar reference hashes: one target per
/// probe index (constructed in the run's own match mode), two runs covering the
/// probes — a dense block from zero and a small block at the top of the u64 range.
fn gpu_self_check_plan(ctx: &SearchContext) -> gpu::GpuSelfCheck {
    let sweep = ctx.raw_targets.is_some();
    let probe_mbr_vals = [0u16, 1, 2, 0x0BD, 0x123, 0x7FF];
    let mut targets = Vec::with_capacity(gpu_probe_indices().len());
    let mut expect = Vec::with_capacity(gpu_probe_indices().len());
    for (k, &index) in gpu_probe_indices().iter().enumerate() {
        let mut serial = [ctx.alphabet[0]; SERIAL_LEN];
        ctx.write_candidate(&mut serial, index);
        let serial = ctx.pad_candidate(&serial);
        let (sid_lo, sid_hi) =
            sha256::hash_40(&build_input_buf(&serial, &ctx.model_bytes, &ctx.sv_bytes));
        let (lo, hi) = if sweep {
            // Sweep probes: pick a feasible mbr_val and derive the raw target value
            // that exactly this candidate's digest can encode to.
            let mix = (probe_mbr_vals[k] as u64) * targets::MIX_MULTIPLIER;
            (
                sid_lo ^ mix as u32,
                ((sid_hi as u32) | 0x100) ^ (mix >> 32) as u32,
            )
        } else {
            // Fixed probes: need_hi is compared against (sid_hi | 0x100), full width.
            (sid_lo, (sid_hi as u32) | 0x100)
        };
        targets.push((lo, hi));
        expect.push(gpu::GpuHit {
            index,
            sid_lo,
            sid_hi,
            target_idx: k as u32,
        });
    }
    gpu::GpuSelfCheck {
        // Second run crosses u64::MAX, exercising the kernel's wrapping index add.
        runs: vec![(0, 1024), (u64::MAX - 1, 3)],
        targets,
        expect,
    }
}

/// The run's target list in GPU match form: fixed `(need_lo, need_hi)` pairs, or the
/// sweep's raw `(tv_lo, tv_hi)` values.
fn gpu_run_targets(ctx: &SearchContext) -> Vec<(u32, u32)> {
    if let Some(raw) = ctx.raw_targets.as_ref() {
        raw.iter().map(|t| (t.tv_lo, t.tv_hi)).collect()
    } else {
        ctx.targets.iter().map(|t| (t.need_lo, t.need_hi)).collect()
    }
}

/// Trust-but-verify GPU hits against the scalar path, then report them through the
/// exact same verification and reporting code as CPU hits.
fn handle_gpu_hits(ctx: &SearchContext, hits: &[gpu::GpuHit]) {
    for hit in hits {
        // Recompute the digest from the candidate index on the scalar path;
        // disagreement means a device error, not a collision.
        let mut serial = [ctx.alphabet[0]; SERIAL_LEN];
        ctx.write_candidate(&mut serial, hit.index);
        let serial = ctx.pad_candidate(&serial);
        let actual = sha256::hash_40(&build_input_buf(&serial, &ctx.model_bytes, &ctx.sv_bytes));
        if actual != (hit.sid_lo, hit.sid_hi) {
            eprintln!(
                "Warning: dropped GPU hit at index {}: device digest disagrees with scalar reference",
                hit.index
            );
            continue;
        }
        if ctx.raw_targets.is_some() {
            sweep_check_match(hit.index, hit.sid_lo, hit.sid_hi, ctx);
        } else {
            check_match(hit.index, hit.sid_lo, hit.sid_hi, ctx);
        }
    }
}

/// Compile, self-check, and return the GPU devices to search with, honoring the
/// `--device` choice. `gpu` is a hard error when nothing usable remains. `auto`
/// races the GPU fleet's measured throughput against the CPU engine's and keeps the
/// GPUs only when their combined rate wins — measured, because the answer genuinely
/// flips by machine (NVIDIA dGPU ≫ any CPU; an M4's ARM-SHA2 CPU beats its own GPU).
fn select_gpu_devices(
    ctx: &SearchContext,
    choice: DeviceChoice,
    num_threads: usize,
) -> Vec<Box<dyn gpu::GpuDevice>> {
    if choice == DeviceChoice::Cpu {
        return Vec::new();
    }
    if !gpu::backend_compiled_in() {
        if choice == DeviceChoice::Gpu {
            eprintln!(
                "Error: --device gpu requested but no GPU backend is compiled in; \
                 build on a machine with the CUDA toolkit (NVIDIA) or on macOS (Metal), \
                 or force with --features cuda / --features metal"
            );
            std::process::exit(1);
        }
        return Vec::new();
    }
    let plan = gpu_self_check_plan(ctx);
    let mut checked = Vec::new();
    for mut device in gpu::compile_devices(&gpu_kernel_spec(ctx)) {
        match gpu::self_check(device.as_mut(), &plan) {
            Ok(()) => checked.push(device),
            Err(error) => {
                if choice == DeviceChoice::Gpu {
                    eprintln!("FATAL: {}: {error}", device.name());
                    std::process::exit(1);
                }
                eprintln!(
                    "Warning: {} failed its startup self-check, falling back: {error}",
                    device.name()
                );
            }
        }
    }
    if checked.is_empty() {
        if choice == DeviceChoice::Gpu {
            eprintln!("Error: no usable GPU device found (--device gpu); see warnings above");
            std::process::exit(1);
        }
        return Vec::new();
    }
    if choice == DeviceChoice::Gpu {
        return checked;
    }

    // Auto: race combined GPU throughput against the CPU engine's measured rate.
    let limit = candidate_space_limit(ctx.alphabet.len());
    let probe = gpu::GpuRun {
        base: 0,
        n: GPU_SAMPLE_CHUNK.min(limit.unwrap_or(GPU_SAMPLE_CHUNK)),
        targets: gpu_run_targets(ctx),
    };
    let mut rates = Vec::new();
    for device in checked.iter_mut() {
        let (rate, hits) = gpu::sample_rate(device.as_mut(), &probe);
        handle_gpu_hits(ctx, &hits);
        if rate <= 0.0 {
            eprintln!(
                "Warning: {} failed during throughput sampling, excluding it",
                device.name()
            );
        }
        rates.push(rate);
    }
    let fleet_rate: f64 = rates.iter().sum();
    let mut rate_iter = rates.into_iter();
    checked.retain(|_| rate_iter.next().is_some_and(|rate| rate > 0.0));
    if checked.is_empty() {
        eprintln!("Note: no GPU device survived sampling -- using the CPU pool");
        return Vec::new();
    }
    let cpu_engine = HashEngine::auto_for_threads(num_threads).unwrap_or_else(|error| {
        eprintln!("FATAL: {error}");
        std::process::exit(1);
    });
    let cpu_rate = cpu_engine
        .sample_rate_hz(num_threads)
        .unwrap_or_else(|error| {
            eprintln!("FATAL: {error}");
            std::process::exit(1);
        });
    if fleet_rate <= cpu_rate {
        eprintln!(
            "Note: CPU wins the measured race ({:.0} vs {:.0} MH/s GPU) -- use --device gpu to force GPU",
            cpu_rate / 1e6,
            fleet_rate / 1e6
        );
        return Vec::new();
    }
    checked
}

/// Drive one GPU device through the candidate space in `GPU_CHUNK` blocks, strided
/// across devices the same way CPU threads stride their batches. Hits are re-hashed
/// on the CPU scalar path before reporting, then flow through the exact same
/// verification and reporting code as CPU hits.
fn search_gpu(
    did: usize,
    device_count: usize,
    start_serial: u64,
    ctx: &SearchContext,
    mut device: Box<dyn gpu::GpuDevice>,
) {
    let chunk = GPU_CHUNK;
    let step = (device_count as u64) * chunk;
    let offset = (did as u64) * chunk;
    let limit = candidate_space_limit(ctx.alphabet.len());
    let mut base = if let Some(limit) = limit {
        match start_serial.checked_add(offset) {
            Some(base) if base < limit => base,
            _ => return,
        }
    } else {
        start_serial.wrapping_add(offset)
    };
    let targets = gpu_run_targets(ctx);

    loop {
        if ctx.stop.load(Ordering::Relaxed) {
            return;
        }
        // The final block before a finite candidate limit can be short; the kernel
        // hashes whatever n says, no padding lanes involved.
        let active = limit.map_or(chunk, |limit| chunk.min(limit - base));
        let hits = device
            .run(&gpu::GpuRun {
                base,
                n: active,
                targets: targets.clone(),
            })
            .unwrap_or_else(|error| {
                eprintln!("FATAL: {}: {error}", device.name());
                std::process::exit(1);
            });
        handle_gpu_hits(ctx, &hits);

        let previous_base = base;
        if let Some(limit) = limit {
            match base.checked_add(step) {
                Some(next) if next < limit => base = next,
                _ => return,
            }
        } else {
            base = base.wrapping_add(step);
        }
        if did == 0 && (base / PROGRESS_INTERVAL) != (previous_base / PROGRESS_INTERVAL) {
            report_progress(base, &ctx.start, &ctx.found_count);
        }
    }
}

/// Rebuild the reported serial and independently hash it before accepting a hit.
/// Compare full SOFTWARE IDs as well as the backend's raw digest, including sweep mix.
fn verify_search_hit(
    index: u64,
    digest: (u32, u8),
    mix: (u32, u32),
    expected_sid: &str,
    ctx: &SearchContext,
) -> Result<([u8; SERIAL_LEN], String), &'static str> {
    let mut serial = [ctx.alphabet[0]; SERIAL_LEN];
    ctx.write_candidate(&mut serial, index);
    let serial = ctx.pad_candidate(&serial);
    let actual = sha256::hash_40(&build_input_buf(&serial, &ctx.model_bytes, &ctx.sv_bytes));
    if actual != digest {
        return Err("search hit failed scalar serial/digest verification");
    }
    let sid = compute_software_id(actual.0, actual.1, mix.0, mix.1);
    if software_id::decode(&sid).ok() != software_id::decode(expected_sid).ok() {
        return Err("search hit failed full SOFTWARE ID verification");
    }
    Ok((serial, sid))
}

/// Check whether a hash result matches any target (only formats serial on a hit)
fn check_match(serial_num: u64, sid_lo: u32, sid_hi: u8, ctx: &SearchContext) {
    for t in ctx.targets.iter() {
        if ((sid_hi as u32) | 0x100) == t.need_hi && sid_lo == t.need_lo {
            let (sbuf, sid) = verify_search_hit(
                serial_num,
                (sid_lo, sid_hi),
                (ctx.mix_lo, ctx.mix_hi),
                &t.name,
                ctx,
            )
            .unwrap_or_else(|error| {
                eprintln!("FATAL: {error}");
                std::process::exit(1);
            });
            let n = ctx.found_count.fetch_add(1, Ordering::Relaxed) + 1;
            let serial_str = std::str::from_utf8(&sbuf).unwrap();

            println!(
                "FOUND [{}] serial={} target={} verified={}",
                n, serial_str, t.name, sid
            );

            if ctx.max_collisions > 0 && n >= ctx.max_collisions {
                ctx.stop.store(true, Ordering::Relaxed);
            }
        }
    }
}

/// Check a hash result against every raw target across the full mbr_val space (0-2047) --
/// used when `search` is run without `--identity`. Unlike `check_match`'s single-fixed-mix
/// comparison, this can find a hit for any mbr_val, not just the one a fixed identity bakes in.
///
/// TODO: reports every feasible target for this serial rather than stopping at the first
/// (decided 2026-09-07) -- change to first-match-wins if multi-target hits per serial turn
/// out noisy in practice. At current target counts this is astronomically rare either way.
fn sweep_check_match(serial_num: u64, sid_lo: u32, sid_hi: u8, ctx: &SearchContext) {
    let raw_targets = ctx
        .raw_targets
        .as_ref()
        .expect("sweep_check_match requires SearchContext::raw_targets");
    let mbr_table = ctx
        .mbr_table
        .as_ref()
        .expect("sweep_check_match requires SearchContext::mbr_table");

    for t in raw_targets.iter() {
        let required = targets::required_mix(sid_lo, sid_hi, t.tv_lo, t.tv_hi);
        if let Some(mbr_val) = targets::feasible_mbr_val(required) {
            let (identity_hex, marker_hex) = mbr_table.lookup(mbr_val);
            let mix = targets::mix_from_identity(&parse_identity_hex(identity_hex));
            let (sbuf, sid) = verify_search_hit(serial_num, (sid_lo, sid_hi), mix, &t.name, ctx)
                .unwrap_or_else(|error| {
                    eprintln!("FATAL: {error}");
                    std::process::exit(1);
                });
            let n = ctx.found_count.fetch_add(1, Ordering::Relaxed) + 1;
            let serial_str = std::str::from_utf8(&sbuf).unwrap();
            println!(
                "FOUND [{}] serial={} target={} mbr_val={} identity={} marker={} verified={}",
                n, serial_str, t.name, mbr_val, identity_hex, marker_hex, sid
            );

            if ctx.max_collisions > 0 && n >= ctx.max_collisions {
                ctx.stop.store(true, Ordering::Relaxed);
            }
        }
    }
}

/// Print progress to stderr
fn report_progress(hashes: u64, start: &Instant, found_count: &AtomicUsize) {
    let elapsed = start.elapsed().as_secs();
    let fc = found_count.load(Ordering::Relaxed);
    eprintln!("{}M hashes, {}s, {} found", hashes / 1_000_000, elapsed, fc);
}

// ---- Other commands ----

/// Convert a signature hex to License Key text
fn cmd_sig2key(hex: &str) {
    print_metadata(hex);
}

/// Convert Key text to signature hex. `input` is treated as a file path if it names an
/// existing file; otherwise it's treated as the key text itself (any of the three forms
/// `key_text_to_signature` accepts -- see `convert.rs`).
fn cmd_key2sig(input: &str) {
    let content = if std::path::Path::new(input).is_file() {
        match std::fs::read_to_string(input) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Cannot read {}: {}", input, e);
                return;
            }
        }
    } else {
        input.to_string()
    };

    match convert::key_text_to_signature(&content) {
        Ok(sig) => print_metadata(&sig),
        Err(e) => eprintln!("Error: {}", e),
    }
}

/// Print a signature's full metadata to stdout: decoded fields, the raw MBR hex blob, and the
/// equivalent `.key` file text -- everything derivable from a 64-byte signature, in one unified
/// layout, regardless of whether the caller started from hex (`sig2key`) or a `.key` file
/// (`key2sig`). Field labels/format match the reference `MTLic`-style parser output (see
/// docs/license-internals.md §8.32).
///
/// `MBR Signature (hex)` is the full 64-byte blob (payload+nonce+signature) as written to MBR
/// 0x110-0x14F -- distinct from the `Signature:` field above it, which is only the trailing
/// 32-byte EC-KCDSA signature scalar (bytes 32..64 of this same blob).
fn print_metadata(signature_hex: &str) {
    match convert::decode_metadata(signature_hex) {
        Ok(m) => {
            println!("  Software ID: {}", m.software_id);
            println!("  Router OS Version: {}", m.version_byte);
            println!("  License Level: {}", m.level);
            println!("  Nonce Hash: {}", m.nonce_hash);
            println!("  Signature: {}", m.signature);

            let valid = match convert::decode_verify_inputs(signature_hex) {
                Ok((payload, nonce_hash, signature)) => Some(curve25519::verify(
                    &payload,
                    &nonce_hash,
                    &signature,
                    &curve25519::LICENSE_PUBLIC_KEY,
                )),
                Err(_) => None,
            };
            match valid {
                Some(v) => println!("  License valid: {}", v),
                None => println!("  License valid: (could not run EC-KCDSA verification)"),
            }

            if !m.padding_ok {
                eprintln!(
                    "  Warning: reserved bytes not all zero -- this may not be a valid signature"
                );
            }
        }
        Err(e) => eprintln!("(could not decode license metadata: {})", e),
    }

    println!("-----");
    println!("  MBR Signature (hex): {}", signature_hex);

    println!("-----");
    match convert::signature_to_key_text(signature_hex) {
        Ok(key_text) => println!("  License: {}", key_text),
        Err(e) => eprintln!("Error: {}", e),
    }
}

/// Check whether a given serial matches a known signature.
///
/// Computes SOFTWARE ID under BOTH the zero-pad and space-pad serial conventions
/// whenever they'd actually produce different bytes (pure-digit serial shorter than
/// `SERIAL_LEN`) -- neither convention is universally correct on real hardware (see
/// `build_serial_bytes_zero_pad`'s doc comment and docs/license-internals.md §8.62), so
/// `check` reports both rather than requiring a `--serial-pad`-style flag to pick one.
#[allow(clippy::too_many_arguments)] // Direct CLI plumbing, no backend hot-path state.
fn cmd_check(
    serial: &str,
    disk_size: Option<u64>,
    unit: SizeUnit,
    model: Option<String>,
    keys: Option<String>,
    identity: Option<String>,
    bus: BusType,
    license: Option<String>,
) {
    let (total_bytes, size_label) = resolve_disk_size(disk_size, unit, bus);
    let sector_val = sector_val_for_bus(bus, total_bytes);
    let model = resolve_model(model, disk_size, &size_label).unwrap_or_else(|error| {
        eprintln!("Error: {error}");
        std::process::exit(1);
    });
    let (mix_lo, mix_hi) = resolve_mix(identity.as_deref());
    let search_targets = targets::load_targets(keys.as_deref(), (mix_lo, mix_hi));
    let model_bytes = build_model_bytes(&model);

    let identity_hex = identity
        .as_deref()
        .map(|s| s.to_uppercase())
        .unwrap_or_else(|| "00000000000000000000".to_string());

    let marker = identity
        .as_deref()
        .map(|hex| targets::marker_from_identity(&parse_identity_hex(hex)))
        .unwrap_or([0xBD, 0xE8]);
    let marker_hex = format!("{:02X}{:02X}", marker[0], marker[1]);

    println!("=== Check ===");
    println!("Model:  {}", model);
    println!("Disk:   {} (SV: 0x{:X})", size_label, sector_val);
    match bus {
        BusType::Ide => println!("Bus:    ide (verified against real hardware; also covers sata0/AHCI)"),
        BusType::Nvme => println!("Bus:    nvme (same sector_val rounding as ide)"),
        BusType::Scsi => println!("Bus:    scsi (scsi0/virtio-scsi-pci only, NOT sata0; sector_val forced to 0 -- see docs/license-internals.md §8.11-8.20)"),
    }
    println!("-----------");
    println!("Identity: {}", identity_hex);
    println!("Marker: {}", marker_hex);
    println!("-----------");

    let zero_bytes = build_serial_bytes_zero_pad(serial);
    let space_bytes = build_serial_bytes_space_pad(serial);

    if zero_bytes == space_bytes {
        print_check_variant(
            None,
            &zero_bytes,
            &model_bytes,
            sector_val,
            mix_lo,
            mix_hi,
            &search_targets,
            license.as_deref(),
            &identity_hex,
            &marker_hex,
        );
    } else {
        println!("(zero-pad and space-pad differ for this serial -- computing both, see docs/license-internals.md §8.62)\n");
        print_check_variant(
            Some("zero-padded"),
            &zero_bytes,
            &model_bytes,
            sector_val,
            mix_lo,
            mix_hi,
            &search_targets,
            license.as_deref(),
            &identity_hex,
            &marker_hex,
        );
        println!();
        print_check_variant(
            Some("space-padded"),
            &space_bytes,
            &model_bytes,
            sector_val,
            mix_lo,
            mix_hi,
            &search_targets,
            license.as_deref(),
            &identity_hex,
            &marker_hex,
        );
    }
}

/// Compute and print one `check` result (SOFTWARE ID, license comparison, target match)
/// for a single already-built serial byte array. `label`, when given, is printed
/// alongside the `Serial:` line to distinguish the zero-pad/space-pad variants when
/// `cmd_check` computes both.
#[allow(clippy::too_many_arguments)]
fn print_check_variant(
    label: Option<&str>,
    serial_bytes: &[u8; SERIAL_LEN],
    model_bytes: &[u8; MODEL_LEN],
    sector_val: u32,
    mix_lo: u32,
    mix_hi: u32,
    search_targets: &[targets::Target],
    license: Option<&str>,
    identity_hex: &str,
    marker_hex: &str,
) {
    let serial_display = std::str::from_utf8(serial_bytes).unwrap_or("<invalid utf8>");
    let buf = build_input_buf(serial_bytes, model_bytes, &sector_val.to_le_bytes());
    let (sid_lo, sid_hi) = sha256::hash_40(&buf);
    let sid = compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi);

    match label {
        Some(l) => println!("Serial ({}): {}", l, serial_display),
        None => println!("Serial: {}", serial_display),
    }
    println!("Software ID: {}", sid);

    if let Some(path) = license {
        compare_license_software_id(path, &sid);
    }

    let matched = search_targets
        .iter()
        .find(|t| ((sid_hi as u32) | 0x100) == t.need_hi && sid_lo == t.need_lo);

    if let Some(t) = matched {
        println!("✅ Matched signature: {}", t.name);
        if t.signature_hex.len() >= 128 {
            println!(
                "   Signature: {}...{}",
                &t.signature_hex[..16],
                &t.signature_hex[112..]
            );
        } else {
            println!("   Signature: {}", t.signature_hex);
        }

        if let Ok(key_text) = convert::signature_to_key_text(&t.signature_hex) {
            println!("   LICENSE KEY:");
            for line in key_text.lines() {
                println!("   {}", line);
            }
        }

        println!(
            "   MBR HEX:\n   {}{}00000000{}",
            identity_hex, marker_hex, t.signature_hex
        );
    } else {
        println!("❌ No match found");
        println!("   sid_lo=0x{:08X} sid_hi=0x{:02X}", sid_lo, sid_hi);
    }
}

/// Read a license file (either `.key` text or a raw 128-char signature_hex file), decode its
/// embedded SOFTWARE ID, and compare it against the SOFTWARE ID computed from `check`'s
/// serial/model/disk-size/identity/bus inputs.
fn compare_license_software_id(path: &str, computed_sid: &str) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("\nError: cannot read license file {}: {}", path, e);
            return;
        }
    };

    let sig_hex = if content.contains("BEGIN MIKROTIK") {
        match convert::key_text_to_signature(&content) {
            Ok(sig) => sig,
            Err(e) => {
                eprintln!("\nError: cannot parse {} as a .key file: {}", path, e);
                return;
            }
        }
    } else {
        content.trim().to_string()
    };

    match convert::decode_metadata(&sig_hex) {
        Ok(m) => {
            println!("\n=== License comparison ({}) ===", path);
            println!("License SOFTWARE-ID: {}", m.software_id);
            println!("Computed SOFTWARE-ID: {}", computed_sid);
            if m.software_id == computed_sid {
                println!(
                    "✅ MATCH -- this license's SOFTWARE ID matches the given disk parameters"
                );
            } else {
                println!("❌ NO MATCH -- this license was issued for a different SOFTWARE ID");
            }
        }
        Err(e) => eprintln!("\nError: could not decode SOFTWARE-ID from {}: {}", path, e),
    }
}

/// Verify SHA-256 + SOFTWARE ID algorithms (self-consistency check)
fn cmd_verify() {
    let (mix_lo, mix_hi) = targets::mbr_mix();
    let cases = [
        ("00000000000000000001", "VMware Virtual I", 0x1800u32),
        ("00000000202155543391", "ROS16G          ", 0x4000),
    ];
    let engine = HashEngine::auto().unwrap_or_else(|error| {
        eprintln!("FATAL: {error}");
        std::process::exit(1);
    });

    println!("=== Verify (engine: {}) ===", engine);
    for (ser, model_str, sv) in &cases {
        let mut serial_bytes = [b'0'; SERIAL_LEN];
        serial_bytes[..ser.len().min(SERIAL_LEN)]
            .copy_from_slice(&ser.as_bytes()[..ser.len().min(SERIAL_LEN)]);
        let mut model_bytes = [SPACE_PADDING; MODEL_LEN];
        model_bytes.copy_from_slice(&model_str.as_bytes()[..MODEL_LEN]);
        let buf = build_input_buf(&serial_bytes, &model_bytes, &sv.to_le_bytes());

        let (sid_lo, sid_hi) = sha256::hash_40(&buf);
        let sid = compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi);
        // Self-consistency: encode → decode → re-encode must round-trip
        let ok = match software_id::decode(&sid) {
            Ok(v) if software_id::encode(v) == sid => "OK",
            _ => "FAIL",
        };
        println!("  {} → {} [{}]", &ser[..8], sid, ok);
    }
}

/// Startup self-check: verify the 6G VMware known hash value
fn verify_6g() {
    let mut serial_bytes = [b'0'; SERIAL_LEN];
    serial_bytes[..20].copy_from_slice(b"00000000000000000001");
    let model_bytes = *b"VMware Virtual I";
    let buf = build_input_buf(&serial_bytes, &model_bytes, &0x1800u32.to_le_bytes());

    let (sid_lo, sid_hi) = sha256::hash_40(&buf);
    if sid_lo != 0x0B49EC2E || sid_hi != 0x35 {
        eprintln!(
            "FATAL: SHA-256 self-check failed! sid_lo=0x{:08X} sid_hi=0x{:02X}",
            sid_lo, sid_hi
        );
        std::process::exit(1);
    }
}
