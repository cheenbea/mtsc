//! RouterOS L6 Serial Generator — computes serials from existing licenses + key conversion tool
//!
//! Selects a CPU-supported SHA-256 backend once at startup; each backend owns
//! its batch size, with portable scalar calculation retained as the reference.

mod convert;
mod curve25519;
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
use std::time::{Duration, Instant};

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
/// Candidates per GPU kernel launch. Large enough to amortize launch/sync overhead,
/// small enough that the stop flag and progress reporting stay responsive.
const GPU_CHUNK: u64 = 1 << 20;

// ---- CLI definition ----

#[derive(Parser)]
#[command(name = "mtsc")]
#[command(about = "RouterOS L6 Serial Generator — collision search & key conversion")]
#[command(version, disable_help_flag = true, disable_version_flag = true)]
struct Cli {
    /// Print help (long-form only -- this project uses no short flags, see AGENTS.md)
    #[arg(long, global = true, action = clap::ArgAction::Help)]
    help: Option<bool>,
    /// Print version (long-form only -- this project uses no short flags, see AGENTS.md)
    #[arg(long, global = true, action = clap::ArgAction::Version)]
    version: Option<bool>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Search collision serial for a disk size
    Search {
        /// Disk size magnitude (paired with --unit). Required for --bus ide/nvme; optional
        /// (and ignored) for --bus scsi, where sector_val is always forced to 0.
        #[arg(long = "size")]
        disk_size: Option<u64>,
        /// Disk size unit: g (gigabytes, default), m (megabytes), k (kilobytes), or b (bytes)
        #[arg(long, value_enum, ignore_case = true, default_value = "g")]
        unit: SizeUnit,
        /// Thread count
        #[arg(long)]
        threads: Option<usize>,
        /// Model name (default: ROS<size><unit>, e.g. ROS100G, ROS128M)
        #[arg(long)]
        model: Option<String>,
        /// keys.toml path
        #[arg(long)]
        keys: Option<String>,
        /// Number of collisions to find (default: 1, 0 = unlimited)
        #[arg(long, default_value = "1")]
        count: usize,
        /// Start from N million hashes (resume from progress output)
        #[arg(long, default_value = "0")]
        from: u64,
        /// Non-standard 20-hex-char MBR identity seed (0x100-0x109), e.g. from a real
        /// device's captured MBR. Default: sweep all 2048 possible mbr_val values per
        /// candidate serial instead of a single fixed identity (see --mbr-table).
        #[arg(long)]
        identity: Option<String>,
        /// Disk bus type: ide (default, verified against real hardware -- also covers
        /// sata0/AHCI, which uses the identical encoding), nvme (same sector_val rounding
        /// as ide), or scsi (scsi0/virtio-scsi-pci specifically, NOT sata0 -- forces
        /// sector_val=0; see docs/license-internals.md §8.11-8.20; end-to-end activation
        /// confirmed on x86_64, §8.18).
        #[arg(long, value_enum, ignore_case = true, default_value = "ide")]
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
        #[arg(long = "size")]
        disk_size: Option<u64>,
        /// Disk size unit: g (gigabytes, default), m (megabytes), k (kilobytes), or b (bytes)
        #[arg(long, value_enum, ignore_case = true, default_value = "g")]
        unit: SizeUnit,
        /// Model name (default: ROS<size><unit>, e.g. ROS100G, ROS128M, ROS67108864B)
        #[arg(long)]
        model: Option<String>,
        /// keys.toml path
        #[arg(long)]
        keys: Option<String>,
        /// Non-standard 20-hex-char MBR identity seed (0x100-0x109), e.g. from a real
        /// device's captured MBR. Default: standard all-zero identity used by collision search.
        #[arg(long)]
        identity: Option<String>,
        /// Disk bus type: ide (default, verified against real hardware -- also covers
        /// sata0/AHCI, which uses the identical encoding), nvme (same sector_val rounding
        /// as ide), or scsi (scsi0/virtio-scsi-pci specifically, NOT sata0 -- forces
        /// sector_val=0; see docs/license-internals.md §8.11-8.20; end-to-end activation
        /// confirmed on x86_64, §8.18).
        #[arg(long, value_enum, ignore_case = true, default_value = "ide")]
        bus: BusType,
        /// Path to a .key license file (or a raw 128-char signature_hex file) to compare
        /// against the SOFTWARE ID computed from serial/model/disk-size/identity/bus above.
        #[arg(long)]
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

/// Disk size unit, paired with the `--size` magnitude
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

/// Resolve `--size`/`--unit` against the selected bus, enforcing that they're required
/// for buses where disk size actually affects sector_val (ide/nvme) while remaining optional
/// (and ignored) for buses where it doesn't (scsi -- sector_val is always forced to 0).
/// Exits the process if disk_size is missing on a bus that needs it.
fn resolve_disk_size(disk_size: Option<u64>, unit: SizeUnit, bus: BusType) -> (u64, String) {
    match disk_size {
        Some(magnitude) => {
            validate_disk_size(magnitude, unit);
            if bus.size_irrelevant() {
                eprintln!(
                    "Warning: --size/--unit have no effect on the SOFTWARE ID for --bus scsi \
                     (sector_val is always 0); they only shape the default --model name. \
                     Omit --size/--unit, or pass --model explicitly, to avoid relying on them."
                );
            }
            disk_size_bytes_and_label(magnitude, unit)
        }
        None if bus.size_irrelevant() => (0, "N/A (scsi, size ignored)".to_string()),
        None => {
            eprintln!(
                "Error: --size is required for --bus ide/nvme (only optional for --bus scsi)"
            );
            std::process::exit(1);
        }
    }
}

/// Parse a 20-hex-char `--identity` argument into the 10-byte MBR identity seed.
/// Exits the process on malformed input (wrong length or non-hex characters).
fn parse_identity_hex(s: &str) -> [u8; 10] {
    let decoded = data_encoding::HEXLOWER_PERMISSIVE
        .decode(s.as_bytes())
        .ok()
        .filter(|b| b.len() == 10);
    match decoded {
        Some(bytes) => bytes.try_into().unwrap(),
        None => {
            eprintln!(
                "Error: --identity must be exactly 20 hex characters (10 bytes), got '{}' ({} chars)",
                s,
                s.len()
            );
            std::process::exit(1);
        }
    }
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
    raw_targets: Option<Arc<targets::RawTargets>>,
    /// `Some` only in full-mbr_val-sweep mode -- pairs with `raw_targets`.
    mbr_table: Option<Arc<mbr_table::MbrTable>>,
    /// Where padding goes for numeric candidate serials shorter than `SERIAL_LEN` bytes
    /// -- see `PadPosition`.
    pad: PadPosition,
    mix_lo: u32,
    mix_hi: u32,
    max_collisions: usize,
    stop: Arc<AtomicBool>,
    found_count: Arc<AtomicUsize>,
    start: Instant,
}

/// Fixed candidate alphabet: digits then uppercase letters, base 36. Not user-configurable
/// -- there is no `--alphabet` flag; every search always counts over this exact symbol set.
const SEARCH_ALPHABET: &[u8; 36] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// `SEARCH_ALPHABET[i] as usize -> i` reverse lookup, built once at compile time. Lets
/// `increment_search_candidate` find a byte's alphabet index in O(1) (one array read)
/// instead of the generic `increment_candidate`'s O(alphabet length) `.position()` scan --
/// see `docs/benchmarks/README.md`'s "Future optimization opportunities". `u8::MAX` marks
/// bytes that aren't in `SEARCH_ALPHABET` at all (never actually read for those, since
/// every candidate byte is always a `SEARCH_ALPHABET` member by construction).
const SEARCH_ALPHABET_REVERSE: [u8; 256] = {
    let mut table = [u8::MAX; 256];
    let mut i = 0;
    while i < SEARCH_ALPHABET.len() {
        table[SEARCH_ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// O(1)-per-digit specialization of `increment_candidate` for the fixed `SEARCH_ALPHABET`,
/// via `SEARCH_ALPHABET_REVERSE`. This is the one actually used by `search`'s hot loop
/// (`SearchContext::increment_candidate` below) -- the generic `increment_candidate`
/// function stays as the reference implementation for arbitrary alphabets, exercised by
/// this project's own tests, and cross-validated against this fast path (see
/// `test_increment_search_candidate_matches_generic`).
#[inline(always)]
fn increment_search_candidate(buf: &mut [u8; SERIAL_LEN]) {
    const BASE: usize = SEARCH_ALPHABET.len();
    for byte in buf.iter_mut().rev() {
        let idx = SEARCH_ALPHABET_REVERSE[*byte as usize] as usize;
        debug_assert!(
            idx < BASE,
            "buffer byte must be a member of SEARCH_ALPHABET"
        );
        if idx + 1 < BASE {
            *byte = SEARCH_ALPHABET[idx + 1];
            return;
        }
        *byte = SEARCH_ALPHABET[0];
    }
}

impl SearchContext {
    /// Encode an index without changing the counter's fixed-width representation.
    #[inline]
    fn write_candidate(&self, serial: &mut [u8; SERIAL_LEN], index: u64) {
        write_candidate(serial, index as u128, SEARCH_ALPHABET);
    }

    /// Advance the fixed-width counter, never a space-padded hashing buffer.
    #[inline]
    fn increment_candidate(&self, serial: &mut [u8; SERIAL_LEN]) {
        increment_search_candidate(serial);
    }

    /// Produce all 20 serial bytes while preserving the model/sector suffix.
    #[inline]
    fn pad_candidate(&self, serial: &[u8; SERIAL_LEN]) -> [u8; SERIAL_LEN] {
        match self.pad {
            PadPosition::Start => *serial,
            PadPosition::End => leading_pad_to_space_padded(serial, SEARCH_ALPHABET[0]),
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
        None => Err("--model is required when --size is omitted (--bus scsi)"),
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
/// right-justified, left-padded with `alphabet[0]`. `alphabet` must be non-empty (this
/// project only ever calls it with the fixed `SEARCH_ALPHABET`).
#[inline(always)]
fn write_candidate(buf: &mut [u8; SERIAL_LEN], mut n: u128, alphabet: &[u8]) {
    let base = alphabet.len() as u128;
    for i in (0..SERIAL_LEN).rev() {
        buf[i] = alphabet[(n % base) as usize];
        n /= base;
    }
}

/// Increment a candidate buffer by 1 in the given `alphabet`'s base. Silently wraps to
/// all-`alphabet[0]` on overflow of the whole buffer; search stops before repeating a
/// finite small-alphabet space.
///
/// No longer called from production code (`SearchContext::increment_candidate` uses the
/// O(1) `increment_search_candidate` fast path instead) -- kept only as the
/// arbitrary-alphabet reference implementation `increment_search_candidate` is
/// cross-validated against in tests. `#[allow(dead_code)]` per this project's own
/// documented clippy exception (`AGENTS.md`: "cargo clippy zero warnings (except
/// dead_code)"), since a plain (non-test) build has no callers for it at all.
#[allow(dead_code)]
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
        } => cmd_search(
            disk_size, unit, threads, model, keys, count, from, identity, bus, mbr_table, pad,
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
    let candidate_limit = candidate_space_limit(SEARCH_ALPHABET.len());
    let start_serial = resolve_start_serial(from, candidate_limit).unwrap_or_else(|error| {
        eprintln!("Error: {error}");
        std::process::exit(1);
    });
    // One process-wide selection, shared by fixed/sweep and every padding mode.
    let engine = HashEngine::auto_for_threads(num_threads).unwrap_or_else(|error| {
        eprintln!("FATAL: {error}");
        std::process::exit(1);
    });
    println!(
        "Alphabet: '{}' (base {}, fixed)",
        std::str::from_utf8(SEARCH_ALPHABET).unwrap(),
        SEARCH_ALPHABET.len()
    );
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

        print_sweep_search_banner(
            &size_label,
            &model,
            sector_val,
            num_threads,
            &raw_targets,
            count,
            start_serial,
            engine,
            bus,
            pad,
        );

        Arc::new(SearchContext {
            model_bytes: build_model_bytes(&model),
            sv_bytes: sector_val.to_le_bytes(),
            targets: Arc::new(Vec::new()),
            raw_targets: Some(Arc::new(raw_targets)),
            mbr_table: Some(Arc::new(table)),
            pad,
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

        print_search_banner(
            &size_label,
            &model,
            sector_val,
            num_threads,
            &fixed_targets,
            count,
            start_serial,
            engine,
            identity.as_deref(),
            bus,
            pad,
        );

        Arc::new(SearchContext {
            model_bytes: build_model_bytes(&model),
            sv_bytes: sector_val.to_le_bytes(),
            targets: Arc::new(fixed_targets),
            raw_targets: None,
            mbr_table: None,
            pad,
            mix_lo,
            mix_hi,
            max_collisions: count,
            stop: Arc::new(AtomicBool::new(false)),
            found_count: Arc::new(AtomicUsize::new(0)),
            start: Instant::now(),
        })
    };

    // Automatic GPU/CPU selection: try to compile and self-check GPU device(s), then race
    // a short measured rate against the CPU engine. Every failure mode here (no backend
    // compiled in for this platform, no device present, self-check disagreement, a device
    // erroring during the benchmark) falls back to the CPU path silently (an informational
    // note only) -- there is no way to force GPU-only or CPU-only, and GPU problems must
    // never abort the search or exit the process.
    let gpu_devices = select_gpu_devices(&ctx, engine, num_threads, start_serial);

    let handles: Vec<_> = if gpu_devices.is_empty() {
        (0..num_threads)
            .map(|tid| {
                let ctx = Arc::clone(&ctx);
                thread::spawn(move || {
                    search_batch(tid, num_threads, start_serial, &ctx, engine);
                })
            })
            .collect()
    } else {
        let targets_list = Arc::new(gpu_target_list(&ctx));
        let num_devices = gpu_devices.len();
        gpu_devices
            .into_iter()
            .enumerate()
            .map(|(did, dev)| {
                let ctx = Arc::clone(&ctx);
                let targets_list = Arc::clone(&targets_list);
                thread::spawn(move || {
                    search_gpu_device(dev, did, num_devices, start_serial, &ctx, &targets_list);
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
    engine: HashEngine,
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
    println!(
        "Threads: {}  Targets: {}  Mode: {}  Engine: {}",
        num_threads,
        targets.len(),
        mode_str,
        engine
    );
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
    targets: &targets::RawTargets,
    count: usize,
    start_serial: u64,
    engine: HashEngine,
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
    println!(
        "Threads: {}  Targets: {}  Mode: {}  Engine: {}",
        num_threads,
        targets.len(),
        mode_str,
        engine
    );
    if start_serial > 0 {
        println!(
            "Start: {}M (serial {})",
            start_serial / 1_000_000,
            start_serial
        );
    }
    println!();

    for (i, (&tv_lo, &tv_hi)) in targets.tv_lo.iter().zip(targets.tv_hi.iter()).enumerate() {
        println!(
            "  {} tv_lo=0x{:08X} tv_hi=0x{:02X}",
            targets.name(i),
            tv_lo,
            tv_hi
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
    let limit = candidate_space_limit(SEARCH_ALPHABET.len());
    let mut base = if let Some(limit) = limit {
        match start_serial.checked_add(offset) {
            Some(base) if base < limit => base,
            _ => return,
        }
    } else {
        start_serial.wrapping_add(offset)
    };
    let mut base_serial = [SEARCH_ALPHABET[0]; SERIAL_LEN];
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
    // Reused across every `sweep_check_match` call this thread makes, so the overwhelmingly
    // common no-hit case never allocates (`Vec::new()` doesn't allocate until first push, and
    // `.clear()` after a rare hit keeps the capacity for next time). Keeps the per-target scan
    // loop free of any call/allocation, which is what actually lets it stay a tight,
    // branch-light loop -- see `sweep_check_match`'s doc comment.
    let mut sweep_hits: Vec<(usize, u16)> = Vec::new();

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
                    lane_serial.fill(SEARCH_ALPHABET[0]);
                } else {
                    ctx.increment_candidate(&mut lane_serial);
                }
            }
        }
        hashes.hash();
        for (lane, &(sid_lo, sid_hi)) in hashes.outputs().iter().take(active).enumerate() {
            let index = base.wrapping_add(lane as u64);
            if sweep_mode {
                sweep_check_match(index, sid_lo, sid_hi, ctx, &mut sweep_hits);
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

/// Rebuild the reported serial and independently hash it before accepting a hit.
/// Compare full SOFTWARE IDs as well as the backend's raw digest, including sweep mix.
fn verify_search_hit(
    index: u64,
    digest: (u32, u8),
    mix: (u32, u32),
    expected_sid: &str,
    ctx: &SearchContext,
) -> Result<([u8; SERIAL_LEN], String), &'static str> {
    let mut serial = [SEARCH_ALPHABET[0]; SERIAL_LEN];
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
/// Split into two passes on purpose (see `docs/benchmarks/README.md`'s "Future optimization
/// opportunities" -- this implements the first one): a hot scan over every target that does
/// *only* arithmetic (`required_mix`/`feasible_mbr_val`, both already O(1)) with no calls, no
/// identity lookups, and no printing, followed by a cold reporting pass that only runs for the
/// (astronomically rare) targets the scan actually flagged. Real hits happen on the order of
/// once per ~10^12 candidates, so keeping the scan itself free of anything but pure arithmetic
/// is what gives the compiler its best chance to auto-vectorize it -- interleaving a `println!`/
/// MBR-table lookup/independent-rehash call into the same loop, as the previous version did,
/// defeats that regardless of how cheap the arithmetic itself is. `hits` is caller-owned and
/// reused across calls so the common (empty) case never allocates.
///
/// TODO: reports every feasible target for this serial rather than stopping at the first
/// (decided 2026-09-07) -- change to first-match-wins if multi-target hits per serial turn
/// out noisy in practice. At current target counts this is astronomically rare either way.
///
/// Perf note (2026-09-13): a follow-up attempt replaced the `.iter().enumerate()` loop
/// below with `mem::take`-owned-local-`Vec` plus `unsafe get_unchecked` indexing, aimed at
/// a ~16% self-time chunk `perf` attributed to slice-iterator/`Vec`-pointer bookkeeping.
/// Re-profiled: that specific cost dropped to ~0%, but an equivalent (slightly larger)
/// cost reappeared as a bounds-check comparison plus `Vec`-internal pointer reads --
/// net effect was a wash, not an improvement. Reverted rather than keeping `unsafe` code
/// that adds review/maintenance cost for zero measured benefit. Also per the same
/// profiling, `ctx.raw_targets` is now `targets::RawTargets`, a structure-of-arrays layout
/// (flat `tv_lo`/`tv_hi`) instead of a `Vec` of one struct per target -- see
/// `docs/benchmarks/README.md`. The real lever for the ~75% spent in
/// `required_mix`/`feasible_mbr_val` themselves is SIMD, not loop-mechanics shuffling; SoA
/// is a prerequisite for that, not a replacement for it.
fn sweep_check_match(
    serial_num: u64,
    sid_lo: u32,
    sid_hi: u8,
    ctx: &SearchContext,
    hits: &mut Vec<(usize, u16)>,
) {
    let raw_targets = ctx
        .raw_targets
        .as_ref()
        .expect("sweep_check_match requires SearchContext::raw_targets");

    debug_assert!(hits.is_empty(), "caller must pass a drained scratch buffer");
    let tv_pairs = raw_targets.tv_lo.iter().zip(raw_targets.tv_hi.iter());
    for (i, (&tv_lo, &tv_hi)) in tv_pairs.enumerate() {
        let required = targets::required_mix(sid_lo, sid_hi, tv_lo, tv_hi);
        if let Some(mbr_val) = targets::feasible_mbr_val(required) {
            hits.push((i, mbr_val));
        }
    }

    if hits.is_empty() {
        return;
    }

    let mbr_table = ctx
        .mbr_table
        .as_ref()
        .expect("sweep_check_match requires SearchContext::mbr_table");
    for &(i, mbr_val) in hits.iter() {
        let name = raw_targets.name(i);
        let (identity_hex, marker_hex) = mbr_table.lookup(mbr_val);
        let mix = targets::mix_from_identity(&parse_identity_hex(identity_hex));
        let (sbuf, sid) = verify_search_hit(serial_num, (sid_lo, sid_hi), mix, name, ctx)
            .unwrap_or_else(|error| {
                eprintln!("FATAL: {error}");
                std::process::exit(1);
            });
        let n = ctx.found_count.fetch_add(1, Ordering::Relaxed) + 1;
        let serial_str = std::str::from_utf8(&sbuf).unwrap();
        println!(
            "FOUND [{}] serial={} target={} mbr_val={} identity={} marker={} verified={}",
            n, serial_str, name, mbr_val, identity_hex, marker_hex, sid
        );

        if ctx.max_collisions > 0 && n >= ctx.max_collisions {
            ctx.stop.store(true, Ordering::Relaxed);
        }
    }
    hits.clear();
}

/// Print progress to stderr
fn report_progress(hashes: u64, start: &Instant, found_count: &AtomicUsize) {
    let elapsed = start.elapsed().as_secs();
    let fc = found_count.load(Ordering::Relaxed);
    eprintln!("{}M hashes, {}s, {} found", hashes / 1_000_000, elapsed, fc);
}

// ---- GPU device selection and driving ----

/// The comparison target list a compiled GPU kernel checks each candidate against:
/// fixed mode `(need_lo, need_hi)` pairs (mirrors `check_match`), sweep mode raw
/// `(tv_lo, tv_hi)` pairs (mirrors `sweep_check_match`) -- see `gpu::GpuRun::targets`.
fn gpu_target_list(ctx: &SearchContext) -> Vec<(u32, u32)> {
    match ctx.raw_targets.as_ref() {
        Some(raw) => raw
            .tv_lo
            .iter()
            .zip(raw.tv_hi.iter())
            .map(|(&lo, &hi)| (lo, hi))
            .collect(),
        None => ctx.targets.iter().map(|t| (t.need_lo, t.need_hi)).collect(),
    }
}

/// Build the per-run kernel spec for `ctx`'s exact serial construction and match mode.
/// `capacity` is the real target count (at least 1 -- `gpu::kernel_source` requires it).
fn build_gpu_kernel_spec(ctx: &SearchContext, num_targets: usize) -> gpu::GpuKernelSpec {
    gpu::GpuKernelSpec {
        alphabet: SEARCH_ALPHABET.to_vec(),
        pad_end: matches!(ctx.pad, PadPosition::End),
        sweep: ctx.raw_targets.is_some(),
        w5_9: precompute_constant_words(&ctx.model_bytes, &ctx.sv_bytes),
        capacity: num_targets.max(1),
    }
}

/// Build a self-check that is independent of the user's real targets: hash one known
/// candidate index (`probe_index`) on the CPU scalar reference, then construct a single
/// synthetic target that a correct kernel must unconditionally match at that index --
/// `(sid_lo, sid_hi|0x100)` is a direct hit in fixed mode, and collapses `required_mix`'s
/// XOR to zero (mbr_val 0, always feasible) in sweep mode, so the exact same target pair
/// works for either mode. A positive-control run containing `probe_index` must reproduce
/// exactly this one hit; a disjoint negative-control run must reproduce none -- agreement
/// on both exercises the whole on-device pipeline (serial generation, padding, hashing,
/// match logic) against the scalar reference, per `gpu::GpuSelfCheck`'s contract.
fn build_gpu_self_check(ctx: &SearchContext, start_serial: u64) -> gpu::GpuSelfCheck {
    let probe_index = start_serial.wrapping_add(4096);
    let mut serial = [SEARCH_ALPHABET[0]; SERIAL_LEN];
    ctx.write_candidate(&mut serial, probe_index);
    let serial = ctx.pad_candidate(&serial);
    let (sid_lo, sid_hi) =
        sha256::hash_40(&build_input_buf(&serial, &ctx.model_bytes, &ctx.sv_bytes));
    let need_hi = (sid_hi as u32) | 0x100;
    gpu::GpuSelfCheck {
        runs: vec![
            (probe_index.wrapping_sub(2048), 4096), // positive control: contains probe_index
            (start_serial, 1024),                   // negative control: disjoint from it
        ],
        targets: vec![(sid_lo, need_hi)],
        expect: vec![gpu::GpuHit {
            index: probe_index,
            sid_lo,
            sid_hi,
            target_idx: 0,
        }],
    }
}

/// Attempt automatic GPU selection: compile devices, self-check each against the CPU
/// scalar reference, and keep only the ones that agree. Every failure mode (no backend
/// compiled in for this platform, no device present, a self-check disagreement) is
/// reported with an informational `eprintln!` and an empty `Vec` -- the caller then runs
/// the existing CPU path. Never exits the process and never panics on a GPU problem.
fn usable_gpu_devices(
    ctx: &SearchContext,
    num_targets: usize,
    start_serial: u64,
) -> Vec<Box<dyn gpu::GpuDevice>> {
    let spec = build_gpu_kernel_spec(ctx, num_targets);
    let mut devices = gpu::compile_devices(&spec);
    if devices.is_empty() {
        return Vec::new();
    }
    let check = build_gpu_self_check(ctx, start_serial);
    let mut good = Vec::new();
    for mut dev in devices.drain(..) {
        let name = dev.name();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            gpu::self_check(dev.as_mut(), &check)
        })) {
            Ok(Ok(())) => good.push(dev),
            Ok(Err(error)) => {
                eprintln!("Info: GPU device {name} failed self-check, skipping: {error}")
            }
            Err(_) => eprintln!("Info: GPU device {name} self-check panicked, skipping"),
        }
    }
    good
}

/// Automatic GPU/CPU selection for the search that's about to run. Returns the GPU
/// devices to drive the search on, or an empty `Vec` to use the existing CPU path.
/// GPU problems at any stage (compile, self-check, benchmark) are reported with an
/// informational note and silently fall back to CPU -- never a hard error.
fn select_gpu_devices(
    ctx: &SearchContext,
    engine: HashEngine,
    num_threads: usize,
    start_serial: u64,
) -> Vec<Box<dyn gpu::GpuDevice>> {
    let targets_list = gpu_target_list(ctx);
    let mut good = usable_gpu_devices(ctx, targets_list.len(), start_serial);
    if good.is_empty() {
        eprintln!("Info: no usable GPU device found; using CPU");
        return Vec::new();
    }

    let bench_run = gpu::GpuRun {
        base: start_serial,
        n: GPU_CHUNK,
        targets: targets_list,
    };
    let mut best_rate = 0.0_f64;
    let mut names = Vec::with_capacity(good.len());
    for dev in good.iter_mut() {
        names.push(dev.name());
        let (rate, hits) = gpu::sample_rate(dev.as_mut(), &bench_run);
        // A real collision found during benchmarking must never be silently dropped.
        for hit in &hits {
            report_gpu_hit(hit, ctx);
        }
        if rate > best_rate {
            best_rate = rate;
        }
    }

    let cpu_rate = engine
        .sample_rate_hz(num_threads, Duration::from_millis(100))
        .unwrap_or(0.0);
    if best_rate > cpu_rate {
        println!(
            "GPU: using {} device(s) [{}] (~{:.1}M hash/s vs CPU ~{:.1}M hash/s)",
            good.len(),
            names.join(", "),
            best_rate / 1e6,
            cpu_rate / 1e6
        );
        good
    } else {
        eprintln!(
            "Info: GPU device(s) [{}] benchmarked slower than CPU (~{:.1}M vs ~{:.1}M hash/s); using CPU",
            names.join(", "),
            best_rate / 1e6,
            cpu_rate / 1e6
        );
        Vec::new()
    }
}

/// Report and verify one GPU-reported hit exactly as `check_match`/`sweep_check_match`
/// do for the CPU path: independently rehash on the CPU scalar reference before ever
/// printing or counting it (a GPU-reported digest is advisory only, per `gpu::GpuHit`'s
/// doc comment). Fixed mode maps `target_idx` straight into `ctx.targets`; sweep mode
/// recomputes `required_mix`/`feasible_mbr_val` from the target's raw `(tv_lo, tv_hi)`
/// to recover `mbr_val`, mirroring `sweep_check_match`'s cold reporting path exactly.
fn report_gpu_hit(hit: &gpu::GpuHit, ctx: &SearchContext) {
    if let Some(raw_targets) = ctx.raw_targets.as_ref() {
        let idx = hit.target_idx as usize;
        let (Some(&tv_lo), Some(&tv_hi)) = (raw_targets.tv_lo.get(idx), raw_targets.tv_hi.get(idx))
        else {
            eprintln!(
                "FATAL: GPU-reported target_idx {idx} is out of range for the loaded targets"
            );
            std::process::exit(1);
        };
        let required = targets::required_mix(hit.sid_lo, hit.sid_hi, tv_lo, tv_hi);
        let Some(mbr_val) = targets::feasible_mbr_val(required) else {
            eprintln!(
                "FATAL: GPU-reported sweep hit failed the CPU required_mix/feasible_mbr_val re-check"
            );
            std::process::exit(1);
        };
        let mbr_table = ctx
            .mbr_table
            .as_ref()
            .expect("sweep mode always carries an mbr_table");
        let name = raw_targets.name(idx);
        let (identity_hex, marker_hex) = mbr_table.lookup(mbr_val);
        let mix = targets::mix_from_identity(&parse_identity_hex(identity_hex));
        let (sbuf, sid) = verify_search_hit(hit.index, (hit.sid_lo, hit.sid_hi), mix, name, ctx)
            .unwrap_or_else(|error| {
                eprintln!("FATAL: {error}");
                std::process::exit(1);
            });
        let n = ctx.found_count.fetch_add(1, Ordering::Relaxed) + 1;
        let serial_str = std::str::from_utf8(&sbuf).unwrap();
        println!(
            "FOUND [{}] serial={} target={} mbr_val={} identity={} marker={} verified={} (gpu)",
            n, serial_str, name, mbr_val, identity_hex, marker_hex, sid
        );
        if ctx.max_collisions > 0 && n >= ctx.max_collisions {
            ctx.stop.store(true, Ordering::Relaxed);
        }
    } else {
        let idx = hit.target_idx as usize;
        let Some(t) = ctx.targets.get(idx) else {
            eprintln!(
                "FATAL: GPU-reported target_idx {idx} is out of range for the loaded targets"
            );
            std::process::exit(1);
        };
        let (sbuf, sid) = verify_search_hit(
            hit.index,
            (hit.sid_lo, hit.sid_hi),
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
            "FOUND [{}] serial={} target={} verified={} (gpu)",
            n, serial_str, t.name, sid
        );
        if ctx.max_collisions > 0 && n >= ctx.max_collisions {
            ctx.stop.store(true, Ordering::Relaxed);
        }
    }
}

/// Drive one GPU device over its share of the candidate space (device `did` of
/// `num_devices`, interleaved by `GPU_CHUNK`-sized launches -- the same partition
/// pattern `search_batch` uses for CPU threads, just at launch granularity instead of
/// per-candidate). Any device error aborts only this device's share and stops the whole
/// search cleanly (matches `ctx.stop`'s existing contract) rather than panicking or
/// exiting the process -- a mid-run GPU fault is not a reason to lose already-found hits
/// or crash a search other devices/threads are still contributing to.
fn search_gpu_device(
    mut dev: Box<dyn gpu::GpuDevice>,
    did: usize,
    num_devices: usize,
    start_serial: u64,
    ctx: &SearchContext,
    targets_list: &[(u32, u32)],
) {
    let limit = candidate_space_limit(SEARCH_ALPHABET.len());
    let step = GPU_CHUNK.saturating_mul(num_devices as u64);
    let offset = GPU_CHUNK.saturating_mul(did as u64);
    let mut base = match limit {
        Some(limit) => match start_serial.checked_add(offset) {
            Some(base) if base < limit => base,
            _ => return,
        },
        None => start_serial.wrapping_add(offset),
    };
    let mut run = gpu::GpuRun {
        base,
        n: 0,
        targets: targets_list.to_vec(),
    };

    loop {
        if ctx.stop.load(Ordering::Relaxed) {
            return;
        }
        let n = match limit {
            Some(limit) => GPU_CHUNK.min(limit - base),
            None => GPU_CHUNK,
        };
        if n == 0 {
            return;
        }
        run.base = base;
        run.n = n;
        match dev.run(&run) {
            Ok(hits) => {
                for hit in &hits {
                    report_gpu_hit(hit, ctx);
                    if ctx.stop.load(Ordering::Relaxed) {
                        return;
                    }
                }
            }
            Err(error) => {
                eprintln!(
                    "Warning: GPU device {} errored during search, stopping: {error}",
                    dev.name()
                );
                ctx.stop.store(true, Ordering::Relaxed);
                return;
            }
        }

        let previous_base = base;
        match limit {
            Some(limit) => match base.checked_add(step) {
                Some(next) if next < limit => base = next,
                _ => return,
            },
            None => base = base.wrapping_add(step),
        }
        if did == 0 && (base / PROGRESS_INTERVAL) != (previous_base / PROGRESS_INTERVAL) {
            report_progress(base, &ctx.start, &ctx.found_count);
        }
    }
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
            println!("  Features: {}", m.features);
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

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SizeUnit::min_magnitude ----

    #[test]
    fn test_min_magnitude_gb_is_1() {
        assert_eq!(SizeUnit::G.min_magnitude(), 1);
    }

    #[test]
    fn test_min_magnitude_mb_is_64() {
        assert_eq!(SizeUnit::M.min_magnitude(), 64);
    }

    #[test]
    fn test_min_magnitude_bytes_is_64mb_in_bytes() {
        assert_eq!(SizeUnit::B.min_magnitude(), 64 * 1024 * 1024);
    }

    #[test]
    fn test_min_magnitude_kb_is_64mb_in_kb() {
        assert_eq!(SizeUnit::K.min_magnitude(), 64 * 1024);
    }

    // ---- sector_val_for_bus ----

    #[test]
    fn test_sector_val_for_bus_ide_matches_standard_rounding() {
        let total_bytes = 6 * 1024 * 1024 * 1024u64; // 6G, matches the known 0x1800 test vector
        assert_eq!(sector_val_for_bus(BusType::Ide, total_bytes), 0x1800);
    }

    #[test]
    fn test_sector_val_for_bus_scsi_is_always_zero() {
        // Confirmed via 7 real boot tests on a 1GiB ARM64 VM (docs §8.11-8.13) -- scsi mode
        // forces sector_val=0 regardless of disk size.
        for total_bytes in [
            1024 * 1024 * 1024u64,
            6 * 1024 * 1024 * 1024,
            100 * 1024 * 1024 * 1024,
        ] {
            assert_eq!(sector_val_for_bus(BusType::Scsi, total_bytes), 0);
        }
    }

    // ---- disk_size_bytes_and_label ----

    #[test]
    fn test_disk_size_gb() {
        let (bytes, label) = disk_size_bytes_and_label(100, SizeUnit::G);
        assert_eq!(bytes, 100 * 1024 * 1024 * 1024);
        assert_eq!(label, "100G");
    }

    #[test]
    fn test_disk_size_mb_128() {
        let (bytes, label) = disk_size_bytes_and_label(128, SizeUnit::M);
        assert_eq!(bytes, 128 * 1024 * 1024);
        assert_eq!(label, "128M");
    }

    #[test]
    fn test_disk_size_mb_256_512() {
        assert_eq!(
            disk_size_bytes_and_label(256, SizeUnit::M).0,
            256 * 1024 * 1024
        );
        assert_eq!(
            disk_size_bytes_and_label(512, SizeUnit::M).0,
            512 * 1024 * 1024
        );
    }

    #[test]
    fn test_disk_size_mb_vs_gb_distinct() {
        let (mb_bytes, _) = disk_size_bytes_and_label(1, SizeUnit::M);
        let (gb_bytes, _) = disk_size_bytes_and_label(1, SizeUnit::G);
        assert_eq!(gb_bytes, mb_bytes * 1024);
    }

    #[test]
    fn test_disk_size_bytes_unit_passthrough() {
        // For SizeUnit::B, magnitude IS the byte count (bytes_per_unit == 1)
        let (bytes, label) = disk_size_bytes_and_label(67_108_864, SizeUnit::B);
        assert_eq!(bytes, 67_108_864);
        assert_eq!(label, "67108864B");
    }

    #[test]
    fn test_disk_size_bytes_matches_equivalent_mb() {
        let (bytes_via_b, _) = disk_size_bytes_and_label(134_217_728, SizeUnit::B);
        let (bytes_via_m, _) = disk_size_bytes_and_label(128, SizeUnit::M);
        assert_eq!(bytes_via_b, bytes_via_m);
    }

    #[test]
    fn test_disk_size_kb() {
        let (bytes, label) = disk_size_bytes_and_label(65_536, SizeUnit::K);
        assert_eq!(bytes, 65_536 * 1024);
        assert_eq!(label, "65536K");
    }

    #[test]
    fn test_disk_size_kb_matches_equivalent_mb() {
        let (bytes_via_k, _) = disk_size_bytes_and_label(131_072, SizeUnit::K);
        let (bytes_via_m, _) = disk_size_bytes_and_label(128, SizeUnit::M);
        assert_eq!(bytes_via_k, bytes_via_m);
    }

    // ---- leading_pad_to_space_padded (b'0') ----

    #[test]
    fn test_zero_padded_to_space_padded_zero() {
        let buf = *b"00000000000000000000";
        let out = leading_pad_to_space_padded(&buf, b'0');
        assert_eq!(&out, b"0                   ");
    }

    #[test]
    fn test_zero_padded_to_space_padded_short() {
        let buf = *b"00000000000000000123";
        let out = leading_pad_to_space_padded(&buf, b'0');
        assert_eq!(&out, b"123                 ");
    }

    #[test]
    fn test_zero_padded_to_space_padded_matches_earlier_real_disk_case() {
        // The exact scenario this feature was requested for: serial=25828501 on a real
        // disk was observed to NOT be zero-padded by the controller (a short zero-padded
        // vs. unpadded serial produced different SOFTWARE IDs when boot-tested on a real
        // VM this session) -- confirming what the space-padded form should look like.
        let buf = *b"00000000000025828501";
        let out = leading_pad_to_space_padded(&buf, b'0');
        assert_eq!(&out, b"25828501            ");
    }

    #[test]
    fn test_zero_padded_to_space_padded_full_length_no_zeros_stripped() {
        // A 20-digit value with no leading zeros: nothing to strip, output == input.
        let buf = *b"18446744073709551615"; // u64::MAX, 20 digits, leads with '1'
        let out = leading_pad_to_space_padded(&buf, b'0');
        assert_eq!(&out, &buf);
    }

    #[test]
    fn test_zero_padded_to_space_padded_leading_zero_digit_preserved() {
        // A significant digit that happens to be '0' (not a leading-zero pad byte) must
        // survive -- only the *leading* run of zero pad bytes is stripped.
        let buf = *b"00000000000000010203";
        let out = leading_pad_to_space_padded(&buf, b'0');
        assert_eq!(&out, b"10203               ");
    }

    // ---- write_candidate / increment_candidate (base-36 candidate generation) ----
    //
    // There is no `--alphabet` flag and no base-10 fast path -- SEARCH_ALPHABET (digits then
    // uppercase letters, base 36) is the only candidate space `search` ever counts over.

    #[test]
    fn test_write_candidate_base36() {
        let alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut buf = [0u8; SERIAL_LEN];
        write_candidate(&mut buf, 0, alphabet);
        assert_eq!(&buf, b"00000000000000000000");

        write_candidate(&mut buf, 35, alphabet);
        assert_eq!(&buf, b"0000000000000000000Z"); // 35 -> last symbol

        write_candidate(&mut buf, 36, alphabet);
        assert_eq!(&buf, b"00000000000000000010"); // 36 -> carries to the next position
    }

    #[test]
    fn test_increment_candidate_base36_carry() {
        let alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let mut buf = *b"0000000000000000000Z";
        increment_candidate(&mut buf, alphabet);
        assert_eq!(&buf, b"00000000000000000010");
    }

    #[test]
    fn test_increment_candidate_consistency_with_write_candidate() {
        let alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let base: u128 = 46655; // 35*36^2 + 35*36 + 35 = "0..0ZZZ"
        let mut buf = [0u8; SERIAL_LEN];
        write_candidate(&mut buf, base, alphabet);

        for i in 1..=40u128 {
            increment_candidate(&mut buf, alphabet);
            let mut expected = [0u8; SERIAL_LEN];
            write_candidate(&mut expected, base + i, alphabet);
            assert_eq!(buf, expected, "base-36 mismatch at base+{}", i);
        }
    }

    #[test]
    fn test_increment_search_candidate_matches_generic() {
        // Cross-validate the O(1)-per-digit `increment_search_candidate` (used by `search`'s
        // hot loop) against the generic O(alphabet-length) `increment_candidate` reference,
        // over a range that exercises single-digit, multi-digit, and full-buffer carries.
        let mut fast_buf = [SEARCH_ALPHABET[0]; SERIAL_LEN];
        let mut generic_buf = [SEARCH_ALPHABET[0]; SERIAL_LEN];
        for i in 1..=200_000u32 {
            increment_search_candidate(&mut fast_buf);
            increment_candidate(&mut generic_buf, SEARCH_ALPHABET);
            assert_eq!(fast_buf, generic_buf, "mismatch at step {i}");
        }
    }

    #[test]
    fn test_increment_search_candidate_wraps_like_generic_at_overflow() {
        // All-'Z' (the maximum base-36 value) must wrap to all-'0' in both implementations.
        let mut fast_buf = [b'Z'; SERIAL_LEN];
        let mut generic_buf = [b'Z'; SERIAL_LEN];
        increment_search_candidate(&mut fast_buf);
        increment_candidate(&mut generic_buf, SEARCH_ALPHABET);
        assert_eq!(fast_buf, [SEARCH_ALPHABET[0]; SERIAL_LEN]);
        assert_eq!(fast_buf, generic_buf);
    }

    #[test]
    fn test_search_alphabet_reverse_is_correct_inverse() {
        for (idx, &symbol) in SEARCH_ALPHABET.iter().enumerate() {
            assert_eq!(SEARCH_ALPHABET_REVERSE[symbol as usize] as usize, idx);
        }
    }

    #[test]
    fn test_leading_pad_to_space_padded_generalizes_zero_padded() {
        let alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        // `write_candidate` interprets `n` in base-36, so plain decimal 123 would spell
        // "3F", not "123" -- pick the base-36 value whose last 3 symbols are literally
        // '1','2','3': 1*36^2 + 2*36 + 3 = 1371.
        let mut buf = [0u8; SERIAL_LEN];
        write_candidate(&mut buf, 1371, alphabet); // "00000000000000000123"
        let out = leading_pad_to_space_padded(&buf, alphabet[0]);
        assert_eq!(&out[..3], b"123");
        assert_eq!(&out[3..], &[SPACE_PADDING; 17]);
        // Must match the b'0'-specialized case exactly for this all-digit input.
        assert_eq!(out, leading_pad_to_space_padded(&buf, b'0'));
    }

    // ---- candidate_space_limit / resolve_start_serial / resolve_model ----
    //
    // New in the backend refactor (no pre-refactor equivalent to port): the old scalar/SIMD
    // loops wrapped a u64 counter unconditionally; the batch-generic search now stops at an
    // exact candidate-space boundary for small alphabets instead of wrapping mid-space.

    #[test]
    fn test_candidate_space_limit_base36_alphabet_overflows_u64() {
        // 36^20 doesn't fit in u64 (u64::MAX ~= 1.8e19), so SEARCH_ALPHABET's space limit
        // must be None (checked_pow overflow), preserving wrap-to-zero-after-u64::MAX.
        assert_eq!(candidate_space_limit(36), None);
    }

    #[test]
    fn test_candidate_space_limit_small_alphabet_fits() {
        // 2^20 = 1_048_576, comfortably fits in u64.
        assert_eq!(candidate_space_limit(2), Some(1u64 << 20));
    }

    #[test]
    fn test_resolve_start_serial_within_limit() {
        assert_eq!(resolve_start_serial(5, Some(10_000_000)), Ok(5_000_000));
    }

    #[test]
    fn test_resolve_start_serial_exhausted_errs() {
        assert!(resolve_start_serial(5, Some(1_000_000)).is_err());
    }

    #[test]
    fn test_resolve_start_serial_no_limit_never_errs_on_reasonable_input() {
        assert_eq!(resolve_start_serial(5, None), Ok(5_000_000));
    }

    #[test]
    fn test_resolve_model_uses_disk_size_label_when_omitted() {
        assert_eq!(
            resolve_model(None, Some(6), "6G").unwrap(),
            "ROS6G".to_string()
        );
    }

    #[test]
    fn test_resolve_model_explicit_overrides_default() {
        assert_eq!(
            resolve_model(Some("Custom".to_string()), Some(6), "6G").unwrap(),
            "Custom".to_string()
        );
    }

    #[test]
    fn test_resolve_model_errors_without_disk_size_or_explicit_model() {
        assert!(resolve_model(None, None, "").is_err());
    }

    // ---- mbr_val search strategy cross-validation (Approach A vs Approach B) ----
    //
    // Two independent ways to find, for a fixed serial/model/size, which `mbr_val`
    // (0..2048) reproduces a target SOFTWARE ID when `--identity` isn't fixed:
    //
    //   Approach A ("sweep"): for each candidate, try all 2048 `mbr_val` values and
    //   compare the resulting (final_lo, final_hi) against the target's raw values.
    //   O(2048) per candidate.
    //
    //   Approach B ("feasibility check", per docs/reference/identity-reverse-search.md):
    //   for each candidate, XOR its sid_lo/sid_hi against the target directly to get the
    //   *required* mix, then check it's an exact multiple of 0x3FF800F with a quotient in
    //   0..=2047. O(1) per candidate (per target) -- no sweep needed.
    //
    // Both must find exactly the same hits. This test builds a small synthetic search
    // space with a known "needle" (a specific candidate/mbr_val pair guaranteed to hit),
    // runs both approaches over it, and asserts their hit sets agree exactly -- the same
    // cross-validation-by-independent-implementation pattern this project already uses
    // for SIMD vs. scalar SHA-256 (`test_simd_matches_scalar`).
    #[test]
    fn test_mbr_val_sweep_vs_feasibility_check_agree() {
        const N_CANDIDATES: usize = 2000;
        const NEEDLE_IDX: usize = 777;
        const NEEDLE_MBR_VAL: u32 = 555;
        const MIX_MULTIPLIER: u64 = 0x3FF800F;

        // Fixed model/disk-size context, same shape as a real `search` run.
        let model_bytes = build_model_bytes("ROS1G");
        let sector_val = disk_bytes_to_sector_val(1_073_741_824); // 1G
        let sv_bytes = sector_val.to_le_bytes();

        // Generate N_CANDIDATES consecutive serials (BCD increment, same as the real
        // search loop) and their (sid_lo, sid_hi) hashes.
        let mut serial_buf = [SEARCH_ALPHABET[0]; SERIAL_LEN];
        let mut candidates: Vec<(u32, u8)> = Vec::with_capacity(N_CANDIDATES);
        for _ in 0..N_CANDIDATES {
            let buf = build_input_buf(&serial_buf, &model_bytes, &sv_bytes);
            candidates.push(sha256::hash_40(&buf));
            increment_candidate(&mut serial_buf, SEARCH_ALPHABET);
        }

        // Plant the needle: the target is whatever SOFTWARE ID candidate NEEDLE_IDX
        // produces under NEEDLE_MBR_VAL. Computed directly (not via encode/decode --
        // those have their own tests) as the raw (target_lo, target_hi) pair, matching
        // `compute_software_id`'s real, hardware-confirmed formula (full width,
        // `(sid_hi|0x100) XOR mix_hi` -- see targets::required_mix's doc comment,
        // 2026-09-07 real-VM confirmation).
        let (needle_sid_lo, needle_sid_hi) = candidates[NEEDLE_IDX];
        let needle_mix = (NEEDLE_MBR_VAL as u64) * MIX_MULTIPLIER;
        let needle_mix_lo = needle_mix as u32;
        let needle_mix_hi = (needle_mix >> 32) as u32;
        let target_lo = needle_sid_lo ^ needle_mix_lo;
        let target_hi = ((needle_sid_hi as u32) | 0x100) ^ needle_mix_hi;

        // Approach A: sweep all 2048 mbr_val per candidate.
        let mut hits_a: Vec<(usize, u32)> = Vec::new();
        for (i, &(sid_lo, sid_hi)) in candidates.iter().enumerate() {
            for mbr_val in 0u32..2048 {
                let mix = (mbr_val as u64) * MIX_MULTIPLIER;
                let mix_lo = mix as u32;
                let mix_hi = (mix >> 32) as u32;
                let final_lo = sid_lo ^ mix_lo;
                let final_hi = ((sid_hi as u32) | 0x100) ^ mix_hi;
                if final_lo == target_lo && final_hi == target_hi {
                    hits_a.push((i, mbr_val));
                }
            }
        }

        // Approach B: feasibility check per candidate, no sweep.
        let mut hits_b: Vec<(usize, u32)> = Vec::new();
        for (i, &(sid_lo, sid_hi)) in candidates.iter().enumerate() {
            let required_mix_lo = sid_lo ^ target_lo;
            let required_mix_hi = ((sid_hi as u32) | 0x100) ^ target_hi;
            let required_mix = (required_mix_lo as u64) | ((required_mix_hi as u64) << 32);
            if required_mix.is_multiple_of(MIX_MULTIPLIER) {
                let mbr_val = required_mix / MIX_MULTIPLIER;
                if mbr_val < 2048 {
                    hits_b.push((i, mbr_val as u32));
                }
            }
        }

        assert!(
            hits_a.contains(&(NEEDLE_IDX, NEEDLE_MBR_VAL)),
            "planted needle must be found by approach A"
        );
        assert!(
            hits_b.contains(&(NEEDLE_IDX, NEEDLE_MBR_VAL)),
            "planted needle must be found by approach B"
        );
        assert_eq!(
            hits_a, hits_b,
            "sweep (A) and feasibility-check (B) must find exactly the same hits"
        );
    }

    /// Real-disk, all-`keys.toml`-targets version of the A-vs-B cross-check above: for a
    /// specific real serial/model/size, sweep all 2048 `mbr_val` (Approach A) against
    /// *every* entry in `keys.toml` and separately run the feasibility check (Approach B)
    /// against every entry, then assert the two full hit sets agree exactly -- not just a
    /// single planted needle this time, the complete result for this disk.
    ///
    /// `#[ignore]`: depends on `keys.toml` existing at the crate root at test-run time
    /// (gitignored, not present in a fresh clone/CI) -- run explicitly with
    /// `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn test_real_disk_all_targets_sweep_vs_feasibility_check_agree() {
        const MIX_MULTIPLIER: u64 = 0x3FF800F;

        let serial = "1";
        let model = "VMware Virtual SATA Hard Drive";
        let sizes: [(&str, u64); 18] = [
            ("60M", 62_914_560),
            ("128M", 128 * 1024 * 1024),
            ("256M", 256 * 1024 * 1024),
            ("512M", 512 * 1024 * 1024),
            ("1G", 1024 * 1024 * 1024),
            ("2G", 2 * 1024 * 1024 * 1024),
            ("4G", 4 * 1024 * 1024 * 1024),
            ("6G", 6 * 1024 * 1024 * 1024),
            ("8G", 8 * 1024 * 1024 * 1024),
            ("10G", 10 * 1024 * 1024 * 1024),
            ("12G", 12 * 1024 * 1024 * 1024),
            ("16G", 16 * 1024 * 1024 * 1024),
            ("18G", 18 * 1024 * 1024 * 1024),
            ("20G", 20 * 1024 * 1024 * 1024),
            ("24G", 24 * 1024 * 1024 * 1024),
            ("32G", 32 * 1024 * 1024 * 1024),
            ("48G", 48 * 1024 * 1024 * 1024),
            ("64G", 64 * 1024 * 1024 * 1024),
        ];

        let entries = targets::load_from_file("keys.toml").expect("keys.toml must be present");
        assert!(!entries.is_empty(), "keys.toml must not be empty");

        // Raw (unmasked) (name, tv_lo, tv_hi) per target -- NOT run through
        // `entries_to_targets`, which bakes in one fixed mix and masks tv_hi to u8.
        let raw_targets: Vec<(String, u32, u32)> = entries
            .iter()
            .map(|e| {
                let tv = software_id::decode(&e.software_id)
                    .unwrap_or_else(|err| panic!("invalid SOFTWARE ID {}: {}", e.software_id, err));
                (e.software_id.clone(), tv as u32, (tv >> 32) as u32)
            })
            .collect();

        for (size_label, total_bytes) in sizes {
            for (bus, bus_label) in [(BusType::Ide, "Ide"), (BusType::Scsi, "Scsi")] {
                let sector_val = sector_val_for_bus(bus, total_bytes);
                let serial_bytes = build_serial_bytes_zero_pad(serial);
                let model_bytes = build_model_bytes(model);
                let buf = build_input_buf(&serial_bytes, &model_bytes, &sector_val.to_le_bytes());
                let (sid_lo, sid_hi) = sha256::hash_40(&buf);

                // Approach A: sweep all 2048 mbr_val, check against every target. Matches
                // `compute_software_id`'s real, hardware-confirmed full-width formula
                // (`(sid_hi|0x100) XOR mix_hi`, see targets::required_mix's doc comment,
                // 2026-09-07).
                let mut hits_a: Vec<(String, u32)> = Vec::new();
                for mbr_val in 0u32..2048 {
                    let mix = (mbr_val as u64) * MIX_MULTIPLIER;
                    let mix_lo = mix as u32;
                    let mix_hi = (mix >> 32) as u32;
                    let final_lo = sid_lo ^ mix_lo;
                    let final_hi = ((sid_hi as u32) | 0x100) ^ mix_hi;
                    for (name, tv_lo, tv_hi) in &raw_targets {
                        if final_lo == *tv_lo && final_hi == *tv_hi {
                            hits_a.push((name.clone(), mbr_val));
                        }
                    }
                }

                // Approach B: feasibility check per target, no sweep.
                let mut hits_b: Vec<(String, u32)> = Vec::new();
                for (name, tv_lo, tv_hi) in &raw_targets {
                    let required_mix_lo = sid_lo ^ tv_lo;
                    let required_mix_hi = ((sid_hi as u32) | 0x100) ^ tv_hi;
                    let required_mix = (required_mix_lo as u64) | ((required_mix_hi as u64) << 32);
                    if required_mix.is_multiple_of(MIX_MULTIPLIER) {
                        let mbr_val = required_mix / MIX_MULTIPLIER;
                        if mbr_val < 2048 {
                            hits_b.push((name.clone(), mbr_val as u32));
                        }
                    }
                }
                hits_a.sort();
                hits_b.sort();

                eprintln!(
                    "[{size_label} bytes={total_bytes} {bus_label}] sid_lo=0x{sid_lo:08X} sid_hi=0x{sid_hi:02X} -- {} keys.toml targets checked",
                    raw_targets.len()
                );
                eprintln!("[{size_label} {bus_label}] Approach A hits: {hits_a:?}");
                eprintln!("[{size_label} {bus_label}] Approach B hits: {hits_b:?}");

                assert_eq!(
                    hits_a, hits_b,
                    "[{size_label} {bus_label}] sweep (A) and feasibility-check (B) must find exactly the same hits for every keys.toml target"
                );
            }
        }
    }

    // ---- compute_software_id ----

    #[test]
    fn test_compute_software_id_6g_vmware() {
        let (mix_lo, mix_hi) = targets::mbr_mix();
        let sid = compute_software_id(0x0B49EC2E, 0x35, mix_lo, mix_hi);
        // Self-consistency: result must be a valid SOFTWARE ID that round-trips
        assert_eq!(sid.len(), 9);
        assert_eq!(sid.chars().nth(4), Some('-'));
        let v = software_id::decode(&sid).expect("decode computed sid");
        assert_eq!(software_id::encode(v), sid);
    }

    #[test]
    fn test_compute_software_id_deterministic() {
        let (mix_lo, mix_hi) = targets::mbr_mix();
        let a = compute_software_id(0xAABBCCDD, 0xEE, mix_lo, mix_hi);
        let b = compute_software_id(0xAABBCCDD, 0xEE, mix_lo, mix_hi);
        assert_eq!(a, b, "same input must produce same output");
    }

    // ---- build_model_bytes ----

    #[test]
    fn test_build_model_bytes_short() {
        let bytes = build_model_bytes("ROS6G");
        assert_eq!(&bytes[..5], b"ROS6G");
        assert_eq!(bytes[5], SPACE_PADDING);
        assert_eq!(bytes[15], SPACE_PADDING);
    }

    #[test]
    fn test_build_model_bytes_exact() {
        let bytes = build_model_bytes("VMware Virtual I");
        assert_eq!(&bytes, b"VMware Virtual I");
    }

    // ---- build_serial_bytes_zero_pad / build_serial_bytes_space_pad ----
    //
    // `cmd_check` computes BOTH conventions for any serial where they'd actually differ
    // (pure digits shorter than SERIAL_LEN) rather than guessing one -- see §8.62.

    #[test]
    fn test_build_serial_bytes_zero_pad_numeric_short() {
        let bytes = build_serial_bytes_zero_pad("123");
        assert_eq!(&bytes, b"00000000000000000123");
    }

    #[test]
    fn test_build_serial_bytes_space_pad_numeric_short() {
        // Confirmed against real hardware, not just disassembly -- see §8.62.
        let bytes = build_serial_bytes_space_pad("123");
        assert_eq!(&bytes[..3], b"123");
        assert_eq!(&bytes[3..], &[SPACE_PADDING; 17]);
    }

    #[test]
    fn test_build_serial_bytes_zero_and_space_pad_agree_at_full_length() {
        // Already exactly SERIAL_LEN bytes: no padding applies, so both conventions
        // produce the identical literal pass-through.
        let zero = build_serial_bytes_zero_pad("00000000350481748276");
        let space = build_serial_bytes_space_pad("00000000350481748276");
        assert_eq!(&zero, b"00000000350481748276");
        assert_eq!(zero, space);
    }

    #[test]
    fn test_build_serial_bytes_alpha_exact() {
        // 19-char alphanumeric serial: right-padded with one trailing space to fill
        // SERIAL_LEN (20). Alphanumeric input has no meaningful "zero-pad" form, so
        // zero_pad falls back to the same space-pad result as space_pad directly.
        let zero = build_serial_bytes_zero_pad("G4HQT594JN8VLY0FGN9");
        let space = build_serial_bytes_space_pad("G4HQT594JN8VLY0FGN9");
        assert_eq!(&space, b"G4HQT594JN8VLY0FGN9 ");
        assert_eq!(zero, space);
    }

    #[test]
    fn test_build_serial_bytes_alpha_short() {
        let bytes = build_serial_bytes_space_pad("SZHYPO14090903D0164");
        // 19 chars + 1 space padding on right
        assert_eq!(&bytes[..19], b"SZHYPO14090903D0164");
        assert_eq!(bytes[19], SPACE_PADDING);
    }

    #[test]
    fn test_build_serial_bytes_with_hyphen() {
        let bytes = build_serial_bytes_space_pad("HYSSD-20160419B7902");
        assert_eq!(&bytes[..19], b"HYSSD-20160419B7902");
        assert_eq!(bytes[19], SPACE_PADDING);
    }

    #[test]
    fn test_build_serial_bytes_empty_matches_keyman_space_padding() {
        // keyman zero-fills its 20-byte serial buffer before reading the disk, then
        // sweeps the whole buffer turning every zero byte into a space -- an empty
        // (zero-length) serial therefore becomes 20 ASCII spaces, not 20 '0' chars.
        // Confirmed via keyman_x86_7.24.1 disassembly (zero-fill at 0x8050411-0x805041e,
        // pad loop at 0x8050a1e-0x8050a29, which never special-cases length 0). Both
        // functions must agree here: zero_pad's `is_numeric` check treats empty as
        // non-numeric and falls back to space_pad, matching keyman's real behavior.
        let zero = build_serial_bytes_zero_pad("");
        let space = build_serial_bytes_space_pad("");
        assert_eq!(&zero, &[SPACE_PADDING; SERIAL_LEN]);
        assert_eq!(zero, space);
    }

    // ---- parse_identity_hex / resolve_mix ----

    #[test]
    fn test_parse_identity_hex_exact_20() {
        let bytes = parse_identity_hex("0011223344556677AABB");
        assert_eq!(
            bytes,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xAA, 0xBB]
        );
    }

    #[test]
    fn test_parse_identity_hex_lowercase() {
        let bytes = parse_identity_hex("0011223344556677aabb");
        assert_eq!(
            bytes,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xAA, 0xBB]
        );
    }

    #[test]
    fn test_resolve_mix_none_matches_standard() {
        assert_eq!(resolve_mix(None), targets::mbr_mix());
    }

    #[test]
    fn test_resolve_mix_custom_matches_targets_fn() {
        let hex = "0011223344556677AABB";
        assert_eq!(
            resolve_mix(Some(hex)),
            targets::mix_from_identity(&parse_identity_hex(hex))
        );
    }

    // ---- is_valid_serial / is_valid_model ----

    #[test]
    fn test_is_valid_serial() {
        assert!(is_valid_serial("00000000350481748276"));
        assert!(is_valid_serial("G4HQT594JN8VLY0FGN9"));
        assert!(is_valid_serial("HYSSD-20160419B79028"));
        assert!(!is_valid_serial("hello world")); // space invalid
        assert!(!is_valid_serial("test@#$"));
    }

    #[test]
    fn test_is_valid_model() {
        assert!(is_valid_model("VMware Virtual I"));
        assert!(is_valid_model("ROS128G"));
        assert!(is_valid_model("cheerlon"));
        assert!(!is_valid_model("test@model"));
    }

    // ---- build_input_buf ----

    #[test]
    fn test_build_input_buf_layout() {
        let serial = *b"00000000000000000001";
        let model = *b"VMware Virtual I";
        let sv = 0x1800u32.to_le_bytes();
        let buf = build_input_buf(&serial, &model, &sv);

        assert_eq!(buf.len(), INPUT_LEN);
        assert_eq!(&buf[..SERIAL_LEN], b"00000000000000000001");
        assert_eq!(
            &buf[SERIAL_LEN..SERIAL_LEN + MODEL_LEN],
            b"VMware Virtual I"
        );
        assert_eq!(&buf[SERIAL_LEN + MODEL_LEN..], &sv);
    }

    // ---- check_match ----

    fn make_test_ctx(targets: Vec<targets::Target>) -> SearchContext {
        let (mix_lo, mix_hi) = targets::mbr_mix();
        SearchContext {
            model_bytes: [SPACE_PADDING; MODEL_LEN],
            sv_bytes: [0; 4],
            targets: Arc::new(targets),
            raw_targets: None,
            mbr_table: None,
            pad: PadPosition::Start,
            mix_lo,
            mix_hi,
            max_collisions: 0,
            stop: Arc::new(AtomicBool::new(false)),
            found_count: Arc::new(AtomicUsize::new(0)),
            start: Instant::now(),
        }
    }

    /// Hash the serial `check_match`'s `verify_search_hit` would independently reconstruct
    /// for `make_test_ctx`'s default context (`PadPosition::Start`, space-padded all-blank
    /// model, zero sector value).
    fn hash_for_ctx_serial(serial_num: u64) -> (u32, u8) {
        let mut serial = [0u8; SERIAL_LEN];
        write_candidate(&mut serial, serial_num as u128, SEARCH_ALPHABET);
        let buf = build_input_buf(&serial, &[SPACE_PADDING; MODEL_LEN], &[0u8; 4]);
        sha256::hash_40(&buf)
    }

    /// A target genuinely consistent with `(sid_lo, sid_hi)` under `make_test_ctx`'s mix
    /// (`targets::mbr_mix()`). `check_match` now independently re-hashes and re-derives the
    /// full SOFTWARE ID via `verify_search_hit` before accepting a hit (a safety net added
    /// post-refactor -- not present in the pre-refactor version this test was ported from),
    /// so unlike the old arbitrary `"TEST-0001"` placeholder, `name` must be the real
    /// `compute_software_id` result or `verify_search_hit` rejects the hit as unverifiable.
    fn make_fake_target(sid_lo: u32, sid_hi: u8) -> targets::Target {
        let (mix_lo, mix_hi) = targets::mbr_mix();
        targets::Target {
            need_lo: sid_lo,
            need_hi: (sid_hi as u32) | 0x100,
            name: compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi),
            signature_hex: "AA".repeat(64),
        }
    }

    #[test]
    fn test_check_match_hit() {
        let (sid_lo, sid_hi) = hash_for_ctx_serial(1);
        let ctx = make_test_ctx(vec![make_fake_target(sid_lo, sid_hi)]);

        check_match(1, sid_lo, sid_hi, &ctx);
        assert_eq!(ctx.found_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_check_match_miss() {
        let (sid_lo, sid_hi) = hash_for_ctx_serial(1);
        let ctx = make_test_ctx(vec![make_fake_target(sid_lo, sid_hi)]);

        check_match(999, 0xDEADBEEF, 0xFF, &ctx);
        assert_eq!(ctx.found_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_check_match_sid_hi_only_miss() {
        let (sid_lo, sid_hi) = hash_for_ctx_serial(1);
        let ctx = make_test_ctx(vec![make_fake_target(sid_lo, sid_hi)]);

        check_match(999, sid_lo, 0x99, &ctx);
        assert_eq!(ctx.found_count.load(Ordering::Relaxed), 0);
    }

    /// The always-present first entry of `HashEngine::supported()` is guaranteed to be the
    /// portable `Scalar` backend (see its doc comment/construction) -- used here to drive
    /// `search_batch` deterministically without depending on `HashEngine::auto()`'s
    /// timing-based calibration (which spawns threads and is unsuitable for a unit test).
    fn scalar_engine() -> HashEngine {
        HashEngine::supported()[0]
    }

    /// Ported from the pre-refactor `test_search_scalar_finds_space_padded_target`:
    /// `search_scalar`/`search_simd` were merged into a single batch-generic `search_batch`
    /// that takes an explicit `HashEngine`, so this now drives it with the scalar engine.
    #[test]
    fn test_search_batch_finds_space_padded_target() {
        let model_bytes = [SPACE_PADDING; MODEL_LEN];
        let sv_bytes = [0u8; 4];

        // Plant a target at serial=7 using SPACE padding ("7" + 19 spaces), not the
        // default zero padding.
        let mut zero_buf = [b'0'; SERIAL_LEN];
        write_candidate(&mut zero_buf, 7, SEARCH_ALPHABET);
        let space_buf = leading_pad_to_space_padded(&zero_buf, b'0');
        let buf = build_input_buf(&space_buf, &model_bytes, &sv_bytes);
        let (sid_lo, sid_hi) = sha256::hash_40(&buf);

        let need_lo = sid_lo;
        let need_hi = (sid_hi as u32) | 0x100;
        // `check_match`'s `verify_search_hit` independently recomputes the full SOFTWARE ID
        // and rejects the hit unless `name` is exactly that -- an arbitrary label like the
        // old "SPACE-TEST" placeholder would make this test fail post-refactor.
        let (mix_lo, mix_hi) = targets::mbr_mix();
        let make_target = || targets::Target {
            need_lo,
            need_hi,
            name: compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi),
            signature_hex: "00".repeat(64),
        };

        // With --pad end, search_batch must find it at serial index 7.
        let mut ctx = make_test_ctx(vec![make_target()]);
        ctx.pad = PadPosition::End;
        ctx.max_collisions = 1;
        ctx.model_bytes = model_bytes;
        ctx.sv_bytes = sv_bytes;
        search_batch(0, 1, 0, &ctx, scalar_engine());
        assert_eq!(ctx.found_count.load(Ordering::Relaxed), 1);
        assert!(ctx.stop.load(Ordering::Relaxed));

        // The same target's hash must NOT be produced by the start-padded serial=7
        // ("00000000000000000007") -- confirms the two padding modes genuinely diverge.
        let zero_input_buf = build_input_buf(&zero_buf, &model_bytes, &sv_bytes);
        let (zero_sid_lo, zero_sid_hi) = sha256::hash_40(&zero_input_buf);
        assert!(zero_sid_lo != need_lo || ((zero_sid_hi as u32) | 0x100) != need_hi);
    }

    /// Ported from `test_search_scalar_finds_target_with_custom_alphabet` /
    /// `test_search_simd_finds_target_with_custom_alphabet`: those two engine-specific tests
    /// merged into one loop over every backend `HashEngine::supported()` returns on this
    /// host, since `search_scalar`/`search_simd` are now the single generic `search_batch`.
    /// There is no more `--alphabet` flag or base-10 default to compare against -- base 36
    /// (`SEARCH_ALPHABET`) is the only candidate space `search` ever counts over, and this
    /// confirms it produces letter-bearing candidates correctly across every backend
    /// `HashEngine::supported()` returns on this host.
    #[test]
    fn test_search_batch_finds_target_with_letters_all_engines() {
        let model_bytes = [SPACE_PADDING; MODEL_LEN];
        let sv_bytes = [0u8; 4];

        // Candidate index 46, in base-36, is 1*36 + 10 -> the last two symbols are
        // alphabet[1]='1' and alphabet[10]='A', i.e. "...001A" -- genuinely requires a letter.
        let idx: u128 = 46;
        let mut target_buf = [0u8; SERIAL_LEN];
        write_candidate(&mut target_buf, idx, SEARCH_ALPHABET);
        assert!(
            target_buf.contains(&b'A'),
            "sanity: base-36 index {} should contain a letter",
            idx
        );

        let buf = build_input_buf(&target_buf, &model_bytes, &sv_bytes);
        let (sid_lo, sid_hi) = sha256::hash_40(&buf);
        let need_lo = sid_lo;
        let need_hi = (sid_hi as u32) | 0x100;
        // Same `verify_search_hit`-consistency requirement as above: `name` must be the
        // real computed SOFTWARE ID, not an arbitrary label.
        let (mix_lo, mix_hi) = targets::mbr_mix();
        let make_target = || targets::Target {
            need_lo,
            need_hi,
            name: compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi),
            signature_hex: "00".repeat(64),
        };

        for engine in HashEngine::supported() {
            let mut ctx = make_test_ctx(vec![make_target()]);
            ctx.pad = PadPosition::Start;
            ctx.max_collisions = 1;
            ctx.model_bytes = model_bytes;
            ctx.sv_bytes = sv_bytes;
            search_batch(0, 1, idx as u64, &ctx, engine);
            assert_eq!(
                ctx.found_count.load(Ordering::Relaxed),
                1,
                "engine {} failed to find the planted hit",
                engine
            );
            assert!(ctx.stop.load(Ordering::Relaxed));
        }
    }

    #[test]
    fn test_check_match_stops_at_target_count() {
        let (sid_lo, sid_hi) = hash_for_ctx_serial(0);
        let mut ctx = make_test_ctx(vec![make_fake_target(sid_lo, sid_hi)]);
        ctx.max_collisions = 1;

        check_match(0, sid_lo, sid_hi, &ctx);
        assert!(ctx.stop.load(Ordering::Relaxed));
    }

    // ---- End-to-end SOFTWARE ID ----

    #[test]
    fn test_end_to_end_6g_vmware() {
        let serial = *b"00000000000000000001";
        let model = *b"VMware Virtual I";
        let buf = build_input_buf(&serial, &model, &0x1800u32.to_le_bytes());

        let (sid_lo, sid_hi) = sha256::hash_40(&buf);
        let (mix_lo, mix_hi) = targets::mbr_mix();
        let sid = compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi);
        // Self-consistency: computed SOFTWARE ID must encode/decode round-trip
        let v = software_id::decode(&sid).expect("decode computed sid");
        assert_eq!(software_id::encode(v), sid);
    }

    #[test]
    fn test_end_to_end_16g() {
        let serial = *b"00000000202155543391";
        let model_bytes = build_model_bytes("ROS16G");
        let buf = build_input_buf(&serial, &model_bytes, &0x4000u32.to_le_bytes());

        let (sid_lo, sid_hi) = sha256::hash_40(&buf);
        let (mix_lo, mix_hi) = targets::mbr_mix();
        let sid = compute_software_id(sid_lo, sid_hi, mix_lo, mix_hi);
        let v = software_id::decode(&sid).expect("decode computed sid");
        assert_eq!(software_id::encode(v), sid);
    }

    // ---- precompute_constant_words ----

    #[test]
    fn test_precompute_constant_words() {
        let model = b"VMware Virtual I";
        let sv_bytes = 0x1800u32.to_le_bytes();
        let words = mtsc::sha256_backend::precompute_constant_words(model, &sv_bytes);

        assert_eq!(words[0], u32::from_be_bytes(*b"VMwa"));
        assert_eq!(words[1], u32::from_be_bytes(*b"re V"));
        assert_eq!(words[2], u32::from_be_bytes(*b"irtu"));
        assert_eq!(words[3], u32::from_be_bytes(*b"al I"));
        assert_eq!(words[4], u32::from_be_bytes([0x00, 0x18, 0x00, 0x00]));
    }

    // ---- HashEngine backend cross-validation (new in the multi-ISA backend refactor) ----
    //
    // No pre-refactor equivalent to port: scalar/AVX-512 were the only two backends and
    // already had dedicated tests above and in `sha256_simd.rs`. SHA-NI/AVX2/ARM-SHA2/NEON
    // are new in this PR and never had test coverage. `HashEngine::self_check()` already
    // cross-validates whatever backends the *current* CPU supports against the scalar
    // reference at runtime (called from `auto_for_threads` before real work starts) -- these
    // tests just make that mechanism also run under `cargo test`/CI, so a broken new backend
    // fails the build instead of only being caught the first time it runs in production.
    //
    // KNOWN COVERAGE GAP (as of 2026-09-13): `HashEngine::supported()` is architecture-gated
    // (`#[cfg(target_arch = ...)]` in sha256_backend.rs), so these tests only ever exercise
    // whatever backends match the machine `cargo test` actually runs on. On x86_64 CI that's
    // scalar/sha-ni/avx2/avx512 -- real hardware execution, confirmed on hkg-land-03
    // (AVX-512F/BW + SHA-NI + AVX2). `arm-sha2`/`neon` have ONLY been verified once, manually,
    // via QEMU user-mode emulation (`aarch64-unknown-linux-gnu` cross-compiled, run under
    // `qemu-aarch64-static -cpu max`) during this PR's review -- not on real ARM hardware, and
    // not wired into any CI job (`.github/workflows/build-release.yml`'s `build` job runs
    // `clippy`/`cargo build` for `aarch64-unknown-linux-gnu`/`aarch64-pc-windows-msvc`/
    // `aarch64-apple-darwin` but never `cargo test` for any of them). Until CI actually runs
    // this test suite on an aarch64 runner (or under an aarch64 emulator), a broken
    // `arm-sha2`/`neon` kernel would only be caught by a real user hitting `self_check`'s
    // runtime error on real hardware -- treat these two backends as unverified-by-CI, not
    // "tested," until that gap is closed.

    #[test]
    fn test_hash_engine_supported_always_includes_scalar() {
        let engines = HashEngine::supported();
        assert!(
            engines
                .iter()
                .any(|e| e.backend() == mtsc::sha256_backend::HashBackend::Scalar),
            "HashEngine::supported() must always include the portable Scalar backend"
        );
    }

    #[test]
    fn test_hash_engine_self_check_passes_for_every_supported_backend() {
        for engine in HashEngine::supported() {
            assert!(
                engine.self_check().is_ok(),
                "self_check failed for backend {} (batch size {})",
                engine,
                engine.batch_size()
            );
        }
    }

    /// Extra cross-validation beyond `self_check`'s 5 built-in patterns: a handful of
    /// additional realistic model/sector-value/serial combinations, run through every
    /// supported backend and compared lane-by-lane against the scalar reference. Not
    /// redundant with `self_check` -- different input shapes (varying model strings,
    /// serial digit patterns) exercise different W[]-schedule/carry paths in each SIMD
    /// kernel than the fixed patterns already covered.
    #[test]
    fn test_hash_batch_matches_scalar_reference_extra_patterns() {
        let cases: [(&[u8; 16], u32); 3] = [
            (b"ROS100G         ", 0x1800),
            (b"VMware Virtual I", 0x4000),
            (b"CCR1009-7G-1C-1S", 0x0001),
        ];

        for engine in HashEngine::supported() {
            for (model, sv) in cases {
                let sv_bytes = sv.to_le_bytes();
                let mut batch = HashBatch::new(engine, model, &sv_bytes);
                for lane in 0..batch.len() {
                    let serial = format!("{:020}", lane * 7 + 1);
                    batch.serial_mut(lane).copy_from_slice(serial.as_bytes());
                }
                batch.hash();

                for lane in 0..batch.len() {
                    let serial = format!("{:020}", lane * 7 + 1);
                    let mut buf = [0u8; INPUT_LEN];
                    buf[..SERIAL_LEN].copy_from_slice(serial.as_bytes());
                    buf[SERIAL_LEN..SERIAL_LEN + MODEL_LEN].copy_from_slice(model);
                    buf[SERIAL_LEN + MODEL_LEN..].copy_from_slice(&sv_bytes);
                    let expected = sha256::hash_40(&buf);
                    assert_eq!(
                        batch.outputs()[lane],
                        expected,
                        "engine {} lane {} mismatch for model {:?}",
                        engine,
                        lane,
                        model
                    );
                }
            }
        }
    }
}
