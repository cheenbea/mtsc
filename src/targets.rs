//! Collision search target management
//!
//! Loads known L6 signatures from an external `keys.toml`, allowing new keys to be added without recompilation.
//!
//! # Configuration format
//! ```toml
//! [[key]]
//! software_id = "XXXX-XXXX"
//! signature_hex = "..."
//! ```

use crate::software_id;
use std::fs;
use std::path::Path;

/// Collision search target
pub struct Target {
    /// SOFTWARE ID (e.g. "XXXX-XXXX")
    pub name: String,
    /// Required sid_lo to match (= target_lo ⊕ mix_lo)
    pub need_lo: u32,
    /// Required value of `(sid_hi | 0x100)` to match (= target_hi ⊕ mix_hi, full width, NOT
    /// masked to a byte). Compared against a full-width `(sid_hi as u32) | 0x100`, not raw
    /// `sid_hi` -- see `compute_software_id`'s identical formula, confirmed against real
    /// hardware 2026-09-07 (a VM's actual computed SOFTWARE ID matched this exactly).
    ///
    /// Before 2026-09-07 this was `u8` and the comparison masked both sides with `& 0xFF` --
    /// correct only when `target_hi` happens to land in `256..512` (as it always does for
    /// this project's earlier-confirmed real collisions), silently wrong for the ~45% of
    /// real `keys.toml` targets outside that range (confirmed via decode(): 59/131).
    /// Masking discarded the fact that `(sid_hi|0x100)` structurally always has bit 8 set
    /// and no bits above 8 -- for `target_hi` inside `256..512` this made no difference
    /// (bit 8 was already implied 1, higher bits already 0), but for `target_hi` outside
    /// that range no `mbr_val` could ever produce a full-width match, even though the
    /// masked low-byte comparison could still spuriously report a "hit". Found via a live
    /// VM test that produced a different SOFTWARE ID than the (masked) match predicted.
    pub need_hi: u32,
    /// MBR signature hex (64 bytes, printed on a hit)
    pub signature_hex: String,
}

/// Multiplicative constant used to derive `mix` from `mbr_val`: `mix = mbr_val * MIX_MULTIPLIER`.
/// Public because production hot-path code (the full `mbr_val` sweep in `search`) needs it
/// directly, not just through `mbr_mix()`/`mix_from_identity()`.
pub const MIX_MULTIPLIER: u64 = 0x3FF800F;

/// Fixed mix value for an all-zero MBR: mbr_val=0x0BD
const MBR_MIX: u64 = 0x0BD_u64 * MIX_MULTIPLIER;

/// Load targets from keys.toml; exits with error if not found or empty.
///
/// `mix` must be the *same* mix (lo, hi) that the caller will use to compute candidate
/// SOFTWARE IDs (`targets::mbr_mix()` for the standard identity, or
/// `targets::mix_from_identity(...)` for a custom one) -- `need_lo`/`need_hi` are only
/// meaningful relative to that specific mix. Passing a mismatched mix silently makes
/// every match check fail (or match the wrong candidates).
pub fn load_targets(config_path: Option<&str>, mix: (u32, u32)) -> Vec<Target> {
    let entries = config_path
        .and_then(load_from_file)
        .or_else(|| load_from_file("keys.toml"))
        .unwrap_or_default();

    if entries.is_empty() {
        eprintln!("Error: keys.toml not found or empty. Copy keys.example.toml to keys.toml and add your signatures.");
        std::process::exit(1);
    }

    eprintln!("Loaded {} keys from config", entries.len());
    entries_to_targets(&entries, mix)
}

/// Get the lo/hi components of the MBR mix
pub fn mbr_mix() -> (u32, u32) {
    (MBR_MIX as u32, (MBR_MIX >> 32) as u32)
}

/// Derive the raw, unmasked 16-bit value (`sha_val XOR chksum`) for a 10-byte MBR
/// identity seed (`0x100-0x109`).
///
/// This single 16-bit value is the source of *both* `mbr_val` (its low 11 bits, used for
/// the mix) *and* the MBR `marker` bytes at `0x10A-0x10B` (the full, unmasked value,
/// written little-endian) -- see `marker_from_identity()` and
/// `docs/identity-marker-formula.md`. They were never two independent fields: the
/// "standard" marker `BD E8` is simply what this formula produces for an all-zero
/// identity (`raw16 = 0xE8BD`, and `0xE8BD & 0x7FF == 0x0BD`).
fn raw16_from_identity(identity: &[u8; 10]) -> u16 {
    let sha_val = crate::sha256::hash_10(identity);
    let mut sum: u16 = 0;
    for chunk in identity.as_chunks::<2>().0 {
        sum = sum.wrapping_add(u16::from_le_bytes(*chunk));
    }
    let chksum = !sum;
    sha_val ^ chksum
}

/// Derive the mix (lo, hi) from a real, non-standard 10-byte MBR identity seed
/// (`0x100-0x109`), instead of assuming the standard all-zero identity.
///
/// Formula (see `docs/license-internals.md` §3.2, §3.6, reverse-engineered from and
/// cross-checked against the `keyman` binary):
/// ```text
/// raw16    = MikroTik_SHA256(identity)[0:2] as LE u16  XOR  NOT(sum of 5 LE u16 words of identity)
/// mbr_val  = raw16 & 0x7FF
/// mix      = mbr_val * 0x3FF800F
/// ```
pub fn mix_from_identity(identity: &[u8; 10]) -> (u32, u32) {
    let mbr_val = (raw16_from_identity(identity) as u64) & 0x7FF;
    let mix = mbr_val * MIX_MULTIPLIER;
    (mix as u32, (mix >> 32) as u32)
}

/// Derive the 2-byte MBR `marker` (`0x10A-0x10B`, little-endian) that must accompany a
/// given 10-byte identity seed for a real device (or a real-hardware-equivalent PVE/QEMU
/// activation) to accept the license -- confirmed via disassembly and, this session,
/// real-hardware round-trip activation in both directions: real captured `identity`s
/// correctly predict their recorded `marker` (5/5, two independently confirmed by a live
/// `nlevel` activation), and a `marker`-matching but otherwise unrelated `identity`
/// activates exactly like the standard all-zero identity it was *not* copied from. A
/// mismatched pair (right identity, wrong marker) reproducibly fails to activate -- see
/// `docs/identity-marker-formula.md`.
pub fn marker_from_identity(identity: &[u8; 10]) -> [u8; 2] {
    raw16_from_identity(identity).to_le_bytes()
}

/// Raw, un-masked SOFTWARE ID target value -- unlike `Target`, not baked against any one
/// fixed mix, so it can be checked against every possible `mbr_val` (0-2047) instead of
/// just the single identity `load_targets` was called with. See `required_mix()` /
/// `feasible_mbr_val()`.
pub struct RawTarget {
    /// SOFTWARE ID (e.g. "XXXX-XXXX")
    pub name: String,
    /// Low 32 bits of the decoded, un-masked target value
    pub tv_lo: u32,
    /// High bits (>>32) of the decoded, un-masked target value
    pub tv_hi: u32,
    /// MBR signature hex (64 bytes), kept for parity with `Target` -- not currently printed
    /// by the sweep's hit report, which only needs the SOFTWARE ID name.
    #[allow(dead_code)]
    pub signature_hex: String,
}

/// Load un-masked collision targets from keys.toml, for the full-`mbr_val`-space search
/// (`search` without `--identity`). Exits with error if keys.toml is not
/// found or empty (same policy as `load_targets`).
pub fn load_raw_targets(config_path: Option<&str>) -> Vec<RawTarget> {
    let entries = config_path
        .and_then(load_from_file)
        .or_else(|| load_from_file("keys.toml"))
        .unwrap_or_default();

    if entries.is_empty() {
        eprintln!("Error: keys.toml not found or empty. Copy keys.example.toml to keys.toml and add your signatures.");
        std::process::exit(1);
    }

    eprintln!("Loaded {} keys from config", entries.len());
    entries
        .iter()
        .map(|e| {
            let tv = software_id::decode(&e.software_id)
                .unwrap_or_else(|err| panic!("invalid SOFTWARE ID in config: {}", err));
            RawTarget {
                name: e.software_id.clone(),
                tv_lo: tv as u32,
                tv_hi: (tv >> 32) as u32,
                signature_hex: e.signature_hex.clone(),
            }
        })
        .collect()
}

/// Compute the `mix` a real MBR identity would need to produce for a candidate
/// `(sid_lo, sid_hi)` to encode to the given raw target `(tv_lo, tv_hi)`.
///
/// Derivation: a hit requires `sid_lo XOR mix_lo == tv_lo` and `(sid_hi|0x100) XOR mix_hi
/// == tv_hi` (full width, matching `compute_software_id`'s real, hardware-confirmed
/// formula -- see the 2026-09-07 real-VM finding below and `check_match`/
/// `entries_to_targets`, whose `need_hi` comparison is against `(sid_hi as u32)|0x100`,
/// not raw `sid_hi`). XOR being its own inverse, solving for `mix_hi` gives exactly this.
///
/// Structural consequence, not a bug: since `(sid_hi|0x100)` always has bit 8 set and no
/// bits above 8, and `mix_hi` is always < 32 (so it can only ever flip bits 0-4), a target
/// is reachable via *any* mbr_val/identity only if its own `tv_hi` already has bit 8 set
/// and no bits above 8 -- i.e. `tv_hi` in `256..512`. This is fixed per target,
/// independent of mbr_val. Roughly 45% of real `keys.toml` targets fall outside that
/// range (confirmed via decode(), 59/131) and are genuinely unreachable by this
/// disk/MBR-based collision technique for any serial -- most are router-hardware-identity
/// entries (e.g. the CCR1009 batch), not disk-based SOFTWARE IDs, so this isn't a gap in
/// the technique so much as a different licensing mechanism entirely.
///
/// (2026-09-07 history, corrected same day: an earlier version of this function replaced
/// the `|0x100` with `sid_hi ^ (tv_hi & 0xFF)` to match `entries_to_targets`'s *then*
/// masked comparison -- that was backwards. A real-VM boot (`serial=573214362`,
/// `identity=00000000000000000FF4`, target `MGT2-L23Y`, `tv_hi=0x44`) found via that
/// masked version's sweep produced `software-id: ZTBI-ENJL` on actual hardware, not
/// `MGT2-L23Y` -- proving the masked version was the false positive, and
/// `entries_to_targets`'s masking (not this formula) was the real, separate bug. Fixed by
/// correcting `entries_to_targets` to full-width comparison instead, and reverting this
/// function back to the original `|0x100` formula.)
pub fn required_mix(sid_lo: u32, sid_hi: u8, tv_lo: u32, tv_hi: u32) -> u64 {
    let required_lo = sid_lo ^ tv_lo;
    let required_hi = ((sid_hi as u32) | 0x100) ^ tv_hi;
    (required_lo as u64) | ((required_hi as u64) << 32)
}

/// Modular inverse of `MIX_MULTIPLIER` mod 2^64, computed via Newton's method (valid
/// because `MIX_MULTIPLIER` is odd -- each iteration doubles the number of correct low
/// bits, starting from 3 correct bits, so 5 iterations comfortably exceed 64).
const fn mod_inverse_pow2_64(a: u64) -> u64 {
    let mut x = a;
    let mut i = 0;
    while i < 5 {
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
        i += 1;
    }
    x
}

/// Multiplicative inverse of `MIX_MULTIPLIER` mod 2^64, exposed for GPU sweep kernels
/// (baked into the generated kernel source so `feasible_mbr_val` runs on-device).
pub(crate) const MIX_MULTIPLIER_INV: u64 = mod_inverse_pow2_64(MIX_MULTIPLIER);

/// Check whether a `required_mix` (from `required_mix()`) corresponds to an achievable
/// `mbr_val` (0..=2047), i.e. some real MBR identity could produce it. Returns the
/// `mbr_val` on success.
///
/// This is the hot path for the full `mbr_val` sweep (called once per candidate serial per
/// target), so it replaces the straightforward `required_mix % MIX_MULTIPLIER == 0`
/// division with a multiplicative-inverse trick: `candidate = required_mix *
/// MIX_MULTIPLIER_INV` (mod 2^64) recovers what `required_mix / MIX_MULTIPLIER` would be
/// *if* `required_mix` is an exact multiple of `MIX_MULTIPLIER`; for non-multiples
/// `candidate` is a meaningless wrapped value, so multiplying it back and comparing exactly
/// (only done when `candidate < 2048`, vanishingly rare) is both necessary and sufficient.
/// Previously cross-checked against the plain-division formula for every real `mbr_val`
/// and a large random sample.
pub fn feasible_mbr_val(required_mix: u64) -> Option<u16> {
    let candidate = required_mix.wrapping_mul(MIX_MULTIPLIER_INV);
    if candidate < 2048 && candidate * MIX_MULTIPLIER == required_mix {
        Some(candidate as u16)
    } else {
        None
    }
}

// ---- Internal implementation ----

#[derive(serde::Deserialize)]
pub(crate) struct KeyEntry {
    pub(crate) software_id: String,
    // Legacy SID-only entries remain valid collision targets without a license payload.
    #[serde(default)]
    pub(crate) signature_hex: String,
}

/// Top-level shape of `keys.toml`: an array of `[[key]]` tables. Any other fields present
/// per entry (`level`, `model`, `serial`, `private`, comments, etc.) are metadata for
/// humans/docs only -- `serde` ignores unrecognized fields by default, so they don't need
/// to be declared on `KeyEntry`.
#[derive(serde::Deserialize)]
struct KeysFile {
    #[serde(default, rename = "key")]
    key: Vec<KeyEntry>,
}

/// Load raw SOFTWARE ID/signature entries before applying any fixed mix.
///
/// Parsed with the `toml` crate (real TOML, not the previous hand-rolled line-by-line
/// scanner) -- accepts any valid TOML layout for `[[key]]` entries, including single-line
/// inline-table form (`[[key]]` followed by `software_id = "...", signature_hex = "..."`
/// all on one line is still invalid per TOML's own grammar for array-of-tables headers, but
/// `key = [{ software_id = "...", signature_hex = "..." }]` inline-array-of-tables syntax
/// now works, which the old scanner could never support), not just the exact
/// one-field-per-line shape the old scanner required.
pub(crate) fn load_from_file(path: &str) -> Option<Vec<KeyEntry>> {
    if !Path::new(path).exists() {
        return None;
    }

    let content = fs::read_to_string(path).ok()?;
    match toml::from_str::<KeysFile>(&content) {
        Ok(parsed) => Some(parsed.key),
        Err(err) => {
            eprintln!("Error: failed to parse '{}': {}", path, err);
            std::process::exit(1);
        }
    }
}

fn entries_to_targets(entries: &[KeyEntry], mix: (u32, u32)) -> Vec<Target> {
    let (mix_lo, mix_hi) = mix;

    entries
        .iter()
        .map(|e| {
            let tv = software_id::decode(&e.software_id)
                .unwrap_or_else(|e| panic!("invalid SOFTWARE ID in config: {}", e));
            Target {
                name: e.software_id.clone(),
                need_lo: (tv as u32) ^ mix_lo,
                need_hi: (tv >> 32) as u32 ^ mix_hi,
                signature_hex: e.signature_hex.clone(),
            }
        })
        .collect()
}
