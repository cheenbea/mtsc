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

/// Raw, un-masked SOFTWARE ID targets for the full-`mbr_val`-space search (`search` without
/// `--identity`) -- unlike `Target`, not baked against any one fixed mix, so each target can
/// be checked against every possible `mbr_val` (0-2047). See `required_mix()` /
/// `feasible_mbr_val()`.
///
/// Structure-of-arrays layout, not a `Vec` of one struct per target (2026-09-13, per real
/// `perf` profiling -- see `docs/benchmarks/README.md`'s "Future optimization
/// opportunities"): `tv_lo`/`tv_hi` are flat, parallel arrays holding the *only* fields
/// `sweep_check_match`'s hot per-candidate scan loop touches, so that loop's working set is
/// `len * 8` bytes (comfortably L1-resident even at several thousand targets) instead of
/// striding over a struct that also carries a `name: String` per entry. `names` is separate,
/// same index correspondence, read only on the (astronomically rare) hit-reporting path.
/// `signature_hex` was dropped entirely in this same pass -- it was already `#[allow(dead_code)]`
/// and, confirmed via `grep`, never actually read from this type anywhere (the sweep hit
/// report only needs the SOFTWARE ID name; a *different* type, `Target`, is what
/// `check --license`'s signature printing actually uses).
pub struct RawTargets {
    /// Low 32 bits of each target's decoded, un-masked value.
    pub tv_lo: Vec<u32>,
    /// High bits (>>32) of each target's decoded, un-masked value.
    pub tv_hi: Vec<u32>,
    names: Vec<String>,
}

impl RawTargets {
    /// Number of loaded targets. `tv_lo`/`tv_hi`/`names` are always the same length.
    pub fn len(&self) -> usize {
        self.tv_lo.len()
    }

    /// Whether any targets were loaded. Exists to pair with `len()` (clippy's
    /// `len_without_is_empty`) and for tests -- `load_raw_targets` itself already exits the
    /// process before ever constructing an empty `RawTargets`, so no production code calls
    /// this. `#[allow(dead_code)]` per this project's documented clippy exception
    /// (`AGENTS.md`: "cargo clippy zero warnings (except dead_code)").
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.tv_lo.is_empty()
    }

    /// SOFTWARE ID name for the target at `index` -- only meaningful for an index
    /// `sweep_check_match`'s scan already flagged as feasible via `tv_lo`/`tv_hi`.
    pub fn name(&self, index: usize) -> &str {
        &self.names[index]
    }
}

/// Load un-masked collision targets from keys.toml, for the full-`mbr_val`-space search
/// (`search` without `--identity`). Exits with error if keys.toml is not
/// found or empty (same policy as `load_targets`).
pub fn load_raw_targets(config_path: Option<&str>) -> RawTargets {
    let entries = config_path
        .and_then(load_from_file)
        .or_else(|| load_from_file("keys.toml"))
        .unwrap_or_default();

    if entries.is_empty() {
        eprintln!("Error: keys.toml not found or empty. Copy keys.example.toml to keys.toml and add your signatures.");
        std::process::exit(1);
    }

    eprintln!("Loaded {} keys from config", entries.len());
    let mut tv_lo = Vec::with_capacity(entries.len());
    let mut tv_hi = Vec::with_capacity(entries.len());
    let mut names = Vec::with_capacity(entries.len());
    for e in &entries {
        let tv = software_id::decode(&e.software_id)
            .unwrap_or_else(|err| panic!("invalid SOFTWARE ID in config: {}", err));
        tv_lo.push(tv as u32);
        tv_hi.push((tv >> 32) as u32);
        names.push(e.software_id.clone());
    }
    RawTargets {
        tv_lo,
        tv_hi,
        names,
    }
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
///
/// `#[inline]`: called once per target per candidate in `sweep_check_match`'s hot scan
/// loop (`main.rs`) -- explicit, rather than relying solely on `Cargo.toml`'s `lto = true`
/// to inline it across the crate/module boundary.
#[inline]
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

const MIX_MULTIPLIER_INV: u64 = mod_inverse_pow2_64(MIX_MULTIPLIER);

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
///
/// `#[inline]`: same rationale as `required_mix` above -- called once per target per
/// candidate in the same hot loop, right after it.
#[inline]
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
    #[serde(rename = "softwareId")]
    pub(crate) software_id: String,
    // Legacy SID-only entries remain valid collision targets without a license payload.
    #[serde(default, rename = "signature")]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `content` to a fresh temp file and returns its path, for `load_from_file`
    /// tests that need a real path on disk (it checks `Path::exists` up front).
    fn write_temp_keys_toml(name: &str, content: &str) -> String {
        let path =
            std::env::temp_dir().join(format!("mtsc_test_{}_{}.toml", name, std::process::id()));
        fs::write(&path, content).expect("write temp keys.toml");
        path.to_str().unwrap().to_string()
    }

    /// `RawTargets`' structure-of-arrays layout must keep `tv_lo`/`tv_hi`/`name` correctly
    /// correlated by index -- the entire point of splitting them into parallel arrays
    /// (2026-09-13, see `docs/benchmarks/README.md`) is void if index `i` in one array
    /// doesn't correspond to index `i` in the others. Uses two real, known-valid SOFTWARE
    /// IDs already used elsewhere in this project's tests (not `TEST-0001`-style
    /// placeholders, which aren't valid base-35 and would panic `load_raw_targets`).
    #[test]
    fn test_load_raw_targets_soa_correspondence() {
        let path = write_temp_keys_toml(
            "raw_soa",
            "[[key]]\nsoftware_id = \"TI09-7WK3\"\nsignature_hex = \"AA\"\n\n[[key]]\nsoftware_id = \"VI8Q-E90F\"\nsignature_hex = \"BB\"\n",
        );
        let raw = load_raw_targets(Some(&path));
        let _ = fs::remove_file(path);

        assert_eq!(raw.len(), 2);
        assert!(!raw.is_empty());
        assert_eq!(raw.tv_lo.len(), 2);
        assert_eq!(raw.tv_hi.len(), 2);

        for (i, id) in ["TI09-7WK3", "VI8Q-E90F"].iter().enumerate() {
            assert_eq!(raw.name(i), *id);
            let tv = software_id::decode(id).unwrap();
            assert_eq!(raw.tv_lo[i], tv as u32, "tv_lo mismatch at index {i}");
            assert_eq!(
                raw.tv_hi[i],
                (tv >> 32) as u32,
                "tv_hi mismatch at index {i}"
            );
        }
    }

    #[test]
    fn test_load_from_file_standard_multiline_format() {
        let path = write_temp_keys_toml(
            "multiline",
            "[[key]]\nsoftware_id = \"TEST-0001\"\nsignature_hex = \"AA\"\n",
        );
        let entries = load_from_file(&path).expect("file should parse");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].software_id, "TEST-0001");
        assert_eq!(entries[0].signature_hex, "AA");
        let _ = fs::remove_file(path);
    }

    /// Real TOML (via the `toml` crate) accepts an inline array-of-tables -- one line per
    /// key -- which the old hand-rolled line scanner could never support (it required
    /// `[[key]]` alone on its own line). This is the compact single-line-per-key form.
    #[test]
    fn test_load_from_file_compact_inline_array_of_tables() {
        let path = write_temp_keys_toml(
            "inline",
            r#"key = [
    { software_id = "TEST-0001", signature_hex = "AA" },
    { software_id = "TEST-0002", signature_hex = "BB" },
]
"#,
        );
        let entries = load_from_file(&path).expect("file should parse");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].software_id, "TEST-0001");
        assert_eq!(entries[1].software_id, "TEST-0002");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_mix_from_identity_matches_standard_all_zero() {
        // The standard all-zero identity used by collision search must reduce to
        // the same fixed mix as mbr_mix()'s hardcoded MBR_MIX constant.
        let (lo, hi) = mix_from_identity(&[0u8; 10]);
        let (std_lo, std_hi) = mbr_mix();
        assert_eq!((lo, hi), (std_lo, std_hi));
    }

    #[test]
    fn test_mix_from_identity_deterministic() {
        let identity = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        let a = mix_from_identity(&identity);
        let b = mix_from_identity(&identity);
        assert_eq!(a, b, "same identity must produce same mix");
    }

    #[test]
    fn test_mix_from_identity_differs_from_standard() {
        // A non-zero identity should (overwhelmingly likely) produce a different mix
        // than the standard all-zero one.
        let identity = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA];
        assert_ne!(mix_from_identity(&identity), mbr_mix());
    }

    #[test]
    fn test_marker_from_identity_matches_standard_all_zero() {
        // The all-zero identity's marker is the familiar "standard" BD E8 -- not an
        // independent convention, but this exact formula's output for this input.
        assert_eq!(marker_from_identity(&[0u8; 10]), [0xBD, 0xE8]);
    }

    #[test]
    fn test_marker_from_identity_matches_real_devices() {
        // docs/mbr-data.md real-hardware captures -- WUB2-EYCK and HCC0-4FJR are each
        // independently confirmed by a real `nlevel` activation (this session), not just
        // a formula match; ER1G-WVEL and ZJ3M-ESHW are formula-only cross-checks.
        let cases: [(&str, [u8; 2]); 4] = [
            (
                "13053023E906092F2175", // WUB2-EYCK
                [0xA3, 0x89],
            ),
            (
                "75437493726136326185", // HCC0-4FJR
                [0x33, 0x20],
            ),
            (
                "3836311F7DD5092F2175", // ER1G-WVEL
                [0xD3, 0x53],
            ),
            (
                "32836785814746803233", // ZJ3M-ESHW
                [0x75, 0x08],
            ),
        ];
        for (identity_hex, expected_marker) in cases {
            let identity: [u8; 10] = data_encoding::HEXLOWER_PERMISSIVE
                .decode(identity_hex.as_bytes())
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                marker_from_identity(&identity),
                expected_marker,
                "identity {identity_hex} marker mismatch"
            );
        }
    }

    // ---- entries_to_targets vs real hardware (2026-09-07) ----

    /// Regression test for the `entries_to_targets` masking bug, anchored to an actual
    /// real-VM boot (RouterOS 7.24.1, scsi0, `product=RouterOS-SCSI`, `serial=573214362`,
    /// non-standard identity `00000000000000000FF4`): `/system license print` showed
    /// `software-id: ZTBI-ENJL` -- confirming the true match rule is the full-width
    /// `(sid_hi|0x100) XOR mix_hi == tv_hi`, not the pre-fix `& 0xFF`-masked version (which
    /// would have missed this: `ZTBI-ENJL`'s `tv_hi` is outside `256..512`).
    #[test]
    fn test_entries_to_targets_matches_real_hardware_ztbi_enjl() {
        use crate::sha256;

        let serial_bytes: [u8; 20] = *b"00000000000573214362"; // 20-digit zero-padded numeric serial
        let mut model_bytes = [0x20u8; 16];
        model_bytes[..13].copy_from_slice(b"RouterOS-SCSI");
        let sector_val_bytes = 0u32.to_le_bytes(); // scsi bus forces sector_val=0

        let mut buf = [0u8; 40];
        buf[..20].copy_from_slice(&serial_bytes);
        buf[20..36].copy_from_slice(&model_bytes);
        buf[36..].copy_from_slice(&sector_val_bytes);
        let (sid_lo, sid_hi) = sha256::hash_40(&buf);

        let identity: [u8; 10] = [0, 0, 0, 0, 0, 0, 0, 0, 0x0F, 0xF4];
        let (mix_lo, mix_hi) = mix_from_identity(&identity);

        let entries = vec![KeyEntry {
            software_id: "ZTBI-ENJL".to_string(),
            signature_hex: String::new(),
        }];
        let target = &entries_to_targets(&entries, (mix_lo, mix_hi))[0];

        assert_eq!(sid_lo, target.need_lo);
        assert_eq!((sid_hi as u32) | 0x100, target.need_hi);
    }

    // ---- required_mix / feasible_mbr_val vs production's actual match semantics ----

    /// `required_mix()` must find a hit for any `mbr_val` when the target's `tv_hi` is
    /// constructed the same way `compute_software_id` (real, hardware-confirmed) would
    /// produce it -- i.e. via `(sid_hi|0x100) XOR mix_hi`, always landing in `256..512`.
    #[test]
    fn test_required_mix_finds_hits_for_reachable_targets() {
        let sid_lo = 0xDEADBEEFu32;
        let sid_hi = 0x7Bu8;

        for mbr_val in [0u64, 1, 189, 555, 2047] {
            let mix = mbr_val * MIX_MULTIPLIER;
            let mix_lo = mix as u32;
            let mix_hi = (mix >> 32) as u32;
            let tv_lo = sid_lo ^ mix_lo;
            let tv_hi = ((sid_hi as u32) | 0x100) ^ mix_hi;

            let required = required_mix(sid_lo, sid_hi, tv_lo, tv_hi);
            assert_eq!(
                feasible_mbr_val(required),
                Some(mbr_val as u16),
                "mbr_val={} tv_hi=0x{:X} should hit",
                mbr_val,
                tv_hi
            );
        }
    }

    /// Structural consequence, not a bug (see `required_mix`'s doc comment): a target
    /// whose `tv_hi` falls outside `256..512` can never be matched by *any* mbr_val, for
    /// any sid. Regression test for the 2026-09-07 real-VM finding (`MGT2-L23Y`,
    /// `tv_hi=0x44`, confirmed unreachable -- a real VM boot with `mbr_val=468` produced a
    /// different SOFTWARE ID, `ZTBI-ENJL`, not `MGT2-L23Y`).
    #[test]
    fn test_required_mix_never_hits_for_unreachable_tv_hi() {
        let sid_lo = 0xDEADBEEFu32;

        for tv_hi in [0x44u32, 0x00, 0xFF, 0x200, 0x3FF] {
            for sid_hi in [0x00u8, 0x35, 0x7B, 0xFF] {
                for mbr_val in 0u64..2048 {
                    let mix = mbr_val * MIX_MULTIPLIER;
                    let mix_lo = mix as u32;
                    let tv_lo = sid_lo ^ mix_lo;
                    let required = required_mix(sid_lo, sid_hi, tv_lo, tv_hi);
                    assert_eq!(
                        feasible_mbr_val(required),
                        None,
                        "tv_hi=0x{:X} sid_hi=0x{:X} mbr_val={} should never hit",
                        tv_hi,
                        sid_hi,
                        mbr_val
                    );
                }
            }
        }
    }

    // ---- feasible_mbr_val (multiplicative-inverse trick) ----

    /// Reference implementation using plain division -- the formula already validated in
    /// `main.rs`'s `test_mbr_val_sweep_vs_feasibility_check_agree`. `feasible_mbr_val`
    /// must agree with this on every input; it exists purely so the tests below don't
    /// just check `feasible_mbr_val` against itself.
    fn feasible_mbr_val_via_division(required_mix: u64) -> Option<u16> {
        if required_mix.is_multiple_of(MIX_MULTIPLIER) {
            let q = required_mix / MIX_MULTIPLIER;
            if q < 2048 {
                return Some(q as u16);
            }
        }
        None
    }

    #[test]
    fn test_mod_inverse_is_correct() {
        assert_eq!(MIX_MULTIPLIER.wrapping_mul(MIX_MULTIPLIER_INV), 1);
    }

    #[test]
    fn test_feasible_mbr_val_recovers_every_real_mbr_val() {
        for mbr_val in 0u64..2048 {
            let mix = mbr_val * MIX_MULTIPLIER;
            assert_eq!(feasible_mbr_val(mix), Some(mbr_val as u16));
        }
    }

    #[test]
    fn test_feasible_mbr_val_matches_division_on_edge_cases() {
        for required_mix in [
            0u64,
            1,
            MIX_MULTIPLIER - 1,
            MIX_MULTIPLIER + 1,
            2047 * MIX_MULTIPLIER,
            2048 * MIX_MULTIPLIER, // one past the valid range -- must be rejected
            u64::MAX,
            0xDEAD_BEEF_u64,
        ] {
            assert_eq!(
                feasible_mbr_val(required_mix),
                feasible_mbr_val_via_division(required_mix),
                "mismatch at required_mix=0x{:X}",
                required_mix
            );
        }
    }

    #[test]
    fn test_feasible_mbr_val_matches_division_random_sample() {
        // Deterministic LCG (not a real PRNG, just a cheap way to cover many inputs
        // without a rand dependency) over the realistic ~41-bit required_mix range.
        let mut state: u64 = 0x243F_6A88_85A3_08D3;
        for _ in 0..50_000 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let required_mix = state & 0x1FF_FFFF_FFFF;
            assert_eq!(
                feasible_mbr_val(required_mix),
                feasible_mbr_val_via_division(required_mix),
                "mismatch at required_mix=0x{:X}",
                required_mix
            );
        }
    }

    #[test]
    fn test_marker_from_identity_low_11_bits_match_mix_from_identity() {
        // marker and mix_from_identity's mbr_val are derived from the exact same raw16
        // value -- marker is the full 16 bits, mbr_val is its low 11 bits. They must stay
        // consistent for any identity, not just the cases already spot-checked above.
        for identity in [
            [0u8; 10],
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA],
            [0x71, 0xD2, 0x33, 0x94, 0xF5, 0x56, 0xB7, 0x18, 0xAE, 0xA0],
        ] {
            let marker = marker_from_identity(&identity);
            let raw16 = u16::from_le_bytes(marker);
            let (mix_lo, mix_hi) = mix_from_identity(&identity);
            let expected_mix = ((raw16 as u64) & 0x7FF) * 0x3FF800F;
            assert_eq!(
                (mix_lo, mix_hi),
                (expected_mix as u32, (expected_mix >> 32) as u32)
            );
        }
    }
}
