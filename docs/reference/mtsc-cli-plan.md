# `mtsc` Rename & CLI Restructuring Plan

**Status: partially implemented (as of 2026-09-13).** Originally "planned, not yet
implemented" -- since then, the project rename (`ros-serialgen`->`mtsc`, package +
GitHub repo) landed via separate work not sequenced through this plan, and this plan's
own `--disk-size`->`--size` rename, all-short-flags-removed, and MTBase64/hex
`data-encoding` migration items are now implemented and verified (see each section's
own "Status" note below for specifics). Still NOT implemented: the `generate`
subcommand restructuring (`search` is still `search`, not `generate serial`; the new
mbr_val-full-space `--mbr-table` wiring described under it is also still pending),
`sig2key`/`key2sig` -> unified `convert`, `verify` -> `selftest`, the `mikro_`->`mt_`
prefix unification, the `main.rs` module split, `targets.rs`'s TOML-parser rewrite, and
`CHANGELOG.md`. This document still records the decisions and open questions for
whichever of those is picked up next -- see [command-reference.md](command-reference.md)
for the actual current CLI.

## Rename

`ros-serialgen` -> **`mtsc`**.

Considered `mtrsc` (MikroTik RouterOS Serial Collision) vs `mtsc` (MikroTik Serial
Collision, dropping "RouterOS"). Decided on `mtsc`: MikroTik ships a single OS,
RouterOS -- CHR is that same RouterOS running in a virtualized deployment form, not a
separate product (see [chr-system-id-formula.md](chr-system-id-formula.md)'s intro for
the same point applied to license-mechanism naming) -- so "RouterOS" is redundant once
"MikroTik" is already in the name. `mtsc` is the shorter, equally-clear choice.

Note the project itself now covers more than pure serial-collision search (license
conversion `sig2key`/`key2sig`, EC-KCDSA verification, and now CHR `system-id`
derivation) -- "Serial Collision" undersells the full scope, but renaming further wasn't
requested; flagged here in case it comes up again later.

## `search` -> `generate` subcommand group

Today, `ros-serialgen search` is one flat subcommand that performs a multi-threaded
brute-force collision search (see [command-reference.md](command-reference.md#ros-serialgen-search)
for its current flags). The plan restructures this into a `generate` command, named after
what the user gets rather than the mechanism used to get it.

Originally planned as a noun, `generator` (`mtsc generator serial`) -- changed to the verb
`generate` (`mtsc generate serial`) to match standard CLI subcommand convention (verbs,
not nouns -- e.g. `git commit`, `cargo build`, `openssl genrsa`); "generator serial" reads
as a noun phrase modifying another noun, which is grammatically awkward as a command line.

```
mtsc generate serial      # replaces `ros-serialgen search` as-is
```

### `mtsc generate serial`

Rename of the existing `search` subcommand, plus one behavior change folded into this
same pass (decided 2026-09-07, not deferred like `generate identity`/`generate uuid`
above): **when `--identity` is not given, sweep all 2048 `mbr_val` values per candidate
serial, not just the fixed standard identity.**

- Same flags as today (`--size`/`--unit`/`--threads`/`--count`/`--from`/`--model`/
  `--keys`/`--identity`/`--bus` -- see "Flag rename" below for `--disk-size` -> `--size`),
  plus a new `--mbr-table <path>` (default alongside `--keys`, i.e. next to `keys.toml`).
- When `--identity` **is** given: unchanged, single fixed identity/mix, exactly today's
  behavior.
- When `--identity` is **not** given: for each candidate serial, run the already
  cross-validated feasibility check (Approach B from
  [identity-reverse-search.md](identity-reverse-search.md)) against every `--keys`
  target across all 2048 possible `mbr_val`, instead of only the standard identity's
  fixed `mbr_val=189`. On a hit, look up (or self-heal into) `--mbr-table` for an
  identity/marker reproducing that `mbr_val`, and report `software_id`/`identity`/
  `marker`/`serial`/etc. together, per the original request that started this feature
  thread. Expected ~2048x improvement in hit probability per candidate serial, since the
  search-space math and the Approach A vs. Approach B cross-validation (brute-force
  sweep vs. direct feasibility check, agreeing on every real `keys.toml` target) are
  already done and verified against the real binary this session -- only the wiring into
  `cmd_search`'s actual loop and the `--mbr-table` self-healing loader (create-if-missing
  from an `include_str!`-embedded default; fill gaps from that default if the file is
  incomplete) remain unimplemented.
- Renamed (not just behavior-extended) to describe the outcome ("generate a serial that
  collides with a target SOFTWARE ID") rather than the implementation ("search for one").

### `mtsc generate identity` / `mtsc generate uuid` -- decided: out of scope, not implemented

**Decided (2026-09-07): neither ships as part of this refactor.** Design work on both was
carried far enough to reach a verdict, recorded here for whenever either is picked back
up, but implementation itself is explicitly not happening now:

- **`generate identity`** -- the design question itself is resolved: it would be a
  targeted collision search (`--target <SOFTWARE-ID>` recovers an identity whose
  `mbr_val` reproduces that target for a given serial/model/size; omitted, it enumerates
  all 2048 reachable IDs and cross-checks `--keys`), not trivial random generation --
  the math is fully worked out and cross-validated against the real binary in
  [identity-reverse-search.md](identity-reverse-search.md) (feasibility check is
  instant; identity recovery is a ~2048-try search over the last 2 bytes, microseconds
  at this project's hash throughput). Despite the design being settled, it is **not
  being implemented in this pass** -- deferred, no committed timeline.
- **`generate uuid`** -- still genuinely undecided (trivial random UUID vs. targeted
  `system-id` collision search), and per "Before implementing" below, that decision
  requires working out the CHR `system-id` search-space/collision-rate math first
  (unlike `identity`, this has not been analyzed at all: 128-bit partly-fixed-format
  SMBIOS UUID plus a 16-byte MBR region, no pigeonhole-style density result the way
  identity-marker-formula.md gives for `software_id`). **Not being implemented in this
  pass**, and the prerequisite analysis is also not scheduled.

Net effect on the `generate` restructuring: `mtsc generate serial` is the *only*
`generate` sub-action shipping in this refactor.

## Flag rename: `--disk-size` -> `--size`

**Status: ✅ Implemented 2026-09-13.** `--size` shipped on both `search` and `check`
(the `generate serial` rename itself is still not implemented -- the subcommand is still
called `search`, only its `--disk-size` flag was renamed). `disk_size: u64` was kept as
the internal field name exactly as decided below. Verified: `cargo build/test/clippy/fmt`
all clean, plus a real `mtsc check --size ...` invocation confirmed on the build host.

Decided: `--disk-size` becomes `--size` on both `search`/`generate serial` and `check`.
Internal Rust field name `disk_size: u64` stays as-is -- only the clap `long = "..."`
string changes; it's not user-facing.

**Correction (flagged by doc-consistency review):** this section originally said "short
form `-s` unchanged" and kept `short = 's'` in the code sample below -- written before
the later "remove all short flags entirely" decision elsewhere in this document, and
never back-patched. No short form survives; fixed here to match:

```rust
// src/main.rs, both the `Search`/`generate serial` and `Check` variants:
#[arg(long = "size")]   // was: short = 's', long = "disk-size"
disk_size: u64,
```

### Affected files

**Living docs -- update to `--size` alongside the code change:**
- `README.md`
- `AGENTS.md`
- `docs/quick-start.md`
- `docs/reference/command-reference.md`
- `docs/reference/mtsc-cli-plan.md` (this file)
- `docs/reference/toolchain.md`

**Historical/investigation-log docs -- treatment still open, see below:**
- `docs/investigation/license-internals.md`
- `docs/database/collision-database.md`
- `docs/database/nvme-collision-database.md`
- `docs/database/scsi-collision-database.md`

### Decided: `--disk-size` inside historical logs -> option (B), rewrite throughout

**Decided: (B).** Rewrite `--disk-size` to `--size` in all four historical/
investigation-log files too (`docs/investigation/license-internals.md`,
`docs/database/collision-database.md`, `docs/database/nvme-collision-database.md`,
`docs/database/scsi-collision-database.md`), not just the living docs -- the whole
project's command examples stay internally consistent and copy-pasteable, at the cost of
the logs no longer showing the literal flag name typed at the time. Applies uniformly
alongside the living-docs update listed above; no file is left on the old flag name.

## Resolved: remove all short flags, long-form only

**Status: ✅ Implemented 2026-09-13.** Every `short = ...`/bare `short` attribute was
removed from `Search`/`Check` (including the `bus`/`unit`/`threads`/`model`/`keys`/
`count`/`from`/`identity`/`license` fields), and clap's own auto `-h`/`-V` were also
disabled via `disable_help_flag`/`disable_version_flag` plus explicit long-only
`--help`/`--version` fields with `global = true` (needed so `mtsc search --help` keeps
working at the subcommand level too -- an early attempt without `global = true` broke
subcommand `--help` entirely, caught by build-host verification before landing).
Verified live: `mtsc --help`/`mtsc search --help`/`mtsc check --help` all show long-form
only, `mtsc search -s` now fails with clap's "unexpected argument" error.

Supersedes the `check`'s `--serial`-has-no-short-flag issue below (and preempts the same
namespace pressure recurring for `generate`/`convert`'s own flag sets) -- **decided:
drop short flags entirely across the whole CLI**, not just patch the one collision.

**Why this, and not "give `--serial` a short flag and bump something else," and not
"make short flags case-sensitive (`-s` vs `-S`) to double the namespace":**
- Direct evidence from this project's own recorded user feedback (Claude Code memory
  `feedback_cli_long_flags.md`, not a project file -- referenced here in plain text
  since this doc lives in the repo, where `[[wiki-link]]` syntax used in that memory
  system doesn't resolve to anything): "短参数太难理解了" ("short flags are too hard to
  understand") -- the stated
  objection is comprehension cost, not typing length. A case-sensitive short-flag scheme
  (`-s` vs `-S` meaning different things) makes comprehension cost *worse*, not better --
  it directly cuts against the reason short flags were flagged as a problem in the first
  place, so it was considered and rejected, not just left unconsidered.
- That same memory confirms actual usage: every real invocation already uses long-form
  flags exclusively (`--bus`, `--disk-size`, `--unit`, etc.), never the short forms --
  `AGENTS.md`'s original justification for keeping short flags ("fine in
  interactive/muscle-memory use") doesn't match how this project is actually used.
- Removing short flags entirely is a one-time fix for the *entire class* of "which
  command gets which letter" problems (today's `check`, and the same pressure that would
  otherwise resurface for `generate`/`convert`'s flag sets), not just a patch for the one
  collision found so far.
- Cost is close to zero given the usage evidence above: no observed workflow actually
  depends on the short forms.

**Scope:** every `#[arg(short = ..., long = ...)]` across `Search`/`Check` (and their
`generate`/`convert` successors) loses its `short` attribute; only `long` remains.
`docs/reference/command-reference.md`'s short/long flag tables collapse to long-form-only
listings once this lands alongside the broader CLI rename.

**Confirmed in scope: clap's auto-generated `-h`/`-V` too.** `-h`/`--help` and
`-V`/`--version` aren't defined via this project's own `#[arg(short = ...)]` attributes
-- `clap`'s derive macro adds them automatically to every `Command` -- but the same
"short flags are hard to understand, this project only ever uses long-form" reasoning
applies to them identically, so they're in scope for removal too, not an oversight.
Mechanically this needs explicit clap configuration, not just omitting a `short =`
(there's no `short` attribute on these to omit -- they don't come from this project's
own arg definitions):

```rust
#[derive(Parser)]
#[command(name = "mtsc", disable_help_flag = true, disable_version_flag = true)]
struct Cli {
    #[arg(long, action = clap::ArgAction::Help)]
    help: Option<bool>,
    #[arg(long, action = clap::ArgAction::Version)]
    version: Option<bool>,
    #[command(subcommand)]
    command: Commands,
}
```

(Exact clap incantation to verify against the actual `clap` version pinned in
`Cargo.toml` when implementing -- the API for suppressing just the short form while
keeping the long one has shifted across `clap` major versions before.)

### Strengthened justification: why not a lower-cost middle ground

Flagged during CLI-design review as thin evidence for jumping straight to "remove
everything, no partial option" -- fair criticism of the original reasoning above, which
leaned on one feedback quote plus one usage observation without weighing alternatives.
Examined both zero-cost-sounding middle grounds directly rather than waving the concern
off:

- **"Only remove the ones that actually conflict, keep the rest"** -- rejected: this
  makes the *stated* problem worse, not better. A CLI where some flags have short forms
  and others don't forces users to separately remember *which* flags got the shortcut --
  structurally the same asymmetry that made `check --serial`'s missing short flag feel
  wrong in the first place (see the section above). Partial removal trades one
  inconsistency for another; it isn't actually cheaper to understand, just cheaper to
  type in some cases and not others.
- **"Keep short flags as hidden/undocumented aliases"** -- rejected, and this is the
  more substantive rejection: this rename batch already breaks the binary name
  (`ros-serialgen` -> `mtsc`) and the subcommand names (`search` -> `generate serial`,
  etc.) in the same release. Any script or muscle memory relying on short flags is
  *already* broken by those two changes regardless of what happens to `-s`/`-u`/`-m`/etc.
  -- there is no remaining backward-compatibility benefit left to preserve by keeping
  short flags alive as a hidden alias. What a hidden-alias approach *would* cost: extra
  `clap` attributes maintained indefinitely, and a permanent gap between "what the docs
  say the CLI accepts" and "what the code actually accepts" for the next person reading
  it -- a real, ongoing cost for a compatibility benefit that doesn't actually exist here.

This is the actual reason full removal is correct -- not "the evidence was good enough,"
but that **this specific rename is already a hard breaking release at the binary and
subcommand level, making it the lowest-marginal-cost point to also drop short flags
cleanly**, rather than carrying an inconsistent half-removed state or a silently-still-
working hidden path forward indefinitely.

## `sig2key`/`key2sig` -> unified `convert`

Decided: unify the two conversion subcommands into a single `mtsc convert` verb, instead
of keeping the `X2Y`-abbreviated pair (`sig2key`/`key2sig`) that reads inconsistently
next to the rest of the CLI's full-word verbs (`search`/`check`/`generate`/`verify`).

```
mtsc convert <input>
```

**Decided (previously left open, now closed -- see the note at the end of this section
for why leaving it open was itself a bug in this document):** auto-detect which way to
convert from the shape of `<input>`, rather than adding an explicit `--from`/`--to` flag
pair -- this preserves today's ergonomics (`sig2key`/`key2sig` are already each
single-positional-arg commands) while cutting the command count from two to one.

**Correction (flagged by CLI/UX review as a high-priority pre-implementation blocker):**
an earlier draft of this section ran file-detection and content-format-detection as two
separate, un-composed layers -- "is `<input>` a file path" was resolved first (at the CLI
layer), and *only if not a file* did the hex-vs-key decode-based detection below run on
`<input>` itself; if it *was* a file, the code jumped straight to Key-text parsing
(BEGIN/END markers or bare base64) without ever re-running the same hex-vs-key check on
the file's *contents*. This breaks a case this project's own docs already commit to
supporting: `command-reference.md` documents `check --license` accepting "a path to a
`.key` file (or a raw 128-char signature_hex file)" -- i.e. a file containing bare
`signature_hex` with no BEGIN/END markers at all is already a supported shape elsewhere
in this CLI. Under the un-composed version, such a file would be read and then
incorrectly run through the *Key-text* base64 pipeline instead of the hex pipeline
(hex digits happen to also be valid base64 characters, so this doesn't even fail loudly
-- it would silently decode as base64 and produce a garbage/wrong `signature_hex`).

**Decided: resolve file-vs-literal *first*, unconditionally, then run one single
decode-based detection on whatever content results** -- not two separately-triggered
detection strategies:

```rust
use data_encoding::HEXLOWER_PERMISSIVE;
use std::path::Path;

// Step 1: resolve to content -- read the file if `<input>` is a path, else use it directly.
let content = if Path::new(input).exists() {
    std::fs::read_to_string(input)?   // I/O error handling per this project's convention
} else {
    input.to_string()
};

// Step 2: the SAME decode-based detection runs on `content` regardless of whether it
// came from a file or was passed literally -- one strategy, not two.
match HEXLOWER_PERMISSIVE.decode(content.trim().as_bytes()) {
    Ok(bytes) if bytes.len() == 64 => {
        // bare signature_hex (literal, or from a file containing just the hex) ->
        // convert to Key text (today's sig2key behavior)
    }
    Ok(bytes) if bytes.len() == 80 => {
        // full MBR license-region dump (0x100-0x14F): 10-byte identity + 2-byte marker
        // + 4-byte reserved + 64-byte signature, per identity-marker-formula.md's field
        // layout -- same shape as raw dd/hexdump output off a real MBR, e.g.
        // docs/investigation/chr-license-data.md's "MBR license block written" example.
        // Slice bytes[16..80] (the signature portion) and convert that, same as the
        // 64-byte case -- the leading identity/marker/reserved bytes are echoed as
        // context (see "Decided" below), not part of what gets converted.
    }
    _ => {
        // not hex (wrong length, non-hex characters, or anything else) -> treat
        // `content` as Key text: BEGIN/END-marker multi-line, single-line, or bare
        // MTBase64 -- literal or read from a file, same handling either way (today's
        // key2sig behavior, see below for what this branch already covers)
    }
}
```

This composition also **fully eliminates** the "bare hex-named file" edge case an
earlier draft of this section merely accepted as a residual risk (a file named with 128
or 160 hex characters and no extension being misdetected as literal hex rather than a
path): `Path::exists()` is checked *before* any hex-decode attempt on `<input>` itself,
so a real file is always read as a file first, regardless of what its name looks like --
there's no longer a race between "does this look like a filename" and "does this look
like hex" to get wrong.

This same `_` (not-hex) branch is where all Key-text handling lives -> treat `content`
as Key text, convert to `signature_hex` (today's `key2sig` behavior). This branch
already handles **four** input forms via the two-step resolution above, not one shape
split across ad-hoc layers:
- **File**: `<input>` was a path -- step 1 already read it into `content`, so this case
  needs no special handling *below* step 1 anymore (the earlier draft's bug was
  precisely that it needed one).
- **Multi-line text**: the traditional `.key` file format -- BEGIN marker, base64 data,
  END marker each on their own line, any indentation.
- **Single-line text**: `signature_to_key_text`'s own output shape -- BEGIN marker,
  data, and END marker directly abutting on one line (e.g. copy-pasted from after a
  "License: " label in some other tool's output).
- **Bare base64**: just the MTBase64 payload by itself, no `-----BEGIN...`/`-----END...`
  markers at all.

All three text forms are already handled today by one normalization pipeline in
`key_text_to_signature` (`src/convert.rs`): strip the marker substrings if present,
strip all whitespace, and whatever remains is treated as the base64 payload -- so
multi-line collapses to single-line collapses to bare-base64 through the same code
path, not three separate branches. The `convert` unification carries this forward
unchanged; the earlier draft of this section undersold it by only mentioning file-path
and marker-prefixed text, omitting that bare base64 (no markers) already works too.

This also folds in a fix for the naming-audit finding that `key2sig`'s positional arg
already silently accepts two different input shapes (file path vs. literal text) under
one ambiguous name (`key_file_or_text`) -- unifying to `convert` extends that same
"detect the input shape" approach one level further (now also detecting signature vs.
key, not just file vs. literal), so it's one consistent detection strategy instead of
two different ad-hoc ones. Per this project's input-validation standard (`AGENTS.md`:
"treat all inputs as untrusted, validate at every system boundary"), the detection logic
needs a clear, specific error message when `<input>` decodes as neither 64 nor 80 raw
bytes *and* doesn't parse as Key text either -- e.g. "input is neither a signature_hex,
an MBR hex dump, nor a valid Key file/text", not a downstream panic. (Note this
error condition is now naturally rare: almost anything that isn't valid hex or valid Key
text falls through to the Key-text branch's own parse failure, which already needs a
clear error per `key_text_to_signature`'s existing "no key data found" case.)

**Decided:** for the 160-char MBR-dump case, the sliced-off identity/marker/reserved
prefix is echoed back (alongside the existing `SOFTWARE-ID`/`VERSION`/`LEVEL` metadata,
stderr -- keeping stdout as exactly the converted result, unaffected) so the user can
confirm what was stripped out rather than having it silently discarded.

**Retrospective note on why "auto-detect" needed to stop being simultaneously decided
and undecided:** an earlier draft of this section described the full auto-detect
implementation in prose as if settled, while a bullet a few paragraphs later still
listed "whether auto-detection is acceptable" as open -- i.e. this document had
committed to specific function signatures and error-handling shapes for a design
direction it hadn't actually closed yet. Flagged independently by both a CLI-design and
a docs-consistency review. Resolved above: auto-detection is decided, not proposed, for
two closing reasons beyond what was already argued -- (1) the decode-result-based
detection method above makes it unambiguous in practice (no realistic input triggers the
edge case in the paragraph above), and (2) an explicit `--from`/`--to` pair would be a
strictly worse fit for a command whose entire reason for existing is collapsing two
today-zero-flag positional-arg commands into one -- adding required flags back would
undo that ergonomic win.

**Still needs confirming before implementation** (auto-detection itself is no longer on
this list):
- Whether output (stdout: converted result, stderr: `SOFTWARE-ID`/`VERSION`/`LEVEL`
  metadata, now plus the identity/marker/reserved echo for the 160-char case) stays
  exactly as today's format otherwise, for both directions.
- Exact display format for the echoed identity/marker/reserved (e.g. three separate
  labeled hex fields matching `docs/reference/identity-marker-formula.md`'s field names,
  vs. one combined 32-char hex blob) -- not yet specified.

### Required before shipping: regression-test the `data_encoding` migration against real historical samples

**Status: ✅ Done 2026-09-13.** Both parts implemented in `convert.rs`'s test module:
(1) `test_new_base64_matches_legacy_on_real_signatures` (2 hardcoded real signatures) plus
a new `#[ignore]`d `test_new_base64_matches_legacy_on_every_keys_toml_signature`, run
explicitly against the build host's real `keys.toml` (**1038 signatures, zero
mismatches**); (2) `test_base64_negative_corpus_documents_old_vs_new_behavior` covers
misplaced padding, excess padding count, invalid characters, non-canonical trailing bits,
and off-by-one lengths (63/65 bytes) -- for each, both decoders' actual accept/reject
behavior is asserted explicitly, not just diffed. Confirmed tightenings (new decoder
rejects what the old one silently accepted): misplaced/excess padding. The old
`mt_base64_encode`/`mt_base64_decode` were deleted from production code only after these
passed (kept as `legacy_mt_base64_encode`/`legacy_mt_base64_decode` test-only fixtures).

Flagged independently by both an architecture and a security review, not yet done.
Concern: the hand-written `mt_base64_decode` (`convert.rs`, being replaced per the
earlier `data-encoding` decision) may be **more lenient** than `data_encoding`'s
`Specification`-built encoding on malformed input -- e.g. today's decoder strips `=`
characters found *anywhere* in the input (`data.bytes().filter(|&b| b != b'=')`, no
position or count check at all), whereas `data_encoding` validates padding structure
(count and position of `=`) more strictly by default. If any real, already-in-use key
text relies on the old decoder's leniency (non-standard padding placement, wrong
padding count, etc.), switching decoders could turn a previously-working `.key`
file/signature into a hard decode error post-migration -- a real compatibility
regression, not just a theoretical one.

**Decided, but the original test plan below was insufficient on its own (flagged by
security review as testing the wrong property):** running real historical samples from
`keys/` and `docs/database/*.md` through both decoders and diffing the results tests
**compatibility** (does the new decoder still accept what already works) -- it cannot
test **security**, because every real historical sample is, by construction,
well-formed. A pure compatibility diff cannot surface the actually dangerous failure
mode: *the new decoder silently accepting malformed input the old one correctly
rejected* (or a behavior change in the opposite direction that breaks something).
"No differences found" against only-valid inputs is not evidence of safety against
invalid ones.

The original plan also only considered **padding** leniency (`=` position/count).
Missed: `data_encoding`'s `Specification` also has a `check_trailing_bits` setting --
base64's 6-bit symbols don't divide evenly into 8-bit bytes, so the last symbol in a
group can carry a few bits that don't correspond to real data; a canonical encoder
always zeros them, but a lenient decoder can silently accept *any* value there,
producing the same decoded bytes from multiple distinct encoded strings. Today's
hand-written `mt_base64_decode` performs **no such check at all** -- it's already
maximally lenient on this dimension, a fact the original plan never surfaced because
it only looked at padding.

**Decided (revised):** two-part verification, not one:

1. **Compatibility diff** (the original plan, kept): every file under `keys/` and every
   signature/key text in `docs/database/*.md`, decoded by both the old and new decoder,
   byte-for-byte diff. Still required, but only covers "doesn't break what works today."
2. **Negative/malformed-input corpus (new, closes the actual security gap):**
   hand-construct inputs the old decoder is known to mis-handle or under-check, and
   assert the *specific* accept/reject outcome for both decoders -- not just "ran without
   crashing":
   - Padding in the wrong position (`=` before the end) or wrong count (too many/too
     few `=` for the input length) -- today's decoder strips `=` from anywhere in the
     string with no position/count check at all, so it currently *accepts* these.
   - Characters outside the base64 alphabet embedded mid-string.
   - A last symbol with non-zero, non-canonical trailing bits (dirty padding bits) --
     tests the `check_trailing_bits` gap specifically; today's decoder never checks this,
     so it currently *accepts* non-canonical encodings that decode to the same bytes as
     a canonical one would.
   - Inputs of length 63 and 65 bytes (adjacent to the real 64-byte signature length, to
     catch off-by-one acceptance in either decoder).

   For each case, assert what *actually* happens on **both** decoders (accept-with-value
   X, or reject-with-error) and record it as a deliberate compatibility decision either
   way -- e.g. if the old decoder currently accepts non-canonical trailing bits and the
   new one will reject them, that's a real, documented behavior *tightening* (arguably
   desirable -- rejecting non-canonical encodings closes a class of encoding-malleability
   issue), not a silent regression to discover later. The goal is an explicit table of
   "old decoder does X, new decoder does Y" for each malformed case, not merely "no
   mismatches found."

Both parts must pass (or have their differences explicitly reviewed and accepted) before
the old `mt_base64_decode`/`mt_base64_encode` are deleted -- not discovered after the
fact from a user's bug report.

## `verify` subcommand: semantic overload with license verification

Flagged during the naming audit, not yet decided. "Verify" currently means two
unrelated things in this project:

1. **`mtsc verify`** (the subcommand) -- runs fixed test vectors to self-check that the
   SOFTWARE ID algorithm implementation itself is correct (`cmd_verify`, unrelated to any
   real license). "Is my code right."
2. **`LICENSE-VALID: true/false`** in `check`/`convert`'s output --
   EC-KCDSA cryptographic verification of whether a specific signature is genuinely
   MikroTik-signed (`curve25519::verify()`). "Is this license real."

Sharing the word "verify" between these invites a user to think `mtsc verify` checks a
real license (it doesn't take a license as input at all) when it's actually a pure
self-test.

**Decided:** rename the `verify` subcommand to **`selftest`** (`mtsc selftest`),
reserving "verify" purely for the license/signature-authenticity meaning already used in
output labels like `LICENSE-VALID`. Same behavior/output as today's `cmd_verify`, name
only.

**Caveat flagged by naming review, not resolved by the rename alone:** "selftest" isn't
a neutral word this project gets to define from scratch -- across the CLI ecosystem it
most commonly means a *hardware/environment* self-check (`smartctl -t short`, BIOS
POST-style self-tests, etc.), not an *algorithm* self-check. `mtsc selftest` means "the
SOFTWARE ID pipeline's math is implemented correctly against fixed test vectors," which
is a real but different meaning from what the word usually signals -- someone coming
from other CLI tools could reasonably expect it to probe their actual disk/hardware,
or to validate their actual installed license, neither of which it does. The rename
still fixes the original problem (no longer collides with `LICENSE-VALID`'s meaning of
"verify"), but doesn't make the name self-explanatory on its own.

**Decided:** the rename ships as planned, but `mtsc selftest --help` (and its one-line
`Commands` enum doc comment in `main.rs`) must say explicitly that it does **not**
validate any real license or hardware -- e.g. "Run fixed internal test vectors to
self-check the SOFTWARE ID algorithm's own implementation. Does not verify any real
license, key, or hardware." -- not just "Verify SOFTWARE ID computation with known test
vectors" (today's doc comment), which doesn't rule out the hardware/license readings a
user might otherwise assume.

## `check`: decided to keep as-is, no rename

Considered whether `check` needed the same outcome-oriented treatment as `search` ->
`generate serial`, `sig2key`/`key2sig` -> `convert`, and `verify` -> `selftest`.
**Decided: no rename.** Unlike those three, `check` doesn't actually have the defect that
motivated the other renames -- it's not naming a mechanism instead of an outcome, it's
not an inconsistent abbreviation, and it's not semantically overloaded with another
command. "Check this serial" already *is* what the command does.

One residual, non-blocking risk noted for the docs/help-text pass rather than a naming
fix: `check --license`'s comparison is plain string equality (computed SOFTWARE ID vs.
the ID embedded in a `.key` file) -- conceptually different from `LICENSE-VALID`'s
EC-KCDSA cryptographic authenticity check, but "check" and "verify" read close enough
that a user could conflate the two. Resolve via clear `--help`/doc wording, not a rename.

## `compress()` split: generic primitive + `mt_compress()` convenience wrapper

Follows on from "Generalize `compress()` to accept IV/K as parameters" above -- this is
the concrete API shape, decided:

```rust
/// Generic single-block SHA-2-family compression, parameterized over IV and round constants.
fn compress(padded: &[u8; 64], iv: &[u32; 8], k: &[u32; 64]) -> [u32; 8] { ... }

/// MikroTik-custom-constants convenience wrapper -- what every existing call site keeps using.
fn mt_compress(padded: &[u8; 64]) -> [u32; 8] {
    compress(padded, &INITIAL_HASH_VALUES, &ROUND_CONSTANTS)
}
```

**Why this shape:**
- Zero disruption to existing *scalar* call sites (`hash_10`, `hash_40`,
  `mt_sha256_digest` -- see the prefix-unification decision right below for that rename)
  -- they keep calling a zero-argument function, just renamed from `compress` to
  `mt_compress`. This is what resolves the call-site-simplicity tradeoff noted in the
  generalization decision above.
  **Correction (flagged by architecture review, an earlier draft of this line wrongly
  included "the SIMD path" in this list):** `sha256_simd.rs` is a **separate,
  independent implementation** -- it does not call `compress()`/`mt_compress()` at all.
  Verified directly: `sha256_simd.rs` imports `INITIAL_HASH_VALUES`/`ROUND_CONSTANTS`
  from `sha256_constants.rs` itself and loads them straight into AVX-512 registers via
  its own `_mm512_set1_epi32` calls (`sha256_simd.rs:168-175,191,212-213`) -- this
  generalization touches **only the scalar path**. See the dedicated caveat below.
- `mt_compress` naming is consistent with this project's `mt_`-prefix convention (see
  "Prefix unification" below) for "this project's MikroTik-specific instance of a
  generic thing" -- distinguishable enough from `compress` (generic vs. specific) to
  avoid repeating the `mikro_sha256`/`mikro_sha256_digest` near-duplicate-name confusion
  flagged (and resolved as harmless) earlier in this document.
- Fixed-size array parameters (`&[u32; 8]`, `&[u32; 64]`, not slices) make a
  wrong-length-constants bug a compile error rather than a runtime concern -- no manual
  validation needed, and their differing lengths also mean the type system alone
  prevents an IV/K argument-order swap.
- Visibility: both stay module-private (or `pub(crate)` at most) -- no `pub` yet, since
  publishing as a standalone crate was explicitly ruled out for now (see above).

**Required alongside this change, not a follow-up:** add a test that calls the
generalized `compress()` directly with the real NIST-standard SHA-256 IV/K constants
against a well-known public test vector (e.g. `SHA-256("abc")`) -- this is the concrete
correctness payoff of the generalization (validating the round-function logic itself
against an external ground truth, which none of today's three custom-constants-only
implementations can do), and shouldn't be deferred.

**Coverage caveat (flagged by architecture review -- this document previously implied
broader coverage than it actually has):** this NIST-vector test validates **only the
scalar round function** in `sha256.rs`. `sha256_simd.rs`'s independent AVX-512
implementation has its own separate compression logic with the custom constants loaded
directly (not routed through `compress()`/`mt_compress()` at all, per the correction
above) -- it remains validated *only* by cross-checking against the scalar
implementation (`test_simd_matches_scalar`, `test_simd_6g_known`), not against any
external ground truth. Scalar-vs-scalar-with-different-constants and
SIMD-vs-scalar-with-the-same-custom-constants are two different kinds of coverage; this
generalization only adds the first. Extending real-ground-truth validation to the SIMD
path would require either routing it through a generalized compression primitive too
(a much larger rewrite of hand-tuned AVX-512 code, not attempted here) or writing a
second, SIMD-specific NIST-vector test that bypasses `sha256_simd.rs`'s
custom-constants-only entry points -- neither is in scope for this document; recorded
here as an explicitly open gap, not an implied-complete one.

## Replace hand-rolled MTBase64 with the `data-encoding` crate

**Status: ✅ Implemented 2026-09-13.** `data-encoding = "2"` (2.11.1 resolved) added to
`Cargo.toml`; `MT_BASE64` is a `static ... LazyLock<Encoding>` in `convert.rs`, exactly as
designed below (`Specification` + `BitOrder::LeastSignificantFirst`). `AGENTS.md`'s
Dependencies section was updated per the "Follow-up correction needed" note below.
Verification (compatibility diff + negative corpus) is recorded in the "Required before
shipping" section above.

**Decided:** replace `convert.rs`'s hand-written `mt_base64_encode`/`mt_base64_decode`
with the `data-encoding` crate, rather than keeping (or further generalizing) the
bespoke bit-shifting implementation.

Checked directly (September 2026) rather than assumed: unlike SHA-256 (confirmed no
Rust crate supports custom IV/round-constants, see the earlier decision), base64 *does*
have a real library match. The mainstream `base64` crate supports custom alphabets but
hard-codes RFC 4648's MSB-first bit order, so it can't express MikroTik's LSB-first
variant. **`data-encoding`** (crates.io, v2.9.0, zero dependencies, 165M+ downloads,
actively maintained) explicitly supports this via `Specification`'s `bit_order:
BitOrder::LeastSignificantFirst`, alongside custom `symbols` (alphabet) and `padding`:

```rust
use data_encoding::{Specification, BitOrder, Encoding};

fn mt_base64_encoding() -> Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str(BASE64_TABLE_STR); // "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    spec.bit_order = BitOrder::LeastSignificantFirst;
    spec.padding = Some('=');
    spec.encoding().unwrap()
}
// .encode(data) / .decode(bytes) replace mt_base64_encode/mt_base64_decode directly.
```

**Why replace instead of just generalizing in-house** (unlike `compress`, which stays
hand-rolled since no library alternative exists there): a well-tested, widely-deployed
library is preferable to maintaining bespoke bit-manipulation code once one actually
exists and fits -- same principle as not hand-rolling curve25519 field arithmetic
(`curve25519-dalek` is used for exactly this reason already, see `AGENTS.md`'s
Dependencies section). Bonus: `data-encoding`'s own built-in standard-base64 encodings
give a ready-made external ground truth to test the `Specification` setup against,
without writing that cross-check by hand.

**Follow-up correction needed:** `AGENTS.md`'s Dependencies section currently states
"SHA-256 and MTBase64 are hand-implemented (MikroTik-proprietary variants, no library
equivalent exists to depend on)" -- **this is now only true for the SHA-256 half.** Once
this change lands, that line needs splitting: SHA-256 stays hand-implemented (still no
library option), MTBase64 moves to the new `data-encoding` dependency entry (version
string per this project's Rust convention: `"2"`, major-only, since `data-encoding` is a
stable standalone crate with no version-pairing needs).

**Decided:** update callers to use the `Encoding` value directly -- no
`mt_base64_encode`/`mt_base64_decode` wrapper functions. A single shared `Encoding`
value replaces both; call sites become `MT_BASE64.encode(data)` /
`MT_BASE64.decode(bytes)` (`SCREAMING_SNAKE_CASE` per Rust's static-naming convention --
the value is a `static`, not a function, so it follows `static`/`const` casing rules,
not function casing; the ergonomics the decision was going for -- `mt_base64.encode(...)`
method-call style instead of two separate free functions -- are preserved exactly, just
spelled `MT_BASE64` per Rust idiom rather than `mt_base64`).

Construction, since `Specification::encoding()` returns a `Result` and isn't `const`-
evaluable: use `std::sync::LazyLock` (stable since Rust 1.80, no extra dependency needed
beyond `data-encoding` itself):

```rust
use data_encoding::{Specification, BitOrder, Encoding};
use std::sync::LazyLock;

static MT_BASE64: LazyLock<Encoding> = LazyLock::new(|| {
    let mut spec = Specification::new();
    spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    spec.bit_order = BitOrder::LeastSignificantFirst;
    spec.padding = Some('=');
    spec.encoding().unwrap() // infallible for this fixed, hand-verified spec
});
```

`signature_to_key_text`/`key_text_to_signature` (`convert.rs`, the only current call
sites) switch from `mt_base64_encode(&sig_bytes)` / `mt_base64_decode(&b64_data)` to
`MT_BASE64.encode(&sig_bytes)` / `MT_BASE64.decode(b64_data.as_bytes())`.

### Bonus: `hex_encode`/`hex_decode` (`convert.rs`) -> `data_encoding::HEXLOWER`/`HEXUPPER`

**Status: ✅ Implemented 2026-09-13**, with one deviation from this exact plan: `hex_encode`
uses `HEXUPPER` (matches today's uppercase output exactly), but `hex_decode` uses
`HEXLOWER_PERMISSIVE` rather than plain `HEXLOWER`/`HEXUPPER` -- needed because
`signature_hex`/Key-text input is accepted in either case (matching `main.rs`'s existing
`--identity` behavior; see the "Correctness detail" note in the Duplicate section below,
which flagged this exact permissive-vs-strict distinction). No separate `hex` crate added.

**Decided:** replace `convert.rs`'s hand-written `hex_encode`/`hex_decode` with
`data_encoding`'s built-in `HEXLOWER`/`HEXUPPER` encodings, once `data-encoding` is
already a dependency for the MTBase64 replacement above -- no proprietary MikroTik logic
here at all (plain hex), and no need to additionally pull in the separate `hex` crate
(0.4.x, otherwise the standard choice) when `data-encoding` already covers it, avoiding
a redundant second dependency for the same category of problem.

## Wider audit: everything else hand-written is inherently non-library-replaceable

Went through every remaining hand-rolled piece in `src/` to check whether any other
library opportunities exist, beyond the three already found (SHA-256: none exists;
MTBase64: `data-encoding`; hex: `data-encoding`, bonus above). **None of the rest can be
replaced by a library, on principle, not for lack of searching** -- each of the following
encodes a MikroTik-proprietary, reverse-engineered algorithm or field format with no
generic equivalent:

- `software_id.rs`: Base-35 encode/decode with MikroTik's own scrambled alphabet
  (`TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE`) plus `round_sectors`' rounding rule -- a
  private convention, not a named standard.
- `targets.rs`: `mix_from_identity`/`marker_from_identity`/`raw16_from_identity` -- this
  project's own reverse-engineered formula; exists nowhere else.
- `convert.rs`'s `mt_transform`: a custom ARX block cipher for signature-metadata
  obfuscation -- not a named/standard cipher, MikroTik's own invention.
- `main.rs`: `increment_bcd`/`write_serial` (BCD serial incrementing),
  `build_serial_bytes`/`build_model_bytes`/`build_input_buf` (MikroTik's exact SHA-256
  input field-packing layout), `disk_bytes_to_sector_val`/`sector_val_for_bus` (disk-size
  -> `sector_val` conversion matching MikroTik's algorithm) -- all tightly bound to
  MikroTik's private licensing field conventions.

No further dependency-adoption items expected from this audit; the three found (or two,
after folding hex into the same `data-encoding` dependency) are the complete set.

## Prefix unification: `mikro_` / `mt_` -> `mt_`

The codebase currently uses **two different prefixes** for the same concept ("this
project's MikroTik-proprietary variant of a thing"), an inconsistency the earlier
`mikro_compress` naming discussion didn't catch until specifically re-examined:

- `mikro_`: `sha256.rs`'s `mikro_sha256_digest`, `curve25519.rs`'s `mikro_sha256` wrapper
- `mt_`: `convert.rs`'s `mt_transform`, `mt_base64_encode`, `mt_base64_decode`

**Decided: standardize on `mt_`.** The deciding factor isn't aesthetics -- `mt_` already
has real-world precedent this project itself references: `keys.toml`'s own comments cite
an external tool as `MTTools`/`MTBse64Decode` (`python3 -c "from MTTools import
MTBse64Decode; ..."`), i.e. MikroTik's own ecosystem/tooling already abbreviates itself
as "MT". Adopting `mt_` isn't inventing a new convention -- it aligns with the actual
vendor-side naming this project is reverse-engineering against, which is a stronger
justification than either alternative:
- `mikro_` -- a partial, not-quite-a-word truncation of "MikroTik", no external
  precedent, purely this project's own invention.
- `mikrotik_` -- unambiguous but verbose at every call site (`mikrotik_sha256_digest`,
  `mikrotik_compress`, `mikrotik_base64_encode`, ...).

`mt_`'s one real downside -- a bare 2-letter prefix isn't self-explanatory in isolation
-- is mitigated in practice since every function carrying it already lives in a module
whose file-level doc comment states "MikroTik custom SHA-256" or equivalent context.

### Renames required

| Current | New |
|---|---|
| `sha256.rs`'s `mikro_sha256_digest` | `mt_sha256_digest` |
| `curve25519.rs`'s `mikro_sha256` (private wrapper) | `mt_sha256` |
| `mt_compress` (see above -- already lands on the right prefix, no change needed) | -- |
| `convert.rs`'s `mt_transform`/`mt_base64_encode`/`mt_base64_decode` | unchanged, already correct |

Note `hash_10`/`hash_40` are explicitly excluded per the earlier decision not to prefix
them at all (their names are already unambiguous by field-size, adding any prefix --
`mt_` included -- was rejected as consistency-for-its-own-sake, not fixing a real
ambiguity).

## Internal code/directory naming cleanup (non-CLI, no user-facing impact)

Findings from the naming audit that touch internal module structure and repo directory
casing, not the CLI surface above. Lower priority than the CLI rename, but tracked here
so they're not lost.

### `mikro_sha256` (curve25519.rs) vs `mikro_sha256_digest` (sha256.rs) -- investigated, not a duplicate

Re-checked `src/curve25519.rs:23-25` directly:

```rust
fn mikro_sha256(data: &[u8]) -> [u8; 32] {
    crate::sha256::mikro_sha256_digest(data)
}
```

**Resolved: this is not a duplicate implementation risk.** `mikro_sha256` is a one-line
private wrapper that delegates straight to `sha256::mikro_sha256_digest` -- there's only
one actual SHA-256 implementation in the codebase, called through a local alias for
brevity inside `curve25519.rs` (which calls it twice in `verify()`). The earlier audit
flag was raised from the function *signatures* looking suspiciously similar without
having read the body -- confirmed harmless once read. No action needed; the near-duplicate
*name* is a very minor readability nit at most (two functions named almost identically
in different modules), not worth a rename on its own.

### `sha256_scalar.rs` naming

**Decided:** rename to **`sha256_reference.rs`**. Current name doesn't distinguish it
from `sha256.rs` (which is *also* a scalar implementation, the one actually used in
production) -- a newcomer reading file names alone would have no way to guess that
`sha256.rs` is production and `sha256_scalar.rs` is a `#[cfg(test)]`-only independent
cross-check copy. `sha256_reference.rs` states its actual role directly (kept as an
independently-written reference implementation to cross-validate the production one and
the SIMD one against, not itself on any production path).

**Affected files** (checked directly via `grep`, not assumed -- flagged by review as
missing from an earlier draft of this section): `README.md`, `AGENTS.md` (both mention
the filename in the architecture description), `src/main.rs` (the `#[cfg(test)] mod
sha256_scalar;` declaration), `src/sha256_simd.rs` (calls `sha256_scalar::hash_40` in a
test), `src/sha256_constants.rs` (its own module doc comment lists all three files by
name: "Shared by `sha256.rs`, `sha256_scalar.rs`, and `sha256_simd.rs`").

### `keys/Activated/`, `keys/Blocked/` casing

**Decided:** lowercase to `keys/activated/`, `keys/blocked/`. Every other directory in
this repo (`docs/database`, `docs/guides`, `docs/investigation`, `docs/reference`) uses
lowercase kebab-case; `Activated`/`Blocked` (capitalized, created this session) is the
one inconsistent spot. `L6`/`L5`/`L4`/`L1` level subdirectories underneath are unaffected
by this -- their uppercase `L` matches RouterOS's own `nlevel` naming convention, a
different, legitimate reason to capitalize, not a style slip.

**Affected files** (checked directly, flagged by review as missing from an earlier draft
of this section): `keys/README.md` (entirely built around the `Activated`/`Blocked`
path structure -- directory tree, regen-script logic, status table paths, all need the
lowercase update), `docs/mbr-data.md` (references the same structure -- gitignored/
private, but still needs the update for internal consistency when this rename lands).

### Generalize `compress()` to accept IV/K as parameters, not module constants

**Decided:** parameterize `sha256.rs`'s internal `compress()` (and by extension
`hash_10`/`hash_40`/`mikro_sha256_digest`) to take the initial hash values and round
constants as arguments, instead of reading `sha256_constants::{INITIAL_HASH_VALUES,
ROUND_CONSTANTS}` as fixed module-level consts. MikroTik's custom constants become one
call-site's arguments rather than being baked into the function body.

**Why:** no Rust crate on crates.io currently supports supplying custom SHA-256 IV/round
constants (checked directly, September 2026 -- `sha2`, `sha2-const`, `bitcoin-sha256`,
`sha_256` are all fixed-constant implementations); this project's hand-rolled
implementation is genuinely the only option, parameterizing it further is low-risk.
Concretely useful side effect: this is the **first way to validate the compression
function itself against real NIST SHA-256 test vectors** -- feed it the standard IV/K and
compare against published SHA-256 test vectors -- something today's three
custom-constants-only implementations (`sha256.rs`, `sha256_simd.rs`, and
`sha256_scalar.rs`/soon `sha256_reference.rs`) can't do; they can only cross-check each
other, never against an external ground truth.

**Explicitly not doing right now:** publishing this as a standalone crate. Stays internal
to this project (`src/sha256.rs`), even though the generalization would make it
reasonably close to publishable (and the earlier crates.io search found no existing
equivalent, so there would be an open niche) -- revisit later if it comes up again.

**Tradeoff to keep in mind:** call sites (`hash_10`, `hash_40`, `mikro_sha256_digest` --
renamed `mt_sha256_digest`, see "Prefix unification" below) now need to pass the IV/K
through (either as two extra parameters or a small config struct) instead of implicitly
importing them -- a minor loss of call-site simplicity in exchange for the testability
gain above.

**Correction (flagged twice independently -- the same error was caught and fixed in the
"`compress()` split" section below, but this earlier paragraph was missed in that same
review pass and still had it wrong until now):** this tradeoff, and the "first way to
validate... today's three custom-constants-only implementations" framing two paragraphs
up, both wrongly implied the SIMD path (`sha256_simd.rs`) is affected by or benefits
from this generalization. It is not, and does not: `sha256_simd.rs` is a fully
independent implementation that loads `INITIAL_HASH_VALUES`/`ROUND_CONSTANTS` directly
into AVX-512 registers itself (verified at `sha256_simd.rs:168-175,191,212-213`) and
never calls `compress()`/`mt_compress()` -- this generalization, and the NIST test
vector it enables, cover **only the scalar path**. See the dedicated coverage caveat in
the "`compress()` split" section below for the full explanation; this paragraph and the
"today's three... can't do" framing above should be read with that same caveat in mind,
not as claiming three-way coverage.

### `hash_10`/`hash_40`/`mikro_sha256_digest` -- decided NOT to rename

Checked call-site blast radius directly before deciding (`grep -rn` across `src/`):
`hash_40` alone has 8+ call sites across `main.rs`, plus a parallel SIMD form
(`hash_40_x16` in `sha256_simd.rs`) and a cross-check copy in `sha256_scalar.rs`;
`hash_10` has 1 external call site (`targets.rs`); `mikro_sha256_digest` has 1
(`curve25519.rs`). A rename here is a genuinely bigger mechanical change (5 files) than
the `compress` -> `mt_compress` split above (which was purely internal to
`sha256.rs`, zero external call sites since `compress` is module-private).

**Decided: leave `hash_10`/`hash_40` as-is, no `mikro_` prefix.** Re-examining *why*
`mikro_sha256_digest` has the prefix in the first place: it's disambiguating from what
could otherwise sound like a generic/standard digest function (especially now that a
truly generic `compress(padded, iv, k)` exists alongside it) -- exactly the same reason
`compress` needed `mt_compress` as its specific counterpart. `hash_10` and `hash_40`
don't have that risk: their names are already tied to this project's specific field
sizes (10-byte identity, 40-byte serial+model+sector_val) that no generic crypto library
would ever name a function after -- nobody reading `hash_10` would mistake it for a
standard API. Adding `mikro_` here would be consistency for its own sake, not fixing an
actual ambiguity, at the cost of a real 5-file mechanical rename. Same conclusion as the
`mikro_sha256`/`mikro_sha256_digest` near-duplicate-name check above: flagged by the
audit's pattern-matching, resolved as a non-issue on closer inspection.

### `software_id.rs`'s `round_sectors` -- decided: split out

**Decided (overriding the "leave it" call made earlier in this same document -- explicit
user direction, grounded in the Single Responsibility Principle):** move
`round_sectors()` out of `software_id.rs`. `software_id.rs`'s one job is Base-35
SOFTWARE-ID encode/decode; disk-sector-count rounding is a different responsibility that
happens to feed the same downstream pipeline, not the same responsibility -- "both used
by the same caller" was the earlier, weaker justification for leaving them together,
and SRP is the sharper reason it doesn't hold up: a file should have one reason to
change, and `software_id.rs` currently has two (the Base-35 alphabet/encoding changing,
or the sector-rounding rule changing, are unrelated reasons unrelated future edits would
touch the same file for).

**Destination: fold it into the `main.rs` split's `encoding.rs` (see the "`main.rs`
split candidate" section above), not a standalone `disk.rs`.** That section already
proposes moving `disk_bytes_to_sector_val`/`sector_val_for_bus` (currently in `main.rs`)
into a new file for exactly this kind of disk-size/sector-value logic -- `round_sectors`
is the same category of helper (disk size -> `sector_val` pipeline) split across two
files today for no real reason; consolidating it alongside those two during the same
`main.rs`-split pass is one move instead of two separate ones. Add
`software_id.rs -> encoding.rs` to that section's affected-files/module-boundary list.

## Code-quality findings beyond naming

A separate pass looking at correctness/robustness/organization, not just names. Verified
each finding directly against the source rather than assuming -- some suspected issues
(see "confirmed clean" at the end) turned out fine on inspection.

### `mt_sha256_digest`'s production `assert!` -- violates this project's own rule

**Naming note:** this section's fix and the `mt_`-prefix rename (see "Prefix
unification" below) both land in the same implementation pass (pass 4) -- code samples
below use the final `mt_sha256_digest` name directly rather than the current
`mikro_sha256_digest`, to avoid writing the fix under one name only to immediately
rename it. The underlying source today (before either change lands) is still literally
`sha256.rs:75-80` (`pub fn mikro_sha256_digest`), called in production via
`curve25519::verify()`, not test-only) uses `assert!` to reject inputs over 55 bytes.
`AGENTS.md`'s own Code Rules state "Production code must not use `assert!` (use
`eprintln!` + `process::exit` instead)" -- this is a genuine, isolated violation, not a
style nit: an input over 55 bytes reaching this function currently crashes the whole
process via `panic!` instead of failing gracefully.

**SUPERSEDED -- the `debug_assert!` downgrade below was wrong, do not implement it.**
Originally decided as `debug_assert!`; re-analyzed under independent architecture-review
and security-review scrutiny and retracted. Recorded here (rather than silently deleted)
because the reasoning is itself the useful artifact -- a `debug_assert!` doesn't just
"remove a release-build panic," it **reintroduces a worse, silent failure mode** for a
specific input-length range, traced through the actual function body:

```rust
let mut padded = [0u8; 64];
padded[..data.len()].copy_from_slice(data);              // fine for len <= 63
padded[data.len()] = 0x80;                                // written inside bytes 56..64 when len is 56..=63
padded[56..64].copy_from_slice(&bit_len.to_be_bytes());   // immediately overwrites that 0x80 byte!
```

For `data.len()` in **56..=63**, removing the guard doesn't produce a panic at all -- the
`0x80` padding byte gets silently clobbered by the very next line (the bit-length write),
producing a **wrong hash value with no error, no panic, no diagnostic**. Only
`len >= 64` panics (a generic, unhelpful "index out of range," not today's clear custom
message). A compiled-out `debug_assert!` in a release build is therefore strictly worse
than today's `assert!` -- "clear panic" becomes either "silent wrong crypto-adjacent
output" or "unhelpful panic," never "no problem."

This risk isn't hypothetical for *this specific document*: `mt_sha256_digest` (today's
`mikro_sha256_digest`) is `pub fn`, and this same plan adds a new call path (`convert`'s 160-char MBR-hex-dump
auto-detection, parsing user-pasted input) plus two more planned commands
(`generate identity`/`generate uuid`) that could plausibly grow a future call site which
doesn't preserve today's "always exactly 16 or 32 bytes" invariant. A safety check that
silently disappears in release builds is the wrong tool for guarding a `pub fn`'s input
contract against future callers this same plan is actively creating room for.

**SUPERSEDED AGAIN -- the `eprintln!`+`process::exit` fix below has its own real flaw,
do not implement it either.** Flagged by a Rust-systems review: `std::process::exit`
called from *any* thread terminates the entire process immediately, unconditionally --
unlike a plain `panic!`, which only unwinds and kills the *calling* thread (a spawned
worker's `.join()` returns `Err`, every other thread keeps running, the main thread
observes the failure and decides what to do). The doc-comment guardrail below already
anticipated that a future multi-threaded `generate identity`/`generate uuid` collision-
search worker might call this function -- but didn't follow through to what
`process::exit` actually does in that scenario: called from inside one search worker
thread, it would instantly kill *all* search threads process-wide, skipping progress
reporting, any in-flight collision write-out, and graceful shutdown -- a worse outcome
than a scoped panic in that specific context, even though it's the right tool for
today's single-threaded CLI-argument-parsing call sites (`parse_identity_hex`).

```rust
// SUPERSEDED -- do not implement -- correct for today's callers, wrong for a future
// multi-threaded worker calling this function on a bad length.
pub fn mt_sha256_digest(data: &[u8]) -> [u8; 32] {
    if data.len() > 55 {
        eprintln!(
            "Error: mt_sha256_digest only supports single-block input (<=55 bytes), got {}",
            data.len()
        );
        std::process::exit(1);
    }
    // ... unchanged from here
}
```

**Decided instead (also resolves the separate "safety contract is a doc comment, not
type-enforced" finding below in the same move):** push the length check to a
**newtype constructed via `Result`**, so the invariant is enforced by the type system at
the point of construction -- not by a runtime check buried inside `mt_sha256_digest`
that a caller could simply not go through, and not by a policy (`process::exit`) baked
into a low-level primitive that different call sites (single-threaded CLI parsing vs. a
future multi-threaded search worker) need to handle differently:

```rust
/// A byte slice already validated to fit `mt_sha256_digest`'s single-block limit
/// (<=55 bytes). Constructing one is the only way to prove that length at compile time;
/// `mt_sha256_digest` takes this type instead of `&[u8]` so "input too long" becomes
/// unrepresentable at the call site, not a runtime check deep inside the function.
pub struct SingleBlockInput<'a>(&'a [u8]);

impl<'a> SingleBlockInput<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() > 55 {
            return Err(format!(
                "input must be <=55 bytes for a single SHA-256 block, got {}",
                data.len()
            ));
        }
        Ok(Self(data))
    }
}

pub fn mt_sha256_digest(input: SingleBlockInput) -> [u8; 32] {
    let data = input.0;
    // ... unchanged from here, `data.len() <= 55` is now a type-level guarantee
}
```

**Why this is strictly better than either superseded attempt:**
- Returns `Result`, so **each call site decides its own error handling** instead of one
  policy being forced on every caller -- today's single-threaded CLI call sites
  (`curve25519::verify()`'s callers) can `eprintln!`+`process::exit` at *their* level
  (matching `AGENTS.md`'s convention, and appropriate there since they run before/outside
  any worker threads), while a future multi-threaded search worker can instead log-and-
  skip, propagate via its own channel, or panic *within just that thread* -- whichever
  fits that context, decided where the context is actually known, not inside a shared
  low-level primitive that can't see it.
- The "safety contract" stops being a doc comment someone has to read and remember --
  `SingleBlockInput::new` is the *only* way to obtain the type `mt_sha256_digest`
  accepts, so a future caller literally cannot pass an over-length buffer without
  explicitly handling the `Result` first. This is the "make illegal states
  unrepresentable" pattern this project's own `curve25519-dalek` dependency already uses
  internally (per the earlier library-survey turn) -- applying the same idiom here
  instead of a comment-only contract.
- No behavior change for today's callers beyond adding a `.expect(...)` or `?` at the
  existing fixed 16-/32-byte call sites (both provably always succeed, same as the
  `.try_into().unwrap()` calls already confirmed infallible elsewhere in this document).

### `targets.rs`'s hand-rolled TOML parser -- replace with `toml` + `serde`

**Decided.** Verified current versions (September 2026): `toml` 1.1.2 (`+spec-1.1.0`),
depends on `serde` ^1.0 (currently 1.0.229) -- both mainstream, actively maintained.
Standard combo per this project's Rust version convention (major-only version strings):

```toml
[dependencies]
serde = { version = "1", features = ["derive"] }
toml = "1"
```

Replacing `load_from_file`'s substring-matching parser (`targets.rs:113-160`) with:

```rust
use serde::Deserialize;

#[derive(Deserialize)]
struct KeysFile {
    key: Vec<KeyEntry>,   // matches TOML's `[[key]]` array-of-tables directly
}

#[derive(Deserialize)]
struct KeyEntry {
    softwareId: String,
    signature: String,
}

fn load_from_file(path: &str) -> Option<Vec<KeyEntry>> {
    if !Path::new(path).exists() {
        return None;
    }
    let content = fs::read_to_string(path).ok()?;
    match toml::from_str::<KeysFile>(&content) {
        Ok(parsed) => Some(parsed.key),
        Err(e) => {
            eprintln!("Error: failed to parse {}: {}", path, e);
            std::process::exit(1);
        }
    }
}
```

**Why replace, not just patch the bug:** unlike SHA-256/EC-KCDSA (confirmed no library
exists, must stay hand-written), TOML is a fully standard, open format with mature
Rust support -- there's no proprietary-format reason to hand-roll this one. Confirmed a
concrete correctness bug in the current parser: a line like
`signature = "ABC123..." # a comment` (valid TOML, inline comment after a value) --
`trim_matches('"')` only strips a matching quote from *both* ends of the remaining
string; since the trailing character here is `t` (from "comment"), not `"`, only the
leading quote gets stripped, leaving `ABC123...” # a comment` as the parsed value --
**silently corrupted data, no error raised.** No current `keys.toml` comment happens to
trigger this (all comments are on their own lines today), but it's a live landmine for
the next manual edit. `toml::from_str` handles inline comments, escaped quotes, and
other TOML edge cases correctly by construction, and -- as a genuine improvement over
today's silent-corruption failure mode -- surfaces a specific parse error message
instead of quietly producing wrong data on a malformed file.

**AGENTS.md sync required (flagged by review -- missed the first time, inconsistent with
how the `data-encoding` dependency was handled above):** `AGENTS.md`'s Dependencies
section needs a new `toml`/`serde` entry alongside the existing `clap`/`clap_complete`/
`curve25519-dalek` ones, in the same style (name, version, one-line reason). Draft:

```markdown
- `toml` 1.x / `serde` 1.x — parses `keys.toml`; replaced a hand-rolled line scanner
  that could silently corrupt data on inline comments (see
  docs/reference/mtsc-cli-plan.md)
```

### Affected files (parallel to the `--size` rename's "Affected files" list above)

- `Cargo.toml` (new `toml`/`serde` dependencies)
- `targets.rs` (the parser rewrite itself)
- `AGENTS.md` (Dependencies section, per above)
- `docs/reference/toolchain.md` if it documents `keys.toml`'s format/parsing (check when
  implementing -- not yet confirmed one way or the other)

### `main.rs` is 1447 lines -- 4x the next-largest file, split candidate

```
main.rs:        1447 lines  (CLI definition + all 6 command handlers + search loop + BCD/field encoding + tests)
sha256_simd.rs:  343 lines
convert.rs:      296 lines
targets.rs:      272 lines
sha256.rs:       228 lines
```

**Decided: split, timed to land alongside the CLI restructuring** (`search` ->
`generate serial`, `sig2key`/`key2sig` -> `convert`, `verify` -> `selftest`) rather than
as a separate pass -- the command reshuffle already touches most of these boundaries,
so splitting now avoids moving the same code twice. Proposed module boundaries (open to
adjustment once the CLI changes are actually being implemented):
- `cli.rs`: `Cli`/`Commands`/`BusType`/`SizeUnit` definitions
- `search.rs`: `cmd_search` (-> `cmd_generate_serial`), `search_scalar`, `search_simd`,
  `check_match`, `report_progress`
- `cmd_check`, `cmd_sig2key`/`cmd_key2sig` (folding into the `convert` unification --
  may end up moving into `convert.rs` itself rather than a separate `commands.rs`),
  `cmd_verify` (-> `cmd_selftest`) -- exact placement TBD alongside the CLI work itself
- Serial/BCD/field-packing helpers (`write_serial`, `increment_bcd`,
  `build_serial_bytes`, `build_model_bytes`, `build_input_buf`,
  `disk_bytes_to_sector_val`, `sector_val_for_bus`) -- candidate for a new `encoding.rs`
  or folding into `software_id.rs`

**Compile-error risk this plan missed the first time (flagged by Rust-systems review --
add to the "exact placement TBD" items above, not a separate action item):**
`write_serial`, `build_serial_bytes`, `increment_bcd`, and the other private helpers
above are called today from `main.rs`'s own `#[cfg(test)] mod tests`, which can reach
them precisely *because* Rust's privacy rules let a child module (the test module is a
descendant of the crate root, where these functions also live) access its ancestors'
private items for free. Moving these functions into `search.rs`/`encoding.rs` breaks
that for free ride: whoever does the split must either (a) move the relevant tests into
the *same* new module as the functions they exercise (preserving the private-item-plus-
child-test-module pattern), or (b) mark the moved functions `pub(crate)` so `main.rs`'s
test module (if it stays put) can still reach across the new module boundary. Left
unaddressed, this isn't a style question -- it's a compile error the moment the split
actually happens, not something caught by review beforehand.

This is a >3-file change on its own (before even counting the CLI restructuring it's
bundled with) -- per this project's workflow rule, needs its own explicit sub-task
breakdown when it's actually scheduled, not bundled silently into another change.

**Scoping correction (flagged by doc-consistency review):** that workflow rule was
invoked here as if this were the one change in the document large enough to trigger it.
It isn't -- the rename (`Cargo.toml`/`AGENTS.md`/`README.md`/`CLAUDE.md`/three
`docs/reference/*.md` files/GitHub repo name), the `convert` unification, the two
`data_encoding` migrations (base64 + hex), the `mt_`-prefix rename, and the
`keys/Activated,Blocked` casing fix are collectively far larger than three files on
their own, before this `main.rs` split is even added to the pile. The rule needs to
apply to **the release as a whole**, not to whichever single item happened to be framed
as a "file-structure change" when it was written. See the "Implementation sequencing"
section below, added specifically to apply this consistently instead of piecemeal.

### Duplicate hex-decoding logic across three files -- consolidate onto `data_encoding`

**Status: ✅ Implemented 2026-09-13.** All three call sites now go through
`data_encoding` directly (`main.rs`'s `parse_identity_hex` calls `HEXLOWER_PERMISSIVE`
inline rather than through a shared `convert::hex_decode`, since making `hex_decode`
`pub(crate)` wasn't even necessary once both files can import the same crate-level
constant independently; `targets.rs`'s test does the same). The
`HEXLOWER_PERMISSIVE`-not-`HEXLOWER` correctness detail flagged below was applied.

**Decided.** The same "hex-pair-to-byte" logic is independently hand-rolled in three
places:

```
convert.rs:225   fn hex_decode(hex: &str) -> Result<Vec<u8>, String>      -- production
main.rs:253      parse_identity_hex's from_str_radix loop                 -- production
targets.rs:224   same logic again, inside a #[cfg(test)] test case        -- test-only
```

`main.rs` couldn't just call `convert.rs`'s `hex_decode` because that function is
module-private (no `pub`/`pub(crate)`) -- a visibility gap forced the duplication, not a
deliberate choice. Once `hex_encode`/`hex_decode` move to `data_encoding` (per the
"Bonus" decision above), this is resolved for free: `data_encoding`'s encodings are
externally-accessible values, so `main.rs`, `convert.rs`, and `targets.rs`'s test code
can all call the same one directly, deleting two of the three hand-written copies.

**Correctness detail to get right during the swap:** today's validation
(`s.bytes().all(|b| b.is_ascii_hexdigit())` in `parse_identity_hex`) accepts both
uppercase and lowercase hex digits. `data_encoding`'s plain `HEXLOWER` encoding only
*decodes* lowercase input -- the case-insensitive variant is **`HEXLOWER_PERMISSIVE`**.
Using the non-permissive `HEXLOWER` here would be a silent regression (rejecting
currently-valid uppercase `--identity` input); `HEXLOWER_PERMISSIVE` is the one to use
everywhere this project currently accepts mixed-case hex.

### Forward note for future `generate uuid` work: reuse `MT_BASE64`, don't re-hand-roll

Not an action item today (no code exists yet for `generate uuid`) -- recorded so it
isn't forgotten when that command is eventually implemented. `docs/reference/chr-system-id-formula.md`'s
reference `lsb_base64` (CHR's system-id encoder: same standard alphabet, same LSB-first
bit order as `MT_BASE64`) is the same underlying encoding as this project's own
`MT_BASE64` (`data_encoding`-backed, per the decision above) -- when `generate uuid` is
implemented, it should call the existing `MT_BASE64` value directly rather than adding a
third hand-rolled LSB-first base64 implementation alongside it.

### Considered and rejected: SIMD-abstraction crates (`wide`/`pulp`) for `sha256_simd.rs`

**Decided: not now**, recorded so this doesn't get re-litigated later without new
information. `sha256_simd.rs`'s hand-written AVX-512 intrinsics
(`_mm512_i32gather_epi32`, `_mm512_ternarylogic_epi32`, etc.) could in principle be
rewritten against a portable-SIMD abstraction crate to reduce hand-written `unsafe`
code. Rejected for now because the actual payoff of those crates -- portability across
instruction sets/architectures -- isn't something this project currently needs (x86_64
AVX-512 only; no ARM/NEON target exists today), while the cost is real: the current code
is already tested (`test_simd_matches_scalar`, `test_simd_6g_known`) and hand-tuned for
this exact custom hash's data-dependent access patterns (the `sid_hi` lookup pre-filter,
`W[5..9]` precomputation, etc.) -- rewriting it against a generic abstraction risks
performance regressions or subtle bugs for a benefit (less hand-written code) that isn't
currently needed. Revisit only if/when a non-x86_64 SIMD target is actually planned.

### Checked and confirmed clean (no action needed)

- `convert.rs`'s four `.try_into().unwrap()` calls -- all provably infallible: either
  operating on a fixed-size array slice of guaranteed-correct length (e.g. `mt_transform`
  chunking a `&mut [u8; 16]` into 4-byte pieces), or preceded by an explicit length check
  (`decode_verify_inputs` validates `sig_bytes.len() != 64` before slicing it into the
  16/32-byte parts) -- not a hidden panic risk on untrusted input.
- `parse_identity_hex` (`main.rs`) -- validates length and hex-digit-ness with a proper
  `eprintln!` + `process::exit(1)` before parsing, matching this project's own error-
  handling convention. The one `.unwrap()` inside is safe given that prior validation.
- Search-loop concurrency (`search_scalar`/`search_simd`, `check_match`) -- already uses
  `AtomicUsize::fetch_add`/`AtomicBool` correctly (no coarse locks), consistent with this
  project's stated concurrency preference.

## Changelog requirement

**Decided:** this batch of changes needs a `CHANGELOG.md` entry (no `CHANGELOG.md`
exists in the project yet -- checked directly, this creates the file). Given how much
this plan accumulates -- a project rename, a full CLI subcommand restructuring, and
several breaking flag changes -- these need to be documented for anyone updating from
the old `ros-serialgen` CLI, not left to be discovered via `--help`. Draft entry to
write once implementation actually lands (adjust wording/version number at that time):

```markdown
## [Unreleased] (or the actual next version number)

### Changed
- Renamed project from `ros-serialgen` to `mtsc`.
- `search` renamed to `generate serial`; new `generate identity`/`generate uuid`
  sub-actions added (see docs/reference/mtsc-cli-plan.md for scope).
- `sig2key`/`key2sig` unified into a single `convert` command (auto-detects direction
  and input shape: signature_hex, MBR hex dump, or Key text/file).
- `verify` renamed to `selftest`.
- `--disk-size` renamed to `--size` (`search`/`generate serial` and `check`).
- All short flags (`-s`, `-u`, `-m`, `-k`, `-i`, `-b`, `-c`, `-f`, `-l`, etc.) removed;
  long-form flags only.

### Fixed
- `keys.toml` parsing now uses a real TOML parser (`toml`/`serde`) instead of a
  hand-rolled line scanner -- fixes silent data corruption when a value line has a
  trailing inline comment (e.g. `signature = "..." # comment`).
```

This is a **breaking-change-heavy** release by CLI-tool standards (renamed binary,
renamed subcommands, removed short flags, renamed flags) -- the changelog entry should
say so plainly at the top, and `README.md`/`AGENTS.md` should point to it rather than
silently assuming users will diff `--help` output themselves.

### Considered and declined: migration ceremony (deprecation aliases, Migration Guide)

Flagged during CLI-design review: this batch of changes (binary rename, subcommand
restructuring, flag renames, all short flags removed) ships as one release with no
discussion of version-number semantics, no transitional `ros-serialgen` alias binary, no
deprecated-but-still-working old subcommand names, and a changelog that's a flat list of
changes rather than a dedicated before/after Migration Guide.

**Decided: skip all of that, ship it as a clean breaking change.** This is a
single-maintainer reverse-engineering research tool at an early stage (`Cargo.toml`
version `0.2.0`, pre-1.0 -- semver itself already signals "no compatibility guarantee"
at this stage), not a widely-depended-upon package with an external user base carrying
SLA-like expectations. The cost of alias binaries, deprecation-warning shims for old
subcommand names, and a full Migration Guide document is real engineering and
maintenance overhead that doesn't match the project's actual current scale.

**The one piece worth keeping regardless of project stage, since it costs nothing:**
bump the version number for this release (`0.2.0` -> `0.3.0` -- a `0.x` minor bump is
sufficient per semver for pre-1.0 breaking changes, no need to jump to `1.0.0` just for
this). Add to the "Before implementing" checklist below.

Revisit this decision (deprecation aliases, a real Migration Guide) if the project's
audience ever grows beyond its current single-maintainer scope -- the CHANGELOG draft
above is intentionally kept as the only migration documentation for now.

## Implementation sequencing (addresses the workflow-rule scoping gap above)

Flagged by doc-consistency review: this document invoked the ">3 files needs a sub-task
breakdown" rule exactly once (for the `main.rs` split), when in fact nearly every
section above is individually a multi-file change, and the release as a whole is far
larger than that. Applying the rule honestly means treating this whole plan as several
separate implementation passes, each independently decomposed when it's actually
scheduled -- not one giant commit, and not a rule that only fires for whichever change
happened to look file-structural. Grouping the decided items above into passes by what
naturally lands together (exact grouping/order can change when implementation actually
starts -- this is a sequencing aid, not a new commitment):

1. **Rename pass**: `ros-serialgen` -> `mtsc` project-wide (binary/package name + every
   doc reference, verified complete list below) + version bump (`0.2.0` -> `0.3.0`) +
   new `CHANGELOG.md`.
2. **CLI restructuring + `data_encoding` (MTBase64/hex) pass**: `search` ->
   `generate serial` (including its new mbr_val-full-space sweep + `--mbr-table`
   self-healing loader, decided 2026-09-07 -- see above; `generate identity`/
   `generate uuid` themselves are explicitly out of scope, not "pending" -- see above),
   `sig2key`/`key2sig` -> `convert`, `verify` -> `selftest`, `--disk-size` -> `--size`,
   all short flags removed, the `main.rs` module split -- **plus the `data_encoding`
   migration for MTBase64/hex, moved into this same pass (see the ordering-bug
   correction below for why it can't wait until pass 3)**.
3. **`keys.toml` parsing pass**: `toml`/`serde` for `keys.toml` (the only remaining
   dependency-migration item once `data_encoding` has moved to pass 2 above) -- this one
   has no cross-pass dependency, stays independent.
4. **Internal-naming pass**: `mikro_`/`mt_` -> `mt_` unification, `sha256_scalar.rs` ->
   `sha256_reference.rs`, `keys/Activated,Blocked` -> lowercase, `compress`/
   `mt_compress` split (+ required NIST test vector -- scalar path only, see the SIMD
   caveat below), `mt_sha256_digest`'s `SingleBlockInput` newtype (replaces its
   `assert!`, not just a downgrade -- see the fix's final form above).

**Ordering-bug correction (flagged by doc-consistency review as a real blocker, not a
style note):** the original grouping put `convert`'s `HEXLOWER_PERMISSIVE`-based
detection in pass 2 while introducing the `data_encoding` dependency itself only in what
was pass 3 -- as sequenced, pass 2 could not compile, since it uses a crate pass 3 hasn't
added yet. Fixed by merging the `data_encoding` (MTBase64 + hex) migration into pass 2
above, since `convert.rs` is already being rewritten in that pass for the `sig2key`/
`key2sig` unification anyway -- doing the dependency swap in the same pass touches the
same file for the same reason, rather than needing the dependency to already exist from
an earlier, now-separate pass. `toml`/`serde` (pass 3) has no such cross-pass dependency
and can stay independent.

Each pass gets its own explicit sub-task breakdown at the point it's actually scheduled,
per this project's own workflow rule -- consistently, not just for pass 2's file-split
component.

## Before implementing

- [x] Confirm `identity` and `uuid` sub-actions -- decided 2026-09-07: **neither ships in
      this refactor.** `identity`'s design question is resolved (targeted collision
      search, not trivial generation) but deferred with no timeline; `uuid` remains
      genuinely undecided and its prerequisite search-space/collision-rate math is not
      scheduled. See "`mtsc generate identity` / `mtsc generate uuid`" above.
- [ ] `mtsc generate serial`'s new mbr_val-full-space behavior (decided 2026-09-07, see
      above): wire the already-cross-validated Approach A/B feasibility check into
      `cmd_search`'s actual candidate loop, implement the `--mbr-table <path>`
      self-healing loader (create-if-missing from `include_str!`-embedded default,
      fill gaps from that default if incomplete), and update hit-output to print
      `software_id`/`identity`/`marker`/`serial` together.
- [x] Update all `ros-serialgen` references project-wide -- **done 2026-09-13** for every
      live doc/source file (the repo, package, and binary were already renamed to `mtsc`
      by this point via separate earlier work, not through this plan's own sequencing).
      Deliberately left untouched: `archive/docs2-superseded/*` (frozen historical
      archive) and this plan doc's own narrative (self-referential, discusses the old name
      as its subject matter). Original verified-list note below, for context:
      **This list is now the actual verified output of
      `grep -rl "ros-serialgen" . --include="*.md" --include="*.rs" --include="*.toml"`
      (run September 2026), not an assumed subset** -- an earlier draft of this checklist
      item listed only 7 files, including two (`CLAUDE.md`,
      `docs/reference/chr-system-id-formula.md`) that a direct re-check found **zero**
      matches in, while omitting 15 files that do contain the string. Full verified list
      (22 files, including this plan doc itself, which references the old name
      deliberately throughout for context and needs no renaming pass of its own):
      `AGENTS.md`, `Cargo.toml`, `CONTRIBUTORS.md`, `README.md`, `keys.toml`,
      `src/main.rs`, `docs/README.md`, `docs/quick-start.md`,
      `docs/reference/architecture.md`, `docs/reference/command-reference.md`,
      `docs/reference/identity-marker-formula.md`, `docs/reference/toolchain.md`,
      `docs/guides/x86-install.md`, `docs/guides/x86-automated-install.md`,
      `docs/investigation/license-internals.md`,
      `docs/investigation/arm-reverse-engineering.md`,
      `docs/database/collision-database.md`, `docs/database/nvme-collision-database.md`,
      `docs/database/scsi-collision-database.md`,
      `docs/database/vmware-ide-collision-database.md`,
      `resources/images/RouterOS-v6.49.13-VI8Q-E90F-L4-1GB/README.md` (path updated
      2026-09-03 when `resources/` was split into `images/`/`programmer-firmware/`),
      plus the GitHub repo name
      if that's also in scope (currently `cheebun/ros-serialgen`). Re-run the same
      `grep` at implementation time in case new files have picked up the string since
      this check.
- [ ] Bump version `0.2.0` -> `0.3.0` and write the `CHANGELOG.md` entry (draft above).
- [x] `sig2key`/`key2sig` -> unified `convert` (decided, see above -- auto-detection
      confirmed final, decode-result-based via `HEXLOWER_PERMISSIVE`, not string-shape
      pattern matching).
- [ ] Decide exact display format for the echoed identity/marker/reserved in `convert`'s
      160-char MBR-dump case (three labeled fields vs. one combined hex blob -- not yet
      specified, see above).
- [x] Run the `data_encoding`-migration regression diff (old `mt_base64_decode` vs. new
      decoder) against every real sample -- **done 2026-09-13**, see the "Required before
      shipping" section above (1038/1038 real `keys.toml` signatures agreed, plus a
      negative/malformed-input corpus). The old decoder was deleted from production only
      after this passed.
- [x] `verify` -> `selftest` (decided, see above).
- [x] `check` -> kept as-is, no rename (decided, see above -- previously this line
      still said "undecided" after the decision above had already been made; fixed).
- [x] All short flags removed, long-form only (decided, see above -- reaffirmed after
      review, still the conclusion). **Also code-complete 2026-09-13** -- see the
      "Resolved: remove all short flags, long-form only" section's status note above.
- [x] `software_id.rs`'s `round_sectors` scope mismatch -- decided: leave in place, no
      action required (see above).
- [ ] `main.rs` module split -- scope drafted above, needs its own sub-task breakdown
      when scheduled (see "Implementation sequencing" above).
- [ ] Add a test proving the generic `compress()` matches a real NIST SHA-256 test
      vector -- **scalar path only**; see the SIMD-coverage caveat in the `compress()`
      split section above for why this doesn't extend to `sha256_simd.rs`.
