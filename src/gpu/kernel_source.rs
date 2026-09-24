//! GPU kernel source generation for the collision search.
//!
//! One C core implements the whole per-candidate pipeline on-device — index → base-N
//! serial → padding → single-block MikroTik SHA-256 → target comparison → hit record —
//! so only hit records ever cross the host/device boundary. CUDA and Metal flavors
//! share that core; only the kernel declaration, program-scope constant storage,
//! 64-bit type name, thread-index source, and atomic syntax differ.
//!
//! Everything constant for a whole search run (alphabet, base, padding side, match
//! mode, model/sector words, IV, round constants) is baked into the source as
//! literals, and each thread covers `RUN` consecutive candidates: the base-N counter
//! is built once per thread by u64 division (strength-reduced to multiply-high by the
//! compiler) and advanced by cheap digit-carry increments — 64-bit division measured
//! as 46% of runtime on an Apple M4 before that split. Kernel sources are compiled at
//! runtime (NVRTC / `newLibraryWithSource`), so building `mtsc` needs no GPU toolchain.
//!
//! Host and both GPU targets are little-endian; all struct fields below rely on that.

use crate::sha256_constants::{INITIAL_HASH_VALUES, ROUND_CONSTANTS};
use crate::targets::{MIX_MULTIPLIER, MIX_MULTIPLIER_INV};

use super::GpuKernelSpec;

/// Shader language flavor to generate. Each platform's build only ever compiles in the
/// backend that constructs its own variant (`cuda.rs` outside macOS, `metal.rs` on
/// macOS -- see `src/gpu/mod.rs`'s module gates), so exactly one variant is genuinely
/// unconstructed on any given platform; `#[allow(dead_code)]` documents that as expected
/// per-platform behavior rather than a real bug (this project's own dead-code exemption,
/// `AGENTS.md`: "cargo clippy zero warnings (except dead_code)").
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Flavor {
    /// NVIDIA CUDA C, compiled to PTX by NVRTC at runtime.
    Cuda,
    /// Apple Metal Shading Language, compiled by the Metal framework at runtime.
    Metal,
}

/// Number of hit records the output buffer can hold. More simultaneous hits in one
/// chunk are still counted (the counter keeps climbing) but only the first records
/// survive; real collision density makes overflow unreachable in practice.
pub(crate) const MAX_HITS: usize = 64;

/// Consecutive candidates handled per kernel thread. Launchers dispatch exactly
/// `ceil(n / RUN)` threads.
pub(crate) const RUN: u64 = 16;

/// Emit `0x…, 0x…` u32 array-initializer text.
fn hex_words(words: &[u32]) -> String {
    words
        .iter()
        .map(|w| format!("0x{w:08X}u"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Generate the complete kernel source for `spec` in the given `flavor`.
///
/// The returned source defines exactly one entry point, `mtsc_search`, taking the
/// params struct pointer, the hit-record buffer, and the atomic hit counter.
pub(crate) fn kernel_source(spec: &GpuKernelSpec, flavor: Flavor) -> String {
    debug_assert!(spec.capacity >= 1);

    // Alphabet padded to 64 single-byte entries (tail repeats symbol 0, never read).
    let mut alphabet = [spec.alphabet[0]; 64];
    alphabet[..spec.alphabet.len()].copy_from_slice(&spec.alphabet);
    let alphabet_words = alphabet
        .iter()
        .map(|b| format!("0x{b:02X}u"))
        .collect::<Vec<_>>()
        .join(", ");

    let (header, const_kw, kernel_decl, gid_decl, u64, atomic) = match flavor {
        Flavor::Cuda => (
            "",
            "__constant__",
            concat!(
                "extern \"C\" __global__ void mtsc_search(const Params* __restrict__ params,\n",
                "                                     HitRecord* __restrict__ hits,\n",
                "                                     unsigned int* __restrict__ hit_count)"
            ),
            concat!(
                "    const unsigned long long gid =\n",
                "        (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;"
            ),
            "unsigned long long",
            "atomicAdd(&hit_count[0], 1u)",
        ),
        Flavor::Metal => (
            "#include <metal_stdlib>\nusing namespace metal;",
            "constant",
            concat!(
                "kernel void mtsc_search(device const Params* params [[buffer(0)]],\n",
                "                        device HitRecord* hits [[buffer(1)]],\n",
                "                        device atomic_uint* hit_count [[buffer(2)]],\n",
                "                        uint gid [[thread_position_in_grid]])"
            ),
            "",
            "ulong",
            "atomic_fetch_add_explicit(&hit_count[0], 1u, memory_order_relaxed)",
        ),
    };

    format!(
        r#"{header}
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// Baked per-run constants (see this file's module documentation).
#define BASE {base}u
#define PAD_END {pad_end}
#define SWEEP {sweep}
#define TARGETS_CAP {capacity}u
#define MAX_HITS {max_hits}u
#define RUN {run}u
{const_kw} unsigned int IV[8] = {{ {iv} }};
{const_kw} unsigned int K[64] = {{ {k} }};
{const_kw} unsigned int W5_9[5] = {{ {w59} }};
{const_kw} unsigned char ALPHABET[64] = {{ {alphabet} }};
{const_kw} {u64} MIX_MULT = 0x{mix:016X};
{const_kw} {u64} MIX_INV = 0x{mix_inv:016X};

// Runtime per-chunk parameters. Mirrored byte-for-byte by `pack_run_params`
// (little-endian, natural alignment, no implicit padding).
struct Params {{
    {u64} base;                       // first candidate index of this chunk
    {u64} n;                          // candidate count (base .. base+n-1, wrapping)
    unsigned int num_targets;
    unsigned int tv_lo[TARGETS_CAP];  // fixed: need_lo; sweep: tv_lo
    unsigned int tv_hi[TARGETS_CAP];  // fixed: need_hi; sweep: tv_hi
    unsigned int bitmap[16];          // fixed: keyed by (sid_hi|0x100); sweep: by sid_hi
}};

struct HitRecord {{
    {u64} index;
    unsigned int sid_lo;
    unsigned int sid_hi;
    unsigned int target_idx;
}};

{kernel_decl}
{{
{gid_decl}
    // Each thread owns RUN consecutive indices starting at base + gid*RUN. u64
    // wrapping arithmetic matches the CPU search's wrapping counter; the guard
    // covers launchers that over-dispatch the final partial thread.
    {u64} owned = gid * RUN;
    if (owned >= params->n) return;
    {u64} first = params->base + owned;
    int cnt = (int)((params->n - owned) < RUN ? (params->n - owned) : RUN);

    // Fixed-width base-N counter -> 20 digit values (write_candidate's algorithm),
    // built once per thread; the candidate loop below advances it by carries.
    unsigned char dv[20];
    {u64} t = first;
    for (int i = 19; i >= 0; --i) {{
        dv[i] = t % BASE;
        t /= BASE;
    }}

    for (int r = 0; r < cnt; ++r) {{
        {u64} idx = first + ({u64})r;

        // pad=end: strip the leading run of zero digits, keep at least one digit
        // (leading_pad_to_space_padded's exact algorithm).
        int fs = 0;
        if (PAD_END) {{
            while (fs < 19 && dv[fs] == 0) ++fs;
        }}
        int sig = 20 - fs;

        // Message schedule W[0..15]: W[0..4] packed from the serial digits
        // (big-endian words; spaces beyond the significant digits), W[5..9] shared
        // model/sector suffix, W[10..15] single-block padding (40 bytes + 0x80 +
        // zeros + 0x140 bit length).
        unsigned int w[16];
        w[0] = 0u; w[1] = 0u; w[2] = 0u; w[3] = 0u; w[4] = 0u;
        for (int b = 0; b < 20; ++b) {{
            unsigned int v = (b < sig) ? (unsigned int)ALPHABET[dv[fs + b]] : 0x20u;
            w[b >> 2] |= v << ((3 - (b & 3)) * 8);
        }}
        for (int i = 0; i < 5; ++i) w[5 + i] = W5_9[i];
        w[10] = 0x80000000u;
        w[11] = 0u; w[12] = 0u; w[13] = 0u; w[14] = 0u;
        w[15] = 0x140u;

        unsigned int a = IV[0], b = IV[1], c = IV[2], d = IV[3];
        unsigned int e = IV[4], f = IV[5], g = IV[6], h = IV[7];
        // Fully unrolled so every w[] access stays a compile-time-indexed register;
        // a rolled loop's dynamic ring index would push the schedule array to
        // scratch memory on both compilers.
        #pragma unroll
        for (int i = 0; i < 64; ++i) {{
            if (i >= 16) {{
                unsigned int x15 = w[(i + 1) & 15];   // w[i-15]
                unsigned int x2 = w[(i + 14) & 15];   // w[i-2]
                unsigned int s0 = ROR(x15, 7) ^ ROR(x15, 18) ^ (x15 >> 3);
                unsigned int s1 = ROR(x2, 17) ^ ROR(x2, 19) ^ (x2 >> 10);
                w[i & 15] = w[i & 15] + s0 + w[(i + 9) & 15] + s1;
            }}
            unsigned int s1e = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
            unsigned int ch = (e & f) ^ (~e & g);
            unsigned int t1 = h + s1e + ch + K[i] + w[i & 15];
            unsigned int s0a = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
            unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
            unsigned int t2 = s0a + maj;
            h = g; g = f; f = e;
            e = d + t1;
            d = c; c = b; b = a;
            a = t1 + t2;
        }}
        unsigned int a_final = a + IV[0];
        unsigned int b_final = b + IV[1];
        // hash_40's output convention: state read as big-endian, first word re-read
        // little-endian (a byte reversal), high byte = MSB of the second word.
        unsigned int sid_lo = (a_final >> 24) | ((a_final >> 8) & 0xFF00u)
                            | ((a_final << 8) & 0xFF0000u) | (a_final << 24);
        unsigned int sid_hi = b_final >> 24;

        if (SWEEP) {{
            // targets::required_mix + feasible_mbr_val, on-device. The bitmap holds
            // the exact necessary condition "some target has tv_hi in [256,512) and
            // ((sid_hi ^ tv_hi) & 0xFF) < 32" (mix_hi < 32), so misses cost one load.
            if ((params->bitmap[sid_hi >> 5] >> (sid_hi & 31)) & 1u) {{
                for (unsigned int k = 0; k < params->num_targets; ++k) {{
                    unsigned int req_hi = (sid_hi | 0x100u) ^ params->tv_hi[k];
                    {u64} required = ({u64})(sid_lo ^ params->tv_lo[k]) | (({u64})req_hi << 32);
                    {u64} cand = required * MIX_INV;
                    if (cand < 2048u && cand * MIX_MULT == required) {{
                        unsigned int slot = {atomic};
                        if (slot < MAX_HITS) {{
                            hits[slot].index = idx;
                            hits[slot].sid_lo = sid_lo;
                            hits[slot].sid_hi = sid_hi;
                            hits[slot].target_idx = k;
                        }}
                    }}
                }}
            }}
        }} else {{
            unsigned int hi = sid_hi | 0x100u;
            if ((params->bitmap[hi >> 5] >> (hi & 31)) & 1u) {{
                for (unsigned int k = 0; k < params->num_targets; ++k) {{
                    if (params->tv_lo[k] == sid_lo && params->tv_hi[k] == hi) {{
                        unsigned int slot = {atomic};
                        if (slot < MAX_HITS) {{
                            hits[slot].index = idx;
                            hits[slot].sid_lo = sid_lo;
                            hits[slot].sid_hi = sid_hi;
                            hits[slot].target_idx = k;
                        }}
                    }}
                }}
            }}
        }}

        // Advance to the exact base-N successor (carry ripple; all-(BASE-1) wraps to
        // all zeros — the same wrap the u64 counter itself would take).
        for (int i = 19; i >= 0; --i) {{
            if (dv[i] < BASE - 1u) {{
                dv[i] += 1u;
                break;
            }}
            dv[i] = 0u;
        }}
    }}
}}
"#,
        base = spec.alphabet.len(),
        pad_end = spec.pad_end as u8,
        sweep = spec.sweep as u8,
        run = RUN,
        capacity = spec.capacity,
        max_hits = MAX_HITS,
        iv = hex_words(&INITIAL_HASH_VALUES),
        k = hex_words(&ROUND_CONSTANTS),
        w59 = hex_words(&spec.w5_9),
        alphabet = alphabet_words,
        mix = MIX_MULTIPLIER,
        mix_inv = MIX_MULTIPLIER_INV,
    )
}
