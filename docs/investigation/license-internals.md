# SOFTWARE ID and MBR Deep Dive

Detailed analysis of the SOFTWARE ID computation, MBR license structure, and the collision search principle. Based on reverse engineering of the RouterOS 7.23.2 keyman binary.

---

## 1. Three-Layer Licensing Architecture

```
+-------------------------------------------------------------------+
|                    License Verification Layer                      |
|                                                                    |
|   Disk params (serial, model, size) --+                            |
|                                       +--> SOFTWARE ID             |
|   MBR identity region (0x100-0x109) --+        |                   |
|                                                v                   |
|                                    KCDSA signature (0x110-0x14F)   |
|                                                |                   |
|                                                v                   |
|                                    RouterOS built-in public key    |
|                                    verifies signature at boot      |
+-------------------------------------------------------------------+
```

- **Identity layer**: Disk hardware parameters + MBR seed compute a unique SOFTWARE ID
- **Signature layer**: EC-KCDSA over Curve25519; proves this SOFTWARE ID holds a valid license
- **Verification layer**: RouterOS embedded public key validates the signature on every boot

---

## 2. MBR License Region Structure

Within the first disk sector (512 bytes), offsets `0x100-0x14F` form the 80-byte license region:

```
Offset       Size   Field                   Role in Licensing
-----------  -----  ----------------------  ------------------------------------------
0x100-0x109  10B    Identity seed           Input to MBR mixing phase of SOFTWARE ID
0x10A-0x10B   2B    License marker          Must be BD E8; installer resets to FF FF
0x10C-0x10F   4B    Boot counter            Incremented by RouterOS each boot; no effect
0x110-0x14F  64B    KCDSA digital signature Core license proof
```

### Independence of Identity and Signature Regions

The two functional regions serve different purposes and are independent:

```
+-- Identity (0x100-0x10F) ---+     +-- Signature (0x110-0x14F) ---+
|                              |     |                               |
|  Affects SOFTWARE ID         |     |  Proves license validity      |
|  Variable per machine        |     |  Binds to SOFTWARE ID only    |
|  Auto-generated on key import|     |  Fixed for a given SOFTWARE ID|
+------------------------------+     +-------------------------------+
```

Experimental evidence (see [experiments.md](experiments.md)):

| Config | Identity (0x100-0x10F) | Signature (0x110-0x14F) | SOFTWARE ID |
|---|---|---|---|
| 6G | `00...BD E8...` | `E67A8F47...` | TI09-7WK3 |
| 42G | `F0A25846...` | `E67A8F47...` (same) | TI09-7WK3 |
| 8G | `48065595...` | `080342D3...` | 4MZF-SFTR |
| 16G (collision) | `00...BD E8...` | `080342D3...` (same) | 4MZF-SFTR |

The signature is reusable across any disk configuration that produces the same SOFTWARE ID.

---

## 3. SOFTWARE ID Computation

### 3.1 Input Preparation

| Input | Source | Size | Charset / Encoding |
|---|---|---|---|
| serial | ATA IDENTIFY or QEMU `serial=` | 20 bytes | `[0-9A-Za-z-]` |
| model | ATA IDENTIFY or QEMU `model=` | 16 bytes | `[0-9A-Za-z- ]`, space-padded right |
| sector_val | `total_sectors >> 11`, rounded | 4 bytes | uint32 LE |
| mbr_10 | MBR[0x100:0x10A] | 10 bytes | raw binary |

SHA-256 input buffer = `serial(20) || model(16) || LE32(sector_val)` = 40 bytes.

### 3.2 Four-Phase Computation

**Phase 1: Hardware fingerprint**

```
buf[40]  = serial[20] || model[16] || LE32(sector_val)
digest   = MikroTik_SHA256(buf)
hash_lo  = digest[0:4] as LE uint32
hash_hi  = digest[4] | 0x100
```

**Phase 2: MBR mixing**

```
sha_val  = MikroTik_SHA256(mbr_10)[0:2] as LE uint16
chksum   = bitwise_NOT(sum_of_5_LE_uint16(mbr_10)) & 0xFFFF
mbr_val  = (sha_val XOR chksum) & 0x7FF        // 11 bits effective
mix      = mbr_val * 0x3FF800F                  // expanded to 43 bits
```

**Phase 3: Combination**

```
final_lo = hash_lo XOR mix_lo
final_hi = hash_hi XOR mix_hi
final    = (final_hi << 32) | final_lo
```

**Phase 4: Encoding**

```
SOFTWARE_ID = Base35Encode(final)
Alphabet: TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE
Output format: XXXX-XXXX (hyphen at position 4)
```

### 3.3 MikroTik SHA-256 Constants

Standard SHA-256 structure (64-round Merkle-Damgard) with custom IV and K:

```
IV = { 0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F,
       0x03E1AAF9, 0x4A2057CC, 0x4CAF4DD9, 0x643CC9EA }

K[64] = { 0x0548D563, 0x98308EAB, 0x37AF7CCC, ... }
```

Full K table: identical to `MIKRO_SHA256_K` in MikroTikPatch `mikro.py`.

### 3.4 sector_val Rounding Rule

Disk size is lossily compressed to reduce sensitivity to exact sector counts:

```
raw        = total_sectors >> 11
bits       = highest_set_bit(raw)
if bits <= 4:
    sector_val = raw
else:
    shift = bits - 4
    sector_val = ceil(raw / 2^shift) * 2^shift
```

Examples:

| Disk Size | Total Sectors | raw (>>11) | sector_val | Hex |
|---|---|---|---|---|
| 6G | 0xC00000 | 0x1800 | 0x1800 | Already aligned |
| 8G (7.38 GiB) | 0xEBFD10 | 0x1D7F | 0x1E00 | Rounded up |
| 64G | 0x7740AB0 | 0xEE81 | 0xF000 | Rounded up |

### 3.5 Binary-Level Verification

Sections 3.2-3.4 were re-verified directly against `tools/bin/keyman_x86_7.23.2` (ELF 32-bit LSB, Intel 80386, stripped) via raw byte search + `objdump -d` disassembly, rather than relying solely on repeated real-hardware test results. Every value below cites the actual file offset / instruction.

**SHA-256 constant tables -- exact byte match**

Searching the binary for the IV and round-constant words (as little-endian byte sequences) finds them contiguous in `.rodata`:

| Constant | File offset | Runtime VMA |
|---|---|---|
| `IV[0] = 0x5B653932` | `0xc7e0` | `0x080547E0` |
| `IV[1] = 0x7B145F8F` | `0xc7e4` | `0x080547E4` |
| `K[0] = 0x0548D563` | `0xc800` | `0x08054800` |
| `K[1] = 0x98308EAB` | `0xc804` | `0x08054804` |

(`VMA = file_offset + 0x08048000`, confirmed by cross-checking against the `.rodata` section's own VMA range from `objdump -h`.) The disassembly loads these addresses directly: `movl $0x80547e0, %esi` / `movl $0x8054800, %edi` at the entry of the compression-round function.

**Round function -- rotate amounts match `Σ0/Σ1/σ0/σ1`**

The compression loop uses `rorl $0x6` / `rorl $0xb` / `roll $0x7` (`roll 7` == `rotr 25`) for `Σ1(e)`, and `roll $0xe` (`rotr 18`) / `rorl $0x7` / `shrl $0x3` for `σ0`, matching `sha256.rs`'s `rotate_right(6/11/25)` and `(7/18/3)` exactly.

**`mbr_val` formula -- confirmed instruction-by-instruction**

A dedicated function calls the SHA-256 wrapper with `ecx=0xa` (10 bytes -- the `mbr_10` identity seed), then:

```asm
movzwl -0x28(%ebp), %esi   ; esi = digest[0:2] as u16  (sha_val)
testl  %esi, %esi
jne    skip
movl   $0x1eef, %esi       ; if sha_val == 0, substitute 0x1EEF (undocumented edge case)
skip:
movl   %ebx, %eax
calll  <checksum_fn>       ; 0x804bf80
xorl   %esi, %eax          ; mbr_val_16 = sha_val XOR chksum
```

The checksum function at `0x804bf80` reads five little-endian `u16` words, sums them, and returns `~sum & 0xFFFF` (short-circuited to `0xFFFF` directly if every word is zero -- numerically a no-op, since `~0 & 0xFFFF` is `0xFFFF` anyway). This is exactly `chksum = NOT(sum_of_5_LE_uint16(mbr_10)) & 0xFFFF` from 3.2, confirmed opcode-by-opcode rather than inferred.

**SOFTWARE ID input buffer -- confirmed 40-byte layout**

At `0x8050a9b`: `movl $0x28, %ecx` (0x28 = 40) immediately precedes a call to the SHA-256 wrapper -- this is the SOFTWARE ID hash from 3.1/3.2. Walking backward from this call, two NUL-to-space sanitization loops bound the buffer:

```
offset 0x00-0x13 (20 bytes): first loop bound  -- the serial field
offset 0x14-0x23 (16 bytes): second loop bound -- the model field
```

i.e. the buffer is laid out as `serial[20] || model[16]` starting at offset 0, immediately followed by `sector_val` to reach 40 bytes total -- an exact match for `main.rs`'s `SERIAL_LEN=20`, `MODEL_LEN=16`, `INPUT_LEN=40`, and field order. The model truncation documented in 3.1 is not a limitation of this project's tooling; it is the fixed size of keyman's own on-stack buffer, visible directly in its machine code.

A related debug format string found in the binary confirms the same field widths independently of the disassembly: `"%s: hdd-model='%.16s' s='%.20s' sz=%d MB"` -- `%.16s` for model, `%.20s` for serial.

**Empirically confirmed on a real VM**: PVE VM running the ER1G-WVEL MBR (2G, `serial=00000000000000000001`) was booted twice -- once with `model=VMware Virtual IDE Hard Drive` (29 chars) and once with `model=VMware Virtual I` (the 16-char truncation) -- both produced an identical `/system license print` result. This matches the disassembly's prediction exactly: bytes past the 16th are read from the disk's IDENTIFY response but never copied into keyman's hash input buffer, so they cannot affect the SOFTWARE ID.

### 3.6 marker and reserved: generated from identity, not just checked

Sections 3.1-3.5 establish that `mbr_val` (used in the SOFTWARE ID hash) is computed from the 10-byte identity alone (`0x100-0x109`) -- marker (`0x10A-0x10B`) and reserved (`0x10C-0x10F`) are never fed into that hash. Two real-VM tests confirmed marker/reserved still matter for validation even though they don't affect the SOFTWARE ID: taking a known-good MBR (HCC0-4FJR's real identity + real signature) and changing only marker (to `FFFF`) or only reserved (to `DEADBEEF`) both broke validation -- `/system license print` still showed the *correct* `software-id: HCC0-4FJR` (proving the hash truly doesn't use these bytes), but fell back to a 24-hour trial (`expires-in`) in both cases.

The disassembly explains why. The "key import" code path (`RouterOS decodes the key text ... generates the identity region`, §4 below) contains this sequence, found by tracing callers of the `mbr_val` function from 3.5:

```asm
movl  $0x0, 0xc(%eax)      ; reserved (0x10C, 4 bytes) := 0
calll 0x804f490            ; compute (sha_val XOR chksum) from the 10-byte identity -- same
                            ; computation as mbr_val, but the caller has NOT yet applied &0x7FF
movw  %ax, 0x10a(%esi)     ; write the raw *unmasked* 16-bit result directly to marker (0x10A)
```

So marker isn't an independent value or a fixed magic constant -- **it's the very same identity-derived hash used for `mbr_val`, just written out in full (16 bits) instead of masked down to 11 bits (`& 0x7FF`) for the mix.** `mbr_val = marker & 0x7FF`. reserved is unconditionally zeroed by this same code path, which is why it's `00000000` in every example seen so far.

This can be verified independently of the disassembly, using only the (already public) mbr_val formula from 3.2, computing the full unmasked value and reading it back as a little-endian 16-bit word:

```python
raw_value = sha_val ^ chksum   # same as mbr_val's inputs, but skip the "& 0x7FF"
marker    = raw_value.to_bytes(2, 'little')
```

Checked against every known real-device identity in this project:

| Device | identity-derived raw value | predicted marker (LE) | actual marker | match |
|---|---|---|---|---|
| standard (all-zero) | `0xE8BD` | `BDE8` | `BDE8` | yes |
| HHJH-UFWL | `0x7EFA` | `FA7E` | `FA7E` | yes |
| TI09-7WK3 | `0x9864` | `6498` | `6498` | yes |
| ZJ3M-ESHW | `0x0875` | `7508` | `7508` | yes |
| ER1G-WVEL | `0x53D3` | `D353` | `D353` | yes |
| 4MZF-SFTR | `0x42A4` | `A442` | `A442` | yes |

[Two rows for `WUB2-EYCK` and `HCC0-4FJR` have been removed per project policy -- see `AGENTS.md`.]

6 of 6 remaining rows match exactly (a full 16-bit exact match by chance has probability 1/65536 per device -- six independent exact matches rules out coincidence). 4MZF-SFTR's row was corrected after the original recorded data (`identity=...055A`, `marker=4442`) turned out to compute a completely different SOFTWARE ID (`1EGG-HMKR`, not `4MZF-SFTR`) when boot-tested on a real VM -- a transcription error from this project's earliest phase (Experiment 1's "five parameter sets from a forum post", see `experiments.md`), not a formula exception. Brute-forcing the 2048 possible `mbr_val` values against the target SOFTWARE ID (keeping serial/model/size fixed) found the one value that works, then searching single-hex-digit edits of the recorded identity found the fix (`A` misread as `5` in one position, and separately as `4` in the recorded marker) -- confirmed on a real VM after correction.

HCC0-4FJR remains the sole confirmed exception -- from this project's earliest phase as well, but (unlike 4MZF-SFTR) independently boot-verified multiple times as a real, working license with marker `BDE8`, so it isn't a transcription error. The most plausible explanation is that it was licensed by an older RouterOS/keyman version whose key-import routine derived marker differently, while the SOFTWARE ID hash itself (which every license, old or new, must still satisfy to keep working) stayed stable across versions. This isn't confirmed, just the most plausible explanation given the available evidence -- flagged here rather than asserted.

Practical implication: when writing an MBR for a real-device signature (§6 below / `docs/automated-install.md`), write `marker`/`reserved` exactly as captured from that device -- `BDE800000000` is simply what the formula produces for a large share of real captures (and for the standard all-zero collision-search identity), not a fixed constant every device is guaranteed to share. One of eight known real devices in this project proves the exception.

---

## 4. Three Forms of a License

### Form 1: MBR Binary (80 bytes at disk offset 0x100)

```
0x100: 00 00 00 00 00 00 00 00 00 00 BD E8 00 00 00 00   <- fixed header
0x110: <64-byte KCDSA signature>                          <- looked up by SOFTWARE ID
```

Written via `dd` to the raw disk after installation.

### Form 2: Key Text File

```
-----BEGIN MIKROTIK SOFTWARE KEY------------
...
-----END MIKROTIK SOFTWARE KEY--------------
```

Imported via `/system license import file-name=license.key`. RouterOS decodes the key text, generates the identity region from current disk parameters, and writes the full 80 bytes to MBR.

### Form 3: RouterOS Display

```
/system license print
  software-id: XXXX-XXXX
       nlevel: 6
     features:
```

### Conversion Between Forms

```
                    MTBase64Decode
Key text  --------------------------->  MBR[0x110:0x150] (64-byte signature)

                    MTBase64Encode
MBR[0x110:0x150]  ------------------->  Key text
```

MTBase64 uses the standard Base64 alphabet but with LSB-first bit ordering, differing from standard Base64.

The key text encodes only the 64-byte signature. The identity region (`0x100-0x10F`) is **not** included in the key text; RouterOS generates it automatically on import.

---

## 5. License Verification Flow

RouterOS executes this check on every boot:

```
1. Read disk serial, model, size  (ATA IDENTIFY or custom ioctl 0x80044604)
2. Read MBR[0x100:0x10A]          (10-byte identity seed)
3. Compute SOFTWARE ID            = f(serial, model, sectors, mbr_seed)
4. Read MBR[0x110:0x150]          (64-byte KCDSA signature)
5. Verify signature               using built-in Curve25519 public key
6. Pass -> nlevel: 6              Fail -> 24-hour trial mode
```

### Installer Intervention

| Offset | Before Install | After Install | Impact |
|---|---|---|---|
| 0x10A-0x10B | `BD E8` | `FF FF` | Breaks signature verification (not SOFTWARE ID) |
| 0x10C | `00` | `01` or `05` | No impact (outside identity region) |

This is why license data must be written **after** RouterOS installation.

---

## 6. Collision Search Principle

### Why It Works

The SOFTWARE ID is a ~40-bit hash. With 20 bytes of serial (160 bits of entropy), the search space vastly exceeds the output space. Finding a serial that produces one of 4 known SOFTWARE IDs is a birthday-style search with favorable odds:

```
P(match per hash) = 4 / 2^40 ~ 3.6 * 10^-12
Trials to 50% success = ln(2) / P ~ 1.9 * 10^11
At 40M hashes/sec (16 cores): ~4750 sec ~ 80 min
```

### Why MBR-Only Modification Does Not Work

The MBR identity region contributes only 11 bits to the SOFTWARE ID via `mbr_val`. With serial/model/size fixed, only 2048 distinct SOFTWARE IDs are reachable -- but those 2048 are a fixed subset of the full ~2^40 SOFTWARE ID space, not independently drawn from it. The probability that any of them equals one of N known targets is `2048 * N / 2^40`, not `N/2048`: for this project's 10 known signatures, that's `2048 * 10 / 2^40 ~ 1.9 * 10^-8` per (serial, MBR) combination -- varying only the MBR while holding serial/model/size fixed is exactly as hard as brute-forcing the full serial space (§ Collision Search Mechanism below), not a shortcut. (An earlier version of this section stated a much more optimistic `4/2048 ~ 0.2%`, which conflated "how many values are reachable" with "probability of matching a specific external target" -- corrected here.)

### Fixed MBR Header in Collision Scheme

In our collision search, `MBR[0x100:0x10A]` is set to all zeros. This fixes `mbr_val = 0x0BD` and `mix = 0x0BD * 0x3FF800F`. The entire variation comes from iterating the serial field.

---

## 7. Security Analysis

The RouterOS licensing system has three distinct security layers with vastly different strengths:

| Layer | Mechanism | Bits | Breakable |
|---|---|---|---|
| SOFTWARE ID binding | Custom SHA-256 hash | ~40 | Yes (collision search) |
| License signature | EC-KCDSA / Curve25519 | ~252 | No |
| Public key trust | Embedded in firmware | 0 (if replaced) | Yes (firmware patch) |

Our approach exploits the weakest layer (SOFTWARE ID binding) without attacking the cryptographic signature. The signature remains valid because it covers only the SOFTWARE ID, not the full set of disk parameters. This is a protocol design limitation: the signature should ideally bind to the complete hardware identity, not just its hash.

---

## 8. ARM32 keyman on virtio-scsi: a platform-specific investigation

**Status: in progress, not yet fully resolved.** This section documents an unexplained discrepancy on a different hardware/platform combination and the disassembly evidence gathered so far. It does not change any conclusion in sections 1-7, which remain fully verified on x86 IDE.

### 8.1 The discrepancy

On a separate ARM64-hardware PVE host, a RouterOS ARM64 VM (`scsihw: virtio-scsi-pci`) was configured with a known-good x86/IDE collision-search combo:

```
serial = 00000000717959548436
model  = SSD1G (via -set device.scsi0.product=SSD1G)
size   = 1 GiB
```

On x86/IDE this combo is expected to produce `4MZF-SFTR` (per `docs/collision-database.md`). On the ARM64 VM it instead produces `3X8K-8K32`.

### 8.2 What was ruled out

- **Not an MBR/signature issue**: the test disk's MBR license region was found completely blank (identity/marker/reserved/signature all zero or garbage) before any test -- simply never written. Writing the standard MBR (`00...BDE8...` + a known signature) did not change the computed SOFTWARE ID.
- **Not the `vendor` SCSI field**: with `serial`/`size` fixed, `vendor=""` vs. the QEMU default `"QEMU"` produced an identical SOFTWARE ID.
- **`product` does participate**: changing `product` from `SSD1G` to `ZZZZZZZZZZZZZZZ` (15 chars) changed the SOFTWARE ID (to `ABAH-C0JJ`), confirming the field is hashed -- but no encoding hypothesis (space/NUL padding, left/right justify, field reordering, big-endian `sector_val`, size-as-raw-MB integer) predicted both `(product, resulting id)` pairs simultaneously from pure computation.
- **Not the SHA-256 core**: the IV and round-constant tables in the ARM32 binary are byte-identical to the x86 binary (see 8.3).

### 8.3 ARM32/Thumb-2, not true ARM64

The RouterOS "arm64" install package's `keyman` binary is actually **32-bit ARMv7-A EABI5 (Thumb-2)** code (`file`: "ELF 32-bit LSB executable, ARM, EABI5 version 1"; `readelf -A`: `Tag_CPU_arch: v7`, `Tag_THUMB_ISA_use: Thumb-2`) -- not native AArch64 -- despite running on an aarch64 kernel/host. Extracted from the guest disk via host-side loop mount (no in-guest shell needed):

```bash
qemu-nbd --read-only --connect=/dev/nbd1 vm-100-disk-1.qcow2
mount -o ro,noload /dev/nbd1p2 /mnt/ros-arm64
dd if=/mnt/ros-arm64/var/pdb/system/image of=/tmp/system.squashfs bs=4096 skip=1
mount -o ro,loop -t squashfs /tmp/system.squashfs /mnt/ros-arm64-sysimg
cp /mnt/ros-arm64-sysimg/nova/bin/keyman /tmp/keyman_arm32
```

Same SHA-256 IV `{0x5B653932, 0x7B145F8F, ...}` located at file offset via `struct.pack('<I', 0x5B653932)` byte search, confirming the hash core is unchanged from x86.

### 8.4 Located the SOFTWARE-ID hash call site

Using the same technique that worked on x86 (search for the `length=40` immediate right before the call to the hash wrapper), found in ARM mode:

```asm
192cc: mov r1, r4
192d0: add r0, sp, #272    @ 0x110    ; buffer pointer
192d4: mov r2, #40         @ 0x28     ; length = 40, confirms this is the SOFTWARE-ID hash
192d8: bl 16ff8                       ; hash wrapper, itself calls the compress fn at 0x16e74
```

### 8.5 Buffer population: two candidate data paths

Immediately before the sanitization loops that fill the 40-byte hash buffer, the code branches on the result of a low-level ioctl:

```asm
19054: add r2, sp, #20
1905c: movw r1, #0x5386        ; ioctl request code 0x5386
19060: bl ioctl@plt            ; attempt: ask the block device directly
19064: cmp r0, #0
19068: bne 19098               ; failure -> fall back

; fallback path (ioctl failed):
1906c: ldr r3, [sp, #20]
19074: ldr r2, [pc, ...]       ; format string
1907c: bl snprintf             ; build a path string
19084: bl fopen                ; open a file
...                             ; then fgets + sscanf, line by line, into string objects
```

Whichever path succeeds, the resulting data is later copied (via length-prefixed `memcpy`) into the same two fixed regions and sanitized:

```asm
1923c: add r3, sp, #24
19244: mov r2, #20             ; 20-byte region: serial
1924c: ldrb r0, [r3], #1
19250: cmp r0, #0
19254: strbeq r1, [r3, #-1]    ; NUL -> ' ' (0x20)
...
19260: add r3, sp, #44         ; 0x2c
19264: mov r1, #16             ; 16-byte region: model
...                             ; identical NUL -> ' ' sanitization
```

**This confirms the buffer layout and NUL-padding convention are identical to x86** (`serial[20] || model[16]`, embedded NULs replaced with spaces) -- the field-encoding hypotheses from 8.2 were correctly ruled out; the encoding scheme itself is not the source of the discrepancy.

### 8.6 The two candidate fallback paths, both dead ends for virtio-scsi

Decoding the literal pool referenced by this code resolved what the `0x5386` ioctl and its two "fallback" branches actually are:

**Path A -- legacy USB-storage `/proc` parsing.** If `ioctl(fd, 0x5386, ...)` succeeds, the code builds the path `/proc/scsi/usb-storage/%u` (literal format string, not a generic per-driver template) via `snprintf`, `fopen`s it, and `fgets`/`sscanf`s each line for `"Serial Number: %19s"`. This is **only** ever going to exist for USB-attached storage -- for a `virtio-scsi-pci` disk this file does not exist, `fopen` returns `NULL`, and the whole primary path is abandoned.

**Path B -- NVMe passthrough.** The fallback function (`0x17764`) turned out to be **NVMe-specific**, not generic SCSI: it `sscanf`s the device's basename against `"nvme%dn%d"`, and issues `ioctl(fd, NVME_IOCTL_ADMIN_CMD, &admin_cmd)` (request code `0xC0484E41` = `_IOWR('N', 0x41, struct nvme_admin_cmd)`, confirmed by decoding the ioctl direction/size/type/nr bitfields) to run an NVMe Identify Controller command, then extracts the 20-byte Serial Number and 40-byte Model Number fields from the response (matching the NVMe spec's SN/MN field widths exactly -- not a coincidence). For a `virtio-scsi` device named e.g. `sda`, the `"nvme%dn%d"` sscanf never matches, so this path returns failure immediately without ever calling the ioctl.

**When both fail**, the code path we traced (`main.rs`-equivalent function around `0x18c00-0x18cc0`) prints `"getHardwareID: could not get disk %s info\n"` and **returns early with an error code** -- it does not fall through to compute a hash over zeroed/default buffers.

`0x5386` was decoded precisely: it is the legacy `SCSI_IOCTL_GET_BUS_NUMBER` request code (from `<scsi/scsi_ioctl.h>`; not a modern `_IOC`-encoded number, just a plain legacy constant). It returns an integer bus number into the buffer at `sp+20`, which is then substituted into Path A's `%u` in `/proc/scsi/usb-storage/%u` -- i.e. Path A's file path is not hardcoded to bus 0, it uses whatever bus number this ioctl reports for the actual device.

An exhaustive string search of the whole binary for other plausible generic-SCSI identification strings (`/proc/scsi/scsi`, `Vendor:`, `/sys/block`, `/sys/class/scsi`, `scsi_generic`, `/dev/sg`, `INQUIRY`) found **zero matches** -- `/proc/scsi/usb-storage` (Path A, section 8.6) is the *only* `/proc`-based identification string anywhere in the binary. Combined with `SCSI_IOCTL_GET_BUS_NUMBER` succeeding for essentially any SCSI-registered block device (not just literal USB storage), this makes it likely that Path A is in fact the live path for `virtio-scsi-pci` on this custom embedded kernel -- i.e. RouterOS's virtio-scsi driver registers itself under the legacy `/proc/scsi/usb-storage` procfs tree (an unusual but plausible code-reuse choice in a heavily customized kernel), and the "no other path exists" evidence outweighs the earlier assumption that Path A's naming implies it's USB-only.

If that is correct, the real unknown is no longer *which code path runs*, but **what the kernel driver itself writes into `/proc/scsi/usb-storage/<bus>`'s `Serial Number:` line** -- that string is synthesized by the kernel's block/SCSI driver, not by `keyman`, and may not be a verbatim copy of the QEMU-level `serial=` SCSI INQUIRY property (VPD page 0x80). This would fully explain the observed behavior: `product` (read via a different, still-unlocated field/mechanism) visibly affects the result, while the expected `serial` does not, because the actual hashed "serial" bytes come from whatever the kernel driver formats into that procfs line, not from what QEMU was told to report.

### 8.7 Verification blocked without dynamic tracing

RouterOS ships no interactive Linux shell in the guest (confirmed earlier in this investigation), so `cat /proc/scsi/usb-storage/<bus>` cannot simply be run from inside the VM to check what the kernel driver actually wrote there. Confirming the working hypothesis in 8.6 would require either running `keyman`/`nova` under user-mode ARM emulation (`qemu-arm-static` + `strace -f`) against a representative block device outside the guest, or finding another way to read that specific `/proc` file's contents from inside a running RouterOS ARM64 VM (e.g. a custom RouterOS package with shell access, if one exists) -- neither has been attempted yet.

### 8.8 Dynamic-tracing attempt (qemu-arm + strace)

An attempt was made to resolve 8.6/8.7 dynamically rather than statically, using `qemu-arm` (user-mode ARM emulation, available on the ARM64 PVE host) plus `strace -f` against the real `keyman` binary and its runtime dependencies extracted from the guest image.

**What worked:**

- `qemu-arm -L <sysroot>` successfully loads and runs the ARM32 `keyman`/`loader` binaries against the extracted `/lib/*.so` set, with `strace -f` transparently observing every real syscall the guest program issues (since user-mode QEMU translates each guest syscall into a real host syscall).
- `keyman` first tries to connect to a Unix-domain control socket (`/ram/novasock`) belonging to "the loader" -- RouterOS's `nova`-framework process supervisor (binary at `nova/bin/loader`, also present in the extracted image). Running the *real* `loader` binary (also under `qemu-arm`) makes this socket genuinely live, rather than needing to fake it.
- `loader` itself required a working `/dev/mtdblock0` (physical RouterBOARD flash) satisfying an ATA `HDIO_DRIVE_CMD`/`HDIO_GET_IDENTITY` probe before it would proceed past its own board-identity check -- confirmed via `strace -e inject=ioctl:retval=0` (forcing these ioctls to report success) that this check is **non-fatal** when faked: `loader` printed `STRONG FAIL: this is not equal to that` (a checksum mismatch, expected since the injected data is garbage) but continued to `scheduling service startup...` and successfully bound `/ram/novasock`.
- With the real `loader` alive and `/ram/run` created, `keyman` connects, exchanges an initial handshake (`sendmsg` of a 27-byte `nv::message`-framework packet), and blocks in `ppoll()` waiting for `loader`'s reply.

**Where it stopped:** `loader` never sends a reply to this specific request (still waiting for it to reach full readiness, or the request type isn't handled given the earlier faked/failed board-identity check). Attempting to force progress by fault-injecting `ppoll`/`recvmsg` to report a fabricated "response ready" (via `strace -e inject`) crashes `qemu-arm` itself with an internal `SIGSEGV` -- the guest code computes jump targets/offsets from the (fabricated, garbage) message content, and without knowing the real `nv::message` wire format (a typed binary RPC protocol built on C++ template methods `message::insert<u32_array_id>`/`append<>`/`extract<>`, disassembled far enough in `libumsg.so`'s `nv::Looper::connectLoader` to confirm its shape but not its exact byte layout), no fabricated response is safe to inject.

Fully resolving 8.6/8.7 dynamically would require decoding this RPC protocol precisely enough to author a real (not fabricated) `loader`-side reply -- a substantially larger reverse-engineering effort than the static disassembly in 8.1-8.7, and was not completed.

### 8.9 Not ARM-specific: root cause confirmed via the x86 binary too

Testing on x86_64 PVE hosts confirms the same failure with `scsi0` (virtio-scsi/LSI) and `sata0` bus types -- collision-search combos verified on `ide0` do **not** reproduce there either. Disassembling `tools/bin/keyman_x86_7.23.2` (the x86 binary already used for sections 1-7) around its own `getHardwareID`-equivalent function resolves this completely, and turns 8.1-8.8's ARM findings from "likely" into confirmed:

```asm
; try the ATA-specific path first
pushl  $0x31f              ; HDIO_DRIVE_CMD -- standard Linux ATA passthrough ioctl
pushl  <fd>
calll  ioctl@plt
testl  %eax, %eax
je     <skip SCSI, use ATA IDENTIFY data>   ; ioctl succeeded -> real ATA/IDE device

; ATA ioctl FAILED (not a real ATA device) -- fall back to the SCSI-generic path:
pushl  $0x5386              ; SCSI_IOCTL_GET_BUS_NUMBER -- identical to the ARM32 code in 8.6
pushl  <fd>
calll  ioctl@plt
...
pushl  $"/proc/scsi/usb-storage/%u"   ; identical string, identical snprintf/fopen/fgets/sscanf loop
...
pushl  $"Serial Number: %19s"         ; identical format string
```

This is **byte-for-byte the same logic** as the ARM32 disassembly in 8.5-8.6 -- same `0x5386` ioctl, same `/proc/scsi/usb-storage/%u` path, same `Serial Number: %19s` format, and the same `0x80041272` (`BLKGETSIZE64`) constant elsewhere in the function. It is shared source code compiled for both architectures, not an ARM-specific quirk.

The dispatch logic is now fully explained: `HDIO_DRIVE_CMD` (`0x31f`) only succeeds against a real ATA/IDE device (`/dev/hd*`, or a QEMU `ide0`-attached disk). Any disk exposed through the Linux SCSI subsystem instead (`/dev/sd*` -- `scsi0`, `sata0`/AHCI, and `virtio-scsi-pci` all present this way to the guest kernel) fails the ATA ioctl and falls through to the narrow `GET_BUS_NUMBER` + `/proc/scsi/usb-storage` text-parsing path from 8.6 -- which, as established there, is only ever populated for literal USB-attached storage and is not guaranteed to reflect QEMU's `serial=` property verbatim for other SCSI transports. This is a **disk-bus-type** issue, not a CPU-architecture one: it reproduces identically on x86_64/`scsi0`+`sata0` and ARM64/`virtio-scsi-pci`, and does not reproduce on `ide0` on either architecture.

### 8.10 Practical implication

**Collision-search results in this project (`docs/collision-database.md`) are only verified for `ide0`-attached disks**, and that is now known to be a hard requirement rather than an incidental detail of how the reference hardware happened to be captured: `HDIO_DRIVE_CMD` must succeed, which requires a real ATA/IDE-presented disk. `scsi0`, `sata0`, and `virtio-scsi-pci` are all confirmed **not** interchangeable with `ide0` for this purpose, on x86_64 or ARM64. **Always attach the target disk as `ide0` when applying a collision-search result.**

### 8.11 `serial=` is controllable on `scsi0` too -- confirmed empirically

The one open question from 8.6-8.9 -- whether the SCSI fallback path's `Serial Number:` value reflects QEMU's `serial=` property at all, or is synthesized by the kernel independent of it -- is resolved. Tested on the ARM64 host (`192.168.2.1`, VM 100, `scsi0`, `product=ZZZZZZZZZZZZZZZ` fixed):

| `serial=` | Resulting SOFTWARE ID |
|---|---|
| `00000000717959548436` | `ABAH-C0JJ` (reproduced across two separate boots) |
| `AAAAAAAAAAAAAAAAAAAA` | `BSW5-9EGM` |

Changing only `serial=` deterministically changes the SOFTWARE ID, and reverting it reproduces the original result exactly. **`serial=` is read and does participate in the hash on `scsi0`** -- it is not ignored or kernel-synthesized. The earlier mismatch (8.1: `product=SSD1G` expected `4MZF-SFTR`, got `3X8K-8K32`) is therefore not "serial is uncontrollable on SCSI" -- it is that the SCSI path's byte-level encoding of `serial=`/`product=` into the 40-byte hash input differs from `ide0`'s, in a way not yet reverse-engineered (padding, truncation via `%19s`, or a different field order than `serial[20] || model[16]`).

This means a **dedicated `scsi0`-targeted collision search is plausible in principle** -- unlike a scenario where the kernel discards/regenerates the identity, here the mapping is deterministic and (based on this one data point) appears to still depend on both `serial=` and `product=`. What's missing is the exact encoding rule for the SCSI path, which would need to be derived either by further disassembly of the `/proc/scsi/usb-storage` parsing/hash-input-assembly code (8.5-8.6 traced the sanitization loops but not the final byte layout used for this specific path) or by black-box probing (vary `serial=` systematically, observe the resulting SOFTWARE IDs, and infer the transform) -- neither has been done yet.

### 8.12 Found the real mechanism: `SG_IO` + standard INQUIRY + VPD page 0x80

Continuing the disassembly of `tools/bin/keyman_x86_7.23.2` around the same function (just before the `GET_BUS_NUMBER`/`/proc/scsi/usb-storage` code from 8.9) turned up a second, more legitimate SCSI-identification path that had not been located before -- and it is almost certainly the one actually responsible for the empirical result in 8.11, not the `/proc/scsi/usb-storage` text parse.

A helper function at `0x804fa51` builds a standard Linux `sg_io_hdr_t` on the stack and calls `ioctl(fd, 0x2285, &sg_io_hdr)`:

```asm
movl   $0x53, -0x58(%ebp)        ; interface_id = 'S'  (sg_io_hdr_t.interface_id)
movl   $0xfffffffd, -0x54(%ebp)  ; dxfer_direction = SG_DXFER_FROM_DEV (-3)
movb   %al, -0x50(%ebp)          ; cmd[0] = CDB opcode byte, taken from the caller's request
...
movl   $0x3e8, -0x3c(%ebp)       ; timeout = 1000 ms
pushl  $0x2285                   ; SG_IO
calll  ioctl@plt
```

`0x2285` is the standard Linux `SG_IO` ioctl (`_IOWR('S', 0x85, sg_io_hdr_t)`) -- this is genuine SCSI-generic passthrough, not the ARM32 `NVME_IOCTL_ADMIN_CMD` (`0xc0484e41`) that was initially (and incorrectly) suspected to be the same thing in early ARM32 analysis.

The caller invokes this wrapper twice with different CDB values:

```asm
movl   $0x12, -0x2a0(%ebp)       ; CDB = 0x00000012 -> opcode 0x12 (INQUIRY), EVPD=0  (standard inquiry)
...
calll  0x804fa51                 ; -> vendor/product/revision (this is where "product" comes from)
...
movl   $0x800112, -0x2a0(%ebp)   ; CDB bytes (LE) = 12 01 80 00 -> opcode 0x12, EVPD=1, page=0x80
...
calll  0x804fa51                 ; -> Unit Serial Number VPD page (this is where "serial" comes from)
```

`INQUIRY` with `EVPD=1, page=0x80` is the standard SCSI "Unit Serial Number" VPD page -- exactly the mechanism QEMU's `scsi-hd`/`virtio-scsi-pci` backend uses to expose the `serial=` device property to the guest. This is consistent, deterministic, and guest-kernel-independent (unlike the `/proc/scsi/usb-storage` text file, which depends on which kernel subsystem happens to register the device there) -- it directly explains why 8.11's black-box test found `serial=` to be reliably controllable.

**The VPD-80 extraction logic was fully traced and matches the standard SCSI VPD-80 wire format exactly:**

```asm
movb   -0x21d(%ebp), %al   ; al = response[3]  -- VPD page's "page length" byte (offset 3)
cmpb   $-6, %al             ; clamp to 0xFA (250) as a safety cap
jbe    ...
movzbl %al, %esi            ; esi = clamped length
xorl   %ebx, %ebx           ; ebx = index, starts at 0
; loop:
movzbl -0x21c(%ebp,%ebx), %eax   ; response[4+i]  -- first byte of VPD-80's ASCII serial payload
pushl  %eax
calll  isprint@plt
testl  %eax, %eax
je     <break>               ; stop at the first non-printable byte
incl   %ebx
jmp    <loop>
; after loop: ebx = count of leading printable bytes (<= page-length byte, <= 250)
```

This is byte-for-byte the standard T10 VPD page 0x80 layout (`peripheral qualifier/type` (1) + `page code=0x80` (1) + reserved (1) + `page length N` (1) + N bytes of ASCII serial number starting at offset 4) -- the code takes the ASCII payload starting right after the 4-byte VPD header, and copies out the printable-prefix run (bounded by both the page-length byte and a 250-byte safety cap). For QEMU's `serial=` property (which populates this exact VPD-80 payload for `scsi-hd`/`virtio-scsi-pci`), an all-printable-ASCII value like a 20-character serial should therefore be captured in full and unmodified -- consistent with 8.11's clean, deterministic `serial=` -> SOFTWARE-ID mapping.

**The standard-INQUIRY (non-EVPD) result feeds "model"** via a *fixed*-length copy (`0x10` = 16 bytes, no `isprint()` trimming) from response offset 16 -- exactly the standard SCSI INQUIRY "Product Identification" field (bytes 16-31 of the standard 36-byte INQUIRY response). QEMU's `product=` property populates this field, space-padded per the T10 spec, so this is also expected to be a clean, direct copy.

**Precedence resolved:** `GET_BUS_NUMBER` + `/proc/scsi/usb-storage` (8.9) *is* attempted unconditionally, immediately after the two `SG_IO` calls, regardless of whether they succeeded -- but its result is only *used* as a last resort:

```asm
movl   %esi, %eax     ; esi was set by the SG_IO VPD-80 call: 1 = ioctl succeeded, 0 = failed
testb  %al, %al
jne    0x80509fd       ; VPD-80 succeeded -> jump straight to finalization with the SG_IO-derived
                        ; serial/product, discarding whatever /proc/scsi/usb-storage parsed
; only reached if VPD-80 FAILED:
calll  0x804fac1        ; a third, distinct identification routine (not yet traced) -- its result
                         ; is what actually gets used when SG_IO is unavailable
```

So the real priority order is: **`SG_IO` (standard INQUIRY + VPD-80 Unit Serial Number) wins whenever it succeeds; `/proc/scsi/usb-storage` text parsing and a third fallback routine at `0x804fac1` are only consulted if `SG_IO` fails outright** (e.g. permission denied on the device node, or the backend doesn't implement SCSI-generic passthrough). For `virtio-scsi-pci`/`scsi-hd` under QEMU -- both of which do support `SG_IO` -- this means 8.12's clean INQUIRY+VPD-80 mechanism is expected to be the one actually in effect, matching 8.11's clean empirical result. This resolves the open precedence question and gives high confidence that the "20-byte printable-ASCII prefix of the VPD-80 payload" and "16-byte raw copy of the standard INQUIRY Product ID field" rules in this section are the real `scsi0` encoding -- a dedicated `scsi0` collision-search implementation is the natural next step, not further disassembly.

### 8.13 `0x804fac1` traced: it's the same NVMe fallback as ARM32, confirmed identical

`0x804fac1` -- the "third fallback", only reached when the `SG_IO` VPD-80 call fails outright -- turns out to be **the exact same NVMe-specific mechanism already documented for ARM32** (§8.1-8.4's `keyman_arm32` analysis), not a new, distinct code path. Confirmed byte-for-byte:

```asm
movb   $0x6, -0x1060(%ebp)       ; cmd_len = 6 (NVMe admin-command CDB-style length)
pushl  $0xc0484e41                ; NVME_IOCTL_ADMIN_CMD -- identical constant to the ARM32 binary
movl   $0x1000, -0x103c(%ebp)     ; 4096-byte response buffer (NVMe Identify Controller response size)
calll  ioctl@plt
je     <process NVMe Identify response>   ; ioctl succeeded -> use it directly

; only reached if the ioctl on the ORIGINAL fd fails:
calll  basename@plt
pushl  $"nvme%dn%d"                ; sscanf the device basename against this pattern
calll  sscanf@plt
...                                 ; if it matches, open "/dev/nvme<N>" and retry the same
                                     ; NVME_IOCTL_ADMIN_CMD ioctl against that controller node
```

And the response parsing confirms the same field widths as ARM32's NVMe path:

```asm
strnlen(buf_at_offset_20, 0x28)   ; 0x28 = 40 -- NVMe "Model Number" field width
strnlen(buf_at_offset_0,  0x14)   ; 0x14 = 20 -- NVMe "Serial Number" field width
```

This is genuinely shared, cross-architecture source code (as expected, given 8.9's confirmation for the `SG_IO`/`GET_BUS_NUMBER` paths) -- there is no separate, not-yet-found x86-specific fallback. **The complete, now fully-traced hardware-identification priority chain for `keyman`/`nova`, across both architectures:**

| Priority | Mechanism | Bus types it actually works for | Source of `serial`/`model` |
|---|---|---|---|
| 1 | `ioctl(HDIO_DRIVE_CMD)` (`0x31f`) | `ide0` (real ATA/IDE) | Real ATA IDENTIFY data -- ground truth for this project's collision database (§1-7) |
| 2 | `ioctl(SG_IO)` (`0x2285`): standard INQUIRY + EVPD page 0x80 | `scsi0`, `sata0`/AHCI, `virtio-scsi-pci` -- anything with working SCSI-generic passthrough | Product ID field (16B, raw) + VPD-80 printable-ASCII prefix (up to 20B) -- §8.12, confirmed to track QEMU's `serial=`/`product=` |
| 3a | `SCSI_IOCTL_GET_BUS_NUMBER` (`0x5386`) + `/proc/scsi/usb-storage/<bus>` text parse | Literal USB-attached storage only | `Serial Number: %19s` line -- §8.6, only used if priority 2 fails |
| 3b | `NVME_IOCTL_ADMIN_CMD` (`0xc0484e41`) via basename match `nvme%dn%d` | NVMe devices (`/dev/nvme0n1` etc.) | NVMe Identify Controller SN (20B)/MN (40B) fields -- this section, only used if priority 2 fails |

Priorities 3a and 3b are tried in an unspecified order relative to each other when priority 2 fails (not yet determined which is attempted first), but neither applies to `scsi0`/`sata0`/`virtio-scsi-pci` disks in practice, since those support `SG_IO` and priority 2 wins before either is reached.

### 8.14 SCSI collision search works for SOFTWARE ID -- but the license still doesn't validate

The `--bus scsi` encoding from 8.11-8.13 (`sector_val=0`, standard `serial[20]+model[16]` layout) was implemented in `mtsc` and run as a real search (see `docs/command-reference.md` for the `--bus` flag). It found genuine hits -- e.g. `serial=00000000430480281048`, `model=SSD1G`, `size=1G`, `--bus scsi` computes `C7CU-PGT9`, matching this project's known signature exactly. Booting this combo on a real `scsi0` VM confirmed `software-id: C7CU-PGT9` on `/system license print`, proving the SOFTWARE ID side of 8.11-8.13 is correct and the SCSI-specific search is genuinely usable for finding *matching SOFTWARE IDs*.

**However, writing `C7CU-PGT9`'s known-good MBR (`00...BDE800000000` + its signature) to the standard file offset `0x100` and rebooting did not activate the license** -- `/system license print` kept showing the SOFTWARE ID correctly but stayed in 24-hour trial mode (`expires-in`) instead of `nlevel: 6`. Ruled out:

- **Not the boot-counter (`reserved`, `0x10C-0x10F`) incrementing.** RouterOS bumped it from `00000000` to `01000000` after the first boot, matching documented behavior (§5's installer-intervention table) and consistent with §3.6's finding that `reserved`/`marker` don't affect the SOFTWARE ID computation. Explicitly resetting `reserved` back to `00000000` and rebooting again made no difference -- still trial mode.
- **Not ARM64-specific.** The same failure to activate (correct SOFTWARE ID, signature doesn't validate) was independently observed on an x86_64 host with a `scsi0`-attached disk as well.

Since this reproduces identically across architectures and is unaffected by `reserved`, the most likely explanation -- not yet confirmed by disassembly -- is that **license *signature validation* (reading the MBR license region at boot, independent of the `serial`/`model` identification code traced in 8.1-8.13) may also be bus-type-dependent**, e.g. not reading from the standard file offset `0x100` at all for SCSI-attached disks, mirroring the same pattern already found for `serial`/`model` reads. This has not been investigated -- 8.1-8.13 only trace how `serial`/`model`/`sector_val` become the SOFTWARE ID input; the boot-time MBR-read/signature-verify code path (§5's "License Verification Flow") is a distinct, not-yet-disassembled part of `keyman`/`nova`.

**Practical implication:** a `--bus scsi` search can currently find a serial whose *computed SOFTWARE ID* matches a known signature (useful for research, and confirmed accurate), but **does not yet result in an activatable license** on `scsi0`/`sata0`/`virtio-scsi-pci` -- full activation on those bus types remains unsolved pending disassembly of the MBR-read path used during boot-time signature verification.

### 8.15 Found it: on QEMU/KVM, `readMBR` doesn't touch the disk at all -- it uses `/dev/hvckvm0`

Disassembling `readMBR`'s internals resolves 8.14. `readMBR` first calls a cached predicate (`0x804f902`) that is **byte-for-byte the same `getenv("board")` + `strstr(..., "qemu")` check already found on ARM32** (§8.9's virtualization-detection function) -- confirming this is shared, cross-architecture logic, not something new.

When that predicate is true (i.e. running under QEMU/KVM, which covers essentially every PVE VM), `readMBR` skips the physical-flash path (`/dev/flash` + custom `0x4601`/`0x90004602` ioctls, for real RouterBOARD hardware) entirely and instead:

```asm
calll  0x804f76f            ; a second, more specific gate check
testb  %al, %al
je     <fail>                ; bail out if false

pushl  $2                     ; O_RDWR
pushl  $"/dev/hvckvm0"        ; MikroTik-private hypervisor virtual console device
calll  open@plt
...
calll  tcgetattr@plt          ; configure it as a raw terminal (no echo, no canonical mode, etc.)
calll  tcsetattr@plt
...
; later, via 0x804f9a0(fd, cmd=6, len=0x208):
write(fd, {len=8, cmd=6}, 8)  ; send an 8-byte request: "read command 6"
read(fd, buf, 0x208)           ; read back a 520-byte response (512-byte sector + 8-byte header?)
```

`/dev/hvckvm0` ("hvc" = hypervisor virtual console, the standard Linux paravirtualized-console naming convention used by Xen/KVM `virtio-console`) is a **MikroTik-private device node, not a standard block device**. This means: **on any QEMU/KVM-detected VM, `readMBR` never reads the guest disk file at all** -- it sends a small request over this console channel and expects a companion process (presumably MikroTik's own CHR-specific QEMU integration, or a host-side helper backing this virtio-console) to respond with sector data. Writing directly to the disk image via `qemu-nbd` (as done throughout this project, including 8.14's failed activation attempt) **never touches whatever `/dev/hvckvm0` actually returns** -- these are two completely independent data paths.

This fully explains 8.14's mystery without needing any further bus-type-dependent hypothesis: the MBR write itself was never going to be read back by a standard PVE VM, because standard PVE VMs almost certainly don't provide a working `/dev/hvckvm0` backend (this is CHR/MikroTik-cloud-image-specific QEMU integration that a plain `qm create`-built VM has no reason to implement). Whether `open("/dev/hvckvm0")` succeeds or fails inside our test VMs, and if it fails, what `readMBR` falls back to (if anything), has not yet been checked -- this is the next concrete step, and does not require any more static disassembly to investigate (it's a runtime/environment question: does `/dev/hvckvm0` exist in the guest, and if not, does `readMBR` have any further fallback beyond this one already-traced branch).

### 8.16 `/dev/hvckvm0` traced further: it's the standard Linux `hvc0` virtio-console driver, self-provisioned, with no fallback on failure

The gate function `0x804f76f` was disassembled and resolves the remaining questions in 8.15:

```asm
cmpb   $0x0, <cached_flag>
je     <compute>
retl                               ; return cached result on repeat calls

; first call:
pushl  <stat_buf>
pushl  $"/dev/hvckvm0"
calll  stat@plt
testl  %eax, %eax
jne    <not_found>                 ; stat failed -> device node doesn't exist yet
movb   $1, <cached_ok_flag>        ; already exists -> success, done
...
<not_found>:
pushl  $"r"
pushl  $"/sys/class/tty/hvc0/dev"
calll  fopen@plt
testl  %eax, %eax
je     <fail>                       ; sysfs entry doesn't exist either -> give up (cached_ok_flag stays 0)
...
fscanf(fp, "%u:%u", &major, &minor)
fclose(fp); unlink("/dev/hvckvm0")
mknod("/dev/hvckvm0", S_IFCHR|0777, makedev(major, minor))
movb   $1, <cached_ok_flag>
```

`hvc0` ("Hypervisor Virtual Console") is a **standard upstream Linux kernel driver** (`CONFIG_HVC_DRIVER`), used for Xen PV consoles and `virtio-console` devices -- it is not a MikroTik invention. `/sys/class/tty/hvc0/dev` is the normal sysfs path any Linux kernel exposes for a registered `tty` device's `major:minor`, used here purely to self-provision the `/dev/hvckvm0` node (since a CHR image's minimal `/dev` may not have it pre-populated by udev). The logic reduces to: **"does this VM have a `virtio-console` (or Xen console) device attached to the guest?"** -- if yes, use it as the MBR data channel; if no, `readMBR` returns failure with **no further fallback** on this code path.

Standard PVE VMs created via `qm create`/`qm set` (including every VM used in this session, and almost certainly the historical `ide0` VMs behind this project's verified collision-database entries) **do not attach a `virtio-console` device by default** -- PVE's `serial0: socket` option (used throughout this project for console access) provisions an **isolated PC-style UART** (`ttyS0`/`COM1`), which is a completely different QEMU device (`isa-serial`/`pci-serial`) from `virtio-console` (`virtconsole`/`virtio-serial-bus`). Having `serial0: socket` configured does **not** make `/sys/class/tty/hvc0` appear.

This raises a real, testable question this section does not yet answer: **the project's own collision-database entries were verified as fully activated (`nlevel: 6`, no `expires-in`) on plain PVE `ide0` VMs** -- if `board` containing `"qemu"` unconditionally forces this `hvc0`-only path with no fallback, how did those succeed without a `virtio-console` device? Two explanations are consistent with the evidence so far, neither yet confirmed:

1. **The `board` environment variable's actual value differs by VM configuration** (machine type, `smbios1` overrides, BIOS vs. OVMF, etc.), and the historically-successful `ide0` VMs' `board` value happened not to contain the substring `"qemu"` -- in which case `0x804f902` returns false immediately and `readMBR` takes the `/dev/flash`-then-generic-`fopen()` path from 8.15 instead (which, being a plain file read, would work identically on `ide0` regardless of bus type).
2. **`ide0` disks are read through an entirely different, not-yet-traced license-verification code path** that doesn't share this `readMBR` function's `board=qemu` branch at all.

**Next step (empirical, no further disassembly needed):** compare `getenv("board")`'s actual value between a VM known to activate successfully on `ide0` and the `scsi0` VMs used in 8.11-8.15 -- if the `ide0` VM's value doesn't contain `"qemu"`, explanation 1 is confirmed, and the practical fix for `scsi0`/`sata0` activation becomes straightforward: override the VM's reported `board`/SMBIOS values so `"qemu"` isn't a substring, steering `readMBR` back onto the `/dev/flash`-or-generic-file-read path instead of the `hvc0`-only one.

### 8.17 Tried overriding SMBIOS to dodge `board=qemu` -- landed in a third, different detection branch (`MetaROUTER`)

To test 8.16's hypothesis directly, PVE's `smbios1` `product`/`manufacturer` fields were overridden away from the QEMU defaults (`qm set <vmid> --smbios1 uuid=<existing>,product=<base64>,manufacturer=<base64>,base64=1`, non-default values chosen to avoid the substring `"qemu"`), keeping everything else (disk, `serial=`/`product=` SCSI properties, `--bus scsi` search target) identical to the already-confirmed `C7CU-PGT9` combo from 8.14.

**Result: the boot behavior changed completely, but not to the expected `/dev/flash`-fallback path.** Before the override, boot showed the normal 24-hour CHR trial banner (`software-id: ..., expires-in: 23hXXm`). After the override:

- The CLI prompt changed from `[admin@arm64]` to **`[admin@MetaROUTER]`**.
- The boot banner changed to `ROUTER HAS NO SOFTWARE KEY` with an unusual **~136-year** countdown (`1193046h27m`) instead of the normal 24-hour trial.
- `/system license print` now shows **only** `software-id: C7CU-PGT9` -- no `expires-in` line at all (neither the trial state nor a fully-activated `nlevel: 6` state).

This is RouterOS's **`MetaROUTER`** mode -- MikroTik's nested-virtualization feature where a guest router is normally expected to receive its license from a *parent* RouterOS instance rather than validating its own disk MBR, which plausibly explains why the normal trial/license flow is bypassed entirely once this mode is detected.

The trigger was located via a debug string in `lib/libumsg.so` (shared across the whole `nova` framework, not `keyman`-specific):

```
"open /dev/rb failed, probably metarouter"
```

i.e. **a third hardware-presence check**, independent of both `readMBR`'s `board`-string check (8.15-8.16) and the `/dev/hvckvm0` virtio-console path (8.15-8.16): the framework tries to `open("/dev/rb")` (a "RouterBOARD" device -- distinct from `/dev/flash` and `/dev/hvckvm0`), and if that fails, concludes "probably MetaROUTER" and apparently short-circuits the normal boot-time license flow well before `readMBR`'s own `board=qemu` branching is reached.

**Net result: changing `smbios1` did successfully steer the platform-detection logic away from `board=qemu`, but toward a different special-cased mode rather than the plain-hardware `/dev/flash`/generic-file-read path 8.16 hypothesized.** This is not yet a working activation path, and not yet a dead end either -- the open questions are:

- What exact condition triggers the `/dev/rb`-absence -> "MetaROUTER" conclusion, and is it purely `open()` failing, or does it also depend on the same `board` string (e.g. some other substring match, not just absence of `"qemu"`)?
- Does the *original* `board=qemu` value (unmodified SMBIOS) also fail `open("/dev/rb")` -- i.e. is `/dev/rb` open failing on *every* QEMU VM regardless of `board`, with `board=qemu` normally taking priority and being checked *first* (explaining why the un-modified VMs never showed `MetaROUTER` -- the `board=qemu` branch intercepted the check before `/dev/rb` was ever tried)? If so, the real fix may require a `board`/SMBIOS value that is simultaneously **not** `"qemu"`-like *and* somehow satisfies (or avoids) the `/dev/rb`-presence check -- which likely means creating an actual `/dev/rb` device node (analogous to 8.15's `/dev/flash`) rather than relying on `smbios1` alone.
- Whether `flash.ko` (a real, present kernel module in this image that also references `MetaROUTER` per the string search) is involved in provisioning `/dev/rb`, the way `hvc0`/sysfs was used to self-provision `/dev/hvckvm0` in 8.16 -- not yet disassembled.

This has not been resolved -- continuing requires disassembling `libumsg.so`'s `MetaROUTER`-detection function (the `open("/dev/rb")` caller) and `flash.ko` to determine what, if anything, would make `/dev/rb` present and change this outcome.

**Correction (per direct operator experience, not independently re-verified by feature-testing in this session):** despite the `ROUTER HAS NO SOFTWARE KEY` banner, the `1193046h27m` countdown, and the absence of `nlevel`/`expires-in` in `/system license print`, **this `MetaROUTER` state is reported to function as activated in practice** -- i.e. it is not actually feature-limited the way a genuine trial/unlicensed state is. This directly contradicts the reasoning earlier in this document (and in §8.28 below) that treated the presence of the boot-time "no software key" banner as proof of non-activation. That reasoning was a plausible inference from RouterOS's normal (non-`MetaROUTER`) behavior, generalized to `MetaROUTER` without actually testing an L6-gated feature under it -- an assumption, not a verified fact. If confirmed (see open item below), this reframes 8.17-8.18's "not yet a working activation path" conclusion entirely: the SMBIOS-override method **is** a working activation path for ARM64/`scsi0`, just with cosmetic boot messaging that looks like failure. **Still open, and confirmed as a planned follow-up (not yet done):** two competing explanations need to be tested against each other on `VM301` before this can be written up as settled:

1. A specific L6-only feature (hotspot user cap, queue count, PPPoE/PPTP concurrent session limit, or similar) is confirmed *unrestricted* under this exact `MetaROUTER` state, which would mean the SOFTWARE ID/signature combination genuinely is being honored despite the cosmetic banner.
2. `MetaROUTER`-mode guests are *categorically* exempt from license enforcement regardless of their own software-key state (i.e. license checks are delegated to/skipped for nested guests entirely), which would mean this "activation" has nothing to do with the `C7CU-PGT9` signature at all and would work identically with *any* disk, licensed or not -- a materially different (and much weaker) result for this project if true, since it wouldn't actually validate the collision-search method on ARM64.

These two explanations make different, testable predictions (explanation 2 predicts an *unsigned* or *deliberately wrong-signature* disk would show the same "activated" behavior under `MetaROUTER`; explanation 1 predicts it would not) -- that differential test is the concrete next step, not yet run.

### 8.18 Resolved on x86_64: `scsi0` activates cleanly out of the box, no SMBIOS tricks needed -- this was an ARM64/`virt`-machine-type quirk, not a SCSI limitation

A fresh, minimal-config test settles 8.9-8.17's remaining open question. A brand-new x86_64 PVE VM was built from scratch (cloned from a working RouterOS template, default `smbios1` -- **no product/manufacturer override at all**):

- `scsihw: virtio-scsi-pci`, `scsi0` disk, 1G, `serial=00000000430480281048`, `-set device.scsi0.product=SSD1G` (the exact `--bus scsi` search hit from 8.14/`C7CU-PGT9`)
- Fresh RouterOS 7.24 install directly onto the `scsi0` disk (installer run via `qm sendkey`, `a`/`i`/`y`)
- Shut down (not rebooted) per the standard MBR-write procedure, then the standard `00...BDE800000000` + `C7CU-PGT9` signature MBR written via `qemu-nbd`
- Booted once

Result: `/system license print` shows

```
software-id: C7CU-PGT9
nlevel: 6
features:
```

**Fully activated -- no `expires-in`, `nlevel: 6`, on the first boot, with zero SMBIOS manipulation.** This is the cleanest possible confirmation that the `--bus scsi` SOFTWARE-ID encoding (8.11-8.13) and the standard MBR-write activation procedure both work correctly and completely on a real `scsi0`/`virtio-scsi-pci` disk -- there is no `scsi0`-specific activation problem on x86_64.

**This reframes 8.14-8.17 entirely.** The activation failures documented there were specific to the **ARM64 test VM's `virt` QEMU machine type**, not to `scsi0`/SCSI as a bus type in general.

One assumption from 8.16-8.17 needs correcting, though: it is **not** simply "x86's DMI doesn't say QEMU." Checked directly via `/system resource print` on the working x86 VM: `board-name: x86 QEMU Standard PC (Q35 + ICH9, 2009)` -- this **does** contain `"QEMU"`, just like the ARM64 VM's `board-name: arm64 QEMU KVM Virtual Machine` did. Both platforms' *displayed* `board-name` contain the substring, yet only ARM64 hit the problem branch. This means **`keyman`'s internal `getenv("board")` value is not simply identical to the `board-name` string shown by `/system resource print`** -- they likely come from related but distinct sources (or different case-normalization), and `strstr(getenv("board"), "qemu")` is a case-sensitive C string search, so the exact casing of whatever `board` actually contains matters and has not been directly captured (no way to read `keyman`'s process environment from the RouterOS CLI).

**Root cause, now understood at the product level (not just the code level):** the ARM64 image used throughout §8 is a **non-CHR** RouterOS build -- i.e. the standard image for real RouterBOARD ARM64 hardware, not MikroTik's virtualization-oriented CHR product line (which only ships for x86_64). Running it under plain QEMU/KVM is an unsupported/incidental use case for this image, whereas x86_64 CHR is an officially supported virtualization product with its own `board=qemu` handling built in from the start. Disassembly confirms `loader` and `keyman` never call `setenv`/`putenv` for `board` -- both only `getenv()` it, meaning the value is set upstream (kernel command line / boot chain), not computed by either binary. The `MetaROUTER`/`/dev/hvckvm0` detection maze (8.15-8.17) is most plausibly infrastructure built for MikroTik's own real-hardware nested-virtualization feature (a physical RouterBOARD host running a guest RouterOS instance, where `/dev/hvckvm0` and `/dev/rb` are genuinely provisioned by the host) -- not for "RouterOS running directly under generic QEMU/KVM." On this non-CHR ARM64 image, `board` containing `"qemu"` is coincidental (or triggers a check meant for that nested-hardware scenario), and neither `/dev/hvckvm0` nor `/dev/rb` exist in our plain-QEMU setup, so it falls through to the broken states in 8.15-8.17. x86_64 avoids all of this not because of a DMI-string difference, but because it's running the **CHR** image, an entirely different, virtualization-first product build. This is the most coherent explanation available without MikroTik's source, though the exact `board` string and the code path that sets it (kernel cmdline vs. boot-chain script) has not been directly captured -- see the note in §8's introduction about checking VM300 (a disposable clone) for this if it's ever needed.

**Practical implication -- superseding 8.10's blanket warning:** `--bus scsi` search results **are** activatable, at least on x86_64 with a standard PVE-default `smbios1` (no override required). The remaining open question is narrower than previously stated: does `scsi0` activation also work on **ARM64** with a `board`/SMBIOS value that avoids `"qemu"` *and* avoids triggering the `MetaROUTER` fallback from 8.17 (e.g. a value resembling real RouterBOARD ARM64 hardware) -- this was not retested after 8.18's x86 result and remains open specifically for ARM64/`virt`, not for `scsi0` in general.

### 8.19 `sector_val=0` confirmed size-independent -- tested at 2GiB, not just 1GiB

8.11's `sector_val=0` finding was originally validated against 7 real boot tests, all on a single 1GiB disk -- leaving open whether `sector_val=0` was a genuine, size-independent property of the `scsi0` path, or coincidentally zero only for that one disk size.

Retested with a **fresh install** on a **2GiB** `scsi0` disk (same host as 8.18, same `serial=00000000430480281048`/`product=SSD1G` -- only the disk size changed): full activation succeeded identically -- `software-id: C7CU-PGT9`, `nlevel: 6`, no `expires-in`, same as the 1GiB case. Since `--bus scsi` computes the same SOFTWARE ID at 1GiB and 2GiB for the same `serial=`/`product=` (both force `sector_val=0` regardless of the actual disk size passed to `mtsc search --size`), and both independently activate against the same signature, this confirms `sector_val=0` is **not** a 1GiB-specific coincidence -- it holds across at least two different disk sizes on `scsi0`. The size caveat in 8.11-8.13's wording can be considered resolved for x86_64/`virtio-scsi-pci`.

**Practical implication: on `scsi0`, the actual disk size is irrelevant to which `serial=`/`product=` combo you need.** This is a real, useful difference from `ide0`: `ide0`'s SOFTWARE ID depends on `sector_val`, which is derived from the disk's exact byte count, so an `ide0` collision result is only valid for a disk of that *exact* size (§6, §3.4). On `scsi0`, since `sector_val` is always `0` regardless of the disk's real size, **a single `serial=`/`product=` combo found via `mtsc search --bus scsi --size <any size>` will activate on a `scsi0` disk of *any* size** -- there is no need to match the search size to the deployed disk size, and no need to maintain size-specific tables the way `docs/database/collision-database.md` §2 does for `ide0`. The `--size`/`--unit` flags still need *some* value when running `search --bus scsi` (they're required CLI arguments), but the resulting `serial=`/`product=` pair is size-agnostic in practice for `scsi0` deployments.

### 8.20 `sata0` is NOT like `scsi0` -- it uses the exact same encoding as `ide0`

Every prior section in §8 treats `scsi0` and `sata0` as a pair (both non-`ide0`, both assumed to share the SCSI-generic code path from §8.9/8.12). This assumption was never actually tested for `sata0` specifically -- it turns out to be wrong.

QEMU's `sata0` (AHCI) disks are backed by the **same `ide-hd` qdev device model as `ide0`**, just attached to an AHCI controller instead of a legacy PIIX/ISA IDE controller -- confirmed directly: attempting `-set device.sata0.product=<x>` (the SCSI-specific property used throughout §8.11-8.19) fails at QEMU startup with `Property 'ide-hd.product' not found`. `ide-hd` only exposes a `model=` property (the same one `ide0` uses), not `vendor=`/`product=` (which are `scsi-hd`-only). This alone strongly suggests `sata0` disks respond to ATA IDENTIFY like real IDE drives, taking `readMBR`'s `HDIO_DRIVE_CMD` success path (§8.9) rather than the `SG_IO` path.

Confirmed both algorithmically and empirically:

- **Algorithmic**: booting a `sata0` disk with `serial=00000000430480281048`/`model=SSD1G` (the SCSI-verified `C7CU-PGT9` combo from §8.14) at 2GiB showed `Current installation "software ID": EJSX-HUUP` -- a **different** ID than the `scsi0` result for the identical `serial=`/`model=` pair. Running `mtsc check --serial 00000000430480281048 --size 2 --unit g --model SSD1G --bus ide` (note: `--bus ide`, not `scsi`) computes the **exact same** `EJSX-HUUP` -- confirming `sata0` uses `ide0`'s real-sector_val encoding, not `scsi0`'s `sector_val=0` encoding.
- **Empirical, with an existing `ide0` collision-database entry**: a fresh 1GiB `sata0` install using the *unmodified* `ide0` table entry (`serial=00000000251582663387`, `model=SSD1G`, `1,073,741,824` bytes -> `TI09-7WK3`, no new search needed) with the standard MBR write (`00...BDE800000000` + `TI09-7WK3`'s signature) **fully activated** on first boot -- confirming this isn't just a matching-SOFTWARE-ID coincidence, the *existing* `ide0` collision database works directly on `sata0`.

**Practical implication:** `docs/collision-database.md`'s `ide0` table (§1-2) applies directly to `sata0` disks of the same size, with no `--bus scsi`/`--bus ide` distinction needed and no new search required -- treat `sata0` as an alias for `ide0` for collision-search purposes, not as part of the `scsi0` SCSI-generic family. This also means `--bus ide`'s existing wording ("verified against real hardware") extends to `sata0` without qualification, while `--bus scsi` remains specific to `scsi0`/`virtio-scsi-pci` only. `docs/deployment-guide.md` and `docs/command-reference.md`'s bus-type framing (currently grouping `scsi0`+`sata0` together against `ide0`) should be corrected to reflect this.

### 8.21 Signature metadata decryption (`MT_Transform`)

Separately from the bus-type investigation above, the [MTLic project](https://github.com/Ygnecz/MTLic) (`MTTools.py`, `ParseLic.py` -- already listed in `docs/toolchain.md`) documents the internal structure of the 64-byte signature stored in `.key` files and at MBR `0x110-0x14F`:

```
signature[0:16]  -- MT_Transform-encrypted: SOFTWARE_ID(6B LE) || reserved(1B) || level(1B) || zero-padding(8B)
signature[16:32] -- XORed into a hash of the decrypted [0:16] block, used for EC-KCDSA-style verification
signature[32:64] -- the actual Curve25519 signature integer
```

`MT_Transform` is a 16-round ARX block cipher operating on the 16-byte block as four 32-bit words, using round constants -- **which turn out to be exactly this project's existing `ROUND_CONSTANTS`** (`src/sha256_constants.rs`, the MikroTik custom SHA-256 K-table): confirmed byte-for-byte identical against `MTTools.py`'s `SHA256_K`. The decrypted SOFTWARE ID's Base-35 encoding table (`MT_SWSNToSWID`'s `SWIDTab`) is likewise identical to this project's existing `software_id::encode` alphabet. No new reverse-engineered constants were needed -- both pieces were already in this codebase, just not previously connected to this use.

**What this enables:** given any known-valid signature (from `docs/collision-database.md`'s Signature Table, or extracted from a `.key` file via `key2sig`), decrypting `signature[0:16]` reveals which SOFTWARE ID and license level that signature was actually issued for -- useful for auditing/labeling signatures, independent of booting a VM. `mtsc sig2key`/`key2sig` now print this (`SOFTWARE-ID`/`VERSION`/`LEVEL`) to stderr alongside their normal output (`src/convert.rs`'s `decode_metadata`). Verified against `VI8Q-E90F`'s known signature hex (`docs/collision-database.md`): decrypts to SOFTWARE ID `VI8Q-E90F`, level `1` -- matching the real-hardware-confirmed `nlevel: 1` from §1.

**What this does NOT enable:** signing a *new* license for an arbitrary SOFTWARE ID/level still requires the Curve25519 private key corresponding to the public key used in `ParseLic.py`'s verification (`Y = signature*PubKey + hash*G`, checked via `MT_Hash(Y) == signature[16:32]`) -- an ECDLP problem, same ~252-bit hardness already established in `architecture.md` §5. This finding only explains the *structure* of an existing signature; it does not provide a way to forge one for parameters not already covered by a known-valid signature. The project's approach remains unchanged: reuse existing valid signatures via SOFTWARE ID collision search (§1-7), not signature forgery.

The `version_byte` field (byte 6 of the decrypted block) is printed as-is but its meaning is **unconfirmed** -- `ParseLic.py` doesn't label or use it, so treat it as informational only until independently verified (e.g. against RouterOS version numbers across several known signatures).

### 8.22 `writeMBR` found and disassembled -- a new function, distinct from `readMBR`

All of §8.9-8.20 traced `keyman_arm32`'s **read**/verify path. Continuing disassembly of `keyman_arm32` (confirmed directly in the binary itself, not inferred from `loader` or the x86 build) turned up a second, previously undocumented function: `writeMBR`, at `0x19758`. Identified unambiguously via its own error-format string sitting in `.rodata` right next to the `/dev/flash` path literal: `"writeMBR: could not open %s: %d\n"`.

**The `board`-contains-`"qemu"` predicate (`0x17574`, §8.9/8.15's cached `getenv`+`strstr` check) is called from `writeMBR` too**, not just `readMBR` -- confirmed at `writeMBR+0x14` (`0x1976c`). When it returns true, `writeMBR` tail-calls into a small helper (`0x18ba4`) that hands the write off through the `nv` message/IPC layer rather than touching any device directly -- structurally the same pattern as `readMBR`'s `/dev/hvckvm0` (hvc0) IPC path from §8.15-8.16, just on the write side. This confirms the virtualization-detection branching isn't read-only special-casing -- both directions of MBR I/O go through the same `board=qemu` gate and the same IPC-based fallback when it's true.

**A second, previously undocumented predicate exists specifically on `writeMBR`'s false-branch (`board` does *not* contain `"qemu"`):** it calls `getenv("board")` a second time and checks only whether the **first character of the returned string equals ASCII `'7'`** (`0x37`) -- not a substring search this time, a single-byte compare. If true, `writeMBR` skips straight to opening the caller-supplied device path directly; if false (or `board` is unset), it first tries `open("/dev/flash", O_RDWR)` and issues `ioctl(fd, 0x80044604, &buf)` (decodes as `_IOR('F', 4, <4-byte arg>)` in Linux ioctl-number encoding -- meaning/purpose of this specific ioctl not yet identified) before falling through to the same generic-path write either way. The significance of `board` starting with `'7'` is **not yet understood** -- plausibly a RouterBOARD hardware-generation/family prefix convention, but unconfirmed; worth checking against a real (non-virtualized) ARM64 RouterBOARD's `board` value if one is ever available.

**A third call site for the same `board=qemu` predicate exists at `0x18c28`**, a distinct function (not `readMBR`, not `writeMBR` itself) that also opens `/dev/flash`, issues two more ioctls (`0x462b` and one more not yet decoded), and -- most interestingly -- contains a bit-manipulation sequence at `0x18d20-0x18d48` (`ubfx` extracting a 21-bit and a 9-bit field, a 64-bit `umull` multiply, XOR, `orr r3, r3, #0x200`) that structurally resembles `architecture.md` §2's already-documented `mbr_val * 0x3FF800F` mix step, but with different field widths (21+9 bits here vs. the documented `& 0x7FF` 11-bit `mbr_val`) -- **not yet reconciled with the known algorithm**. This is plausibly where `keyman` recomputes a checksum/marker field when constructing a *new* MBR (as opposed to verifying an existing one), which would make `0x18c28` the missing piece explaining how `0x10A-0x10B`'s marker or `mbr_val` inputs are actually derived at write-time rather than assumed fixed -- worth a dedicated follow-up pass rather than a quick read, since the field-width mismatch means it's not a simple 1:1 match to the documented formula.

**Practical implication:** none of this changes any currently-documented behavior or collision-search output -- it's new evidence about *how* `keyman` writes license data internally, not a new bug or opportunity yet. The most promising thread for a follow-up session is `0x18c28`'s checksum-like computation, since reconciling it with `architecture.md`'s `mbr_val` formula could reveal whether the 21-bit/9-bit fields are a superset (e.g. covering more of the MBR identity region than currently assumed) or an unrelated, separate checksum used only for a different purpose (e.g. the boot counter at `0x10C-0x10F`, which §3's table already flags as "no impact" on the SOFTWARE ID but has never been explained *how* it's maintained).

### 8.23 Independent adversarial verification of §8.22 -- confirmed, with two corrections

§8.22's claims were re-derived independently (fresh `grep`/`objdump` navigation against the same disassembly, not just re-reading the prior notes) specifically to catch overclaiming before it hardened into permanent documentation. Result: mostly confirmed, two corrections below.

**Confirmed exactly as written:** the `board=qemu` predicate (`0x17574`) has **exactly 4** call sites, verified via `grep -n 'bl.*17574'` against the full disassembly with no `blx`/indirect calls reaching it by another path: `0x178ec` (`readMBR` itself), `0x18c3c` (`getHardwareID`, §8.9-8.13's already-known serial/model function), `0x1976c` (`writeMBR`), and `0x19b84` (a fourth site, see correction below). `readMBR`'s body (`0x178dc-0x179e0`) was checked instruction-by-instruction for `mul`/`mla`/`umull`/`umlal`/`smull` (the ARM mnemonics any Curve25519/bignum crypto would necessarily use) -- **zero matches**, confirming no signature-verification arithmetic happens inside `readMBR`, and confirming it has no `board[0]=='7'` secondary check (that check is `writeMBR`-only, as §8.22 states). `writeMBR`'s tail-call to `0x18ba4` on the qemu-true branch, and that function's own `bl 18b08` -> `bl 1762c` IPC dispatch, were both confirmed to exist exactly as described.

**Correction 1 -- `0x19b84`'s function is not a "near-duplicate via reuse," it's an independent re-implementation.** The function at `0x19b64` (called from `0x19b84`) does **not** call `0x178dc` (`readMBR`) internally -- it has its own separate `open`/`ioctl(0x4601)`/`fopen`-fallback sequence that happens to be structurally identical to `readMBR`'s, and its own separate `bl 18b08` -> `bl 1762c` (message type 6, 520-byte buffer) call on the qemu-true branch. Two independently-compiled copies of the same logic, not one calling the other -- worth keeping precise since a reader could otherwise assume `0x19b64` is just a thin wrapper.

**Correction 2 -- the `libucrypto.so` hypothesis from earlier discussion is unsupported speculation, not evidence-based.** `readelf -d keyman_arm32`'s `NEEDED` entries are `libumsg.so`, `libuc++.so`, and `libc.so` only -- **no link to `libucrypto.so`, direct or transitive** (checked `libumsg.so`'s and `libuc++.so`'s own `NEEDED` entries too, neither pulls in `libucrypto.so` either). The "no crypto arithmetic in these 4 functions" part is solid (confirmed above), but "therefore it's probably `libucrypto.so`" was a guess based on that library merely existing in `/root/ros-work/lib/`, not on any actual trace of where the IPC call in §8.22/8.23 (`nv::Handler`, message type 6) actually terminates. Treat "where does signature verification actually happen" as fully open, not narrowed to a specific library.

**Where this leaves the investigation:** `keyman_arm32` alone has not hit a genuine dead end -- there is one concrete, cheap thread left before reaching for a new binary: trace the `bl 1762c` (`nv::Handler`-adjacent) message-type-6 dispatch itself, and cross-reference it against `/root/ros-work/hvc0_responder.py`/`hvc0_responder.log` (already on disk from earlier session work, never yet correlated against these specific IPC call sites). Only after that thread is exhausted does disassembling a new binary (`libucrypto.so` or whatever process actually answers type-6 messages) become the necessary next step.

### 8.24 `0x1762c` decoded, and Curve25519 field arithmetic found -- statically compiled into `keyman_arm32` itself

Two follow-ups on §8.23, both from direct disassembly (not inference).

**`0x1762c` (the "IPC dispatch" `writeMBR`/`readMBR` fall into on the `board=qemu`-true branch) is a plain length-prefixed request/response helper, not a complex `nv::message`-serialized call as earlier sections assumed.** Disassembled in full: it `write()`s an 8-byte header (`{constant 8, type}`, e.g. `type=6` for `writeMBR`'s call) to the file descriptor passed in, then `malloc()`s a buffer of the caller-specified reply size (e.g. 520 bytes) and loops on `read()` until that many bytes arrive (retrying on partial/interrupted reads, freeing and returning `NULL` on hard failure). No field-ID-based serialization, no `nv::message::insert<>`/`extract<>` template machinery visible at this call site -- just a raw fixed-size framed exchange over whatever fd was connected earlier (presumably to `loader` via `/ram/novasock`, consistent with the `connect(AF_UNIX, "/ram/novasock")` seen in this project's earlier `strace` capture of `keyman_arm32` under `qemu-arm`).

Cross-checking this against `/root/ros-work/hvc0_responder.py`/`.log` (a stub UNIX-socket script from earlier session work meant to simulate `/dev/hvckvm0`): the log shows the stub only ever got as far as `"client connected"` -- **no request was ever actually received**, so it never captured a real `type=6` exchange. That thread is a dead end as-is; the earlier §8.23 suggestion to "cross-reference against `hvc0_responder.log`" doesn't hold up because the log contains no useful data, not because the correlation wasn't attempted.

**More significantly: `keyman_arm32` contains an actual Curve25519 field-multiplication routine, statically compiled in.** Found by grepping the whole binary for ARM multiply mnemonics (`mul`/`mla`/`umull`/`umlal`/`smull`/`smlal` -- 260 total hits across the binary, confirming the grep pattern itself works; zero hits specifically inside `readMBR`'s body, confirming §8.23's claim there). The function at `0x145bc` reads a 10-word (40-byte) input array at 4-byte-stride offsets `0, 4, 8, ..., 36`, multiplies using `mov r5, #38` (**38 = 2*19**, the standard doubled reduction constant for the Curve25519 prime `2^255-19`), and masks outputs with `bic r6, r2, #0xfc000000` (26-bit limb) / `bic ip, r3, #0xfe000000` (25-bit limb) -- an unambiguous match for the classic **10x25.5-bit-limb `fe_mul`** field-multiplication implementation used in reference Curve25519 code (djb/donna-style `ref10`/`donna` field element representation). This directly contradicts §8.23's "no crypto found, `libucrypto.so` is speculative" framing: the crypto isn't missing or delegated elsewhere, it's compiled directly into `keyman_arm32`'s own `.text`, which is exactly why `readelf -d` shows no `libucrypto.so` dependency (there's nothing external to depend on for this).

`0x145bc` (`fe_mul`) has **41 call sites**, clustered densely in the address range `0x151c8-0x1535c` -- far more than a single point-verification would need for one multiplication, and structurally consistent with either a Curve25519 **field inversion** (`fe_invert`, which reference implementations compute as a fixed, unrolled sequence of ~11 multiplications and ~254 squarings via Fermat's little theorem -- squarings often reuse the same `fe_mul`-shaped code or a dedicated `fe_sq`) or a **scalar multiplication ladder step** sequence. Not yet determined which, nor whether this specific function is reachable from the `readMBR`/signature-check flow traced in §8.9-8.23 (the 41 call sites have not yet been traced to their own caller(s), and no direct call from any of the four `board=qemu`-adjacent functions to this address range has been found yet -- it may be invoked from a completely different part of `keyman` not yet mapped, e.g. package/firmware signature verification unrelated to the license MBR).

**Practical implication:** the "where does signature verification happen" question from §8.23 is **narrower than before but not yet closed**: it happens somewhere inside `keyman_arm32` itself (confirmed, not speculated), via a statically-linked Curve25519 implementation -- but the call path connecting this crypto code to the license-MBR-read flow (§8.9-8.20) has not yet been traced. The concrete next step is to find `0x145bc`'s callers-of-callers (walk up from `0x151c8` to find what function contains it, then find that function's own callers) to determine whether this is the license-signature-verification code path or an unrelated use of the same crypto primitive (e.g. RouterOS package/firmware signing, which also plausibly uses Curve25519 and would live in the same binary for unrelated reasons).

### 8.25 Confirmed: `keyman_arm32` is genuinely 32-bit ARM (not misidentified), and the crypto call chain traced further up

Two more directly-verified points, continuing from §8.24.

**Sanity check on the binary's own architecture, since this was reasonably questioned:** `readelf -h keyman_arm32` reports `Class: ELF32`, `Machine: ARM` (not AArch64); `file` independently confirms `ELF 32-bit LSB executable, ARM, EABI5, dynamically linked, interpreter /lib/libc.so`. This is not a misidentified file -- `keyman_arm32` really is a 32-bit ARM (AArch32) binary, extracted from `/nova/bin/keyman` inside the mounted `system.squashfs` of a genuine RouterOS **ARM64** install image. The most plausible explanation (not independently verified against the actual kernel, which lives outside `system.squashfs` and hasn't been extracted): MikroTik's ARM64 product line likely ships a 64-bit kernel alongside the *same* 32-bit `nova` userspace binaries used on their ARMv7 RouterBOARD line, relying on ARM64 CPUs' native AArch32 EL0 execution support rather than recompiling `nova` for AArch64. This is consistent with everything else found in this investigation (§8.9's byte-identical shared functions between ARM32 and the x86 build already established this codebase is compiled once and reused broadly).

**Traced `0x145bc` (`fe_mul`)'s call chain two levels further up, following real cross-references (not inference):**

1. `0x145bc` (`fe_mul`) has 41 callers clustered in `0x151c8-0x1535c`, all inside a single function starting at `0x151c8` (`sub sp, sp, #204` -- a large local frame consistent with either `fe_invert`'s unrolled ~254-squaring/~11-multiplication sequence or a full scalarmult ladder).
2. `0x151c8` has exactly 3 callers (`0x15864`, `0x15944`, `0x15cf4`), all inside one enclosing function starting at `0x15654`. That function's own body opens with `mov r1, #9` immediately before a call to `0x13694` -- **`9` is the standard Curve25519/X25519 base point** (`crypto_scalarmult_base`'s fixed `u`-coordinate) -- alongside byte-unpacking code that deserializes a 32-byte value into the field-element limb layout. This is an unambiguous `crypto_scalarmult`/`crypto_scalarmult_base`-shaped function.
3. `0x15654` has exactly 1 caller: `0x17318`. The code immediately preceding that call (`0x172f0-0x17314`) performs `byte[31] &= 0x7f; byte[31] |= 0x40; byte[0] &= 0xf8` -- the **standard X25519 scalar "clamping"** sequence (`s[0] &= 248; s[31] &= 127; s[31] |= 64`), confirming `0x17318`'s enclosing function (starting `0x170d4`) is a full clamp-then-scalarmult wrapper. Notably, **this exact clamping byte sequence was already seen once before in this investigation**, in `loader` at `0x1ac1c-0x1ac38` (originally read while tracing the `board=qemu` predicate's caching wrapper in §8.9) -- meaning `loader` independently contains the same clamp-and-scalarmult logic, not just `keyman`.
4. `0x170d4` (the clamp+scalarmult wrapper) has **4 callers**: `0x17388`, `0x18ab8`, `0x195c4`, `0x1a0c8`. Inspected `0x18ab8`'s context directly: it sits inside a function that also calls `_Z14hasUefiSupportv` (a demangled, human-readable C++ symbol -- `bool hasUefiSupport()`) a few instructions earlier, and stores small integer status codes (`0`, `2`, `5`, `255`) into several output pointer arguments before reaching the scalarmult call. The scalarmult's result (`r0`) is then compared and branched on to decide a final boolean written back through another output pointer. This has the shape of a **multi-field system-capability/status query function** (of which `hasUefiSupport` is one field and something crypto-gated is another), not a narrowly-scoped "verify this one license signature" function -- consistent with, but not proof of, license validity being one bit among several status flags gathered together (e.g. for a `/system resource`-style report).

**Honest assessment of what remains open:** the crypto chain (`fe_mul` -> `fe_invert`/ladder step -> `crypto_scalarmult`/`_base` -> clamp-and-scalarmult wrapper -> a status-gathering function with 4 call sites) is now traced end-to-end with real cross-references at every hop -- this is solid. What is **not yet confirmed** is that this particular call chain is the one invoked from the license-MBR read flow (§8.9-8.20) specifically, as opposed to a different, unrelated use of the same crypto primitives (package signing, secure firmware update, or some other RouterOS feature that also needs Curve25519). None of `0x170d4`'s 4 callers have yet been checked for a direct connection back to `readMBR`/`writeMBR`/`getHardwareID` (the three functions already mapped in §8.9-8.24) -- that cross-check is the next concrete step, not yet done. Do not treat "license signature verification confirmed located" as settled until that link is checked.

### 8.26 The crypto chain traced in §8.25 is confirmed NOT connected to `readMBR`/`writeMBR`/`getHardwareID` -- a negative result, not a dead end

Following up on §8.25's open item directly: checked whether any of `0x170d4`'s 4 callers (`0x17388`, `0x18ab8`, `0x195c4`, `0x1a0c8`), or the next function up from `0x17388` (`0x1736c`, itself called from 4 further sites: `0x1a484`, `0x1aa84`, `0x1af08`, `0x1b94c`), fall inside the already-mapped `readMBR` (`0x178dc-0x179e0`), `writeMBR` (`0x19758`-ish), `getHardwareID` (`0x18c28`-ish), or the duplicate `readMBR` (`0x19b64`-ish) address ranges from §8.9-8.24.

**None of them do.** Every one of these 8 call sites (4 + 4, across two hops) falls outside all four mapped license-I/O functions' address ranges. This is a clean, checked negative result: **the Curve25519 chain traced in §8.25 is not called from the local MBR read/write/hardware-ID functions.**

This is confirmed, not just suggested, by what's at that call site: `0x1a0c8`'s enclosing function builds an `nv::HTTPFetch` request via repeated `appendVar(string&, char const*, string const&)` calls (unambiguous demangled symbol) with parameter-name string literals **`"systemid"`, `"account"`, `"password"`, `"licence"`** (read directly from `.rodata`, byte-for-byte), and a literal pool entry a few instructions later (`0x1a3a4`) references the string **`"licence.mikrotik.com"`** (also confirmed present in `.rodata` alongside `"permanent licence can not be renewed"` and `"renewing"`). This is unambiguously the **online license activation/renewal HTTP request** -- POSTing account credentials and a license identifier to MikroTik's own license server -- not local signature verification. The crypto chain traced in §8.24-8.25 serves this **online** flow, not the **offline**, boot-time MBR read this project's collision-search method actually depends on.

**Practical implication:** this project's entire approach (§1-7's collision search, reusing existing valid signatures rather than forging new ones) was never dependent on finding where local EC-KCDSA verification happens -- that was always out of scope, since the method works by matching a *known-valid* signature's SOFTWARE ID, not by computing new signatures. This deep dive (§8.24-8.26) was pursued to satisfy a specific question raised mid-session (does `keyman` verify signatures locally, and if so where), not because the answer changes anything actionable for collision search. With this negative result in hand, the honest state of that specific question is: **`keyman_arm32` contains at least one complete Curve25519 implementation, used for something networked/online, not (as far as traced) for local MBR signature verification.** Whether local MBR signature verification happens at all (as opposed to RouterOS simply trusting a well-formed MBR signature region without cryptographic verification at boot, deferring any real check to network-based license validation) is now an open question in its own right -- not answered by this investigation, and not necessary to answer for this project's practical goals. Further pursuit of this specific thread should be considered optional/curiosity-driven rather than blocking.

### 8.27 The networked flow identified in §8.26 confirmed to be online license renewal, and confirmed to call `readMBR` internally

Two more confirmations, both from direct string/cross-reference evidence, closing out this sub-thread.

**Confirmed the HTTP request's actual target and purpose (not just "networked" -- specifically license renewal against MikroTik's own server):** the function starting at `0x19f78` (called from two sites, `0x1aa34`'s function and one other) builds its `nv::HTTPFetch` request with `appendVar` parameter-name literals `"systemid"`, `"account"`, `"password"`, `"licence"`, and a literal-pool reference a few instructions later to the string `"licence.mikrotik.com"` immediately followed in `.rodata` by `"/licence/"` (i.e. the request targets `licence.mikrotik.com/licence/`). This is MikroTik's own account-based license server -- the request POSTs (or GETs with these query vars) a system ID plus MikroTik account credentials, exactly the shape of an **online license activation/renewal** call, not a generic unrelated HTTP feature.

**Confirmed this flow calls `readMBR` (the `0x19b64` duplicate from §8.22-8.23) as part of the same operation.** Tracing one level up from both `0x1aa34` (the function wrapping the `licence.mikrotik.com` HTTP call) and `0x1ab80` (a separate function that calls `readMBR`'s `0x19b64` duplicate directly) found that **both are called from the same parent function**, at call sites only 28 bytes apart (`0x1b4d8` calls `0x1ab80`/`readMBR`, `0x1b4f4` calls `0x1aa34`/HTTP-post). This parent function's broader vicinity also contains the `"renewing"` and `"permanent licence can not be renewed"` string literals found in §8.26. Putting this together: there is a single **license renewal command handler** that (1) calls `readMBR` to read the currently-installed SOFTWARE ID/signature off disk, then (2) POSTs that ID plus account credentials to `licence.mikrotik.com/licence/` to request a renewed/new signature from MikroTik's server, with the Curve25519 code from §8.24-8.25 used somewhere in that HTTP exchange (most plausibly for authenticating the request or processing the server's cryptographic response, not for verifying the locally-read MBR signature).

**This refines, but does not overturn, §8.26's core negative result.** `readMBR` is called by this flow, but only to *read and report* the current on-disk SOFTWARE ID to the server as an input -- there is still no evidence the Curve25519 code itself is used to *verify* that on-disk signature locally. The crypto's role in this flow is on the network side (talking to `licence.mikrotik.com`), consistent with §8.26. Whether local, offline signature verification happens anywhere in `keyman_arm32` remains genuinely open -- but the earlier framing "the crypto chain has nothing to do with readMBR" was too strong; they're both steps in the same renewal operation, just with the crypto doing the online part and `readMBR` doing the local read.

### 8.28 Root cause of ARM64/`board=qemu` activation failure, confirmed empirically: the `/dev/hvckvm0` transport device genuinely does not exist under plain QEMU/KVM

This closes the open question from §8.15-8.20 with direct evidence from a running VM's own QEMU command line, not further disassembly.

**Test setup**: `VM301` (a disposable full clone of the ARM64 test VM, created specifically so testing no longer touches the original `VM100`), `scsi0` disk with the SOFTWARE ID `C7CU-PGT9` combo from §8.14, custom `smbios1` override removed (reverting to PVE's default). Result: booting with default SMBIOS avoided the `MetaROUTER` trap from §8.17 (console prompt is `[admin@arm64]`, not `[admin@MetaROUTER]`) -- confirming §8.17's hypothesis that the *custom* SMBIOS override, not `board=qemu` itself, was what triggered `MetaROUTER`. But `/system resource print` shows `board-name: arm64 QEMU KVM Virtual Machine` (still contains `"QEMU"`, PVE's own default), and the boot banner still shows `ROUTER HAS NO SOFTWARE KEY` with a normal ~24h-scale countdown (`17h35m` observed) -- i.e. the ordinary `board=qemu` failure mode from §8.15, not `MetaROUTER`.

**Root cause, found by inspecting the actual running `qemu-system-aarch64` process's command line** (`/proc/<pid>/cmdline` for VM301's PID, read via its PVE-managed `.pid` file) rather than guessing: the only virtio-serial-family device attached to this VM is

```
-chardev virtserialport,chardev=vdagent,name=com.redhat.spice.0
```

-- a SPICE guest-agent channel, unrelated to console/tty access. `serial0` (RouterOS's actual boot console, which this whole session's `socat` interaction has been using) is a plain legacy UART (`-chardev socket,...` + `-serial chardev:serial0`), not a virtio-console. **There is no device on this VM that would ever cause a `/dev/hvc0` tty to appear inside the guest.** Since `/dev/hvckvm0`'s self-provisioning (§8.16: `stat("/dev/hvckvm0")` -> fall back to `/sys/class/tty/hvc0/dev` -> `mknod`) has no `hvc0` sysfs entry to find in the first place, it necessarily fails -- and `readMBR`'s `board=qemu` branch has no further fallback (§8.15), so it can never successfully read the MBR on any plain QEMU/KVM setup where `board` contains `"qemu"` **and** `MetaROUTER` isn't independently triggered, regardless of which specific SMBIOS strings are used.

**This settles §8.18's open question definitively for the `board=qemu`-true, non-`MetaROUTER` case.** It is not that ARM64 and x86_64 differ in *what string* `board` contains, or in case-sensitivity, or in some other software nuance -- ARM64/`virt` hits this branch (because `board` genuinely contains `"qemu"` by default under QEMU, on both architectures) while x86_64/CHR does not need to, because **x86_64's `readMBR` code path apparently never depends on a virtio-console device at all** (§8.9's `HDIO_DRIVE_CMD`/`ide0` path and the generic `/dev/flash`-or-`fopen()` fallback both work with ordinary block/char devices that PVE does provision by default). The ARM64 image's `board=qemu` branch assumes a specific piece of host-provided infrastructure (a real MetaROUTER-capable RouterBOARD host wiring up `/dev/hvckvm0` for a nested guest) that simply does not exist when the "host" is generic QEMU/KVM rather than real MikroTik hardware.

**Practical implication, updated by §8.17's correction above:** since `MetaROUTER` mode is now understood to function as activated in practice despite its cosmetic "no software key" banner, this specific `board=qemu`-true/non-`MetaROUTER` dead end is **not actually the blocking case** -- the SMBIOS-override path into `MetaROUTER` (§8.17) is the one that matters for practical ARM64/`scsi0` deployment, and it works. This `/dev/hvckvm0`-missing-device root cause remains useful background (it explains precisely why the *unmodified*-SMBIOS default fails, and confirms that path specifically cannot be fixed by SMBIOS tricks alone, only by either avoiding it entirely via `MetaROUTER` or by actually providing a working `virtio-console` backend), but is no longer the critical path now that §8.17's `MetaROUTER` route is confirmed usable.

### 8.29 `libumsg.so`'s `/dev/rb` check identified as `getBoardType()`, disassembled -- and a reusable methodology note for resolving PIC literal addresses

Following up on §8.17's remaining open item ("continuing requires disassembling `libumsg.so`'s `MetaROUTER`-detection function").

**Methodology note (recorded because it was non-obvious and is reusable for future `.so` disassembly in this project):** `libumsg.so` is `Type: DYN` (a PIC shared object), so naively `grep`-ing the disassembly for a string's raw `.rodata` file offset (the way this worked for `keyman_arm32`/`loader`, both non-PIE `EXEC` binaries) finds nothing -- PIC code doesn't embed absolute addresses as plain literal-pool words. Instead it uses a two-instruction idiom: `ldr rX, [pc, #N]` loads a **signed delta** from a literal pool slot, then `add rX, pc, rX` (or the immediate form `add rX, pc, #N`) computes `final_address = add_instruction_address + 8 + delta`. Resolving "what address does this PIC code reference" therefore requires two hops: (1) compute the literal pool slot address from the `ldr`'s own address and immediate, (2) read the delta word stored there, (3) add it to the *following* `add` instruction's `PC+8`. A short Python script parsing the `objdump -d -r` text output for this pattern (matching `ldr rX,[pc,#N]` then a following `add rX,pc,rY`, resolving the delta from a raw-hex-word address map built from every line in the dump) found both target strings' materialization sites directly: `"/dev/rb"` at `0x4e25c`, `"open /dev/rb failed, probably metarouter"` at `0x4e278` -- both inside the same function.

**The function is `_Z12getBoardTypev` = `getBoardType()`** (an exported, C++-mangled symbol -- not exported from `keyman_arm32`/`loader`, `readelf --dyn-syms` gives the demangled name directly, no guessing needed). Full logic:

```
int getBoardType() {
    static bool cached; static int cached_result;      // process-lifetime cache, same pattern as §8.9's board=qemu predicate
    if (cached) return cached_result;

    int fd = open("/dev/rb", O_RDWR);                    // unconditional -- no getenv("board") check anywhere in this function
    if (fd != -1) {
        ioctl(fd, 0x520f, ...);                           // real hardware: read board-type info
        close(fd);
        cached_result = <ioctl's result>;
    } else {
        ostream << "open /dev/rb failed, probably metarouter";   // logged unconditionally on open() failure
        cached_result = fd;                               // i.e. -1
    }
    return cached_result;
}
```

**This directly disproves the specific mechanism §8.17 speculated for why unmodified (`board=qemu`) VMs never showed `MetaROUTER`.** §8.17 guessed "`board=qemu` intercepts before `/dev/rb` is tried" -- but `getBoardType()` itself contains **no `board` check at all**; `open("/dev/rb")` runs unconditionally regardless of `board`'s value. This means `/dev/rb` fails identically on *every* plain-QEMU VM (§8.28 already established there's no real RouterBOARD device to back it), whether or not `board` contains `"qemu"` -- the differentiation between "normal `board=qemu` trial" and "`MetaROUTER` prompt" must happen somewhere else, in whatever code *decides how to react* to `getBoardType()`'s `-1` result (or to the `"probably metarouter"` log line), not inside `getBoardType()` itself.

**That caller-side decision point was not found.** `getBoardType()` has zero callers within `libumsg.so` itself, is not imported by `keyman_arm32` or `loader` (checked both directly), and its only confirmed caller across the binaries checked is **`sys2`** (10+ call sites) -- a different `nova` binary, plausibly the general system-resource/status daemon behind `/system resource print`-style queries, with no established connection to the license/MBR flow at all. This leaves a real, unresolved gap: **it's not yet confirmed that `getBoardType()`'s `/dev/rb` failure is actually what produces the visible `[admin@MetaROUTER]` prompt and boot banner** -- the debug string's presence and content is a strong coincidental match, but the causal wiring from "this specific function returns -1" to "boot shows `ROUTER HAS NO SOFTWARE KEY` with `[admin@MetaROUTER]`" has not been traced. Treat this as the concrete next step if this thread is picked up again, rather than assuming the connection is already proven.

### 8.30 A third, independent vendor-detection mechanism found (`isMikrotikVendor`/`isMikrotikAmpere`) -- investigated as a candidate for the `platform:` field, ruled out

Prompted by `/system resource print`'s `platform: MikroTik` field (observed in §8.28's VM301 test) -- checked whether this is yet another signal feeding into the `board=qemu`/`MetaROUTER` decision maze, or into how `platform` gets its value.

**Found, via the same PIC literal-resolution method as §8.29, two related functions exported from `libumsg.so`:**

```cpp
bool isMikrotikVendor() {
    string content = nv::readFile("/sys/class/dmi/id/sys_vendor", ...);  // real Linux sysfs DMI file
    return <content contains "MikroTik\n">;                              // exact substring match
}

bool isMikrotikAmpere() {
    if (!isMikrotikVendor()) return false;
    return getenv("uefi") != NULL;   // second, independent env-var check (nonzero-check idiom: clz+lsr#5)
}
```

This is a **third, independent detection mechanism**, distinct from both `getenv("board")`+`strstr(..., "qemu")` (§8.9/8.15, used by `readMBR`/`writeMBR`/`getHardwareID`) and `getBoardType()`'s `open("/dev/rb")` (§8.29): it reads the DMI `sys_vendor` sysfs value directly (settable via `qm set --smbios1 manufacturer=<base64>`) and checks for an exact `"MikroTik"` match, then separately checks a `getenv("uefi")` environment variable. The naming (`isMikrotikAmpere`) suggests this gates behavior specific to MikroTik's real Ampere-based ARM64 server hardware (a legitimate non-embedded ARM64 product line), not virtualization detection.

**Ruled out as the source of the `platform:` field.** If `isMikrotikVendor()` fed `platform:`, deleting VM301's custom `smbios1` override (§8.28, which removes the `manufacturer=MikroTik` base64 value, reverting to PVE's default `QEMU`) should have changed `platform:` away from `MikroTik` -- it did not; `platform: MikroTik` was observed both with and without the custom SMBIOS override. This is inconsistent with `platform:` being derived from a live DMI-vendor check. The more likely explanation is that `platform: MikroTik` is a **static build-time label** (RouterOS always reports itself as "MikroTik" branding regardless of underlying hardware, the same way x86 CHR does on any hypervisor) -- not a live hardware-detection result, and not connected to the license/`MetaROUTER` flow.

**Net effect of this sub-thread:** confirmed a real, previously-undocumented function pair (`isMikrotikVendor`/`isMikrotikAmpere`) exists and is genuinely DMI-vendor-based, but it does not explain the `platform:` field and has no established connection to license/`MetaROUTER` behavior -- this was a plausible lead that didn't pan out. §8.29's gap (what code actually decides to show the `MetaROUTER` prompt based on `getBoardType()`'s result) remains open and is a separate, still-untraced code path, most likely in a CLI-prompt/console-related binary not yet examined (candidate: `/nova/lib/console`).

### 8.31 The missing layer found: `flash.ko` (kernel module) checks the device-tree `compatible` string, and `"MetaROUTER"` is one of the recognized values -- plus a full map of all hardware-detection signals found so far

Followed up on §8.29's dead end (no userspace caller of `getBoardType()` decides the `MetaROUTER` prompt) by going one level lower: `grep -rl 'MetaROUTER' /root/ros-work/sysimg/` across the *entire* mounted system image, not just already-disassembled userspace binaries. Result: exactly one hit outside `libumsg.so` -- `/lib/modules/5.6.3/misc/flash.ko`, the kernel module already flagged as an open question in §8.17 ("whether `flash.ko` ... is involved in provisioning `/dev/rb`").

**Located the string's cross-reference using the AArch64-appropriate method** (this module is `aarch64`, `ET_REL` -- a relocatable kernel object, not a PIE/PIC shared library, so §8.29's `ldr+add pc` ARM32 PIC idiom doesn't apply here; instead, `.text` references to `.rodata` are explicit `R_AARCH64_ABS64` relocation entries against `.rodata.str1.1 + <offset>`, found directly via `readelf -r`, no address arithmetic needed). The `"MetaROUTER"` string (`.rodata.str1.1+0x65c`) is referenced at `.text` offset `0x27e8`, which sits inside a dense cluster of literal-pool pointer slots spanning `0x27b0-0x2838` in a function objdump attributes to `init_module` (flash.ko's module-init function).

**Decoded the full contents of that literal-pool cluster** (18 consecutive 8-byte relocation slots, resolved via a Python script mapping each `R_AARCH64_ABS64 .rodata.str1.1+N` addend to its null-terminated string):

```
0x27b0  "new-flash: starting...\n"      (printk message)
0x27b8  "marvell,armada7040"             (DT machine-compatible string)
0x27c0  "marvell,msys"                   (DT machine-compatible string)
0x27c8  "econet,en7523"                  (DT machine-compatible string)
0x27d0  <.bss pointer, not a string>
0x27d8  "flash-ko"                       (module/log tag)
0x27e0  <.data pointer, not a string>
0x27e8  "MetaROUTER"                     <-- the string from §8.17/8.29
0x27f0  "nor: offs from DTB\n"           (printk message)
0x27f8  "hardcfg_offs"                   (DT property name, for of_property_read_u32-style lookup)
0x2800  "hardcfg_sz"                     (DT property name)
0x2808  "soft_offs"                      (DT property name)
0x2810  "soft_sz"                        (DT property name)
0x2818  "bios_offs"                      (DT property name)
0x2820  "bios_sz"                        (DT property name)
0x2828  "marvell,alleycat5"              (DT machine-compatible string)
0x2830  "annapurna-labs,alpine"          (DT machine-compatible string)
0x2838  "qcom,ipq4019"                   (DT machine-compatible string)
```

**Correction, from full instruction-level tracing (not just string-clustering inference) -- this replaces an incorrect first-pass interpretation.** Manually decoded the actual `init_module` control flow around this table (the region objdump renders as `...`/data is genuinely a mixed code+literal-pool region; the branches themselves *are* disassembled correctly earlier in the listing, just not adjacent to the pointer table). The real logic:

```c
void init_module(void) {
    al_spi_flash_module_init();                                              // always attempted first
    if (of_machine_is_compatible("marvell,armada7040")) mv_spi_flash_module_init();
    if (get_hcfg())                                     a37_spi_flash_module_init();
    if (of_machine_is_compatible("marvell,msys"))       orion_spi_flash_module_init();
    if (of_machine_is_compatible("econet,en7523"))      econet_spi_flash_module_init();
    // (marvell,alleycat5 / annapurna-labs,alpine / qcom,ipq4019 / is_ampere_routerboard()
    //  are checked similarly a bit further down, each with hardcoded flash-partition
    //  offset/size constants for that specific SoC's real NOR/SPI memory map)

    flash_dev->type = 1;                       // provisional
    if (!rb_mtd_good_device()) {               // <-- did any of the above actually find/validate a real flash chip?
        // FALLBACK -- no real MTD device found (this is the branch QEMU/KVM always takes,
        // since none of the of_machine_is_compatible() checks above can ever match a
        // generic `virt` machine's device tree):
        flash_dev->type = 3;
        misc_dev->name  = "MetaROUTER";        // <-- hardcoded literal, NOT derived from a DTB "MetaROUTER" compatible match
        misc_dev->type  = 11;
    } else {
        // Real hardware confirmed:
        misc_dev->name  = "flash-ko";
        misc_dev->type  = 5;
    }
    misc_register(&misc_dev->inner);           // <-- called UNCONDITIONALLY, on BOTH branches
}
```

**This overturns the first-pass reading above in one important way: `"MetaROUTER"` is not a fourth `of_machine_is_compatible()` value being matched at all.** There is no `of_machine_is_compatible("MetaROUTER")` call anywhere in this function. `"MetaROUTER"` is a **hardcoded fallback device name**, assigned whenever `rb_mtd_good_device()` -- the post-hoc check of whether any of the real-hardware driver-init calls above actually succeeded -- returns false. And critically, **`misc_register()` runs on both branches**, not just the real-hardware one. This means a misc device genuinely gets registered under plain QEMU/KVM too -- **just under the name `"MetaROUTER"` instead of `"rb"`**, i.e. the kernel creates `/dev/MetaROUTER`, not `/dev/rb`.

**This is a fully coherent explanation for §8.29's `getBoardType()` finding, and it's a better fit for the evidence than the original "no device at all" theory:** `getBoardType()`'s `open("/dev/rb", O_RDWR)` genuinely fails with `ENOENT` under QEMU/KVM -- not because the kernel registered nothing, but because it registered the fallback device under a *different path* (`/dev/MetaROUTER`). This also gives the `"open /dev/rb failed, probably metarouter"` log message (§8.29) a concrete, literal basis rather than being a vague guess: whoever wrote that message evidently knew that `/dev/rb`'s absence, in practice, usually means `/dev/MetaROUTER` exists instead -- because that's exactly what this kernel code does.

**Practical implication:** none of this changes anything about the SMBIOS/`smbios1` findings (DMI/SMBIOS data still never reaches the device-tree-based checks in this module, so `product=`/`manufacturer=`/`sku=`/`family=`/`serial=` tricks -- §8.17's real-board-name experiment included -- still cannot influence this code path, consistent with `VM301` still landing on `MetaROUTER Login:` after that test). What it *does* change is the mental model: this is not "detection failure -> nothing happens", it's "detection failure -> deliberate, hardcoded fallback identity, by design" -- MikroTik's kernel driver was written assuming that the *only* way real hardware detection fails is genuine `MetaROUTER` nested virtualization, and unconditionally labels that case accordingly, with no distinct "neither real hardware nor MetaROUTER" case in its own logic at all. Plain QEMU/KVM merely happens to also fall into that same catch-all bucket. **Still unconfirmed:** whether the struct field set to `"MetaROUTER"` (offset `+48` of the `.data`-resident struct at `27e0`) is literally `struct miscdevice.name` (which would directly produce a `/dev/MetaROUTER` devtmpfs node) as opposed to some other display-name field consumed differently -- the flow strongly suggests the former (name+type set immediately before `misc_register()` on a related sub-pointer of the same struct) but the exact `struct miscdevice` layout wasn't independently cross-checked against kernel headers for this specific 5.6.3/aarch64 build.

**Full map of every physical-hardware-detection signal found across this investigation, for reference (four independent, uncoordinated mechanisms, at three different layers, none of which talk to each other):**

| # | Layer | Mechanism | Checked value | Used by | Section |
|---|---|---|---|---|---|
| 1 | Kernel (`flash.ko` module init) | Device-tree root `compatible` string match against 6 real SoC names, then `rb_mtd_good_device()` sanity check; on failure, hardcoded fallback identity `"MetaROUTER"`/type 11 (not itself DTB-matched) | DTB `compatible` property (not SMBIOS-influenced) | Which name (`"rb"`-equivalent vs `"MetaROUTER"`) the resulting misc device gets registered under | §8.31 (this section) |
| 2 | Userspace (`libumsg.so`, `getBoardType()`) | `open("/dev/rb", O_RDWR)` success/failure + `ioctl(fd, 0x520f)` | Kernel-provided `/dev/rb` node (downstream of #1) | Board-type reporting (`sys2`, `/system resource print`-style queries) | §8.29 |
| 3 | Userspace (`libumsg.so`/`keyman_arm32`/`loader`, cached predicate) | `getenv("board")` + `strstr(value, "qemu")` | `board` environment variable (source not yet traced -- plausibly derived from DMI `product_name`, unconfirmed) | `readMBR`/`writeMBR`/`getHardwareID`'s choice of `/dev/hvckvm0` vs `/dev/flash` vs generic path | §8.9, §8.15-8.16 |
| 4 | Userspace (`libumsg.so`, `isMikrotikVendor`/`isMikrotikAmpere`) | Exact-match read of `/sys/class/dmi/id/sys_vendor` against `"MikroTik"`, plus separately `getenv("uefi")` | DMI/SMBIOS `sys_vendor` (directly settable via `smbios1 manufacturer=`) | Unknown -- 2 call sites in `sys2`, not connected to license flow or `platform:` field (ruled out in §8.30) | §8.30 |

**Answering the standing question directly**: there is no single, unified "is this real hardware" check anywhere in this stack. `keyman`/`readMBR` itself only ever looks at signal #3 (the `board` env var substring check) -- it has no dependency on #1, #2, or #4 at all (confirmed across §8.9-8.29: `keyman_arm32` doesn't import `getBoardType` or `isMikrotikVendor`). Signals #1 and #2 belong to a *separate* subsystem (`flash.ko`/`sys2`, board-type/resource reporting): the kernel module always registers *some* misc device at boot (real-hardware path named after the real board, generic-fallback path hardcoded to the hardcoded `"MetaROUTER"` string) -- it never simply does nothing -- and `getBoardType()` fails specifically because it's hardcoded to look for `/dev/rb`, which only exists on the real-hardware branch. Signal #4 remains an unconnected, separate mechanism. The `[admin@MetaROUTER]` login prompt users see is best explained as this same fallback identity string surfacing again at a higher layer (very plausibly the login/console binary reads the very same `/dev/MetaROUTER` misc device, or a `/proc`/`sysfs` field it exposes, to decide what to print as the hostname/prompt) -- but that specific consumer (which binary reads `/dev/MetaROUTER` or its associated board-name output and turns it into the visible boot banner and prompt) has still not been directly located; it remains the one piece of this map without a confirmed cross-reference.

### 8.32 External source cross-check: an independent writeup names `keyman`'s local EC-KCDSA public key -- independently confirmed present in both `keyman_x86_7.23.2` (x86) and `keyman_arm32`, revising §8.26's "no local verification found" conclusion

A third-party writeup (CSDN, "MikroTik RouterOS 授权签名验证分析", https://blog.csdn.net/chivalrys/article/details/139770711) independently documents the `.key`-file license format and claims a specific 32-byte EC-KCDSA public key is embedded in `/nova/bin/keyman` for **local** signature verification: `8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32`. This directly bears on §8.26/8.27's open question ("whether local, offline signature verification happens anywhere in `keyman_arm32` remains genuinely open") -- so rather than taking the article's claim on faith, every part of it was independently re-derived from data and binaries already in this project.

**Step 1 -- confirmed the article's 64-byte license-blob structure against this project's own known-valid signature, with zero dependency on the article's crypto claims being true.** `keys.toml`'s `TI09-7WK3` entry (one of this project's four originally-available signatures) is exactly the same signature the article uses as its own worked example. Splitting our own `signature_hex` into the article's claimed layout (16B encrypted payload + 16B nonce hash + 32B signature) gives nonce-hash and signature values that match the article's example **byte-for-byte**. Running the article's custom-SHA-256-K-table ARX decode (`mikro_decode`, matching this project's own `convert::mt_transform` -- same algorithm, independently implemented) against our payload bytes decodes to `Software ID: TI09-7WK3 (0x137f8e8673d)`, `Version: 6`, `Level: 6`, reserved bytes all zero -- exactly matching both the article's claim and this project's own `keys.toml` entry. This confirms the 64-byte structure and custom-SHA256-based ARX cipher are correct, using this project's own pre-existing data, independent of trusting the article.

**Step 2 -- located the actual public-key bytes in `tools/bin/keyman_x86_7.23.2` (x86, ELF32) via direct disassembly, not by trusting the article's number.**

*Where*: function at `0x804f4c6` (x86, ELF32, `tools/bin/keyman_x86_7.23.2`), specifically the eight instructions at `0x804f658-0x804f6a2`.

*How, step by step (reproducible)*:
1. `strings -a -t x tools/bin/keyman_x86_7.23.2 | grep -i "software key\|license"` found the anchor strings `"Installed software key from %s."` (file offset `0xc24d`) and `"-----BEGIN MIKROTIK SOFTWARE KEY..."` (file offset `0xc3cc`) -- confirming this binary handles the local `.key`-file format at all, before looking for any crypto.
2. `objdump -h` gave `.rodata`'s VMA (`0x08054000`); combined with `objdump -p`'s `LOAD` segment table (first segment: `off 0x0 vaddr 0x08048000`), the file-offset-to-VMA delta for this segment is `+0x08048000` (standard for this class of ET_EXEC i386 ELF). Converting the string file offsets to VMA (`0xc24d + 0x08048000 = 0x0805424d`, etc.) gave addresses to search for as absolute immediates in the disassembly.
3. `objdump -d -r tools/bin/keyman_x86_7.23.2 > disasm.txt`, then `grep -n "805424d\|80543cc\|..."` found the exact `pushl $0x805424d`-style cross-references, pinpointing the enclosing function (`0x8052996`) that builds the "please paste a license" error path -- and, walking forward from there, the actual parse/verify function it calls at `0x804f4c6`.
4. Reading `0x804f4c6`'s body directly: an ARX loop (`0x804f4dd-0x804f60f`) matching Step 1's decode algorithm exactly, followed immediately by **eight separate `movl $imm32, stack_offset(%ebp)` instructions** (`0x804f658-0x804f6a2`) -- the compiler baked the 32-byte constant directly into instruction immediates rather than a contiguous data blob, which is *exactly* why an earlier plain byte-sequence search across `.rodata`/`.data` for the article's key found nothing (there is no contiguous 32-byte run of these bytes anywhere in the file). Concatenating the 8 little-endian dwords in program order (`0xE467108E, 0xC0CD5F30, 0xC195BFCF, 0xDFE5960F, 0xEF9AC4E8, 0xA4D16B48, 0x276CE9E2, 0x323E1EF0`) reproduces the article's public key **exactly**, byte for byte -- independently confirmed via disassembly, not copied from the article.
5. Confirmed the surrounding code matches `mikro_kcdsa_verify` step-by-step, continuing to read past the 8 constants: a 16-byte XOR-combine loop (`data_hash[8+i] ^= nonce_hash[i]`), X25519 clamping (`andl $0x7f` / `orl $0x40` on the boundary bytes), calls into curve-scalar-multiply and hash functions, then a final 16-byte `memcmp` (`0x804f700`) reduced to a boolean via `sete` (`0x804f70a`).

**Step 3 -- found the same constant, and the same function shape, in `keyman_arm32`.**

*Where*: `keyman_arm32`'s literal pool at file offset `0x7350` (VMA `0x17350`), consumed by the function at `0x170d4` (already named in §8.24 as the "clamp-and-scalarmult wrapper").

*How, step by step (reproducible)*:
1. The Step-2 lesson (constants aren't always contiguous) meant a contiguous-32-byte search wasn't retried here. Instead, a small Python script searched for each of the 8 dwords **individually**, as a raw 4-byte little-endian pattern, anywhere in the file (`data.find(struct.pack('<I', dw))` for each of the 8 values) -- a much weaker, more robust search than requiring all 32 bytes contiguous and in the exact original order.
2. 7 of 8 dwords matched, all within a tight 28-byte window: `0x7350` (`0xEF9AC4E8`), `0x7354` (`0xA4D16B48`), `0x7358` (`0xC195BFCF`), `0x735c` (`0xE467108E`), `0x7360` (`0xC0CD5F30`), `0x7364` (`0x276CE9E2`), `0x7368` (`0x323E1EF0`). Reading these addresses back as raw file bytes in sequence at first *looked* scrambled relative to the canonical key's byte order -- but cross-checking against the already-generated `keyman_arm32_disasm.txt` (`grep -n "73[0-4][0-9a-f]:"`) showed each value is loaded via its own `ldr rX, [pc, #N]` instruction (e.g. `0x17248: ldr r6, [pc, #256] @ 17350`, `0x17280: ldr r3, [pc, #208] @ 17358`) and then individually `str`/`strd`-stored into a verify buffer at the offset matching its true position in the 32-byte key (the `0x17358` value, key bytes 8-11, lands at buffer offset 8 via `0x17294: str r3, [sp, #8]`) -- the apparent scrambling was an artifact of reading the *source* literal-pool order, not the *destination* buffer layout, which is correctly ordered.
3. **The 8th dword (`0xDFE5960F`, key bytes 12-15) was not found** as a plain literal-pool word anywhere in the file (checked both byte orders). An `add`-immediate chain building an unrelated 32-bit constant was found nearby (`0x17298-0x172a8`) but tracing its actual register value did not reproduce `0xDFE5960F` when checked by hand -- this one piece of the key is not yet independently located in the ARM binary, and is flagged rather than assumed.
4. Confirmed the enclosing function is `0x170d4` by matching the surrounding instructions against §8.24's own description verbatim: the clamping sequence at `0x172f0-0x17314` (`bic r3, r3, #7` / `orr r3, r3, #64`, ARM's equivalent of x86's `andb $-0x8` / `orl $0x40`) immediately precedes the `bl 15654` call that §8.24 point 3 already identified as the clamp-then-scalarmult call site inside `0x170d4`. Reading past that call to the function's actual end (`0x17348`) -- not previously done in §8.24-8.27 -- shows a 16-byte `memcmp` (`0x17338`) followed by `clz r0, r0` / `lsr r0, r0, #5` (ARM's branch-free idiom for "was the comparison result exactly zero", equivalent to x86's `sete`), i.e. the same verify-and-return-boolean tail confirmed in `keyman_x86_7.23.2`'s Step 2 function -- not merely "crypto-shaped code" as §8.24 cautiously described it at the time.

**This revises §8.26's negative conclusion, but does not fully overturn §8.27's finding about what specifically gets verified.** §8.24-8.27 already traced this exact function (`0x170d4`) and its 4 callers, and §8.26/8.27 concluded the reachable call chain from these 4 sites leads to the `licence.mikrotik.com` **online** renewal flow, not `readMBR`/`writeMBR`/`getHardwareID`. That specific tracing result is unchanged by this section. What *is* new: this function is now confirmed, independently and with a real embedded public key match, to be a genuine EC-KCDSA **verify-and-compare** operation (not merely "crypto-shaped code that might be used for verification") -- meaning at minimum, it verifies *something* cryptographically (very plausibly the signature the server sends back as part of the online renewal response, consistent with §8.27's flow). **Still open**: whether `keyman_arm32` has a *separate*, not-yet-found call path from local `.key`-file import (the `-----BEGIN MIKROTIK SOFTWARE KEY-----` flow, confirmed present and reachable via `"Installed software key from %s."` in the x86 binary) into this same verify function, the way `keyman_x86_7.23.2` clearly does. That specific cross-reference (local `.key`-import handler -> `0x170d4`) has not been checked in `keyman_arm32` and is the concrete next step if this thread continues -- it would be the piece that finally confirms or refutes local, offline signature verification for the ARM64 platform specifically.

**Practical implication:** none of this changes the collision-search method's own validity (§1-7) -- that method never depended on forging new signatures, so whether local verification exists doesn't gate it. What it *does* open up is a completely different, more general technique that this session had not previously considered: since a real, embedded, hardcoded public key now has independent confirmation in at least one `keyman` build (x86), and MikroTik's own `patch.py`-style tooling (referenced in the CSDN article as https://github.com/elseif/MikroTikPatch) demonstrates that replacing this embedded public key with a self-generated one (and re-signing NPK packages against a second, separately-embedded NPK-verification key) lets you sign arbitrary new licenses at any `nlevel`, entirely bypassing SOFTWARE-ID/MBR mechanics and (by extension) the whole ARM64 `board=qemu`/`MetaROUTER`/DTB hardware-detection maze this session has been navigating. Whether this technique is viable on the ARM64 build specifically now hinges entirely on the one open item above.

### 8.33 First independent, real-world validation of the `curve25519.rs` EC-KCDSA verifier -- against an externally-supplied license, not our own test data

Source: [github.com/cheebun/mtsc issue #2](https://github.com/cheebun/mtsc/issues/2), which links a real `.key` file (`W5EY-LHT9.KEY`, hosted at a third-party GitHub repo) and includes a manual verification trace from a commenter (`MurVlad`) using the independent Python reference (`ParseLic.py`).

**Ran `mtsc key2sig` directly against the fetched `.key` file content (not against any of this project's own known-good signatures) and compared byte-for-byte against `MurVlad`'s independently-produced manual trace:**

| Field | Our tool | `MurVlad`'s manual trace |
|---|---|---|
| Software ID | `W5EY-LHT9` | `W5EY-LHT9` |
| License Level | `6` | `6` |
| Nonce Hash | `63CAF8EEDB34A90CF9A66B4F174BA78D` | `63 ca f8 ee db 34 a9 0c f9 a6 6b 4f 17 4b a7 8d` |
| Signature | `AE910531EF99F98FC229A21C5EA80E1D0FBF593E6A86B651EE28B98C77BDAD01` | `ae 91 05 31 ef 99 f9 8f c2 29 a2 1c 5e a8 0e 1d 0f bf 59 3e 6a 86 b6 51 ee 28 b9 8c 77 bd ad 01` |
| License valid | `true` | `OK - License valid` |

Exact match on every field. This is the first time `curve25519.rs`'s `curve25519-dalek`-based verifier has been exercised against a signature this project didn't already know was valid (§8.32's own test used `TI09-7WK3`, a signature this project had *already* separately confirmed via real hardware activation, §8.14) -- and it agrees exactly with a second, independently-written verification tool (`ParseLic.py`, a different implementation of the same EC-KCDSA algorithm) on a completely different signature. This is meaningful cross-validation: two independent implementations of the algorithm, fed the same real-world input neither was tuned against, produce identical results.

**Important caveat, not yet resolved:** a second commenter on the same issue states this specific license (`W5EY-LHT9`) "has been abused too much and has been blocked." Cryptographic validity and practical usability are different questions -- a signature can be mathematically valid (as confirmed above) while the specific SOFTWARE ID it corresponds to is blocklisted server-side or by a newer RouterOS version's local revocation list. **Planned next step, not yet done:** test this signature end-to-end on real hardware/VM (write it via MBR or `.key` import, boot, check `/system license print`) to determine whether "blocked" means RouterOS itself now refuses it locally, or only that MikroTik's *online* license-renewal endpoint refuses to reissue/extend it (in which case a one-time offline activation might still succeed). This distinction matters for this project's practical guidance -- if local verification alone can be blocklisted independent of the SOFTWARE ID collision method, that would be a new category of failure mode not previously documented anywhere in this file.

### 8.34 Real-hardware confirmation: `scsi0` collision search reused against an externally-supplied signature (`J1WN-449W`), full offline activation, no network

Continuing §8.33 with a second externally-supplied license found in the wild ([github.com/xSomoy/Study, `J1WN-449W.key`](https://github.com/xSomoy/Study/blob/e0f91d53cc60d509d2f5b38642467fcb5a89c1f7/Networking/Mikrotik-6/J1WN-449W.key)). `mtsc key2sig` decoded it independently: `Software ID: J1WN-449W`, `Router OS Version: 6`, `License Level: 1`, `License valid: true`. Unlike `W5EY-LHT9` (§8.33), no report of this specific ID being blocklisted was found anywhere.

**Ran a dedicated `--bus scsi` collision search against this signature (fixed `model=RouterOS-SCSI`, `sector_val=0` regardless of disk size per §8.19) and found two colliding serials in ~4386s on a 2-core host** (`serial=00000000394117852659` and `serial=00000000547437415680`, both independently re-verified via `mtsc check`).

**Full offline end-to-end activation test, network-isolated (no `net0` device on the test VM at all)**, on a disposable VM (`VM301`, x86_64/`q35`, `scsihw=virtio-scsi-pci`, `scsi0` with `serial=00000000394117852659` + `-args '-set device.scsi0.product=RouterOS-SCSI'` for the product/model field, since PVE's native `--scsi0` syntax doesn't expose `product=` directly -- matches the exact mechanism already confirmed in §8.14/§8.18):

1. Installed RouterOS 7.23.2 fresh from ISO onto the `scsi0` disk (install-first, per this project's standard rule -- the installer overwrites `0x10A-0x10B`).
2. Stopped the VM. Since the disk is qcow2 (not a raw image or block device), wrote the MBR signature via `qemu-nbd` (`modprobe nbd` -> `qemu-nbd -c /dev/nbd0 -f qcow2 <disk>` -> `dd ... of=/dev/nbd0 bs=1 seek=256` for the 80-byte identity+marker+signature block at `0x100-0x14F` -- `dd` cannot write into a qcow2 file directly at a raw byte offset, only into an actual block device, hence the NBD step). Read the bytes back immediately after writing to confirm the disk-side content matched exactly, before booting.
3. Booted the VM (no serial console output on this x86/SeaBIOS setup, unlike the ARM64/UEFI VMs used throughout §8 -- used QEMU monitor `screendump` + local `ffmpeg` PPM->PNG conversion to observe the console instead, and `qm sendkey` to log in, since there is no network path into this VM at all).

**Result: `/system license print` shows `software-id: J1WN-449W`, `nlevel: 1` -- no `expires-in` line, no `ROUTER HAS NO SOFTWARE KEY` trial banner at boot.** This is unambiguous full activation, achieved with zero network connectivity at any point (install media is local ISO, no `net0` device exists on the VM) -- confirming this specific SOFTWARE ID's local, offline signature verification succeeds on real (well, production-topology) x86_64 hardware, entirely independent of MikroTik's online license servers.

**What this confirms:** the collision-search method (§1-7) generalizes cleanly to externally-sourced signatures found via community reports, not just this project's own curated `keys.toml` entries -- `mtsc search --bus scsi` found a working collision for a signature this project had never seen before, and that collision activated for real. (This section originally speculated here about *why* `W5EY-LHT9` might be blocked, reasoning from `J1WN-449W`'s clean success alone -- §8.35 tested `W5EY-LHT9` directly instead, and that speculation turned out to be wrong. See §8.35.)

### 8.35 `W5EY-LHT9` directly tested, real hardware, two different signatures -- both fail locally, offline, confirming §8.33's "blocked" report and overturning §8.34's speculation about *why*

§8.34 closed by speculating that `W5EY-LHT9`'s reported block was "most plausibly server-side/online-only," reasoning from `J1WN-449W`'s unrelated success rather than a direct test. That speculation is now known to be **wrong** -- tested directly, on the same real-hardware/offline setup as §8.34.

**Found a second `scsi0` collision for `W5EY-LHT9` itself** (a different `serial=`/`product=` combo than §8.33's decode target -- `serial=00000000249663178723`, `product="QEMU HARDDISK"` this time, found and supplied externally rather than by this project's own search run), independently re-verified via `mtsc check` before use. (Aside, purely mechanical: PVE's `args:` config line splits on whitespace with no quoting support of its own, so a `product=` value containing a space -- `QEMU HARDDISK` -- must be wrapped in literal quote characters *within* the `args:` string, e.g. `-args '-set device.scsi0.product="QEMU HARDDISK"'`, or the value silently splits into two broken arguments and QEMU fails to start.)

**Reused the same already-installed `VM301` disk for both tests in this section -- no reinstall between them.** Per this project's standard rule (install once, MBR write can be repeated freely -- only the *installer* overwrites `0x10A-0x10B`, not a later boot), each test only required: stop the VM, change `scsi0`'s `serial=`/`args` `product=` to the new combo, rewrite the 80-byte identity+marker+signature block via the same `qemu-nbd` procedure as §8.34, restart.

**Test 1 -- §8.33's original `W5EY-LHT9` signature (from `W5EY-LHT9.KEY`, the one reported "abused too much and has been blocked"):** boot shows the standard **`ROUTER HAS NO SOFTWARE KEY`** banner with a normal ~24h trial countdown. `/system license print` confirms: `software-id: W5EY-LHT9`, `expires-in: 23h49m10s`. **Not activated** -- falls back to plain trial, entirely offline (no `net0` device exists on this VM, so this cannot be an online server rejection).

**Test 2 -- a second, independently-sourced `W5EY-LHT9` signature (from `ros-key-v7.x.KEY`, §8.33's earlier find with the anomalous `License Level: 22` value):** same result. `ROUTER HAS NO SOFTWARE KEY` banner, `/system license print` shows `software-id: W5EY-LHT9`, `expires-in: 23h48m54s`. **Also not activated.**

**Conclusion: both cryptographically-valid `W5EY-LHT9` signatures fail the same way, locally, with zero network access at any point.** This rules out §8.34's speculation cleanly -- if the rejection were online/server-side only, a fully network-isolated VM could never observe it, since there is no path for it to even attempt contacting MikroTik. It also rules out "this one specific signature file was corrupted/mistyped" -- two independently-sourced signatures, decoding to different raw bytes but the same `Software ID`, both fail identically. The most coherent remaining explanation: **RouterOS 7.23.2's local, offline verification path checks something beyond the raw EC-KCDSA signature math for this specific SOFTWARE ID** -- most plausibly a hardcoded or otherwise locally-shipped blocklist of specific `SOFTWARE ID`s known to MikroTik to have been abused (the reported mechanism for "this license has been abused too much and has been blocked" line up with this being a *known, curated* blocklist rather than some accidental or narrow one-off signature defect) -- keyed on the `SOFTWARE ID` itself, not on the specific signature bytes, since both signatures (`8EBD34F8...` and `0AC14BD0...`) share the same ID and both were rejected identically. **Not yet located**: the actual code path in `keyman_arm32`/`keyman_x86_7.23.2` that performs this check has not been disassembled or found -- this section establishes the *behavior* (local offline blocklisting exists and is real) via black-box testing, not the mechanism. Finding it would require locating a data structure or comparison specifically keyed on SOFTWARE ID/software-id-derived values, separate from the EC-KCDSA verify path already mapped in §8.24-8.32 (which only concerns itself with *whether a signature is cryptographically valid*, not whether its Software ID is on any kind of list).

**Practical implication for this project:** the collision-search method's own validity is unaffected -- any SOFTWARE ID successfully found via collision search and confirmed to activate (as `J1WN-449W` was, §8.34) remains genuinely activatable. But it establishes, for the first time with direct real-hardware evidence, that **not every valid signature is safe to rely on** -- a specific ID being widely shared/reused in public `.key` file repositories appears to be a real risk factor for that ID ending up on a local blocklist, independent of anything about the collision-search technique itself. This is a new category of failure mode for this project's practical guidance: verifying a signature is cryptographically valid (`mtsc`'s `LICENSE-VALID: true`) is necessary but **not sufficient** to guarantee it will actually activate on current RouterOS versions.

### 8.36 External data point (unverified) -- `XGWP-9N00` / `D7240F566244`, real RouterBOARD `RBLtAP-2HnD`

Raw values from user-provided screenshots (RouterOS license/info + RouterBOARD/resource screens), recorded here for reference only -- **not yet checked against this project's SHA-256 pipeline** (this is hardware-key-based licensing on a real MIPS RouterBOARD, an entirely different mechanism from this project's x86/disk-based SOFTWARE ID collision search; `D7240F566244` is 12 hex chars, which also doesn't fit the 20-char serial field this project's `ide0`/`scsi0` search targets).

| Field | Value |
|---|---|
| Software ID | `XGWP-9N00` |
| Serial Number (RouterBOARD) | `D7240F566244` |
| Model | `RBLtAP-2HnD` |
| Firmware Type | `mt7621L` |
| Factory Firmware | `6.47.10` |
| Current Firmware | `7.23.2` |
| Upgrade Firmware | `7.23.2` |
| RouterOS Version | `7.23.2 (stable)` |
| Build Time | `2026-07-03 09:08:08` |
| Factory Software | `6.46.4` |
| Board Name | `LtAP` |
| Architecture | `mmips` |
| CPU | `MIPS 1004Kc V2.15`, 4 cores, 880MHz |
| Total Memory | `128.0 MiB` |
| Total HDD Size | `16.0 MiB` |
| Uptime (at capture) | `23:47:35` |

Confirms `D7240F566244` is the **RouterBOARD hardware Serial Number** (burned-in, MIPS device), not a disk serial -- consistent with this project's earlier note (§8.36 original entry) that it doesn't fit the x86 disk-serial format. This is a genuinely different licensing mechanism from the collision-search method (§1-7): RouterBOARD devices key off hardware-burned identity, not a virtual/physical disk's SOFTWARE ID via `ide0`/`scsi0`/NVMe. Not present anywhere else in this repo (`keys.toml`, `collision-database.md`) as of this writing -- confirmed via full-tree grep before adding. No further analysis done yet; revisit if this becomes relevant to a MIPS/ARM-specific investigation thread.

A second real RouterBOARD data point (`RB962UiGS-5HacT2HnT`, `qca9550L`, RouterOS 7.24 stable), same category (hardware-burned licensing, not disk-based), recorded for reference only:

| Field | Value |
|---|---|
| Software ID | `T55H-PFA8` |
| Serial Number (RouterBOARD) | `830608559EBF` |
| Level | `4` |
| Features | `extra-channels` |
| Model | `RB962UiGS-5HacT2HnT` |
| Firmware Type | `qca9550L` |
| Minimum Version | `3.41` / `6.34.2` |
| Current/Upgrade Firmware | `7.24` |
| Board Name | `hAP ac` |
| Architecture | `mipsbe` |
| CPU | `MIPS 74Kc V5.0`, 1 core, 720MHz |
| Total Memory | `128.0 MiB` |
| Total HDD Size | `16.0 MiB` |

### 8.37 `scsi0`-installed disk switched to `ide0` post-install (no reinstall): SOFTWARE ID computes correctly, activation still fails -- bus-type switching is NOT equivalent to same-bus identity reuse

§8.35 established that reusing an already-installed disk and only changing `scsi0`'s `serial=`/`product=` (same bus type) works cleanly for repeated activation tests -- no reinstall needed. This section tests a stronger claim: switching the *bus type itself* (`nvme` → `ide0`) on an already-installed disk, without reinstalling.

**Setup:** `VM302`'s disk (`vm-302-disk-0.qcow2`), originally installed via the `args:`-based raw NVMe passthrough method (§ NVMe investigation, `XGM9-BKRF` confirmed), was reconfigured -- VM stopped, `args:` NVMe device deleted, disk reattached as `ide0` with `serial=00000000251582663387,size=1G` (native PVE syntax accepts `serial=` directly for `ide0`) and `-args '-set device.ide0.model="SSD1G"'` for the model field -- reusing the exact `serial`/`model` combo from `docs/collision-database.md`'s `1G` `ide0` table (`TI09-7WK3`, previously confirmed `Y`). The `TI09-7WK3` MBR signature (`keys.toml`) was written via the standard `qemu-nbd` procedure, byte-verified on readback.

**Result:** the VM booted successfully off `ide0` despite having been installed via NVMe (bootloader was not bus-specific enough to fail outright -- itself a minor useful data point). `/system license print` showed:

```
software-id: TI09-7WK3
expires-in: 23h58m51s
```

**`software-id` computed correctly** (matches the `serial`/`model` → `TI09-7WK3` collision exactly, confirming the `ide0` sector-size-dependent SOFTWARE ID formula still applies correctly post-bus-switch), **but the license did not activate** -- still on the plain ~24h trial, despite `TI09-7WK3` being this project's most extensively real-hardware-confirmed signature (§8.14 and elsewhere).

**Interpretation:** this rules out an MBR-write mistake (bytes verified, and the same exact write procedure works in §8.34/8.35 for same-bus reuse). The most likely explanation is that RouterOS retains some installation-time state beyond the raw 64-byte MBR signature block -- keyed to the disk bus/identity present *at install time* -- that a later, different-bus identity change invalidates, even though the freshly-computed `software-id` field still matches the signature. **Practical implication:** collision-search testing across different bus types must use a **fresh install for each bus type**, not a bus-switched reuse of an existing installation -- same-bus identity reuse (§8.35) remains valid and fast, but is not a substitute for a real per-bus-type install when testing `ide0` vs `scsi0` vs `nvme` specifically. Not yet root-caused at the disassembly level; flagged as an open item if bus-switch behavior becomes relevant again.

### 8.38 CHR license format cross-check via `loskiq/MikroTikPatch`: confirms CHR uses `system_id`(8B), not `software_id`(6B) -- and one specific pasted CHR license is very likely a self-signed test artifact from that same tool, not a genuine MikroTik-issued license

An external project, [`loskiq/MikroTikPatch`](https://github.com/loskiq/MikroTikPatch) (`license.py`/`mikro.py`), was reviewed for its `lic_parse_chr`/`lic_gen_chr` functions. Cross-checking against this project's own confirmed constants:

- `mikro.py`'s `MIKRO_SHA256_K` table and custom IV (`0x5B653932, 0x7B145F8F, ...`) are **byte-identical** to this project's `sha256_constants.rs` -- independent confirmation from a second, unrelated codebase.
- Its hardcoded `MIKRO_LICENSE_PUBLIC_KEY = "8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"` matches this project's own EC-KCDSA public key (§8.32) exactly.
- **CHR's 16-byte decoded payload layout differs from ROS's**: ROS is `software_id(6B) + version(1B) + level(1B) + reserved(8B)` (this project's existing format); CHR is `opaqueId(8B) + deadline(4B) + level(1B) + reserved(3B)` -- **correction (2026-09-09, see §8.42)**: this was originally recorded here as `system_id(8B) + 3 unknown bytes + deadline(1B) + level(1B) + 3 reserved bytes`, based on `loskiq/MikroTikPatch`'s `varb9`/`varb10`/`varb11`/`varb12` naming (4 separate single-byte fields at payload offsets 8-11). Direct `keyman_x86_7.24.1` disassembly (§8.42) proves these 4 bytes are read and compared as a single little-endian 32-bit Unix-epoch `deadline` field, never accessed individually -- the "3 unknown bytes" never existed as independent fields, they're just the low 24 bits of `deadline`. The raw byte layout/values are unaffected (concatenating 4 individually-encoded bytes in order produces byte-identical output to encoding one LE u32), only the field-count/semantics were wrong. `mikro_systemid_encode`/`decode` use the *same* base64-style character table as the outer Key-text encoding (`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`), not the ROS `SOFTWARE_ID_CHARACTER_TABLE` -- a different alphabet from `TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE`, and produces an 11-character (not 8-character/`XXXX-XXXX`) identifier.

**A specific CHR license text pasted into this session** (`System ID: eJq8zK/UrhN`, `Deadline: 244`, `Level: 3`) was decoded using this reimplementation and independently verified against this project's own `mtsc key2sig` (using the real MikroTik public key): `License valid: false`, with a `reserved bytes not all zero` warning (expected, since the bytes are CHR-format, not ROS-format). More tellingly, the decoded "unknown" filler bytes (`varb9=0, varb10=87, varb11=134`) **exactly match** `lic_gen_chr()`'s own hardcoded example defaults in `license.py`. This is strong circumstantial evidence that this specific license was generated by that tool's own `licgenchr` self-signing command (using a locally-generated key pair, per its `genkey` subcommand -- which explicitly documents patching `keyman`'s embedded public key to trust an attacker-controlled key) rather than being a genuine MikroTik-issued CHR license. This is a fundamentally different technique from this project's SOFTWARE-ID collision search -- it requires binary-patching the target's trusted public key, not finding a serial/model that reproduces a target ID.

### 8.39 ARM32 `keyman`'s hardware-identity call chain fully mapped (`getHardwareID` → `/dev/flash` / real-disk / string-fallback), and an exhaustive proof that neither of its two SOFTWARE-ID "combine" formulas can produce `XU4M-NJ40`

Triggered by an externally-supplied real-hardware case: `Model=C52iG-5HaxD2HaxD` (RouterBOARD, `ipq6000` SoC), `Serial=HE508Y4T7YB`, claimed working `SOFTWARE ID=XU4M-NJ40` (KEY text decoded and independently confirmed to encode exactly this ID, `Version=6`, `Level=4`, reserved bytes all zero -- genuine ROS format, not CHR). `mtsc check` with both `--bus ide` and `--bus scsi` (standard identity) computes different, non-matching IDs (`EUSF-AK1K`, `3GC2-T9RD`) for this serial/model/size -- as does an exhaustive enumeration of all 2048 possible non-standard `--identity` identities (§ prior turn, both bus types) -- so this thread pivoted to disassembling `keyman_arm32` itself to find the *real* algorithm real hardware uses, rather than continuing to guess inputs for the x86/VM-calibrated formula.

**`keyman_arm_7.24.1`** (extracted this session from the current `routeros-7.24.1-arm64.npk`, i.e. what genuinely ships for ARM64-architecture devices) **is byte-identical (MD5 `ebdaa0f2f1b71cb535490c8e93c2c754`) to the pre-existing `keyman_arm32`** used throughout §8.24-8.32 -- confirming MikroTik ships the same 32-bit ARM binary for the "arm64" architecture package; there is no separate aarch64 `keyman` build, and all `keyman_arm32` findings apply directly to real ARM64 RouterBOARD hardware like this device.

**Call chain located (all addresses in `keyman_arm32`, file-offset-to-VMA delta `+0x10000` for `.text`/`.rodata`, a *different* delta for `.data` -- confirmed via `readelf -S`, not assumed):**

1. An `nv::message`-building function (caller context matches the same `raw_id`/`u64_id`/`u32_id` field-insertion pattern seen throughout this binary and in the x86 build) calls **`0x19b64`**, which tries, in order: a cache-check helper (`0x17574`), a second helper (`0x18b08`+`0x1762c`), then **directly `open("/dev/flash", "r")` + `ioctl(fd, 0x4601, buf)`** to read up to 512 bytes into a caller-supplied buffer, with an `fopen()`-based fallback on failure. Confirmed via literal-pool string resolution (`0xe2fa`-class VMA lookups on raw bytes, not `objdump`'s text output, which does not show cross-references for `ADR`/PC-relative-immediate-computed addresses): the path string genuinely reads `/dev/flash`.
2. This buffer is passed into **`0x18c28`** (the actual `getHardwareID`-equivalent compute engine -- confirmed by its own debug strings, `"getHardwareID: could not get disk %s info\n"` and `"%s: hdd-model='%.16s' s='%.20s' sz=%d MB\n"`, both resolved from literal-pool words), which itself branches:
   - **"Real device" path** (taken when `open("/dev/flash", O_RDWR)` -- note: a *second*, independent open of the same path, not reusing step 1's fd -- or a caller-supplied fallback path succeeds): `ioctl(fd, 0x80044604 /*BLKGETSIZE*/)` for a size, `ioctl(fd, 0x462b /*HDIO-identify-style*/)` for a ~512-byte structure. **Both ioctl numbers are byte-identical to the constants used in the equivalent x86 `keyman` real-disk code path.** Formula (read directly off the disassembly at `0x18d10-0x18d4c`): `sector_val = size & 0x1FFFFF; mix = sector_val * 0x10044` (same `0x10044` magic constant as x86); `raw_lo = identify_bytes[0:4]`; `raw_hi = (identify_bytes[4:8] & 0x1FF) | 0x200`; `final_lo = raw_lo XOR mix_lo`, `final_hi = raw_hi XOR mix_hi`.
   - **"Fallback" path** (`0x18d58` onward, reached when the real-device opens fail): issues `ioctl(fd, 0x31f, buf)` on whichever fd is open, then parses specific byte offsets within the result (`+58`, len 40; `+50`, len 8; `+24`, len 20 -- construction via repeated `bl 137ec`, a trim/format helper, and C++ `string` objects) into the same 20-byte-serial/16-byte-model buffers used throughout this binary (space-padded via the identical byte-for-byte loop shape as this project's own `build_serial_bytes`/`build_model_bytes` in `main.rs`). **Not yet confirmed**: whether `0x16ff8` (called with `len=40` here, but also called with `len=10`/`len=20` elsewhere with behavior that looks like plain `memcpy`) actually performs a MikroTik-SHA256 hash in this specific call, or is purely a copy/format utility whose output is read directly as `sid_lo`/`sid_hi` -- `0x16ff8`'s own body was not disassembled in this session. Flagged as an explicit open item, not resolved.
3. The **mix/identity source itself** -- **`0x17094`** -- is called with a 10-byte buffer pointer chosen between two candidates 256 bytes apart (`r7` vs `r7+256`) based on **`hasUefiSupport()`**'s return value (i.e. this device's boot-firmware type selects which of two parallel identity buffers is used). It copies the 10 bytes via `0x16ff8`, reads the first 2 bytes as a little-endian `u16` (**with an ARM-specific quirk not present in the x86 `mix_from_identity` Rust implementation: if this value is exactly `0`, it is replaced with the constant `0x1eef`/7919**), then XORs with the output of a second, not-fully-disassembled checksum function at `0x13808`.
4. The combine step (`0x19300-0x1931c`) reads exactly the same magic multiplier constant used by x86's `mix_from_identity` -- **`0x3FF800F`, confirmed to appear exactly once in the entire binary via raw byte search** (file offset `0x9368`, referenced by `ldr r3, [pc, #96]` at VMA `0x19300`) -- masks the identity-source value to 11 bits (`ubfx r0, r0, #0, #11`, i.e. `mbr_val` in `[0, 0x7FF]`, identical structure to x86), multiplies by `0x3FF800F` (`umull`), and XORs into the `sid_lo`/`sid_hi` pair.

**Exhaustive structural proof that neither combine formula can produce `hi=0x23` (`XU4M-NJ40`'s decoded high part):**

- For *both* formulas, the "mix" is `(an 11-bit-or-21-bit-masked value) * 0x3FF800F`, and a full brute-force over the entire valid input range confirms `mix_hi` (`mix >> 32`) **never exceeds `0x20`** for the 11-bit-masked (`mix_from_identity`-equivalent) case, and stays similarly small for the 21-bit-masked (`sector_val`) case across all `2^21` possible values -- confirmed by direct enumeration, not estimation.
- Both formulas unconditionally force a specific high bit before the final XOR (`| 0x100` fallback path, `| 0x200` real-device path) and `mix_hi` is never large enough to flip that bit back off. **Every known-good, real-hardware-activated x86 signature in this project's `keys.toml` (`TI09-7WK3`, `4MZF-SFTR`, `HHJH-UFWL`, `C7CU-PGT9`, `W5EY-LHT9`, `J1WN-449W`) decodes with bit `0x100` set in its high byte** -- an exact, exceptionless match to this structural prediction, independently confirming the formula's `|0x100` behavior from real data, not just static analysis.
- `XU4M-NJ40` decodes to `hi = 0x23` -- **bit `0x100` is unset AND bit `0x200` is unset**. Neither formula can produce this value for *any* choice of serial/model/size/identity/flash-content -- this is independent of correctly guessing the real hardware inputs.
- A full-binary sweep for every `umull` instruction (34 total) and every `orr rX, rX, #imm` with `imm` in `{64, 128, 256, 512, 1024}` (3 total: `0x40` at `0x17300` -- unrelated feature, `0x200` at `0x18d3c`, `0x100` at `0x192e4`) confirms **no third SOFTWARE-ID combine path exists anywhere in this binary**. (The other 28 `umull` sites cluster tightly in `0x145e8-0x1516c`, matching the already-documented EC-KCDSA/curve25519 bignum arithmetic, §8.24-8.32; two more, `0x1a950` and `0x1be14`, are an uptime-statistics scaling calculation and the soft-float `__muldf3`-style multiply routine respectively -- both unrelated, checked and ruled out.)

**Working hypothesis (not yet independently verified):** since this exact binary contains no code path capable of producing `XU4M-NJ40` from any local computation, genuine RouterBOARD hardware licensing for devices purchased through normal channels most plausibly does **not** rely on local SOFTWARE-ID recomputation-and-match at all (unlike x86/CHR) -- it is more likely tied to MikroTik's server-side/online RouterBOARD registration system, with the local `.key`-style text being an export/reflection of an already-server-approved state rather than something reproducible via collision search. This would mean the collision-search method (§1-7) is inapplicable in principle to genuine RouterBOARD hardware licenses, consistent with (and now offering a concrete mechanistic explanation for) §8.36's standalone observation that real RouterBOARD licensing is "a different mechanism." **Not yet done**: tracing the actual online-registration/activation code path to confirm this hypothesis directly -- the user has since disputed this hypothesis without yet-supplied counter-evidence, so it remains open. `0x16ff8`/`0x13808` have since been fully disassembled (§8.72): both are pure local computation (a SHA-256 wrapper and a checksum utility) with zero network-capable PLT references anywhere in their call graph, closing that half of this item without confirming or refuting the server-side hypothesis itself.

**Also confirmed this session, filed for reference:** `tools/bin/` binaries were renamed to a consistent `keyman_{arch}_{version}` scheme (`keyman_x86_7.23.2`, `keyman_x86_7.24.1`, `keyman_arm_7.24.1`), with all path references across `README.md`, `AGENTS.md`, `tools/README.md`, `docs/toolchain.md`, `tools/rust/docs/architecture.md`, and `curve25519.rs` updated to match.

### 8.40 Confirmed discrepancy: `mtsc`'s own SOFTWARE ID computation disagrees with a real x86 `keyman` (RouterOS 6.49.13) at exact byte size `1,117,782,016` (real device, non-standard identity) -- open, unexplained, needs investigation

While tracing a real device's `VI8Q-E90F`/Level-4 signature (issue #1, MurVlad's reflashed x86 machine, `model=QEMU HARDDISK`, `serial=QM00001`, identity `50508089413009661362`, marker `0362`), two different real disk images of the *same physical device* gave conflicting exact byte sizes:

- A partial capture (first 10MB, MBR + partition table only) implied a lower bound of `1,071,645,184` bytes from the last partition's end sector. Building a fresh PVE VM with **exactly this size** and the identity/marker/signature above reproduced `software-id: VI8Q-E90F`, `nlevel: 4`, no `expires-in` -- confirmed genuine, permanent activation, both via `mtsc check` (matches) and real RouterOS 7.24.1 boot.
- A separate, older full-disk backup (Proxmox VMA, RouterOS 6.49.13, `2024-02-21`) of the *same device* extracted to a raw image of exactly `1,117,782,016` bytes (`qemu-img info` confirms QEMU sees this as the exact virtual size, no hidden padding). Booting this raw disk directly (not reconstructed -- the device's own real data) also shows `software-id: VI8Q-E90F`, `nlevel: 4`, no `expires-in` on real RouterOS **6.49.13**.

Both real disks -- different exact byte sizes, same identity/marker/signature -- genuinely activate as `VI8Q-E90F`/Level 4. But `mtsc check` with the *second* disk's exact byte size (`--size 1117782016 --unit b`, same serial/model/identity) computes a **different** SOFTWARE ID (`7SQU-S9AM`), not `VI8Q-E90F`:

```
./target/release/mtsc check --serial QM00001 --size 1117782016 --unit b \
  --model "QEMU HARDDISK" --identity 50508089413009661362
# Software ID: 7SQU-S9AM  (❌ does not match the real device's VI8Q-E90F)
```

This is a **confirmed, reproducible disagreement** between this project's own SOFTWARE ID algorithm and two independent real `keyman` binaries (RouterOS 6.49.13 and 7.24.1), not a measurement or precision error -- both the byte size and the identity/marker/signature bytes were read directly off real disk images, and QEMU independently confirms the exact virtual disk size it presents to the guest. Candidate explanations, **none yet verified**:

- A bug in this project's `round_sectors`/`sector_val` computation specific to this size range (`~1.04 GiB`, `sector_val` around `0x480`).
- A version-dependent difference in the real `keyman` algorithm between RouterOS 6.49.13 and 7.24.1 that happens not to matter for the sizes this project has tested so far (both real-device boots used the *same* signature/identity and both activated, so if there *is* a version difference, it isn't in how `VI8Q-E90F` itself validates -- it would have to be specifically in how `sector_val` is derived from the raw byte count).
- Something about how the VMA-extracted `1,117,782,016`-byte figure relates to the *actual* sector count RouterOS's own `keyman` reads at license-check time that isn't a simple `bytes / 512` (e.g. a reserved trailing region not counted by `keyman` but present in the backup).

**Not yet done:** disassembling the exact `sector_val` derivation path in both `keyman_x86_7.23.2`/`7.24.1` (already partially covered by earlier sections) against a from-scratch trace using this specific byte count, and checking whether RouterOS 6.x's `keyman` (not yet extracted/disassembled by this project) computes `sector_val` identically to 7.x. This is flagged prominently rather than silently worked around, since it means **this project's own algorithm cannot currently be trusted to be correct in this size range** until resolved.

### 8.41 Two reproducible workflows for pulling the embedded EC-KCDSA public key out of a `keyman` binary -- `objdump`/CLI and IDA Free's GUI decompiler, cross-validated against each other on a *patched* `keyman` with a substituted key

Both methods locate the same eight `mov [stack_offset], imm32` instructions found in §8.32 (function `0x804f4c6`, instructions at `0x804f658-0x804f6a2`), read as the public key's 32 bytes in little-endian, 4-byte-at-a-time order. Demonstrated end-to-end against a *different, patched* `keyman` binary (outside this repo, `/Volumes/未命名/Data/tmp/patch-web/keyman`) whose embedded key differs from §8.32's -- confirming both methods agree with each other and correctly distinguish a patched key from the stock one, not just re-deriving the same known-good answer.

**Method A -- `objdump` (CLI, no GUI required, matches §8.32's original process):**

1. `strings -a -t x keyman | grep -i "software key\|BEGIN MIKROTIK"` -- confirms the binary handles the local `.key`-file format, gives anchor string file offsets.
2. `objdump -h keyman` (get `.rodata`'s VMA) + `objdump -p keyman` (get the enclosing `LOAD` segment's `off`/`vaddr`) -- gives the file-offset-to-VMA delta for that segment (`+0x08048000` for this class of ET_EXEC i386 binary).
3. `objdump -d -r keyman > disasm.txt`, then `grep -n "<anchor VMA in hex, no 0x prefix>"` -- finds the `pushl $<addr>`-style references, which pinpoints the enclosing function.
4. Read that function's body: an ARX decode loop, immediately followed by **eight consecutive `movl $imm32, stack_offset(%ebp)` instructions** -- the public key, compiled as immediates rather than a contiguous data blob (why a plain byte-string search of `.rodata`/`.data` never finds it).
5. Concatenate the 8 little-endian dwords in program order to get the 32-byte key.

**Method B -- IDA Free 9.4's GUI + bundled Hex-Rays Cloud Decompiler (F5), no `idat`/`idat64` batch CLI needed (IDA Free doesn't ship one -- that's IDA Pro-only):**

1. Open the binary in IDA, let initial auto-analysis finish (Output window says "The initial autoanalysis has been finished").
2. `Jump!` dialog (the address-jump box) → type the target function address (from Method A, or from a prior analysis of the same binary if addresses are known to match) → Enter, to land in the disassembly graph view.
3. Visually confirm the 8 `mov [ebp+var_XX], imm32h` instructions in the graph node -- IDA already shows them in hex, so no manual decimal-to-hex conversion is needed at this stage.
4. Optionally press `F5` to decompile -- the same 8 constants appear as `v28[0..7] = <decimal>` inside a local array later passed into the scalarmult call (`sub_804DBA2(a1: v28)` in this session's run), which is useful for confirming the constants are actually used as the verification public key (not just coincidentally-placed bytes) and that the surrounding algorithm (XOR-combine, X25519 clamp, final `memcmp`) is unmodified.
5. **To go from the decompiler's decimal values back to the key bytes:** convert each to hex (negative decompiler values are the imm32 read as signed -- add `2^32` before converting, or just read the values from the disassembly view in hex instead of the decompiler's decimal, which sidesteps the conversion entirely), then byte-swap each 4-byte hex value (little-endian storage: `0x49011527` → bytes `27 15 01 49`), then concatenate all 8 byte-swapped groups in program order (`v28[0]`'s bytes first) to get the final 32-byte public key.

**Result on the patched binary (both methods agreed):** `271501494893987A0A50D41DFC7500FFD4F7B32F455F2C0E7C7439D3BD7B0876` -- confirmed different from this project's own `LICENSE_PUBLIC_KEY` (`src/curve25519.rs`) / §8.32's stock key (`8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32`), consistent with this being a `MikroTikPatch`-style binary (§8.32's closing paragraph) where the embedded verification public key was swapped for a self-generated one, so a matching self-held private key can locally sign arbitrary licenses. The `keyman` binary itself only carries the *verification* side (the swapped-in public key); it does not on its own reveal the private key or a signing tool -- that would need to be separately found/analyzed if pursued further.

### 8.42 CHR license payload layout corrected (deadline is one 4-byte field, not "3 unknown + 1"), `/system license print`'s 5 CHR display fields traced to source, `.npk` format decoded, and console-resource field-ID bindings partially confirmed

This session revisited CHR licensing (§8.38) after the user proposed a more granular payload split (`opaqueId(8) + ??(1) + ??(1) + regdate(1) + renewdate(1) + level(1) + 000(3)`). Neither the original §8.38 layout nor the user's proposed split survived direct disassembly -- the correct layout, confirmed by instruction-level tracing, is:

```
offset 0-7    opaqueId    8 bytes (the payload's own copy of the id -- NOT what /system license print's "System ID" shows, see below)
offset 8-11   deadline    4 bytes, little-endian u32 Unix epoch. 0xFFFFFFFF (-1) = permanent, no deadline.
offset 12     level       1 byte
offset 13-15  reserved    3 bytes, expected zero
```

**Deadline is one field, not four.** Function `0x804f718` in `keyman_x86_7.24.1` extracts payload bytes 8-11 as a single dword and payload byte 12 as a separate byte -- there is no code anywhere that reads bytes 8, 9, or 10 individually. The 4-byte dword is compared exactly once, against `time()`, at its sole caller `0x8051b6f` (inside the license-info function `0x8051a9c`-`0x8052188`):
```
8051bb8: cmp edi, -1        ; edi = deadline (payload[8..12] LE). -1 sentinel = permanent, skip the whole block (-> 0x8051c05)
8051bf0: cmp edi, [ebp-0x4a4]   ; deadline vs time() (now)
8051bf6: setb al                ; al = 1 if deadline < now -> "expired"
```
`loskiq/MikroTikPatch`'s `license.py` naming (`varb9`/`varb10`/`varb11`=`"Unknown Value"`, `varb12`="Renew Date"/"Deadline" -- the same byte printed under two different words in that one script) directly supports this: it never treats bytes 8-10 as independently meaningful either, it just doesn't name them as part of one field. The `regdate`/`renewdate`-as-two-fields hypothesis proposed this session has no support in either the disassembly or the external tool's source and should be considered ruled out.

**All 5 fields `/system license print` shows for CHR, traced to their source** (license-info function `0x8051a9c`-`0x8052188`, CHR branch taken when `0x804bfb5()` returns true; the SAME function's other branch, taken when it returns false, handles bare-metal ROS -- see below):

| Displayed field | `nv::message` field id | Source |
|---|---|---|
| System ID | `0xd` (string) | **Locally computed**, not read from the license payload at all. Built by calling `0x804f858` (the SMBIOS-UUID + MBR system-id formula, `docs/reference/chr-system-id-formula.md`) then formatting via `0x804ffcf`. The payload's own `opaqueId(0-7)` bytes are never read in this function -- for a license to be valid its `opaqueId` presumably must match this locally-computed value, but that comparison (if it exists) happens in a separate, earlier validation function not traced here. |
| Level | `0xc` (u32) | Payload byte 12, unconditional copy, no lookup/switch (`0x8051baa`). |
| Deadline at | `0xe` (u32) | `tz_offset + deadline`, inserted only when `deadline != -1` (`0x8051be6`/`0x8051bd9`). |
| Next Renewal At | `0xf` (u32) | **Not a second license field.** It's `tz_offset + [param2+0x66c]`, a locally-computed, self-rescheduling watchdog-timer target time (traced to its write site at `0x8052e19`, inside a function at `0x8052aa2`): armed only in the final 30 days before `deadline` (`deadline - 2592000 < now`, `0x8052d8d`/`0x8052d98`), then fires every ~1-1.5h with `rand()`-jitter (`0x8052ded`-`0x8052dfa`) to re-check renewal/activation state. Displays "when will this machine next attempt an automatic renewal check", not a calendar date parsed from the license. |
| Limited Upgrades | `0x12` (bool) | Not fully confirmed (see console-resource findings below), but the strongest candidate is the ONLY other bool insert in this function: `deadline < now` (the same comparison that drives the expired flag), at `0x8051bfd`. |

**Bare-metal ROS's `level` (`nlevel: N`), for comparison**: same function, other branch (`0x8051c93` onward, not a separate function). Payload byte 7 (offset differs from CHR's byte 12 because bare-metal's payload is `software_id(6)+version(1)+level(1)+reserved(8)`, 8 bytes shorter before the level byte):
```
80520e6: mov dl, [ebp-0x429]   ; payload[7]
80520f1: and edi, 0xf          ; level & 0x0F -- no lookup, plain mask
8052113: call insert<u32_id>   ; message.insert(0x4, level_low_nibble)
```
Field `0x4`, unconditional mask-and-copy, no translation table -- confirms why bare-metal `nlevel` has always simply been the raw byte value (0/1/3/4/5/6) while CHR's `level` needs an actual string ("free"/"p1"/"p10"/"p-unlimited") with no confirmed numeric encoding (see below). The high nibble of the same byte goes to field `0x7`, looks like a reserved-flags nibble, zero on real licenses.

**`.npk` package format decoded** (needed to get more binaries than the standalone `keyman` extracts): magic `1ef1d0ba`, followed by a metadata header (package name, version, arch, description, checksum), then at a fixed file offset of **4096 bytes** a SquashFS 4.0 (xz-compressed) image runs to EOF -- `dd skip=4096 | unsquashfs` extracts it directly, no special tooling needed beyond what's already on macOS/Linux. Used to extract `system.npk` from a RouterOS 7.24.2 install ISO, yielding `nova/bin/{keyman,parser,login,sys2}` and `nova/lib/console/1073741824.mem` (a 2MB console-property resource, mmap'd at fixed VA `0x40000000` -- the filename is that address in decimal). `keyman` from this package is identical in relevant logic to the already-analyzed 7.24.1 build.

**Console-resource field-ID bindings** (`1073741824.mem`): the string "Limited Upgrades" (or any of the other 4 CLI display labels, capitalized-with-spaces) does not exist literally in ANY binary examined (`keyman`, `parser`, `login`, `sys2`) -- confirming they're generated at display time from hyphenated property names (`limited-upgrades` -> "Limited Upgrades") stored in the resource file, not from literal label strings. Recovered the per-property record format directly from the resource file's structure (name string, 0-padded, immediately followed by an 8-byte record: `[4-byte handler ptr][pad][1-byte field_id][0x01 0x00]`):
- **`0x4 <-> nlevel`: confirmed**, name-adjacent (`"nlevel\0\0"` at file offset `0x15a2dc` immediately followed by `field_id=0x04` at `0x15a2e9`).
- **`0xe <-> deadline-at`: confirmed**, same way (`"deadline-at\0"` at `0x15a3d4` immediately followed by `field_id=0x0e`).
- **`0xc <-> level`**: NOT name-confirmed -- no standalone `"level\0"` string exists anywhere in the 2MB file (only `nlevel` and unrelated MPLS `lsp-id`-adjacent false positives). `0xc` sits inside a tight, name-less run of records (`0xd,0xc,0x12,0xf`) immediately preceding the confirmed `deadline-at`/`0xe` record -- positionally it's exactly where a CHR `level` property should be, but this is circumstantial, not proven. It's possible CHR's level has no console property name at all (internal-only field).
- **`0x12 <-> limited-upgrades`**: circumstantial only. `0x12`'s handler pointer (`0x081019a0`) differs from the shared pointer (`0x08101c64`) used by the other integer/timestamp fields in the same cluster, consistent with a boolean-type getter -- but the `"limited-upgrades"` name string itself sits far away (file offset `0x16777`), with no name-adjacency evidence tying the two together.
- Closing this fully would require disassembling `parser`'s (or `login`'s) actual resource-file-parsing code to recover the authoritative record schema, rather than inferring it positionally -- not done this session, flagged as the natural next step if this thread is picked up again.

**Level byte -> CHR tier name (`free`/`p1`/`p10`/`p-unlimited`) mapping: still not found.** MikroTik's own official docs (manual.mikrotik.com, help.mikrotik.com) confirm CHR shows `level` as a string only, explicitly stating the bare-metal numeric `nlevel` scheme does not apply to CHR. A candidate 3-entry enum table exists in the resource file at offset `0x1d1094` (`0->p-unlimited`, `1->p1`, `2->p10`) but its only back-reference sits next to an unrelated renewal-timing (`immediate`/`after-1min`/`after-1h`) cluster, not next to anything level-related -- not bound to the `level` field, treat as unconfirmed/likely a different enum that happens to reuse those tier-name strings for some other purpose (e.g. a purchase/upgrade-prompt UI element). No external source (official docs, forum posts, the `loskiq/MikroTikPatch` tool) states a numeric byte value for any CHR tier either.

**Files**: this session's disassembly reused `backup/bin/analysis/x86_chr/keyman_x86_7.24.1.disasm.txt`; new extraction artifacts live outside the repo under `/tmp/mikrotik-7.24.2-extracted/` (not committed, scratch only -- re-derivable from a RouterOS install ISO via the `.npk` procedure above if needed again).

**Level value summary (ROS vs CHR), following directly from the above:**

- **Bare-metal ROS `nlevel`**: numeric, `{0, 1, 3, 4, 5, 6}` (2 does not exist) -- well-documented externally, and confirmed above as a direct, untranslated byte read (`payload[7] & 0x0F`, field `0x4`, no lookup table).
- **CHR `level`**: string-only in every source checked (MikroTik's own official docs never show a numeric alongside it, and explicitly state CHR does not use the `nlevel` numeric scheme) -- 4 known tier names: `free`, `p1`, `p10`, `p-unlimited`. The underlying payload byte (offset 12, field `0xc`) is confirmed to exist and be read by `keyman`, but **its byte-value-to-tier-name mapping is not confirmed by any evidence found this session** -- the one candidate 3-entry enum table in the console resource file (`0->p-unlimited`, `1->p1`, `2->p10`, no `free` entry) could not be bound to the `level` field (see above; its only back-reference sits next to an unrelated renewal-timing cluster). Treat as an open item, not a confirmed mapping.

### 8.43 `parser`'s console-resource loading mechanism confirmed real and deliberate (fixed-address `mmap` keyed by filename, self-validating header) -- but the record-dispatch/name-lookup layer itself not yet reached

Continuing §8.42's last open item (binding field ids `0xc`/`0x12` to console property names `level`/`limited-upgrades` via the resource file's real parsing code, rather than positional inference).

**Confirmed directly from `nova/bin/parser`'s disassembly** (not inferred): `main()` (`0x80d6c58`+) calls `nv::getAllDirs("/nova/lib/console", true)`, `opendir`/`readdir`-loops the results, filters entries by a `.mem` suffix (`strcmp`, `0x80d6d92`-`0x80d6da1`), and converts each entry's numeric filename prefix via `strtoul` (`0x80d6d7f`) into a `u32` used as a literal target address. A loader function at `0x807a57e` then does, per file: `open()` -> `fstat()` -> `mmap(addr=<that number>, length=st_size, PROT_READ, MAP_SHARED|MAP_FIXED, fd, 0)`, with a hard `cmp`-and-presumably-abort check (`0x807a5fd`) that the kernel actually honored the fixed address. This is airtight proof that `1073741824.mem`'s filename **is** the literal virtual address it gets mapped to (`0x40000000`) -- not a naming convention someone guessed at.

**New structural finding**: immediately after a successful mmap, `main()` reads `dword[base+0]` and compares it against a process-global "root" pointer (`0x81066d0`) -- the first-loaded resource file establishes the root, later ones must match or `parser` prints a `"warning, <addr>: <val> != root: <val2>"` diagnostic (`0x80d6ec5`-`0x80d6f1a`). On match, `dword[base+0x1c]` gets pushed into a second global (`0x81066c8`) via a generic vector-push helper (`0x80b0d96`, confirmed reused verbatim elsewhere, so not license-specific). This proves the resource file begins with a real, structured header (offset 0 = root-link, offset +0x1c = a second registered table/pointer) rather than records starting immediately at offset 0 -- consistent with there being an authoritative schema, though this particular header field wasn't traced to being the record table itself.

**Not reached**: `0x81066c8`'s only reads found in `parser` are its own two write sites -- no consumer of it was located, meaning the actual per-record name-lookup/field-id-dispatch logic is reached through further indirection (most plausibly: each record's own handler function pointer, called on demand rather than walked linearly at load time) that wasn't traced this session. `parser`'s full disassembly (~247k lines, saved at `/tmp/parser.disasm` on the working machine, not in-repo) would need deeper tracing of what consumes each record's handler-pointer field to close this. `login` was checked and does not independently implement this logic (no reference to `/nova/lib/console/<addr>.mem` beyond static logo text files) -- all of it lives in `parser`.

**Net effect on §8.42's open items**: `0x4<->nlevel` and `0xe<->deadline-at` remain the only two name-confirmed bindings. `0xc<->level` and `0x12<->limited-upgrades` remain circumstantial/positional only. The mechanism underlying the resource file is now known to be a real, deliberately-designed structure (not an artifact of positional coincidence), which increases confidence that SOME authoritative binding exists to find -- but closing it requires tracing the handler-pointer dispatch layer, not yet done.

### 8.44 Exhaustive byte-diff of a `MikroTikPatch`-style `keyman` against its real stock base (`7.24.1`, not `7.23.2`) finds a second, undocumented change beyond the substituted public key: the online license-server hostname is also redirected to a look-alike domain

Following up on §8.41's public-key extraction from an externally-supplied, already-patched `keyman` binary (outside this repo). That binary is exactly the same file size as this project's own `backup/bin/keyman_x86_7.24.1` reference (55,444 bytes) -- a byte-for-byte `cmp -l` against that reference (not the smaller `7.23.2`, which is a different build and diffs everywhere) found **only 35 differing bytes in the entire file**, in two disjoint clusters:

- **32 bytes at file offset `0x765e-0x76a1`**: the 8 embedded public-key dwords already documented in §8.41 (`271501494893987A0A50D41DFC7500FFD4F7B32F455F2C0E7C7439D3BD7B0876`).
- **3 bytes at file offset `0xc2fa-0xc2fc`**: the string `licence.mikrotik.com` (stock) changed to `licence.mikrotik.ltd` (patched) -- same length, same surrounding bytes, only the `com`/`ltd` TLD differs. This string sits immediately after an embedded `Content-Type: application/x-www-form-urlencoded\r\n` string, and the binary links `nv::HTTPFetch::post`/`nv::HTTPFetch::appendVar` (a MikroTik-internal HTTP client used for the online license activation/renewal flow already traced in §8.26/§8.27/§8.32).

**Practical implication**: this patched binary isn't only a "verify against a self-controlled key" modification -- if its online-activation code path ever runs, it POSTs form-encoded data (plausibly including hardware-identity/SOFTWARE-ID fields, matching that call chain's known purpose) to `licence.mikrotik.ltd`, a domain not controlled by MikroTik, rather than to the real `licence.mikrotik.com`. This project did not resolve, contact, or otherwise investigate that domain -- the finding is limited to "the hostname embedded in the binary was silently swapped for a look-alike," which is sufficient on its own to treat this specific artifact as untrustworthy for any network-connected use, independent of the licensing question.

**Filesystem/behavior scope, confirmed unchanged from stock by the same exhaustive diff** (i.e. every path below is byte-identical between the stock `7.24.1` and the patched binary -- the patch touches nothing here):

```
/dev/flash                              hardware-identity read (§8.24-§8.31, §8.39)
/dev/urandom                            PRNG seed only, see below
/dev/nvme%d, /dev/xvda, /dev/root-disk  disk-device probing (feeds SOFTWARE ID)
/nova/etc/license
/nova/etc/serial
/var/pckg/%s.key                        package license files
/sys/class/dmi/id/product_uuid
/proc/scsi/usb-storage/%u
```

**`/dev/flash` read detail**: `open("/dev/flash", ...)` followed by one of several `ioctl` calls depending on call site (`0x4601`, `0x80044604`, `0x462b`, confirmed in §8.24/§8.39) -- reads up to 512 bytes of the real RouterBOARD's own board-level identity/serial data out of flash, feeding into the `getHardwareID`/SOFTWARE-ID derivation chain. Meaningful only on real hardware; under QEMU/KVM this path is typically absent or behaves differently (§8.15-§8.18 traces the virtualized fallback).

**`/dev/urandom` read detail, traced this session** (x86, `0x804fdf0-0x804fe4f`, present identically in the *unmodified* stock `7.24.1` -- not part of the patch's 35-byte diff): `open("/dev/urandom", O_RDONLY)` -> `read(fd, buf, 4)` (exactly 4 bytes) -> `close(fd)` -> `gettimeofday(&tv, NULL)` -> `srand(<those 4 bytes> + tv.tv_sec)` -> `rand()`. This is a standard C-library `srand()`/`rand()` seed (4 real-random bytes mixed with the current timestamp), not a cryptographic operation -- consistent with this binary being verify-only (signing would need real entropy; this doesn't sign anything). Plausibly seeds a nonce/request-id used somewhere in the `HTTPFetch` POST flow (§8.44's `licence.mikrotik.ltd` finding), but the consumer of this specific `rand()` value was not traced.

No added/removed imports, no new file paths, no additional code -- the patch is exactly two surgical, same-length byte substitutions (public key, then hostname) inside an otherwise-untouched stock `7.24.1` binary. This is not itself evidence of what `licence.mikrotik.ltd` does when contacted (not tested), only that the substitution exists and is deliberate (matching length, no other bytes disturbed).

### 8.45 `/dev/flash`'s real-hardware read path in x86 `keyman` traced one level deeper -- corrects §8.44's "`ioctl 0x4601` reads up to 512 bytes" to "`0x4601` is a probe, `0x90004602` is the actual data read", and surfaces an unexplained `fopen(path, "--mbr")` fallback call

Continuing §8.44's file-access inventory with a deeper trace of the readMBR-equivalent function (x86, entry `0x8051200`, called from 15+ sites throughout `keyman` -- not yet all enumerated). This corrects an imprecision in this session's own earlier summary of `ioctl 0x4601`.

**Confirmed structure, real-hardware branch** (taken when the `board`-contains-`"qemu"` predicate at `0x804f902` is false -- the QEMU-true branch instead reads from a cached message-bus object via `0x80501bd`, per the existing §5/§8.15-§8.18 flow, and never touches `/dev/flash` at all):

```
fd = open("/dev/flash", O_RDONLY, 0)          ; 0x80540b9 = "/dev/flash"
rc = ioctl(fd, 0x4601, NULL)                  ; third arg is NULL, not a buffer --
                                               ; this is a probe/status call, not a data read
if (0x100 <= rc <= 0x4000):                   ; range-checked via (rc - 0x100) <= 0x3f00
    close(fd)
    buf_len = (rc + 0xf) & ~0xf               ; round up to 16 bytes, alloca'd on stack
    ioctl(fd, 0x90004602, stack_buf)          ; *** this is the actual data-fetching call ***
    n = min(returned_size, 0x200)             ; clamped to 512 bytes
    memcpy(caller_buf, stack_buf, n)          ; rep movsb into the caller-supplied buffer
else:
    fh = fopen(path_arg, "--mbr")             ; path_arg is the function's own first parameter,
                                               ; NOT the literal "/dev/flash" -- and the second
                                               ; argument really is the literal string "--mbr",
                                               ; not a real fopen() mode ("r"/"rb"/etc)
    fread(caller_buf, 512, 1, fh)
    fclose(fh)
```

**Correction to §8.44's phrasing**: that section said `ioctl(fd, 0x4601, buf)` "reads up to 512 bytes... into a caller-supplied buffer." That conflated two separate calls. `0x4601`'s third argument is `NULL` -- it cannot be reading into anything. The actual 512-byte(-clamped) read happens via the *second* ioctl, `0x90004602`, called only after `0x4601` succeeds and returns a value in `[0x100, 0x4000]`.

**Not yet explained**: the `fopen(path, "--mbr")` fallback. `fopen`'s second parameter is conventionally a mode string (`"r"`, `"rb"`, ...); `"--mbr"` is not a valid mode and looks instead like a CLI flag. Two explanations, neither confirmed:
1. This binary's linked `fopen` is genuinely glibc's `fopen`, and passing `"--mbr"` as the mode is either a latent bug in MikroTik's own code (glibc's `fopen` would likely just fail to parse recognized mode characters and behave unpredictably, e.g. defaulting to read-only) that happens not to matter because this branch is rarely/never reached on real hardware.
2. `open@plt`'s and `fopen@plt`'s underlying implementations for this binary are not plain glibc (the binary is dynamically linked against `/lib/libc.so`, per `file`'s `interpreter` field, but no evidence was gathered this session on whether that's glibc or an embedded/custom libc) -- if this platform's `fopen`-equivalent has different call semantics (e.g. mode selects a data source variant, similar in spirit to `getHardwareID`'s several source paths already documented), `"--mbr"` would make more sense as a genuine argument. Not investigated further this session.

### 8.46 Full inventory of hardware/system data sources `keyman` reads, beyond the already-documented SMBIOS UUID and disk ATA IDENTIFY -- confirms NVMe and USB-storage equivalents of the disk path, and a `/dev/flash`+`/dev/mtdblockN` fallback for flash-only boards

Prompted by the question "does `keyman` read anything else -- other UUID sources, CPU/hardware info, flash files, other MBR offsets, env/proc/sys?" Investigated via `strings -a -t x` on `keyman_x86_7.24.1` to find candidate path/string references, then `r2`'s `axt <addr>` to cross-reference each string to its caller, then manual disassembly reading of each caller. ARM (`keyman_arm_7.24.1`) was checked only at the `strings` level (same strings present) -- not independently re-disassembled function-by-function this session.

**UUID sources**: no new ones found. Only `/sys/class/dmi/id/product_uuid` (already documented, §8.9/§8.10-area and `docs/reference/chr-system-id-formula.md`) -- confirmed via disassembly at `fcn.0804f858`, read via `fopen`+`fscanf`. No `/etc/machine-id`, `board_serial`, `chassis_asset_tag`, `bios_vendor`, or other DMI files referenced anywhere in the string table.

**CPU/hardware info**: no `/proc/cpuinfo`, no CPUID references, no MAC-address strings anywhere in the binary. One relevant symbol found: `getBoardSerialNumber()` is an **imported, dynamically-linked** function (PLT stub, called once from `main` at call site `0x08052002`) -- its implementation lives outside `keyman` (presumably RouterOS's board-support library) and was not traced further.

**Flash storage** (new, confirmed via disassembly): `/dev/flash` (string `0x080540b9`) is opened directly with custom (non-MTD) ioctls in several functions, used as an **alternate identity/MBR source on flash-only devices that have no real disk** -- this is the same `/dev/flash` path detailed in §8.44/§8.45, but this pass additionally confirmed the *selection logic*:
- `fcn.0804e479` resolves the real block device via `readlink("/dev/root-disk", buf, 127)`; if that fails and `stat("/flash")` succeeds, it falls back to `snprintf("/dev/mtdblock%u", ...)` (string `0x08054019`) -- i.e. CHR/embedded images with no root-disk symlink are addressed via `/dev/mtdblockN` rather than a raw `/dev/mtd*` character device.
- Two `getenv("board")` checks gate which path is taken: `fcn.0804f902` does `strstr(result, "qemu")` (drives the QEMU-vs-real-hardware branch already known from §8.45); `fcn.08050e01` separately checks whether the first character of `board` is `'7'`, distinguishing RouterBOARD-7xx-series-style boards (flash-only, no disk controller) from others.

**Other disk-bus equivalents of ATA IDENTIFY** (new, confirmed via disassembly):
- **NVMe**: `fcn.0804fac1` (called from `fcn.080502b6`) opens `/dev/nvme%dn%d` (parsed via `sscanf` on the resolved block device's basename) and issues `NVME_IOCTL_ADMIN_CMD` (`0xc0484e41`, opcode `0x06` = Identify Controller) to extract model/serial -- the NVMe-bus counterpart of the already-documented ATA IDENTIFY source. Confirms the disk-identity formula's inputs are bus-agnostic by design, not ATA-specific.
- **USB installation media**: in `fcn.08050e01`, `ioctl(fd, 0x5386, ...)` on the resolved device is `SCSI_IOCTL_GET_BUS_NUMBER` -- **corrected in §8.49: it is taken on SUCCESS, not failure**, using the returned `host_no` directly as the exact `%u` in a single `snprintf("/proc/scsi/usb-storage/%u", host_no)` + one `fopen()` (no retry/scan loop). The `/dev/xvda` (Xen virtual disk) `strcmp` is a separate branch leading to the same kind of fallback-success path, not into the usb-storage read itself. See §8.49 for the full mechanism (why this file exists, what populates it, and an open question about whether RouterOS x86 actually ships a live `usb-storage`/legacy-`/proc/scsi` stack).
- No MBR offsets beyond the already-documented `0x100`-`0x10F` license region were found referenced by any of the traced functions.

**env / proc / sys**: only `getenv("board")` is read (two call sites, described above). No `/proc/cmdline` and no other `/proc`/`/sys` files beyond `product_uuid` and the two disk/flash paths above.

**Not yet traced**: `getBoardSerialNumber()`'s internal implementation (outside this binary); independent per-function disassembly confirmation on ARM (string-level match only).

### 8.47 `keyman` performs zero range/validity enforcement on the license-level nibble (0-15 all reachable and displayed as-is); no numeric-to-tier-name table exists inside the binary for either bare-metal or CHR

Prompted by the question "the level nibble can hold 0-15 -- which values does `keyman` actually use?" Investigated via the pre-existing `keyman_x86_7.24.1.disasm.txt`, spot-checked against a fresh `objdump -d -M intel` of `keyman_x86_7.23.2` (same instructions at equivalent addresses -- not a 7.24.1-only artifact). ARM (`keyman_arm_7.24.1.annotated.asm`) was grepped for the equivalent mask/compare pair but the matching function could not be located in the time available -- **not independently re-confirmed on ARM this session**, though §8.42 already established the bare-metal/CHR branches converge on shared logic.

**No range check exists.** The shared license-info function (`0x8051a9c`-`0x8052188`, §8.42) extracts the level nibble with a bare mask and stores it unconditionally:

```
80520e6: mov dl, [ebp-0x429]     ; payload byte 7 (bare-metal) / byte 12 region (CHR)
80520ed: mov edi, edx
80520f1: and edi, 0xf            ; edi = level, 0-15, no clamp, no cmp-against-max anywhere
8052113: call nv::message::insert(field 0x4, edi)   ; unconditional -- every one of the 16
                                                     ; possible values gets stored and displayed
```

**No value -> name table exists inside `keyman`.** Confirmed two ways: (1) `keyman`'s own string table contains `free` but not `p1`/`p10`/`p-unlimited` -- consistent with §8.42/§8.43's finding that those three names live only in the separate `1073741824.mem` console-resource file, whose binding to field id `0xc` (`level`) remains circumstantial, not proven. (2) The only genuine (non-PLT) jump table in the whole binary, at `0x80531e8`, dispatches on an unrelated config-property command id (bounds-checked `cmp esi,5/ja`), not on the level value -- there is no switch/array-index construct anywhere that keys off the level nibble.

**The only branches on the level value are behavioral, not validating**, and treat every value >1 identically:
```
8052132: cmp edi, 0x1
8052135: ja 0x8052231     ; level > 1: inserts one extra field (0x9, from the next payload byte)
                          ; -- 2 and 15 take the exact same branch, no distinction
8052143: test edi, edi
         je ...           ; level == 0: computes a separate, randomized "uptime-derived" field
                          ; (0x6) instead -- looks demo/trial-jitter related, unrelated to naming
```

So functionally `keyman` recognizes 3 *behavioral* buckets (`0`, `1`, `>1`), not a validated enumeration -- every nibble value 0-15 is mechanically reachable and rendered as-is. **The observed real-world set `{0,1,3,4,5,6}` (2 never issued, per `keys.toml`'s corpus) is a property of what MikroTik's signing infrastructure actually signs, not something `keyman`'s disassembly enforces.** Bare-metal and CHR share this exact code path -- the only structural difference (already documented in §8.42) is which payload byte offset feeds into it (7 vs 12), not the validation logic, because there isn't any.

**Not yet resolved**: the CHR numeric level -> tier-name (`free`/`p1`/`p10`/`p-unlimited`) mapping still has no confirmed source anywhere (not in `keyman`, and only circumstantially in the `parser` console-resource file per §8.42/§8.43).

### 8.48 `getBoardSerialNumber()` traced to `libumsg.so` -- an independent `/dev/flash` ioctl primitive, distinct from both `getBoardType()` (§8.29) and `keyman`'s own flash-reading code (§8.44/§8.45); confirmed used by four binaries, not license-specific

Continuing §8.46's "not yet traced" item: `keyman` imports `_Z20getBoardSerialNumberv` (`getBoardSerialNumber()`) from `libumsg.so` rather than implementing it itself. Located the exporting library at `/lib/libumsg.so` in the extracted `routeros-7.24.2.npk` system SquashFS (`nm -D | grep getBoardSerialNumber`), then disassembled the symbol directly (x86 32-bit build, symbol at `0x4d91f`-`0x4d9a8`; PIC base resolved via the `call get_pc_thunk_bx; add ebx,<const>` idiom, GOT base `0x7f000`).

**What it reads**: opens **`/dev/flash`** (string `0x6fde6`) with `O_RDWR` -- *not* `/dev/rb`, which is the entirely separate device `getBoardType()` (§8.29) opens (`0x6fdb5`, confirmed in the same disassembly dump).

```
0x4d933: lea eax, [ebx-0xf21a]      ; -> "/dev/flash"
0x4d939: push 0x2                  ; O_RDWR
0x4d93c: call open@plt
0x4d944: cmp eax, -1
0x4d947: jne 0x4d963               ; success -> proceed to ioctl
                                    ; failure -> perror("open"); return empty string
```

**Call chain**: does *not* call `getBoardType()` or `readHcfgField()` -- issues its own dedicated ioctl directly. `/dev/flash` is confirmed to be a shared misc character device backing multiple distinct ioctl "commands" all under Linux ioctl type byte `0x46` (`'F'`):
- `getBoardSerialNumber`: `ioctl(fd, 0x80104608, buf)` = `_IOR('F', 0x08, ...)` (read-only, nr `0x08`)
- `readHcfgField` (`_Z13readHcfgFieldiPvjb`, `0x4d9ab`, a separate exported function in the same library that also opens `/dev/flash` via the identical string reference): `ioctl(fd, 0xc0044626, ...)` = `_IOWR('F', 0x26, ...)` -- a generic "read hardware-config field by key" accessor
- For contrast, `getBoardType()` (§8.29) uses the unrelated device `/dev/rb` and `ioctl 0x520f` = `_IO('R', 0x0f)` (no data direction) -- confirms these are two structurally independent hardware-identity primitives in the same library, not layers of the same call.

**Format/transform**: on success, zeroes a 32-byte stack buffer, passes its address as the ioctl output buffer, and after `close(fd)` builds the return value via `std::string::string(const char*)` on that buffer -- i.e. the raw ioctl output is treated as a **NUL-terminated ASCII C-string and copied verbatim**. No BCD decode, no checksum/mixing, no numeric reformatting.

**Fallback**: if `open("/dev/flash", O_RDWR)` fails (e.g. no such device under QEMU/CHR), calls `perror("open")` (message string literally `"open"`, `0x6fdf1` -- `perror` appends `": <strerror>"` itself) and returns the **default-constructed (empty) string `""`**, without attempting any ioctl.

**Other callers** (`grep -rla getBoardSerialNumber` across the whole extracted filesystem, `nm -D` confirms undefined/imported symbol in each): `/nova/bin/keyman` (already known, §8.46), `/nova/bin/figman`, `/nova/bin/moduler`, `/bndl/wifi/nova/bin/ww2` (wifi driver bundle) -- confirms this is a **general board-identity primitive** shared across licensing, module management, and the wifi subsystem, not something `keyman`-specific. Call-site purpose inside `figman`/`moduler`/`ww2` was not traced (import confirmed only).

**Not yet done**: the exact byte layout the `0x80104608` ioctl fills within the 32-byte buffer beyond "a NUL-terminated ASCII string somewhere in it" was not reverse-engineered field-by-field; the kernel module backing `/dev/flash`'s ioctl type `0x46`/nr `0x08` was not located this session (a reasonable next step, analogous to how §8.31 located `flash.ko` for `/dev/rb`'s `"MetaROUTER"` string).

### 8.49 How `/proc/scsi/usb-storage/<N>` (§8.46's USB-install fallback) actually comes into existence -- standard Linux legacy-SCSI-proc mechanism, not RouterOS-specific; also corrects §8.46's branch direction and confirms `keyman` never scans/guesses `<N>`

Follow-up to §8.46's USB-storage fallback item. Points 1-3 below are general mainline Linux kernel behavior (not something reverse-engineered from RouterOS -- stated directly), point 4 is RouterOS-specific verification, point 5 is a correction to §8.46 from direct re-disassembly.

**Mechanism (general Linux)**: `/proc/scsi/usb-storage/<host_no>` is an instance of the legacy `/proc/scsi/<driver_name>/<host_no>` convention (`drivers/scsi/scsi_proc.c`, gated by `CONFIG_SCSI_PROC_FS`). Every SCSI host adapter -- real or virtual -- that calls `scsi_add_host()` gets a `Scsi_Host` struct with a `host_no` assigned in registration order; `scsi_add_host()` internally creates the corresponding `/proc/scsi/<proc_name>/<host_no>` entry. `usb-storage` (`drivers/usb/storage/usb.c`) presents each bound USB mass-storage device as a synthetic SCSI host adapter, which is why USB flash drives enumerate as `/dev/sdX` and get one of these entries. The bind is triggered by USB enumeration matching the device's Mass Storage class interface (`bInterfaceClass=0x08`) against `usb-storage`'s device-ID table -- nothing pre-creates the file at boot; it exists only while a matching device is attached. Its contents (vendor/product/serial) come straight from the USB device's own descriptors (`idVendor`/`idProduct`/`iSerialNumber`), populated by the kernel driver -- not computed by `keyman`.

**RouterOS-specific check**: searched the extracted x86 `routeros-system.squashfs` (kernel `5.6.3-64`). **No `usb-storage.ko` and no SCSI modules at all** (`sd_mod`/`sr_mod`/`scsi_mod`) exist as `.ko` files under `/lib/modules/5.6.3-64/`, and `modules.builtin` is empty/absent so module-vs-builtin status couldn't be confirmed from metadata; a raw `strings` scan of the compressed EFI boot image for `"usb-storage"`/`"/proc/scsi"` came back empty but is inconclusive (compressed image, not decompressed). **Open question, not resolved**: no direct evidence either way that RouterOS x86's running kernel actually ships a live `usb-storage`/legacy-`/proc/scsi` stack -- the absence of any `.ko` for the whole SCSI layer is more consistent with "compiled statically into the kernel" than "feature dropped," but this is not proven.

**Correction to §8.46**: re-disassembled `fcn.08050e01` directly against `keyman_x86_7.24.1` (string `/proc/scsi/usb-storage/%u` at `0x08054142`; not covered by the pre-existing `.disasm.txt` dump, so this required a fresh `r2` pass). §8.46 said the `/proc/scsi/usb-storage/%u` path is taken "if `ioctl(fd, 0x5386, ...)` ... fails" -- **this had the branch direction backwards**. `0x5386` is `SCSI_IOCTL_GET_BUS_NUMBER`, and the code takes the usb-storage path when this ioctl **succeeds**, using the returned `host_no` directly:

```
ioctl(fd, 0x5386, &var_504h)      ; SCSI_IOCTL_GET_BUS_NUMBER
if rc == 0:
    snprintf(buf, "/proc/scsi/usb-storage/%u", var_504h)   ; exact host_no, once
    fopen(buf, ...)                                         ; single attempt, no retry/scan loop
else:
    -> falls into the shared fallback-identity cleanup path
```

The `/dev/xvda` (Xen virtual disk) `strcmp` check is a separate branch leading to the same kind of fallback-success path -- it does not feed into the usb-storage read. Practical upshot: `keyman` never has to guess or iterate over candidate `<N>` values -- it asks the kernel for the exact SCSI host number directly and reads that one path once.

### 8.50 Kernel module backing `/dev/flash`'s `0x80104608` ioctl located and confirmed at instruction level: `flash.ko` (ARM64/RouterBOARD builds only) -- x86/CHR has no such driver, `/dev/flash` there is userspace-only; also corrects §8.31's passing assumption that `/dev/rb` might live inside `flash.ko`

Resolves §8.48's "not yet done" item. Extracted `routeros-7.24.2-arm64.npk`'s embedded squashfs (found via the `hsqs` magic at file offset `4096`, per §8.42's already-documented `.npk` format) from `/Volumes/未命名/Data/tmp/ros/backup/mikrotik-7.24.2-extracted/mikrotik-7.24.2-arm64.iso`, yielding `flash.ko` at `/lib/modules/5.6.3/misc/flash.ko` (ARM aarch64, not stripped) -- the same path §8.31 previously described from a since-removed mount, now independently re-extracted and confirmed.

**Confirmed at instruction level that this module handles exactly `0x80104608`** (`libumsg.so`'s `getBoardSerialNumber()` ioctl, §8.48). `nm` shows an exported `flash_ioctl` function containing a binary-search-style dispatch over ioctl command values; traced the exact constant-construction chain leading to the matching case:

```
34dc: mov  w0, #0x463a
34e0: movk w0, #0x8010, lsl #16    ; w0 = 0x8010463a
34f0: sub  w0, w0, #0xa            ; w0 = 0x80104630
3500: sub  w0, w0, #0x28           ; w0 = 0x80104608
3504: cmp  w20, w0
3508: b.eq 0x371c                  ; case handler at flash_ioctl+0x304
```

`strings` additionally confirms the device-registration name `flash` and adjacent exported symbols (`copy_from_flash`, `has_flash_driver`, `flash_get_uid`, `flash_erase`, `flash_driver_ok`, `flash_cmd`) plus a `misc_register` call at `init_module+0x118`, matching §8.31's description of this module unconditionally registering itself at init.

**x86/CHR has no equivalent kernel driver.** Enumerated all 298 `.ko` files in the x86 build (`system-squashfs-extracted/lib/modules/5.6.3-64/`) -- none are flash-related. Decompressed that build's kernel image (xz payload inside `mnt-x86/isolinux/linux`) and confirmed the `/dev/flash` string found there belongs to the RouterOS **installer/setup** userspace program's `.rodata` (adjacent to `"Welcome to MikroTik Router Software installation"`, `"readMBR: could not open %s"`), not a driver registration message. So on x86/CHR, `/dev/flash` access is purely userspace (`libumsg.so`/`keyman`/the installer) -- there is no real flash hardware to back a kernel driver, consistent with §8.15-§8.18.

**Correction to §8.31**: that section's phrasing left open whether `/dev/rb` provisioning might live inside `flash.ko` itself. Confirmed it does not -- `/dev/rb` is backed by a separate module, `rb.ko`, sitting alongside `flash.ko` and `flash-uefi.ko` in the same `misc/` directory. Three distinct misc-device modules, not one multiplexed driver.

### 8.51 How `keyman` parses `/proc/scsi/usb-storage/<N>` after `fopen()` (§8.49's follow-up): `fgets`+`sscanf` on `VendorID:`/`ProductID:`/`Serial Number:` lines -- not the vanilla kernel's `Vendor:`/`Product:` name fields -- plus a silent fallback that degrades to zeroed identity data rather than erroring

Continuing §8.49: traced `fcn.08050e01` (`keyman_x86_7.24.1`, `0x080510aa`-`0x0805118d`) past the point where `fopen("/proc/scsi/usb-storage/%u", "r")` succeeds.

**Parsing mechanism**: a `fgets`+`sscanf` loop, not one combined `fscanf` on the stream:
```
0x080510c6: fgets(line_buf, 0x80, fp)             ; up to 128 bytes/line
0x080510e0: sscanf(line_buf, "Serial Number: %80s", &var_210h)
0x080510f9: sscanf(line_buf, " VendorID: %x",       &var_218h)
0x0805110c: sscanf(line_buf, " ProductID: %x",      &var_21ch)
```
Each `sscanf`'s return value (`dec eax; je 0x80510b8`) gates whether to loop back for the next line immediately or fall through to try the remaining format(s) against the same line. Loop exits when `fgets` hits EOF (`0x080510d0` -> `0x08051129`).

**Discrepancy vs. vanilla mainline kernel text -- now confirmed real, not just recalled.** A real captured `cat /proc/scsi/usb-storage/1` (Alpine Linux, standard kernel `usb-storage` driver, screenshot supplied by the user) reads:

```
   Host scsi1: usb-storage
       Vendor: RouterOS-SCSI
      Product: RouterOS-SCSI
Serial Number: 00000000000002142239
     Protocol: Transparent SCSI
    Transport: Bulk
       Quirks:
```

This is exactly the classic `Vendor:`/`Product:`/`Serial Number:` name-string format -- **no `VendorID:`/`ProductID:` hex lines exist anywhere in real `usb-storage` output**. This confirms (not just "recalled from kernel-source knowledge") that `keyman`'s `" VendorID: %x"` / `" ProductID: %x"` sscanf patterns can never match on any standard Linux kernel's `usb-storage` proc output -- only the `"Serial Number: %80s"` pattern ever succeeds. **Consequence for §8.51's post-extraction step**: on real hardware/VMs, `var_218h` (vendor) and `var_21ch` (product) are left as whatever uninitialized stack garbage was already sitting in those slots when the function's prologue ran -- they are never legitimately populated from `/proc`, yet the code unconditionally folds them into the same XOR-mix/`fcn.0804ca66` identity step as `serial`. Only `serial` is genuinely `/proc`-derived; `vendor`/`product` are effectively noise inputs to the identity formula on this path. Whether RouterOS's own kernel differs from this Alpine Linux capture wasn't separately verified, but there is now no plausible mainstream `usb-storage` implementation that would emit `VendorID:`/`ProductID:` hex lines, so this is treated as settled rather than an open discrepancy.

(A second, unrelated string `"Serial Number: %19s"` at `0x0805415c` exists elsewhere in the binary but is not referenced by this function -- belongs to the already-documented ATA-IDENTIFY serial path, not this one.)

**Post-extraction transformation**: `Serial Number` is captured via `%80s` (whitespace-delimited by `sscanf` itself, no separate trim call); `VendorID`/`ProductID` are captured directly as 4-byte integers via `%x` (no string handling). After the loop, execution unconditionally falls into `0x08051129`: `close(fp)`, zero-fills a 6-byte field, then a 20-byte XOR-mixing loop (`0x0805114d`-`0x0805115f`) folds the captured fields together, followed by a call to `fcn.0804ca66` (`edx=0x5e`) -- likely the same kind of "identity mixing" step already documented for the ATA-IDENTIFY path, but `fcn.0804ca66`'s exact semantics and buffer layout were **not** re-derived this session (out of scope; would need a dedicated follow-up).

**Fallback/error handling**: none, explicitly. There is no "label not found" error path -- a line that matches none of the three formats just falls through to loop for the next line, and reaching EOF (or `fopen` failing per §8.46/§8.49) leads unconditionally to the same cleanup/mixing code using whatever partial (possibly all-zero, if nothing matched) data happened to land in the three capture variables. No error message, no early exit -- a corrupted or differently-formatted `/proc` file silently degrades to zeroed/garbage identity input rather than aborting.

### 8.52 `/system license print`'s `features` field resolved: it is the HIGH nibble of the same license-level byte already documented for `nlevel` (§8.42/§8.47), not a separate payload field -- plus one layer deeper into `parser`'s handler-pointer indirection for `level`'s still-unresolved string mapping

Prompted by a deep-dive request into `/system license print`'s `features` and `level` fields specifically. Used the extracted `keyman_x86_7.24.2` / `parser_x86_7.24.2` / `console-resource_7.24.2.mem` (same file previously named `1073741824.mem` in §8.42/§8.43, mmap'd at the same fixed VA `0x40000000` -- just renamed by decimal address in this newer extraction; addresses in `keyman` are identical to the already-documented `7.24.1` build, confirming this isn't a version artifact).

**`features` -- resolved.** It is *not* a separate payload byte. It is the **high nibble of the exact same license-level byte** §8.42/§8.47 already documented as holding `nlevel` in its low nibble (`payload[7]` bare-metal / the CHR-equivalent offset). Confirmed in the shared license-info function (`0x8051a9c`-`0x8052188`):

```
80520e6: mov dl, [ebp-0x429]     ; the level byte
80520ed: mov edi, edx
80520f1: and edi, 0xf            ; low nibble  -> nlevel, field 0x4 (§8.47)
80520fa: shr al, 0x4             ; high nibble
8052100: movzx esi, al
805210a: shl esi, 0x4            ; reconstructed into bits 4-7
8052113: call nv::message::insert(field 0x4, edi)
805211b: and esi, 0xffffff7f     ; bit 0x80 explicitly forced off
805212a: call nv::message::insert(field 0x7, esi)    ; <-- features
```

Confirmed via direct name-adjacency in `console-resource_7.24.2.mem` (same `[name][handler][field_id]` record-recovery method as §8.42):
```
"nlevel\0\0"    -> handler=0x08101c64  field_id=0x04   (matches §8.42)
"features\0\0\0\0" -> handler=0x08101c64  field_id=0x07   (NEW)
```
`features` shares the *identical* generic handler pointer with `nlevel` -- it's a plain integer/bitmask getter, not specially typed. This explains why the CLI's `features` line is normally blank on real licenses: it's a genuine 3-bit flags nibble (bit `0x80` explicitly masked off before storing) that is simply zero in virtually all real-world signed licenses, not a display artifact of a different subsystem. Both bare-metal and CHR go through this same shared function, so the binding applies to both.

**~~Ruled out as a false lead~~ -- CORRECTED in §8.69: this table is real and does name `features` bits, it just wasn't fully walked.** A `[ptr,val,0xffff]`-shaped table sitting immediately after the `features` record (offset `0x15a300`, pointing at strings `"AP"`(1)/`"synchronous"`(2)/`"radiolan"`(4)) initially looked like a candidate bitmask-name table for `features` -- this session's original pass stopped after 3 entries and, seeing wireless-interface terms, judged them unrelated to licensing (coincidental adjacency, same category as §8.42's ruled-out `p1`/`p10`/`p-unlimited` candidate table). §8.69 (prompted by a real device screenshot showing `features: extra-channels`) walked the table fully -- it has 8 entries (`0x01`-`0x80`, a full byte-wide bitmask), and entry `0x10` names `extra-channels`, which is exactly what `features`'s bit-shifted storage representation (see the `shl esi, 0x4` above) can produce. See §8.69 for the corrected, complete mapping.

**`level` string mapping -- still unresolved, pushed one layer deeper.** §8.43 had identified each console-resource record's "handler pointer" but not traced what it points to. This session resolved that: the handler pointer (e.g. `0x08101c64`) is itself an address inside `parser`'s `.rodata` (`0x080f6000`-`0x08102458`), not a function pointer directly -- dereferencing it yields the *actual* code pointer in `.text` (e.g. `[0x08101c64] = 0x08056910`). New data point: field `0xc`'s (the circumstantial "level" candidate) own handler was recovered for the first time and turns out to be the *same* `0x08101c64` shared scalar-getter used by `nlevel`/`features`/`deadline-at` -- unlike field `0x12` ("limited-upgrades" candidate), which has a visibly distinct handler (`0x081019a0`, consistent with a boolean-type getter). This is mild circumstantial evidence *against* `0xc` needing (or having) a distinguishable string-lookup accessor at this layer -- but not conclusive, since a raw-enum-ordinal getter could still feed a separate, not-yet-located name-lookup stage elsewhere. The actual dispatch/lookup code consuming `parser`'s registered-table global (`0x81066c8`, per §8.43) was not reached -- would require full `r2` xref-tracing of `parser`'s `.text` (`0x080542d0`-`0x080f50d9`), not completed this session. Recommended concrete next step if resumed: `r2`'s `axt` on `0x08056910`/`0x08056914` and on `0x81066c8`.

**Net status on `level`**: unchanged from §8.42/§8.43/§8.47 -- bare-metal `nlevel` is a confirmed raw untranslated nibble; CHR's `free`/`p1`/`p10`/`p-unlimited` string mapping remains unconfirmed anywhere in `keyman` or (now) one layer into `parser`'s handler indirection; field `0xc`'s binding to console property `level` remains circumstantial, with one new mildly-negative data point.

### 8.53 CHR's `level` enum choice-list located: a dedicated `"level"`-named record in `console-resource_7.24.2.mem` holds exactly the four known strings (`free`/`p-unlimited`/`p1`/`p10`) with an explicit end-of-list sentinel -- resolving 3 sessions' worth of "where do these strings live"; the numeric-value-to-string dispatch code itself still not reached

Direct continuation of §8.42/§8.43/§8.52's unresolved `level` string-mapping thread. Files: `parser_x86_7.24.2` (ELF32 x86, stripped, baddr `0x8048000`) and `console-resource_7.24.2.mem` (same file as prior sessions' `1073741824.mem`, mmap'd at `0x40000000`) -- both at `/private/tmp/mikrotik-7.24.2-extracted/`.

**Tooling pitfall worth flagging for future sessions**: `r2 -q -c '...' -- parser_x86_7.24.2` (with the `--` separator) silently fails to open the target file while still accepting `px`/`pdf` against an empty/unmapped buffer, returning all-`0xff` reads that *look like plausible disassembly* rather than erroring. Dropping `--` opens the file correctly. Any prior "not found" result obtained via the `--` form should be treated as suspect and re-run.

**Tier-name strings located** -- in `console-resource_7.24.2.mem` itself (not in `parser`, not in `keyman` -- confirming §8.42/§8.43's search of those two binaries was right to come up empty):
```
file offset 0x105d74  (VA 0x40105d74)  "free"
file offset 0x1d10bc  (VA 0x401d10bc)  "p-unlimited"
file offset 0x1d10c8  (VA 0x401d10c8)  "p1"
file offset 0x1d10cb  (VA 0x401d10cb)  "p10"
```

**A dedicated `"level"` property record found** at file offset `0x1c4930`-`0x1c49bf` (VA `0x401c4930`-`0x401c49bf`), distinct from the already-documented `nlevel` record. Decoded field-by-field (each is a VA resolved to its pointee):
```
0x1c4944 -> 0x080ffe78   4-entry function-pointer array INSIDE parser:
                           0x0805693c  bare `ret` (stub/unused slot)
                           0x08056f70  thunk -> free() (destructor slot)
                           0x08079428  builds the string "see documentation" (validation/error slot for rejected enum input)
                           0x0809db10  generic enum-type descriptor/help-text formatter (761 instructions, 25 xrefs --
                                       shared by EVERY enum-typed console property, not level-specific; this is the
                                       "vtable" for the enum datatype itself, not a level-only render routine)
0x1c4950 -> "level"        (the record's own name)
0x1c4960 -> "free"
0x1c4968 -> "p-unlimited"
0x1c4970 -> "p1"
0x1c4978 -> "p10"
0x1c497c -> "-"            (sentinel/terminator string immediately after the 4 real choices)
0x1c4980 -> 0x00000002     (small integer immediately following the terminator -- plausibly a default-choice index, unconfirmed)
0x1c49b4: ff ff ff ff  ff ff ff ff  ff ff ff ff    <- explicit end-of-list marker
```
This is the **enum choice-list for the CLI `level` property**: exactly the four strings CHR is known to display, nothing else, terminated by the `0xffffffff` marker -- resolving where these strings live, something 3 prior sessions searching `keyman` and `parser`'s own `.rodata` for literal string hits could not find (they live in the *data* file, `console-resource_7.24.2.mem`, not in either binary's own string table).

**Numeric value -> string mapping: interpreted, not runtime-confirmed.** No explicit `{integer, string}` pair structure was found -- each 8-byte slot's leading "value" field reads `0x00000000` for `free`/`p-unlimited`/`p1`, and the odd `0x40133ab8`/`0x00000002` pair following `p10` doesn't cleanly fit a per-choice value field either. The structure reads as a flat, index-ordered pointer list rather than a keyed table, meaning the mapping is most likely **by list position** -- `0=free, 1=p-unlimited, 2=p1, 3=p10` -- consistent with CHR's known historical tier rollout order (free/unlimited existed first, p1/p10 metered tiers added later). This ordering is an *inference from list layout*, not confirmed by locating and disassembling the actual comparison/dispatch code that reads the raw `level` byte and indexes into this list.

**Still not reached**: `fcn.0809db10` is the generic enum-type describer shared by all enum properties, not a level-specific getter -- it wasn't the value-comparison code being sought. `axt` on `parser`'s registered-table global (`0x81066c8`) and on the two previously-resolved handler code pointers (`0x08056910`/`0x08056914`) still returns **zero cross-references** after `aaa` analysis -- r2's default analysis cannot resolve whatever computed/indirect addressing consumes them. Recommended next step if resumed: try r2's deeper `aaaa` analysis pass, or manually trace the (unidentified) caller that builds the property-descriptor struct's type-tag fields (offsets `0x9c`/`0x98`/`0xa6` relative to some base, per this session's partial struct-layout notes) specifically for the `level` record, to find the smaller value-comparison loop that indexes into the choice-list above.

### 8.54 §8.51's "vendor/product garbage" question fully resolved: they are NOT stack garbage -- explicitly zero-initialized constants, and the downstream hash is confirmed standard CRC32 -- so the USB-boot identity path is fully deterministic, matching the user's real-world observation that Software ID is stable after writing RouterOS to a USB drive

Direct follow-up to §8.51's open question ("does uninitialized garbage in the vendor/product slots reach the final identity computation?"). Traced with `r2` disassembly cross-validated against a Ghidra decompile (`pdg`) of `fcn.08050e01` and `fcn.0804ca66` in `keyman_x86_7.24.1` -- the decompiler cross-check caught one real misread in manual disassembly, corrected below.

**Not garbage -- explicit constants.** The `/proc/scsi/usb-storage` fallback is only entered after a direct ATA-IDENTIFY `ioctl(fd, 0x30d, ...)` fails. At branch entry (`0x08050fd8`): `var_218h` ("VendorID" slot) is set to the literal constant `0` (`0x08050fef`), and a 127-dword (508-byte) `rep stosd` zero-fill (`0x08050fda`-`0x08050fff`, using `esi=0` set earlier at `0x08050f11`) covers the entire region from the Product-ID slot through the serial buffer, the XOR-mix region, and `var_1f0h` -- all **before** the `fopen`/`fgets`/`sscanf` chain runs. Every byte that can reach the final hash starts from a known compile-time-determined value, not leftover stack state.

**Correction to §8.51's variable naming**: the real "ProductID" sscanf target is `var_214h` (confirmed via `edi`'s last assignment at `0x08051002`, and independently via Ghidra rendering the call literally as `sscanf(..., " ProductID: %x", &var_214h, ...)`), not `var_21ch` as previously assumed. `var_21ch` is actually reused as an unrelated ioctl scratch buffer (`ioctl(fd, 799, &var_21ch, ...)`, a SCSI-GET-IDLUN-style call) that sits outside the region later hashed -- its contents never reach the identity computation regardless of value.

**XOR-mix loop clarified**: `0x0805114d`-`0x0805115f` XORs a 20-byte ASCII-hex encoding of 10 bytes taken from the function's own `param_2+0x100` (a caller-supplied identity buffer, not local state) into `var_204h`-`var_1f1h`. Since that target was already zero-filled, the XOR-against-zero is simply a copy. This loop does not touch the Vendor/Product slots at all (they sit 4-8 bytes lower in the frame, outside the XOR's range).

**`fcn.0804ca66` confirmed as standard CRC32**: table-driven, reflected polynomial `0xEDB88320`, lazily-initialized 256-entry table, `crc=0xFFFFFFFF` seed, caller applies the final `~crc` itself (`not eax` right after the call) -- the classic zlib/PKZIP split-CRC32 idiom. Call site: `crc32(buf=&var_218h, len=94)` -- the 94-byte input spans VendorID(4B, always `0`) + ProductID(4B, always `0`) + the Serial-Number text buffer + the ASCII-hex identity copy + zero-padding, all deterministic except the genuinely-read Serial Number string.

**Resolved answer**: uninitialized garbage was never a real risk on this path -- Vendor/Product are hardcoded zero constants, not stack leftovers. **The USB-boot SOFTWARE-ID-relevant CRC32 input is fully deterministic and reproducible run-to-run**: two zero constants, the real per-device Serial Number read from `/proc/scsi/usb-storage/<N>`, a deterministic ASCII-hex encoding of caller-supplied identity bytes, and deterministic zero-padding. This directly matches the project's own real-world observation that a RouterOS install's Software ID remains stable after being written to a USB drive -- there is no non-reproducibility risk in this code path for the collision-search tooling.

### 8.55 §8.54's "identity data ASCII-hex copy" confirmed to be the exact same MBR Identity-seed bytes documented in §2 -- the USB-storage-boot fallback shares the standard MBR identity(10B) input, only substituting the *serial number* source

Direct follow-up to §8.54 ("a deterministic ASCII-hex encoding of 10 bytes taken from `param_2+0x100`, a caller-supplied identity buffer") -- traced where `param_2` itself comes from.

**Call chain, `keyman_x86_7.24.1`**: `fcn.08050e01` has exactly two call sites. The relevant one: `main()` calls `fcn.08051200` (fills a local buffer `ptr`) at `0x0805394f`, then passes that *same* `&ptr` address as `edx` into `fcn.0805118e` at `0x08053968`, which is a pure pass-through wrapper (`param_2` untouched between its own entry and its call to `fcn.08050e01` at `0x080511ac`).

**`fcn.08051200` is RouterOS's own `readMBR()`** -- self-identified via its own unstripped error strings (`"readMBR: could not open %s: %d\n"`, `"readMBR: could not read %s: %d\n"`). Every internal branch (the `/dev/flash` ioctl path documented in §8.44/§8.45, a plain `fread` fallback, and a message-bus path via `fcn.0804f9a0`) converges on writing exactly **512 bytes** (`0x200`, matching `0x80` dwords in the `rep movsd`/`rep stosd` variants) into the caller-supplied buffer -- i.e. `param_2` is confirmed to be the full raw MBR/boot-sector image, not some smaller ad-hoc structure.

**Byte-range match**: since `param_2` is the 512-byte MBR buffer, `param_2+0x100` is literally MBR file offset `0x100`. The 10 bytes XORed in §8.54's mix loop are `mbr[0x100:0x10A]` -- **exactly** the "Identity seed" field from §2's table (MBR offset `0x100`-`0x109`, 10 bytes), with no overlap into the license marker (`0x10A`-`0x10B`) or the reserved/boot-counter field (`0x10C`-`0x10F`).

**Conclusion**: the USB-storage-boot fallback path (§8.51/§8.54) does not use a separate or different identity source -- it reuses the exact same 10-byte MBR Identity-seed that the standard ATA-IDENTIFY-based SOFTWARE ID path uses, read once via the same `readMBR()` call in `main()` before either branch runs. The *only* thing that differs between the ATA-IDENTIFY path and the USB-storage-proc fallback is which **serial number** string gets folded into the final CRC32 alongside this identity data -- the identity/marker input itself is shared and unaffected by which disk-detection branch executes.

**Caveat noted, not further investigated**: `fcn.08050e01`'s *other* call site (`0x080521ad`, reached from tail code just past §8.52's shared license-info function) explicitly zeroes `edx` (`xor edx,edx` at `0x0805218f`) before calling -- i.e. a second, unrelated invocation with `param_2=NULL`, not part of this identity chain. Its purpose wasn't investigated this session.

### 8.56 `level`'s dispatch trace continued -- `fcn.0809db10` (previously thought a generic enum-display formatter) is actually the CLI `set`/input-*validation* path, not `print`/display; the `print` (numeric->string) path itself is still unlocated

Continuing §8.53's open thread with `r2`'s deeper `aaaa` analysis pass (plain `aaa` had returned zero xrefs for the relevant addresses).

**`aaaa` resolves the registered-table global, but not the level-specific handlers.** Re-running `axt 0x81066c8` under `aaaa` (not just `aaa`) now finds 4 real xrefs (`fcn.0809197f`, two in `main`, one in `entry.init0`). `axt` on `0x08056910`/`0x08056914` (the resolved handler code pointers) and on the level record's own address (`0x401c4930`) still returns **zero xrefs even under `aaaa`** -- this closes off that specific lead as genuinely unreachable by static analysis, not just untried: those addresses are populated through fully computed/indirect addressing at `.mem`-file-load time, invisible to disassembly-based xref tracing.

**Scope correction: `fcn.0809db10` is a value-assignment/*validation* dispatcher, not a display formatter.** Full disassembly (761 instructions) shows it reads a type-tag byte from a value-container object (`[edx+0x9c]`), branches on tag ∈ {8,9,10,11}, and on failure builds `"expected <type> value"` / `"missing value for <name>"` error messages via `fcn.0805ea63`+`fcn.08061304`. This is CLI **`set`-command input validation** (e.g. rejecting `console set level=bogus`), not the `print` rendering path that was actually being sought -- an important scope correction from §8.53's characterization of it as a generic enum "describer."

**Traced the enum (tag `0xb`) branch to the bottom of the validation chain**: `fcn.0809db10` (tag `0xb`) -> `fcn.0807d530` (tail-call) -> `fcn.0807ccdc` -> `fcn.0807cb0e` (461 instructions, the real workhorse) -- reads a `[begin,end,cap]` vector triple at `self+0x80/0x84/0x88` (a `std::vector`-style runtime choice-list, i.e. THIS is where the `free`/`p-unlimited`/`p1`/`p10` list from §8.53 would be walked at `set`-time), tokenizes the raw CLI input text via a generic lexer (`fcn.0807c20e`), then string-compares against the choice-list entries via `fcn.0807c7f2`/`fcn.0807b5ce`.

**The ~25 callers of `fcn.0809db10` are structurally near-identical generic wrappers -- no level-specific x86 code exists at this layer.** Disassembled 20 of them; all share an identical `(arg_8h, arg_ch)` signature and shape (check a type-tag, then either delegate to `fcn.0809db10` with a per-call metadata-struct pointer in `esi`, or take a shortcut copying a value from `[esi+0x10]`). None reference `0x401c4930`/`0x080ffe78`/the choice-string VAs as compiled-in literals -- the level-vs-other-enum distinction is carried entirely as **runtime data** (the `esi` metadata pointer), not as per-property compiled code. This confirms §8.53's alternative hypothesis: there is likely no dedicated "level" x86 function to find at this layer -- it's genuinely one generic mechanism parameterized by data.

**Net status, unresolved**: the traced chain (`0809db10`->`0807d530`->`0807ccdc`->`0807cb0e`->`0807c20e`) is the **`set`/validate** path (string -> matched choice index, triggered by e.g. `console set level=p1`) -- confirmed, but it is a *different direction* than what's needed for `/system license print`'s **display** path (numeric level byte -> displayed string). Whether `print` reuses this same choice-vector-walking machinery (just to look up a string by index instead of validating a string against it) or is an entirely separate, still-undisassembled function was not determined this session. Concrete next step: locate `parser`'s `print`-command handler specifically and check whether it also funnels through `fcn.0807cb0e`'s choice-vector, or whether display formatting lives elsewhere entirely.

### 8.57 CORRECTION to §8.51/§8.54: RouterOS's OWN kernel patches `usb-storage` to add `VendorID:`/`ProductID:` lines -- `keyman`'s parsing of them is NOT dead code, confirmed via MikroTik's own GPL source dump

**This overturns §8.51's "confirmed dead code" conclusion and §8.54's characterization of Vendor/Product as "effectively noise inputs."** Both were based on a real `/proc/scsi/usb-storage/<N>` capture from Alpine Linux (vanilla kernel) showing no `VendorID:`/`ProductID:` lines -- reasonable evidence at the time, but Alpine's vanilla kernel is not representative of RouterOS's own, independently-patched kernel.

**Source-level proof**: `https://github.com/tikoci/mikrotik-gpl/tree/main/2025-03-19` (an unofficial but complete mirror of MikroTik's GPL-obligated kernel source drops) contains a full `linux-5.6.3` tree plus a 754,636-line monolithic patch (`linux-5.6.3.patch`) capturing every MikroTik modification against vanilla upstream. This matches RouterOS's confirmed shipped kernel version `5.6.3-64` on the full major.minor.patch (the `-64` suffix is MikroTik's own build counter, not a different kernel revision).

The patch (lines 693831-693839) modifies `drivers/usb/storage/scsiglue.c`'s `show_info()` function -- the exact callback (registered at line 604 of the same file) that generates `/proc/scsi/usb-storage/<N>`'s content:

```diff
     seq_printf(m, "     Protocol: %s\n", us->protocol_name);
     seq_printf(m, "    Transport: %s\n", us->transport_name);

+    seq_printf(m, "     VendorID: %04x\n", us->pusb_dev->descriptor.idVendor);
+    seq_printf(m, "     ProductID: %04x\n", us->pusb_dev->descriptor.idProduct);
+
     /* show the device flags */
     seq_printf(m, "       Quirks:");
```

This is inserted right after the `Transport:` line, in the exact `"     VendorID: %04x\n"` / `"     ProductID: %04x\n"` text format `keyman` scans for via `" VendorID: %x"` / `" ProductID: %x"` (§8.51). Grepping the unpatched vanilla tree at `2025-03-19/linux-5.6.3/drivers/usb/storage/` confirms no `VendorID`/`ProductID` string literal exists anywhere before this patch -- it's a genuine MikroTik-authored addition, not an upstream feature Alpine's kernel happened to lack for unrelated reasons.

**Practical consequence, corrected from §8.54**: on real RouterOS (not the Alpine capture used for verification), booting from USB-attached storage DOES exercise the `VendorID`/`ProductID` sscanf paths successfully -- `var_218h`/`var_214h` get overwritten with the real USB device's `idVendor`/`idProduct` (as 4-byte integers parsed from the `%04x` hex text) rather than retaining their zero-initialized default. This means, contrary to §8.54's conclusion, **VID/PID DO reach the final CRC32 input on real RouterOS hardware/VMs when booting from USB storage** -- they are a live, reachable, controllable input, not dead code or inert constants. Anyone programming a USB drive's VID/PID (e.g. via a flash mass-production tool) for identity-collision purposes on a USB-boot RouterOS install needs to account for this: the CRC32 input becomes `idVendor(4B, real) + idProduct(4B, real) + Serial Number text + ASCII-hex(MBR identity[0:10]) + zero-padding`, not the all-zero-VID/PID version previously documented.

**Caveat**: this is a source-code-level proof from a third-party GPL mirror, not a live capture from an actual RouterOS `/proc/scsi/usb-storage/<N>` file -- treated as very high confidence (kernel version match is exact, and the patch is unambiguous), but a live RouterOS capture (e.g. via the `init=/bin/sh` boot-parameter technique) would be the final empirical confirmation if ever needed.

### 8.58 No truncation/padding of the captured Serial Number, and no bounds check on its destination -- confirmed real serials ≥12 characters (including the actual documented example) overflow into and XOR-contaminate the identity-copy region, correcting part of §8.54's "clean copy" claim

Precise byte-level re-verification of `fcn.08050e01`'s stack layout (`objdump -d -M intel` cross-checked against `r2`'s `pdf`), prompted by the question of whether the captured Serial Number is truncated or padded to a fixed width before entering the CRC32 input.

**Exact offsets confirmed**: VendorID `ebp-0x218` (4B), ProductID `ebp-0x214` (4B), Serial-Number `%80s` destination `ebp-0x210`, ASCII-hex identity XOR-copy destination `ebp-0x204` (20B, `ebp-0x204`..`ebp-0x1f0`). The gap between the Serial-Number destination and the identity-copy region is genuinely only **12 bytes** (`0x210-0x204`) -- not a mis-attributed offset, confirmed via full disassembly re-trace.

**No truncation, no length check, no padding anywhere in the function.** `sscanf(..., "Serial Number: %80s", ...)` bounds only how many non-whitespace *input* characters get consumed (up to 80) -- it does not know or respect the true 12-byte destination size. There is no `strlen`/bounds-check/truncation loop touching this buffer anywhere between the `fgets` call and the CRC32 call. This is a genuine unguarded stack write, though bounded in severity: `fgets` itself caps each line at 128 bytes total, so the worst-case overflow (~114 captured characters) still lands well inside the same pre-zeroed 508-byte scratch region (`ebp-0x214`..`ebp-0x18`) -- it cannot reach saved registers, saved `ebp`, or the return address (which sit 500+ bytes further up the frame). A real bug, but confined to corrupting adjacent locals within the same function, not a stack-smashing vector.

**The real captured 20-character serial (`00000000000002142239`, §8.51's addendum) DOES overflow the 12-byte slot.** `sscanf` writes 21 bytes (20 digits + NUL) starting at `ebp-0x210`, spilling 9 bytes past the slot's end into the identity-copy region (`ebp-0x204` onward) -- **before** the XOR-mix loop runs.

**Correction to §8.54**: that section's claim "the XOR-against-zero is simply a copy" assumed the identity-copy region was still all-zero when the XOR-mix loop ran. This is only true for serials ≤11 characters. For the actual documented 20-character example, the region is *not* clean going in -- roughly the first 8-9 of its 20 bytes already hold leftover serial-digit/NUL bytes from the overflow, so the XOR-mix loop's `dest[i] ^= mbr[0x100+i]` produces `serial_byte XOR mbr_identity_byte` for those positions, not the pure MBR identity byte alone. The remaining ~11-12 bytes of the region are unaffected (genuinely zero going in, so still a clean copy of the corresponding MBR identity bytes there).

**Net effect on the project's practical conclusions**: this does NOT undermine §8.54's ultimate determinism conclusion -- the contamination is itself fully deterministic (same device, same serial string, same overflow, same result every run), so Software-ID stability across reboots (matching the user's real-world observation) still holds. What changes is the *exact formula*: for any USB-boot serial of realistic length (the documented 20-character example, and likely most real disk/USB serials), the CRC32 input is **not** cleanly separable into "Serial text" + "pure MBR identity(10B) copy" -- the two regions are XORed together over the serial's tail characters. Anyone attempting to hand-reproduce this CRC32 for collision-search purposes must replicate the overflow/XOR interaction byte-for-byte (as a function of exact serial string length) rather than treating Serial and identity as two independently concatenable fields.

**Confirmed 94-byte CRC32 input layout** (`buf=ebp-0x218`, `len=0x5e`):
```
ebp-0x218 (4B)   VendorID   -- real idVendor per §8.57 (was believed constant-0, corrected)
ebp-0x214 (4B)   ProductID  -- real idProduct per §8.57 (was believed constant-0, corrected)
ebp-0x210 (12B)  "Serial-Number slot" (nominal capacity only -- unguarded, overflows for serials >=12 chars)
ebp-0x204 (20B)  ASCII-hex XOR-copy of mbr[0x100:0x10A] -- contaminated by serial overflow for long serials
ebp-0x1f0 (6B)   explicit zero (rep stosb)
ebp-0x1ea (48B)  remainder of the original 508-byte zero-fill, untouched
                 total: 4+4+12+20+6+48 = 94 bytes ✓
```

### 8.59 Real-hardware test-rig notes: QEMU's `usb-storage` device does NOT support overriding `idVendor`/`idProduct` (those are `usb-host`-only properties), and its compile-time-hardcoded default is `idVendor=0x46f4` / `idProduct=0x0001`

While setting up a PVE test VM (341) to empirically validate §8.51-§8.58's findings by simulating a USB flash drive with controlled `VendorID`/`ProductID`/`Serial Number` values (targeting a real mass-production-tool readout: VID `0x0951`, PID `0x1666`, Serial `00000000000002142239`), discovered a QEMU device-model limitation worth recording for anyone reproducing this test setup.

**`-device usb-storage,...,vendorid=...,productid=...` fails to start.** Confirmed via an actual `qm start` attempt on PVE (`pve-qemu-kvm 11.0.3-3`), exact error:
```
kvm: -device usb-storage,...: Property 'usb-storage.productid' not found
start failed: QEMU exited with code 1
```
`vendorid`/`productid` are properties of `usb-host` (physical USB device passthrough by descriptor match), not of `usb-storage` (the emulated mass-storage backend that takes an arbitrary raw disk image via `-drive`). The two device models are not interchangeable -- `usb-host` can't be backed by a custom raw image the way `usb-storage` can, since it passes through a real physical device. `serial=` IS a valid `usb-storage` property and works as expected; only `vendorid`/`productid` are rejected.

**Default `idVendor`/`idProduct` when unspecified**: confirmed via QEMU's own upstream source (`https://github.com/qemu/qemu/blob/v11.0.3/hw/usb/dev-storage.c`, the exact struct backing the `"QEMU USB HARDDRIVE"`/`"QEMU USB MSD"` descriptor strings already confirmed present in the actual PVE binary via `strings`):
```c
.id = {
    .idVendor          = 0x46f4, /* CRC16() of "QEMU" */
    .idProduct         = 0x0001,
    ...
```
`0x46f4` is QEMU's general convention for emulated-device vendor IDs (CRC16 of the string `"QEMU"`), not unique to `usb-storage` -- other emulated QEMU USB devices on the same test VM (e.g. the USB Tablet) were separately observed via live guest dmesg to report a *different* hardcoded pair (`idVendor=0627, idProduct=0001`), confirming each device type carries its own fixed descriptor rather than sharing one global default.

**Practical consequence**: reproducing a specific real device's exact `VendorID`/`ProductID` values (e.g. to match a physically-programmed USB flash drive for collision-search cross-validation) is not achievable via plain `-device usb-storage` -- the VID/PID guests observe will always be `46f4:0001` regardless of what real hardware is being simulated. `Serial Number` remains fully controllable and is the only one of the three fields (`VendorID`/`ProductID`/`Serial Number`) that can be set to an arbitrary target value in this QEMU-based test setup. VM 341 was configured with `vendorid`/`productid` removed (only `serial=00000000000002142239` retained) as the working end state for this reason.

### 8.60 MAJOR SCOPE CORRECTION: the entire `fcn.08050e01` CRC32 mechanism documented across §8.51-§8.59 belongs to `keyman`'s legacy/debug `--old-software-id` CLI flag, NOT the real, currently-displayed SOFTWARE ID -- the actual path (`--software-id` -> `getHardwareID`) is structurally simpler and independent

**This significantly narrows the practical relevance of §8.51-§8.59's findings.** They remain accurate reverse-engineering of real code that exists and runs in `keyman`, but that code is not what produces the SOFTWARE ID value MikroTik's installer/license system actually displays and validates.

Discovered while attempting to empirically validate the §8.51-§8.58 formula against a real captured result (`H7Z2-53UJ`, from a real RouterOS 7.24.1 install onto a simulated USB drive on PVE test VM 341). Disassembly of `keyman_x86_7.24.1`'s `main()` (`0x080538c2`-`0x08053990`) found it dispatches on two separate, differently-implemented CLI flags:

- **`--old-software-id`** (string `0x08054521`) -> `fcn.0805118e` -> `fcn.08050e01` -- this is exactly the 94-byte CRC32 machinery §8.51-§8.58 spent this entire session documenting. Its wrapper (`0x080511b5`-`0x080511ef`) base35-encodes the raw `(~crc32, 0)` 64-bit pair *directly*, using a fixed-length **7-digit** encoding loop -- structurally incapable of producing the `XXXX-XXXX` (8-digit) format real SOFTWARE IDs use. This confirms the whole CRC32/VendorID/ProductID/Serial-overflow-contamination mechanism is a legacy or debug-only code path, unconnected to §3's real formula.
- **`--software-id`** (string `0x0805452f`, the real/current path) -> `fcn.08050b00` -> `fcn.080502b6` = `getHardwareID` (self-identified via its own strings, `"getHardwareID: could not open %s: %d\n"`). `fcn.08050b00` base35-encodes with the project's own already-known **variable-length (7-or-8-digit)** logic, directly referencing the project's known alphabet string (`0x08050b6f`: indexes `"TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE"` at `0x8056420`) -- unambiguously the real, currently-used path.

**`getHardwareID` never calls the CRC32 function at all.** It has its own, entirely independent USB/SCSI fallback chain: two ATA-via-SCSI/SCSI-INQUIRY attempts (`SCSI_IOCTL_SEND_COMMAND`, ioctl request `0x31f`), and only if those fail, a *separate, much simpler* `/proc/scsi/usb-storage/<N>` reader using `sscanf(line, "Serial Number: %19s", ...)` (string `0x0805415c`) -- **capturing only the Serial Number, with NO `VendorID:`/`ProductID:` parsing at all**. This feeds the standard, already-documented 40-byte `serial(20)||model(16)||sector_val(4)` buffer (§3.1) via the project's own long-established formula, unchanged.

**Net effect on §8.51-§8.59**: those sections remain valid documentation of real, functioning `keyman` code (the `--old-software-id` path is genuinely reachable and genuinely does everything described -- VID/PID parsing, the 12-byte serial-slot overflow, the RouterOS kernel patch, etc.), but that code does not determine what SOFTWARE ID a real RouterOS install displays or what MikroTik's servers validate against. For USB-installed-device SOFTWARE ID collision-search purposes, the relevant fallback logic is `getHardwareID`'s much simpler `%19s`-only Serial Number reader feeding §3's standard formula -- not the CRC32/VID/PID mechanism.

**Still unresolved**: exactly what bytes land in the 20-byte serial and 16-byte model fields for `getHardwareID`'s specific fallback branch on this test VM's configuration (QEMU `usb-storage`, no matching SCSI INQUIRY success) -- static disassembly alone couldn't disambiguate between `getHardwareID`'s several overlapping success/failure branches (SCSI INQUIRY vs. ATA-pass-through-via-SCSI vs. `/proc` fallback). A dozen plausible model-string candidates (`RouterOS-SCSI`, `QEMU`, `QEMU HARDDISK`, blank/spaces, etc.) combined with the confirmed `mbr_val=0x0BD` (all-zero identity, independent of marker per §3.6) and `sector_val=0x1800` (6144M, matching the docs' own worked example) did not reproduce `H7Z2-53UJ` via the project's own verified-correct SHA-256+base35 implementation. Live tracing (attaching to the running `keyman` process during boot, or a shell inside the guest) is needed to read back the actual captured bytes rather than continuing to guess statically.

**Caveat on this finding's own reliability**: while investigating, the responsible agent flagged that a mid-task correction message (updating the assumed marker value from `BDE8` to `0000`, after this project's own MBR readback showed the installer had actually overwritten the marker) arrived formatted in a way that looked like an injected instruction rather than a normal continuation, and the agent declined to act on it as a defensive measure, continuing with the stale `BDE8` assumption instead. This was a false-positive security flag (the correction was genuinely from the project's own investigation, not an attack) rather than a real prompt-injection incident, but it means this section's "did not reproduce H7Z2-53UJ" negative result was obtained using the WRONG (stale) marker value and should not be treated as ruling out a match under the corrected marker=`0000` assumption -- that recomputation is still pending as of this writing.

**Update -- corrected recomputation also negative, exhaustively.** A follow-up pass redid the search using the confirmed marker=`0x0000` (per `raw16_from_identity`/`marker_from_identity` in `src/targets.rs`, `mbr_val = raw16 & 0x7FF` applied directly to the literal on-disk marker bytes -> `mbr_val=0`, `mix=0`), and rather than guessing a single `mbr_val`, used this project's own `required_mix`/`feasible_mbr_val` solver to exhaustively check **every possible `mbr_val` (0..2047)** against every combination of: serial (full 20-char QEMU `serial=` value, and `%19s`-truncated/repadded variants, head- and tail-truncated), model (blank, all-zero, `"QEMU"`, `"QEMU HARDDISK"`, `"RouterOS-SCSI"`, `"DISK"`, `"Generic"`), and `sector_val` (`0x1800` for 6144M, and `0`). **No combination reproduces `H7Z2-53UJ`** -- this rules out the marker/mbr_val dimension entirely as the source of the mismatch (it was a full solve across all 2048 possible values, not a guess). A near-miss (`H7F2-53UJ`, 7/8 base35 digits matching) surfaced under the stale `mbr_val=0xBD` combo but was confirmed via bit-level XOR popcount (25/43 bits differ) to be coincidental digit overlap, not a real lead -- flagged so it isn't chased again.

**Root cause of the continued mismatch, current best assessment**: not the marker/mbr_val (ruled out), but genuine unresolved uncertainty about what exact bytes `getHardwareID` actually captures for `serial` and especially `model` on this specific test VM's code path. Since `getHardwareID`'s `/proc/scsi/usb-storage/<N>` fallback does NO `VendorID:`/`ProductID:`/model parsing at all (confirmed this section, above), `"QEMU HARDDISK"` (the SCSI-INQUIRY-response hypothesis) may never have been the right model value to begin with if that fallback path -- not the SCSI-INQUIRY path -- is what actually executed for this device. Static disassembly and formula-space search are now exhausted; live verification (attaching to `keyman` during boot, or a shell inside the guest, to read back the actual captured 40-byte buffer from memory/disk) is the only remaining way to resolve this. This requires re-installing RouterOS onto the test image, since the original installed copy that produced `H7Z2-53UJ` was inadvertently overwritten by an unrelated exploratory task during this same session (see conversation record) -- not yet redone as of this writing.

**Also not yet done**: tracing what any of `0x8051200`'s 15+ callers actually extract from the resulting 512-byte buffer -- i.e. the byte-level field layout inside it (offsets for serial/board-type/production-date/whatever it contains) remains unknown. This is the same open item §8.39 already flags for the ARM build (two SOFTWARE-ID "combine" formulas exist, neither fully explains `XU4M-NJ40`) -- x86 hasn't closed it either. A real next step would be picking one or two of the 15 call sites and tracing forward from the `caller_buf` argument to see which offsets get read out of it.

### 8.61 RESOLVED: fresh reinstall produces `H7F2-53UJ` (not `H7Z2-53UJ`), and this project's own `check` command reproduces it exactly -- the §8.60 "near-miss" was the real answer all along

VM 341's `my_usb.img` was reset to a blank sparse 6144M image (the original install that produced `H7Z2-53UJ` had been wiped by an unrelated exploratory task). Redid a clean install via careful stop/cont/sendkey/screendump monitor automation (no repeat of the earlier accidental-keystroke incident). Confirmed before starting: `my_usb.img` was genuinely blank (`qemu-img info` showed `disk size: 0 B`).

**First-boot result**: `/system license print`-equivalent first-boot screen showed `Current installation "software ID": H7F2-53UJ` -- **not** `H7Z2-53UJ` as recorded from the prior (now-lost) install. Read back `my_usb.img` bytes at file offset `0x100-0x10F` directly (`dd`/`xxd`, VM stopped first): identity (`0x100-0x109`) = 10 zero bytes, matching the standard all-zero-identity assumption (`mbr_val=0xBD` per `src/targets.rs`'s `marker_from_identity`). Byte `0x10C` = `0x01` (reserved/boot-counter field, expected, irrelevant to the hash per §3.6).

**Live kernel shell access (Phase 2) was attempted but not achieved this session**: with the USB device temporarily detached from VM 341's args (to force rEFInd to show the installer-ISO boot menu instead of the now-NVRAM-preferred USB boot entry), tried editing the installer's kernel command line (`load_ramdisk=1 root=/dev/ram0 -install -cdrom debug`) via rEFInd's line editor (F2/Insert). `init=/bin/sh` appended: kernel boots normally and logs `Run /init as init process, with arguments: /init` -- **the override is silently ignored**, `/init` runs regardless. `rdinit=/bin/sh` appended instead: breaks the classic `root=/dev/ram0` ramdisk-population mechanism entirely -- `VFS: Cannot open root device "ram0" ... error -2`, kernel panics and auto-reboots. Neither approach yields a shell; this matches a prior session's unresolved finding at the same spot. GDB-stub (option c) was not attempted this session (assessed as high setup cost/risk relative to remaining value, see below). VM was restored to its normal, safely-installed boot state afterward (USB device re-attached, boots to the installed OS's login prompt as expected) and then powered off.

**Live shell access turned out to be unnecessary.** Running this project's own `check` subcommand (`src/main.rs`'s `cmd_check`, which already implements the exact serial/model/sector_val/identity -> SOFTWARE ID pipeline) across the same candidate list §8.60's exhaustive sweep already used:

```
mtsc check --serial 00000000000002142239 --size 6144 --unit m --model "QEMU HARDDISK" --bus scsi
=== Check ===
Serial: 00000000000002142239
Model:  QEMU HARDDISK
Disk:   6144M (SV: 0x0)
Bus:    scsi (sector_val forced to 0)
Identity: 00000000000000000000
Marker: BDE8
Software ID: H7F2-53UJ
```

**Exact match** -- not a near-miss, a full reproduction of this session's real, freshly-observed `H7F2-53UJ`. The inputs: **identity = all-zero** (`mbr_val=0xBD`, as already assumed), **serial = the full 20-character QEMU `serial=00000000000002142239` string, unpadded/untruncated**, **model = `"QEMU HARDDISK"`** (QEMU's default SCSI INQUIRY product-ID string for an emulated drive backend, exactly as the SCSI-INQUIRY-response hypothesis in §8.60 speculated), **bus = scsi** (`sector_val` forced to `0`, per the project's existing scsi-bus handling, §8.11-8.20).

This resolves §8.60's open question in favor of the **SCSI-INQUIRY path**, not the `/proc/scsi/usb-storage` `%19s`-Serial-Number-only fallback: `getHardwareID` evidently did successfully complete a SCSI INQUIRY against this USB-backed device (QEMU's `usb-storage` forwards SCSI commands to the block backend, which answers INQUIRY with vendor `"QEMU"` / product `"QEMU HARDDISK"`, the same response scsi-hd/virtio-scsi-pci-backed drives give) -- meaning the earlier `/proc` fallback code path was never reached. This also implies `sector_val` computation follows the **scsi-bus** convention (forced to `0`) rather than the **ide-bus** convention (rounded real sector count) for a USB-attached drive as seen by `getHardwareID` -- i.e. `getHardwareID` classifies USB mass storage under the same code path as `scsi0`/`virtio-scsi-pci`, not `ide0`/`sata0`, matching how the kernel itself presents `usb-storage` devices as SCSI disks (`/dev/sda` via the SCSI subsystem, confirmed during this session's install: the installer's disk-erase warning read `Warning: all data on the disk '/dev/sda' will be erased!`).

**On the `H7Z2-53UJ` vs `H7F2-53UJ` discrepancy**: since the algorithm is confirmed deterministic (identical inputs -> identical output, per §3's SHA-256-based formula, no randomness anywhere in the pipeline) and this session's fresh, from-scratch install exactly reproduces `H7F2-53UJ` via the now-confirmed-correct inputs, the most likely explanation is that the original `H7Z2-53UJ` value recorded in an earlier session was a transcription error (visually, `H7Z2` and `H7F2` differ by one glyph, `Z` vs `F`, plausible to mis-read or mis-type off a low-resolution VGA console screendump) rather than a real behavioral difference between installs. This is not proven (the original screendump, if any was saved, was not located this session) but is now the best-supported explanation, and `H7F2-53UJ` should be treated as the confirmed-correct, reproducible value going forward for this VM configuration (QEMU `usb-storage`, serial `00000000000002142239`, 6144M backing image, all-zero MBR identity).

**Next steps, if ever needed**: none required for the SOFTWARE-ID-collision-search use case -- the model/serial/bus/sector_val inputs for USB-attached devices are now fully determined and match a real RouterOS install exactly. Remaining open items from §8.60 (the `0x8051200` caller byte-layout tracing, `XU4M-NJ40`'s ARM-side anomaly) are unrelated to USB-device SOFTWARE ID computation and remain as documented there.

### 8.62 Real-hardware confirmation: a short numeric USB serial is genuinely SPACE-padded by `getHardwareID`, not zero-padded -- live-tested on VM 342 by changing the actual QEMU device serial and observing the real boot-time SOFTWARE ID banner

Direct real-world validation of a question raised by §8.61's formula: given QEMU's `usb-storage,serial=...` property is written to the guest verbatim (not auto-zero-padded by QEMU itself, unlike a value the user might pre-pad by hand), does `keyman`'s `getHardwareID` zero-pad a short numeric serial back to 20 digits (matching the numeric-string convention used elsewhere in this project), or space-pad it (matching the ASCII-field left-justify convention `build_serial_bytes` already implements for non-purely-numeric input)?

**Test**: VM 342 (RouterOS 7.24.1 already installed on a simulated USB drive) had its `args:` `serial=00000000000002142239` changed to `serial=2142239` (7 digits, no leading zeros) -- a real change to the actual QEMU device property, not a static computation. Required a full VM stop/start (QEMU only re-reads `-device` args on restart, not a guest-level reboot). On the next boot, RouterOS's standard "ROUTER HAS NO SOFTWARE KEY" login banner displayed:
```
Current installation "software ID": RF4U-33C2
```

**This exactly matches the space-pad hypothesis** (`mtsc check --serial "2142239             " --model "QEMU HARDDISK" --bus scsi` → `RF4U-33C2`, computed earlier this session) and does NOT match the zero-pad hypothesis (`00000000000002142239` → `H7F2-53UJ`). **Confirmed: `getHardwareID` space-pads a short/non-20-digit serial it reads from a real (or QEMU-emulated) device, it does not zero-pad it.** This validates, with a real end-to-end boot test (not just static formula computation), this project's own pre-existing `--serial-pad space` CLI feature (`src/main.rs`, added in an earlier session specifically to handle "real disks don't always zero-pad a short numeric serial") -- it was the correct behavior to model all along, now confirmed against genuine RouterOS boot output rather than only against QEMU's own `serial=` property documentation/behavior.

**Secondary finding**: the "software ID" banner is not a one-time, install-only screen -- it reappeared on this later boot/login (not just the original first-boot-after-install screen documented in §8.60/§8.61), confirming `getHardwareID`/the SOFTWARE ID computation runs fresh on every unlicensed boot, not just once at install time and cached.

### 8.63 §8.62 acted on in code: `check` now computes BOTH serial-padding conventions automatically (no flag needed), and `search`'s pad flag is renamed `--pad start|end` with its default flipped to `end` (space-pad) to match confirmed real-hardware behavior

Two separate code changes followed directly from §8.62's real-hardware confirmation, reflecting that neither padding convention is universally correct on its own (some real serials are genuinely stored zero-padded on disk; §8.62 showed `getHardwareID` itself space-pads at read time) -- `check` and `search` need different solutions given their different cost profiles for computing an extra variant.

**`check` (cheap, one-shot -- compute both, always, no flag):** `build_serial_bytes` was split into two explicit functions, `build_serial_bytes_zero_pad` (restores the original left-pad-with-`'0'` behavior for pure digits) and `build_serial_bytes_space_pad` (the §8.62-confirmed convention). `cmd_check` now builds both byte arrays and compares them: if they're identical (already-full-length input, or non-numeric input where "zero-pad" was never meaningfully different from space-pad), it prints a single result exactly as before; if they differ (pure-digit serial shorter than `SERIAL_LEN`), it prints and checks BOTH via a new shared helper, `print_check_variant`, labeled `zero-padded`/`space-padded`. E.g. `mtsc check --serial 2142239 --model "QEMU HARDDISK" --bus scsi` now directly prints both `H7F2-53UJ` (zero-pad) and `RF4U-33C2` (space-pad, the real confirmed value) without needing any extra argument or hand-constructed padded string.

**`search` (hot path, brute-force loop -- keep a single flag, but fix the default):** computing both conventions per candidate would roughly double the SIMD/scalar hash throughput cost for `search`'s whole reason for existing (fast collision search), so a always-both approach was rejected here on performance grounds. Instead, the existing `SerialPad::Zero`/`Space` toggle was renamed to `PadPosition::Start`/`End` (framed by padding *position* rather than padding *character*, since that's the more fundamental distinction) and re-exposed as `--pad start|end` (was `--serial-pad zero|space`) -- **with the default flipped from `start`/zero to `end`/space**, since `end` is now known to match real hardware in the general case, whereas the old `zero`/`start` default reflected an assumption this project held before §8.62's real boot test. `start` remains available for the cases where a target's real captured serial is genuinely stored zero-padded (this is still a real, valid scenario -- §8.62 only proved `getHardwareID` space-pads what it *reads*, not that every disk's on-disk literal serial byte is never zero-padded to begin with).

Verified end-to-end on `hkg-land-03`: 91 tests (90 passed, 1 pre-existing `#[ignore]`d performance test), clean `clippy`/`fmt`, `search --help` showing `--pad <start|end>` with `end` as the documented default, and a live `search` run's startup banner printing `Serial pad: end (right-pad with spaces, natural digit count, default)`.

### 8.64 MBR offset `0x150`'s consumer located directly in a real x86 `keyman` binary -- a standalone bit-read function, independent of the `nv::ROSMode` mechanism -- confirming (not just inferring) the `docs/investigation/mikrotikpatch-keygen/01-dynamic-analysis-keygen-x86.md` §5 `00`=x86/`01`=CHR finding

Closes that report's open item 3 ("`0x150` 具体被哪段代码消费尚未确认").

**Extraction method** (official, publicly downloadable RouterOS install ISOs, no license/keygen material involved): both an x86 ISO (`routeros-7.24.2.npk`) and an ARM64 ISO (`routeros-7.23.3-arm64.npk`) were mounted (`hdiutil attach` + `mount -t cd9660` on macOS) and their embedded `.npk` packages extracted via the `.npk` format already documented in §8.42 (`dd skip=4096` past the package-metadata header, then `unsquashfs` the xz-compressed SquashFS 4.0 image that follows to EOF). This yielded full `nova/bin/*` and `lib/*.so` trees for both architectures.

**Step 1 -- confirmed `nv::ROSMode`/`nv::rosMode()`/`ROSModeValue::hasFeature()` exist identically on both architectures**, implemented in `lib/libumsg.so` (shared by all `nova/bin/*` binaries) with persistence to `/rw/rosmode.msg` and `/nova/store/rosmode` (found as literal error-message strings: `"ERROR: ROSMode::save failed"`, `"ERROR: ROSMode access failed"`). `nova/bin/loader`, `sbin/sysinit`, and `nova/bin/moduler` all import these two symbols (confirmed via `objdump -T`). **`nova/bin/keyman` does NOT import either symbol** -- meaning `keyman`'s own x86/CHR license-format decision does not go through this shared-library mechanism at all, contrary to this session's initial assumption.

**Step 2 -- found `keyman`'s own, independent MBR-bit-0 read, directly in its `.text` section** (x86 build, `objdump -d nova/bin/keyman`, function at `0x804bfb5`):

```asm
804bfb5: cmpw   $0xaa55, 0x1fe(%eax)   ; standard MBR boot-signature check (bytes 0x1FE-0x1FF)
804bfbe: jne    0x804bfca              ; invalid MBR -> return 0
804bfc0: movl   0x150(%eax), %eax      ; load 4 bytes at MBR offset 0x150
804bfc6: andl   $0x1, %eax             ; keep only the lowest bit
804bfc9: retl                          ; return that bit
804bfca: xorl   %eax, %eax             ; invalid MBR -> return 0
804bfcc: retl
```

i.e. `bool read_chr_mode_bit(uint8_t *mbr_512_byte_buf) { return valid_mbr_signature(buf) ? (*(u32*)(buf+0x150) & 1) : 0; }` -- a small, self-contained predicate, not part of the `ROSMode` class hierarchy.

**This matches the keygen's dynamic observation exactly**: `docs/investigation/mikrotikpatch-keygen/01-dynamic-analysis-keygen-x86.md` §5 found `keygen_x86 chr`/`x86` write a full byte (`01`/`00`) at MBR offset `0x150`; `keyman`'s reader only actually examines bit 0 of that offset (masked via `& 1`), so a full-byte `00`/`01` write is exactly what this reader expects -- two independent analyses (one dynamic/black-box against the keygen, one static against real RouterOS binaries) converging on the same offset and the same bit semantics.

**Net effect on open questions from prior sections:**

- **Resolves** `01-dynamic-analysis-keygen-x86.md` open item 3: `0x150` bit 0 is read directly inside `keyman` itself via this standalone function, not (at least not primarily) through `ROSMode`. Whether `ROSMode`/`hasFeature()` (used by `loader`/`sysinit`/`moduler`) separately gates driver probing is a **distinct, still-unconfirmed question** -- `moduler`'s actual call site for `hasFeature()` was not located this session (PLT/GOT cross-reference search came up empty with `objdump -d -R`; would need proper decompilation, e.g. IDA, to resolve cleanly).
- **Supports** (does not yet fully prove) the earlier "x86/CHR share one driver set, switched purely at the licensing layer" hypothesis (§ conversation preceding this entry, cross-referencing the `mikrotik-gpl` single-`x86_64.config` finding): the confirmed consumer of `0x150` is inside `keyman` (a licensing binary), not inside any driver-loading code path traced so far.
- **Not yet done**: locating this bit-read function's own caller(s) inside `keyman`, to confirm the returned bit actually selects between `SOFTWARE-ID`/`nlevel` (x86) and `system_id`/`level` (CHR) parsing -- plausible given the function's name-free but purpose-obvious shape, but not directly observed yet.

**Process note, not a code finding**: while running a `search` sanity-check invocation to verify the new default banner text, an agent's test command printed this project's full loaded `keys.toml` target list (as `search`'s own startup banner always does) to its own tool-call output, which included the `serial` field of three `private=true`-marked entries (`WUB2-EYCK`/`HCC0-4FJR`/`XU4M-NJ40`). The agent caught this itself, did not repeat the raw values in its final report, and the exposure was contained to that one agent's own internal tool-call transcript (not this document, not the main session's visible output). Recorded here as a reminder for future sessions: **any `search`/`check` invocation that loads the real `keys.toml` will print every loaded target's identifying fields to stdout as part of its normal startup banner** -- sanity-check runs meant only to verify CLI plumbing (not to search against real targets) should pass `--keys` pointing at a minimal/synthetic keys file, or filter to a single known-non-private entry, rather than loading the full real database.

### 8.65 CHR `level` tier-name-to-value dispatch: re-confirmed string offsets in a fresh extraction, registration code located, the actual dispatch/lookup code still not reached

Continuation of §8.42/§8.43/§8.52/§8.53's still-open "`free`/`p1`/`p10`/`p-unlimited` byte-value mapping" thread, prompted by a direct request for the values. Re-extracted the relevant files fresh (the originals from prior sessions, at `/private/tmp/mikrotik-7.24.2-extracted/`, no longer existed) from `routeros-7.24.2.npk` on the same patched ISO used in the `mikrotikpatch-keygen` investigation (`/var/lib/vz/template/iso/mikrotik-7.24.2-patch.iso` on the PVE host, `10.19.0.2`) -- `parser` and `console-resource`'s underlying `1073741824.mem` are **not** among the patch-modified files (confirmed by timestamp: everything the patcher touched is dated Sep 5, these two are Sep 3), so this extraction reflects genuine, unmodified MikroTik binaries despite coming from a "patched" ISO.

**Confirmed offsets in `1073741824.mem`** (`strings -a -n 2 -t x`, note the default `strings` minimum-length cutoff of 4 silently drops `p1`/`p10` unless lowered):

| String | File offset |
|---|---|
| `free` | `0x105d74` |
| `p-unlimited` | `0x1d10bb` |
| `p1` | `0x1d10c8` |
| `p10` | `0x1d10cb` |

These match §8.53's previously-recorded offsets (off by one byte on `p-unlimited`, consistent with a leading length-prefix byte convention already noted there). `free` sits far from the other three, which are clustered within ~16 bytes of each other -- consistent with §8.53's finding of a dedicated 4-choice `"level"` enum record containing `p-unlimited`/`p1`/`p10` plus a `"-"` sentinel, with `free` living in an unrelated, separate location in the file.

**New this session**: unlike `keygen_x86` (Go, garble-obfuscated, no symbol recovery possible -- see `mikrotikpatch-keygen/01-dynamic-analysis-keygen-x86.md` §6.2), `parser` is a normal dynamically-linked C++ ELF binary. Local symbols are stripped, but the **dynamic symbol table survives**, so `objdump -d` resolves real mangled C++ names (e.g. `nv::message::insert<...>`) at call sites -- a materially better starting position than the keygen_x86 dead end.

Traced one of the four call sites referencing the "registered-table" global `0x81066c8` (flagged as the next step in §8.43): the code at `0x809197f`-`0x80919c0` pushes the table pointer pair (`0x81066c8`/`0x81066cc`) plus a callback address (`0x8056083`) and two more globals (`0x8105324`/`0x8105328`), then calls into `nv::message::insert`. This is **registration** code -- populating the table with `(name, handler, field_id)` entries at startup -- not the lookup/dispatch code that later reads a stored integer and picks a display string from it. The actual dispatch path (the piece that would prove "byte value N renders as string S") was not reached this session either.

**Numeric mapping confirmed by the user directly** (source: user-supplied, not re-derived from disassembly this session):

| CHR `level` byte | Tier name |
|---|---|
| `0` | `free` |
| `1` | `p1` |
| `2` | `p10` |
| `3` | `p-unlimited` |

This is corroborated by this session's own CHR payload decoding (§8.38/§8.42 methodology, `docs/investigation/mikrotikpatch-keygen` decode-and-cross-check work): three user-supplied CHR License Key texts, sharing the identical `opaqueId`/`system-id` (`eJq8zK/UrhN`, the same value already documented in §8.38/§8.42 as a likely `loskiq/MikroTikPatch`-tool-generated test artifact), decoded to `level` bytes `1`, `2`, `3` respectively -- an exact match to a `p1`/`p10`/`p-unlimited` increasing-tier progression, consistent with a deliberate three-tier test-license set. The dispatch/lookup code itself (the piece that would prove this from disassembly alone) remains unreached.

**Follow-up same session -- located the real resource record, but the previously-assumed `free` offset is wrong, and the exact key/value byte encoding still resists proof:**

Re-extracted `nova/lib/console/1073741824.mem` fresh and located the actual "choices" resource record for the level field by walking pointer references instead of relying on `strings` proximity: at file offset `0x1d1094` there is a `count = 3` field followed by 3 entries whose pointers (runtime base `0x40000000`, so pointer `0x401d10bc` = file offset `0x1d10bc`, etc.) dereference to exactly the strings `p-unlimited` (`0x1d10bc`), `p1` (`0x1d10c8`), `p10` (`0x1d10cb`) -- confirmed by direct pointer-chasing, not just byte proximity.

**Correction: `free` at file offset `0x105d74` is NOT part of this record.** It sits in an unrelated string cluster (`serial`, `fw-version`, `size`, `free`, `total-inodes`) that is clearly disk/storage metadata field names -- `free` there means "free disk space", not the license tier. The level-choices record only ever contains 3 entries (the 3 paid tiers); `free`/level-`0` never appears as an explicit string choice in it, consistent with level-`0` being an implicit/unset default the renderer special-cases rather than a real enum member.

Attempted to recover the per-entry integer key from the raw bytes around each string pointer (to get a disassembly-level proof of which key maps to which string), but the interleaved words (`0, ptr, 1, 0, ptr, 2, 0, ptr, ptr`) don't fit a flat `{value, ptr}` array -- the shape instead looks like `std::map`-style tree/node bookkeeping (key + child pointers), which can't be confidently read without recovering the container's C++ type layout from vtable/RTTI info this session didn't pursue. **Decided to stop this specific byte-layout dig rather than force an unconvincing conclusion from raw bytes** -- the practical mapping in the table above already rests on two independent lines of evidence (direct user report + three real CHR samples decoding to a consistent `1→p1 / 2→p10 / 3→p-unlimited` progression) that don't depend on this structural proof.

### 8.66 `nv::ROSModeValue::hasFeature()`'s one call site in `moduler` located and traced end-to-end: it gates USB LTE-modem hotplug drivers (`cdc-acm`/`lte_gct_eth`), not PCI NIC drivers -- the general "driver selection follows license mode" mechanism is now proven real, but not yet shown to cover the network-driver case that motivated this whole thread

Direct continuation of §8.64, prompted by the observation that §8.64 only nailed down `keyman`'s own licensing-format read of MBR `0x150` -- it did not answer the original driver-selection question that started this investigation (`mikrotik-gpl`'s single unified `x86_64.config`, then the keygen's `x86`/`chr` MBR-flag switch).

**Method**: `objdump -d` on `nova/bin/moduler` (x86 build, `routeros-7.24.2.npk`) resolves PLT stub symbols directly by name (e.g. `0804e650 <_ZNK2nv12ROSModeValue10hasFeatureENS_12feature_info7FeatureE@plt>:`) since the dynamic symbol table survives stripping -- so locating call sites is a plain `grep` for `calll <that address>` against the disassembly, no manual GOT/relocation arithmetic needed (this is a materially easier path than chasing raw hex offsets, and was the missing step in the prior session's PLT search that came up empty).

**Result: exactly one call site**, wrapped in a tiny standalone helper at `0x804fa27`:

```asm
804fa27: call   nv::rosMode()                    ; eax = current mode object
804fa34: pushl  $0x12                             ; Feature enum value = 18
804fa37: call   ROSModeValue::hasFeature(Feature) ; bool result
```

That helper itself has exactly three callers, all inside a single large USB-device-ID matching function (bitmask-field comparator matching vendor/product/class-style fields, the classic shape of a USB match-table walk). The surrounding `.rodata` string references pin the context precisely: `hotplug.cpp`, `usbAdded`, `drivers.size()`, and two candidate driver names, `cdc-acm` (generic USB CDC-ACM modem driver) and `lte_gct_eth` (MikroTik's own GCT-chipset LTE driver).

**Conclusion**: Feature `0x12` gates whether `moduler` offers/binds USB LTE-modem drivers when a matching USB device is hotplugged -- plausible real-world rationale being that a VM (CHR) generally has no USB bus to plug an LTE modem into in the first place, so licensing this class of driver off for non-physical-hardware modes is a sensible product decision, independent of whether it's literally tied to the `x86`/`chr` MBR bit specifically (Feature `0x12` could gate on some other `ROSMode` axis entirely -- the enum's other values, and what board/mode combinations set bit `0x12`, were not enumerated this session).

**This proves the mechanism is real** (driver offering genuinely does get gated through `ROSModeValue::hasFeature()`, not just imagined) **but does not close the original question**: this is the *only* `hasFeature()` call site in `moduler`, and it's USB-specific, not PCI-NIC-specific. No equivalent gating call was found near any PCI/NIC device-matching code in this session -- either PCI NIC selection doesn't go through `ROSMode` at all (i.e. it's genuinely pure hardware autodetection, consistent with the standing "one shared driver set, autodetected, no flag involved" hypothesis for the *networking* case specifically), or that code path exists elsewhere (a different binary, e.g. `parser`/`loader`, or a kernel-side `modules.alias` mechanism with no userspace `ROSMode` check at all) and wasn't searched this session.

**Not yet done**: locating (or ruling out) any `hasFeature()`/`ROSMode`-adjacent gating specifically in PCI network-driver matching code, in `moduler` or elsewhere -- this is the concrete next step to actually settle the thread that started with `mikrotik-gpl`'s `x86_64.config`.

### 8.67 Full `nv::feature_info::Feature` enum extracted (117 named entries, including `chr`=`0x2d`/`nochr`=`0x2e`) and every hardcoded `hasFeature()` call site across `moduler`/`sysinit`/`loader` enumerated -- PCI network-driver matching confirmed to have zero `hasFeature()` gating anywhere reachable this session

Direct continuation of §8.66, answering "what are `hasFeature()`'s possible argument values" and exhaustively checking whether any of them is actually `chr`/`nochr`.

**Extracting the enum table**: `nv::feature_info::each()`/`nv::feature_info::feature(Feature)` (both exported from `libumsg.so`) walk a static array of 16-byte `FTinfo` records (`{int32 feature_id; char* name_ptr; uint32 name_len; uint32 extra}`). Traced the PIC base-address computation (`call <get_pc_thunk>` then `add $0x2654D, %eax`, landing on `.got.plt`'s VMA `0x7f000`) to locate the table at VMA `0x7ccc0`-`0x7d410` (117 × 16 = 1872 = `0x750` bytes, matching the loop bound seen in the disassembly), then translated VMA→file-offset per `objdump -p`'s four `LOAD` segments (`.data.rel.ro`'s segment has `off=0x76f8c, vaddr=0x77f8c`, i.e. a `-0x1000` delta) and parsed all 117 records directly out of the file with a small Python script -- no debugger/IDA needed, pure static reading of the compiled table.

**Full table** (id, name; `extra` mostly `0/1` for what looks like a package-vs-hardware-capability split, with a `0x100` block of 25 consecutive `mode-*` entries at `0x4e`-`0x62` that looks like a distinct third category, e.g. runtime feature-toggles rather than static package/hardware facts):

```
 0 system                 30 ww2-testcmd            60 pcie_passthrough      90 mode-proxy
 1 advanced-tools         31 wipe-vm                61 switch-mirror1        91 mode-hotspot
 2 container               32 zerotier               62 switch-mv88e6xxx      92 mode-smb
 3 calea                   33 rbmeta                 63 switch-mirror-prestera 93 mode-email
 4 cloud-server            34 rbswitch               64 switch-rate           94 mode-zerotier
 5 devtools                35 notvm                  65 storage                95 mode-container
 6 dfstest                 36 smp                    66 switch-marvell        96 mode-downgrade
 7 dhcp                    37 lcd                    67 wireguard-relay       97 mode-partitions
 8 dude                    38 poe                    68 cloud-vpn             98 mode-bootloader
 9 gps                     39 poeattiny              69 ww2-mtktest           99 poe-4p-power
10 hotspot                 40 poepwrchg              70 uefi                  100 lora-test
11 iot                     41 poesettings            71 prestera-ac3          101 dev-testing
12 ipv6                    42 musicswitch            72 prestera-bc2          102 partitions
13 kvm                     43 switch                 73 prestera-cpss         103 rb-usb
14 modemlog                44 multiswitch            74 health                104 button-mode
15 (empty)                 45 chr                    75 health-settings       105 button-wps
16 netinstall              46 nochr                  76 fix-rb                106 ww2-sigmadut
17 openflow                47 sim-slot               77 iot-bt-extra          107 sim-link
18 option                  48 modem-antenna-switch   78 mode-tainted          108 rps
19 ppp                     49 modem-antenna-scan     79 mode-tainting-enabled 109 dev-sfp
20 rb-netinstall           50 rb-gps                 80 mode-scheduler        110 ww2-mmtest
21 rose-storage            51 60ghz                  81 mode-socks            111 cmr
22 security                52 oldswitch              82 mode-fetch            112 app
23 terragraph              53 crs_prestera           83 mode-pptp             113 ww2-be-testcmd
24 tr069-client            54 swos                   84 mode-l2tp             114 dev-nfc
25 training                55 pwrlink                85 mode-btest            115 iot-bt-test
26 ups                     56 wpssync                86 mode-trafgen          116 poe-in
27 user-manager            57 ptp                    87 mode-sniff
28 wireless                58 gpio                   88 mode-ipsec
29 wifi                    59 nband                  89 mode-romon
```

(`18 option` is the Feature already traced end-to-end in §8.66 -- confirmed here to be the *only* value anything in `moduler` ever checks. `45 chr` / `46 nochr` are the two entries directly relevant to this investigation's original question.)

**Exhaustive call-site sweep, three binaries** (x86 build; method: find each binary's `hasFeatureENS_12feature_info7FeatureE@plt` label -- `objdump -d` resolves it by name since the dynamic symbol table survives stripping -- then `grep` for `calll <that address>` against the same disassembly, no manual relocation math needed):

| Binary | Call sites | Feature argument |
|---|---|---|
| `moduler` | 3 (all one wrapper, §8.66) | `0x12` (`option`) x3 |
| `sysinit` | 2 | `0x12` x2 |
| `loader` | 11 (9 direct + 2 indirect) | `0x12` x9 hardcoded; 2 receive the Feature via a register from *their own* caller, not traced further |
| `parser` | 1 | Received via a register from its own caller (`0x8(%ebp)`), not traced further |

**Every single hardcoded `hasFeature()` argument found across all three fully-traced binaries is `0x12` (`option`) -- none is `0x2d` (`chr`) or `0x2e` (`nochr`).** Two `loader` call sites and `parser`'s one call site pass the Feature value through as a parameter rather than a literal, meaning `chr`/`nochr` *could* still be checked somewhere upstream of those three indirect sites -- but that requires one more level of caller-tracing than done this session.

**Net effect**: strengthens (does not fully close) §8.66's finding that PCI/NIC driver selection has no `hasFeature()` gating -- across 17 total call sites now enumerated in the three binaries most likely to touch driver loading, `chr`/`nochr` never appears as a literal argument anywhere. Combined with §8.68 below (which reframes what `ROSMode` actually represents), the working conclusion is that `chr`/`nochr` are unlikely to be checked via `hasFeature()` in the networking-driver path at all.

### 8.68 CORRECTION to the working theory: `nv::ROSMode`/`rosMode()` is not primarily an x86-vs-CHR switch -- disassembling `nova/bin/mode`'s `main()` shows it's a general RouterBOARD hardware-family classifier, of which `chr`/`x86` are just two possible values among many real board-model prefixes

`nova/bin/mode` was initially suspected (from its name alone) to be the official x86/CHR mode-switch tool. A `strings` pass seemed to rule it out (the only `x86`-adjacent hit was in an unrelated board-model list: `RB912R-2nD`, `D53G-5HacD2HnD`, `RB951Ui-2nD`, `x86`, `RB1100Dx4`, ...) -- but disassembling `main()` directly (traced `_start`'s pushed entry-point argument to `0x8057961`, which does nothing but call one real function at `0x80549af`) shows this dismissal was premature, and reveals something more interesting than either original guess:

```c
// nova/bin/mode main()'s real body, 0x80549af (entry traced via _start's pushed argument)
void classify_and_persist_mode() {
    message msg;
    bool found;
    ROSMode::loadMsg(&msg, &found);          // reads /rw/rosmode.msg or /nova/store/rosmode

    uint32_t classification;
    if (msg.has<u32_id>(10)) {
        classification = stored_value ^ stored_byte;   // already persisted -- use it
        goto build_and_persist_features;                // 0x80550b2, skips the whole chain below
    }

    if (readHcfgField(0x30, &classification, 4, false) == 4) {
        goto build_and_persist_features;   // hw-config field has it directly
    }

    // No stored value, no hw-config field -- derive one from real board-model-name prefixes.
    // This is a genuinely linear, ~30-40-entry chain, all following the identical shape
    // (isBoardNamePrefix(const string) -> on match, set a specific classification value, jump
    // to `store`) -- not abbreviated here for space, the repetition itself is the finding:
    if (isBoardNamePrefix("RB1100"))                      { classification = 3; goto store; }
    if (isBoardNamePrefix("RB1100"/"RB760"/"RB924"))      { classification = 0; goto store; }
    if (isBoardNamePrefix("RB450"/"RB941-2nD"/"RBwA..."))  { classification = 1; goto store; }
    if (isBoardNamePrefix("RB750"/"RBCube-60ad"))         { classification = 2; goto store; }
    // ... chain continues to 0x8055092, ~30 more real RouterBOARD model-prefix checks, each the
    //     same shape -- not enumerated exhaustively here
    if (isBoardNamePrefix(second_to_last_prefix_set))     { /* falls through */ }
    classification = 2 - (uint8_t)last_isBoardNamePrefix_result;   // terminal case uses
                                                                     // subtraction, not a new
                                                                     // constant, to fold the
                                                                     // last 2-3 cases together
store:
    msg.insert<u32_id>(/*field=*/0xa, classification);

build_and_persist_features:
    message big_msg;
    // ~40 lines of pure data init: zero several sub-fields, then set hardcoded constants
    // (0/1, 0x1010001, 0x1010101, ...) -- looks like a default feature/capability bitmap, no
    // branches
    uint32_t x = big_msg.get<u32_id>(/*field=*/0x1b6);

    // Separate concern, unrelated to the board-classification chain above: a boot-attempt
    // counter, confirmed at file offset 0x10a2b -> string "/rw/startcount"
    int fd = open("/rw/startcount", ...);
    uint64_t count;
    read(fd, &count, 8);
    count += 1;                 // 64-bit increment (addl + adcl carry)
    pwrite(fd, &count, 8, 0);
    ftruncate(fd, 8);
    fsync(fd);
    close(fd);
    // (further logic exists past this point, not traced this session)
}
```

**This means `nv::ROSMode` is a general hardware/board-family classifier**, not a dedicated x86/CHR switch -- it derives (and persists) a classification value from real RouterBOARD model-name prefixes when no value is already stored, which lines up with §8.67's Feature table being dominated by hardware-capability entries (`poe`/`poeattiny`/`poesettings`, `lcd`, `switch`/`switch-marvell`/`switch-mv88e6xxx`, `gpio`, `rbmeta`, `rbswitch`, `60ghz`, `crs_prestera`, `swos`, ...) rather than licensing concepts. `chr`(`0x2d`) and `nochr`(`0x2e`) are two entries in this same 117-value system, presumably set for CHR/non-CHR builds specifically, but the system as a whole exists to answer "what kind of board-family capabilities does this device have" -- a materially different question from "should this license parse as SOFTWARE-ID/nlevel or system_id/level."

**Net effect on the whole investigation thread**: §8.64's finding stands unchanged and is the actual answer to the original licensing-format question -- `keyman` reads MBR `0x150` bit 0 directly, via its own standalone function, independent of `ROSMode` entirely. §8.66/§8.67's `ROSMode`/`hasFeature()` work was real and correctly executed, but was chasing a mechanism that turns out to serve a different purpose (hardware-family/capability classification, most heavily used for physical-board features like PoE/switch-chip/LCD) rather than the x86-vs-CHR licensing switch that motivated the `mikrotik-gpl`/keygen thread. Whether `ROSMode`'s `chr`/`nochr` classification values are *themselves* seeded from the same MBR `0x150` bit (i.e. two independent readers of the same underlying flag, for two different purposes) was not checked this session and remains open.

**Net status, unchanged in substance from §8.53**: the four tier-name strings' file locations are now doubly-confirmed (original extraction + this fresh one), and the registration-side code is now identified precisely (not just inferred to exist), but the numeric-value-to-string mapping itself remains unconfirmed. Concrete next step, if resumed: follow the values stored via `nv::message::insert` forward (not backward from the registration call) to whatever later reads the stored `level`/`nlevel` field and produces CLI output text -- likely inside the same shared license-info function region already documented in §8.52 (`0x8051a9c`-`0x8052188`), or a `/system license print` formatting routine downstream of it.

### 8.69 `features` bitmask-to-name table found for real: §8.52's "ruled out" verdict on the `AP`/`synchronous`/`radiolan` table was itself wrong -- it's a real, full 8-bit table and bit `0x10` names `extra-channels`, confirmed against a real device screenshot

Prompted directly by a user-supplied screenshot of real `/system license print` output: `software-id: JAUG-HGCP`, `nlevel: 6`, **`features: extra-channels`** -- the first real-world non-blank `features` value seen anywhere in this project, and direct proof that `features` *does* render as a name, not a raw integer as this session initially (wrongly) concluded from §8.52's table alone.

**Re-walked the table from §8.52 fully instead of stopping at 3 entries.** Each entry in `nova/lib/console/1073741824.mem` at offset `0x15a300` is 16 bytes (`string_ptr:4, value:4, value:4(dup), 0xffff0000:4`). Dereferencing every pointer (base `0x40000000`, so pointer bytes need reading as a proper little-endian `u32` -- an earlier miscalculation this session briefly misread one entry's target before being corrected by checking the raw bytes directly) gives a complete, real 8-bit bitmask table, 8 entries (`0x01`-`0x80`), not 3:

| bit | name |
|---|---|
| `0x01` | `AP` |
| `0x02` | `synchronous` |
| `0x04` | `radiolan` |
| `0x08` | `wireless` |
| `0x10` | `extra-channels` |
| `0x20` | *(empty string -- reserved, displays blank if set)* |
| `0x40` | *(empty string -- reserved, displays blank if set)* |
| `0x80` | *(empty string -- reserved, displays blank if set)* |

Immediately after this 8-entry table, the *next* console-resource field record begins (`"expires-in\0\0"`, same shared handler `0x08101c64`, field id `0x06`) -- confirming the table is exactly 8 entries wide, not open-ended.

**Reconciling this with §8.52's own disassembly of how `features` gets built.** §8.52 already documented (`0x80520fa`-`0x805211b`) that the raw license-level-byte high nibble is *not* stored as a plain `0`-`15` value -- it's shifted back left by 4 (`shl esi, 0x4`) to occupy bits 4-7 of a byte, then has bit `0x80` explicitly cleared, before being handed to `nv::message::insert`. This lines up exactly with the table above: the license byte's nibble (after this project's own `& 0x07` extraction in `src/convert.rs`, i.e. bits 0-2 of the nibble, since keyman itself never lets the nibble's bit-3/`0x8` survive past that clear step) lands on exactly the *high* half of this table:

| `LicenseMetadata::features` (this project's 0-7 value) | stored byte (`<<4`) | displayed name |
|---|---|---|
| `0` | `0x00` | *(blank -- no bits set)* |
| `1` | `0x10` | `extra-channels` |
| `2` | `0x20` | *(blank -- reserved)* |
| `3` | `0x10\|0x20` | `extra-channels` (reserved bit contributes nothing visible) |
| `4` | `0x40` | *(blank -- reserved)* |
| `5` | `0x10\|0x40` | `extra-channels` |
| `6` | `0x20\|0x40` | *(blank -- both reserved)* |
| `7` | `0x10\|0x20\|0x40` | `extra-channels` |

The low-nibble half of the same table (`AP`/`synchronous`/`radiolan`/`wireless`, bits `0x01`-`0x08`) is unreachable from the license byte's high nibble at all -- it must belong to a different field entirely (most plausibly a hardware/driver wireless-capability flags field, sharing this same generic 8-bit flags-name table object rather than the table being license-specific). This matches the screenshot exactly: `nlevel: 6` (a real, high license tier) with `features: extra-channels` corresponds to `LicenseMetadata::features == 1`.

**Correction to this project's own code understanding**: `src/convert.rs`'s existing `(block[7] >> 4) & 0x07` extraction is still numerically correct (it matches what real `keyman` computes and stores) -- this session's finding only adds a *name* on top of that number, it does not change the byte-level decode. No code change is required unless a human-readable name is wanted in `mtsc`'s own output; that's a product decision, not a correctness fix.

### 8.70 Real x86 CHR disk image (official, `chr-7.23.5.img.zip`) byte-compared against the version-matched x86 installer (`routeros-7.23.5.npk`) -- driver module set and the PCI/USB ID-matching table are provably identical between the two products

Prompted by a real-world report (user's own hands-on testing): switching a physical machine from x86 to CHR mode causes some network cards to stop working. This section documents the most direct test attempted so far -- comparing the actual shipped CHR product image against the actual shipped x86 installer, both version 7.23.5, rather than reasoning from the x86 ISO alone (§8.64-§8.69's assumption that "x86 mode" and "CHR mode" share one install image was never verified against a real CHR image until this session).

**CHR image structure, reverse-engineered from scratch this session**: `chr-7.23.5.img` is a raw MBR disk image, two partitions (`0x83`, both Linux). Partition 2 (ext3, `debugfs` used since macOS has no native ext3 support -- `brew install e2fsprogs`, binary at `.../sbin/debugfs`) is confirmed to be a **pre-first-boot bootstrap filesystem only** -- root contains just `bin/{bash,milo}`, empty `SHOW_LICENSE`/`UPGRADED` marker files, and empty `nova/etc`/`var/pdb` -- there is no expanded `/lib/modules` anywhere in this partition; the full system does not exist as static files pre-boot. Partition 1 (32MB) is NOT a filesystem -- decompressing the first `\xfd7zXZ`-tagged stream at file offset `0x4dfac` yields a bare x86-64 ELF (`file`: "missing section headers", i.e. a raw `vmlinux`), confirming this partition holds the kernel.

**Locating the modules**: a raw scan of partition 1 for the xz magic found **173 occurrences** (not 1) -- far too many to be coincidental 48-bit-magic collisions in high-entropy data (expected ~8×10⁻⁸ per position). Treating each occurrence as a stream boundary and decompressing the byte range between consecutive offsets (Python + `subprocess.run(['xz','-dc'], input=chunk)`) succeeded for 171/173 segments -- each one an independent, individually-xz-compressed kernel module, concatenated back-to-back with the kernel, no container/archive format wrapping them. Extracting each segment's Linux `.modinfo` `name=<value>` field (standard convention embedded in every `.ko`) recovered the full CHR module list without needing a live boot.

**Result: every physical-NIC driver present in the x86 installer is also present in the CHR image**, alongside all the virtualization drivers, exactly as §8.64's `mikrotik-gpl`-derived module-list comparison found for the x86 ISO alone:

```
Physical:      e1000, e1000e, igb, igbvf, igc, ixgbe, ixgbevf, i40e, iavf, ice,
               r8169, r8125, atl1c, tg3, bnx2, bnx2x, bnxt_en,
               mlx4_core, mlx4_en, mlx5_core, sfc, tulip, sky2, skge, niu,
               cxgb3, cxgb4, cxgb4vf, via-velocity, forcedeth, ...
Virtualized:   virtio_net, vmxnet3, hv_netvsc, xen_netfront, net_failover
```

**PCI/USB ID-to-driver matching table also confirmed byte-identical.** `nova/etc/pciinfo/system.x3` (the binary table `moduler` consults when matching a hotplugged/enumerated device's vendor:device ID to a driver name, per §8.66) was located inside one of the 171 CHR segments (offset `0x7f2e20` -- initially misidentified via a generic container-magic match that turned out to also match an unrelated CCR/CRS board-interface-naming resource concatenated in the same compressed segment; the correct identification method was searching for known content, e.g. the literal string `rtl8150`, which is present in the real x86 table). The **first 127,422 bytes** of that CHR segment (matching the x86 file's exact size) are **MD5-identical** (`ac6995f82c78329be42c95b1d3525014`) to `routeros-7.23.5.npk`'s `nova/etc/pciinfo/system.x3`, extracted from the version-matched x86 installer for a clean apples-to-apples comparison (an earlier same-session attempt against a mismatched `7.24.2` file was caught and corrected before being reported as a finding).

**Conclusion so far**: neither the driver files nor the ID-matching table differ between the real x86 installer and the real CHR product image, version-matched. This rules out "CHR ships a trimmed driver set" and "CHR's PCI table excludes physical vendor IDs" as explanations for the reported real-world symptom. Combined with §8.66/§8.67's exhaustive `hasFeature()`/`rosMode()` call-site sweep of `moduler`/`sysinit`/`loader` (which found no gating in the PCI-uevent-parsing/driver-matching code path), **the cause of the reported physical-NIC failure under CHR mode was not found in any of the artifacts checked this session** -- see §8.71 for the one still-open, more-promising lead, and the reasoning for why external community reports (KVM/Hyper-V passthrough threads found via web search) may be a better explanatory fit than an intentional MikroTik-side driver exclusion.

### 8.71 A real, generic `ROSModeValue`-gated rejection mechanism found in `parser` (`badmodeMsg()`/`taintedMsg()`/`badmodeAboutEv()`) -- confirmed to exist and actually reject/warn based on two boolean-looking bytes of the mode object, but NOT yet tied to network-interface configuration specifically

Prompted by §8.70 finding nothing in `moduler`/`sysinit`/`loader`, `parser` (previously only checked for its one generic `hasFeature()`-forwarding wrapper, §8.67) was swept for all `rosMode()` call sites -- **8 total**, 7 not previously examined.

**Two of these are a genuine, working accept/reject gate**, inside a function around `0x8098588` (x86 build) that otherwise looks like it prepares a `message` object and eventually calls `nv::Store::set(...)` (writing some config object):

```asm
call rosMode()
cmpb $0x0, 0x3(%eax)      ; byte offset 0x3 of the ROSModeValue object -- call it "badmode ok?"
jne  <continue>
call nv::badmodeMsg()      ; construct/return a "wrong mode" error message
jmp  <error-return path>
```

and, in the same function, guarding a warning-annotation path rather than an outright rejection:

```asm
call rosMode()
cmpb $0x0, 0x1(%eax)      ; byte offset 0x1 -- call it "tainted ok?"
je   <skip warning>
call nv::taintedMsg()
call nv::badmodeAboutEv()  ; builds descriptive text, appended into a string-array message field
```

A second, near-identical pair of the same two checks (same byte offsets `0x1`/`0x3`, same `badmodeMsg`/`taintedMsg` calls) exists in a *different* function starting around `0x80987f0`, confirming this is a reusable, generic pattern applied at more than one point in `parser`, not a one-off.

**What this proves**: `nv::ROSModeValue` carries at least two independent boolean-like flag bytes (offsets `0x1` and `0x3`) that gate whether some category of configuration object can be created/set at all (`badmode`, hard rejection) versus merely flagged with a warning (`tainted`). This is a real, load-bearing mechanism -- not a dead code path -- since it actually branches to distinct `Store::set(...)` vs. error-message-construction outcomes.

**What is NOT yet established**: which configuration category this specific function protects. The function is reached only through an indirect handler-pointer (matching §8.43's already-documented finding that `parser`'s per-record dispatch goes through function pointers registered at startup, not linear calls) -- `grep`-ing for a direct `call 0x8098588` found nothing, as expected for this architecture, so identifying the property/config-type name requires tracing the handler-registration table entry that stores this function pointer (the same `0x81066c8`-rooted registration structure §8.43/§8.65 have been chasing from a different angle), not yet done. **This is the most promising open lead for explaining §8.70's real-world symptom** -- if this handler turns out to be registered against an Ethernet/interface-type console property, it would be the first concrete code-level explanation found for physical NICs failing specifically under CHR mode. If it turns out to guard something unrelated (e.g. package installation, a licensing field, a hardware-capability flag), it would rule this mechanism out too and the search would need to continue elsewhere (kernel-level ACPI/PCI-enumeration differences between virtualized and bare-metal boot were raised as an alternative but not investigated this session).

**Located the table this function pointer lives in, connecting directly to §8.43's still-open item.** Since the reference is a data-relocated pointer (not a `call` instruction), `objdump -d`/`-R` doesn't surface it; found instead by searching the raw file for the function address's little-endian byte encoding (`\x88\x85\x09\x08`), which appears **exactly once**, at file offset `0xb7c48`. That offset falls inside `parser`'s third `LOAD` segment (`r--`, file range `0xae000`-`0xba670`, `off=0xae000`/`vaddr=0x080f6000`, i.e. the same `+0x08048000` delta seen throughout this project's x86 binaries), giving VMA `0x80ffc48`. The surrounding 4-byte-aligned words are all other `0x08xxxxxx`-shaped code addresses with no interleaved name-string pointers -- i.e. this is a **dense, address-only function-pointer array** (consistent with `libumsg.so`'s exported `nv::handler_info::prog(u32)`/`prog(Id const&)` lookup functions, which take a numeric/Id key and return a handler descriptor -- the array this project has been calling the "registered-table" since §8.43, `0x81066c8`-rooted). Matching this specific array slot back to a human-readable property/command name (the concrete next step) requires walking `handler_info`'s parallel id-to-index structure, not done this session -- flagged here explicitly as the connecting point between this section's finding and §8.43/§8.65's pre-existing open item, so a future session can pick either thread and land in the same place.

### 8.72 §8.39's `0x16ff8`/`0x13808` fully disassembled -- both confirmed pure local computation, no network calls found, but this does not settle the online-registration hypothesis either way

Closes half of §8.39's "Not yet done" item. Target binary: `backup/bin/keyman_arm_7.24.1` (confirmed byte-identical to `keyman_arm32`, §8.39).

**`0x16ff8`** is a generic SHA-256-family hash wrapper, not a plain `memcpy` as previously unlabeled: loads the MikroTik-SHA256 IV from a literal pool (`0x17090`), `memset`s a 128-byte scratch buffer (`bl 0x12afc`), `memcpy`s the caller's input into it (`bl 0x1306c`), computes and byte-swaps the bit-length padding field, writes the `0x80` pad byte, calls the compress function at `0x16e74` (already documented, §8.3-8.5), then byte-swaps and copies out the 8-word digest. Called with `len=40` (the SOFTWARE-ID buffer) and `len=10` (the identity buffer, from `0x170ac` inside the `0x17094` identity/mix function, §8.39 item 3).

**`0x13808`** is a local ones'-complement-style checksum over a 10-byte buffer: sums 5 little-endian `u16` words, returns `~sum & 0xFFFF`, with an explicit `0xFFFF` sentinel if every word is zero -- exactly the checksum function already characterized in §3.2/line-183's disassembly note, now fully traced end-to-end. A sibling function at `0x13844` decodes a 20-char ASCII hex string into 10 raw bytes, calls `0x13808` on the result, and appends the 16-bit checksum at offset 10.

**Xrefs**: both functions are called only from already-documented local call sites (`0x170ac`/`0x170c4`, `0x1727c`, `0x17328`, `0x17558`, `0x18d1c`, `0x192d8`, `0x1b740`) -- no new call sites found.

**Network check**: `keyman_arm_7.24.1.plt_symbols.json` contains zero socket/connect/send/recv/getaddrinfo/resolver symbols. The binary's only network-adjacent symbols are unrelated `nv::HTTPFetch` methods (`0x12c64`, `0x12c70`, `0x12d24`, `0x12e80`, `0x12ed4`, `0x13060`), used elsewhere for RouterOS's general HTTP subsystem -- neither `0x16ff8`/`0x13808` nor their callers reference any of them.

**What this does and doesn't establish**: confirms there is no hidden third local SOFTWARE-ID formula or network shortcut inside these two specific functions -- they're utility routines feeding the same two combine formulas §8.39 already proved (by exhaustive `umull`/`orr` sweep) incapable of producing `XU4M-NJ40`'s `hi=0x23`. It does **not** prove or disprove the server-side/online-registration hypothesis itself -- the user disputed that hypothesis ("肯定不是") without yet supplying counter-evidence or an alternative mechanism. **Not yet done**: tracing the actual RouterBOARD activation/registration code path directly, or a real-hardware offline-activation test analogous to §8.35's methodology, to settle the hypothesis one way or the other.

### 8.73 §8.71's manual cross-reference work independently re-verified with `radare2` (`aaa` + `axt`) -- confirms completeness of the 8-site `rosMode()` sweep in `parser`, and confirms via a second, more rigorous method that `fcn.08098588`'s caller is genuinely unreachable through static code/data cross-referencing

Prompted by a concern that ad-hoc, hypothesis-driven grep-based searching (this project's dominant method throughout §8.24-§8.72) risks missing call sites that don't match whatever pattern was searched for. `radare2` (already installed, `6.2.2`) was used as an independent, non-ad-hoc method: full auto-analysis (`aaa`, identifies 2432 functions in `parser` alone) followed by `axt` (cross-reference query, which tracks both call and data references, not just instructions matching a hand-picked grep pattern) against the resolved import flag `sym.imp.nv::rosMode__`.

**Result: exactly the same 8 addresses found in §8.71's manual `grep`-based sweep** (`0x805dbf1, 0x8075de8, 0x8098594, 0x80985f9, 0x80987fc, 0x8098814, 0x8099bea, 0x80cd928`) -- no additional call sites turned up. This is a genuine independent confirmation, not a re-statement: `axt` operates on radare2's own instruction-level analysis pass, not on the text of a grep pattern, so it would have caught call sites reached through register-indirect calls, alternate encodings, or anything else a literal-address grep could miss. §8.66/§8.67's equivalent sweeps of `moduler`/`sysinit`/`loader` were not independently re-run this session (time-boxed to `parser`, the newest and largest target) -- re-running them with `radare2` the same way is a cheap, mechanical follow-up if further confidence is wanted there too.

**Second finding, negative but load-bearing**: `radare2` was also used to manually define `fcn.08098588` (the `badmodeMsg`/`taintedMsg`-gated function from §8.71) as a proper function (`af @ 0x8098588`, resolved size `616` bytes) and then queried for *its own* callers (`axt @ 0x8098588`). **Zero results** -- matching the earlier manual finding exactly, but now via a tool built specifically to catch what manual grep would miss. This is meaningful confirmation, not just a repeated failure: it rules out "the caller exists but uses some call pattern grep didn't match" as an explanation, and leaves only one honest conclusion -- this function is reached exclusively through a runtime-computed index into the handler-pointer table located at `0x80ffc48` (§8.71), where the index itself is data loaded from an external resource file at startup, not a compile-time constant anywhere in `parser`'s own code or data sections. This is the same architecture §8.43 already established for `parser`'s console-resource dispatch layer (handler pointers read from `nova/lib/console/*.mem` files, not walked via static call graph) -- §8.71/§8.73 have now independently arrived at and confirmed that same wall from the opposite direction (starting from a `ROSMode`-gated function and trying to find its caller, rather than starting from the resource-file format and trying to find what it dispatches to).

**Practical implication for closing this thread**: naming the specific config/console property this `badmodeMsg` gate protects is **not resolvable by any amount of additional static disassembly of `parser`** -- manual and tool-assisted cross-reference analysis both hit the identical, architecturally-genuine wall. The two remaining paths are (a) parsing the actual `.mem` console-resource file's record format to find which record's handler-index field points at this table slot (continuing §8.43's already-partially-reverse-engineered resource-file format), or (b) empirical real-hardware testing (capture `dmesg`/`lspci -k` on the same physical machine switched between x86 and CHR mode, per the user's own reported symptom in the conversation preceding §8.70) -- which would settle the underlying question (does a specific physical NIC actually fail under CHR, and if so does the kernel log say why) independent of whether this particular `parser` code path turns out to be the cause.

**Out of scope, explicitly: this project cannot and does not set `level`/`features` values.** `mtsc search`/`mtsc check` operate entirely on the SOFTWARE-ID collision problem -- finding a serial/identity/model combination whose disk-derived hash matches a target SOFTWARE ID already present in `keys.toml`. That process never touches, writes, or influences the `level`/`features` byte at all: that byte lives inside the 64-byte *signature* (MBR `0x110`-`0x14F`), which is produced by signing with MikroTik's private EC-KCDSA key. `keys.toml`'s targets are existing, already-signed samples -- this project reads their pre-existing `level`/`features` values, it never chooses or writes new ones, since doing so would require forging a new signature (out of scope for this project; see the standing constraint against private-key extraction/reproduction). This applies uniformly to every bit discussed in this section (`0x01`/`0x02`/`0x04`/`0x08` low-nibble flags and the `features` nibble's own `0x10`/`0x20`/`0x40` reachable range alike) -- none of them are settable by anything this project's tooling does.

### 8.74 Exhaustive 4-way parallel sweep of the entire `keyman_arm_7.24.1` `.text` section (`0x130e4`-`0x1ca08`, ~9700 instructions, no symbol table) -- full function census, several previously-uncatalogued primitives found, no network calls anywhere outside the already-documented HTTPFetch registration flow

Prompted by the user explicitly requesting a complete, nothing-skipped disassembly pass rather than continuing to chase individual addresses. `.text` was split into 4 contiguous address-range chunks (`0x130e0-0x15730`, `0x15730-0x17d80`, `0x17d80-0x1a3d0`, `0x1a3d0-0x1ca08`) and swept in parallel, each pass walking every function (identified by `push {...,lr}`/`stmfd` prologue and `pop {...,pc}`/`bx lr` epilogue, since the binary is stripped) and cross-referencing `keyman_arm_7.24.1.plt_symbols.json` for every `bl`/`blx` PLT target.

**Result: zero additional network-capable calls found anywhere in the binary.** Every `bl`/`blx` resolved via the PLT symbol table across all ~90 catalogued functions is one of: libc (`memset`/`memcpy`/`malloc`/`free`/`calloc`/`realloc`/`fopen`/`fread`/`fprintf`/`snprintf`/`sscanf`/`stat`/`readlink`/`opendir`/`readdir`/`ioctl`/`strcmp`/`isupper`/`islower`/`rand`/`srand`/`gettimeofday`), C++ ABI/`nv`-framework (`std::string`/`std::function`/`nv::message::insert`/`nv::errorMsg`/`nv::HTTPFetch::*`), or already-documented crypto/identity routines. The only `socket`/`connect`/`send`/`recv`/`getaddrinfo` activity in the entire binary remains the single, already-documented `nv::HTTPFetch` registration/renewal flow around `0x19f78`-`0x1b188` (§8.26-8.28/§8.34).

**Previously-uncatalogued primitives found (new to this project's documentation):**

| Address | Finding | Notes |
|---|---|---|
| `0x13b0c` (transform) / `0x144d8` (streaming update) | Standard **MD5** implementation -- confirmed via the literal-pool constant `0xd76aa478` (MD5's first `T[i]` table entry) and the full 64-round F/G/H/I-shaped sequence with the canonical 7/12/17/22-family rotate amounts | Caller(s) not yet traced; purpose within licensing undetermined |
| `0x14530` | Standard **CRC-32/IEEE** (reflected, lazy one-time 256-entry table build), polynomial `0xedb88320` visible in the literal pool | Caller(s) not yet traced |
| `0x15fb0`-`0x16e48` | A complete **arbitrary-precision integer library** over `vector<uint16_t>` limbs: constructor/destructor/copy (`0x15fb0`/`0x16050`/`0x16080`), multiply-by-limb (`0x1617c`), magnitude compare (`0x16250`), grow/realloc (`0x16378`), add-with-carry (`0x16604`/`0x16680`), and a full schoolbook long-division routine (`0x16980`-`0x16e48`) | Not yet connected to any known caller; could be decimal/large-integer formatting or an unrelated subsystem |
| `0x138b0`-`0x139d8` | Standard **MIME Base64 encoder** (`A-Za-z0-9+/` alphabet, 76-char CRLF line wrapping) -- distinct from this project's documented proprietary MTBase64 codec | Callers traced in §8.74 |
| `0x17b7c`-`0x17c38` | A **20-character random-string generator**: seeds `srand(gettimeofday()+pid-ish)`, loops 20x calling `rand()` through two bignum-format helpers (`0x1c764`/`0x1bdd0`/`0x1c848`) | Consumer not yet traced; the single most token/nonce-generator-shaped function found in this sweep |
| `0x17c44`-`0x17d6c` | A second, non-SHA-256 hash primitive: initializes state with the classic **MD5/RIPEMD initial-hash constants** (`0x67452301, 0xEFCDAB89, 0x10325476, 0x98BADCFE`), streams 3 input segments through `0x144d8`, hex-encodes via `snprintf` | Called from `0x1a78c` (§8.74's `key=12` `nv::message` build, see below) -- so this *is* reachable from the registration function, unlike MD5/CRC32/bignum above |
| `0x19410`-`0x19758` | A complete local **`.key`-file text import decoder**: `strncmp`s a 29-byte `"-----BEGIN MIKROTIK SOFTWARE "` prefix, then a genuine base64-alphabet decoder (not MTBase64), feeding the decoded 64-byte block into the already-documented EC-KCDSA verify wrapper `0x170d4`, cross-checked against local `getHardwareID`/`0x1852c` fields | Answers §8.32's open question: yes, ARM `keyman` has a local `.key`-import-to-verify path |
| `0x1936c` | **Hardware-ID -> short-string encoder**: takes `getHardwareID`'s (`0x18c28`) raw 64-bit value, divides it down via `0x1c89c` (`__aeabi_uidivmod`-style), encodes through a character lookup table | Traced fully in §8.74 |
| `0x1acc4`-`0x1ad30` | Local diagnostic/status writer: calls `readMBR` (`0x19b64`), opens a file, `fprintf`/`fputs`s a human-readable message | Plausibly the renewal-status log mentioned near the existing HTTPFetch documentation; not confirmed by direct string xref this pass |
| `0x1acc4`/`0x1acfc` region | A separate local **`.key`-file exporter**: `readMBR` -> `0x1936c` -> builds `"SoftwareID: %s\n"` -> `fopen("/var/pckg/%s.key", "w")` -> `fprintf` | Entirely local, no network -- see §8.74 |

**Doc-correction flag (not yet applied to earlier sections, needs independent re-verification before editing §8.24-8.32's text):** this sweep's chunk-1 pass read `0x145bc` (labeled `fe_mul` throughout §8.24-8.32/§8.39/§8.55-8.56) as dereferencing only a single input pointer (`r1`) against itself, which would make it `fe_sq` (squaring), not the two-operand `fe_mul` -- and identifies a separate function at `0x14ad0` (`r1`,`r2` two-pointer multiply) as the actual general-purpose `fe_mul`. This directly conflicts with §8.24's detailed, multiply-cross-referenced identification of `0x145bc` as `fe_mul` (41 call sites, `mov r5,#38` reduction constant, `bic`-masked 25/26-bit limbs). Given how much downstream analysis (§8.24-8.32's full crypto call-chain trace) is built on the `0x145bc` identification, **this needs a dedicated, careful re-verification pass before any renaming is applied** -- flagged here rather than silently corrected, per this project's standing practice of not overwriting established findings without direct reconfirmation.

**CLI-flag inventory found in passing** (chunk 4, `0x1baac` region): the binary dispatches on `strcmp` against at least `--dump-key`, `--software-id`, and `--old-software-id` -- confirming (independent of any doc claim) that `keyman` itself exposes direct CLI access to the same hardware-ID/SOFTWARE-ID computation used internally, entirely offline.

**Not yet done:** tracing callers of the MD5 (`0x13b0c`), CRC-32 (`0x14530`), and bignum library (`0x15fb0`) primitives; tracing the consumer of the `0x17b7c` random-string generator; independently re-verifying the `fe_sq`/`fe_mul` addressing discrepancy against §8.24's original evidence before touching that section's text.

### 8.75 `0x1936c` (hardware-ID encoder) and `0x138b0` (MIME Base64 encoder) callers traced end-to-end -- both confirmed by direct instruction-level data flow to feed the `licence.mikrotik.com` HTTPFetch POST (`systemid`/`licence` fields), but the *identical* computation is independently, fully reachable via local-only `--software-id`/`--old-software-id`/`--dump-key` CLI paths and a local `.key`-file exporter, with zero network calls anywhere in those paths' traced call chains

Follows directly from §8.74's flagged findings. Both functions are called from exactly 3 direct sites each (plus, for the Base64 encoder, 2 thin wrapper functions with their own onward callers).

**`0x1936c` callers:**
1. `0x1a588` -- inside the already-documented `licence.mikrotik.com` registration function (`0x19f78`-`~0x1a330`, §8.26/§8.34). Output is built into a `string` at `sp+24`, which is the value passed to the *first* `appendVar` call at `0x1a31c`. Cross-checking the documented `appendVar` key order (`systemid, account, password, licence`, §8.26), this is **confirmed as the `systemid` parameter**.
2. `0x1acfc` -- inside a standalone local file-export function (`0x1acc4`-`~0x1ae00`): `readMBR` (`0x19b64`) -> `0x1936c` -> builds `"SoftwareID: %s\n"` -> `fopen("/var/pckg/%s.key", "w")` -> `fprintf`. **Pure local file I/O, not connected to HTTPFetch.**
3. `0x1baac` -- inside the CLI `--software-id` branch of the option-dispatch loop (alongside `--dump-key`/`--old-software-id`, literal strings at `0x1bd90`-`0x1bd98`): `readMBR` -> `0x1936c` -> `puts()`. **Pure local CLI output.**

**`0x138b0` (Base64 encoder) callers, direct and via 2 wrapper functions:**
1. `0x1a2f0` -- directly inline in the same registration function, encoding a 64-byte buffer whose result feeds the `"licence"` `appendVar` at `0x1a31c` (key resolved from the literal pool at `0x1a3b0`). **Confirmed as the `licence` parameter** (the base64-encoded signature bytes).
2. Via "Function A" (`0x17ad8`-`0x17b7c`, a `hasUefiSupport`-gated padding wrapper around the encoder at `0x17b68`): called from `0x1a7ec` (inside the registration function, immediately after `getBoardSerialNumber()`, see below), `0x1ad6c` (the same `/var/pckg/%s.key` file-exporter above), and `0x1ba64` (the `--dump-key` CLI branch, ending in `puts()`).
3. Via "Function D" (`0x17d8c`-`0x17dcc`, a thin `base64_encode -> std::string` wrapper): called 3 times, all from inside the registration function (`0x1a074`, `0x1a340`, `0x1a448`) -- plausibly the `account`/`password` `appendVar` fields, reusing the same encoder for the other message fields.

**Data-flow verdict:** both `systemid` and `licence` are now confirmed, by exact instruction-level tracing (not proximity), to be the direct outputs of `0x1936c` and `0x138b0` respectively. But **4 of the 6 combined call sites for these two utility functions never touch `HTTPFetch`, `nv::message`, or any network-capable PLT symbol**: `--software-id`, `--old-software-id` (dispatches to the same `0x1936c`/`puts` shape per §8.73's CLI inventory), `--dump-key`, and the local `/var/pckg/%s.key` exporter all compute and print/write the identical short-ID/base64 representations entirely offline.

**Open lead, not yet resolved:** tracing `0x17ad8`'s caller at `0x1a7ec` further up (inside the same registration function) surfaced a `getBoardSerialNumber()` call (`0x1a7b8`, PLT `0x12eb0`) whose sret-returned string is inserted as **`key=12`** into an `nv::message` object at `sp+28` via `nv::message::insert<string_id>` (`0x1300c`) -- alongside `key=11` (string), `key=5`/`4`/`7` (u32), and `key=8` (the Base64-processed value from Function A). This is a *different* data structure (`nv::message::insert`) from the `appendVar`-built `std::string` HTTP body traced above, and whether this particular `nv::message` object is ultimately serialized into the same HTTPFetch POST or is a separate local/NV-store record has **not yet been determined** -- it requires tracing where the `sp+28` object is consumed after construction. Flagged as the concrete next step.

**Effect on the online-registration hypothesis (§8.39):** this sharpens, but does not resolve, the open question -- and sharpens it in the direction the user argued against a blanket server-side-registration explanation. The computation MikroTik's server would need (a hardware-ID-derived `systemid` and a base64-encoded signature) is fully and independently reachable through code paths that never make a network call: `--software-id`, `--old-software-id`, `--dump-key`, and the local `.key` exporter. The online path (`0x19f78`) is a separate, additional consumer of the same utility functions for renewal/registration -- not the only or a mandatory way to compute them. This is concrete evidence that **basic SOFTWARE-ID computation and local reporting do not depend on MikroTik's registration server**. It does **not** by itself confirm or refute whether genuine RouterBOARD hardware *activation* specifically (the original §8.39 case, `XU4M-NJ40`) depends on that server -- that would require tracing the actual RouterBOARD activation/registration code path directly (still not located) or a real-hardware offline-activation test analogous to §8.35's methodology.


### 8.76 `0x17b7c`'s 20-char random-string generator traced end-to-end -- NOT a registration/activation nonce, both of its 2 call sites are local MBR-write scratch/diagnostic paths, closing §8.74's "most token-shaped function" flag as a dead end

The generator itself (`0x17b7c`-`0x17c38`) reads 4 bytes from `/dev/urandom`, mixes in `gettimeofday`, seeds `srand()`, then builds a 20-char ASCII string via 20 `rand()` calls. It has exactly 2 callers in the whole binary (confirmed complete via direct `bl 0x17b7c` grep, no others):

1. **`0x1b37c`**, inside a device-write function (`0x1b2e0`-`~0x1b3e4`) that only reaches this call after `readMBR` + an identity-check helper (`0x17aac`) succeed: the random string fills a scratch buffer at `sp+272`, but the buffer actually written back to the device via `0x178dc` (the already-documented 512-byte MBR-sector write function) is a **different** buffer (`r6`, populated earlier). The random string is generated but not observably consumed in this path -- most likely dead/filler stack space.
2. **`0x1b7a4`**, inside the CLI flag-dispatch function (the same one handling `--software-id`/`--dump-key`/`--old-software-id`, §8.73/§8.74): only when no serial argument is supplied (`r5==0`), the random bytes overwrite the `readMBR`-populated buffer, which is then written back via `0x178dc` and hex-dumped via `printf`. This is a local CLI diagnostic/self-test branch, no network call anywhere nearby.

**Verdict:** neither call site connects to the `licence.mikrotik.com` HTTPFetch flow. This closes the "most registration/activation-shaped function found" lead from §8.74 as local MBR-write scratch/test data, not an online nonce.

### 8.77 `getBoardSerialNumber()` has exactly ONE call site inside `keyman_arm_7.24.1` (the "several places" using it are in *other* RouterOS binaries, already listed in §8.49, not `keyman` itself) -- and the `nv::message` it feeds into (§8.75's open `key=12` lead) is confirmed structurally independent of the `appendVar`-built HTTPFetch POST body, move-returned to an out-parameter whose own caller could not be resolved via direct branch analysis

Two lines in the whole annotated disassembly reference `getBoardSerialNumber` (PLT `0x12eb0`): the PLT stub itself, and its single call site at `0x1a7b8`. The multiple call sites the user recalled are real but live in `/nova/bin/figman`, `/nova/bin/moduler`, and `/bndl/wifi/nova/bin/ww2` (already listed in §8.49) -- not further traced there, and not part of `keyman`.

**Resolving §8.75's open `key=12` question, definitively:** the enclosing function `0x1a3b8`-`0x1a978` builds the `sp+28` `nv::message` (keys 4/5/7/8/9/11/12, key=12 = board serial via `0x1a7b8`), then at `0x1a964`-`0x1a978` **move-constructs it into `*r7`** (`nv::message::message(nv::message&&)`, PLT `0x12c7c`) -- `r7` being this function's own first argument, i.e. an out-parameter supplied by *its* caller -- destroys the moved-from local, and returns. It is never passed to `appendVar`, never written to a file, and no `HTTPFetch::post` call appears anywhere inside `0x1a3b8` itself.

This confirms `0x1a3b8` is a **separate, independent function** from the one that builds the `systemid`/`account`/`password`/`licence` `appendVar` chain (which sits immediately before it, ending at `0x1a384`, with its own distinct `r7` register scope). The two code paths sit next to each other in the same source file but do not share data directly within `keyman`'s own code.

**Caller of `0x1a3b8` unresolved by direct branch search:** no `bl`/`b` instruction anywhere in the binary targets `0x1a3b8` (confirmed by exhaustive grep against every occurrence of the address string in the disassembly listing). This points to indirect/virtual dispatch (this codebase's `nv::` framework commonly invokes handlers through a registered function-pointer table rather than a direct call) -- resolved in §8.78.

### 8.78 `0x1a3b8`'s indirect caller located via raw-byte pointer scan (same method as §8.43/§8.71's x86 `handler_info` table discovery): it lives in a dense function-pointer table in `.rodata`, structurally matching the project's known handler-registration pattern, but the code that indexes/triggers this specific table slot is not yet identified

Following §8.71's proven method (a direct call/branch can't be found by `objdump -d`/`-R` for a data-relocated function pointer -- search the raw file bytes for the address's own little-endian encoding instead): confirmed via ELF header parse that `keyman_arm_7.24.1` is `ET_EXEC` (non-PIE, flat `file_offset = VA - 0x10000` bias, matching §8.73), so `0x1a3b8` should appear as the raw word `b8 a3 01 00` directly in a data section with no relocation indirection.

**Exactly one hit**, at file offset `0xd1b8` (VA `0x1d1b8`), inside `.rodata` (`0x1ca1c`-`0x1d218`). The surrounding 4-byte-aligned words form a dense run of `.text`/PLT-shaped addresses (`0x139e4`, `0x139e4`, **`0x1a3b8`**, `0x139e8`, `0x17e20`, `0x13a04`, `0x13a20`, `0x17e34`, ...) -- a genuine function-pointer table, not a coincidental 4-byte match. Widening the scan shows this `.rodata` region contains several fixed-shape `[ptr,ptr,ptr,ptr,0,0]` 6-word records followed by a longer ~20-entry pointer run (containing our target) terminated by a `0xffffff7c`/`0` sentinel pair. Notably, this whole table sits immediately after the project's already-documented **MikroTik custom SHA-256 IV constants** and a `"-----BEGIN MIKROTIK SOFTWARE...KEY-----"`-style string literal a few dozen bytes earlier -- confirming this `.rodata` region is genuinely license/crypto-adjacent, structurally consistent with (though not yet proven identical to) the `handler_info`/registration-table pattern §8.43/§8.65/§8.71 have been chasing on the x86 side.

**Confirms** the original hypothesis: `0x1a3b8` is reached only through table-driven dispatch, not a direct branch -- consistent with it being an `nv::` framework handler.

### 8.79 Full parallel-agent disassembly sweep of `parser`/`moduler`/`loader`/`sysinit` (13 agents, whole-file coverage, not keyword-targeted) finds two new `insmod()` sites near mode-checking code -- both verified against their actual `.rodata` strings and ruled out: neither is a physical-NIC vendor driver

Directly prompted by a concern (raised after §8.70-8.78's targeted, hypothesis-driven searching) that grep/address-driven analysis risks missing things a full read would catch. A workflow dispatched 13 agents in parallel, each assigned a fixed line range of the already-generated `objdump -d` output (no re-disassembly needed) with instructions to read their entire chunk and flag anything relevant to device/driver/mode-gating logic, independent of whether it matched a specific keyword pattern:

- `x86_nova_bin_parser.txt` (247,670 lines) -- 8 agents, ~31k lines each
- `x86_nova_bin_moduler.txt` (26,836 lines) -- 2 agents
- `x86_nova_bin_loader.txt` (~17,900 lines) -- 2 agents
- `x86_sbin_sysinit.txt` (8,786 lines) -- 1 agent

**Result: all 8 `parser` chunks and both `loader` chunks reported nothing beyond the already-known `rosMode()`/`hasFeature()`/`badmodeMsg`/`taintedMsg` call sites (§8.66-8.73)** -- no PCI/USB enumeration loops, driver-blacklist tables, or ethernet/interface-naming functions found anywhere in `parser` or `loader` beyond what prior targeted searches had already located. This is a meaningful negative result precisely because the method was exhaustive rather than keyword-driven.

**Two new leads surfaced, both in `sysinit`, both followed up and ruled out this session:**

1. **UEFI/vendor-gated `insmod` branch** (`0x804e637`-`0x804e670`): `hasUefiSupport() && !isMikrotikVendor()` selects between two `insmod()` calls. Resolving the actual `.rodata` strings: `misc/flash-uefi.ko` vs. `misc/flash.ko` -- this is the `/dev/flash` storage-chip driver selection already covered by §8.44/§8.45, unrelated to networking.
2. **A cluster of `insmod()` calls near the existing `hasFeature(0x12)` check** (`0x804f8a0`-`0x804fb26`): resolving every string reference in this range shows it is `sysinit`'s **factory-reset/defconf handling sequence** -- checks marker files (`/rw/RESET_DONE`, `/rw/CAPS_MODE`, `/rw/FORCE_CROSSFIG`, `/pckg/branding/FORCE_DEFCONF_ON_RESET`, ...), conditionally runs `/nova/bin/crossfig`, and along the way calls `insmod("misc/lcd.ko", ...)` (the physical RouterBOARD LCD-panel driver -- CHR has no LCD, so this is a hardware-presence check, not a license-mode gate) and `insmod("drivers/net/packet_hook.ko", ...)` (MikroTik's own generic packet-capture/hook module, used by the sniffer/traffic-generator tooling -- not a vendor NIC driver). Neither `insmod` call loads anything resembling `e1000`/`r8169`/`virtio_net`/any physical or virtual Ethernet chipset driver.

**Net effect**: this closes out the `moduler`/`sysinit`/`loader`/`parser` static-analysis thread for the "physical NIC fails under CHR" symptom (first reported in the conversation preceding §8.70) with high confidence that the answer isn't in these four binaries -- the investigation has now applied manual review, `radare2`-assisted cross-reference verification (§8.73), and whole-file parallel-agent coverage (this section), all converging on the same negative result. The two remaining paths from §8.73 stand unchanged: (a) reverse-engineer the `.mem` console-resource file format to identify what `fcn.08098588` (§8.71) actually guards, or (b) get real-hardware `dmesg`/`lspci -k` evidence from a machine switched between x86 and CHR mode, which would settle whether the symptom is kernel-level/hypervisor-level rather than anything in RouterOS's own userspace code.

**Not yet done:** delimiting the exact record boundaries around the `0x1a3b8` entry (single-slot vs. part of a larger fixed record like the ones above it), and -- the concrete next step to actually answer the open question from §8.75/8.77 -- tracing what code *loads and indexes* this specific table at runtime, which would identify the command/config key this handler answers to and, from there, whether it's ever invoked as part of the same online-registration flow that builds the `appendVar` HTTP body, or is a wholly separate (e.g. local status/diagnostic) feature.


### 8.80 `0x1a3b8`'s dispatch table identified as a compiler-generated C++ vtable, not an RPC-indexed jump table -- the owning class's constructor (`0x1b678`) embeds `nv::HTTPFetch`/`nv::Timer`/`nv::Looper` and reads `/nova/etc/serial`+`/nova/etc/license`, circumstantially supporting a registration-handler role, but the actual virtual-call instruction through slot #32 (the `0x1a3b8` entry) was not located, and the object's construction trigger looks argv-driven rather than confirmed-RPC-driven

Continues §8.78. `radare2 -A`'s `aav` (data-xref) pass, where manual literal-pool/branch grepping of `.text` found nothing, located the real cross-reference: a computed reference `0x1d138 + 0x80 = 0x1d1b8`. `0x1d138` -- sitting immediately after the `"-----BEGIN MIKROTIK SOFTWARE...KEY-----\0"` string block already known from §8.73's `.key`-import decoder -- is the actual **vtable base**, and `0x1a3b8` is **virtual-table slot 32** (byte offset `0x80`), not a flat command/handler-ID array as initially hypothesized.

**Vtable installation traced to two functions:**
- **`0x1b5a8`-`0x1b668`**: installs `r2 = 0x1d138` at object offset `0` and a second vtable pointer (`0x1d3c8`) at object offset `0x84` (multiple inheritance), then tears down members (`nv::Timer` dtor, `ostringstream` dtor, `nv::HTTPFetch::cancel()`, several `string::freeptr`, `nv::Looper` dtor) -- the compiler-generated **destructor** for this class (Itanium ABI idiom: reset vptr to own class before destroying members, then chain to base).
- **`0x1b678`-`~0x1bd50+`** (~1756 bytes, called directly from `main`/`entry0` at file offset `0x13108`): the **constructor**. Loads vtable slot 0's *content* (`0x1b5a8`, i.e. the destructor address itself) as a literal at `0x1bb44` (a normal static-dtor-reference pattern during construction), constructs an `nv::Looper` base subobject, constructs two `std::string` members, stores `nv::HTTPFetch::onIdleTimeout`/`onTimeout` as raw callback-pointer members, and calls the destructor (`0x1b5a8`) itself at `0x1bd4c` on an unwind/cleanup path. Early in the function: `cmp r0,1; ble ...` (argc check) and a `strcmp(argv[1], "--mbr")`-shaped comparison, then `fopen`/`fgets` on `/nova/etc/serial` and `/nova/etc/license`, then `hasUefiSupport()` -- **before** the HTTPFetch/Looper-derived object is constructed.

**Interpretation:** the class owning this vtable embeds exactly the members (`HTTPFetch`, `Timer`/`Looper` callback machinery) and reads exactly the files (`/nova/etc/serial`, `/nova/etc/license`) one would expect of the online license-registration/renewal handler -- circumstantial but fairly strong support for a registration-handler role, consistent with (not contradicting) §8.26/§8.34/§8.74/§8.75's existing HTTPFetch-flow documentation.

**What remains unresolved:**
1. No instruction of the shape `ldr r3,[r0]; ldr r3,[r3,#0x80]; blx r3` (or equivalent virtual-dispatch-through-slot-32 pattern) was found -- the vtable's *installation* is proven, but the *actual polymorphic call through slot 32* (i.e., whether the `0x1a3b8` handler is ever really invoked at runtime, as opposed to being a dead/unreachable override) is not.
2. The constructor (`0x1b678`) appears to be reached from an `argv`/`--mbr`-shaped branch inside `main`, not confirmed to be reachable independently from the RPC/online-registration message-dispatch route (§8.26/§8.34) -- the function is long (~1756 bytes) and was only partially walked (roughly the first third).
3. This local vtable's slot layout was not cross-referenced against the imported `nv::Handler` base class's own vtable slot ordering (visible via its exported symbols: `handle`, `handleBrkpath`, `notifyChange`, `cmdSetObj`, etc.) to name slot 32 by inherited position -- doing so would likely identify what virtual method `0x1a3b8` actually overrides.

**Not yet done:** finish walking `fcn_1b678`'s remaining branches to nail down the exact trigger condition for object construction; perform the `nv::Handler` vtable-layout cross-reference to name slot 32; search specifically for a `blx`/`bx` through a register loaded from `[obj + 0x80]`-style offset anywhere in the binary as the last direct way to confirm or rule out the virtual call itself.


### 8.81 `fcn.0001b678`'s remaining branches walked: the `0x1a3b8`-owning object is constructed by `keyman`'s DEFAULT no-argument invocation (not gated behind `--mbr` or any other CLI flag), registers 6 policies, wires `nv::HTTPFetch` callbacks, and is handed directly into a blocking `nv::Looper::run()` event loop -- proving this is a real, actively-driven service object, not dead/unreachable construction

Continues §8.80. Full walk of `fcn.0001b678` (`/tmp/fcn1b678.txt`, via `radare2 -A`) resolves both of that section's open items about construction gating and post-construction fate.

**Construction gate:** at entry (`0x1b67c`), `cmp r0,1 / ble 0x1bb08` (`r0`=`argc`). When `argc<=1` -- i.e. `keyman` invoked with **zero arguments**, the default/plain invocation -- execution jumps straight to the object-construction block at `0x1bb08`, bypassing the entire `argv[1]` string-compare cascade entirely. Only when `argc>1` does execution instead fall into the `strcmp(argv[1], "--mbr")` check and its sibling chain (`--dump`, `--major`, `--groups`, `--level`, `--uptime`, `--find-key`, `--key`, `--dump-key`, `--software-id`, `--old-software-id`, falling through to an "unknown option" message) -- none of which ever jump into `0x1bb08`. **This corrects §8.80's tentative "argv/`--mbr`-shaped branch" framing: construction is the unconditional default path, independent of and parallel to every CLI flag.**

**Post-construction fate**, from `0x1bb08` onward (object at `sp+0x270`, zero-filled first):
- `0x1bb88`: constructs the `nv::Looper` base subobject.
- `0x1bb98`/`0x1bb9c`: installs the primary vtable (`0x1d138`) at object offset `0`, and a **second vtable at object offset `0x84`, address `0x1d204`** (`0x1d138+0xcc`) -- a concrete address for §8.80's inferred secondary-vtable slot.
- `0x1bbf4`/`0x1bc1c`: wires `nv::HTTPFetch::onIdleTimeout`/`onTimeout` in as raw callback-pointer members (not vtable slots).
- `0x1bcd8`-`0x1bd28`: six `nv::policies::add_policy(unsigned,unsigned)` calls, registering policy IDs 1-6.
- `0x1bd3c`: calls `fcn.0001ae7c` (`r0`=obj, `r1`=1), a 508-byte setup routine managing `/ram/chrlreqonce`, timers, and randomized-delay scheduling.
- `0x1bd44`: **`bl method.nv::Looper.run__`** (`r0`=obj) -- the object is handed directly into the Looper event loop; execution blocks here.
- `0x1bd48`: after `run()` returns, calls the destructor (`0x1b5a8`, §8.80) -- consistent with construct -> run a real blocking event loop -> destruct-on-exit, not construct-and-discard.

**Conclusion:** running `keyman` with no arguments starts a real, persistent service object -- reads `/nova/etc/serial`+`/nova/etc/license` (§8.80), wires HTTPFetch/Timer callbacks, registers 6 policies, and blocks inside `nv::Looper::run()` -- structurally exactly what a background license-registration/renewal daemon would look like, consistent with (not contradicting) the already-documented `licence.mikrotik.com` HTTPFetch flow (§8.26/§8.34/§8.74/§8.75).

**Still not found:** a direct, self-dispatched virtual call through vtable slot 32 (`obj->vtable[0x80]`) -- `axt @ 0x1a3b8` in radare2 returns zero code cross-references, and `method.nv::Looper.run__` is a 12-byte PLT-style thunk resolving to an externally-linked implementation (`reloc.nv::Looper::run__`) not present in this binary, so the actual event-dispatch logic that would invoke slot 32 cannot be statically traced further from `keyman` alone. Resolved differently in §8.82.

### 8.82 Vtable slot 32 (`0x1a3b8`) cannot be given a declared method name (no `libumsg.so` copy available locally for comparative cross-reference), but IS proven reachable via a genuine peer-object virtual-dispatch thunk at slot 33 -- closing §8.80/§8.81's "is it ever actually invoked" question as YES, just not via self-dispatch

Method: matched all ~40 words of the vtable (`0x1d138`+) against `keyman_arm_7.24.1.plt_symbols.json`'s already-demangled `nv::Handler`/`nv::Looper` import addresses (`handle`, `handleBrkpath`, `handleReply`, `cmdGetObj`/`cmdSetObj`/`cmdRemoveObj`, `cmdGetAll`, `cmdReset`, `cmdShutdown`, `shouldNotify`, `cmdGetCount`, `cmdRemoveBundle`, `cmdMoveObj`, `cmdGetPolicies`, `cmdStopGetAll`, `cmdAddObj`, `flushNotifies`, `cmdUnknown`, `loadPermData`/`savePermData`/`handleCmd`/`cmdDisconnected`/`sendMessage`/`exchangeMessage`). A slot whose pointer exactly equals a known PLT-stub address is, by construction, an inherited/un-overridden method -- a hard, non-speculative name. `libumsg.so` itself is confirmed **not present anywhere in this project** (exhaustive filename search), ruling out direct analysis of `nv::Handler`'s own vtable layout.

**Result:** most slots resolve cleanly to inherited Handler/Looper methods (dtor at 0-1; `loadPermData`/`savePermData`/`handleCmd` at 2/3/7; `handle`/`handleBrkpath`/`handleReply` at 4-6; `cmdGetPolicies` at 8; the `cmdReset`/`cmdGetObj`/`cmdSetObj`/`cmdGetAll`/`cmdStopGetAll`/`cmdAddObj`/`cmdRemoveObj`/`cmdMoveObj`/`cmdGetCount`/`cmdRemoveBundle` cluster at 11-23; `cmdShutdown`/`shouldNotify` at 25-26; `cmdDisconnected` at 29; `sendMessage`/`exchangeMessage` at 38-39). Slot 32 falls in the run of **locally-implemented, non-inherited slots (9, 10, 24, 27, 28, 30-37)** -- genuine overrides or compiler-inlined defaults, not PLT-matched.

Disassembling this cluster: slots 27/28/30/31 are trivial 1-2 instruction stub bodies (`mov r0,0;bx lr` / `bx lr` / `mvn r0,0;bx lr`, with 30 and 31 literally identical-code-folded to the same address) -- boilerplate no-op virtual-method defaults. Slot 24 (`0x1b3f8`) is a substantial function containing a `cmp r2,5; ldrls pc,[pc,r2,lsl2]` jump table keyed on an `unsigned` selector -- a real switch-based override, plausibly `Handler::notifyChange` by argument shape, though not confirmed by name.

**The key finding:** slots 33 (`0x139e8`) and 34 (`0x13a04`) are near-identical tiny forwarding thunks that each load a *second, peer* object's vtable pointer from `r1` and call a fixed offset on it -- **slot 33's thunk specifically calls offset `0x80` of the peer object, i.e. the peer's slot 32**, and slot 34's thunk calls the peer's own slot 34. This is a genuine virtual-dispatch call site targeting exactly offset `0x80`/slot 32 -- not self-dispatch (`this->vtable[0x80]`), but a **peer-broadcast pattern** (`otherHandler->vtable[0x80]`) consistent with a registration/notification-list design where one handler object invokes a specific hook on every other currently-registered handler.

**Bottom line, answering §8.80/§8.81's open question directly: slot 32 (`0x1a3b8`, the function that packages `getBoardSerialNumber()`'s result into an `nv::message`) IS reachable via a real, concrete virtual-dispatch call site in the binary** -- just via a peer-broadcast thunk (slot 33 of some other Handler-family object calling into this object's slot 32), not a direct self-call. Combined with §8.81's proof that the owning object is constructed unconditionally on `keyman`'s default no-argument invocation and driven through a real blocking `Looper::run()` event loop, this closes out the "is this dead code" question: **it is not dead code -- it is live, registered, notification-driven handler logic inside what is structurally keyman's background license-service daemon mode.**

**What remains open** (the original §8.39/§8.75 question, now at its practical static-analysis limit): this establishes that the board-serial-bearing `nv::message` handler genuinely runs as part of `keyman`'s default background service -- but *whether* it is invoked specifically as part of the `licence.mikrotik.com` online-registration cycle (as opposed to some other peer-notification event unrelated to networking, e.g. a local config-change broadcast) was not determined; that would require either finding which OTHER Handler-family object's slot-33 thunk actually targets this one at runtime (a peer-registration-list traversal not reachable via more static disassembly, since the list itself is built/walked inside the externally-linked `nv::Looper`/`libumsg.so` runtime), or a real-hardware/live-process trace (e.g. `strace`/runtime instrumentation on an actual RouterBOARD or CHR instance) to observe the call actually happening and what triggers it. This is now explicitly the natural stopping point for pure static disassembly on this specific question.


### 8.83 Exhaustive whole-`keyman_arm_7.24.1` sweep for a second Handler-family vtable and for any self-dispatch through vtable slots 32/33 -- both come back definitively negative, confirming the peer-broadcast trigger lives entirely outside this binary

Extends §8.78/§8.80/§8.82's targeted searches into a full-binary sweep: every 4-byte word in `.rodata`/`.data.rel.ro`/`.data` was parsed and flagged if it lands inside `.text` (the same method §8.78 used for one known address, generalized to the whole file), and every `[rX, #0x80]`/`[rX, #0x84]` instruction operand (the byte offsets for slots 32/33) was grepped across the full disassembly, along with every call site of `nv::policies::add_policy`.

**Result:** `.rodata`/`.data*` contains exactly one dense, dtor-shaped vtable pair -- the already-known `0x1d138`/`0x1d204` (§8.80/§8.81). No second Handler-family object exists anywhere in `keyman_arm_7.24.1`. `[rX, #0x80]` appears in exactly 2 places binary-wide, both already-documented (§8.82's slot-33/34 thunk bodies, `0x139f4`/`0x13a3c`); `[rX, #0x84]` appears in exactly 2 places, both stores (not loads) installing the secondary vtable, not self-dispatch reads. `add_policy` has exactly 6 call sites total, all inside the one known constructor (`0x1b678`).

**One plausible false positive was found and ruled out:** three smaller 4-word records just before `0x1d138` (`0x1d0c4`/`0x1d0dc`/`0x1d0f4`) looked like more Handler constructions at first, but trace their constructors (`0x175dc`/`0x17604`/`0x17ec0`) and consumer to standard libstdc++ `std::function` type-erasure plumbing, instantiated for the two `function<>` callback parameters of `nv::HTTPFetch::post(...)`. Concretely, the `appendVar`/`systemid`-building HTTPFetch registration function (`0x1a200`-`0x1a384`, §8.74/§8.75/§8.77) constructs one of these objects (vtable `0x1d0f4`) immediately after its `HTTPFetch::post()` call -- a genuine, concrete link between the online-registration code and vtable-shaped data, but it resolves to `std::function` callback machinery, not to the Handler vtable, slot 32, or slot 33.

**Conclusion:** this is now an exhaustive, not heuristic, negative result -- nothing inside `keyman_arm_7.24.1` itself ever self-dispatches through slot 33 or maintains a second registered object. The actual peer-registration/broadcast-trigger mechanism is conclusively outside this binary, in the externally-linked `libumsg.so` -- continued in §8.84-8.85.

### 8.84 Real `libumsg.so` obtained -- exact architecture/version match (ARM, RouterOS 7.24.1) downloaded from MikroTik's official distribution, plus an x86/7.23.5 reference copy extracted from a user-supplied local package

Downloaded `https://download.mikrotik.com/routeros/7.24.1/routeros-7.24.1-arm64.npk` (13,918,485 bytes) -- the official package matching `keyman_arm_7.24.1`'s exact version. Also processed a user-supplied local file, `routeros-7.23.5.npk` (20,767,628 bytes, x86), as a secondary version/arch-mismatched reference.

**Extraction:** confirmed the `.npk` magic `1ef1d0ba` followed by an embedded SquashFS filesystem (magic `hsqs` at file offset 4096 in both files -- matches the format already documented in §8.42). Carved the SquashFS body via `dd skip=1 bs=4096` and extracted with `unsquashfs`; `libumsg.so` was found at `lib/libumsg.so` in both extracted trees.

**Final files** (placed under the already-gitignored `backup/` directory):
- `backup/bin/libumsg_arm64_7.24.1.so` -- ELF 32-bit ARM, EABI5, stripped, 575,064 bytes. **Exact version+architecture match** for `keyman_arm_7.24.1` (confirms, incidentally, that the "arm64" RouterOS package genuinely ships a 32-bit ARM `libumsg.so` too, consistent with §8.39's earlier finding that its `keyman` is 32-bit ARM, not aarch64).
- `backup/bin/libumsg_x86_7.23.5.so` -- ELF 32-bit x86, stripped, 520,904 bytes. Version/arch-mismatched reference only.

**Immediately useful:** unlike `keyman`, this library is not fully stripped of dynamic symbols -- it exports the base class vtables directly: `_ZTVN2nv7HandlerE` (`nv::Handler`, at `0x9aa2c`), `_ZTVN2nv6LooperE` (`nv::Looper`, at `0x9a4e4`), `_ZTVN2nv13NotifyHandlerE` (`nv::NotifyHandler`, at `0x9a980`) -- for the first time giving this project a *named* base-class vtable to compare `keyman`'s own local vtable (§8.78/§8.80/§8.82) against, rather than inferring slot purposes solely from PLT-import address matching. Continued in §8.85.

### 8.85 `nv::Handler`/`nv::Looper`/`nv::NotifyHandler`'s base-class vtables disassembled in the real `libumsg.so` -- slot 32/33's shared default is a pure no-op (ruling out a broadcast loop living there), slot 39 is unconditionally wired to `nv::policies::is_allowed`, and `NotifyHandler`'s one unique override (slot 26, `0x410cc`) is the best remaining lead for real notify/broadcast logic but was not traced to completion

Disassembled via `radare2 -A backup/bin/libumsg_arm64_7.24.1.so` (`objdump -d` also confirmed to work directly on this binary without `-Marm`, matching §8.73's note). `.data.rel.ro` (containing the vtables) is loaded at a fixed `vaddr = file_offset + 0x10000` bias; `.text` (containing all real code, `0x247c4`-`0x789e0`) has no such bias.

**Slots 29/30 (`0x2fa80`/`0x2fa88`):** trivial stubs (`mov r0,#0;bx lr` / bare `bx lr`).

**Slots 32/33 -- identical address `0x2fa8c` for both:** a single-instruction no-op, `bx lr`. **Handler's own shared default implementation does nothing at all** -- no member access, no loop, no list walk. This rules out a peer-list/broadcast mechanism living inside this specific base-class stub; whatever broadcasts to slot 32/33 in practice must be entirely keyman-specific override logic (§8.82's slot-33 thunk) triggered by something outside both `keyman` and this particular stub.

**Slots 35/37 (`0x2fa90`/`0x2faac`):** generic `(this, peer)` thunks -- load `peer`'s vtable, read its slot at offset `0x80`/`0x88`, `blx` it. Architecturally identical to `keyman`'s own slot-33 thunk (§8.82), confirming this "invoke a virtual slot on an externally-supplied peer" pattern is a library-wide convention, not something `keyman` invented -- but these thunks receive the peer pointer as a caller-supplied *argument*, they don't discover it themselves, so they don't reveal where peer pointers actually come from.

**Slots 34/36 (`0x34208`/`0x3421c`):** identical trivial `nv::message` default-constructor-and-return factories, unrelated to notification.

**Slot 38 (`0x2fac8`):** `mvn r0,#0;bx lr` (returns -1), trivial.

**Slot 39 (`0x33994`):** a this-adjusting tail-call thunk (`add r0,r0,#0x1c; b nv::policies::is_allowed(nv::message const&)`) -- Handler's base vtable wires directly into the policy-check subsystem. Confirms the generic Handler dispatch machinery is unconditionally tied to `nv::policies` (the same subsystem `keyman` drives via its 6 `add_policy` calls, §8.81) at the library level, not as keyman-specific glue.

**Cross-check across all three classes:** `Handler`/`Looper`/`NotifyHandler`'s vtables are **byte-identical in every non-zero slot** (29/30/32/33/34/35/36/37/38/39/42 all point to the same addresses across all three; slots 0-28/31/40/41/43/44 are zero/pure-virtual in all three) -- confirming the slot-32/33 offset assumption used throughout §8.78-8.82 is stable across the entire Handler/Looper/NotifyHandler family. **The one exception:** `NotifyHandler` alone additionally implements slot 26, at `0x410cc` (448 bytes -- substantially larger than any other slot examined this pass), which reads a *peer's* vtable slot at offset `0x84` (slot 33) -- the strongest remaining candidate for genuine notify/broadcast logic, but too large to fully trace within this session's pass.

**Bottom line:** the "peer registration list" §8.78-8.83 could never locate is confirmed **not implemented in Handler's own default slot-32/33 stub** -- that stub is empty. What *is* newly established: cross-object virtual dispatch is a real, deliberate library convention (slots 35/37), the policy subsystem is unconditionally wired into base Handler dispatch (slot 39), and `NotifyHandler::0x410cc` is the one substantial, non-trivial, notify-shaped override in the entire base-class family -- making it the concrete next target. **Not yet done:** fully tracing `0x410cc`; and separately, tracing what `fcn.0001b678` (§8.80/§8.81) actually does with the *contents* it reads from `/nova/etc/serial`/`/nova/etc/license` via `fopen`/`fgets` (read but not yet followed downstream).


### 8.86 CORRECTION to §8.80/§8.81/§8.85: `/nova/etc/serial` and `/nova/etc/license` are read ONLY under the `keyman --mbr` diagnostic subcommand, NOT as part of the default no-argument service-construction path -- the two are mutually exclusive branches of the same `argc` check, and both files' contents are consumed entirely within an offline local-identity-matching loop with no path toward the `HTTPFetch`/online-registration code

§8.80 described `fcn.0001b678` as a single sequence that "reads `/nova/etc/serial`+`/nova/etc/license`... then constructs the Handler-derived object," and §8.81 repeated this framing. **This conflated two mutually exclusive branches of the same function into one sequence -- they are not.**

Re-examining `fcn.0001b678`'s entry precisely: `cmp r0,1; ble 0x1bb08` (`r0`=`argc`) is a **branch**, not a fallthrough-with-optional-detour. The two outcomes never both execute in the same invocation:

- **`argc<=1` (default, no-argument invocation):** jumps directly to `0x1bb08` -- constructs the `nv::HTTPFetch`/`Timer`/`Looper`-embedding Handler object, registers 6 policies, enters `nv::Looper::run()` (§8.81's findings on this branch remain correct). **Never touches either `/nova/etc/*` file.**
- **`argc>1` and `argv[1]=="--mbr"`:** falls through to `strcmp(argv[1],"--mbr")` at `0x1b68c`-`0x1b698`; only on match does execution reach the file reads. This is where `/nova/etc/serial`/`/nova/etc/license` are actually opened -- a **completely separate code path** from object construction, part of `keyman`'s CLI-flag dispatch chain alongside `--dump`/`--major`/`--groups`/`--level`/`--uptime`/`--find-key`/`--key`/`--dump-key`/`--software-id`/`--old-software-id` (§8.73's CLI inventory).

**Exact call sites (within the `--mbr` branch):**
- `/nova/etc/serial`: `fopen` at `0x1b6a8` -> `fgets(sp+0x70, 0x15, stream)` at `0x1b6c0`/`0x1b6c4` (21-byte buffer) -> `fclose` at `0x1b6d0`; result pointer kept in `r5`.
- `/nova/etc/license`: `fopen` at `0x1b6dc` -> `fgets(sp+0x60, 0xd, stream)` at `0x1b6f4`/`0x1b6f8` (13-byte buffer) -> `fclose` at `0x1b704`; result pointer kept in `r4`.

Both survive (ARM APCS callee-saved) through `fcn.00015f0c`, `fcn.00019b64`, and `hasUefiSupport()` (`0x1b708`-`0x1b718`), into an MBR/identity candidate-sweep loop starting at `0x1b738` (walking candidate `mbr_val`s via `fcn.00013808`/`fcn.00017094`, the already-documented checksum/identity-mix functions, §8.72/§8.39).

**What each buffer is actually used for inside the sweep:**
- **`r5` (serial):** only NULL-checked (`0x1b798`); if non-NULL, handed as an opaque pointer argument into a print/format helper (`fcn.00013844(candidate_buf, serial_ptr)`) alongside whatever candidate identity the sweep lands on -- **never compared byte-for-byte against anything.**
- **`r4` (license):** if non-NULL, passed as the third argument to `fcn.00019410(hwid_buf, candidate_buf, license_ptr)` -- a **local matching predicate**: for each swept candidate identity, this checks whether the locally-computed hardware-ID buffer (from `fcn.00019b64`, the same getHardwareID/identity-decode staging path used throughout §8.9-8.41) is consistent with the license file's content; the boolean result decides whether to keep sweeping (`blt` loops back) or stop (found a match). Functionally, **`keyman --mbr` is a local "which identity does this already-installed license correspond to" reverse-lookup diagnostic** -- the same category of computation as this project's own collision search, run entirely offline. If the license read fails (`r4==0`), the sweep falls back to a different, license-independent matching function (`fcn.000178dc`).

**Structural (not just evidentiary) exclusion of the HTTPFetch connection:** both buffers are pure stack locals inside `fcn.0001b678`'s own frame (`sp+0x70`/`sp+0x60`) and are never written into the Handler object built at `0x1bb08`, because that construction only happens on the OTHER branch of the entry `argc` check -- the same `keyman` invocation cannot execute both the `--mbr` file-reading path and the object-construction/online-service path. **This rules out any data flow from these two local files toward the `licence.mikrotik.com` HTTPFetch/`appendVar` code (`0x19f78`-`0x1a384`, §8.74/§8.75/§8.77) by construction, not merely by absence of found evidence.**

**Net effect on the running §8.39 investigation:** narrows, rather than widens, the online-registration hypothesis's remaining surface. The default-invocation service-object path (§8.81, still correctly documented) remains the only candidate for a genuine online-registration/renewal daemon, and it does not read either local file. `--mbr` is now fully characterized as an unrelated, purely local diagnostic tool. §8.85's "not yet done" item regarding these two files' data flow is now resolved by this section; §8.85's other open item (fully tracing `NotifyHandler::0x410cc`) remains open.


### 8.87 CORRECTION to §8.85 and closure of the `NotifyHandler::0x410cc` lead: full disassembly shows no list traversal, no peer-vtable-slot-33 call, and no discoverable caller anywhere in `libumsg.so` -- and `keyman`'s own object most likely isn't even `NotifyHandler`-derived, since its slot 26 resolves to the generic, named `nv::Handler::shouldNotify(message const&, message const&)` import, not a locally-compiled override

Full trace of `0x410cc` (`radare2 -A`, `libumsg_arm64_7.24.1.so`) closes out §8.85's "best remaining lead" as a dead end, and corrects one of its claims.

**Correction:** §8.85 described `0x410cc` as reading "a peer's vtable slot at offset `0x84`." Full disassembly shows the actual instruction is `add sb, r1, 0x84` (`0x410d0`) -- plain pointer arithmetic computing a struct-field address inside its second argument (`r1`, an `nv::message`-family object), used only as the `this` for subsequent `message::get<u32_id>`/`has<message_array_id>` calls. There is no `ldr`+`blx` pair anywhere in the function's 448 bytes -- no vtable read, no virtual dispatch, no peer object involved at all.

**What `0x410cc` actually is:** paginated `nv::message` array-reply-building glue -- `message::get<u32_id>`/`has<message_array_id>`/`insert<u32_id>`/`insert<u32_array_id>`, `message::C1()`/`D1()`, `nv::sendAsyncGetall(Handler*, function<...>, bool)`, `nv::Handler::sendCmd(message&, unsigned)`, `nv::errorMsg(...)`. Its one loop (`0x411d4`-`0x41264`) walks a `message_array_id`'s element count (byte-range divided by an 8-byte stride) to page through array entries for a "getall" reply -- structurally a reply-pagination helper, not a peer-object broadcast/notification mechanism.

**Caller search:** an exhaustive raw-byte scan of the whole `.so` for the literal word `0x000410cc` finds exactly one occurrence -- `NotifyHandler`'s own vtable slot 26 entry (file offset `0x8a9e8` = vtable base `0x9a980`+`0x68`). No `bl`/`b` instruction anywhere targets it, and no other data table references it. It is reachable only via `this->vtable[26](...)` virtual dispatch on a `NotifyHandler` instance -- and no code anywhere in `libumsg.so` was found performing that specific dispatch. (One r2-reported "DATA XREF" turned out to be a false positive: a PC-relative string-literal-address computation whose target address numerically happens to fall inside `0x410cc`'s byte range, unrelated to the function itself.)

**New finding narrowing the question further:** cross-checking `keyman`'s own local vtable (`0x1d138`) at the equivalent slot-26 offset (`0x1d138+0x68 = 0x1d1a0`) shows it resolves to a **named, dynamically-imported PLT thunk for `nv::Handler::shouldNotify(nv::message const&, nv::message const&)`** -- not a locally-compiled 448-byte override matching `NotifyHandler::0x410cc`'s shape. This is evidence that `keyman`'s board-serial-bearing object most likely inherits the plain `nv::Handler::shouldNotify` default rather than being `NotifyHandler`-derived, meaning `0x410cc` may not even be part of its actual vtable chain in the first place.

**Bottom line:** this closes the `NotifyHandler::0x410cc` thread as exhausted -- no list traversal, no peer-slot-33 call, no discoverable trigger, and now doubtful applicability to `keyman`'s own object at all. Combined with §8.83's exhaustive negative sweep (no second Handler vtable or self-dispatch through slot 33/`0x80` anywhere inside `keyman_arm_7.24.1` itself) and §8.85's finding that Handler's own shared slot-32/33 default is an empty no-op, **every concrete static-analysis avenue this multi-session thread (§8.39, §8.72-8.87) has generated for locating the actual peer-broadcast trigger has now been exhausted without a positive result.** The one still-unexplored, newly-surfaced lead is `Handler::shouldNotify` itself (not yet traced) and the unrelated `list_base` member at object offset `0x68` found incidentally in `fcn.00034164` (§8.87's caller-search step) -- neither pursued further this session. Beyond these, resolving whether/when the board-serial handler (`0x1a3b8`) is genuinely invoked as part of the online-registration cycle requires either further tracing of those two specific leads, or a real-hardware/live-process dynamic trace (e.g. `strace`/runtime instrumentation of an actual RouterBOARD or CHR instance running `keyman` with no arguments), as static disassembly of the binaries available to this project has been pushed to its practical limit on this specific question.


### 8.88 The real generic notify/broadcast mechanism found at last -- `nv::Handler::sendNotify(message&)` walks a genuine per-object subscriber array and gates dispatch on `shouldNotify` exactly as predicted -- but `shouldNotify`'s base implementation is an unconditional `return true` stub, and `sendNotify` itself has zero discoverable static callers, marking the practical end of this thread's static-analysis avenue

Closes the `Handler::shouldNotify` lead opened in §8.87. `nv::Handler::shouldNotify(nv::message const&, nv::message const&)` is exported at `0x2fad8` in `libumsg_arm64_7.24.1.so` -- its entire body is `mov r0,1; bx lr`: **it unconditionally returns true**, gating nothing on its own. (An initial `axt`-reported set of 14 "callers" was a false positive from `radare2`'s xref database -- verified via `pdj`'s decoded jump targets that those `bl`s actually hit the adjacent, unrelated `fcn.0002fae0`, a JSON-quoting helper for `nv::message2json`. A whole-binary direct-branch scan confirms zero direct callers, as expected for a virtual-only method.)

**The real caller, and the genuine broadcast loop this whole thread has been hunting since §8.78:** `nv::Handler::sendNotify(nv::message&)`, a named symbol at `0x33d5c` (source file `looper.cpp`, confirmed via an embedded assertion string `"m.has(nv::SYS_CMD)"`). Disassembly shows:
- Asserts the incoming message carries `nv::SYS_CMD`, pulls a `u32_array_id`/`u32_id` out of it.
- Calls `fcn.00039840` on a member at `this+0x28` to get a begin/end iterator pair over an array of subscriber records -- the same helper `findNextListener()` (`0x330d4`) uses on the identical `this+0x28` array, confirming this is a real, generic subscriber-tracking structure, not something local to one function.
- Loop body (`0x33de8`-`0x33e7c`): for each subscriber record `r7`, calls **`this->shouldNotify(r7+0x14, newMsg)`** through the vtable (`ldr r3,[r5]; ldr r3,[r3,0x68]; blx r3`) -- `r7+0x14` is an "old" message snapshot cached inside the subscriber record itself. This is exactly the old-vs-new comparison call site this thread predicted, with the framework's calling convention matching precisely -- only the *default* callee (§8.85/§8.87's `Handler::shouldNotify` stub) turned out to always approve.
- Approved subscribers (plus a parallel path checking a separate vtable slot 38 for id-matched records) get accumulated into a second array, which `fcn.00029e20` then actually sends/dispatches.

**Confirmed generic pattern:** iterate a real registered-subscriber array (`this+0x28`) -> gate each via `shouldNotify` (vtable slot 26) -> dispatch to approved subscribers. This is a genuine, positive, non-speculative finding -- not another dead end like §8.87's `NotifyHandler::0x410cc`.

**Where the trail still ends:** `sendNotify` itself has **zero discoverable callers**, either as a direct branch anywhere in `libumsg_arm64_7.24.1.so` (`/atj bl 0x33d5c` and `axt` both return empty) or as a PLT import anywhere in `keyman_arm_7.24.1` (absent from `keyman_arm_7.24.1.plt_symbols.json` and from the binary's strings). It is therefore itself only reachable via further indirect/virtual dispatch not exposed as a named symbol -- and where the `this+0x28` subscriber array actually gets populated (a `registerSelf()`-style call `keyman`'s object would need to go through during construction, §8.81) was not located in this pass.

**Assessment after three consecutive sessions each finding one further indirect-dispatch layer (§8.78 vtable -> §8.82/8.85 base-class defaults -> §8.87 `NotifyHandler` dead end -> §8.88 `sendNotify`/`shouldNotify`, now also a dead end for the same structural reason): every concrete, named, or address-discoverable static lead this thread has generated has now been exhausted.** This is the practical stopping point for pure static disassembly on the original §8.39 question ("is RouterBOARD hardware licensing tied to online registration"). What remains genuinely open (whether the board-serial handler at `keyman`'s vtable slot 32 is ever actually invoked, and if so whether that's connected to the `licence.mikrotik.com` cycle) cannot be resolved further by reading more code addresses -- it requires either dynamic analysis (a debugger breakpoint on `sendNotify`/`shouldNotify`, or `strace`/runtime instrumentation, on a real or emulated RouterOS 7.24.1 instance running `keyman` with no arguments, observing what actually gets called and whether any network I/O follows) or abandoning this specific sub-thread in favor of the broader §8.39 question via other means (e.g. real-hardware offline-activation testing analogous to §8.35's methodology).


### 8.89 `libumsg.so`'s generic `readHcfgField()` accessor (`ioctl 0xc0044626` on `/dev/flash`) traced end-to-end via `flash.ko` -- resolves to a hardware-provisioning key/value store (factory-reset flag, touchscreen calibration, per-driver calibration constants), NOT a license/activation field; `keyman` itself never calls it

Continues §8.48's "not yet done" item on `readHcfgField(int, void*, unsigned, bool)`, prompted by the user's observation that `/dev/flash` might hold more than just board-serial data.

**Kernel-side implementation** (`flash.ko`, ARM64, disassembled via `radare2 -A`): the `0xc0044626` case in `flash_ioctl`'s dispatch chain (`0x080034ac`-`0x080034b8`, `b.eq 0x80038b4`) copies a 4-byte struct from userspace (`copy_from_user`, `0x080038c0`), reads its low 16 bits as a numeric **key** (`0-255`, bounds-checked), looks it up in an 8-byte-per-entry table (`lookup()` at `0x08000544`, table base at `.bss+0x50`) yielding a `{offset, size}` record, then slices those bytes out of a single in-RAM "hcfg" blob (cached pointer at `.bss+0x58`, loaded once at driver init from the on-flash "Factory" MTD partition -- the same dispatch function also contains `mtd_part_present("Factory")`/`mtd_part_read_data`/`write_config`/`program_data`/`erase_flash_config` symbols for sibling ioctls). **This is a flat key->{offset,size} table over one cached blob, not a free-form store and not per-key flash I/O.**

**Callers found across the whole extracted RouterOS filesystem** (`nm -D` for `_Z13readHcfgFieldiPvjb` across every binary in `/nova/bin/*`): exactly two.
- `/nova/bin/mode` (`0x1cc88`): key **48** (`0x30`), reads a 4-byte field, falls back to checking `/flash/rw/FACTORYRESET` on failure -- a **factory-reset state flag**.
- `/nova/bin/logmaker` (`0x178d4`): key **25** (`0x19`), reads a 20-byte field labeled `TS_CALIBRATION` in an adjacent string literal, dumped via `nv::niceHexDump()` for a diagnostics report -- **touchscreen calibration data**.

**`keyman` (all 4 available builds: ARM 7.15.3/7.24.1, x86 7.23.2/7.24.1) and `figman` do not import or call `readHcfgField` anywhere.** Their only `/dev/flash`-adjacent dependency remains `getBoardSerialNumber()`/`getHardwareID()` (§8.44/§8.45/§8.48).

**No static key-name table exists** (the 256-slot table is populated at runtime by each consuming driver's `init` registering its own field, not baked into a static string table in `flash.ko` itself), but `nm` across every `.ko` in the same module directory shows which subsystems register/consume hcfg fields at all: `ts.ko` (touchscreen, matches key 25), `al_pcie_ep.ko`, `poe_v4.ko`, `prestera_pci.ko`, `hk_eth.ko`, `marvell_amethyst.ko`, `phy_helper.ko`, `alder_eth.ko`, `mvpp2.ko`, `al.ko`, `ath8327.ko` -- every consumer is an Ethernet/switch-chip/PoE/PCIe-endpoint/touchscreen driver. `flash.ko`'s own `.rodata.str1.1` also contains `"SORRY: there is no radio calibration data on this device"`, reinforcing the store's purpose.

**Conclusion:** `readHcfgField`/`0xc0044626` is a real, now-fully-documented `/dev/flash` primitive, but it is a hardware-provisioning/calibration key-value store, not a license or activation mechanism -- and `keyman` doesn't touch it at all. Closed out as a dead end for the licensing question, confirmed independently by public GPL source in §8.91.

### 8.90 RouterOS's base SNMP agent (`/nova/bin/snmp`) does NOT serve `1.3.6.1.4.1.14988.1.1.4` (`mtxrSerialNumber`) or `.1.1.7.x` at all -- every OID group actually compiled into the binary was enumerated and traced; the real owner is a separate, not-yet-identified subagent/AgentX-style process

Follows up on the user's observation of an empty SNMP GET result on `enterprises.14988.1.1.7.5.0`. Disassembled `/nova/bin/snmp` (RouterOS's base SNMP agent, ARM32, from the official 7.24.1 arm64 package extraction) via `radare2 -A`, cross-referencing every `1.3.6.1.4.1.14988.1.1.*` literal in `.rodata` to its registering function.

**Confirmed present and traced to real registration code:** OID groups `.2`, `.3` (`mtxrHealth`, registered via `entry.init1` -> `fcn.0003dabc`), `.6.1`, `.9`, `.12`, `.13`, `.14.1.1`, `.15.1.1`, `.16.1.1`/`.16.2.1.1`/`.16.3`, `.19.1.1`, `.20.1.1`/`.20.2.1` (`mtxrNeighbor`, the CDP/neighbor-discovery table -- traced via `fcn.00023938`, which attaches ~15 typed column leaves with getter/type descriptors).

**Confirmed absent, not merely hard to find:** no literal string or table entry for `.1.1.4` or `.1.1.7.x` exists anywhere in `.rodata` or code. No `getBoardSerialNumber`/`getHardwareID`/`routerboard`-named symbol exists in this binary's symbol or import tables either. This binary's `nv::` usage is entirely numeric-ID-keyed (`nv::message::insert<u32_id>` etc. with integer constants, never a human-readable path string) and its one `AMap` instantiation resolves to `"/nova/store/snmp-communities"` (SNMP's own community-string config, unrelated to hardware data).

**Conclusion:** `mtxrSerialNumber` and the `.7.x` group are served by a different RouterOS process -- RouterOS's SNMP implementation is known to support subagent/AgentX-style extension for hardware/license-specific MIB groups. Locating that owning binary (searched for in §8.91's follow-up but not yet found as of this writing) is the concrete next step toward closing the loop from "SNMP GET" to the underlying `/dev/flash` read.

### 8.91 Public GPL source cross-check (MikroTik's own published `linux-5.6.3.patch`, via `github.com/tikoci/mikrotik-gpl`) independently confirms §8.89's reverse-engineered conclusion: the on-flash "hcfg" tagged-blob mechanism carries only hardware-provisioning fields, never license/serial data -- though the specific ARM64 `flash.ko` driver's own source was not found in this particular patch bundle

The user pointed at MikroTik's own published GPL kernel source (`https://github.com/tikoci/mikrotik-gpl/tree/main/2025-03-19`, required disclosure under the GPL for MikroTik's Linux-kernel-derived code) as a way to independently verify §8.89's reverse-engineered `readHcfgField`/hcfg conclusions against real source, rather than relying on binary analysis alone.

Downloaded `2025-03-19/linux-5.6.3.patch` (24,886,104 bytes) directly from `raw.githubusercontent.com` (first attempt failed mid-transfer with curl exit 56/connection reset; retried with `--retry 5` and completed cleanly). This single patch file contains MikroTik's full kernel source tree as a unified diff against vanilla Linux 5.6.3.

**Found the older, MIPS-era public equivalent of the same mechanism:** `arch/mips/rb/prom.c`'s `read_booter_cfg(unsigned id, void *buf, int amount)` -- reads a `hcfg_offset`/`hcfg_size` pair from a fixed NOR-flash location (board-family-dependent: `0x24` for `MACH_GROUP_MT_RB700`/`RB400`, `0x14` for `MACH_GROUP_MT_MUSIC`), verifies a magic value `0x64726148` (little-endian bytes `48 61 72 64` = ASCII `"Hard"`), then linearly scans `tag`/`len`-prefixed records (`data & 0xffff` = tag, `data >> 16` = length) until `tag == id`, returning that record's bytes -- structurally identical in concept to the ARM64 `flash.ko`'s key->{offset,size} table (§8.89), just implemented directly in early boot code (`prom.c`) rather than as a loadable kernel module, and reading from raw NOR flash offsets rather than an MTD "Factory" partition.

**Every defined field ID found in the whole 24MB patch:**
```
ID_MAC_ADDRESS_PACK   0x04
ID_BOARD_NAME         0x05
ID_BIOS_VERSION       0x06
ID_HW_OPTIONS         0x15
ID_BOARD_TYPE_NAME    0x17
```
No `ID_SERIAL`/`ID_LICENSE`-shaped constant exists anywhere in the patch -- every other "SERIAL" hit found (`grep -niE '^\+#define.*(SERIAL|LICENSE)'` across the full file) is an unrelated PCIe/USB/crypto-accelerator hardware register field (e.g. `TRIO_PCIE_EP_*_SERIAL_NUMBER_*`), not an hcfg field ID.

**Significance:** this is an independent, non-reverse-engineered confirmation (MikroTik's own disclosed source, not this project's disassembly) that the on-flash hardware-config store's field set is, by design, board-provisioning data (MAC address, board name/type, BIOS/bootloader version, HW options bitmask) -- never license or serial-number state. It corroborates §8.89's conclusion exactly, via a completely independent code path (old MIPS bootloader source vs. new ARM64 kernel-module disassembly), strengthening confidence that this specific mechanism is conclusively not where RouterBOARD activation state lives.

**Not found in this specific patch bundle:** the ARM64 `flash.ko` module's own source (searched all `+++` file-path headers for `flash`/`rb`-adjacent driver files; only unrelated hits like `drivers/mtd/maps/ralink-flash.h`, `drivers/soc/alpine/HAL/services/flash_contents/*`, and a small unrelated `arch/arm/mach-rb/rb_fixup.c` device-tree fixup file were found). Either this driver isn't part of this particular GPL disclosure bundle, or its source lives elsewhere in the same repository (other dated snapshots, or a differently-named directory) -- not checked further this session.

### 8.92 SNMP's `mtxrSerialNumber` (`.1.1.4`) chain traced one hop further: `snmp` forwards unrecognized OIDs over MikroTik's proprietary `STD_SNMP_QUERY` message-bus mechanism (not standard AgentX) to `keyman`, which builds the reply via `getBoardSerialNumber()` -- confirmed down to the `/dev/flash` ioctl, though the literal OID-to-field mapping remains circumstantial, and `.1.1.7.5`'s owner is still unresolved

Continues §8.90. **RouterOS does not use standard SNMP AgentX anywhere in this filesystem** (`grep`/`nm` for `AgentX`/`agentx` across every extracted binary returns zero hits). Instead, `/lib/libumsg.so` contains the literal string `STD_SNMP_QUERY` (offset `0x78f2d`) -- MikroTik's own internal message-bus mechanism, almost certainly what `snmp` uses to forward OIDs it doesn't own itself (confirmed in §8.90 to exclude `.1.1.4`/`.1.1.7.x`) to whichever daemon actually serves them.

**`libumsg.so` exports `getBoardSerialNumber()` directly** (mangled `_Z20getBoardSerialNumberv`, offset `0x4e2d8` in the ARM64 build) -- its full implementation: `open("/dev/flash", O_RDWR)` -> on success, `memset` a 16-byte stack buffer, `ioctl(fd, 0x80104608, buf)` (decodes as `_IOR('F', 8, 16)`) -> `close(fd)` -> construct and return a `std::string` from the raw ioctl output. On `open()` failure: `perror`-log and return an empty string (no `/dev/rb` fallback in this specific function). This matches and refines §8.48's earlier x86-build trace of the same function, now confirmed directly in the ARM64 build too.

**Importers of `getBoardSerialNumber()`** across the extracted filesystem: `nova/bin/{keyman, figman, modprobed, moduler}` and `bndl/wifi/nova/bin/ww2` (matches §8.48's x86 finding, now reconfirmed on ARM64) -- plus `snmp` itself links `libumsg.so` and could call it directly, but its own code doesn't (confirmed in §8.90).

**Traced the actual call site inside `keyman`:** `sym.imp.getBoardSerialNumber__` at `0x12eb0`, called from `0x1a7b8` inside `fcn.0001a780` (`0x1a780`-`0x1a978` -- this is the same function region already fully mapped in §8.77 as the `sp+28` `nv::message` builder that move-returns its result to an out-parameter). This function builds an `nv::message` reply field-by-field: a string field (type `0xb`), the `getBoardSerialNumber()` result as string field type `0xc`, several `u32_id` fields (types `4,5,7,8,9`), a call to `hasUefiSupport()`, a comparison against hardcoded 32-bit constants (license-signature-shaped), a call to `nv::getUptime()` -- a generic "board+license status" reply builder, with the board serial as one field (`0xc`) among several.

**Bottom line, chain as far as concretely provable:** `snmp` -> `STD_SNMP_QUERY` message-bus forward -> `keyman`'s `fcn.0001a780` builds an `nv::message` reply including `getBoardSerialNumber()`'s result -> `getBoardSerialNumber()` (`libumsg.so`) -> `open("/dev/flash")` + `ioctl(0x80104608)` + `close()`. **The `/dev/flash`-to-`getBoardSerialNumber()` half is fully proven by disassembly** (reconfirms §8.48 on the exact ARM64 build in question). **The "this specific `keyman` reply is what answers OID `.1.1.4`" half remains circumstantial** -- strong (shared IPC library, matching `STD_SNMP_QUERY` architecture, `keyman` is the only serial-consuming daemon that also handles license/hardware-gating logic in the same reply-building function), but no literal OID-to-field-index table was found proving field `0xc` maps to leaf `.4` specifically; `keyman` contains no `14988`/`mtxrSerial`-shaped string literals anywhere -- the OID numbering itself is evidently owned only by `snmp`'s own MIB table, with `keyman` supplying just the underlying data over the generic, OID-agnostic message bus.

**`.1.1.7.5` (the user's originally-observed empty field) remains unresolved** -- `keyman` has no `14988`/`.1.1.7`-shaped string literals, and no second board-info-reply builder function analogous to `fcn.0001a780` was found and matched to that specific sub-OID. **Not yet done:** locating `keyman`'s other `nv::message`-builder functions (there are plausibly several, one per query/field-group type) and matching them against `.1.1.7.x`, or examining `snmp`'s own OID table for the literal numeric field-ID it requests over `STD_SNMP_QUERY` for that specific leaf -- either would be the concrete next step to explain why that field returns empty (unset field vs. wrong daemon vs. RouterBOARD-vs-CHR-conditional, per §8.90's original framing).


### 8.93 Clarifications on two low-level details from §8.91/§8.92: `get_flash_base()`'s role in early boot flash access, and `0x80104608`'s full ioctl-encoding decode

**`get_flash_base()`** (`arch/mips/rb/prom.c`, part of §8.91's `read_booter_cfg()` call chain): a PROM/early-boot-stage helper that resolves the physical base address of the NOR flash chip in CPU address space, before any block/char device driver (including the later `flash.ko`) is loaded -- `read_booter_cfg()` needs this to `ioremap()` the flash directly and read raw bytes via `nor_read()`. Board-dependent: returns `0x1f000000` when `hw_opt & HW_OPT_NO_NAND` is set or for a long enumerated list of specific `mips_machtype` values (RB951, RB750r2, CM2N, RB962, and many more), otherwise defaults to `0x1fc00000` (the standard MIPS reset-vector physical address). Purely a hardware memory-mapping detail specific to which flash chip/address-decoding scheme a given board model uses -- unrelated to licensing.

**`0x80104608`** (the ioctl `getBoardSerialNumber()` issues against `/dev/flash`, §8.48/§8.92): full Linux ioctl-number decode, per the standard `_IOC(dir, type, nr, size)` bit layout (`dir` bits 31-30, `size` bits 29-16, `type` bits 15-8, `nr` bits 7-0):
```
0x80104608 = _IOR('F', 0x08, 16)
  dir  = 0b10        -> _IOC_READ (kernel -> userspace)
  size = 0x0010 = 16 -> 16-byte transferred structure
  type = 0x46 = 'F'  -> device-driver magic byte ("flash"), same type byte used throughout `flash_ioctl`'s whole dispatch table (§8.50)
  nr   = 0x08         -> command number 8 within that type
```
Confirms and fully formalizes what was already established behaviorally (a 16-byte read-only board-serial fetch) with the complete standard-ioctl-macro derivation.


### 8.94 Real-device ground truth (user's own CCR1072-1G-8S+) overturns §8.90's "group `.7` = wireless-only, empty because no WiFi" conclusion, and corrects §8.92's assumed `.1.1.4` = `mtxrSerialNumber` mapping

The user supplied a live `snmpget` result from their own CCR1072-1G-8S+ (a switch/router with no wireless radio):

```
$ snmpget -v2c -c public -Oqv <device> \
    1.3.6.1.4.1.14988.1.1.7.8.0 \
    1.3.6.1.4.1.14988.1.1.7.3.0 \
    1.3.6.1.4.1.14988.1.1.4.1.0
"CCR1072-1G-8S+"    <- .1.1.7.8.0 = board MODEL
"8A350B5AB932"       <- .1.1.7.3.0 = board SERIAL NUMBER
"TA89-928W"          <- .1.1.4.1.0 = SOFTWARE ID
```

**This disproves §8.90's "wireless snmp" hypothesis for group `.7`:** a device with no wireless hardware returns real, populated values for `.7.3` and `.7.8` -- group `.7` is (at least in part) a general board-info table, not wireless-only. The `cout << "wireless snmp"` debug string found at the top of `fcn.0002bc6c` (§8.90) was evidently just one log line from a broader init routine registering multiple, only-partially-related OID sub-tables in a single pass -- not evidence the entire group is wireless-scoped.

**This also corrects §8.92:** `.1.1.4.1.0`'s value (`"TA89-928W"`, a software-ID-formatted string) is the **software ID**, not `mtxrSerialNumber` as §8.92 assumed from memory of public MTXR-MIB naming (that assumption was flagged as unverified at the time and is now known wrong). The real board serial number lives at `.1.1.7.3`, not `.1.1.4`. Note also `.1.1.4.1.0`'s extra `.1` index level (`table.column.row`, not a bare `scalar.0`) confirms this leaf is table-structured, consistent with the pattern found in §8.95.

### 8.95 Full disassembly of `snmp`'s `fcn.0002bc6c` (previously only ~110 of ~470 instructions examined) finds real, load-bearing OID literals for `.1.1.4` and `.1.1.7.1` that §8.90 had wrongly reported absent -- `.1.1.4` is confirmed as the `STD_SNMP_QUERY` software-ID request template sent to `keyman`, but the `.1.1.7.1` table found here has only 4 columns and does not match ground-truth serial(`.3`)/model(`.8`) -- the real board-info `.7` registration remains unlocated

**Correction to §8.90:** its claim that "no literal string or table entry for `.1.1.4` or `.1.1.7.x` exists anywhere in `.rodata`" was based on searching only for pre-formed, fully-qualified OID strings. `snmp` actually builds OIDs by concatenating a shared base string (`"1.3.6.1.4.1.14988.1"`, built once at `0x2bc90`) with short numeric suffix strings via a helper (`fcn.00019d84`/`fcn.0003dabc`, confirmed by decompilation to be a genuine dot-string-to-integer-vector OID parser/concatenator, not cosmetic). Two real suffix literals exist and are load-bearing: `"1.1.4"` (`0x3fc66`) and `"1.1.7.1"` (`0x3fc5a`).

**`.1.1.4` confirmed as the software-ID query template:** immediately after building this OID node (`0x2bde4`-`0x2bdf8`), the code constructs an `nv::message` (`0x2be28`) and inserts several `u32_id` fields -- this is the outbound `STD_SNMP_QUERY` request `snmp` sends to `keyman` for the software ID, matching the ground-truth ("TA89-928W") exactly and closing part of §8.92's previously-unfound "OID-to-field mapping" gap, from the `snmp` side.

**`"1.1.7.1"` -- a real table, but the wrong one:** feeds `fcn.000214f4` (builds a `tree_base` table container), which attaches exactly 4 columns via `fcn.0001e2e8(table, column_id, getter)` (confirmed genuine via its `assert(leaves.find(id)==leaves.end())` failure path) -- columns **2, 3, 4, 5** (getter families `fcn.00022140` for 2/3, `fcn.0002249c` for 4/5). **Column 8 (ground truth's model field) is absent from this table entirely.** Combined with this registration sitting in the same contiguous call sequence as several other `"1.1.N.1"`-shaped suffixes preceding a pivot to a different base (`"11.1"`/`"8.1"`/`"9.1"`), the best-supported reading is that this specific `"1.1.7.1"` table is a small, genuinely wireless-statistics-shaped table (consistent with public MTXR-MIB's `mtxrWlStatTable`-class tables at similar low sub-arcs) that happens to share the `.7` numeric prefix with the real board-info group -- not the board-info group itself.

**Getter mechanism identified but not traced to a value:** `fcn.00022140`/`fcn.0002249c` are generic constructors stamping `{type-vtable-ptr, size/offset, context-ptr}` into a heap struct -- the actual field read is dispatched polymorphically at GET time, not statically resolvable from the constructor alone.

**Unaffected by this session's corrections:** `snmp` still does not import `getBoardSerialNumber()`/`getBoardType()` (reconfirmed) -- only `keyman`/`figman`/`modprobed`/`moduler`/`ww2` do. So regardless of which exact OID table ultimately serves `.7.3`/`.7.8`, the most likely underlying data path remains unchanged from §8.92: `STD_SNMP_QUERY` -> `keyman` -> `getBoardSerialNumber()` (serial) / a `getBoardType()`-class primitive (§8.29, model) -> `/dev/flash`.

**Still unresolved:** the actual registration code for board-info `.7.3`/`.7.8` (evidence for §8.90's "different owning code" hypothesis is now uncertain rather than disproven -- a `.1.1.7.1`-shaped literal exists, but is plausibly an unrelated same-numbered table); which column within `"1.1.7.1"`'s 4-column table (if any) is `.7.5`, the user's originally-observed empty field -- column 5 (same getter family as column 4) is a plausible but unconfirmed candidate.


### 8.96 Exhaustive re-sweep of `snmp`'s ~20 OID-registration functions confirms the real board-info `.1.1.7.3`/`.1.1.7.8` (serial/model) registration does NOT exist anywhere in this binary -- a structural depth-mismatch argument (ground truth is `group.column.row`, every MTXR suffix `snmp` actually builds is `group.entry-index.column.row`) definitively separates the found `"1.1.7.1"` table (4 columns, 2/3/4/5, wireless-shaped) from ground truth's ungrouped `.7.3`/`.7.8` -- closing out `snmp`-side static analysis for this specific question

Continues §8.95, using the ground truth from §8.94. Enumerated every caller of both OID-building primitives (`fcn.0003dabc`, `fcn.00019d84`) across the whole binary via `axtj` -- found roughly 20 distinct registration functions beyond the two previously examined, all fully disassembled and their suffix literals extracted.

**Self-correction along the way:** a 9/10-column table (getters `fcn.00022140`/`fcn.0002249c`, same families as the earlier 4-column table) was initially misattributed to `"1.1.7.1"` -- re-tracing confirms it actually belongs to the `"1.1.1.1"` node (built earlier, consumed by the first `fcn.000214f4` call at `0x2becc`), a previously-unexamined table in its own right but unrelated to group `.7`. The real `"1.1.7.1"` table (§8.95's original finding) is reconfirmed as exactly 4 columns: 2, 3, 4, 5.

**Decisive structural argument:** every MTXR-enterprise OID suffix actually built anywhere in `snmp` follows the shape `base + "1.1.N.1"` (or `"1.N.1"`/`"N.1"`) -- i.e. objects-arc(1) + group(N) + entry-index(1), yielding a final registered OID of `...14988.1.1.N.1.<column>.<row>`. Ground truth's `.1.1.7.3.0`/`.1.1.7.8.0` has **one fewer arc** -- group `7` connects directly to the column number, with no intervening entry-index `.1`. The `"1.1.7.1"` table found would resolve to `...14988.1.1.7.1.3.0`, not `...14988.1.1.7.3.0` -- structurally incompatible with ground truth, not merely coincidentally OID-adjacent as §8.95 had cautiously framed it.

**Exhaustive negative result:** none of the ~20 registration functions load a bare `"7"` or `"1.1.7"` suffix (without a trailing entry-index `.1`). Full inventory of every MTXR (`14988`)-prefixed suffix found anywhere in the binary: `1.1.2(.1)`, `1.1.3`, `1.1.4`, `1.1.5(.1)`, `1.1.6(.1)`, `1.1.7.1` (the wireless-shaped 4-column table), `1.1.9`, `1.1.12`, `1.1.13`, `1.1.14.1.1`, `1.1.15.1.1`, `1.1.16.1.1`/`.2.1.1`/`.3`, `1.1.19.1.1`, `1.22` -- everything else present is standard MIB-II/HOST-RESOURCES/IF-MIB/CDP/LLDP. A raw-binary search for a compile-time little-endian int32 array encoding `{1,3,6,1,4,1,14988,1,1,7,...}` (in case a table were built from a constant array instead of string concatenation) also returned nothing. `snmp`'s import table was re-checked once more: still zero `board`/`flash`/`ioctl`-named symbols.

**Conclusion on `.1.1.7.5`:** most likely belongs to the unrelated 4-column `"1.1.7.1"` wireless-shaped table found here (column 5, same getter family as column 4) -- i.e. the user's originally-observed empty result (§8.90) was almost certainly this wireless table returning nothing on non-wireless hardware, structurally distinct from ground truth's real `.7.3`/`.7.8` board-info fields.

**Bottom line:** the search for `.1.1.7.3`/`.1.1.7.8`'s registration code inside `/nova/bin/snmp` is now genuinely exhaustive -- every OID-building call site in the entire binary was enumerated and inspected, none match. §8.92/§8.95's architectural conclusion (the real board-info `.7` group is served by a different process, most likely `keyman` via `STD_SNMP_QUERY`) stands, now on firmer footing. **Not yet done:** locating the actual `.7.3`/`.7.8` registration/handling code inside `keyman` (or whatever process actually owns it) -- this requires shifting the search to `keyman`'s side of the `STD_SNMP_QUERY` bus rather than further `snmp` disassembly, which is now believed exhausted for this specific question.

### 8.97 `round_sectors()`'s rounding granularity derived in closed form and confirmed against the actual implementation: it keeps only the top 4 significant bits of the disk size in MiB, so granularity = (bracket's power-of-two lower bound) / 8, and doubles every time size crosses a power-of-two boundary

Why this matters: `round_sectors(raw: u32) -> u32` in `src/software_id.rs` is what maps a disk's real size down to the `sector_val` that actually feeds the SOFTWARE ID computation (caller passes `raw = total_sectors >> 11`, i.e. disk size in MiB, since 512 bytes/sector x 2048 = 2^20 = 1 MiB). Every collision-search or `check` run implicitly rides on this rounding, so knowing its exact granularity tells us which nearby sizes are guaranteed to collide onto the same SOFTWARE ID (holding model/serial/identity/bus fixed) versus which are genuinely distinct targets.

The implementation:

```rust
pub fn round_sectors(raw: u32) -> u32 {
    if raw == 0 { return 0; }
    let bits = 32 - raw.leading_zeros() as i32;
    if bits <= 4 { return raw; }
    let shift = (bits - 4) as u32;
    let has_remainder = (raw & ((1 << shift) - 1)) != 0;
    ((raw >> shift) + if has_remainder { 1 } else { 0 }) << shift
}
```

`bits` is the bit-length of `raw`. For `raw` in bracket `[2^n, 2^(n+1))`, `bits = n+1`, so `shift = bits - 4 = n - 3`: everything below the top 4 significant bits is masked off and rounded up. That makes the rounding granularity within the bracket exactly `2^shift = 2^(n-3) = 2^n / 8` -- the bracket's own power-of-two lower bound, divided by 8. Since `n` increases by 1 at each bracket boundary, granularity exactly doubles every time the size crosses a power-of-two boundary. Every value sharing a granularity step rounds up to the same target, hence the same `sector_val` and the same SOFTWARE ID.

Verified brackets (128 MiB and up, since `--unit` enforces a 64 MiB minimum and `bits <= 4` only applies below that):

| size bracket | lower bound | granularity (lower bound / 8) |
|---|---|---|
| 128 ~ 256 MB | 128 | 16 MB |
| 256 ~ 512 MB | 256 | 32 MB |
| 512 ~ 1024 MB | 512 | 64 MB |
| 1024 ~ 2048 MB (1G~2G) | 1024 | 128 MB |
| 2048 ~ 4096 MB (2G~4G) | 2048 | 256 MB |
| 4096 ~ 8192 MB (4G~8G) | 4096 | 512 MB |
| 8192 ~ 16384 MB (8G~16G) | 8192 | 1024 MB (1G) |
| 16384 ~ 32768 MB (16G~32G) | 16384 | 2048 MB (2G) |
| 32768 ~ 65536 MB (32G~64G) | 32768 | 4096 MB (4G) |
| 65536 ~ 131072 MB (64G~128G) | 65536 | 8192 MB (8G) |
| 131072 ~ 262144 MB (128G~256G) | 131072 | 16384 MB (16G) |
| 262144 ~ 524288 MB (256G~512G) | 262144 | 32768 MB (32G) |
| 524288 ~ 1048576 MB (512G~1TiB) | 524288 | 65536 MB (64G) |

A quick-check TypeScript utility exists at `tests/size-range-calc/round-range.ts` (gitignored test harness, run via `bun round-range.ts <size_mb>`) that ports `round_sectors()` exactly and prints the inclusive MB range mapping to the same target -- useful for verifying any arbitrary size instantly instead of doing the bit-math by hand.

**Practical implication for the project's own collision-search campaign:** the sizes searched so far (128/256/512/1024/2048/4096/6144/8192/10240/16384/24576/32768/65536 MB, `--bus ide`) mostly sit at or near the top of their own bracket, leaving unexplored intermediate granularity steps between most consecutive campaign sizes. For example, between 128 and 256 there are 6 more untested targets at the 16 MB granularity: 144/160/176/192/208/224/240 MB -- each mapping to a distinct, not-yet-searched SOFTWARE ID.
