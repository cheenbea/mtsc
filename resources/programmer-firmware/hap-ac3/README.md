# hap_ac3.bin — Identification Notes

Full flash dump for a MikroTik hAP ac³ (`RBD53iG-5HacD2HnD`, board id `d53ig-dk`).

## File identification

- Size: 16,777,216 bytes (16 MiB) exactly -- same size/format as `resources/programmer-firmware/hap-ac2/hap_ac2-7.16.1.bin`
- `file`: ELF 32-bit LSB executable, ARM, EABI5, statically linked, no section header
- MD5: `e47b882f332258171b0bda4ecc5b6bb6`

Not yet region-mapped (bootloader/squashfs/config-gap boundaries) the way
`resources/programmer-firmware/hap-ac2/README.md` did for the ac² dump -- same file shape (size, `file`
signature) strongly suggests the same overall layout (bootloader + dual squashfs +
writable config gap), but not independently confirmed for this device.

## Device context

- Source: https://www.right.com.cn/forum/thread-8377931-1-1.html (poster wsgtrsys,
  2024-5-27) -- board details below confirmed present on that page.
- Board serial: `E7290EC46727` (hex serial `2767c40e`)
- Board MAC: `2cc81b383749`
- Board Memsize: 536,870,912 bytes (512 MiB)
- Board MAC Count: 7
- HW Options: 2908, HW setting: Has_POE out, Has_WiFi
- Factory RouterBoot version: 6.46.8

Associated with `softwareId = "ESXZ-K7X6"` in `keys.toml` (Version 6, Level 4,
EC-KCDSA-verified valid) -- the license key text for that entry was supplied directly in
conversation, not independently re-found on the linked forum page.
