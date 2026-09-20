# Android boot and vendor boot images

`src/discovery/validators/android_boot.cpp` (validator `android-boot`),
signatures `android-boot` (`ANDROID!`, format `android-boot`) and
`android-vendor-boot` (`VNDRBOOT`, format `android-vendor-boot`) in
`signatures/core.toml`, category `container`.

## Header versions 0-2 (`ANDROID!`, little-endian)

| offset | field | constraint |
|---|---|---|
| 8 | `kernel_size`, 12 `kernel_addr` | |
| 16 | `ramdisk_size`, 20 `ramdisk_addr` | |
| 24 | `second_size`, 28 `second_addr`, 32 `tags_addr` | |
| 36 | `page_size` | power of two, 2048..65536 |
| 40 | `header_version` | 0..4 (same offset in every version) |
| 44 | `os_version` | A.B.C in bits 31..11, patch level year/month in bits 10..0 |
| 48 | `name[16]`, 64 `cmdline[512]`, 576 `id[32]`, 608 `extra_cmdline[1024]` | |
| 1632 | v1: `recovery_dtbo_size` u32, `recovery_dtbo_offset` u64, 1644 `header_size` | |
| 1648 | v2: `dtb_size` u32, 1652 `dtb_addr` u64 | |

`size` = `page_size` + each of kernel, ramdisk, second, recovery_dtbo (v1+),
dtb (v2+) rounded up to `page_size`.

## Header versions 3-4 (fixed 4096-byte page)

| offset | field |
|---|---|
| 8 | `kernel_size`, 12 `ramdisk_size`, 16 `os_version`, 20 `header_size` |
| 40 | `header_version`, 44 `cmdline[1536]` |
| 1580 | v4: `signature_size` |

`size` = 4096 + kernel + ramdisk (+ signature, v4), each page-rounded.

## Vendor boot (`VNDRBOOT`, v3/v4)

| offset | field |
|---|---|
| 8 | `header_version` (3/4), 12 `page_size`, 16 `kernel_addr`, 20 `ramdisk_addr` |
| 24 | `vendor_ramdisk_size`, 28 `cmdline[2048]`, 2076 `tags_addr`, 2080 `name[16]` |
| 2096 | `header_size`, 2100 `dtb_size`, 2104 `dtb_addr` u64 |
| 2112 | v4: `vendor_ramdisk_table_size`, 2116 `entry_num`, 2120 `entry_size`, 2124 `bootconfig_size` |

`size` = header, vendor ramdisk, dtb (+ table and bootconfig, v4), each
page-rounded.

## Tiers

| tier | when |
|---|---|
| magic | `header_version` > 4, bad `page_size`, kernel and ramdisk both empty (the magic is a bootloader string literal), or a cut header |
| structural | declared sections run past the data (`size` clamped) |
| consistent | every declared section inside the data |

## Attributes

`header_version`, `page_size`, `kernel_size`, `ramdisk_size`, `cmdline`
(control bytes replaced by `_`, `extra_cmdline` appended), `os_version`,
`os_patch_level`, `name`, `id` (hex); v0-2 also `second_size`,
`kernel_addr`, `ramdisk_addr`, `second_addr`, `tags_addr`,
`recovery_dtbo_size`, `dtb_size`, `header_size`; v3/v4 `header_size`,
`signature_size`; vendor boot `vendor_ramdisk_size`, `dtb_size`,
`vendor_ramdisk_table_size`, `bootconfig_size`.

## Diagnostics

`android-boot-truncated-header`, `android-boot-bad-header`,
`android-boot-empty` (magic); `android-boot-truncated` (structural).

## Verified on

* `auto-ivi-example` at `0x104400`: v0, 16 KiB pages, 6409432-byte
  kernel, no ramdisk, 6438912 bytes.
* `mkbootimg` (AOSP) v2, v4 and vendor v4 images: sizes equal the files.

## What the reader writes

Reader: `src/containers/androidboot/AndroidBootReader.{h,cpp}`, registered
for both `android-boot` and `android-vendor-boot`, tests
`tests/unit/containers/archive_test.cpp`.

One entry per non-empty section, named for what it is: `kernel`, `ramdisk`,
`second`, `recovery_dtbo`, `dtb` and `boot_signature` for a boot image,
`vendor_ramdisk`, `dtb`, `vendor_ramdisk_table` and `bootconfig` for a vendor
boot image. Each is streamed 1 MiB at a time from its page-aligned offset.

The one subtlety is where the first section starts. For a boot image the
header occupies exactly one page whatever `header_size` says; for a vendor
boot image it occupies `ceil(header_size / page_size)`. Those two rules
genuinely differ, and AOSP's `unpack_bootimg.py` does the same.

Sections are emitted **as stored**. A ramdisk is normally a gzipped cpio, and
the analysis pass re-scans every file this writes, so the chain
`boot.img -> ramdisk -> gzip -> cpio -> the early rootfs` is followed without
any special case.

`ContainerInfo`: `size` (the sum of the page-aligned sections), and attrs
`header_version`, `page_size`, `board_name` and one `<section>_size` per
section.

## Known gaps

* Sections are extracted but not hashed against the header's `id` field, so a
  tampered section is not detected here.
* `cmdline`, `os_version` and the addresses are recorded by the validator as
  attrs; the reader does not re-emit them as a file.
* Header versions above 4 and the `VNDRBOOT` versions below 3 are refused at
  `open()`; the node keeps the validator's finding.
