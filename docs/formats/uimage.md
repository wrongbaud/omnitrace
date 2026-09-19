# U-Boot legacy image (uImage)

This page is for examiners who see a `uimage` node in `INFO.yaml` (usually
the kernel of a router or camera) and for contributors who will write the
container reader. After reading it you know what the header holds, why the
finding is `verified` or only `consistent`, which attrs and diagnostics it
emits, and what is not opened yet.

`src/discovery/validators/uimage.cpp` (validator `uimage`), signature
`uimage` in `signatures/core.toml` (magic `27 05 19 56`, big-endian, format
`uimage`, category `container`). The FIT successor format has its own page
(`docs/formats/fit.md`). There is no container reader: `analyze` makes a
`container` node whatever the category (`kind_for`,
`src/discovery/Recurse.cpp:194`), adds the `analyze-no-reader` warning and
the coverage row `uimage / unsupported / "no container reader registered"`,
and carves it (`0x00050000-uimage.bin` on the router image).

## On-disk layout

A 64-byte big-endian header followed by the payload:

| offset | field | notes |
|---|---|---|
| 0 | `ih_magic` u32 | `0x27051956` |
| 4 | `ih_hcrc` u32 | crc32 (zlib) of the header with this field zeroed |
| 8 | `ih_time` u32 | build time, epoch seconds |
| 12 | `ih_size` u32 | payload bytes |
| 16 | `ih_load` u32 | load address |
| 20 | `ih_ep` u32 | entry point |
| 24 | `ih_dcrc` u32 | crc32 (zlib) of the payload |
| 28 | `ih_os` u8 | linux, u-boot, qnx, vxworks, ... |
| 29 | `ih_arch` u8 | mips, arm, arm64, powerpc, x86, ... |
| 30 | `ih_type` u8 | kernel, ramdisk, multi, firmware, script, filesystem, flatdt, kernel_noload, ... |
| 31 | `ih_comp` u8 | none, gzip, bzip2, lzma, lzo, lz4, zstd |
| 32 | `ih_name[32]` | image name, NUL-padded |

The name tables the validator uses (`os_name`, `arch_name`, `type_name`,
`comp_name`, `uimage.cpp:20-65`) follow U-Boot `include/image.h`; unknown
values render as `unknown(n)`.

## What the validator checks

| tier | assigned when |
|---|---|
| magic | fewer than 64 bytes (`uimage-truncated-header`) or the header CRC fails (`uimage-header-crc-mismatch`); no fields are trusted |
| consistent | header CRC ok but the payload is truncated (`uimage-truncated`, `data_crc=unchecked`) or its CRC differs (`uimage-data-crc-mismatch`, `data_crc=mismatch`) |
| verified | header CRC and payload CRC both match (`uimage.cpp:94`, kept when `data_crc` is set to `ok` at `uimage.cpp:116`) |

**Size.** `64 + ih_size`, clamped to the data. Because the header CRC covers
every field, a verified hit is never noise; the payload CRC is what tells a
modified kernel from the one the vendor shipped.

**Category.** `ih_type` 2 (kernel) or 14 (kernel_noload) changes the finding's
category to `kernel` (`uimage.cpp:104`), so `scan --json` reports
`"category": "kernel"` for the router kernel and `container` for a
`filesystem`-type wrapper.

## Attributes

`name`, `os`, `arch`, `type`, `compression`, `data_size`, `load_address`
(hex), `entry_point` (hex), `timestamp`, `data_crc` (`ok` / `mismatch` /
`unchecked`). Meanings: `docs/reference/ATTRS.md`. `name` and `timestamp`
are the cheapest provenance an image offers ("MIPS OpenWrt Linux-4.14.63",
built 2021-07-13).

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `uimage-truncated-header` | warning | fewer than 64 bytes; magic tier |
| `uimage-header-crc-mismatch` | warning | header CRC differs; magic tier, fields not reported |
| `uimage-truncated` | warning | payload extends past the data; size clamped, tier consistent |
| `uimage-data-crc-mismatch` | warning | payload CRC differs from `ih_dcrc`; tier consistent |

## Verified on

* `tests/fixtures/out/uimage-lzma.img` (mkimage, type `filesystem`, arm,
  lzma): `verified`, size 322755 = 64 + 322691, `data_crc=ok`.
* The 16 MiB OpenWrt router image used throughout `docs/CLI.md`: `uimage` at
  `0x50000`, `verified`, `type=kernel`, `arch=mips`, `compression=lzma`,
  `name=MIPS OpenWrt Linux-4.14.63`, category `kernel`.

## Not yet supported

* No container reader: the payload is not decompressed or handed back to the
  scanner, so a filesystem wrapped in a `filesystem`-type uImage is only found
  if its own magic is visible (it is not when the wrapper is compressed).
* `multi` images (a NUL-terminated list of sizes before the parts) are not
  split into their parts.
* No decompression probe: `compression=lzma` is the header's claim, not a
  verified stream.

## References

* U-Boot `include/image.h` (read for understanding; no code copied)
* U-Boot `tools/mkimage` and `dumpimage` as the reference tools
