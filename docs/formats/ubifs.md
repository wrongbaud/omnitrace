# UBIFS (discovery validator)

`src/discovery/validators/ubifs.cpp` (validator `ubifs`), signature `ubifs`
in `signatures/core.toml` (format `ubifs`, category `filesystem`). This page
covers identification; a reader is a separate piece of work.

## On-disk layout (little-endian)

Every node starts with the 24-byte common header: `magic` u32
(`0x06101831`), `crc` u32, `sqnum` u64, `len` u32, `node_type` u8,
`group_type` u8, pad. `crc` is crc32 with init `0xFFFFFFFF` and no final xor
over bytes 8..`len`. Only the superblock node (type 6, `len` 4096, first
node of LEB 0) anchors a filesystem; hits on other node types are rejected
because they are the body of a filesystem whose superblock is elsewhere.

Superblock fields (after the common header):

| offset | field | constraint |
|---|---|---|
| 26 | `key_hash` u8 | 0 (r5) or 1 (test) |
| 27 | `key_fmt` u8 | 0 |
| 28 | `flags` u32 | |
| 32 | `min_io_size` u32 | power of two |
| 36 | `leb_size` u32 | multiple of `min_io_size` |
| 40 | `leb_cnt` u32 | 1 <= x <= `max_leb_cnt` |
| 44 | `max_leb_cnt` u32 | |
| 56 | `log_lebs`, 60 `lpt_lebs`, 64 `orph_lebs`, 68 `jhead_cnt` | 3 + log + lpt + orph < `leb_cnt` |
| 72 | `fanout` u32 | >= 3 |
| 80 | `fmt_version` u32 | 1..5 |
| 84 | `default_compr` u16 | none / lzo / zlib / zstd |
| 96 | `rp_size` u64, 104 `time_gran` u32 | |
| 108 | `uuid[16]` | |
| 124 | `ro_compat_version` u32 | |
| 256 | `hash_algo` u16 (fmt 5, authentication) | |

`size` = `leb_size * leb_cnt`, clamped. Inside a UBI volume the LEBs are not
contiguous on flash, so the size is only meaningful for a plain image; the
UBI finding owns the region in that case.

Alignment: a superblock starts a LEB, so a hit is accepted only at an offset
that is a multiple of `min_io_size` or of 512.

## Tiers

| tier | when |
|---|---|
| rejected | not a superblock node, or unaligned |
| magic | field constraints fail |
| structural | fields sane but the LEB budget does not fit, or CRC unchecked |
| consistent | LEB budget fits, CRC mismatch |
| verified | node CRC matches |

## Attributes

`fmt_version`, `ro_compat_version`, `min_io_size`, `leb_size`, `leb_cnt`,
`max_leb_cnt`, `log_lebs`, `lpt_lebs`, `orph_lebs`, `jhead_cnt`, `fanout`,
`lsave_cnt`, `key_hash`, `flags`, `default_compr`, `rp_size`, `sqnum`,
`uuid`, `hash_algo`, `crc_check`.

## Diagnostics

`ubifs-bad-superblock` (magic), `ubifs-bad-leb-layout` (warning),
`ubifs-crc-mismatch` (warning), `ubifs-truncated` (info: fewer LEBs present
than `leb_cnt`).

## Verified on

* `tests/fixtures/out/ubifs.img` (mkfs.ubifs 2.1.5): verified, LEB 129024 x 15,
  size equal to the file.
