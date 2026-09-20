# QNX IFS (image filesystem)

Validator `src/discovery/validators/qnx_ifs.cpp` (signature `qnx-ifs` in
`signatures/core.toml`), reader `src/filesystems/qnxifs/QnxIfsReader.{h,cpp}`
registered as `qnx-ifs`, decoder `src/core/ucl.{h,cpp}` (UCL NRV2B), tests
`tests/unit/discovery/qnx_ifs_validator_test.cpp`,
`tests/unit/filesystems/qnxifs_test.cpp`, `tests/unit/core/ucl_test.cpp`.

The IFS is the boot image `mkifs` builds for QNX Neutrino: the startup
program, the kernel (`procnto`), the boot script and every file the system
needs before a disk filesystem is mounted, usually under `/proc/boot`. On
automotive head units it sits in its own eMMC partitions (`ifs_a`, `ifs_b`,
`ifs_recovery`) and is also stored as a file inside the QNX6 partitions and
inside update packages. The image is immutable: there is no history to
recover, and the whole image (or its compressed form) is checksummed.

## On-disk layout

Every multi-byte field is in the target's byte order; `flags1` bit `0x02`
(and the image header's `flags` bit `0x01`) say big-endian. The magic in
`signatures/core.toml` is the little-endian encoding `eb 7e ff 00`; the
reader also accepts `00 ff 7e eb` at offset 0.

### Startup header (256 bytes, `struct startup_header`)

| offset | field | notes |
|---|---|---|
| 0 | `signature` u32 | `0x00ff7eeb` |
| 4 | `version` u16 | 1 |
| 6 | `flags1` u8 | `0x01` virtual, `0x02` big-endian, `0x1c` compression: `0x04` zlib, `0x08` lzo, `0x0c` ucl |
| 7 | `flags2` u8 | none defined; vendors set bits after mkifs (see checksums) |
| 8 | `header_size` u16 | 256 |
| 10 | `machine` u16 | ELF `e_machine`: 3 x86, 8 mips, 20 ppc, 40 arm, 42 sh, 62 x86_64, 183 aarch64 |
| 12 | `startup_vaddr` u32 | entry point after the IPL |
| 16 | `paddr_bias` u32 | |
| 20 | `image_paddr` u32 | where the image lives in physical memory |
| 24 | `ram_paddr` u32 | where the IPL copies it |
| 28 | `ram_size` u32 | RAM used by startup and the image |
| 32 | `startup_size` u32 | header plus startup code plus trailer; never compressed |
| 36 | `stored_size` u32 | the whole image as stored |
| 40 | `imagefs_paddr` u32 | filled by the IPL |
| 44 | `imagefs_size` u32 | size of the uncompressed image filesystem |
| 48 | `preboot_size` u16 | |
| 50 | `zero0` u16, 52 `zero[3]` u32 | must be zero (the discriminator against stray magics) |
| 64 | `info[48]` u32 | `startup_info` records; vendors write board strings here |

The startup code follows the header; the last 4 bytes of the `startup_size`
region are the startup trailer, a checksum word (see below).

### Image filesystem header (88 bytes plus mountpoint, `struct image_header`)

At `startup_size` (uncompressed) or at the start of the decompressed data:

| offset | field | notes |
|---|---|---|
| 0 | `signature` char[7] | `imagefs` |
| 7 | `flags` u8 | `0x01` big-endian, `0x02` read-only, `0x04` inode bits valid |
| 8 | `image_size` u32 | header through trailer |
| 12 | `hdr_dir_size` u32 | header through the last directory entry |
| 16 | `dir_offset` u32 | first directory entry |
| 20 | `boot_ino[4]` u32 | inodes of the bootstrap executables (procnto) |
| 36 | `script_ino` u32 | inode of the compiled boot script |
| 40 | `chain_paddr` u32 | next image, if any |
| 44 | `spare[10]` u32 | |
| 84 | `mountflags` u32 | |
| 88 | `mountpoint` | NUL-terminated, padded to `dir_offset` |

The last 4 bytes of `image_size` are the image trailer, a checksum word.

### Directory entries (`union image_dirent`)

From `dir_offset` to `hdr_dir_size`, each entry starts with the 24-byte
`image_attr`: `size` u16 (of the whole entry, padded to 4; 0 ends the
directory), `extattr_offset` u16 (0: none), `ino` u32, `mode` u32, `gid` u32,
`uid` u32, `mtime` u32. The high bits of `ino` are flags, not part of the
number: `0x80000000` processed ELF, `0x40000000` run-once ELF, `0x20000000`
bootstrap executable. `ino` 0 means "skip this entry". The body depends on
`mode & S_IFMT`:

| type | body |
|---|---|
| regular `0100000` | `offset` u32 (from the image header), `size` u32, path |
| directory `0040000` | path (the root is the entry with an empty path) |
| symlink `0120000` | `sym_offset` u16, `sym_size` u16, path, then the target at path + `sym_offset` |
| char `0020000`, block `0060000`, fifo `0010000`, named `0050000`, socket `0140000` | `dev` u32, `rdev` u32, path |

Paths are NUL-terminated, relative, without a leading slash. Entries are in
the order mkifs wrote them (symlinks first in the corpus images, then
directories, then files); the reader keeps that order.

### Compression

When `flags1 & 0x1c` is non-zero the bytes after the startup code are the
compressed image filesystem; `stored_size - startup_size` covers them:

* **ucl** (`0x0c`, the mkifs default) and **lzo** (`0x08`): a sequence of
  blocks, each a 2-byte big-endian compressed length followed by that many
  bytes, ended by a zero length, then padding to 4 and the checksum word.
  Each block decodes to at most 64 KiB (mkifs compresses 64 KiB at a time).
  UCL blocks are NRV2B streams (decoded by `src/core/ucl.cpp`, written from
  the published algorithm; UCL's `ucl_nrv2b_99_compress` is what mkifs
  calls); LZO blocks are LZO1X (`core/Compression.h`).
* **zlib** (`0x04`): one gzip stream (mkifs documents that such images are
  not bootable).
* **lz4** (`0x10`): no SDP release documents it; the reader accepts the code
  with the same block framing as ucl/lzo and decodes raw LZ4 blocks. The
  `exMifsLz4` / `exMifsLzo` vendor containers in the reference material use a
  different, block-table framing and are not this format.

### Checksums

Both trailers make the u32 sum (target byte order) of their region zero:
`sum(startup header .. startup trailer) == 0` and
`sum(image header .. image trailer) == 0`; for a compressed image the IPL
checks `sum(compressed area .. its trailer) == 0` over
`stored_size - startup_size` bytes. On every corpus image the image and
compressed-area sums are zero while the startup sum is not: `flags2` is set
to 1 after mkifs (the residual is exactly `flags2 << 24`; the diagnostic says
so) and the recovery image also carries a board string patched into `info[]`.
A startup mismatch is therefore reported and never lowers the tier.

## Validator

1. Reads `flags1` for the byte order, then rejects the hit as noise
   (`nullopt`) unless `version == 1`, `header_size == 256` and the four zero
   fields are zero: a 4-byte magic inside compressed data is common (two in
   one 2 MiB splash partition of the auto-ivi corpus).
2. Records the header fields as attrs; `startup_size` below 256, unaligned or
   above `stored_size` is `qnx-ifs-bad-startup-size` (magic tier). An
   unknown `machine` is a warning only.
3. Verifies the startup checksum (`startup_checksum`, no tier change).
4. Uncompressed: needs `imagefs` at `startup_size`; nested `dir_offset <=
   hdr_dir_size <= image_size` gives `structural`, a directory chain that
   walks to its end gives `consistent`, a zero image sum gives `verified`.
   Size is `startup_size + image_size` (or `stored_size` when larger).
5. Compressed: the first block length must be non-zero and inside the data
   (`structural`); the chain is walked to its terminator (bounded by
   `max_blocks`, TOML key, default 1048576) and `stored_size` is accepted
   when it ends within padding plus a checksum word of the chain, else the
   chain extent is the size. A zero sum over the compressed area gives
   `verified`. zlib: a gzip magic at `startup_size`, size `stored_size`.

Attrs: `version`, `flags1`, `flags2`, `machine`, `startup_vaddr`,
`paddr_bias`, `image_paddr`, `ram_paddr`, `ram_size`, `startup_size`,
`stored_size`, `imagefs_size`, `preboot_size`, `compressed` (`none`, `zlib`,
`lzo`, `ucl`, `lz4`), `startup_checksum`; uncompressed: `image_flags`,
`image_size`, `hdr_dir_size`, `dir_offset`, `boot_ino` (flag bits stripped),
`script`, `mountpoint`, `entries`, `files`, `image_checksum`; compressed:
`blocks`, `compressed_bytes`, `stored_checksum`. `max_dir_entries` (TOML,
default 1000000) bounds the directory count.

| code | severity | when |
|---|---|---|
| `qnx-ifs-truncated-header` | warning | fewer than 64 bytes after the magic |
| `qnx-ifs-bad-startup-size` | warning | `startup_size` cannot hold the header or exceeds `stored_size` |
| `qnx-ifs-unknown-machine` | warning | `machine` is not in the known list |
| `qnx-ifs-unsupported-compression` | warning | compression code 5..7 |
| `qnx-ifs-truncated` | warning | `startup_size`, `image_size` or a block chain runs past the data |
| `qnx-ifs-startup-checksum-bad` | warning | startup region does not sum to zero |
| `qnx-ifs-no-image-header` | warning | no `imagefs` at `startup_size` |
| `qnx-ifs-bad-image-header` | warning | `dir_offset`, `hdr_dir_size`, `image_size` not nested |
| `qnx-ifs-dirent-corrupt` | warning | the directory chain breaks (validator: entry count so far) |
| `qnx-ifs-image-checksum-bad` | warning | image does not sum to zero |
| `qnx-ifs-stored-size-mismatch` | info | `stored_size` disagrees with the structures |
| `qnx-ifs-bad-compressed-block` | warning | first block length zero or past the data; no gzip magic |
| `qnx-ifs-limit-blocks` | warning | more than `max_blocks` blocks |
| `qnx-ifs-stored-checksum-bad` | warning | compressed area does not sum to zero |

## Reader

`open()` parses the startup header (fails with `qnx-ifs-bad-header` or
`qnx-ifs-unsupported-compression`), decompresses a compressed image into
memory, parses the image header (`qnx-ifs-no-image-header`,
`qnx-ifs-bad-image-header`) and counts the directory. `walk()` emits the
directory in stored order; `WalkOptions::history` is accepted and ignored.

Decompression is bounded by `Limits::max_file_bytes` and by
`max_decompress_ratio` times the compressed byte count; a tripped cap
(`qnx-ifs-decompress-cap`) or a block that does not decode
(`qnx-ifs-decompress-failed`) keeps the prefix, and the directory is walked
as far as it reaches. `open()` uses the default `Limits`; a `walk()` whose
limits differ decompresses again with the caller's.

### What the reader captures

`FileMeta`: `path`, `kind` (from `mode`), `mode` (permission bits), `uid`,
`gid`, `mtime` (the only timestamp mkifs records), `inode` (flag bits
stripped), `nlink` 1, `size` (`size` for files, target length for symlinks),
`link_target`, `rdev_major`/`rdev_minor` (QNX `major()`/`minor()`: bits
10-15 and 0-9 of `rdev`), and `extra`: `data_offset` (files, from the image
header), `processed_elf`, `runonce_elf`, `bootstrap` (the `ino` flag bits),
`script` (the entry `script_ino` names: the compiled boot script, emitted as
a regular file and not decoded), `boot` (named by `boot_ino`),
`extattr_offset`, `dev` and `rdev` (devices, hex). The root entry (empty
path) is not emitted; its mode and mtime are `root_mode` / `root_mtime`.

`FilesystemInfo`: `size` (`stored_size` or the extent), `compression`
(`ucl`, `lzo`, `lz4`, `zlib` or empty), `label` (mountpoint), `endian`
(of the image header) and attrs `endian`, `version`, `machine`, `flags1`,
`flags2`, `startup_vaddr`, `paddr_bias`, `image_paddr`, `ram_paddr`,
`ram_size`, `startup_size`, `stored_size`, `imagefs_size`, `preboot_size`,
`startup_checksum`, `compressed`, `blocks`, `compressed_bytes`,
`decompressed_bytes`, `decompress_capped`, `decompress_failed`,
`image_flags`, `image_size`, `hdr_dir_size`, `dir_offset`,
`image_checksum`, `boot_ino`, `script_ino`, `chain_paddr`, `mountflags`,
`mountpoint`, `entries`, `files`, `dirs`, `symlinks`, `devices`,
`skipped_entries`, `root_mode`, `root_mtime`.

### Limits

| Limits field | effect |
|---|---|
| `max_file_bytes` | decompressed image size (`qnx-ifs-decompress-cap`) and bytes streamed per file (`qnx-ifs-limit-file-bytes`) |
| `max_decompress_ratio` | decompressed image size as a multiple of the compressed bytes (`qnx-ifs-decompress-cap`) |
| `max_nodes_per_fs` | directory entries parsed (`qnx-ifs-limit-nodes`) and compressed blocks decoded (`qnx-ifs-limit-blocks`; the image is cut there, `decompress_capped`) |
| `max_files` | entries emitted (`qnx-ifs-limit-files`) |
| `max_bytes` | enforced by the Sink |

### Reader diagnostics

| code | severity | when |
|---|---|---|
| `qnx-ifs-startup-checksum-bad` | warning | startup region does not sum to zero (see Checksums) |
| `qnx-ifs-image-checksum-bad` | warning | image does not sum to zero, or is truncated so it cannot be checked |
| `qnx-ifs-decompress-failed` | warning | a compressed block did not decode; image cut there, `truncated` |
| `qnx-ifs-decompress-cap` | warning | a cap stopped decompression; image cut there, `truncated` |
| `qnx-ifs-image-truncated` | warning | `hdr_dir_size` or `image_size` past the data, or a block chain with no terminator |
| `qnx-ifs-dirent-corrupt` | warning | entry size below 24 or past the directory (walk stops), no NUL-terminated path, unknown type, symlink target outside its entry (entry skipped or target lost) |
| `qnx-ifs-entry-skipped` | info | an entry with inode 0, which mkifs defines as "skip" |
| `qnx-ifs-file-out-of-range` | warning | file data past the image; the prefix inside it is recovered, entry `truncated` |
| `qnx-ifs-limit-nodes` / `-blocks` / `-files` / `-file-bytes` | warning | a `Limits` guard tripped; `truncated` set |
| `qnx-ifs-sink-error` | warning | the Sink refused an entry; skipped |

`open()` fails with `qnx-ifs-bad-header` (no signature, version, header
size, `startup_size`), `qnx-ifs-unsupported-compression`,
`qnx-ifs-no-image-header` or `qnx-ifs-bad-image-header`.

### History

None. An IFS is written once by mkifs; nothing in it is superseded or
deleted.

### Verified on

* `qnx-example` corpus, `ifs_a` partition (32 MiB at `0x12800000`): aarch64,
  UCL, 196 blocks, 5.2 MB stored for 12.7 MB of image, 124 entries (75
  files); the
  listing (names, kinds, sizes, modes, owners, mtimes, inodes) and every
  extracted file are identical to `dumpifs` (QNX's own tool, run against
  the same slice by the test when it is installed). `ifs_recovery` (256 MiB
  at `0x2800000`): UCL, 948 entries, 94 MB decompressed, listing identical.
  Both carry `flags2 = 1` (startup checksum residual `0x01000000`); the
  recovery image also has a board string in `info[]`.
* `auto-ivi-example` splash partition (2 MiB at `0x6e904400`): two
  startup magics inside compressed data, both rejected by the version and
  header-size check.

### Known gaps

* ETFS and EFS (the NAND and NOR flash filesystems) are separate formats and
  not covered here; QNX6 is the `qnx6` reader.
* lz4 images are decoded on the assumption that they use the ucl/lzo block
  framing; no sample exists.
* The compiled boot script is emitted as bytes; the script commands are not
  decoded into text.
* Extended attributes (`extattr_offset`) are reported but not parsed.
* `startup_info` records in `info[]` are not decoded.
* The `chain_paddr` link to a following image is reported, not followed;
  a nested IFS stored as a file is found by the scan of extracted files.

## References

* QNX SDP documentation: *Building Embedded Systems*, "Structure of an OS
  image" and "startup_header"; the `mkifs` and `dumpifs` utility pages
  (read for understanding).
* QNX `sys/startup.h` and `sys/image.h` (Apache-2.0 header files) for the
  field layout.
* UCL 1.03 NRV2B algorithm description (the decoder is an independent
  implementation; the test vectors were produced with libucl).
* `dumpifs` (QNX) as the parity tool; qnxmount (NFI, Apache-2.0) does not
  cover IFS.
