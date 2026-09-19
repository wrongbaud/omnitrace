# Compressed streams: gzip, xz, lz4, zstd

This page is for examiners who see `gzip` / `xz` / `lz4` / `zstd` findings
with a `?` size and for contributors who will write the stream readers. After
reading it you know what each validator checks, why these findings never rise
above `structural`, how conflict resolution hides the streams that make up a
filesystem, and what is not decoded yet.

Four validators, one per stream format, all in `src/discovery/validators/`
and registered from `signatures/core.toml` with category `compressed`:

| format | signature | magic | validator |
|---|---|---|---|
| `gzip` | `gzip` | `1f 8b 08` | `gzip.cpp` (`gzip`) |
| `xz` | `xz` | `fd 37 7a 58 5a 00` | `xz.cpp` (`xz`) |
| `lz4` | `lz4-frame` | `04 22 4d 18` | `lz4.cpp` (`lz4`) |
| `zstd` | `zstd` | `28 b5 2f fd` | `zstd.cpp` (`zstd`) |

None of them sets a size: the header does not state the compressed length,
and finding the end means decoding the stream. There is no container reader
either: `analyze` makes a `container` node of unknown extent, which claims no
bytes and parents nothing, adds `analyze-no-reader` and `carve-unknown-size`,
and the coverage row `<format> / unsupported / "no container reader
registered"`. The decoders themselves exist (`include/omnitrace/core/Compression.h`,
used by the SquashFS reader); what is missing is the stream walker.

## Why structural is the ceiling

A validated filesystem is built from these streams: SquashFS data blocks are
gzip/xz/lz4/zstd, JFFS2 file nodes carry zlib data. Conflict resolution moves
a finding into `also_matched` when it lies inside a finding of **strictly
higher** confidence (`docs/formats/signatures.md`). Keeping the streams at
`Confidence::Structural` (60) means every stream inside a `consistent` (85)
SquashFS or a `verified` (99) JFFS2 disappears from the output, while a
stream that sits on its own (a compressed kernel, a `.tar.gz` update
package) is still reported. The xz flags CRC is therefore only used to
*reject* corrupt headers, never to lift a stream to `verified`
(`xz.cpp:5-9`).

## gzip (RFC 1952)

Header: `1f 8b`, `CM` (8 = deflate, part of the magic), `FLG`, `MTIME` u32
LE, `XFL`, `OS`, then optional `FEXTRA` (u16 length + data), `FNAME`
(NUL-terminated), `FCOMMENT`, `FHCRC`.

| tier | assigned when |
|---|---|
| rejected | any reserved `FLG` bit (0xE0) is set |
| magic | fewer than 10 bytes (`gzip-truncated-header`), `OS` byte above 13 and not 255 (`gzip-bad-os`), or `FEXTRA` length missing |
| structural | header parsed (`gzip.cpp:45`) |

`FNAME` is read through `span.cstring` capped by the signature's
`max_name_len` (4096 in `core.toml`) so a hostile header cannot make the
validator scan the whole image. `FCOMMENT` and `FHCRC` are flagged but not
walked, so `header_len` stops at the name.

Attributes: `mtime`, `xfl`, `os`, `flags` (hex), `text`, `extra_len`,
`original_name`, `has_comment`, `has_header_crc`, `header_len`.

## xz (.xz stream header)

Header: 6 magic bytes, 2 stream-flag bytes (byte 0 must be 0; byte 1 low
nibble is the check type 0 none / 1 crc32 / 4 crc64 / 10 sha256, high nibble
0), then the CRC32 of the two flag bytes.

| tier | assigned when |
|---|---|
| magic | fewer than 12 bytes (`xz-truncated-header`), invalid flags (`xz-bad-stream-flags`), or the flags CRC differs (`xz-header-crc-mismatch`) |
| structural | flags valid and their CRC matches (`xz.cpp:48`) |

Attributes: `check`.

## lz4 (frame format)

Header: 4 magic bytes, `FLG` (bits 7-6 version must be 01, bit 5 block
independence, bit 4 block checksum, bit 3 content size present, bit 2 content
checksum, bit 1 reserved, bit 0 dictionary id present), `BD` (bits 6-4 block
max size 4..7, other bits 0), optional u64 content size and u32 dictionary id,
then the header checksum byte.

| tier | assigned when |
|---|---|
| magic | fewer than 6 bytes (`lz4-truncated-header`) or invalid `FLG` / `BD` (`lz4-bad-frame-descriptor`) |
| structural | descriptor valid (`lz4.cpp:33`) |

Attributes: `block_max_size` (`64KiB` .. `4MiB`), `block_independence`,
`block_checksum`, `content_checksum`, `content_size`, `dictionary_id` (hex),
`header_len`. The header checksum byte (`HC`) is counted in `header_len` but
not verified.

## zstd (RFC 8878 frame header)

Header: 4 magic bytes, the frame header descriptor (bits 7-6 content-size
field size, bit 5 single segment, bits 4 and 3 reserved, bit 2 content
checksum, bits 1-0 dictionary-id size), a window descriptor unless single
segment, the dictionary id (0/1/2/4 bytes) and the frame content size
(0/1/2/4/8 bytes).

| tier | assigned when |
|---|---|
| magic | fewer than 5 bytes (`zstd-truncated-header`) or a reserved bit set (`zstd-bad-frame-header`) |
| structural | descriptor valid (`zstd.cpp:33`) |

Attributes: `content_checksum`, `single_segment`, `window_size` (bytes,
absent for single segment), `dictionary_id`, `frame_content_size`,
`header_len`. Skippable frames (`50 2a 4d 18` .. `5f 2a 4d 18`) have no
signature.

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `gzip-truncated-header` | warning | fewer than 10 bytes, or `FEXTRA` length missing; magic tier |
| `gzip-unusual-xfl` | info | `XFL` is not 0, 2 or 4 |
| `gzip-bad-os` | warning | `OS` byte undefined; magic tier |
| `xz-truncated-header` | warning | fewer than 12 bytes; magic tier |
| `xz-bad-stream-flags` | warning | flags invalid; magic tier |
| `xz-header-crc-mismatch` | warning | flags CRC differs; magic tier |
| `lz4-truncated-header` | warning | fewer than 6 bytes; magic tier |
| `lz4-bad-frame-descriptor` | warning | `FLG` / `BD` invalid; magic tier |
| `zstd-truncated-header` | warning | fewer than 5 bytes; magic tier |
| `zstd-bad-frame-header` | warning | reserved bits set; magic tier |

## Verified on

* `tests/fixtures/out/nested.tar.gz`: one `gzip` finding at `0x0`,
  `structural`, size `?`, `os=unknown`, `xfl=2`.
* `tests/fixtures/out/squashfs-xz.img` and `squashfs-zstd.img`: the six
  `xz` / `zstd` streams inside each are absorbed into the `squashfs`
  finding's `also_matched` (`scan --json` shows them there;
  `tests/unit/discovery/resolve_test.cpp` covers the rule). The gzip and lz4
  variants show nothing to absorb: SquashFS gzip blocks are zlib streams
  without the `1f 8b` member header, and its lz4 blocks are raw, without the
  frame magic.

## Not yet supported

* No extent: deflate blocks, the xz index, lz4 block sizes and zstd blocks
  are not walked, so `size` is always unknown and nothing nested is found.
* No decode probe, so `verified` is unreachable by design (see above).
* No reader: nothing is decompressed into the case directory.
* No signatures for LZMA-alone (`5d 00 00`), bzip2 (`BZh`) or LZO streams;
  a `.lzma` kernel is reported only through its uImage wrapper.
* gzip multi-member files are reported once per member magic.

## References

* RFC 1952 (gzip), RFC 8878 (zstd)
* The .xz File Format specification, section 2.1.1 (stream header)
* LZ4 Frame Format Description v1.6.x
