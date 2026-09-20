# Compressed streams: gzip, xz, lzma, lz4, zstd

This page is for examiners who meet `gzip` / `xz` / `lz4` / `zstd` findings
and for contributors writing the remaining stream readers. After reading it you
know what each validator checks, which of them measure the stream's extent and
which still report `?`, how conflict resolution hides the streams that make up
a filesystem, and what is not decoded yet.

gzip, xz and LZMA-alone have a reader
(`src/containers/stream/StreamReader.{h,cpp}`, registered for all three format
ids) and a validator that sizes them. lz4 and zstd have neither yet.

Four validators, one per stream format, all in `src/discovery/validators/`
and registered from `signatures/core.toml` with category `compressed`:

| format | signature | magic | validator |
|---|---|---|---|
| `gzip` | `gzip` | `1f 8b 08` | `gzip.cpp` (`gzip`) |
| `xz` | `xz` | `fd 37 7a 58 5a 00` | `xz.cpp` (`xz`) |
| `lzma` | `lzma-lc3-lp0-pb2`, `lzma-lc1-lp2-pb2` | none (see below) | `lzma.cpp` (`lzma`) |
| `lz4` | `lz4-frame` | `04 22 4d 18` | `lz4.cpp` (`lz4`) |
| `zstd` | `zstd` | `28 b5 2f fd` | `zstd.cpp` (`zstd`) |

No header states the compressed length, so finding the end means decoding the
stream. The gzip and xz validators do exactly that, through
`compress::stream_length` (`include/omnitrace/core/Compression.h`), which runs
the decoder to the end of the stream and keeps only the measurements: the
payload is discarded as it is produced, so measuring a multi-gigabyte stream
costs one 64 KiB window. A measured stream gets `size`, the attribute
`payload_bytes` and `Confidence::Consistent`; one that does not decode to an
end keeps size 0, records `compressed-stream-unmeasured` and claims no bytes,
which is the pre-measurement behaviour.

The walk is bounded from the TOML, never from a constant in the validator:
`max_ratio` (1000) caps the payload as a multiple of the input still available,
so a small stream claiming to expand forever is abandoned, and `max_payload`
(4 GiB) is the absolute ceiling.

lz4 and zstd are not measured and stay at `structural` with size `?`. A finding
with no extent claims no bytes and parents nothing.

## lzma (LZMA-alone, .lzma)

The 13-byte header is a properties byte, a `u32` dictionary size and a `u64`
uncompressed size (all ones when the encoder did not know it, in which case
the stream ends with an end marker). **There is no magic.** The properties
byte packs `lc + lp * 9 + pb * 45`, so it is below 225; that is the whole of
the format's self-description.

Each signature therefore keys on one properties byte followed by the two zero
bytes a dictionary size that is a multiple of 64 KiB always has. Two are
shipped: `5d` (lc=3 lp=0 pb=2, the encoder default) and `6d` (lc=1 lp=2 pb=2,
what OpenWrt's lzma-loader emits). Another properties byte is one more line in
`signatures/core.toml`.

Because there is no magic, the validator **rejects rather than downgrades**,
at every step: a properties byte of 225 or more, a dictionary outside
4 KiB..1.5 GiB, a declared size above `max_payload`, or a stream that does not
decode to its end. `5d 00 00` occurs about a hundred times in a 16 MB router
image, and reporting those as magic-tier findings buried the one real stream
among them. The consequence is that a finding is only ever `consistent`, and a
real but truncated `.lzma` is missed — the price of a format with no magic.

This is what completes the router chain: a uImage payload is usually LZMA-alone,
so `uImage -> lzma -> the kernel` and everything the kernel embeds (a device
tree, an initramfs cpio, ELF sections) is now reachable.

## Why the extent matters

An extent is what lets a finding own its bytes. Without one the analysis pass
plans an `unidentified` region over the very bytes the stream occupies, a
nested find inside the stream is parented to the image rather than to the
stream, and `--carve all` records `carve-unknown-size` instead of a file.

## How the streams inside a filesystem stay hidden

A validated filesystem is built from these streams: SquashFS data blocks are
gzip/xz/lz4/zstd, JFFS2 file nodes carry zlib data. Conflict resolution moves a
`compressed` finding into the `also_matched` of any enclosing finding that is
not itself a compressed stream, at any tier
(`docs/formats/signatures.md`). Tier ordering used to carry that rule and could
not keep carrying it once the streams became measurable: a measured xz stream
at `consistent` (85) inside a SquashFS truncated down to `structural` (60)
would have escaped. Containment decides instead, so every stream inside a
filesystem disappears from the output while a stream that sits on its own — a
compressed kernel, a `.tar.gz` update package — is still reported.

## gzip (RFC 1952)

Header: `1f 8b`, `CM` (8 = deflate, part of the magic), `FLG`, `MTIME` u32
LE, `XFL`, `OS`, then optional `FEXTRA` (u16 length + data), `FNAME`
(NUL-terminated), `FCOMMENT`, `FHCRC`.

| tier | assigned when |
|---|---|
| rejected | any reserved `FLG` bit (0xE0) is set |
| magic | fewer than 10 bytes (`gzip-truncated-header`), `OS` byte above 13 and not 255 (`gzip-bad-os`), or `FEXTRA` length missing |
| structural | header parsed, stream not measurable |
| consistent | the deflate stream was walked to its end; `size` and `payload_bytes` are set |

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
| structural | flags valid and their CRC matches, stream not measurable |
| consistent | the stream (and any concatenated ones after it) was walked to its end |

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
| `compressed-stream-unmeasured` | info | the decoder could not follow the stream to an end, so the finding has no extent (gzip and xz only) |
| `container-decompress-failed` | error | the reader could not decode the stream; no payload emitted |
| `container-limit-file-bytes` | warning | the payload exceeds `--max-file-bytes` and was cut there |
| `container-sink-error` | warning | the Sink refused the payload |

## The reader

`StreamReader` handles both formats: one `ContainerReader` parameterised by
codec and magic. `open()` checks the magic only; `walk()` decodes and emits
exactly one entry named `payload` (`Container.h`), capped by
`Limits::max_file_bytes` — a capped payload is still emitted, marked
`truncated`, with `container-limit-file-bytes`. Concatenated gzip members are
one logical stream (RFC 1952 §2.2) and become one payload. `info()` reports
`size` (the stream's input length), `compression`, `stream_bytes` and
`payload_bytes`; `analyze` uses `size` to give the node an extent when the
validator could not.

The payload lands in `containers/<node-id>/files/payload` and is re-scanned
like any extracted file, so a `.tar.gz` holding a filesystem is walked to the
end: gzip container -> payload -> the filesystem inside it.

## Verified on

* `tests/fixtures/out/nested.tar.gz`: one `gzip` finding at `0x0`, now
  `consistent` with the full 319376-byte extent and
  `payload_bytes=327680`; the payload is the tar, and the SquashFS inside it
  becomes a walked `filesystem` node with its 11 entries.
* `tests/fixtures/out/squashfs-xz.img` and `squashfs-zstd.img`: every `xz` /
  `zstd` stream inside is absorbed into the `squashfs` finding's
  `also_matched`, so each image reports exactly one top-level finding
  (`scan --json` shows them nested; `tests/unit/discovery/resolve_test.cpp`
  covers the rule). The gzip and lz4 variants show nothing to absorb: SquashFS
  gzip blocks are zlib streams without the `1f 8b` member header, and its lz4
  blocks are raw, without the frame magic.
* Concatenated streams are one logical stream in both formats, so a measured
  xz finding inside a SquashFS covers the blocks stored after it. That is
  correct for a `.xz` file and harmless inside a filesystem, where the whole
  run is absorbed either way.

## Not yet supported

* lz4 and zstd have no extent and no reader: their block lists and frame
  indexes are not walked, so `size` stays unknown and their payloads are not
  decompressed.
* bzip2 (`BZh`) and LZO streams have no signature and no decoder: both would
  need a new third-party dependency (libbz2, liblzo2), which
  `docs/ARCHITECTURE.md` treats as a decision rather than an omission.
* Only two LZMA properties bytes have signatures; a stream written with other
  `lc`/`lp`/`pb` settings is not found.
* `verified` is unreachable for every stream format: neither gzip's CRC32 nor
  xz's check value is compared against the decoded payload.
* The payload is held in memory in one piece, so a payload larger than
  `--max-file-bytes` is cut rather than streamed.
* No signatures for LZMA-alone (`5d 00 00`), bzip2 (`BZh`) or LZO streams;
  a `.lzma` kernel is reported only through its uImage wrapper.
* gzip multi-member files are reported once per member magic.

## References

* RFC 1952 (gzip), RFC 8878 (zstd)
* The .xz File Format specification, section 2.1.1 (stream header)
* LZ4 Frame Format Description v1.6.x
