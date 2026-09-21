# Compressed streams: gzip, bzip2, xz, lzma, lz4, zstd

This page is for examiners who meet `gzip` / `bzip2` / `xz` / `lzma` / `lz4`
/ `zstd` findings. After reading it you know what each validator checks, how the extent
of a stream is found at all, how conflict resolution hides the streams that
make up a filesystem, and what is not decoded yet.

All six have a reader (`src/containers/stream/StreamReader.{h,cpp}`, one
class registered for every format id) and a validator that sizes them.

Six validators, one per stream format, all in `src/discovery/validators/`
and registered from `signatures/core.toml` with category `compressed`:

| format | signature | magic | validator |
|---|---|---|---|
| `gzip` | `gzip` | `1f 8b 08` | `gzip.cpp` (`gzip`) |
| `bzip2` | `bzip2` | `BZh` + a digit (see below) | `bzip2.cpp` (`bzip2`) |
| `xz` | `xz` | `fd 37 7a 58 5a 00` | `xz.cpp` (`xz`) |
| `lzma` | `lzma-lc3-lp0-pb2`, `lzma-lc1-lp2-pb2` | none (see below) | `lzma.cpp` (`lzma`) |
| `lz4` | `lz4-frame` | `04 22 4d 18` | `lz4.cpp` (`lz4`) |
| `zstd` | `zstd` | `28 b5 2f fd` | `zstd.cpp` (`zstd`) |

No header states the compressed length, so finding the end means decoding the
stream. Every one of these validators does exactly that, through
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

gzip, bzip2, xz, lz4 and zstd all allow streams or frames to be concatenated,
and every decoder here follows them, so a measurement covers the whole run. That
also means the validator and the reader cannot disagree: they call the same
function on the same bytes. Trailing data after the last stream the decoder
accepts is not claimed. A raw lz4 block has no frame header and is not
measured — there is no extent to find.

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
4 KiB..1.5 GiB, a dictionary that is neither `2^n` nor `2^n + 2^(n-1)`, a
declared size above `max_payload`, a declared size of **zero**, or a stream
that does not decode to its end. `5d 00 00` occurs about a hundred times in a
16 MB router image, and reporting those as magic-tier findings buried the one
real stream among them. The consequence is that a finding is only ever
`consistent`, and a real but truncated `.lzma` is missed — the price of a
format with no magic.

The last two of those checks were added after a full-corpus run, which
produced 17 LZMA findings that decoded to nothing and five
`decompress-memlimit` errors. Both rules are grounded in what encoders
actually write rather than in what the format permits:

* **A declared size of zero makes the decode probe vacuous.** The probe is the
  validator's only real evidence, and a header promising zero output is
  satisfied by consuming 13 header bytes plus 5 priming bytes and producing
  nothing — which any 18 bytes passing the cheap screens will do. It accounted
  for 16 of the 17. No encoder writes it: compressing an *empty* file with
  `lzma` still yields the all-ones "unknown" size.
* **A dictionary that is neither `2^n` nor `2^n + 2^(n-1)`** is one the format
  calls unportable and liblzma will not emit — asked for 1552809984 it writes
  1610612736, asked for 2031616 it writes 2097152. Every real stream in the
  corpus has a `2^n` dictionary; every non-conforming one belonged to a false
  positive, including the five whose ~1.5 GB dictionaries exceeded the
  reader's memory limit and produced the errors.

One caveat worth knowing: the probe's memory limit is derived from the payload
cap, which is derived from how many bytes follow the header. A stream near the
end of an image therefore gets a smaller allowance than the same stream in the
middle of one, so a very large dictionary can validate in one position and not
in another.

This is what completes the router chain: a uImage payload is usually LZMA-alone,
so `uImage -> lzma -> the kernel` and everything the kernel embeds (a device
tree, an initramfs cpio, ELF sections) is now reachable.

## bzip2

Header: `BZh` then one digit `1`..`9`, the block size in units of 100 kB.
What follows is a bit stream, but its first field lands on a byte boundary
because the header is a whole number of bytes: either a compressed block,
which starts with the 48-bit magic `31 41 59 26 53 59` (pi in BCD), or the
end-of-stream magic `17 72 45 38 50 90` (the square root of pi) for an empty
stream.

| tier | assigned when |
|---|---|
| rejected | the digit is not `1`..`9`, or neither 48-bit magic follows it |
| structural | header and block magic valid, stream not measurable |
| consistent | the stream, and any concatenated after it, decoded to its end |

`BZh` is three bytes and occurs in prose and in binaries, so the digit and
that 48-bit magic are what actually identify a stream — ten bytes of
discriminator before the decode probe is asked for anything, and a mismatch
rejects rather than downgrades.

libbz2 has no "skip to the next member" call, so the decoder is torn down and
rebuilt at each stream boundary, which is what `bunzip2` does too. That is how
`bzip2 -c a b > c` and every `pbzip2` output come back as one payload.

Attributes: `level`, `block_size`, `empty`.

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
| structural | descriptor valid, frame not measurable |
| consistent | the frame, and any concatenated after it, decoded to its end |

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
| structural | descriptor valid, frame not measurable |
| consistent | the frame, and any concatenated after it, decoded to its end |

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
| `compressed-stream-unmeasured` | info | the decoder could not follow the stream to an end, so the finding has no extent |
| `compressed-stream-checksum-mismatch` | warning | the stream decoded to its end and then disagreed with its own checksum; it is still sized and read |
| `container-decompress-failed` | error | the reader could not decode the stream; no payload emitted |
| `container-checksum-mismatch` | error | the payload does not match the checksum the stream records over it; it is emitted anyway |
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

## Checksums

Every one of these formats records something over its own payload, and each
library verifies it while decoding. What was missing was a way to *say* so, so
the entry now carries a `checksum` extra and the node a `checksum_kind` attr:

| format | what is recorded | `checksum_kind` |
|---|---|---|
| gzip | CRC-32 and ISIZE in the 8-byte trailer (RFC 1952 §2.3.1) | `crc32` |
| zlib | Adler-32 in the 4-byte trailer (RFC 1950) | `adler32` |
| deflate (raw) | nothing | `none` |
| bzip2 | a CRC-32 per block and a combined one per stream | `crc32` |
| xz | the check id in stream-flags byte 2 | `none`, `crc32`, `crc64`, `sha256` |
| lzma (alone) | nothing | `none` |
| lz4 | xxHash32 over the content, per block or both (`FLG` bits 2 and 4) | `xxh32` or `none` |
| zstd | the low 32 bits of an XXH64 over the content (`FHD` bit 2) | `xxh64` or `none` |

`compress::stream_check` reads that from the header alone; the verdict on the
entry comes from the decode:

* `ok` — the decoder reached the stream's end, which means the check passed.
* `none` — the stream records nothing to check against (`xz --check=none`,
  raw deflate, LZMA-alone). The same third answer `LzopReader` gives `lzop -F`.
* `unchecked` — the payload was cut at `--max-file-bytes`, so the trailer was
  never reached.
* `mismatch` — the compressed data decoded to its natural end and then
  disagreed with what the producer recorded.

A mismatch is the one decode failure that still yields evidence. The bytes are
all there; they are simply not the bytes that were compressed, and dropping
them would hide the damage. So the validator still sizes the stream
(`compressed-stream-checksum-mismatch`, `checksum=mismatch` on the finding) and
the reader still emits the payload (`container-checksum-mismatch`). Leaving the
extent unknown instead would bury a damaged stream under an "unidentified"
region, which is the opposite of what an examiner wants.

Two limits are worth knowing:

* Only gzip, zlib, lz4 and zstd can report a mismatch. liblzma and libbz2
  return one undifferentiated data error for a bad check and for corrupt data
  alike, so a bad xz check surfaces as `decompress-corrupt` and no payload.
* On an lz4 or zstd mismatch the payload may be short by up to one 64 KiB
  output window. Both libraries write the last block into the caller's buffer
  and then return the checksum error *before* recording how much they wrote,
  so those bytes cannot be committed. The zlib-backed codecs commit before
  they check and are byte-complete; gzip's extent is exact too, because
  `inflate_zlib` adds back the four ISIZE bytes zlib stops short of reading.

## Verified on

* `corpus/router-wrt-example`: the gzip member at `0x60bc71` fails its own CRC-32.
  `gzip -t` agrees ("invalid compressed data--crc error"). It used to be an
  unmeasured magic with a false-positive gzip magic inside its range; it is
  now `consistent`, 1010712 bytes, `checksum=mismatch`, and its 1024784-byte
  payload -- a GNU tar -- is recovered and flagged. The image went from 19
  findings to 18.
* Eleven hand-built streams (`gzip`, `xz --check=crc64`, `xz --check=none`,
  `zstd` with and without `--check`, `lz4` with and without `--no-frame-crc`,
  `bzip2`) round-trip to 200000 bytes with the expected `checksum` and
  `checksum_kind`; flipping one byte of each recorded check turns exactly
  those four formats that can tell into `mismatch`, and `gzip -t`, `zstd -t`
  and `lz4 -t` each confirm the corruption is in the check and not the data.
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

* The `verified` tier is still unreachable. A passing checksum now raises the
  reader's confidence in the payload, but the validator scores the header
  before any decode and nothing promotes a finding on the strength of a
  successful walk.
* A raw lz4 block (no frame magic) and the legacy `02 21 4c 18` format have no
  signature: neither has a header to recognise.
* Only two LZMA properties bytes have signatures; a stream written with other
  `lc`/`lp`/`pb` settings is not found.
* The payload is held in memory in one piece, so a payload larger than
  `--max-file-bytes` is cut rather than streamed.
* gzip multi-member files are reported once per member magic.

## References

* RFC 1952 (gzip), RFC 8878 (zstd)
* The .xz File Format specification, section 2.1.1 (stream header)
* LZ4 Frame Format Description v1.6.x
