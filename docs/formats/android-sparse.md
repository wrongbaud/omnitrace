# Android sparse image

This page is for examiners who see an `android-sparse` node (a `system.img`
or `userdata.img` from a factory package or `fastboot` pull) and for
contributors who will write the expander. After reading it you know the chunk
layout, what the validator walks, which attrs and diagnostics it emits, and
why the filesystem inside is not analysed yet.

`src/discovery/validators/android_sparse.cpp` (validator `android-sparse`),
signature `android-sparse` in `signatures/core.toml` (magic `ed 26 ff 3a`,
little-endian, format `android-sparse`, category `container`). There is no
container reader: `analyze` makes a `container` node, adds the
`analyze-no-reader` warning and the coverage row
`android-sparse / unsupported / "no container reader registered"`, and
carves the sparse file as is.

## On-disk layout

Little-endian throughout (`AOSP system/core/libsparse/sparse_format.h`).

File header, 28 bytes:

| offset | field | constraint |
|---|---|---|
| 0 | `magic` u32 | `0xED26FF3A` |
| 4 | `major_version` u16 | 1 |
| 6 | `minor_version` u16 | 0 |
| 8 | `file_hdr_sz` u16 | 28 |
| 10 | `chunk_hdr_sz` u16 | 12 |
| 12 | `blk_sz` u32 | non-zero, multiple of 4 |
| 16 | `total_blks` u32 | blocks in the expanded image |
| 20 | `total_chunks` u32 | chunks that follow |
| 24 | `image_checksum` u32 | not verified |

Chunk header, 12 bytes, followed by the chunk's data:

| `chunk_type` | data | `total_sz` must be |
|---|---|---|
| `0xCAC1` raw | `chunk_sz * blk_sz` bytes copied to the output | `12 + chunk_sz * blk_sz` |
| `0xCAC2` fill | one u32 repeated over `chunk_sz` blocks | 16 |
| `0xCAC3` don't care | nothing; `chunk_sz` blocks skipped in the output | 12 |
| `0xCAC4` crc32 | one u32 | 16 |

## What the validator checks

| tier | assigned when |
|---|---|
| magic | header truncated (`sparse-truncated-header`), version not 1.0 (`sparse-unknown-version`), or header sizes / block size out of range (`sparse-bad-header`) |
| structural | the file header is valid (`android_sparse.cpp:44`) |
| consistent | every chunk parsed with the `total_sz` its type requires, the list closed inside the data, and the chunks cover exactly `total_blks` blocks (`android_sparse.cpp:120`) |

**Size.** The walk position after the last chunk parsed, so a truncated or
corrupt list still yields the bytes that were valid. Each chunk advances at
least 12 bytes, so a hostile `total_chunks` is bounded by the data. The walk
stops at the first bad chunk (`sparse-bad-chunk-type`,
`sparse-chunk-size-mismatch`, `sparse-truncated`).

Neither `image_checksum` nor the crc32 chunks are verified.

## Attributes

`block_size`, `total_blocks`, `total_chunks`, `output_size`
(`total_blocks * block_size`, the size of the expanded image),
`image_checksum` (hex), `raw_chunks`, `fill_chunks`, `dont_care_chunks`,
`crc_chunks`, `chunks_walked`. Meanings: `docs/reference/ATTRS.md`.

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `sparse-truncated-header` | warning | fewer than 28 bytes; magic tier |
| `sparse-unknown-version` | warning | version is not 1.0; magic tier |
| `sparse-bad-header` | warning | header sizes or block size out of range; magic tier |
| `sparse-truncated` | warning | a chunk header or its data lies past the end of the data; walk stops |
| `sparse-bad-chunk-type` | warning | unknown chunk type; walk stops |
| `sparse-chunk-size-mismatch` | warning | `total_sz` disagrees with the type and `chunk_sz`; walk stops |
| `sparse-block-count-mismatch` | warning | the chunks cover a different number of blocks than `total_blks` |

## Verified on

* Synthetic images in `tests/unit/discovery/validators_test.cpp` (a valid
  raw+fill+don't-care list, a truncated list, a bad chunk type). There is no
  fixture image yet; `tests/fixtures/generate.py` does not produce one.

## Not yet supported

* No expander: the raw chunks are not concatenated and the fill / don't-care
  chunks not materialised, so the ext4 or f2fs inside is not found and not
  walked. Expanding is what makes the format useful; it is the first thing to
  add (`DEVELOPMENT_PLAN.md` 5.2 lists it under structured headers).
* Because the scanner also runs over the sparse file's bytes, a raw chunk that
  happens to hold a superblock can produce a nested finding at the wrong
  offset and with a wrong extent. Treat any finding nested under an
  `android-sparse` node as a hint, not a map, until the expander exists.
* Checksums (`image_checksum`, crc32 chunks) are reported, not verified.
* Sparse files split across several `.img` parts (`sparse_chunk`) are not
  joined.

## References

* AOSP `system/core/libsparse/sparse_format.h` (read for understanding; no
  code copied)
* `simg2img` / `img2simg` from AOSP libsparse as the reference tools
