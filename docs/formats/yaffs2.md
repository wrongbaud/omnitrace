# YAFFS2

`src/discovery/validators/yaffs2.cpp` (validator `yaffs2`), signature `yaffs2`
in `signatures/core.toml` (format `yaffs2`, category `filesystem`), and
`src/filesystems/yaffs2/Yaffs2Reader.cpp` (reader `yaffs2`). Both read the
chunk grid through `omnitrace::yaffs`
([core/Yaffs.h](../../include/omnitrace/core/Yaffs.h)).

This page is for examiners reading a `yaffs2` node and for contributors
working on either half. After reading it you know how an image with no
superblock and no magic is identified at all, how the reader gets from a
chunk to a file's bytes, what `--history` recovers, and what is not handled.

**The spare area has to be in the dump.** Everything that says which object a
chunk belongs to lives in the NAND spare (out-of-band) area, so a dump taken
without it -- page data only -- is not readable as YAFFS2 by anything,
including a kernel. `omnitrace` says so with `yaffs2-no-grid` rather than
guessing.

## On-disk layout (little-endian)

An image is a flat grid of chunks, each a NAND page followed by its spare:

```
[ page: 2048 ][ spare: 64 ]  [ page ][ spare ]  [ page ][ spare ] ...
```

There is no superblock, no magic and no index. The spare holds
`struct yaffs_packed_tags2`:

| offset in the tags | field | meaning |
|---:|---|---|
| 0 | `seq_number` u32 | the erase block's sequence number; higher is newer |
| 4 | `obj_id` u32 | which object the chunk belongs to |
| 8 | `chunk_id` u32 | 0 = object header, else data block `chunk_id - 1` |
| 12 | `n_bytes` u32 | valid bytes of the page (data chunks) |
| 16 | `col_parity` u8, 20 `line_parity` u32, 24 `line_parity_prime` u32 | `yaffs_ecc_other` over the sixteen bytes above |

Twenty-eight bytes in all. Where they start inside the spare depends on the
flash's layout -- 0 for yaffs's own, 2 for Linux MTD's -- and **neither the
page size, the spare size nor that offset is recorded anywhere in the image**.

A header chunk's page is a `yaffs_obj_hdr`:

| offset | field | notes |
|---|---|---|
| 0 | `type` u32 | 1 file, 2 symlink, 3 directory, 4 hard link, 5 special |
| 4 | `parent_obj_id` u32 | the directory it is in -- a YAFFS2 directory has no entries of its own, each object says where it belongs |
| 10 | `name[256]` | |
| 268 | `yst_mode`, 272 `yst_uid`, 276 `yst_gid` | |
| 280 / 284 / 288 | `yst_atime` / `yst_mtime` / `yst_ctime` u32 | |
| 292 | `file_size_low` u32 | files only; all ones when unused |
| 296 | `equiv_id` i32 | hard links: the object they are a link to |
| 300 | `alias[160]` | symlinks: the target |
| 460 | `yst_rdev` u32 | special files: the device number |
| 496 | `file_size_high` u32 | all ones when the file does not need it, **not** zero |

Object ids 1 to 4 are reserved: 1 is the root, 2 `lost+found`, 3 unlinked and
4 deleted.

## Identification

The signature anchors on `03 00 00 00 01 00 00 00 ff ff` -- the object header
of a directory whose parent is the root, which every non-trivial image has --
and the validator does the real work.

It tries each page and spare size YAFFS2 is used with, and each of the two
tag offsets, until one makes the chunk tags verify **against their own
checksum**. That is what makes the search safe: read the tags out of
alignment and the checksum says so at once, so sixteen bytes plus a
verifying checksum in chunk after chunk is not something other data
reproduces by accident. Small-page NAND (512 + 16) is not among the
candidates, because twenty-eight bytes of packed tags do not fit in a
sixteen-byte spare; those parts use the yaffs1 tag format or in-band tags,
neither of which is read here.

With the grid known the validator walks back from the hit to the image's
first chunk -- the magic lands on the first top-level directory, which is
chunk 0 in a freshly made image but need not be in a dump -- and then forward
while chunks verify or are erased. A single chunk whose tags fail is
tolerated as a bit error; two in a row end the image. Trailing erased chunks
are not claimed.

| tier | when |
|---|---|
| rejected | no geometry makes the tags verify, or fewer than four chunks do |
| verified | the grid was found, its chunks verified and there are object headers among them |

There is no tier in between: YAFFS2 has no superblock to cross-check against,
so either the grid is there or it is not.

## The reader

`open()` finds the grid the same way -- it is handed a Span, not a finding --
and then reads every chunk's tags once. That scan *is* the mount: YAFFS2 has
no index, so a kernel does exactly this and keeps the newest chunk it finds
for each key. "Newest" is `(seq_number, chunk index)`: the sequence number
orders the erase blocks, the position inside one orders the chunks.

A directory's children are found by asking every object who its parent is,
because that is where the answer is kept.

* **Hard links** are objects of their own whose header names the object with
  the content. The entry takes the target's mode, size, times and bytes, and
  reports the target's id as its inode, so a listing pairs the names.
  YAFFS2 stores no link count, so `nlink` is the name itself plus however
  many links point at it -- which is recoverable, and is what the reader
  reports.
* **Holes** are blocks that were never written, and read as zeros.
* **A chunk whose tags fail their checksum is not believed.** Taking it would
  put wrong bytes in a file; it is counted in `bad_chunks` and reported with
  `yaffs2-bad-chunk`.

## History

YAFFS2 never overwrites. A change is a new chunk with a higher sequence
number, and the old one stays until its erase block is reclaimed, so the scan
`open()` already did has every past state in it. `--history` emits them.

* **Deleted files.** Deleting is writing the object's header again with the
  parent set to 4 (deleted) or 3 (unlinked); the data chunks are not touched.
  The header *before* that one still says which directory the file was in and
  what it was called, so the entry keeps its real path rather than a
  `lost+found` placeholder, and its content comes back whole.
* **Earlier states** of a file that is still there, one per header chunk
  before the newest.
* **Objects with no reachable name**, under `lost+found/#<id>-<name>`. A
  YAFFS2 object carries its own parent, so a corrupted parent pointer can
  strand an object -- or a pair of directories pointing at each other -- where
  no mount will ever show it. The data is still on the medium and this is what
  gets it back.

**Version numbers** are path-scoped and start at 1, oldest first, so
`(path, version)` is unique and `DiskSink` never needs to disambiguate
`.omnitrace-versions/<path>/v<n>`. The live entry keeps 0, which is what makes
the live tree byte-identical with and without `--history`.

**One wrinkle about write order.** A live filesystem writes a file's data and
then the object header recording its new size, so a state's data is at or
before its header. `mkyaffs2` does the reverse: it creates the object, writing
the header, and then writes the contents. The oldest state of a file that was
laid down by `mkyaffs2` and later modified on a device therefore has its data
*after* its own header. Reading zeros there would be wrong -- the bytes are on
the medium -- so when a block has nothing at or before the cutoff the reader
takes the earliest chunk that block ever had and marks the entry
`content_from_first_write`. The header's size bounds the read, so this can
only fill in a block the state really had.

## Attributes

From both: `page_size`, `spare_size`, `tags_offset`, `spare_layout`,
`seq_min`, `seq_max`, `used_chunks`. The validator adds `chunks`,
`object_headers`, `erased_chunks` and `trailing_erased_chunks`; the reader
adds `objects` and `bad_chunks`. Meanings: `docs/reference/ATTRS.md`.

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `yaffs2-limit-chunks` | info / warning | the walk stopped at its chunk cap |
| `yaffs2-no-headers` | warning | the grid verifies but holds no object header |
| `yaffs2-bad-chunk` | warning | chunks fail their tag checksum and were skipped |
| `yaffs2-bad-header` | warning | an object header is unreadable, or the object has no name |
| `yaffs2-missing-chunk` | warning | a file's data chunk could not be read; zero-filled |
| `yaffs2-broken-hardlink` | warning | a hard link to an object that is not on the medium |
| `yaffs2-limit-nodes` | warning | `max_nodes_per_fs` stopped the walk |
| `yaffs2-sink-error` | warning | the Sink refused an entry |
| `yaffs2-history-scan` | info | what `--history` found and recovered |

`open()` fails with `yaffs2-empty`, `yaffs2-no-grid` or `yaffs2-no-objects`.

## Not yet supported

* **Big-endian images.** YAFFS2 stores integers in the host's byte order, so
  an image made on a big-endian device is readable with the fields swapped.
  There is no fixture for one, and shipping an untested code path is worse
  than the gap.
* **yaffs1 tags and in-band tags.** Small-page NAND and the `inband_tags`
  mount option both put the tags somewhere this does not look.
* The page-data ECC is not checked. `mkyaffs2` writes none, and on a device
  it belongs to the controller's spare layout rather than to YAFFS2.
* Shrink headers are flagged (`shrink_header`) but a truncation is not
  reconstructed as a separate state.
* **A file's size is not clamped to the image.** Holes cost nothing on flash,
  so a file can legitimately be larger than the medium it is on, and a
  corrupt header is indistinguishable from that. A header claiming more than
  every chunk of the image put together gets `yaffs2-size-beyond-image` and
  the zeros past its last data chunk are still written, because for a real
  sparse file they are its content. What that costs is bounded by
  `--max-file-bytes` and the run-wide `--max-bytes`: a crafted image of 74 KiB
  whose headers claim terabytes produced 4.1 GiB of zeros at the defaults
  before `--max-bytes` stopped it. Lower `--max-file-bytes` when an image is
  suspect.

## Verified on

* `tests/fixtures/out/yaffs2.img` and `yaffs2-yaffsecc.img` (mkyaffs2 0.2.9,
  2048 + 64, the Linux MTD and yaffs spare layouts): identified as `verified`
  with the geometry worked out from the image, size equal to the file, and the
  reader passes the fixture conformance suite on both -- all 20 entries with
  matching kind, size, mode, owner, mtime, link target and sha256, the hard
  link sharing its inode and reporting `nlink` 2, and the extracted files
  hashing to the expected digests.
* `tests/fixtures/out/yaffs2-history.img`: the same tree plus the chunks a
  device would have left -- two further versions of `history/config.txt` and
  `history/deleted.txt`'s header written again with parent 4 -- built by
  `tests/fixtures/generate.py` and described in
  [TESTING.md](../TESTING.md#yaffs2-history-chunks). `--history` recovers both
  earlier versions and the deleted file's 1126 bytes under its own name, all
  byte-identical to the ground truth.
* The tag checksum verifies on all 277 chunks of both fixtures, which is what
  the `verified` tier rests on.

## References

* https://yaffs.net/documents/how-yaffs-works
* https://github.com/yaffs/yaffs2 (`yaffs_guts.h`, `yaffs_packedtags2.c`,
  `yaffs_ecc.c`), read for understanding; nothing copied
* yaffs2utils (`mkyaffs2`), the tool the fixtures are built with
