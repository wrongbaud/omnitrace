# romfs

`src/discovery/validators/romfs.cpp` (validator `romfs`), signature `romfs`
in `signatures/core.toml` (format `romfs`, category `filesystem`).

## On-disk layout (big-endian)

| offset | field | constraint |
|---|---|---|
| 0 | `-rom1fs-` | magic |
| 8 | `full size` u32 | >= 16 + name field + 16 |
| 12 | `checksum` u32 | u32 sum of the first min(512, full size) bytes is zero |
| 16 | volume name | NUL-terminated printable ASCII, padded to 16 bytes |
| 16 + name | first file header | `next` (low 4 bits = type), `spec`, `size`, `checksum`, name |

Images are padded to 1024 bytes; `size` = full size rounded up to 1024.

## Tiers

| tier | when |
|---|---|
| magic | volume name is not printable ASCII (`-rom1fs-` inside a string table: seen next to `squashfs`, `NSR02`, `BEA01` in a blkid table on the audio image), or full size cannot hold a header |
| structural | fields sane, image runs past the data, or the first file header points outside |
| consistent | inside the data |
| verified | checksum sums to zero |

## Attributes

`volume_name`, `full_size`, `checksum` (`ok` / `mismatch`).

## Diagnostics

`romfs-truncated-header`, `romfs-bad-name`, `romfs-bad-size` (magic);
`romfs-truncated`, `romfs-bad-first-header` (structural);
`romfs-checksum-mismatch` (consistent, not verified). The name length limit
is `max_name_len` from the signature.

## The reader

`src/filesystems/romfs/RomfsReader.cpp` walks the whole tree. Every directory
is a singly linked list of 16-byte-aligned headers: `next` holds the offset of
the sibling that follows with the low four bits carrying the type (0-7) and an
executable bit, `0` ends the list, and a directory's `spec` is the offset of
its first child. Data follows the header's padded name, uncompressed and
contiguous. There is no inode table, no block map and no timestamps.

Two properties of that shape drive the implementation:

* **Every directory begins with `.` and `..` as hard links.** They are
  navigation, not entries, and following them is the shortest path to a loop,
  so the walk skips them by name.
* **The tree is a graph of raw offsets**, and nothing in the format forbids
  one pointing backwards. Every traversal is bounded by a visited set of
  header offsets, a nesting depth of 64, and `Limits::max_nodes_per_fs`;
  a hard-link chain is bounded separately.

A hard link that resolves is emitted under its own name with the target's
bytes, which is what an examiner expects to find on disk, and carries
`hard_link_to` pointing at the target header.

romfs stores no permissions, owners or timestamps — a type and one executable
bit is all there is. The reader synthesises the mode the kernel itself would
(0755 for directories and executables, 0644 otherwise, 0777 for symlinks) so
the extracted tree is usable, and puts `mode_source` on every entry so the
mode never reads as something the image recorded.

### Checksums

Only the superblock's is verified, because that is the only one the kernel
verifies (`romfs_checksum` over the first `min(512, size)` bytes, summing
big-endian u32 words to zero). `genromfs` also writes a per-header checksum,
but nothing in the kernel reads it and its exact coverage is not specified
anywhere authoritative, so this reader does not invent a check it cannot
validate. A bad superblock checksum is reported and the walk continues: a
damaged image is still evidence.

## Diagnostics (reader)

`romfs-bad-header`, `romfs-bad-link`, `romfs-cycle`, `romfs-truncated-entry`,
`romfs-checksum-mismatch`, `romfs-limit-nodes`, `romfs-limit-depth`,
`romfs-sink-error`.

## Verified on

* Images built from `Documentation/filesystems/romfs.rst` and independently
  identified by `file` ("romfs filesystem, version 1 ... named testvol") and
  `binwalk`, and accepted at `verified` by this project's own validator, which
  was written separately from the reader.
* `tests/unit/filesystems/romfs_test.cpp` builds every case in the test: all
  eight entry types, a 40 KB file, a directory that contains itself, a sibling
  list that loops, an entry claiming more than the image holds, a hard link
  pointing nowhere, and one that resolves.

## Known gaps

* No real romfs image is in the corpus. The `-rom1fs-` hit on the audio image
  is a blkid magic table compiled into a binary, sitting between `XFSB` and
  `iso9660`, not a filesystem.
* No `--history`: romfs is read-only and keeps no superseded versions.
