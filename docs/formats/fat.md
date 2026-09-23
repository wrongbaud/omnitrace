# FAT12 / FAT16 / FAT32

Reader: `src/filesystems/fat/FatReader.{h,cpp}` (`fs::FilesystemReader`,
format id `fat`). Validator: `src/discovery/validators/fat.cpp`.
Tests: `tests/unit/filesystems/fat_test.cpp`, and the `fat32` fixture through
the conformance harness.

FAT is the boot partition of a large share of embedded devices, the format on
almost every SD card, and the one most likely to still hold a deleted file's
bytes. It is also the only filesystem here with **no magic number at all**.

## There is no magic, only a type string

What the signatures match is the file-system type field: `FAT32   ` at offset
82, or `FAT12   ` / `FAT16   ` / `FAT     ` at 54. Microsoft's own
specification says of that field that it "is not required to be correct" and
must never be used to determine the type.

So it is treated as what it is — a cheap screen saying *a BPB might begin 54
or 82 bytes back* — and every decision comes from the BIOS Parameter Block
behind it. That distinction is not academic: three corpus images carry
`FAT32   `, `FAT12   ` and `FAT16   ` **within twenty bytes of each other**,
which is a driver's string table, not three overlapping filesystems. The
validator rejects them on the BPB, which is nonsense there.

The consequence is a real gap, stated plainly: a FAT volume whose type string
was blanked is not found. Every formatter in normal use writes it.

## What decides the type

The cluster count, and nothing else:

```
RootDirSectors = (RootEntCnt * 32 + BytsPerSec - 1) / BytsPerSec
DataSec        = TotSec - (RsvdSecCnt + NumFATs * FATSz + RootDirSectors)
Clusters       = DataSec / SecPerClus

Clusters < 4085   -> FAT12
Clusters < 65525  -> FAT16
otherwise         -> FAT32
```

The two thresholds are exact; being off by one makes a volume unreadable, and
the specification is emphatic about it. When the counted type contradicts the
string that found the volume, `fat-type-string-disagrees` records it and the
count wins.

## Layout

Three areas follow each other. The reserved sectors come first (the boot
sector among them), then `NumFATs` copies of the allocation table, then the
data area. On FAT12/16 a fixed root directory of `RootEntCnt` entries sits
between the tables and the data; on FAT32 the root is an ordinary cluster
chain like any other directory.

Clusters are numbered from 2, so cluster *N* starts at
`data_start + (N - 2) * cluster_bytes`. Entries of 0 and 1 are reserved and
are the usual shape of a corrupt or hostile directory entry.

| width | FAT entry | end-of-chain |
|---|---|---|
| FAT12 | 12 bits, packed one and a half bytes per entry | `>= 0x0FF8` |
| FAT16 | 16 bits | `>= 0xFFF8` |
| FAT32 | 32 bits, top four ignored | `>= 0x0FFFFFF8` |

A FAT12 entry can straddle a sector boundary, so it is read as a 16-bit window
and shifted by four when the cluster number is odd.

## Long names come **before** the entry they name, in reverse order

A file called `ünïcödé ファイル.txt` is three 32-byte long-name entries holding
UTF-16 fragments — ordinals 3, 2, 1, with `0x40` set on the first one read —
followed by the real 8.3 entry. A reader that assembles fragments in the order
it meets them gets the name backwards.

Each fragment carries a checksum over the 8.3 name it belongs to, which is how
a live long name is told from a stale one left behind by a rename.

## Deleted files, and what can honestly be recovered

Deleting a file here does two things: it stamps `0xE5` over the **first byte
of the name**, and it frees the cluster chain. The directory entry keeps the
first cluster and the exact size.

With `--history` those entries are recovered, and the report is careful about
three separate kinds of uncertainty:

* **The bytes.** The chain is gone, so the file is read *contiguously* from
  its first cluster. For a file that was never fragmented that is exactly
  right. For one that was, it is the right number of bytes from the wrong
  places — and from the entry alone the two are indistinguishable. Every
  recovered file over one cluster says so with `fat-deleted-unchained`, and
  every one carries `recovery` in its `extra`.
* **The name.** The first character is *gone*. Nothing else in the format
  keeps a copy, so `DELETED.TXT` can only ever come back as `_ELETED.TXT`.
  Rendering the `0xE5` as a character produced `åeleted.txt`, which reads like
  a real name; the placeholder and the `name_first_char` note replaced it.
  When a long-name entry survives, it has the whole name and is used instead.
* **What is not there at all.** A superseded version leaves nothing behind.
  FAT frees the old directory entry on a rewrite and the next write reuses
  that slot, so the `fat32` fixture — whose `config.txt` was written three
  times — holds exactly **one** `CONFIG  TXT` entry. v1 and v2 cannot be
  named or found by anyone, which is why the fixture records them under
  `overwritten` rather than `superseded`.

A deleted *directory* is emitted as an entry but not descended into: its chain
is freed too, so its children cannot be reached reliably.

## What the reader captures

`FileMeta` gets `path`, `kind`, `size`, `mtime`, `crtime`, `atime` and
`inode` (the first cluster). `FilesystemInfo` carries the label, the cluster
size as `block_size`, and `attrs` `fat_type`, `bytes_per_sector`,
`sectors_per_cluster`, `cluster_size`, `clusters`, `fat_count`,
`fat_sectors`, `total_sectors`, `reserved_sectors`, `volume_id`, `oem_name`
and either `root_cluster` or `root_entries`.

Two things FAT does not have, which are therefore **synthesised**:

* **No permissions and no owners.** `mode` is reported as `0644`, or `0444`
  when the read-only attribute is set, so the case directory is usable; uid
  and gid are 0. The real attribute bits are kept in `extra` as `read_only`,
  `hidden` and `system`. The fixture's `features` block says `mode: false`
  and `owner: false`, so the conformance harness does not check them.
* **No time zone.** FAT stores local time with no zone, and no field records
  which one. Timestamps are converted as if UTC, which is what every other
  tool does; the fixture is built with `TZ=UTC` so the two agree.

## Diagnostics

| code | severity | when |
|---|---|---|
| `fat-bad-jump` | Warning | no `0xEB`/`0xE9` at offset 0 — the usual shape of a type string inside a binary |
| `fat-bad-sector-size`, `fat-bad-cluster-size`, `fat-bad-media`, `fat-bad-geometry`, `fat-bad-root` | Warning | the BPB cannot describe a volume |
| `fat-type-string-disagrees` | Info | the string and the cluster count name different widths |
| `fat-no-boot-signature`, `fat-first-entry-mismatch` | Info | one of the two cross-checks failed; the volume is still read, at `Structural` |
| `fat-truncated` | Warning | the BPB describes more bytes than the image holds |
| `fat-bad-chain` | Warning | a chain leaves the data area, loops, or hits the bad-cluster mark |
| `fat-short-read` | Warning | a chain ended before the size the entry records |
| `fat-bad-entry`, `fat-orphan-long-name`, `fat-dir-loop` | Warning / Info | a directory entry that cannot be used |
| `fat-deleted-unchained` | Info | a recovered file spans more than one cluster; see above |

## Confidence

`Magic` when the type string matched but the BPB does not hold up.
`Structural` when the BPB is self-consistent — sector and cluster sizes, media
byte, a data area that exists, and a root directory of the right shape for the
counted type. `Consistent` when the boot sector also ends with `0x55AA` **and**
`FAT[0]` holds the media byte the BPB declares, which are the two independent
confirmations available without reading the tree. A truncated volume cannot
reach either and stays at `Structural`.

## Known gaps

* A volume whose type string was blanked is not found; there is nothing else
  at a fixed offset to key on.
* exFAT is a different format and is not handled.
* The FSInfo sector (free-cluster hint) and the backup boot sector are not
  read; neither changes what is recoverable.
* The second and later copies of the allocation table are not compared against
  the first. Where they disagree, one of them may recover a chain the other
  lost — a genuine recovery avenue this does not yet take.
* Short names are decoded as Latin-1 rather than through an OEM code page,
  which round-trips and stays printable; a long name, where present, is
  authoritative and is proper UTF-16.

## References

* Microsoft, *FAT32 File System Specification* (`fatgen103`) — also the
  specification for FAT12 and FAT16, including the cluster-count rule
* Linux `fs/fat/` (read for understanding; no code copied)
* `tests/fixtures/generate.py` — how the `fat32` fixture and its history are built
