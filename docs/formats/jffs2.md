# JFFS2

Validator `src/discovery/validators/jffs2.cpp` (signatures `jffs2-le` /
`jffs2-be` in `signatures/core.toml`), reader
`src/filesystems/jffs2/Jffs2Reader.{h,cpp}` registered as `jffs2`, tests
`tests/unit/filesystems/jffs2_test.cpp`, fixtures `tests/fixtures/out/jffs2-le`,
`jffs2-be`, `jffs2-history`. JFFS2 is the log-structured flash filesystem of
NOR-based routers, industrial controllers and older set-top boxes, usually the
writable overlay or configuration partition. Because it is a log, the flash
keeps every earlier version of every file and every deleted file until garbage
collection reclaims the erase block; the reader recovers all of it.

## On-disk layout

A JFFS2 partition is a sequence of erase blocks, each holding 4-byte-aligned
nodes. Every node starts with the 12-byte unknown-node header, in the
filesystem's byte order:

| offset | field | notes |
|---|---|---|
| 0 | `magic` u16 | `0x1985` |
| 2 | `nodetype` u16 | `0xE001` dirent, `0xE002` inode, `0x2003` cleanmarker, `0x2004` padding, `0x2006` summary, `0xE008` xattr, `0xE009` xref |
| 4 | `totlen` u32 | node length including the header, >= 12 |
| 8 | `hdr_crc` u32 | crc32 (init 0, no final xor) over bytes 0..7 |

Bits of `nodetype`: `0x2000` JFFS2_NODE_ACCURATE, `0x4000` ROCOMPAT,
`0x8000` INCOMPAT. **Obsolete nodes:** on NOR flash the kernel obsoletes a
node in place by clearing the ACCURATE bit. The stored CRC was computed with
the bit set, so `fs/jffs2/scan.c` re-sets it before checking; the validator
and the reader do the same (`obsolete_nodes` counts them). Erased space is
`0xFF`; a cleanmarker node (`0x2003`, 12 bytes) marks a freshly erased block
on NOR.

Inode node (`struct jffs2_raw_inode`, 68 bytes, data follows):

| offset | field | notes |
|---|---|---|
| 12 | `ino` u32 | inode number; 1 is the root |
| 16 | `version` u32 | per-inode counter, higher is newer |
| 20 | `mode` u32 | type and permission bits |
| 24 | `uid` u16, `gid` u16 | owner |
| 28 | `isize` u32 | file size after this node (truncations shrink it) |
| 32 | `atime`, `mtime`, `ctime` u32 | seconds |
| 44 | `offset` u32 | file offset of this node's data |
| 48 | `csize`, `dsize` u32 | stored and decompressed data size |
| 56 | `compr`, `usercompr` u8 | 0 none, 1 zero, 2 rtime, 3 rubinmips, 4 copy, 5 dynrubin, 6 zlib, 7 lzo, 8 lzma (OpenWrt) |
| 58 | `flags` u16 | |
| 60 | `data_crc` u32 | crc32 over the `csize` stored bytes |
| 64 | `node_crc` u32 | crc32 over bytes 0..59 (`sizeof(jffs2_raw_inode) - 8`) |

Dirent node (`struct jffs2_raw_dirent`, 40 bytes, name follows):

| offset | field | notes |
|---|---|---|
| 12 | `pino` u32 | parent inode |
| 16 | `version` u32 | |
| 20 | `ino` u32 | target inode; **0 records an unlink** of the name |
| 24 | `mctime` u32 | |
| 28 | `nsize` u8, `type` u8 | name length, DT_* type |
| 32 | `node_crc` u32 | crc32 over bytes 0..31 |
| 36 | `name_crc` u32 | crc32 over the name |

Xattr nodes (32-byte header: `xid`, `version`, `xprefix`, `name_len`,
`value_len`, `data_crc`, `node_crc`, then name, NUL, value) and xref nodes
(28 bytes: `ino`, `xid`, `xseqno`, `node_crc`) link inodes to extended
attributes. A symlink's target and a device's number are the inode's data
(2 bytes `old_encode_dev` or 4 bytes `new_encode_dev`).

## Validator

### What the validator does

1. Accepts a hit only when the node header CRC verifies (2-byte magic alone
   is noise), so the tier is `verified` from the start.
2. Walks nodes by `totlen` (rounded to 4). On non-node bytes it looks ahead
   up to `max_gap` bytes (TOML key, default 131072) for the next CRC-valid
   header at a 4-aligned offset, classifying the skipped bytes as erased
   (all `0xFF`) or dirty (anything else: padding, garbage, dead data).
3. Stops when no header appears inside the window. The finding's `size`
   ends at the last node; trailing erased space is not claimed (the erase
   block's remaining bytes are reported through `aligned_size`).
4. Infers the erase-block size from cleanmarker spacing: the largest power of
   two dividing the gcd of all cleanmarker offsets relative to the start.

The scanner's same-signature coverage rule then skips every later hit inside
the accepted range, so one filesystem is one finding even with thousands of
nodes and obsolete nodes.

### Validator attributes

`nodes`, `inode_nodes`, `dirent_nodes`, `cleanmarkers`, `padding_nodes`,
`summary_nodes`, `xattr_nodes`, `unknown_nodes`, `obsolete_nodes`,
`first_nodetype`, `erased_gap_bytes`, `dirty_gap_bytes`, `gaps`,
`erase_size` (bytes, or `unknown`), `erase_size_source`, `erased_blocks`
(erase blocks inside the walk holding nothing but an optional cleanmarker),
`aligned_size` (size rounded up to the erase size).

### Validator diagnostics

| code | severity | meaning |
|---|---|---|
| `jffs2-truncated` | warning | last node's `totlen` runs past the data |
| `jffs2-unknown-nodetype` | info | nodes with a type this scanner does not know |
| `jffs2-dirty-gaps` | info | non-node, non-erased bytes were skipped between nodes |
| `jffs2-no-erase-size` | info | fewer than two cleanmarkers: erase size not inferred |

### Validator verified on

* `spi-example` corpus image: one finding at `0xfa0000` (85 nodes, 61
  obsolete, 9 cleanmarkers, erase size 32 KiB) where the previous walk
  produced nine findings because it stopped at the first obsolete node.
  The 64 KiB block after the last cleanmarker holds unrelated board data and
  is not claimed.
* `router.bin`: unchanged (2519 nodes, 64 KiB erase size).

### Validator known gaps

* NAND images with cleanmarkers in OOB have no in-band cleanmarkers, so the
  erase size stays `unknown`.
* Two distinct JFFS2 partitions closer than `max_gap` merge into one finding.
* Summary nodes are counted, not parsed.

## Reader

`Jffs2Reader::open()` scans every node of the Span; `walk()` emits the live
tree, and with `WalkOptions::history` every earlier version and every
deleted inode as well. Everything is read through `Span`; file data is
streamed to the `Sink` one node at a time.

### Scan

* Byte order comes from the first header whose CRC verifies (`85 19` little,
  `19 85` big). Runs of `0xFF` are skipped a word at a time; any other
  non-header word is stepped over.
* Every node's `hdr_crc` is checked with the obsolete-bit rule above.
  `totlen < 12` or a `totlen` past the Span skips the header
  (`jffs2-node-malformed`, `jffs2-node-truncated`) and scanning resumes at the
  next word, so one hostile length never hides the rest of the partition.
* Inode nodes: `node_crc` over 60 bytes and `data_crc` over the `csize`
  payload (read in 64 KiB pieces). Dirents: `node_crc` and `name_crc`.
  Xattr and xref nodes: `node_crc`. A `csize`, `nsize` or `name_len` past
  `totlen` is `jffs2-node-malformed` and the payload is ignored.
* A node that fails a CRC, or is obsolete, is **never used for the live
  tree** (the kernel drops it too) but is kept for history, where the
  entries it contributes to carry `extra["crc"] = "bad"` or
  `extra["obsolete"] = "true"`.
* Cleanmarkers, padding and summary nodes are counted; summary nodes are not
  parsed (they only duplicate what the scan reads). Unknown types are
  skipped by `totlen` (`jffs2-unknown-nodetype`).
* `Limits::max_nodes_per_fs` bounds the scan (`jffs2-limit-nodes`, `truncated`).
  `open()` scans with the default `Limits`; `walk()` rescans when its
  options carry a different cap.

### Reconstruction (kernel semantics)

For one inode, nodes are ordered by `(version, offset)`.

* **Metadata** (mode, uid, gid, isize, atime/mtime/ctime, flags) comes from
  the newest usable node.
* **Content**: data nodes are applied in version order; a later node
  overwrites the bytes it covers. A metadata-only node (`dsize` 0) whose
  `isize` is smaller than the data written so far truncates it (what the
  kernel did at `setattr` time). The result is cut to the newest `isize`;
  bytes no node covers are zeros (`jffs2-isize-exceeds-data` when the tail is
  uncovered: a sparse file or lost nodes).
* The reader first computes a **coverage plan** (`[range -> node]`) for the
  state, then streams it in file order: a node that still contributes is
  decoded once (consecutive ranges of the same node share the decode), and
  only one decoded node is held at a time. A node that cannot be decoded is
  zero-filled for its range and the entry is marked `truncated`.
* **Compression**: none/copy, zero (no payload; streamed as zeros without
  materializing `dsize` bytes), rtime, zlib, lzo and lzma
  through `core/Compression.h`. Compression id 8 is OpenWrt's headerless
  LZMA1 (`compr_lzma.c`: lc=0, lp=0, pb=0, 8 KiB dictionary); the reader
  prepends the LZMA-alone header so liblzma decodes it. rubinmips and
  dynrubin are not decoded (`jffs2-unsupported-compression`). Every decode is
  bounded: `dsize` above `max_file_bytes` (`jffs2-limit-file-bytes`) or above
  `csize x max_decompress_ratio` (`jffs2-limit-decompress-ratio`) is refused
  before any allocation.
* **Directory tree**: for each `(pino, name)` the highest-version usable
  dirent wins; `ino == 0` means the name is deleted. Root is inode 1 (it
  needs no inode node; mkfs images often have none). Hard links are the same
  inode under several names (`nlink` = live dirents pointing at it).
* **Walk order** is deterministic: depth first, names sorted bytewise within
  a directory. JFFS2 has no on-disk directory order (readdir order is the
  in-memory hash order of the mount), so bytewise is the only stable choice.
* A dirent whose inode has no usable node is still listed
  (`jffs2-missing-inode`), from the dirent alone: a mount shows the name and
  fails to stat it. A dirent naming an ancestor, or a second name for a
  directory already walked, is not descended (`jffs2-dir-loop`). Names that
  are empty, `.`, `..`, or contain `/` or NUL are skipped
  (`jffs2-bad-entry-name`).

### What the reader captures

`FileMeta`: `path`, `kind` (from the inode mode; from the dirent type when
no inode node is usable), `mode` (permission bits), `uid`, `gid`, `size`
(`isize`; 0 for directories and devices; target length for symlinks),
`atime`, `mtime`, `ctime` (seconds; JFFS2 has no sub-second or creation
times), `inode`, `nlink`, `link_target`, `rdev_major`/`rdev_minor`,
`version` (the path-scoped version of the state, see "Version numbers"
below; **not** the raw node version), `deleted`, `superseded`, and `extra`:
`jffs2_version` (the raw JFFS2 version of the newest node in the state, or
of the dirent for an unlink record), `inode_history` (comma-joined inode
numbers of every inode that ever held the path, present only when there
were two or more), `compression` (ids of the nodes that contribute bytes,
e.g. `zlib,lzma`), `nodes` (inode nodes in the state), `crc` = `bad`,
`obsolete` = `true`, `flags` (inode flags when non-zero), `xattrs`
(comma-joined names: `user.comment,security.selinux`, `#<xid>` when the
xattr node is missing), `dirent_version` (name-only entries), `record` =
`unlink`, `parent_inode` (unlink records), `orphan` = `true`,
`newer_than_live` = `true`, `versions_dropped`.

`FilesystemInfo`: `endian`, `size` (end of the last node rounded up to the
erase size), `block_size` (erase size), `compression` (codecs seen), and the
attrs `endian`, `first_node`, `nodes`, `inode_nodes`, `dirent_nodes`,
`cleanmarkers`, `padding_nodes`, `summary_nodes`, `xattr_nodes`,
`xref_nodes`, `unknown_nodes`, `obsolete_nodes`, `crc_failures`,
`unlink_dirents`, `erase_size`, `compressors`, `xattr_count`, `inodes_live`,
`inodes_deleted`, `inodes_multi_version`, `scan_capped`.

### History

With `WalkOptions::history` the reader emits, after the live tree:

**Versions.** Nodes of one inode are grouped into *writes*: a run of
consecutive data nodes where each starts where the previous one ended,
carries the same `mtime` and `ctime`, and does not shrink `isize` is one
write (the kernel and mkfs.jffs2 split a single write into page-sized
nodes). Every other node (an overwrite, a truncation, a metadata-only node,
a later append) starts a new version. The state after each write, except
the one the live tree shows, is emitted as an entry with the live path,
`superseded = true`, `version` = its path-scoped version (below),
`extra["jffs2_version"]` = the raw version of the last node in that state,
metadata from that node, and content reconstructed from the nodes up to it.
A rewrite with identical bytes is still a version (the write happened).
Versions built on a CRC-failed or obsolete node are emitted with
`extra["crc"] = "bad"` / `extra["obsolete"] = "true"`; a state newer than
the live one (its node failed its CRC) carries `extra["newer_than_live"]`.
`DiskSink` places every such entry under
`.omnitrace-versions/<path>/v<version>`.

Example, `etc/config/network` written three times: nodes v1 (create, isize
0), v2 (0..4096), v3 (4096..5000, same times as v2), v4 (0..300, new times),
v5 (chmod, dsize 0):

| entry | version | content |
|---|---|---|
| `etc/config/network` v1, superseded | 1 | empty |
| `etc/config/network` v3, superseded | 3 | 5000 bytes (v2 + v3 are one write) |
| `etc/config/network` v4, superseded | 4 | 300 bytes, mode before the chmod |
| `etc/config/network` (live) | 5 | 300 bytes, mode after the chmod |

**Version numbers.** The JFFS2 node version is a per-inode counter, so two
inodes that held the same path over time (a file deleted and recreated, a
rename over an existing target; `network.lua` on the router corpus was inode
429 and then inode 549, each with versions 1..7) both produce v1, v2, ... and
`.omnitrace-versions/<path>/v<n>` would collide. `FileMeta::version` is
therefore **path-scoped**: for each path the reader collects every state of
every inode that ever held it (live state included) and every unlink record
at it, orders them, and numbers them in one sequence, so `(path, version)`
is unique across the whole walk and `DiskSink` never needs a `~1` suffix.

* Order: holders by the version of the dirent that bound each of them to
  the name when those dirents share a parent directory (the parent's dirent
  counter is the clock of that name, so an older inode renamed over a
  younger one at this path comes last), otherwise by inode number (JFFS2
  allocates inode numbers monotonically, so the earlier holder has the lower
  number); then each holder's states in node order, and an unlink record
  right after the states of the inode it unlinked (after every holder when
  that inode is unknown or lives under another path).
* Numbering: a state keeps its raw JFFS2 version unless an earlier state of
  the path already used that number or a higher one, in which case it takes
  the next free number. A path held by one inode therefore keeps the numbers
  `jffs2dump` shows (the common case, and what the fixtures record); a second
  holder's versions continue after the first holder's last number.
* The live entry carries the same path-scoped number with and without
  `--history`, so the live tree is byte-identical in both modes; the raw
  number is always in `extra["jffs2_version"]`, and `extra["inode_history"]`
  lists the holders when there were several.

`network.lua` on the router corpus: inode 429 (deleted) v1..v7 keep 1..7,
its final state being the deleted entry; inode 549 v1..v7 become 8..14, of
which 14 is the live file and 8..13 are superseded; every entry carries
`inode_history: 429,549`.

**Deleted inodes.** Every inode that has nodes but no live dirent is emitted
with `deleted = true`: its newest state with `version` = newest node version,
and each earlier version with `deleted = true` and `superseded = true`. The
path is resolved from history: the highest-version CRC-valid dirent (obsolete
ones included) that named the inode gives the name; its parent's path is the
parent's live path when the parent is live, otherwise resolved the same way,
recursively, with cycle detection. A parent that no dirent ever named
becomes `lost+found/#<pino>`; an inode no dirent ever named becomes
`lost+found/#<ino>` (`jffs2-orphan-inode`, `extra["orphan"]`). A deleted
directory's children keep their full path (`d/c`) even though `d` is gone.

**Unlink records.** A dirent with `ino == 0` is an explicit unlink (or the
old name of a rename). It is emitted as a deletion record (`deleted = true`,
size 0, `version` = dirent version, `mtime` = `mctime`,
`extra["record"] = "unlink"`) unless the inode the name pointed at is
already emitted as deleted under that same path, so a deleted file appears
once, with content.

**Renames.** JFFS2 renames by writing a dirent for the new name and an
unlink for the old one; the inode stays live, so the old name appears only
as an unlink record. When a rename replaces an existing target, the target's
inode loses its only name and is emitted as deleted under that path with the
old inode number. A name whose dirent history maps to different inodes over
time (unlink and recreate) thus yields the older inode as deleted with the
same path as the live file.

`WalkResult.superseded` counts entries with `superseded`, `deleted` counts
entries with `deleted`; an earlier version of a deleted inode counts in both.
The live part of a history walk is byte-identical to a plain walk. History
entries are emitted after the live tree, grouped by path (bytewise order)
and by version within a path.

### Limits

| Limits field | effect |
|---|---|
| `max_nodes_per_fs` | nodes scanned (`jffs2-limit-nodes`) |
| `max_versions_per_entry` | history versions kept per path (every holder's states and unlink records together, the live state excluded); the newest are kept, `jffs2-limit-versions`, `extra["versions_dropped"]` on the newest kept entry |
| `max_files` | entries emitted (`jffs2-limit-files`) |
| `max_file_bytes` | bytes streamed per entry and the largest `dsize` decoded (`jffs2-limit-file-bytes`) |
| `max_decompress_ratio` | `dsize / csize` a data node may claim (`jffs2-limit-decompress-ratio`) |
| `max_bytes` | enforced by the Sink |

### Reader diagnostics

| code | severity | when |
|---|---|---|
| `jffs2-node-crc-mismatch` | warning | node_crc failed (count); live tree ignores them, history keeps them flagged |
| `jffs2-data-crc-mismatch` | warning | data_crc failed (count); same handling |
| `jffs2-name-crc-mismatch` | warning | name_crc failed (count); the dirent is not used for any path |
| `jffs2-node-truncated` | warning | totlen past the Span (count); header skipped, scan resumes |
| `jffs2-node-malformed` | warning | totlen below the type minimum or a payload length past totlen (count) |
| `jffs2-unknown-nodetype` | info | node types the reader does not decode (count and types) |
| `jffs2-unsupported-compression` | warning | rubinmips/dynrubin nodes (per entry and once per walk); ranges zero-filled, entry `truncated` |
| `jffs2-decompress-failed` | warning | a payload did not decode or was short; range zero-filled, entry `truncated` |
| `jffs2-isize-exceeds-data` | info | isize beyond the covered data; tail zero-filled |
| `jffs2-missing-inode` | warning | live dirent with no usable inode node; entry from the dirent |
| `jffs2-dir-loop` | warning | ancestor or repeated directory; not descended |
| `jffs2-bad-entry-name` | warning | unsafe name; entry skipped |
| `jffs2-orphan-inode` | info | inodes never named; under `lost+found/#<ino>` |
| `jffs2-limit-nodes` / `-files` / `-file-bytes` / `-decompress-ratio` | warning | a `Limits` guard tripped; `truncated` set |
| `jffs2-limit-versions` | warning | the per-path history cap (`max_versions_per_entry`) dropped the oldest versions; the newest are kept and the newest kept entry carries `versions_dropped`; the walk is not `truncated` (the live tree is complete) |
| `jffs2-sink-error` | warning | the Sink refused an entry; skipped |

`open()` fails with `jffs2-no-nodes` when no CRC-valid header exists.

### Verified on

* `router.bin` corpus, partition at `0xc60000` (3735564 bytes, OpenWrt
  overlay): 2519 nodes, 1480 inode nodes for 330 inodes of which 82 are
  live, 248 deleted with recoverable data, 381 unlink dirents, 239 inodes
  with several versions, 327 LZMA nodes. The live
  `upper/usr/lib/lua/luci/controller/admin/network.lua` (10975 bytes, three
  LZMA nodes plus three metadata nodes) matches an independent reassembly;
  moria (no LZMA) emits zeros for it.
* Fixtures `jffs2-le`, `jffs2-be` (mkfs.jffs2 2.1.5, 64 KiB erase blocks) and
  `jffs2-history` (config.txt written three times, deleted.txt unlinked).

### Known gaps

* rubinmips and dynrubin compression are not decoded.
* Xattr values are not decoded (names and count only); ACL entries appear
  as their prefix name.
* Summary nodes are counted, not parsed.
* NAND images need the OOB stripped first (ECC and cleanmarkers live there).
* mtime of directories is captured but not applied by `DiskSink`.
* Holders whose binding dirents sit under different parent inodes (a
  directory deleted and recreated with the same name) are ordered by inode
  number, which is allocation order, not necessarily the order in which they
  held the path (`inode_history` and `jffs2_version` show the raw facts).

## References

* Linux `include/uapi/linux/jffs2.h`, `fs/jffs2/scan.c`, `readinode.c`,
  `dir.c`, `write.c`, `compr_rtime.c`, `compr_zlib.c`, `compr_lzo.c` (read
  for understanding; nothing copied).
* OpenWrt `target/linux/generic/files/fs/jffs2/compr_lzma.c` (compression id 8).
* mtd-utils `mkfs.jffs2.c`, `jffs2dump.c`.
* D. Woodhouse, *JFFS: The Journalling Flash File System* (Ottawa Linux
  Symposium 2001).
