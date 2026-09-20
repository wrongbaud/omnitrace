# UBIFS

`src/discovery/validators/ubifs.cpp` (validator `ubifs`), signature `ubifs`
in `signatures/core.toml` (format `ubifs`, category `filesystem`), and
`src/filesystems/ubifs/UbifsReader.cpp` (reader `ubifs`).

This page is for examiners reading a `ubifs` node and for contributors
working on either half. After reading it you know what the validator checks,
how the reader gets from the superblock to a file's bytes, why the journal
matters on a dump from a running device, and what is not recovered yet.

**A UBIFS lives inside a UBI volume, and the volume has to be reassembled
first.** `lnum` maps to `lnum * leb_size`, which only holds once the logical
erase blocks are contiguous. The UBI reader does that
([ubi.md](ubi.md)); a `ubifs` superblock found at a raw offset in unreassembled
UBI blocks is absorbed into the `ubi` finding, because nothing can be read
from there.

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

`size` = `leb_size * leb_cnt`, clamped. On raw flash the LEBs are not
contiguous, so the size is only meaningful for a reassembled volume or a
plain image; the UBI finding owns the region otherwise.

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

From the validator: `fmt_version`, `ro_compat_version`, `min_io_size`,
`leb_size`, `leb_cnt`, `max_leb_cnt`, `log_lebs`, `lpt_lebs`, `orph_lebs`,
`jhead_cnt`, `fanout`, `lsave_cnt`, `key_hash`, `flags`, `default_compr`,
`rp_size`, `sqnum`, `uuid`, `hash_algo`, `crc_check`.

From the reader: the superblock facts above plus `commit_no` (which master
node was used), `index_size`, `index_nodes` and `index_leaves` (what the walk
covered), `inodes`, `dentries` and `data_nodes` (what the index and journal
add up to), `bud_lebs` and `journal_nodes` (what the replay added),
`unlink_records` and `bad_nodes` when non-zero. Meanings:
`docs/reference/ATTRS.md`.

## The reader

`open()` reads the superblock, then the newest of the two master nodes whose
CRC verifies -- a torn commit leaves the older copy intact, which is why
there are two. The master node says where the index root is.

**The index** is a B-tree of `idx` nodes. Each holds `child_cnt` branches of
20 bytes (`lnum`, `offs`, `len`, then an 8-byte key); above level 0 they
point at more index nodes, at level 0 at the leaves. A key is two
little-endian words: the inode number, then the key type in the top three
bits and a block number or a name hash in the rest.

| key type | leaf node | what it carries |
|---|---|---|
| 0 | `ino` | the inode: mode, owner, size, times, and inline data (a symlink's target, a device's numbers) |
| 1 | `data` | one 4 KiB block of a file, compressed with `none`, `lzo`, `zlib` (raw deflate) or `zstd` |
| 2 | `dent` | one directory entry: parent inode in the key, child inode and name in the node |
| 3 | `xent` | one extended attribute; its value is an inode of its own |

**The journal** is what a mount replays before showing anything, and skipping
it would show the filesystem as the last commit froze it rather than as it
is. The log head (`log_lnum` in the master node) starts with a commit-start
node for that commit; the reference nodes after it name bud erase blocks, and
each bud holds nodes written since the commit. Those are scanned from where
the reference says they start and applied on top of the index, later writes
winning by `sqnum`. A node that fails its CRC ends the bud: a torn write
means nothing after it was completed either. When the log cannot be followed
the tree is still emitted, with `ubifs-journal-unreplayed` saying that recent
changes are missing -- which is the case that matters on a dump taken from a
running device.

An unlink is a directory entry pointing at inode 0. The reader treats it as
the deletion record it is and drops the name, counting it in
`unlink_records`.

`walk()` goes from inode 1 in key order, streaming each file block by block:
a block the index and journal do not have is a hole and reads as zeros, and
each block is decompressed on its own, so nothing larger than 4 KiB is held.

## History

UBIFS never overwrites in place. A node stays exactly where it was written
until garbage collection reclaims its erase block, so the state a file was in
before its last write, and the inode and blocks of a file that has been
deleted, are usually still on the medium. With `WalkOptions::history` the
reader sweeps for them.

**The sweep.** Every erase block is scanned for the node magic at each 8-byte
boundary -- UBIFS pads every node to 8, so that is a scan of the candidates,
not of every byte -- and the CRC decides. A sequential walk would miss what
sits in the tail of an erase block that was partly reused, which is exactly
where a deleted file's nodes end up. It costs about 0.3s per 180 MiB and is
only done when asked for.

Nodes are then grouped by key: inode nodes per inode, data nodes per (inode,
block), directory entries per (parent, name), each ordered by `sqnum`.

**What comes out of it.**

* **Deleted files.** A name whose newest directory entry points at inode 0 was
  unlinked. The entry before it names the inode, and the state that inode was
  in at that moment is its newest inode node with `sqnum` no higher than the
  unlink's, with the blocks to match. The entry is emitted with
  `deleted = true`, its `unlink_sqnum` and `unlink_node_offset` in
  `FileMeta::extra`; earlier states of the same file follow as
  `deleted + superseded`.
* **Earlier states of live files.** Every inode node of a live inode other
  than the one the index and journal agree on is a past state, with the
  content its blocks held at that `sqnum`. A node written *after* the live one
  was never committed -- an interrupted write, not a past -- and carries
  `newer_than_live`.
* **Inodes with no name.** An inode whose directory entry has already been
  reclaimed, or one unlinked while it was still open, has no name to be
  emitted under. It goes to `lost+found/#<inum>` with `name_lost`, which is
  also what makes a volume with a wrecked index still yield its files.

**Version numbers** are path-scoped and start at 1, oldest first, so
`(path, version)` is unique and `DiskSink` never needs to disambiguate
`.omnitrace-versions/<path>/v<n>`. The live entry keeps version 0, which is
what makes the live tree byte-identical with and without `--history`.

**The one state it cannot reconstruct** is a data-only rewrite: UBIFS marks a
point in time with an inode node, so a block overwritten without the inode
being written again leaves the old block on the medium with nothing to say
when it stopped being current. In practice a write updates `mtime` and so
writes the inode node too.

## Diagnostics

From the validator: `ubifs-bad-superblock` (magic), `ubifs-bad-leb-layout`
(warning), `ubifs-crc-mismatch` (warning), `ubifs-truncated` (info: fewer
LEBs present than `leb_cnt`).

From the reader:

| code | severity | meaning |
|---|---|---|
| `ubifs-bad-index` | warning | the index did not parse to the end; what it yielded is still walked |
| `ubifs-bad-node` | warning | an inode node is unreadable or fails its CRC |
| `ubifs-journal-unreplayed` | warning | the journal could not be followed; the tree is as of the last commit |
| `ubifs-missing-inode` | warning | a name whose inode is not on the medium; the name is still listed |
| `ubifs-missing-block` | warning | a data node could not be read; the block is zero-filled |
| `ubifs-decompress-failed` | warning | a block did not decode, or names an undefined compression type |
| `ubifs-directory-loop` | warning | a directory is its own ancestor; the branch stops there |
| `ubifs-limit-nodes` | warning | `max_nodes_per_fs` stopped the walk |
| `ubifs-sink-error` | warning | the Sink refused an entry |
| `ubifs-history-scan` | info | what the `--history` sweep found and recovered |
| `ubifs-deleted-unresolved` | info | an unlink record whose target or directory is no longer on the medium |
| `ubifs-limit-history-nodes` | warning | the sweep hit its node cap; older states beyond it were not recovered |

`open()` fails with `ubifs-bad-magic`, `ubifs-bad-superblock`,
`ubifs-bad-master` or `ubifs-truncated`.

## Not yet supported

* Authentication (format 5 HMAC nodes) is not verified.
* Encrypted UBIFS (`fscrypt`) contents are extracted as stored.
* The orphan area is not read. An inode unlinked while still open is listed
  there as well as left on the medium, so `--history` still recovers it, but
  under `lost+found/#<inum>` rather than by the name the orphan record would
  give it.

## Verified on

* `tests/fixtures/out/ubifs.img` (mkfs.ubifs 2.1.5): verified, LEB 129024 x 15,
  size equal to the file. The reader passes the fixture conformance suite on
  it -- all 20 entries with matching kind, size, mode, owner, mtime, link
  target and sha256, the hard link sharing its inode, and the extracted files
  hashing to the expected digests.
* The same fixture inside a `ubinize` UBI image
  (`tests/fixtures/out/ubi.img`): the volume is reassembled first and the
  filesystem reads identically through it.
* `tests/fixtures/out/ubifs-history.img`: the same tree with a hand-assembled
  journal bud (two further versions of `history/config.txt` and an unlink
  record for `history/deleted.txt`, with a reference node in the log), built
  by `tests/fixtures/generate.py` and described in
  [TESTING.md](../TESTING.md#ubifs-history-nodes). The live tree shows
  `config.txt` at v3 and no `deleted.txt`; `--history` recovers v1 and v2 of
  `config.txt` and `deleted.txt`'s 1126 bytes, all byte-identical to the
  ground truth the builder recorded.
* A copy of the fixture whose index branches were rewritten to point at random
  erase blocks, one of them back at the index node itself: the index walk
  yields nothing, and `--history` still recovers all ten regular files under
  `lost+found/#<inum>`, every one byte-identical to the intact fixture. That
  is the case the sweep exists for.
