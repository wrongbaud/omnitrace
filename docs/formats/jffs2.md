# JFFS2 (discovery validator)

`src/discovery/validators/jffs2.cpp`, signatures `jffs2-le` / `jffs2-be` in
`signatures/core.toml`. This page covers identification and sizing; the
filesystem reader is documented separately once it lands.

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
the bit set, so `fs/jffs2/scan.c` re-sets it before checking; this validator
does the same (`obsolete_nodes` counts them). Erased space is `0xFF`; a
cleanmarker node (`0x2003`, 12 bytes) marks a freshly erased block on NOR.

## What the validator does

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

## Attributes

`nodes`, `inode_nodes`, `dirent_nodes`, `cleanmarkers`, `padding_nodes`,
`summary_nodes`, `xattr_nodes`, `unknown_nodes`, `obsolete_nodes`,
`first_nodetype`, `erased_gap_bytes`, `dirty_gap_bytes`, `gaps`,
`erase_size` (bytes, or `unknown`), `erase_size_source`, `erased_blocks`
(erase blocks inside the walk holding nothing but an optional cleanmarker),
`aligned_size` (size rounded up to the erase size).

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `jffs2-truncated` | warning | last node's `totlen` runs past the data |
| `jffs2-unknown-nodetype` | info | nodes with a type this scanner does not know |
| `jffs2-dirty-gaps` | info | non-node, non-erased bytes were skipped between nodes |
| `jffs2-no-erase-size` | info | fewer than two cleanmarkers: erase size not inferred |

## Verified on

* `spi-example` corpus image: one finding at `0xfa0000` (85 nodes, 61
  obsolete, 9 cleanmarkers, erase size 32 KiB) where the previous walk
  produced nine findings because it stopped at the first obsolete node.
  The 64 KiB block after the last cleanmarker holds unrelated board data and
  is not claimed.
* `router.bin`: unchanged (2519 nodes, 64 KiB erase size).

## Known gaps

* NAND images with cleanmarkers in OOB have no in-band cleanmarkers, so the
  erase size stays `unknown`.
* Two distinct JFFS2 partitions closer than `max_gap` merge into one finding.
* Summary nodes are counted, not parsed.
