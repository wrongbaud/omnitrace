# UBI

This page is for examiners who see a `ubi` node above a `ubifs` node in
`INFO.yaml` and for contributors working on either half. After reading it you
know how the validator finds the erase-block size, why the finding ends where
it does, how the reader puts a volume back together, and which attrs and
diagnostics each emits.

`src/discovery/validators/ubi.cpp` (validator `ubi`), signature `ubi` in
`signatures/core.toml` (magic `UBI#`, big-endian, format `ubi`, category
`container`), and `src/containers/ubi/UbiReader.cpp` (reader `ubi`), which
rebuilds the volumes into `containers/<node-id>/files/`. A UBIFS superblock
found by magic in the *unreassembled* blocks is absorbed into the `ubi`
finding's `also_matched` -- nothing can be read from that offset, and the
real filesystem turns up under the rebuilt volume
([ubifs.md](ubifs.md)). `partitions/mount.sh` lists the carve in the nandsim
comment block.

## On-disk layout

A UBI image is a sequence of physical erase blocks (PEBs). Every PEB starts
with a 64-byte erase-counter header, big-endian:

| offset | field | notes |
|---|---|---|
| 0 | `magic` | `UBI#` |
| 4 | `version` u8 | 1 is the only version that exists |
| 8 | `ec` u64 | erase counter of this PEB |
| 16 | `vid_hdr_offset` u32 | where the volume-identifier header sits inside the PEB (the min I/O unit on real flash) |
| 20 | `data_offset` u32 | where LEB data starts inside the PEB |
| 24 | `image_seq` u32 | image sequence number, the same in every PEB of one image |
| 60 | `hdr_crc` u32 | crc32, init `0xFFFFFFFF`, no final xor, over bytes 0..59 |

The VID header (`UBI!`) at `vid_hdr_offset` names the volume and the logical
erase block the PEB holds; an unmapped (free) PEB has `0xFF` there. The PEB
size is not stored anywhere.

## What the validator checks

| tier | assigned when |
|---|---|
| rejected | fewer than 64 bytes, or the CRC fails **and** the fields are insane (a 4-byte magic inside other data) |
| magic | the header is truncated (`ubi-truncated-header`) |
| structural | the fields are sane but the CRC fails (`ubi-ec-crc-mismatch`); size unknown, because a corrupt first block cannot anchor a walk |
| verified | the EC header CRC matches (`ubi.cpp:72`); `ubi-ec-fields-insane` is added when the fields are still out of range, and the walk is skipped |

"Sane" means `version == 1`, `vid_hdr_offset >= 64`,
`data_offset >= vid_hdr_offset + 64` and `data_offset` inside the data.

**PEB size and extent.** With a verified header the validator probes forward
from `start + data_offset` in steps of `vid_hdr_offset` for the next EC header
whose CRC verifies; the distance is `peb_size` (`ubi.cpp:92-100`). It then
walks PEB by PEB: a CRC-valid header counts, an all-`0xFF` header is an erased
PEB, anything else ends the walk. The finding ends after the last valid PEB;
erased PEBs inside the run are counted in `pebs` / `erased_pebs`, trailing
erased PEBs are reported as `trailing_erased_pebs` and not claimed. With no
second header the size stays unknown (`ubi-single-peb`).

The VID magic of the first PEB is checked only to set `first_peb_mapped`.
Volume tables, LEB numbers and volume names are not read.

## Volume reassembly (the reader)

The PEB order on the medium says nothing about the order of a volume's
blocks: wear levelling scatters them, and the same logical block can sit in
two PEBs at once when an update or a block move was interrupted. Each PEB's
volume-identifier header (`UBI!` at `vid_hdr_offset`, 64 bytes big-endian)
says which volume and which logical erase block it holds:

| offset | field | used for |
|---|---|---|
| 0 | `magic` | `UBI!`; absent (0xFF) on an unmapped PEB |
| 4 | `version` u8, 5 `vol_type` u8, 6 `copy_flag` u8, 7 `compat` u8 | `vol_type` 2 = static |
| 8 | `vol_id` u32 | which volume |
| 12 | `lnum` u32 | which logical erase block of it |
| 20 | `data_size` u32 | bytes used in this block (static volumes) |
| 24 | `used_ebs` u32 | blocks the volume uses (static volumes) |
| 28 | `data_pad` u32 | bytes at the end of the block the volume does not use |
| 40 | `sqnum` u64 | global sequence number; higher is newer |
| 60 | `hdr_crc` u32 | same CRC parameters as the EC header |

`UbiReader` walks every PEB, files each LEB under its volume, and emits one
entry per volume: LEB 0 first, `peb_size - data_offset - data_pad` bytes per
block, static volumes cut to the `data_size` their blocks declare. That is
the image `ubinize` consumed and that `ubiattach` would expose, so a nested
scan finds the SquashFS or UBIFS inside it as a filesystem rather than as a
magic hit among scattered blocks.

Three rules are worth knowing when reading a listing:

* **The newest copy wins.** Two PEBs claiming the same `(vol_id, lnum)` are
  resolved by `sqnum`. The older copies are the block as it was *before* it
  was rewritten, so they are real evidence: `ubi-leb-superseded` says how
  many there are, and `--history` writes each one out as
  `<volume>.leb<N>.sqnum<S>` with `superseded: true`, its `peb` and its
  `sqnum`.
* **Gaps are filled, not closed.** A missing LEB inside a volume becomes
  `0xFF` (erased flash), because closing the gap would move every later block
  off the offset the filesystem on top expects. `ubi-leb-gap` reports it and
  the entry is marked truncated.
* **Names come from the volume table**, the internal volume `0x7FFFEFFF`,
  whose LEBs hold 172-byte records (`reserved_pebs`, `alignment`, `data_pad`,
  `vol_type`, `upd_marker`, `name_len`, `name[128]`, `flags`, crc32 over the
  first 168 bytes). A name is evidence, so it becomes one host-safe path
  component; without a readable table volumes are `vol<id>`
  (`ubi-vtbl-unreadable`). The layout volume itself is never emitted.

## Attributes

From the validator: `version`, `erase_counter`, `vid_hdr_offset`,
`data_offset`, `image_seq` (hex), `first_peb_mapped` (`true` / `false`,
absent when unreadable), `peb_size`, `pebs`, `erased_pebs`,
`trailing_erased_pebs` (when non-zero).

From the reader: `peb_size`, `leb_size`, `vid_hdr_offset`, `data_offset`,
`image_seq`, `pebs`, `erased_pebs`, `unmapped_pebs`, `bad_pebs` (when
non-zero), `volumes`, and `volume_table` = `id:name:type:lebs;...`. Each
entry carries `vol_id`, `vol_type`, `lebs` and `leb_size`; a superseded block
carries `vol_id`, `lnum`, `sqnum`, `peb` and `copy_flag`.
Meanings: `docs/reference/ATTRS.md`.

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `ubi-truncated-header` | warning | fewer than 64 bytes for the EC header; magic tier |
| `ubi-ec-crc-mismatch` | warning | header CRC differs; structural tier, size unknown |
| `ubi-ec-fields-insane` | warning | CRC ok but version or offsets out of range; verified tier, size unknown |
| `ubi-single-peb` | info | no second EC header found; PEB size and image size unknown |
| `ubi-vtbl-unreadable` | warning | no volume-table record verified; volumes are named `vol<id>` (reader) |
| `ubi-bad-peb` | warning | PEBs with an unreadable EC header were skipped (reader) |
| `ubi-leb-gap` | warning | a volume is missing logical erase blocks; filled with `0xFF` (reader) |
| `ubi-leb-superseded` | info | older copies of a block exist; `--history` extracts them (reader) |
| `ubi-limit-entries` | warning | `max_nodes_per_fs` stopped the walk (reader) |
| `ubi-no-volumes` | warning | no PEB carries a VID header (reader) |

## Verified on

* `tests/fixtures/out/ubi.img` (ubinize, 2.3 MiB): `ubi` at `0x0`,
  `verified`, 18 PEBs of 131072 bytes, `vid_hdr_offset=2048`,
  `data_offset=4096`, and the nested `ubifs` finding at `0x41000` (LEB 0 of
  the volume, `verified`). Both findings are kept because equal-confidence
  nesting is not collapsed. The reader rebuilds the single `rootfs` volume
  (16 LEBs, 2031616 bytes) byte-identically to
  `ubireader_extract_images`.
* A three-volume `ubinize` image (mtd-utils 2.3.1): a dynamic `rootfs`
  holding a SquashFS, a *static* `config` of 100000 bytes, and a dynamic
  `data` holding a UBIFS. All three match `ubireader_extract_images` byte for
  byte, including the static volume's cut to `data_size`, and the SquashFS
  inside `rootfs` resolves to a filesystem on the nested pass.

## Not yet supported

* NAND dumps with OOB data are not handled; strip the spare area first.
* Two UBI images back to back with the same PEB size merge into one finding,
  and their PEBs are then reassembled as if they were one image. `image_seq`
  differs between them, which is the field that would separate them.
* `data_crc` (the VID header's checksum over a static volume's block) is read
  but not verified, so a corrupt static block is emitted without a warning.
* An update marked in progress (`upd_marker` in the volume table) is not
  reported.

## References

* Linux `drivers/mtd/ubi/ubi-media.h` (read for understanding; no code copied)
* http://www.linux-mtd.infradead.org/doc/ubi.html
* mtd-utils (`ubinize`, `ubiattach`, `ubireader`) as the reference tools
