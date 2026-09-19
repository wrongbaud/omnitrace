# UBI (discovery validator)

This page is for examiners who see a `ubi` node above a `ubifs` node in
`INFO.yaml` and for contributors who will rebuild UBI volumes. After reading
it you know how the validator finds the erase-block size, why the finding ends
where it does, which attrs and diagnostics it emits, and what a volume reader
still has to do.

`src/discovery/validators/ubi.cpp` (validator `ubi`), signature `ubi` in
`signatures/core.toml` (magic `UBI#`, big-endian, format `ubi`, category
`container`). There is no container reader: `analyze` makes a `container`
node with the `analyze-no-reader` warning and the coverage row
`ubi / unsupported / "no container reader registered"`, and carves it. A UBIFS
superblock inside the region is a separate, nested `ubifs` finding
(`docs/formats/ubifs.md`); `partitions/mount.sh` lists that carve in the
nandsim comment block.

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

## Attributes

`version`, `erase_counter`, `vid_hdr_offset`, `data_offset`, `image_seq`
(hex), `first_peb_mapped` (`true` / `false`, absent when unreadable),
`peb_size`, `pebs`, `erased_pebs`, `trailing_erased_pebs` (when non-zero).
Meanings: `docs/reference/ATTRS.md`.

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `ubi-truncated-header` | warning | fewer than 64 bytes for the EC header; magic tier |
| `ubi-ec-crc-mismatch` | warning | header CRC differs; structural tier, size unknown |
| `ubi-ec-fields-insane` | warning | CRC ok but version or offsets out of range; verified tier, size unknown |
| `ubi-single-peb` | info | no second EC header found; PEB size and image size unknown |

## Verified on

* `tests/fixtures/out/ubi.img` (ubinize, 2.3 MiB): `ubi` at `0x0`,
  `verified`, 18 PEBs of 131072 bytes, `vid_hdr_offset=2048`,
  `data_offset=4096`, and the nested `ubifs` finding at `0x41000` (LEB 0 of
  the volume, `verified`). Both findings are kept because equal-confidence
  nesting is not collapsed.

## Not yet supported

* No volume rebuild: PEBs are not mapped to LEBs, so a UBIFS inside a
  multi-volume image is found by its superblock but its LEBs are scattered;
  the `ubifs` finding's `size` is not meaningful there (`docs/formats/ubifs.md`).
* The volume table (internal volume 0x7FFFEFFF) and VID headers are not
  parsed: no volume names, no `sqnum`, no old-copy detection (the history
  source `DEVELOPMENT_PLAN.md` 5.3 describes).
* NAND dumps with OOB data are not handled; strip the spare area first.
* Two UBI images back to back with the same PEB size merge into one finding.

## References

* Linux `drivers/mtd/ubi/ubi-media.h` (read for understanding; no code copied)
* http://www.linux-mtd.infradead.org/doc/ubi.html
* mtd-utils (`ubinize`, `ubiattach`, `ubireader`) as the reference tools
