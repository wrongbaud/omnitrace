# android-super

`src/discovery/validators/super.cpp` (validator `android_super`), signature
`android-super` in `signatures/core.toml` (format `android-super`, category
`container`), reader `src/containers/super/SuperReader.cpp`. The layout and
table parsing are shared by both and live in `omnitrace::lp`
(`include/omnitrace/core/Lp.h`), because a validator and a reader that parse
the same bytes twice drift apart.

An Android device with dynamic partitions ships one physical `super` partition
holding several logical ones — `system`, `vendor`, `product`, `system_ext` and
their `_a`/`_b` slots — whose sizes are decided when the device is flashed
rather than when the image is built. Without this, the logical partitions are
only reachable by whatever magic happens to sit at the front of each one, and
they are named by offset instead of by name.

## On-disk layout (little-endian)

| offset | bytes | what |
|---|---|---|
| 0 | 4096 | reserved; a partition table may live here |
| 4096 | 4096 | geometry, magic `gDla` (0x616C4467) |
| 8192 | 4096 | backup geometry |
| 12288 | `metadata_max_size` | metadata slot 0, magic `0PLA` (0x414C5030) |
| … | | `metadata_slot_count` slots, then the same again as backups |

Geometry (52 bytes): `magic`, `struct_size`, `checksum[32]`,
`metadata_max_size`, `metadata_slot_count`, `logical_block_size`. The three
sizes start at offset **40**, after the 32-byte checksum — getting that wrong
shifts every field by four and is the first thing to check against a real
image.

Metadata header (128 bytes as written today): `magic`, `major`, `minor`,
`header_size`, `header_checksum[32]` at 12, `tables_size` at 44,
`tables_checksum[32]` at 48, then four `{offset, num_entries, entry_size}`
table descriptors at 80: partitions, extents, groups, block devices. Table
offsets are relative to the end of the header.

Rows: partition 52 bytes (`name[36]`, `attributes`, `first_extent`,
`num_extents`, `group_index`), extent 24 (`num_sectors` u64, `target_type`
u32, `target_data` u64 **unaligned at 12**, `target_source` u32), group 44,
block device 60. A newer liblp may write larger rows, which are read by field
offset; a row smaller than the fields read out of it is rejected.

All extents and targets are in 512-byte sectors regardless of
`logical_block_size`.

## Tiers

| tier | when |
|---|---|
| magic | `gDla` present, geometry fields not a super's (`super-bad-geometry`) |
| structural | geometry parses, metadata slot 0 does not (`super-bad-metadata`) |
| consistent | the map parses — partitions, extents and sizes are known |
| verified | the SHA-256 over the tables matches, and the block-device table states a size |

**Only a verified map gets an extent.** The geometry magic is four bytes at a
fixed offset, so a scan of an eMMC image finds it in unrelated data; what
separates a super from that is the SHA-256 liblp stores over the partition map
itself, which does not match by accident. A map that fails it is described in
the manifest and claims no bytes, because an untrusted map would otherwise
become extents on disk — the same rule as the GPT header CRC and the tar member
checksum. The reader applies it again in `open()` rather than trusting the
caller, because a reader more permissive than its validator turns a guess into
bytes on disk (see `romfs`).

Without a device size there is no extent either: the logical partitions say
where their bytes are, not where the container ends.

## What the reader emits

One entry per logical partition, named as the metadata names it, assembled
from its extents in order: a `linear` extent is bytes at `target_data * 512`,
and a `zero` extent is that many zero bytes written out, so the entry is the
image the device would see. A partition with no extents is emitted as an empty
file — an unpopulated A/B slot is worth showing, not dropping. Each extracted
partition is then re-scanned by `analyze`, which is how the ext4 inside one is
found and walked without this reader knowing anything about ext4.

## Attributes

Validator: `version`, `partition_count`, `extent_count`, `group_count`,
`partitions` (`name:bytes:extent_count;…`), `logical_bytes`, `device_size`,
`metadata_max_size`, `metadata_slots`, `logical_block_size`,
`geometry_checksum`, `header_checksum`, `tables_checksum`.
Reader: `version`, `partitions`, `extents`, `logical_block_size`,
`metadata_slots`; each entry carries `extents` and `attributes`.

## Diagnostics

`super-bad-geometry` (magic), `super-bad-metadata` (structural),
`super-tables-checksum-mismatch`, `super-truncated`, `super-no-device-size`;
from the reader `super-extent-outside`, `super-partition-empty`,
`super-partition-unnamed`.

## Known gaps

* **Only metadata slot 0 is read.** A device mid-update has a different map in
  another slot, and the backup copies at the far end of the metadata area are
  not consulted when slot 0 is damaged. Recovering a partition list from a
  backup slot is the same shape as the GPT backup-header rule and is not done
  yet.
* **`target_source` is ignored.** Every extent is read from the super itself.
  liblp allows extents on other block devices (a retrofitted device with
  `super` spanning several partitions); one of those would be read from the
  wrong bytes. The block-device table is parsed, so the check exists to be
  written.
* **An unknown `target_type` is treated as zeros** rather than refused, so a
  future extent kind would produce a hole rather than an error.
* **No corpus image.** The automotive Android unit VCUNH unit's `la_super` (32 GiB, four logical
  partitions, one extent each) is the only real super this has been aimed at,
  and the drive holding it was disconnected before the reader was finished, so
  the checksums and the assembled output have been verified only against
  images this project builds. The multi-extent and zero-extent paths have no
  real evidence behind them at all — that shape did not occur in the one unit
  seen. Treat the field offsets as corroborated (they agree with an
  independent implementation) and the end-to-end result as unconfirmed until a
  real super is run through it.

## References

* AOSP `system/core/fs_mgr/liblp`, `metadata_format.h` — read for the layout.
* <https://source.android.com/docs/core/ota/dynamic_partitions>
