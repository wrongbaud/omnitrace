# Partition tables: MBR, EBR and GPT

Validators: `src/discovery/validators/mbr.cpp` (format `mbr`) and
`src/discovery/validators/gpt.cpp` (format `gpt`, signatures `gpt` for
512-byte sectors and `gpt-4k` for 4096-byte sectors). Category
`partition-table`. Consumers: `src/discovery/Recurse.cpp` turns each table
finding into one Partition node for the table plus one per entry.
Tests: `tests/unit/discovery/partition_test.cpp` and the `MbrValidator` /
`GptValidator` cases in `tests/unit/discovery/validators_test.cpp`.

The one rule that everything below follows: **a partition-table finding is
the table, not the disk.** Its `offset`/`size` cover the bytes the table
itself occupies (512 bytes for an MBR, about 17 KiB for a GPT), and what the
table says about the disk goes into `attrs`. Before this rule a GPT finding
on a 3.6 GB eMMC dump was 3.6 GB long and conflict resolution moved every
filesystem inside the disk into its `also_matched`.

## On-disk layouts

### MBR (sector 0)

```
offset  size
0       440     boot code
440     4       disk signature (u32 LE)
444     2       usually 0
446     64      four 16-byte partition entries
510     2       0x55 0xAA
```

Entry: `0 status` (0x00 inactive, 0x80 bootable), `1..3 CHS start`, `4 type`,
`5..7 CHS end`, `8 lba_start u32 LE`, `12 sectors u32 LE`. Type 0 is an empty
slot. Types 0x05, 0x0F and 0x85 are extended containers; 0xEE is the
protective entry of a GPT disk. Sector size is 512.

### EBR chain

An extended container starts with an EBR that has the same 0x55AA layout.
Entry 1 is the logical partition, `lba_start` **relative to that EBR**;
entry 2, when non-empty, links to the next EBR, `lba_start` **relative to the
start of the extended container**. Entries 3 and 4 are unused. Linux numbers
logicals from 5 in chain order regardless of which primary slots are used,
and so do we.

### GPT

```
LBA 0          protective MBR (one 0xEE entry covering the disk)
LBA 1          primary header
LBA 2..33      primary entry array (128 entries x 128 bytes = 16 KiB)
...            partitions
LBA n-33..n-2  backup entry array
LBA n-1        backup header
```

Header (92 bytes, LE): `0 "EFI PART"`, `8 revision`, `12 header_size`,
`16 header_crc32` (over `header_size` bytes with this field zeroed),
`24 my_lba`, `32 alternate_lba`, `40 first_usable_lba`, `48 last_usable_lba`,
`56 disk_guid[16]`, `72 partition_entry_lba`, `80 num_entries`,
`84 entry_size`, `88 entry_array_crc32`. Entry: `0 type_guid[16]`,
`16 unique_guid[16]`, `32 first_lba`, `40 last_lba`, `48 attributes`,
`56 name[36]` UTF-16LE. GUIDs are mixed-endian (first three fields LE) and
are rendered in the canonical text form. Reference: UEFI Specification 2.10
§5.3.

Every LBA in a header is relative to LBA 0 of the disk it describes, not to
the header. The validator therefore reads everything relative to the header
through `my_lba`: the entry array is at
`header + (entry_lba - my_lba) * sector`, the alternate header at
`header + (alternate_lba - my_lba) * sector`, and LBA 0 (`disk_offset`) is
at `header - my_lba * sector` when that is inside the data. This is what
makes a backup header at the end of a disk, a primary at a vendor LBA
(audio keeps its primary at LBA 12289 with the protective MBR at 12288 and
garbage at LBA 1) and a carved slice that no longer contains LBA 0 all
parse identically.

## What is validated, per tier

### MBR

The 0x55AA magic is two bytes, so a candidate is **rejected** (not
downgraded) unless it passes the hard checks:

* the sector is 512-byte aligned in the Span;
* at least one entry has status 0x00 or 0x80, a non-zero type, a non-zero
  sector count and a start inside the available data.

Entries that fail the status/size/start checks are dropped with
`mbr-entry-invalid` (Info). An entry that starts inside the data but ends
past it is kept, because truncated dumps are the normal case in the field,
and carries `mbr-partition-truncated` (Warning). A 0xEE entry marks the
table `protective`. Overlapping entries (extended containers and 0xEE
excluded) give `mbr-partitions-overlap` (Warning). EBR chains are walked up
to `ebr_max_chain` (TOML) links, with loop detection.

| tier | condition |
|---|---|
| structural | accepted; some entry invalid, truncated or overlapping |
| consistent | every non-empty entry sane, inside the data, no overlaps |

`verified` is unreachable: an MBR has no checksum.

On a auto-emmc.bin dump, six unaligned 0x55AA hits in random data used to
become MBRs (one claiming 5.6 GB); the alignment rule alone removes them,
and the sane-entry rule removes aligned noise.

### GPT

"EFI PART" is eight bytes, so a corrupt header is reported at `magic` with a
diagnostic rather than rejected; only two conditions reject outright:

* the structure start is not 512-byte aligned, or the header is not on a
  boundary of its own sector size (`hdr % sector != 0`);
* the header CRC is fine but the entry array only verifies when read with
  the *other* sector size (512 vs 4096): the hit belongs to the other
  signature and would otherwise be a duplicate finding with garbage entries.

| tier | condition |
|---|---|
| magic | header truncated, `header_size` not in [92, sector], `entry_size` not a multiple of 8 >= 128, `my_lba` 0 or equal to `alternate_lba` |
| structural | header fields sane; header CRC mismatch |
| consistent | header CRC ok; entry array outside the data, or its CRC mismatches |
| verified | header CRC ok and entry array CRC ok |

Entries with a zero type GUID are unused. Entries with a type GUID but
`first_lba == 0` or `last_lba < first_lba` are stale slots (LBA 0 is the
protective MBR and can never start a partition); they are skipped and
counted in `gpt-entry-invalid`. At most `max_entries` (TOML) entries are
read.

### Backup recovery rule

A header whose `my_lba > alternate_lba` is a backup. It is parsed exactly
like a primary from its own entry array (the array before the header), and
the state of the primary it names decides the diagnostic:

* primary present, header CRC ok, `my_lba`/`alternate_lba` cross-consistent,
  same disk GUID and same entry-array CRC → `gpt-backup` (Info, "backup
  header, matches primary"), `attrs["primary"] = "valid"`;
* primary present and valid but describing a different array or disk →
  `gpt-backup-mismatch` (Warning), `attrs["primary"] = "mismatch"`. The
  primary finding carries the same diagnostic and `attrs["backup"] =
  "mismatch"`;
* primary missing, corrupt or outside the data → `gpt-primary-missing`
  (Warning, "primary GPT header at LBA <alt> is invalid|outside the data;
  partition list recovered from the backup header at LBA <n>"),
  `attrs["primary"] = "invalid" | "outside"`.

Both tables are always reported as findings; a consumer building Partition
nodes should build them from the primary when it is valid and from the
backup only when `attrs["primary"] != "valid"`, or it will get every
partition twice.

The audio dump is the motivating case: LBA 1 is garbage, the primary sits at
LBA 12289 and the backup at LBA 7340031; a slice of only the last 33 sectors
still yields the ten partitions (`micdata`, `mdp`, `ddp`, `wifical`,
`kern0`, `rootfs0`, `kern1`, `rootfs1`, `jffs`, `hwv_scratch`).

## Finding extent

| table | offset | size |
|---|---|---|
| mbr-primary | the boot sector | 512 |
| gpt-primary | the sector before the header (LBA 0 for a standard primary) | through the end of the entry array when the array is at header + 1 sector (typically 0x4400); otherwise the two header sectors and `gpt-entries-detached` |
| gpt-backup | the start of the entry array when it ends at the header | through the end of the header sector (typically 0x4200); otherwise the header sector only and `gpt-entries-detached` |

The EBRs of an MBR chain are members of the table, not tables of their own:
the validator lists them in `attrs["also_covers"]` and the scanner skips
same-signature hits inside those sectors (see `Scan.cpp`).

## attrs contract

Common to every table:

| key | value |
|---|---|
| `table` | `mbr-primary` \| `gpt-primary` \| `gpt-backup` |
| `partitions` | the entry list, see below |
| `partition_count` | entries in `partitions` |
| `disk_offset` | Span-relative offset of LBA 0 of the disk the table describes; absent when LBA 0 lies before the data (carved slice, `gpt-origin-outside`). Partition starts in `partitions` are relative to this, **not** to the finding offset. For a standard primary it equals the finding offset. |
| `disk_size` | bytes the table implies: MBR = end of the farthest partition; GPT = `(last LBA + 1) * sector` where the last LBA is `alternate_lba` for a primary and `my_lba` for a backup, never smaller than the farthest partition |
| `protective` | `true` when an MBR has a 0xEE entry |

`partitions` (the encoding `Recurse.cpp` parses; entries separated by `;`,
fields by `:`, names sanitised by `list_safe`):

```
MBR   pN:start_bytes:size_bytes:type_byte[:boot][:logical]
      p1..p4 are primary slots, p5.. logicals in chain order
GPT   pN:start_bytes:size_bytes:type_guid:unique_guid:name[:attrs=0x..]
      N is the 1-based slot in the entry array
```

MBR only: `disk_signature` (`0x` + 8 hex digits), `also_covers`
(`offset:512;...`, the EBR sectors).

GPT only: `revision`, `sector_size`, `disk_guid`, `header_lba` (`my_lba`;
a backup also carries the alias `my_lba` that earlier consumers read),
`alternate_lba`, `entries_lba`, `entry_count`, `entry_size`,
`first_usable_lba`, `last_usable_lba`, `entry_array_crc` (`ok` \| `mismatch`,
absent when the array is outside the data), `alternate`
(`valid` \| `invalid` \| `outside`: the header at `alternate_lba`), and
`backup` on a primary / `primary` on a backup
(`valid` \| `mismatch` \| `invalid` \| `outside`).

Evidence strings name the role and LBA, the partition count and both CRC
results, e.g. `primary header at LBA 1, 18 partition(s), header CRC ok,
entry array CRC ok`.

## Diagnostics

| code | severity | when |
|---|---|---|
| `mbr-entry-invalid` | Info | status not 0x00/0x80, zero length, or start past the data |
| `mbr-partition-truncated` | Warning | entry ends past the available data |
| `mbr-partitions-overlap` | Warning | two entries of the same class overlap |
| `mbr-ebr-missing` | Warning | chain link points at a sector without 0x55AA |
| `mbr-ebr-chain-limit` | Warning | more than `ebr_max_chain` links |
| `gpt-truncated-header` | Warning | fewer than 92 bytes after the magic |
| `gpt-bad-header-size` | Warning | `header_size` outside [92, sector] |
| `gpt-bad-entry-size` | Warning | `entry_size` not a multiple of 8 >= 128 |
| `gpt-bad-my-lba` | Warning | `my_lba` is 0 or equals `alternate_lba` |
| `gpt-header-crc-mismatch` | Warning | header CRC32 differs |
| `gpt-entries-outside` | Warning | entry array not inside the data |
| `gpt-entry-limit` | Warning | more than `max_entries` entries; the rest unread |
| `gpt-entry-invalid` | Info | entries with a type GUID but no valid LBA range skipped |
| `gpt-entry-array-crc-mismatch` | Warning | entry array CRC32 differs |
| `gpt-entries-detached` | Info | entry array not adjacent to the header; finding covers the header only |
| `gpt-origin-outside` | Info | LBA 0 lies before the data; `disk_offset` absent |
| `gpt-disk-truncated` | Warning | `disk_size` exceeds the data available from LBA 0 |
| `gpt-backup` | Info | backup header that matches its primary |
| `gpt-backup-mismatch` | Warning | primary and backup describe different disks or arrays |
| `gpt-primary-missing` | Warning | backup parsed because the primary is invalid or outside the data |

## Conflict resolution

`Scan.cpp` treats partition tables specially: a table finding is only ever
absorbed by another partition table (the protective MBR at the same offset
as its GPT), never by a filesystem or container that starts at the same
offset or claims the bytes around it. A table's own extent is small, so the
normal rule still suppresses stray magics that land inside its entry array.
The total order (offset, confidence, size, name) is unchanged, so output is
byte-identical run to run.

## Known gaps

* An MBR at a non-zero offset is read as a nested disk image: its LBAs are
  taken relative to the MBR sector. A relocated protective MBR beside a
  vendor-LBA GPT (audio) therefore reports its single 0xEE entry at the
  wrong offset; it is absorbed by the GPT finding at the same offset, whose
  `disk_offset` is authoritative.
* Hybrid MBRs (0xEE plus real entries) are accepted and tagged `protective`;
  no attempt is made to reconcile them with the GPT.
* Apple APM, BSD disklabels, Sun VTOC and vendor tables (MTD partition
  strings in the kernel command line, Qualcomm `partition.xml`) are not
  recognised yet.
