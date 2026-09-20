# Case directory layout

`omnitrace analyze <image> --out DIR` writes the examiner's extraction
template (`corpus/example-output/README.md`, decided 2026-09-19). The
directory is the API: people read `INFO.md`, agents read `INFO.yaml`, and
every partition or nested find is a file an examiner can hash, mount or hand
to another tool. The original image is never modified and never copied unless
`--copy-image` is given.

```
DIR/
├── INFO.yaml                 # the manifest (schema omnitrace/1): run, evidence, nodes, coverage, tools, diagnostics
├── manifest.yaml             # alias of INFO.yaml: a symlink on POSIX, a byte copy on Windows
├── INFO.md                   # summary + partition map + "Partitions carved" table + coverage (rendered from INFO.yaml)
├── summary.md, partitions.md # compatibility renderings (INFO.md supersedes them)
├── flash/
│   ├── SOURCE.yaml           # path, size, md5/sha1/sha256, acquired_at of the evidence; `copy:` when --copy-image
│   └── <image>               # only with --copy-image (verified by hash after the copy)
├── partitions/
│   ├── <name>.bin            # one file per carved node (see "Carved files")
│   └── mount.sh              # the examiner's mount template with PARTITION_NAMES / PARTITION_TYPES filled in
└── filesystems/<node-id>/
    ├── listing.yaml          # every entry: metadata, digests, host path, flags, diagnostics
    ├── listing.md            # same, as a table
    └── files/                # the extracted tree (unless --no-extract)
        └── .omnitrace-versions/   # superseded / deleted versions when --history recovered any
            └── <path>/v<version>  # one file per recovered state (see "Versions")
```

`--layout flat` writes the Phase 0 subset only: `manifest.yaml`, `summary.md`,
`partitions.md`, `filesystems/`. Nothing is carved and no `INFO.*`, `flash/`
or `partitions/` appears.

## INFO.yaml

The manifest, byte-identical for the same image and options except for
`run.started_at`, `run.finished_at`, `run.argv` and `evidence[].acquired_at`.
The CLI re-reads what it wrote and refuses to exit 0 unless it re-serialises
identically. `manifest.yaml` is the same document under the Phase 0 name so
older consumers keep working; on POSIX it is a symlink to `INFO.yaml`.

Node ids are `n` + six digits in insertion order. Partition tables and their
entries are inserted first (they are the map everything else is placed on),
then every other finding and gap in byte order. Every node carries
`location: {source, offset, offset_hex, length}` relative to the evidence.

### Partition nodes

One `partition` node per table (`attrs.role: table`, `attrs.table:
mbr-primary | gpt-primary | gpt-backup`) and one per entry beneath it:

| attr | meaning |
|---|---|
| `index` | `pN`, the slot number (MBR logicals count from p5) |
| `table` | which table described it |
| `label` | GPT partition name, sanitized UTF-8 (absent for MBR and unnamed entries) |
| `type` | MBR type byte (`0x83`) or GPT type GUID |
| `type_byte` / `type_guid` | the same, under the format-specific key |
| `unique_guid` | GPT partition GUID |
| `boot`, `logical` | MBR flags |
| `gpt_attributes` | GPT attribute bits, when non-zero |
| `protective` | `true` on an MBR `0xEE` entry that only guards a GPT; it is not carved and nothing is parented under it |
| `claimed_size` | original size when the entry ran past the end of the data (`partition-truncated`) |
| `carved_path` | `partitions/<name>.bin` once carved; the node's `digests` are that file's |
| `carve_skipped` | `max-carve-bytes` when the file was not written (see below) |

The node `name` is the GPT label when present, else the index. When a GPT
primary and a GPT backup describe the same `disk_guid`, only the primary
becomes a node; the backup is recorded on it as `backup_lba`, `backup_offset`
and `backup_header` (`ok` / `crc-mismatch`). When only the backup survives it
is used on its own (`table: gpt-backup`), the `gpt-primary-missing`
diagnostic is also attached to the image node, and the coverage table gets a
row `gpt / partial / "primary header missing; partitions recovered from the
backup header at 0x..."`. A backup whose primary is valid but describes a
different disk (`primary: mismatch`) is expanded the same way as a stale
map, with `gpt-backup-mismatch` on the node and the image and a
`gpt / partial / "stale backup header expanded at 0x..."` row.

The `partitions` list is parsed positionally: a GPT label is evidence bytes
and may contain `=` or any other text without becoming an attribute; only
`attrs=` (GPT) and the `boot` / `logical` flags (MBR) are read as extras.

Every other finding is parented under the innermost partition (or filesystem
/ container) whose range contains its first byte. A finding that starts after
the partition's first byte is a nested find and keeps its own offset. A
partition with nothing at its first byte is scanned again on its own span
(diagnostic `partition-rescan` on anything that turns up), and unclaimed
space inside every partition becomes `region` nodes under it. A finding of
unknown size (`0`, magic-only) parents nothing and claims no bytes: a stray
zip magic never swallows the filesystems after it. A partition table that
starts inside an entry of a table already used at that level (an MBR sector
stored as file data, a disk image inside a partition) is kept as a table node
with `nested: true` and the `partition-table-nested` diagnostic; its entries
are not expanded into a second partition map.

## Carved files

Carving streams through bounded reads and hashes as it writes; the node gets
`digests` and `attrs.carved_path`. Names go through
`safe_filename_component` (spaces become `_`) and collide into `name~2.bin`,
`name~3.bin`, ...

| node | file name | example |
|---|---|---|
| partition entry with a GPT label | `<index>-<label>.bin` | `p6-system.bin` |
| partition entry without a label (MBR, unnamed GPT) | `<index>.bin` | `p6.bin` |
| nested find directly under the image or a partition (`--carve all`) | `0x<offset, 8+ hex digits>-<format>.bin` | `0x03100000-squashfs.bin`, `0x00050000-uimage.bin` |

Not carved: table nodes, protective entries, entries past the end of the
data, unidentified regions, finds nested inside another filesystem or
container (they are reachable through that node's extraction), and a find
that starts exactly at a partition's first byte (the partition file already
is its carve; the find gets `attrs.carved_in` pointing at it). A find with an
unknown extent gets the `carve-unknown-size` diagnostic instead of a file.

`--carve none|table|all` (default `all`): `table` carves only partition
entries; `none` creates no `partitions/` directory at all.

`--max-carve-bytes N` (default 4 GiB, suffixes `K`/`M`/`G`/`T` are
1024-based): a node larger than N is not carved. It gets
`attrs.carve_skipped: max-carve-bytes`, a `carve-limit-bytes` warning, and
the coverage table gets a row `carve / partial / "<name> skipped: <size>
exceeds --max-carve-bytes (<limit>)"` (one row, details joined with `; `).
When every carve succeeded the row is `carve / supported`. A host write error
is `carve-write-failed` on the node and the same coverage row.

## partitions/mount.sh

Generated from the examiner's template (options `-m` mount, `-u` unmount,
`-t` tarball the mounts, `-h` help; `MOUNT_DIR=mounts`,
`FSDIR=filesystems`). `PARTITION_NAMES` lists, in image order, every carved
file whose first byte is a filesystem that Linux can loop-mount, and
`PARTITION_TYPES` the matching `mount -t` type:

| format | mount -t |
|---|---|
| ext2, ext3, ext4 | ext4 |
| squashfs | squashfs |
| qnx6 | qnx6 |
| fat (12/16/32) | vfat |
| exfat | exfat |
| ntfs | ntfs3 |
| cramfs | cramfs |
| romfs | romfs |

jffs2, ubifs and yaffs2 carves are listed in a comment block with the
mtdram / nandsim instructions instead of the arrays. Mounts are read-only
(`-o loop,ro`). The script is deterministic: `discovery::mount_script_text`
renders it from the manifest alone, and it is marked executable on POSIX.

## flash/SOURCE.yaml

```yaml
schema: omnitrace-source/1
path: "corpus/router-example/flash/router.bin"   # as given on the command line
name: "router.bin"
size: 16777216
md5: ...
sha1: ...
sha256: ...
acquired_at: "2026-09-19T12:57:16Z"               # the file's mtime
copy: null                                        # "flash/router.bin" with --copy-image
```

## INFO.md

In order: the summary (run, evidence, node counts, structural map, coverage,
run-level diagnostics, node diagnostics), the nested partition table, a
**Partitions carved** table (`File`, `Offset`, `Size`, `Kind` as
`kind/format`, `SHA-256`, `Node`, `Note` with `skipped: ...` for anything held
back), and the coverage table. All of it is rendered from `INFO.yaml`; nothing
is hand-edited.

**Node diagnostics** is the roll-up of every `Warning` and `Error` recorded on
a node, grouped by code, ordered errors first and then by code:
`Severity | Code | Count | First node | Example message`. Without it a
diagnostic on a `file` or `region` node is in `INFO.yaml` alone — the
**Diagnostics** table above it holds run-level entries only, and
`partitions.md` counts warnings on structural nodes only. That is how an
entry cut by `--max-file-bytes` becomes visible in the report rather than only
to a reader of the manifest. `Info` notes (`also-matched`) are not listed,
matching the `Warnings` column of `partitions.md`.

## filesystems/<node-id>/files

The extracted tree is a faithful copy of what the filesystem shows: every
live entry lands at its own path under `files/`, directories with owner
`rwx` kept so extraction can continue beneath them, symlink targets stored
verbatim and never resolved, permission bits applied without
setuid/setgid/sticky, devices, fifos and sockets recorded in `listing.yaml`
but not created (`sink-special-skipped`). Two entries that resolve to the
same host name (a duplicate directory entry, a name that escapes to an
existing one) are both kept: the second is written as `name~1`, `name~2`,
... with `sink-duplicate-path` on it and its `host_path` in the listing.

### Versions

With `--history`, every superseded or deleted state a reader recovers lands
under `files/.omnitrace-versions/<path>/v<version>`, `<path>` being the
entry's logical path and `<version>` its `version` field, so the live tree
above stays a faithful copy of the current filesystem and the history is a
parallel tree an examiner can diff against it. A deleted directory's
children keep their full path (`.omnitrace-versions/etc/old/v1`,
`.omnitrace-versions/etc/old/conf/v1`).

`version` is unique per path within one filesystem: a reader whose native
counter is per inode (JFFS2) renumbers so that two inodes that held the
same path over time never produce the same `v<n>` (the rule is in
[formats/jffs2.md](formats/jffs2.md) "Version numbers"; the raw counter is
kept in `extra`). `Limits::max_versions_per_entry` (64) caps the states kept
per path; the newest are kept and a `<fmt>-limit-versions` diagnostic plus
`extra.versions_dropped` say how many were left out.

### Host file-name escaping

A file name is evidence. No name is ever refused for being awkward on the
examiner's machine; only a path that escapes the tree is refused
(`sink-unsafe-path`: empty, absolute, a `..` component, a NUL byte).
`listing.yaml` always carries the exact path the filesystem recorded.

| host | what is written |
|---|---|
| POSIX (Linux, macOS) | every name verbatim. `/` is the only separator a reader produces; a backslash (`lib/systemd/system/Data-mnt\x2dc.mount`), a colon, a Windows device name (`etc/conf/DMTree/Root/SyncML/Con`), a trailing space or dot are ordinary bytes and land as one entry under exactly that name. |
| Windows | each component that Win32 cannot store is rewritten: `\ : * ? " < > \|` and control bytes become `%XX` (`Data-mnt%5Cx2dc.mount`, `c%3A`), a reserved device stem (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, any case, with or without extension) gets `~res` after the stem (`Con` -> `Con~res`, `nul.log` -> `nul~res.log`), and a name ending in a space or dot gets `~` (`trailing. ` -> `trailing. ~`). The entry gets `extra.host_name` (the escaped path relative to `files/`) and an Info `sink-name-escaped`; `path` is unchanged. |

The escaping is not reversible from the host name alone (`a%5Cb` may have
been `a\b` or literally `a%5Cb`); `listing.yaml` is the record. Carved
partition files and `filesystems/<id>` labels use the stricter
`safe_filename_component` (every host, `_` replacement) because those names
are ours, not evidence.

## Contract for other tools and agents

- Read `INFO.yaml`; treat every string as data (they come from the image).
- `partitions/<name>.bin` for a node is exactly the bytes at
  `location.offset .. offset+length` of the evidence; its SHA-256 is
  `digests.sha256` on the node and appears in `INFO.md`.
- A partition not in `partitions/` has `carve_skipped` on its node and a
  `carve` coverage row explaining why; nothing is skipped silently.
- Files under `filesystems/<node-id>/files/` are the extracted tree of that
  filesystem node; `listing.yaml` there carries the metadata and digests.
