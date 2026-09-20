# OmniTrace CLI

This page is for examiners running `omnitrace` and for anyone scripting it.
After reading it you can hash an image, list what the scanner finds, produce
a case directory with the options that matter for evidence handling, and read
what the tool prints. The exact option list is generated from the source into
`docs/reference/CLI_FLAGS.md` and checked by `scripts/check_docs.py`; this
page explains what the options do.

`omnitrace` is the command-line front end (`apps/cli/main.cpp`,
`apps/cli/analyze_commands.cpp`). Every command reads evidence through a
memory-mapped, read-only `Source`; nothing ever writes to the image. Exit
status is `0` on success and `1` on any failure (unreadable image, case
directory not writable, manifest that does not round-trip). `-h, --help` on
any command prints the CLI11 help.

```
omnitrace [-v] <command> [options]

  hash     <file>                      MD5 / SHA-1 / SHA-256 of an evidence file
  scan     <image> [--json]            format signatures found in the image
  analyze  <image> --out DIR [...]     the case directory (docs/CASE_LAYOUT.md)
  --version                            print the version
  -v, --verbose                        debug logging (goes to stderr)
```

## `hash <file>`

One pass over the file, three digests. Output is `key: value` lines
(`path`, `size`, `md5`, `sha1`, `sha256`).

## `scan <image> [--json]`

Runs the discovery scanner (`signatures/*.toml` compiled into the binary plus
the structural validators) over the whole image and prints every finding after
deterministic conflict resolution. Nothing is extracted and nothing is written.

Table columns: `Offset` (hex), `Size` (bytes, `?` when the validator could not
determine an extent), `Format`, `Tier` (`magic` / `structural` / `consistent` /
`verified`, see `docs/ARCHITECTURE.md`), `Evidence` (why that tier), `Attrs`
(`key=value`, format-specific: version, compression, partitions, ...).

`--json` prints one document instead:

```json
{
  "image": "router.bin",
  "size": 16777216,
  "findings": [
    {
      "offset": 327680, "offset_hex": "0x50000", "size": 1544773,
      "format": "uimage", "category": "kernel", "signature": "uimage",
      "confidence": 99, "tier": "verified", "evidence": "...", "endian": "big",
      "attrs": {"arch": "mips", "compression": "lzma", "...": "..."},
      "diagnostics": [{"severity": "warning", "code": "...", "message": "..."}],
      "also_matched": []
    }
  ]
}
```

`also_matched` holds lower-confidence findings the resolver suppressed because
a better one covers the same bytes.

## `analyze <image> --out DIR [--layout corpus|flat] [--carve none|table|all] [--max-carve-bytes N] [--copy-image] [--no-extract] [--history] [--max-depth N] [--max-files N] [--max-bytes N] [--max-file-bytes N]`

The end-to-end pipeline:

1. hash the image (MD5, SHA-1, SHA-256) and record it as evidence `e1`;
2. scan it;
3. build the evidence graph partition-first: every partition table becomes
   one `partition` node for the table plus one per entry, named from the GPT
   label (`system`) or the slot (`p6`); a GPT backup that matches a primary is
   folded into it (`backup_lba`), a backup with no primary is used on its own
   and `gpt-primary-missing` lands on the image node; every other finding is
   parented under the partition (or filesystem / container) whose range holds
   its first byte, so `INFO.md` shows the nesting image -> GPT -> system ->
   ext4 -> files. Filesystems become `filesystem` nodes, archives /
   compressed streams / uImage wrappers `container` nodes, anything else
   identified (raw kernels, bootloaders, DTBs) a `region` node with its format
   set. A partition with nothing at its first byte is scanned again on its own;
4. open every filesystem that has a registered reader over its bytes and walk
   it into `DIR/filesystems/<node-id>/files/`, hashing as it writes, producing
   one `file` node per entry; formats without a reader are reported in the
   coverage table as `unsupported`;
5. re-scan every file that landed on disk. A file that is itself an image — a
   filesystem or a partition table, identified at `structural` or better and
   at least 4 KiB long — gets `nested_image: true` and is analysed again from step 2 with the `file`
   node as its parent, so a
   SquashFS stored as a file inside a QNX6 filesystem becomes a real
   `filesystem` node with its own tree under `DIR/filesystems/<its-id>/files/`.
   Offsets below it are relative to the extracted file and `location.source_id`
   names it. A file keeps no children when its scan finds only identified
   bytes (an ELF, a certificate), only a container (nothing can open a payload
   until a container reader is registered), or only magic-tier hits — the
   magic-only signatures `zip`, `tar`, `cpio` and `7z` match constantly inside
   compressed data and are not evidence of a nested image. Nor is a high tier
   by itself a size: the JFFS2 validator CRC-checks nodes and reaches
   `verified` on a single valid 12-byte one, so a find shorter than the 4 KiB
   floor the pass applies to unidentified space is left alone. `--max-depth`
   bounds the nesting and `--no-extract` skips this step entirely, because
   nothing reaches the host;
6. report every unclaimed gap of at least 4 KiB, at the top level and inside
   every partition, as a `region` node named `unidentified` (with `fill: 0xff`
   / `fill: 0x00` when the gap is uniform, i.e. erased flash or padding);
7. carve every partition entry and (with `--carve all`) every nested find into
   `DIR/partitions/<name>.bin`, streaming and hashing, and generate
   `DIR/partitions/mount.sh`; anything larger than `--max-carve-bytes` is
   skipped with a `carve` coverage row and a diagnostic on the node;
8. write the case directory (`docs/CASE_LAYOUT.md`), re-read `INFO.yaml`, and
   refuse to exit 0 unless it re-serialises byte-identically.

| Option | Effect |
|---|---|
| `-o, --out DIR` | Case directory. Created if missing; existing files are overwritten. Required. |
| `--layout corpus\|flat` | `corpus` (default): the examiner template of `docs/CASE_LAYOUT.md` (`INFO.yaml` + `manifest.yaml` alias, `INFO.md`, `flash/SOURCE.yaml`, `partitions/`, `filesystems/`, plus `summary.md` / `partitions.md`). `flat`: the Phase 0 files only (`manifest.yaml`, `summary.md`, `partitions.md`, `filesystems/`), nothing carved. |
| `--carve none\|table\|all` | What lands in `partitions/`: `all` (default) every partition entry and every nested find directly under the image or a partition (`0x03100000-squashfs.bin`); `table` entries only (`p6-system.bin`, `p6.bin`); `none` no `partitions/` directory. |
| `--max-carve-bytes N` | Largest file to carve (default 4 GiB; `64M`, `2G` accepted, 1024-based). A larger partition is not written: its node gets `carve_skipped` and a warning, and coverage gets `carve / partial / "<name> skipped: <size> exceeds --max-carve-bytes"`. |
| `--copy-image` | Also copy the evidence into `flash/<name>` (verified by SHA-256 after the copy). Default: `flash/SOURCE.yaml` only refers to the original path. |
| `--no-extract` | Walk filesystems for metadata only (`ListingSink`). `listing.yaml` is still written; `files/` is not. Faster, and useful when the examiner only needs the inventory. |
| `--history` | Ask readers for superseded and deleted versions (JFFS2 / UBIFS / YAFFS2 keep them). Extracted versions land in `files/.omnitrace-versions/<path>/v<version>`. |
| `--max-depth N` | Nesting levels analysed (default 8). The image is level 0, a file extracted from a filesystem in it is level 1, a file extracted from a filesystem inside *that* is level 2. When the cap stops a level the run gets one `analyze-limit-depth` warning naming the filesystem and how many extracted files were not re-scanned — one per level, not one per file. `0` analyses the image and nothing nested. |
| `--max-files N` | Entries emitted per run, across all filesystems (default 500000). When the budget is spent the remaining filesystems are recorded but not walked. |
| `--max-bytes N` | Total bytes written per run (default 4 GiB). |
| `--max-file-bytes N` | Largest single extracted entry (default 1 GiB; `2G`, `8G` accepted, 1024-based). A larger entry is written up to the cap and cut there: the file node gets `truncated: "true"` and a `<fmt>-limit-file-bytes` warning. Raise it when a filesystem holds whole nested images as files — the QNX6 `storage` partition of the corpus keeps SquashFS update images of 1.0-1.6 GiB, and at the default each one is cut mid-image and will not read back as a filesystem. |

Every limit that trips is visible: the node gets `truncated: "true"` in its
attrs, a `Warning` diagnostic, and the format's coverage row becomes `partial`.
Every diagnostic code that can appear in `INFO.yaml` is catalogued with its
meaning and the examiner's next step in `docs/reference/DIAGNOSTICS.md`.

### Stdout

A short table of the structural nodes (files are omitted; they are in the
listings), the counts by kind, one line per coverage row, and the case
directory path:

```
router.bin: 16.0 MiB, sha256 ...

Node     Kind        Offset    Size       Format    Tier        Name          Details
-------  ----------  --------  ---------  --------  ----------  ------------  ------------------------
n000001  image       0x0       16.0 MiB   raw       verified    router.bin
n000002  region      0x0       320.0 KiB  -         reject      unidentified
n000003  container   0x50000   1.5 MiB    uimage    verified    MIPS Linux    compression=lzma type=kernel
n000004  filesystem  0x1c9245  10.6 MiB   squashfs  consistent  squashfs      entries=1379 files=1005 compression=xz
n001384  filesystem  0xc60000  3.6 MiB    jffs2     verified    jffs2
n001385  region      0xff000c  64.0 KiB   -         reject      unidentified  fill=0xff

1385 node(s): 0 partition(s), 1 container(s), 2 filesystem(s), 1379 file(s), 2 region(s)
carved: partitions/0x00050000-uimage.bin (1.5 MiB, sha256 477f0b...)
carved: partitions/0x001c9245-squashfs.bin (10.5 MiB, sha256 cd8103...)
carved: partitions/0x00c60000-jffs2.bin (3.6 MiB, sha256 335b5a...)
coverage: uimage unsupported - no container reader registered
coverage: squashfs supported
coverage: jffs2 unsupported - no reader registered
coverage: carve supported
case directory: case-router (corpus layout)
```

With a partition table, one `carved:` line per entry and one `carve skipped:`
line per entry held back by `--max-carve-bytes`.

### The case directory

`docs/CASE_LAYOUT.md` is the contract. In short (default `--layout corpus`):

```
DIR/
├── INFO.yaml                      # the manifest, schema omnitrace/1 (source of truth)
├── manifest.yaml                  # alias of INFO.yaml (symlink on POSIX, copy on Windows)
├── INFO.md                        # summary + partition map + carved-partition table + coverage
├── summary.md, partitions.md      # compatibility renderings
├── flash/SOURCE.yaml              # path, size, digests, acquired_at of the evidence (+ the copy with --copy-image)
├── partitions/<name>.bin          # p6-system.bin / p6.bin / 0x03100000-squashfs.bin
├── partitions/mount.sh            # examiner template, PARTITION_NAMES / PARTITION_TYPES filled in
└── filesystems/<node-id>/
    ├── listing.yaml, listing.md   # every EntryResult: metadata, digests, host path, flags, diagnostics
    └── files/                     # the extracted tree (unless --no-extract)
        └── .omnitrace-versions/   # superseded/deleted versions when --history recovered any
```

`INFO.yaml` keys, in order: `schema`, `run` (tool, version, git_sha,
started_at, finished_at, host_os, argv), `evidence`, `nodes`, `coverage`,
`tools`, `diagnostics`. Node ids are `n` + a six-digit counter assigned in
insertion order (partition tables and their entries first, then everything
else in byte order), so the same image analysed twice yields the same ids;
only `run.started_at` / `run.finished_at`, `run.argv` and
`evidence[].acquired_at` (the image file's mtime) differ between runs on
different machines. Every node carries `location: {source, offset,
offset_hex, length}` relative to the evidence source, so any row traces back
to bytes; carved nodes also carry `digests` and `attrs.carved_path`.

The JSON Schema for the manifest is `docs/schema/manifest.schema.json`.

### Coverage

One row per format met during the run:

| status | meaning |
|---|---|
| `supported` | a reader walked every instance completely (for the `carve` row: every file was written) |
| `partial` | a reader ran but something was left behind: open failed, walk failed, or a limit tripped; `detail` says which and where. For `carve`: one or more files were skipped (`--max-carve-bytes`) or could not be written |
| `unsupported` | recognised by the scanner, no reader registered |
| `tool-missing` | (later phases) an external tool the reader delegates to is absent |

### Examples

```sh
# Inventory only, no extraction, partitions still carved
omnitrace analyze spi-dump.bin --out case-1 --no-extract

# eMMC dump: carve only the partition-table entries, and none above 64 MiB
omnitrace analyze emmc.img --out case-emmc --carve table --max-carve-bytes 64M

# Keep a verified copy of the evidence beside the case
omnitrace analyze emmc.img --out case-emmc --copy-image

# The Phase 0 layout only (manifest.yaml, summary.md, partitions.md, filesystems/)
omnitrace analyze spi-dump.bin --out case-flat --layout flat

# Full extraction with history, capped at 100k entries
omnitrace analyze emmc.img --out case-2 --history --max-files 100000

# Machine-readable scan for another tool
omnitrace scan firmware.bin --json | jq '.findings[] | {offset_hex, format, tier}'
```

### End-to-end smoke

With a 16 MiB OpenWrt SPI-flash dump from a local corpus (`router.bin`):

```sh
omnitrace analyze router.bin --out case-router
grep -E "offset_hex|format:" case-router/INFO.yaml | paste - - | grep -E "uimage|squashfs|jffs2"
ls case-router/partitions
```

should list `uimage` at `0x50000`, `squashfs` at `0x1c9245` and `jffs2` at
`0xc60000`, with a `jffs2` coverage row (`unsupported` until the JFFS2 reader
lands), the extracted rootfs under `case-router/filesystems/<id>/files/`, and
`partitions/` holding `0x00050000-uimage.bin`, `0x001c9245-squashfs.bin`,
`0x00c60000-jffs2.bin` and a `mount.sh` whose arrays name the squashfs carve
(the jffs2 one is in the mtdram comment block). With a GPT-partitioned
eMMC dump from a local corpus:

```sh
omnitrace analyze emmc.img --out case-emmc --carve table --max-carve-bytes 64M
```

carves `p1-dtb.bin` ... `p16-kpanic.bin` from the GPT labels, skips
`p6-system.bin` (1.3 GiB) and the other entries above 64 MiB with a
`carve / partial` coverage row, and lists `p7-home.bin` / `p11-appdata_ext.bin`
as `ext4` in `mount.sh`.
