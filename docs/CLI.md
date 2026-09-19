# OmniTrace CLI

`omnitrace` is the command-line front end. Every command reads evidence
through a memory-mapped, read-only `Source`; nothing ever writes to the image.
Exit status is `0` on success and `1` on any failure (unreadable image, case
directory not writable, manifest that does not round-trip).

```
omnitrace [-v] <command> [options]

  hash     <image>                     MD5 / SHA-1 / SHA-256 of an evidence file
  scan     <image> [--json]            format signatures found in the image
  analyze  <image> --out DIR [...]     the Phase 0 case directory
  --version                            print the version
  -v, --verbose                        debug logging (goes to stderr)
```

## `hash <image>`

One pass over the file, three digests. Output is `key: value` lines.

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

## `analyze <image> --out DIR [--no-extract] [--history] [--max-depth N] [--max-files N] [--max-bytes N]`

The end-to-end Phase 0 pipeline:

1. hash the image (MD5, SHA-1, SHA-256) and record it as evidence `e1`;
2. scan it;
3. turn every top-level finding into a node of the evidence graph: partition
   tables become one `partition` node for the table plus one per entry,
   filesystems become `filesystem` nodes, archives / compressed streams /
   uImage wrappers become `container` nodes, anything else identified (raw
   kernels, bootloaders, DTBs) becomes a `region` node with its format set;
4. open every filesystem that has a registered reader over its bytes and walk
   it into `DIR/filesystems/<node-id>/files/`, hashing as it writes, producing
   one `file` node per entry; formats without a reader are reported in the
   coverage table as `unsupported`;
5. report every unclaimed gap of at least 4 KiB as a `region` node named
   `unidentified` (with `fill: 0xff` / `fill: 0x00` when the gap is uniform,
   i.e. erased flash or padding);
6. write the case directory, re-read `manifest.yaml`, and refuse to exit 0
   unless it re-serialises byte-identically.

A finding that lies inside a partition entry (or inside another filesystem or
container) is parented to that node, so `partitions.md` shows the nesting:
image -> MBR -> p1 -> squashfs -> files.

| Option | Effect |
|---|---|
| `-o, --out DIR` | Case directory. Created if missing; existing files are overwritten. Required. |
| `--no-extract` | Walk filesystems for metadata only (`ListingSink`). `listing.yaml` is still written; `files/` is not. Faster, and useful when the examiner only needs the inventory. |
| `--history` | Ask readers for superseded and deleted versions (JFFS2 / UBIFS / YAFFS2 keep them). Extracted versions land in `files/.omnitrace-versions/<path>/v<version>`. |
| `--max-depth N` | Nested extraction levels (default 8). Phase 0 only analyses the image itself; the option is honoured by the recursion pass that follows. |
| `--max-files N` | Entries emitted per run, across all filesystems (default 500000). When the budget is spent the remaining filesystems are recorded but not walked. |
| `--max-bytes N` | Total bytes written per run (default 4 GiB). |

Every limit that trips is visible: the node gets `truncated: "true"` in its
attrs, a `Warning` diagnostic, and the format's coverage row becomes `partial`.

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
coverage: squashfs supported
coverage: jffs2 unsupported - no reader registered
case directory: case-router
```

### The case directory

`manifest.yaml` is the source of truth; every Markdown file is rendered from it
by `output/` and is never hand-edited. Layout (DEVELOPMENT_PLAN.md §6; the
parts Phase 0 produces are marked):

```
DIR/
├── manifest.yaml                  # (Phase 0) schema omnitrace/1: run, evidence, nodes, coverage, tools, diagnostics
├── summary.md                     # (Phase 0) run info, evidence digests, counts by kind, structural map, coverage
├── partitions.md                  # (Phase 0) one row per image/partition/container/filesystem/region node, nested
├── filesystems/<node-id>/
│   ├── listing.yaml               # (Phase 0) every EntryResult: metadata, digests, host path, flags, diagnostics
│   ├── listing.md                 # (Phase 0) same, as a table
│   └── files/                     # (Phase 0, unless --no-extract) the extracted tree
│       └── .omnitrace-versions/   # superseded/deleted versions when --history recovered any
├── artifacts.yaml, artifacts.md   # Phase 2
├── findings.yaml                  # Phase 2: examiner dispositions
├── timeline.csv                   # Phase 2
├── regions/                       # Phase 2: carved / unallocated blobs
├── report/index.html              # Phase 2
└── case.db                        # Phase 2
```

`manifest.yaml` keys, in order: `schema`, `run` (tool, version, git_sha,
started_at, finished_at, host_os, argv), `evidence`, `nodes`, `coverage`,
`tools`, `diagnostics`. Node ids are `n` + a six-digit counter assigned in
insertion order (byte order of what was found), so the same image analysed
twice yields the same ids; only `run.started_at` / `run.finished_at` and
`evidence[].acquired_at` (the image file's mtime) differ between runs on
different machines. Every node carries `location: {source, offset, offset_hex,
length}` relative to the evidence source, so any row traces back to bytes.

The JSON Schema for the manifest is `docs/schema/manifest.schema.json`.

### Coverage

One row per format met during the run:

| status | meaning |
|---|---|
| `supported` | a reader walked every instance completely |
| `partial` | a reader ran but something was left behind: open failed, walk failed, or a limit tripped; `detail` says which and where |
| `unsupported` | recognised by the scanner, no reader registered |
| `tool-missing` | (later phases) an external tool the reader delegates to is absent |

### Examples

```sh
# Inventory only, no extraction
omnitrace analyze spi-dump.bin --out case-1 --no-extract

# Full extraction with history, capped at 100k entries
omnitrace analyze emmc.img --out case-2 --history --max-files 100000

# Machine-readable scan for another tool
omnitrace scan firmware.bin --json | jq '.findings[] | {offset_hex, format, tier}'
```

### End-to-end smoke

With the sample router image:

```sh
omnitrace analyze /home/wrongbaud/projects/omnitrace/firmware/router.bin --out case-router
grep -E "offset_hex|format:" case-router/manifest.yaml | paste - - | grep -E "uimage|squashfs|jffs2"
```

should list `uimage` at `0x50000`, `squashfs` at `0x1c9245` and `jffs2` at
`0xc60000`, with a `jffs2` coverage row (`unsupported` until the JFFS2 reader
lands) and, once the SquashFS reader is registered, the extracted rootfs under
`case-router/filesystems/<id>/files/`.
