# Testing: synthetic fixtures and the parity harness

Two harnesses live under `tests/`:

| | What it does | Entry point |
|---|---|---|
| **Fixtures** | Builds a small, forensically rich file tree into every filesystem, container and partition-table format OmniTrace reads, with a scripted create / overwrite / delete history, and writes a ground-truth `*.expected.yaml` beside every image. Byte-reproducible. | `tests/fixtures/build.sh` (or `scripts/fixtures.sh`) |
| **Parity** | Runs unblob, binwalk 3, moria and (when built) the OmniTrace CLI over one image, normalises their output into one shape, diffs findings by offset and files by path + sha256, and writes a Markdown report and a JSON summary. | `tests/parity/run.py` |

Unit tests (`tests/unit/<layer>/*_test.cpp`) read the fixtures through `OMNITRACE_TEST_DATA_DIR`, which `cmake/Warnings.cmake:48` compiles in as `<repo>/tests/fixtures`; the test helpers append `/out`, so nothing needs to be set and a missing fixture makes the test skip, not fail. A reader test compares what it walks against the `tree` and `history` sections of the matching `expected.yaml`, never against another tool.

---

## 1. Synthetic fixtures (`tests/fixtures/`)

### Files

| File | Role |
|---|---|
| `Dockerfile` | `debian:bookworm` with squashfs-tools, mtd-utils (`mkfs.jffs2`, `mkfs.ubifs`, `ubinize`), e2fsprogs, dosfstools, mtools, python3-yaml, plus **yaffs2utils** (`mkyaffs2`, GPL-2.0, executed only, never linked) built from the GitHub export of the code.google.com project at a pinned commit (`YAFFS2UTILS_COMMIT` build arg). |
| `build.sh` | Builds the Docker image and runs `generate.py` inside it with `tests/fixtures/out` bind-mounted at `/out`, then hands ownership back to the invoking user. `--native` runs `generate.py` on the host and skips fixtures whose tool is missing. `--check` builds twice and fails unless every image is byte-identical. |
| `generate.py` | The builder. `--only NAME` (repeatable), `--skip-missing`, `-v`. |
| `out/` | Generated: images, `<name>.expected.yaml`, `index.yaml`. Regenerate; do not edit. |

`scripts/fixtures.sh {build|check|list|verify|clean|parity}` wraps all of this.

```
scripts/fixtures.sh build              # Docker, every image (~1 min after the image is cached)
scripts/fixtures.sh build --native     # host tools only: squashfs, ext4, fat32, wrappers
scripts/fixtures.sh check              # reproducibility gate used in CI
scripts/fixtures.sh verify             # every image still matches its expected.yaml sha256
```

Native builds need `mksquashfs`, `mkfs.ext4` + `debugfs`, `mkfs.vfat` + `mcopy`/`mdel`; jffs2, ubifs/ubi and yaffs2 additionally need mtd-utils and yaffs2utils. yaffs2 also needs root (mkyaffs2 preserves ownership from the staging tree), so it is Docker-only in practice.

### What is produced

| Image | Built with | Notes |
|---|---|---|
| `squashfs-{gzip,xz,lz4,zstd}.img` | `mksquashfs -comp … -b 131072` | ownership via `-pf` pseudo file, `-mkfs-time`/`-root-time` pinned |
| `squashfs-none.img` | `mksquashfs -noI -noD -noF -noX` | superblock names gzip, every block stored raw; payload of `uimage-lzma.img` |
| `jffs2-le.img`, `jffs2-be.img` | `mkfs.jffs2 -e 65536 --pad` | little/big endian, cleanmarkers |
| `jffs2-history.img` | `mkfs.jffs2` + hand-assembled nodes | see [History semantics per format](#history-semantics-per-format) |
| `ubifs.img` | `mkfs.ubifs -m 2048 -e 129024 -c 128 -x zlib` | superblock UUID and every inode's atime/ctime pinned after the fact (CRCs recomputed) |
| `ubifs-history.img` | `mkfs.ubifs` + a hand-assembled journal | see [History semantics per format](#history-semantics-per-format) |
| `ubi.img` | `ubinize -m 2048 -p 131072 -s 2048 -O 2048 -Q 0x12345678` | one dynamic autoresize volume `rootfs` holding `ubifs.img` |
| `yaffs2.img` | `mkyaffs2 -p 2048 -s 64` | page + spare (OOB) image, Linux MTD spare layout (tags at spare byte 2) |
| `yaffs2-yaffsecc.img` | `mkyaffs2 -p 2048 -s 64 --yaffs-ecclayout` | YAFFS spare layout (tags at spare byte 0). mkyaffs2 has no inband-tags mode, so there is no "without OOB" variant; both layouts are produced instead |
| `yaffs2-history.img` | `mkyaffs2` + hand-assembled chunks | see [History semantics per format](#history-semantics-per-format) |
| `ext4.img` | `mkfs.ext4` + `debugfs` scripts | 16 MiB, 4 KiB blocks, no journal, fixed UUID/hash seed; history via `unlink`/`kill_file`/`link`/`rm` |
| `fat32.img` | `mkfs.vfat --invariant` + `mcopy`/`mdel` | 33 MiB, 512-byte clusters, `-m` keeps mtimes |
| `mbr-two-partitions.img` | Python | MBR with `ext4.img` (0x83, bootable) at 1 MiB and `squashfs-gzip.img` (0x83) at 17 MiB |
| `gpt.img` | Python | protective MBR + primary/backup GPT with `fat32.img` (MS basic data) and `squashfs-xz.img` (Linux FS); header and entry CRCs valid |
| `nested.tar.gz` | Python tarfile/gzip | `firmware/README.txt` + `firmware/squashfs-gzip.img` |
| `uimage-lzma.img` | Python | uImage legacy header (CRCs valid, type filesystem, arch arm, comp lzma) wrapping `squashfs-none.img` as an LZMA-alone stream with the real uncompressed size in the header (what U-Boot and real firmware carry) |

`index.yaml` lists every image with size, sha256, format, the tool versions used, and any fixture that was skipped and why.

### The file tree

Every filesystem image contains the same tree (entries a format cannot represent are dropped and `features` in the YAML says so):

```
bin/                              0755 1000:100
  busybox                         0755  300 KiB pseudo-random (spans several blocks)
  ash                             hard link to busybox (nlink 2)
  sh -> busybox                   symlink
etc/                              0755 0:0
  passwd                          0644 0:0
  secret.key                      0600 1000:100, 1 KiB
  network/interfaces              0644  (MAC address, static IP, SSID: artifact bait)
data/dir with spaces/ünïcödé ファイル.txt   name with spaces and non-ASCII
data/sparse.bin                   4 KiB marker + 192 KiB zeros + 4 KiB marker
empty.txt                         0 bytes
history/config.txt                v1, then overwritten with v2 and v3
history/deleted.txt               created, then unlinked
var/log/messages                  0644 0:0, 40 syslog-style lines
```

uid 1000 / gid 100 throughout except the root-owned `etc`, `var` and their files. mtimes are `1700000000 + 2n` (even, so FAT's 2-second resolution keeps them). Content is derived from SHA-256 chains, so no two builds differ.

### `<name>.expected.yaml`

```yaml
schema: omnitrace-fixture/1
name: jffs2-history
image:   {file, format, size, sha256, builder, argv}
features: {symlink, hardlink, mode, owner, mtime_resolution}
tree:                       # sorted by path; the *live* tree after the history script ran
- path: bin/ash
  kind: regular             # directory | regular | symlink
  mode: '0755'              # octal string; absent when the FS has no modes (FAT)
  uid: 1000
  gid: 100
  size: 307200
  sha256: 5d6bc9…           # regular files only
  hardlink_of: bin/busybox  # when the entry shares an inode
  nlink: 2
  link_target: busybox      # symlinks
  mtime: 1700000004
attrs:   {…}                # format specifics: compression, erase size, endian, UUIDs, page/spare layout
history:                    # only for images with a scripted history
  superseded: [{path, inode, version, size, sha256, mtime, …}]   # older versions still on disk
  current:    [{path, inode, version, size, sha256, mtime}]
  deleted:    [{path, inode, size, sha256, mtime, content_recoverable, …}]
  note: how the history was produced and what a reader can expect to recover
tools:   {mkfs.jffs2: "mkfs.jffs2 (mtd-utils) 2.1.5", …}
```

Wrapper images carry `partitions:` (MBR/GPT: `name, fixture, offset, size, content_sha256, type…`), `volumes:` (UBI), `layers:` + `tree:` (nested tar.gz) or `header:` + `payload:` (uImage) instead of a tree; the `fixture` field names the inner image whose own YAML describes the contents.

### History semantics per format

**JFFS2 history nodes** (`jffs2-history.img`). <a name="jffs2-history-nodes"></a> `mkfs.jffs2` cannot express history, so the image is written normally and then nodes are appended in Python after the last node mkfs wrote (never crossing an erase block; a cleanmarker is emitted when a new block is started). Versions continue from the highest version mkfs used. All three CRCs are Linux `crc32_le(0, …)`: reflected polynomial 0xEDB88320, initial value 0, **no final XOR** (`zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF`).

`jffs2_raw_inode` (68-byte header + data, all integers in the image's byte order):

| off | size | field | value used |
|---:|---:|---|---|
| 0 | u16 | magic | 0x1985 |
| 2 | u16 | nodetype | 0xE002 |
| 4 | u32 | totlen | 68 + len(data) |
| 8 | u32 | hdr_crc | crc(bytes 0..8) |
| 12 | u32 | ino | inode of `history/config.txt` (looked up from the live dirents) |
| 16 | u32 | version | max + 1, max + 2 |
| 20 | u32 | mode | copied from the file's newest mkfs node |
| 24 / 26 | u16 | uid / gid | copied |
| 28 | u32 | isize | new file size |
| 32 / 36 / 40 | u32 | atime / mtime / ctime | 1700000100, 1700000110 |
| 44 | u32 | offset | 0 (whole file in one node) |
| 48 / 52 | u32 | csize / dsize | len(data) (compr none) |
| 56 / 57 | u8 | compr / usercompr | 0 |
| 58 | u16 | flags | 0 |
| 60 | u32 | data_crc | crc(data) |
| 64 | u32 | node_crc | crc(bytes 0..64) |
| 68 | | data | v2 then v3 of config.txt |

`jffs2_raw_dirent` (40-byte header + name) for the unlink: `nodetype 0xE001`, `pino` = inode of `history/`, `version` = max + 3, **`ino = 0`** (that is how JFFS2 records a deletion), `mctime 1700000130`, `nsize`, `type DT_REG`, `node_crc = crc(bytes 0..32)`, `name_crc = crc(name)`. The original inode nodes of both files stay on flash; `history.superseded` lists config v1 (mkfs node) and v2 (appended), `history.current` v3, `history.deleted` `deleted.txt` with `unlink_node_offset`, and `history.appended_nodes` gives every appended node's offset and length. The builder re-parses the finished image and verifies every header CRC.

**UBIFS journal and history** (`ubifs-history.img`). <a name="ubifs-history-nodes"></a>
`mkfs.ubifs` only ever writes a clean image: everything is in the index and the
log holds nothing but a commit-start node. The states a forensic reader has to
recover only exist once something has been written *since* the last commit, so
the builder appends a journal bud to the mkfs output, which is byte for byte
the state the medium is in after three ordinary operations.

Every node carries the 24-byte common header (magic `0x06101831`, crc32 over
bytes 8..`len` with initial value `0xFFFFFFFF` and **no final XOR**, a global
`sqnum`, `len`, `node_type`). The bud goes in the first erase block that is
still all `0xFF`, and its nodes are written in the order UBIFS writes them --
data first, the inode node carrying the new size and times last, `sqnum`
increasing and continuing from the highest mkfs wrote:

| node | type | key | what it says |
|---|---|---|---|
| data | 1 | (`config.txt` inode, type 1, block 0) | v2 of `history/config.txt`, uncompressed |
| inode | 0 | (`config.txt` inode, type 0) | its new size and mtime 1700000100; mode, owner and link count copied from the mkfs node |
| data | 1 | (`config.txt` inode, type 1, block 0) | v3 |
| inode | 0 | (`config.txt` inode, type 0) | its new size and mtime 1700000110 |
| dent | 2 | (`history` inode, type 2, the name's hash) | `deleted.txt` with **`inum = 0`**, which is how UBIFS records an unlink |

A reference node (type 8, 64 bytes, naming the bud's erase block) then goes in
the log, at the first minimum-I/O boundary after the commit-start node -- past
the padding node that fills out the commit-start node's own unit, which is
where UBIFS itself would put it. Without that reference nothing reaches the
bud, so the reference is what makes the journal replay find any of this.

The live tree is therefore `config.txt` at v3 and no `deleted.txt`;
`history.superseded` lists v1 (the mkfs node, still in the index) and v2,
`history.current` v3, and `history.deleted` `deleted.txt` with its
`unlink_node_offset` and `unlink_sqnum`. `history.appended_nodes` gives every
appended node's erase block, offset and length. The builder re-sweeps the
finished image for the node magic at every 8-byte boundary and fails unless
exactly the expected number of nodes verify.

**YAFFS2 history chunks** (`yaffs2-history.img`). <a name="yaffs2-history-chunks"></a>
`mkyaffs2` emits a clean image: one object header per file and no deletions,
so there is no history in it at all. A running YAFFS2 never overwrites -- a
change is a new chunk with a higher sequence number and the old one stays
until its erase block is reclaimed -- and that is what the builder appends,
with a sequence number one above the highest `mkyaffs2` wrote:

| chunk | tags | page |
|---|---|---|
| data | `obj_id` of `history/config.txt`, `chunk_id` 1, `n_bytes` = len(v2) | v2 of the file |
| object header | same `obj_id`, `chunk_id` 0, `n_bytes` 0xFFFF | a copy of the header mkyaffs2 wrote with the new `file_size_low` and times |
| data, object header | the same pair again | v3 |
| object header | `obj_id` of `history/deleted.txt` | its header again with `parent_obj_id` set to **4**, the id YAFFS2 reserves for deleted objects |

Each chunk's spare is 0xFF throughout except the sixteen tag bytes and the
`yaffs_ecc_other` over them, which is how `mkyaffs2` lays it out. The column
parity of that checksum is shifted right by two and masked to six bits before
it is stored (`yaffs_ecc_calc_other`); an implementation that skips that step
produces a value that looks plausible and verifies nothing.

Chunks go down the way a live filesystem writes them, **data first and the
object header last**, which is the order that records the new size once the
bytes are there. `mkyaffs2` does the reverse, writing a file's header when it
creates the object, so the oldest state of `config.txt` is the one whose data
sits after its own header -- the case a reader has to reach back for, and the
reason that state carries `content_recoverable: true` in the YAML rather than
being dropped.

The live tree is therefore `config.txt` at v3 and no `deleted.txt`;
`history.superseded` lists v1 and v2, `history.current` v3, and
`history.deleted` `deleted.txt` with its `unlink_node_offset`.
`history.appended_chunks` gives every appended chunk's index and offset. The
builder re-sweeps the finished image for chunks whose tags verify and fails
unless exactly the expected number do.

Like the other yaffs2 fixtures this needs root, because `mkyaffs2` takes
ownership from the staging tree, so it is Docker-only in practice.

**ext4** (`ext4.img`). Populated with `debugfs -w` (no kernel, no journal). v2 and v3 of `config.txt` are written up front under temporary names so each version owns its own blocks; the history script then does `unlink` + `kill_file` on the old inode and `link`s the new one under `config.txt`, and finally `rm history/deleted.txt`. Result: three freed inodes (`lsdel` shows 26, 27, 31) that keep size, extent tree and data blocks with `dtime` set; the unlinked directory entries (`history/.config.v2`, `.config.v3`, `deleted.txt`) remain in the directory block. Without a journal nothing ties the freed inodes to `config.txt`: v1's entry was overwritten in place by the later `link` of the same name (a reader emits it as `lost+found/#26`) and v2 is named only by the unlinked `.config.v2`, so the YAML lists both under `history.deleted` (with `recovered_as` / `name_recoverable: false` for v1) and `history.superseded` is empty. `E2FSPROGS_FAKE_TIME` pins every timestamp e2fsprogs would otherwise take from the clock.

**FAT32** (`fat32.img`). `mcopy -o` deletes and re-creates, so `config.txt` gets a new directory entry and new clusters per version (old clusters may be reused: `content_recoverable: false`); `mdel history/deleted.txt` leaves its entry with the first byte set to 0xE5, LFN entries, start cluster and size intact (`content_recoverable: true`).

**SquashFS, JFFS2 (plain), UBIFS, YAFFS2**: no history script; the tree is the live tree. UBIFS and YAFFS2 sequence numbers are whatever mkfs wrote.

### Determinism

Every source of entropy is pinned: content from SHA-256 chains, timestamps via tool flags (`-mkfs-time`, `-m`, `-i`, `--invariant`), `E2FSPROGS_FAKE_TIME`, fixed UUIDs / volume ids / image sequence numbers, sorted inputs, `TZ=UTC`, and post-processing where a tool has no flag (UBIFS superblock UUID and inode atime/ctime; YAFFS2 object-header atime/ctime). `SOURCE_DATE_EPOCH` is deliberately dropped from the environment because `mksquashfs` refuses it together with `-mkfs-time`. `build.sh --check` proves it: 18 images byte-identical across two builds.

### Things other tools do with these fixtures (useful when reading parity output)

- **jefferson** (unblob's JFFS2 extractor) ignores `ino == 0` dirents, so it resurrects `history/deleted.txt`, and it does not create hard links, so `bin/ash` is missing. moria honours both.
- **binwalk 3** finds every filesystem but extracts SquashFS/JFFS2 only through external `sasquatch`/`jefferson`, which are usually absent.
- **unblob** has no uImage handler; it finds the LZMA stream at header + 64 instead.

---

## 2. Parity harness (`tests/parity/`)

### Files

| File | Role |
|---|---|
| `run.py` | The harness, one image at a time. Python 3.9+, PyYAML only for `expected.yaml`/manifest parsing. |
| `sweep.py` | Runs `run.py` over many images and pools one number (`scripts/fixtures.sh sweep`). See "Measuring parity" below and `docs/PARITY.md`. |
| `test_run.py` | Unit tests for the normalisers, the diff and the recovery metric: `python3 -m unittest tests/parity/test_run.py`. |
| `moria.Dockerfile` | Builds moria (MIT, https://github.com/nmatt0/moria) at commit `30e4038` into `omnitrace-parity-moria`. `run.py` builds it on first use. |

### Prerequisites

- Docker, with `ghcr.io/onekey-sec/unblob:latest` pullable.
- `binwalk` 3 on the host (`/usr/bin/binwalk`). Its external extractors (`sasquatch`, `jefferson`, `ubireader`) improve its file counts if installed.
- The OmniTrace CLI is optional: `--omnitrace PATH`, else `omnitrace` on `PATH`, else `build/*/apps/cli/omnitrace`. Until `omnitrace analyze <img> --out <dir>` exists the tool is reported as *skipped*.

### Usage

```
tests/parity/run.py IMAGE [--out DIR] [--tools unblob,binwalk,moria,omnitrace]
                    [--expected YAML | --no-expected] [--reuse] [--binwalk-matryoshka]
                    [--unblob-image TAG] [--moria-image TAG] [--no-build] [--omnitrace BIN]
                    [--jobs N] [--timeout S] [--max-list N] [--timestamp ISO]
```

- Default `--out` is `tests/parity/out/<image name>/`.
- When `<image stem>.expected.yaml` sits next to the image (every fixture does) it is loaded as the pseudo-tool **`expected`**, so each tool is also diffed against ground truth.
- `--reuse` skips running any tool whose raw output already exists and only re-normalises and re-diffs (fast iteration on the diff logic; the router run below takes ~20 s cold, <2 s reused).
- Exit code 1 if any tool *failed*; skipped tools do not fail the run.

How each tool is invoked (image directory mounted read-only, containers run as the invoking uid/gid):

| tool | command |
|---|---|
| unblob | `docker run --rm -u UID:GID -v <imgdir>:/data:ro -v <out>/unblob:/out -w /out ghcr.io/onekey-sec/unblob:latest -e /out --report /out/report.json --log /out/unblob.log -p N /data/<img>` (`-w /out` because unblob writes `unblob.log` to cwd) |
| binwalk | `binwalk -e -C <out>/binwalk -l <out>/binwalk/binwalk.json [-M] <img>` |
| moria | `docker run --rm -u UID:GID -v <imgdir>:/data:ro -v <out>/moria:/out omnitrace-parity-moria -j -e -C /out /data/<img>` (stdout is the JSON) |
| omnitrace | `omnitrace analyze <img> --out <out>/omnitrace`, then `manifest.yaml` |

### Normalisation

Each tool's raw output becomes `<out>/<tool>.normalized.json`:

```json
{"tool": "moria", "status": "ok", "version": "moria 0.2.1",
 "findings": [{"offset": 1872453, "format": "squashfs", "raw_format": "squashfs",
               "size": 11054868, "extracted": true, "root": "0x1c9245-squashfs",
               "files": [{"relpath": "bin/busybox", "size": 1, "sha256": "…", "kind": "regular", "target": ""}]}]}
```

- **Findings** are the tool's top-level results: unblob `ChunkReport`s (and `UnknownChunkReport`s as `unknown`) of the depth-0 task, binwalk's `file_map`, moria's `findings[]`, OmniTrace's Partition/Container/Filesystem children of the Image node, and for `expected` one finding per partition/volume or one at offset 0.
- **Files** of a finding are every regular file and symlink under that finding's extraction root, recursively, relative to the root (unblob: the subtask directory of the chunk id; binwalk: `extractions[id].output_directory`; moria: the `depth == 1` row of `extraction.extracted`; OmniTrace: `filesystems/<node>/files`, or the File nodes' digests when nothing was extracted). Nested extraction directories therefore appear as path prefixes and differ between tools by design.
- **Format aliases** (`FORMAT_ALIASES` in `run.py`): `squashfs_v4_le|squashfs_v4_be|squashfs_v3_*|SquashFS → squashfs`, `jffs2_new|jffs2_old|JFFS2 → jffs2`, `extfs|ext2|ext3|ext4 → ext`, `fat32|vfat → fat`, `yaffs|YAFFSv2 → yaffs2`, `cpio_* → cpio`, `lz4_* → lz4`, `sevenzip → 7z`, `elf32|elf64 → elf`, `trx_v* → trx`, … Unknown names fall back to stripping `_v<n>`, `_le`, `_be`, `_new`, `_old`, `_legacy`, `_built_in` suffixes.

### Diff

For every pair of tools that ran (`expected` included):

- **Findings** match on **exact offset**, then canonical format. Same offset but different formats is reported separately (`format_mismatch`). Everything else is `only_a` / `only_b`. Note that a container and its payload are different offsets: unblob's `lzma` at `0x50040` never matches moria's `uimage` at `0x50000`; that is a real difference in what the tools claim and is left visible.
- **Files** of a matched finding are compared by `relpath`: identical (same sha256, or for symlinks the same in-tree target after resolving `../` against the link's directory, because unblob rewrites absolute targets to relative), differing content, path only in one tool; plus **content only in one tool** (sha256 present nowhere in the other tool's file set, so a renamed-but-identical file does not count as missing).

Outputs: `report.md` (tables; lists capped at `--max-list`), `summary.json` (`schema: omnitrace-parity/1`; tool status/version/runtime/argv, `findings_union` keyed by offset, and every pair's full lists), and the per-tool `*.normalized.json`.

### Baseline: `router.bin` (16 MiB OpenWrt SPI dump, sha256 `56a97e35…`)

`tests/parity/run.py /home/wrongbaud/projects/omnitrace/firmware/router.bin` (unblob 25.11.25, binwalk 3.1.0, moria 0.2.1 @30e4038; OmniTrace skipped, CLI not built yet):

| offset | unblob | binwalk | moria |
|---:|---|---|---|
| 0x0 | unknown 327,744 B | | |
| 0x17a40 | | | uboot 24,316 B |
| 0x1d93c | | | uboot_env 126 B |
| 0x50000 | | uimage 1,544,773 B | uimage 1,544,773 B |
| 0x50040 | lzma 1,544,709 B | | |
| 0x1c9245 | squashfs_v4_le 11,054,868 B, 3154 files | squashfs, not extracted (no sasquatch) | squashfs 11,054,868 B, 3154 files |
| 0xc54159 | unknown 48,807 B | | |
| 0xc60000 | jffs2_new 3,801,088 B, 61 files | jffs2 3,735,564 B, not extracted | jffs2 3,801,088 B, 39 files (status *partial*) |

Pairwise (after symlink-target normalisation):

| pair | findings matched / mismatch / only A / only B | files identical / differ / only A / only B |
|---|---|---|
| unblob vs moria | 2 / 0 / 3 / 3 | squashfs: 3154 vs 3154, 3144 identical, 10 differ (all symlinks in `usr/lib`: unblob reports the end of the link chain, e.g. `libz.so -> libz.so.1.2.11`, moria the on-disk target `libz.so -> libz.so.1`, which `unsquashfs -lls` confirms; 33 further symlinks differ only in absolute-vs-relative target and are counted identical); jffs2: 61 vs 39, 2 common paths (`.fs_state`, one Lua file: differ), 59 paths only in unblob, 37 only in moria |
| unblob vs binwalk | 2 / 0 / 3 / 1 | binwalk extracted nothing for the matched findings |
| binwalk vs moria | 3 / 0 / 0 / 2 | binwalk's only file is the uImage payload |

Interpretation: on SquashFS the two extracting tools agree byte-for-byte. On the overlay JFFS2 they disagree completely: jefferson (unblob) emits deleted and obsolete nodes as live files (`1`, `bin/GL_*`, `mac_vendor.db`, `tertfinfo_bak`, `work/`…) and moria's reader stops early (`partial`). This is exactly the case OmniTrace's history-aware JFFS2 reader has to settle against `jffs2-history.expected.yaml`, where the ground truth is known.

### Fixture sweep

Every fixture can be run through the harness; `expected` is picked up automatically:

```
for img in tests/fixtures/out/*.img tests/fixtures/out/nested.tar.gz; do
  tests/parity/run.py "$img" --tools unblob,binwalk,moria --reuse
done
```

Observed on the current fixtures (all 18 run clean, exit 0):

- squashfs-* (all five), ext4, fat32, ubifs, and the MBR/GPT members: unblob and moria both reproduce every `expected` file byte-for-byte.
- jffs2-le/-be: moria matches; unblob (jefferson) lacks the hard link `bin/ash`. jffs2-history: moria matches the post-history tree exactly; jefferson additionally resurrects `history/deleted.txt`.
- yaffs2, yaffs2-yaffsecc: unblob matches; moria lacks the hard link `bin/ash`.
- ubi, nested.tar.gz, uimage-lzma: every file is found by both tools but under a nested extraction prefix (`ubi_extract/…`, `firmware/squashfs-gzip.img_extract/…`), so the path diff against `expected` reports them as only-in-tool; use the `content_only_*` counts (0) there.
- uimage-lzma: binwalk and moria report `uimage` at 0; unblob reports `unknown` (the 64-byte header) at 0 and `lzma` at 64.
- binwalk finds every filesystem but, without `sasquatch`/`jefferson`/`ubireader`, extracts none of them; its uImage, UBI and tar extraction is built in.

### Recovery: the image-wide metric

The pairwise diff above compares files **inside findings matched at the same
offset and format**. That is the right unit for "do these two tools agree
about this structure" and the wrong one for "what fraction of the data did
each tool recover": a container and its payload sit at different offsets by
design, and a nested extraction is a path prefix in one tool and its own
finding in another.

So `summary.json` also carries a `recovery` block, and `report.md` a
**Recovery (image-wide)** table: the set of distinct file contents each tool
produced from the image, regardless of finding or path. The headline unit is
the **sha256 of every regular file**; symlinks are counted too, in a second
figure, but are only approximately comparable between tools because a link's
target resolves against the directory it is in and each tool nests its
extractions under a prefix of its own.

Two columns exist to keep the number honest:

- **zero-fill**: of the contents only one tool has, how many are a run of
  NULs — a file whose data that tool could not reconstruct. moria writes 28 of
  those on `router.bin`'s JFFS2 overlay; counting them would penalise a tool
  for not reproducing another's failure.
- **regular vs with-symlinks**: the gap between the two is the prefix
  artifact, and it is large enough to matter (226 "missing files" on one
  router image that is 100% on regular files).

### Measuring parity (`sweep.py`)

```sh
ls tests/fixtures/out/*.img tests/fixtures/out/*.tar.gz > /var/tmp/images.txt
find corpus -maxdepth 3 -type f \( -name '*.bin' -o -name '*.BIN' \) -size -100M >> /var/tmp/images.txt

scripts/fixtures.sh sweep --list /var/tmp/images.txt --out /var/tmp/parity \
    --omnitrace build/linux-gcc/apps/cli/omnitrace
```

Writes `sweep.md` and `sweep.json`: per image, and pooled over the set, the
share of each baseline's recovered contents that OmniTrace also recovered,
plus the unweighted per-image mean, the median and every image below 95%.
A fixture's `expected.yaml` is picked up as the pseudo-tool `expected`, which
is the only one of the four that settles who is right.

Each image's extraction trees are deleted as soon as its summary is read
(`--keep` retains them) — four tools over a corpus is tens of gigabytes, and
the bytes are evidence-derived. The `*.normalized.json` files keep every path
and hash, so `--reuse` re-aggregates without re-running anything and a changed
metric does not mean a re-run.

The measured result, the method and the gaps it found are in
**`docs/PARITY.md`**.

### Adding a tool

Add `run_<name>` to `Runner` (produce raw output under `<out>/<name>/`), a pure `parse_<name>(…) -> list[Finding]` next to the others, the name to `ALL_TOOLS`, aliases to `FORMAT_ALIASES`, and a test in `test_run.py` built from a hand-written raw report and a temporary extraction tree.

---

## 3. Conformance harness (`tests/unit/filesystems/fixture_conformance_test.cpp`)

The fixtures are only useful if every reader is held to them, present and
future, without anyone remembering to write the test. The conformance harness
in `test_filesystems` does that: it instantiates one GoogleTest parameter per
`tests/fixtures/out/<name>.expected.yaml` and, for every fixture whose
`image.format` has a reader in `fs::FilesystemRegistry`, opens the image the
way `discovery::analyze` would and checks the walk against the YAML. A reader
is covered the moment its `OMNITRACE_REGISTER_FILESYSTEM` line exists; the
harness has no per-format code. Fixtures whose format has no reader are
skipped with a message naming the format, and `FixtureCoverage.Report` prints
the whole table, so the log shows what "supported" means in practice:

```
fixture conformance coverage (.../tests/fixtures/out)
  registered readers: squashfs
  ext4: format ext4: NO READER [history]
  jffs2-history: format jffs2: NO READER [history]
  squashfs-gzip: format squashfs: reader 'squashfs'
  ...
  5 of 15 reader fixtures have a reader
```

```sh
./build/linux-gcc/src/filesystems/test_filesystems --gtest_filter='Fixture*'
./build/linux-gcc/src/filesystems/test_filesystems --gtest_filter='*FixtureConformance*/jffs2_history'   # one fixture
./build/linux-asan/src/filesystems/test_filesystems --gtest_filter='Fixture*'                            # under ASan/UBSan
```

Test names carry the fixture (`Fixtures/FixtureConformance.History/jffs2_history`,
dashes become underscores), so a failure says which image and which check.
When `tests/fixtures/out` has not been built the whole suite skips.

### How a fixture is opened

`MappedFile` over the image, `discovery::scan` on the whole Span, then the
finding at offset 0 whose format matches the YAML (`ext4` matches an `ext`
reader, `fat32` a `fat` or `vfat` one: trailing digits are ignored). The
reader gets `span.sub(0, finding.size)` exactly as `Recurse::process_filesystem`
would hand it. If no validator identifies the fixture at offset 0 the test
fails (analyze() would never open it) and the reader is still run over the
whole image so its own problems are visible in the same log.

### The four checks

| Test | Sink / options | What must hold |
|---|---|---|
| `LiveTree` | `ListingSink(hash=true)`, `history=false` | Walk succeeds, is not truncated, and emits no Warning/Error diagnostic (walk-level or per entry). Every `tree` entry is present with matching kind, size (non-directories), mode (permission bits, when `features.mode`), uid/gid (when `features.owner`), mtime (exact for resolution 1, off by less than the resolution otherwise), `link_target`, sha256 and byte count for regular files; `nlink` when the reader reports one. Entries with `hardlink_of` share a non-zero inode with their target. No live entry beyond the tree except `lost+found` on ext. `WalkResult` counts equal the emitted entries by kind; nothing is flagged deleted/superseded. |
| `History` | `ListingSink(hash=true)`, `history=true` (fixtures with a `history` section) | The live tree still matches. Every `history.superseded` entry is emitted with `superseded: true`, the same path and `version`, and matching size, inode, mtime and sha256; every `history.deleted` entry with `deleted: true` under its path (or `lost+found/#<inode>` when the name is unrecoverable) and matching fields, sha256 only when `content_recoverable` is not false. Superseded entries have a non-zero version; a live entry that reports a version must report `history.current`'s. `WalkResult::superseded` / `deleted` are at least the YAML counts and equal the flagged entries. |
| `DiskSink` | `DiskSink` under a temp dir, `hash=true`, `write_versions=true`, `history` on when the YAML has it | Same tree and history checks on the returned `EntryResult`s, then on disk: every regular file's bytes hash to the expected sha256 at `<root>/<path>` with `host_path` and `written` set, directories are directories, symlinks carry the expected target; every superseded/deleted version with recoverable content is at `<root>/.omnitrace-versions/<path>/v<version>` and hashes correctly; every historical `host_path` lies under `.omnitrace-versions`; no `.omnitrace-versions` directory appears without history. |
| `Determinism` | three `ListingSink` walks: a reader walked twice, plus a fresh reader | Identical entry sequences (path, kind, mode, owner, size, every timestamp, inode, nlink, link target, rdev, flags, version, `extra`, per-entry diagnostic codes, sha256, bytes) and identical walk diagnostics. |

The reader contract these encode is `docs/ARCHITECTURE.md` rule 6 and the
history contract in `docs/EXTENDING.md` ("Add a filesystem reader"): the live
tree is what a mount shows; with `WalkOptions::history` every older version of
a file that still has a live entry is an extra entry with the same path,
`superseded = true` and `version` set, and every file without a live
directory entry is `deleted = true` with the best-known path.

### `fixture_yaml`: reading expected.yaml without yaml-cpp

`test_filesystems` links only core and discovery, and the shared CMake files
are not edited for tests, so `tests/unit/filesystems/fixture_yaml.{h,cpp}` is
a small parser for exactly the subset PyYAML `safe_dump` writes for the
fixtures: block mappings, block sequences (including the indentless form
under a key), plain / single-quoted / double-quoted scalars that may fold
across lines, `[]` and `{}`, comments and document markers. Anchors, tags,
block scalars and non-empty flow collections are rejected with a line number
rather than mis-parsed. Values stay text; `as_int()`, `as_uint()` and
`as_bool()` convert on demand (`mode: '0755'` is parsed as octal by the
harness itself). `FixtureYaml.EmbeddedSample` pins the parser on an inline
document covering every construct, `FixtureYaml.RejectsWhatItDoesNotSupport`
the error paths, and `FixtureYaml.ParsesEveryExpectedYaml` parses every
ground-truth file present (schema, name, sorted tree, 64-hex sha256s, image
size on disk, `index.yaml` agreeing with the directory).

### Checking a case directory: `check_listing.py`

The same comparison for what the CLI wrote, without the test binary
([tests/fixtures/README.md](../tests/fixtures/README.md) has the full flag
list):

```sh
tests/fixtures/check_listing.py tests/fixtures/out/jffs2-history.expected.yaml case/filesystems/n000002/listing.yaml --history
tests/fixtures/check_listing.py --cases /tmp/cases --history      # /tmp/cases/<fixture-name>/ per fixture
```

`--history` adds the superseded/deleted checks above to the live-tree check;
`--cases` prints one `PASS` / `FAIL` / `SKIP` line per fixture (MBR/GPT
fixtures are checked partition by partition against the inner fixture,
matched by the filesystem node's offset in `INFO.yaml`) and exits 1 when any
failed.

### Adding a reader or a fixture

Nothing to register on either side. A new reader appears in
`FixtureCoverage.Report` as `reader '<key>'` and its fixtures start being
checked; a new fixture (`docs/EXTENDING.md`, "Add a fixture image") is picked
up from `out/` on the next run. If a fixture's format has a reader but no
validator accepts the image, `LiveTree` fails with the list of findings the
scanner did produce.
