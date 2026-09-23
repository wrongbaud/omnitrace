# OmniTrace v2 — Full-Stack Development Plan

Status: draft v0.1, 2026-09-19
Scope source: `CLAUDE.md` in this directory
Prior art: `/home/wrongbaud/projects/omnitrace` (v1, Python/FastAPI/React) and `/home/wrongbaud/projects/omnisonde` (report generation, UI design system)

---

## 1. Product decision

OmniTrace v2 is an **open-source, offline, cross-platform embedded-systems forensic suite**. An examiner drops in a raw SPI/eMMC/NAND dump, an MTD partition, or a firmware update package, and gets back a traceable evidence graph: image → partition → filesystem → file → byte range → artifact → finding → report.

What changes from v1:

| | v1 (2026, Python) | v2 (this plan) |
|---|---|---|
| Core | Python worker, shells out to unblob/binwalk/pytsk3 | **C++20 library** with native parsers; external tools optional, never required |
| Distribution | Docker Compose, uv, Node | **Single static binary** per OS (Linux/Windows/macOS) that bundles CLI, HTTP API, and web UI |
| Outputs | Postgres/SQLite + React UI | **Markdown + YAML manifests on disk are the primary output**; SQLite index and UI are views over them |
| Deleted-file recovery | pytsk3 on ext/FAT only | Native for log-structured flash FS (JFFS2/UBIFS/YAFFS) where obsolete nodes are the whole game, plus libtsk for ext/FAT |
| Identity/auth | OIDC, orgs, entitlements, licensing | **Cut.** Local single-examiner tool. Loopback bind. Case-level integrity only |
| Reports | Typed doc model → self-contained HTML | Same model **ported to C++ as a standalone library** (`omnireport`) with C and Python bindings so OmniSonde can adopt it |

### MVP outcome

An examiner can, from the CLI or the local web UI:

1. Ingest an image (raw flash, eMMC, MTD, tar/zip/firmware package) and get MD5/SHA-1/SHA-256 recorded before anything else touches it.
2. See a partition/format map (offsets, sizes, types, confidence) and recursively extracted filesystems.
3. Browse and extract files, including **deleted and superseded versions** where the filesystem makes them recoverable.
4. Run built-in and user-supplied YAML search packs (MACs, logs, connection history, PII, credentials, certificates).
5. Produce a self-contained HTML/Markdown report with hashes, tool versions, coverage limits, and examiner notes.

### Explicit non-goals for the MVP

- Emulation, dynamic analysis, vulnerability scanning, SBOM generation (EMBA/FACT/FirmAE territory).
- Multi-user, auth, cloud deployment.
- Native PDF rendering (print-to-PDF via CSS is sufficient; revisit after MVP).
- Chip-level acquisition. OmniTrace starts at the dump file. Hardware acquisition stays in OmniFlash/OmniSonde.

---

## 2. Competitive landscape

See `docs/COMPETITIVE_LANDSCAPE.md` for the full survey with URLs, status, and per-tool gap analysis. Summary:

| Tool | Lang / license | Extraction | Flash FS | Hashing / CoC | Deleted recovery | Artifact search | Reports | Cross-platform | Status (2026-09) |
|---|---|---|---|---|---|---|---|---|---|
| binwalk 3 | Rust / MIT | Yes | Sq, UBI, JFFS2, YAFFS via ext. tools | No | No | No | No | L/M/W | v3.1.0 (2024), stalled |
| unblob | Py+Rust / MIT | Yes, 83 formats | Sq, UBI, JFFS2, YAFFS, QNX bits | No | No | No | JSON | L/M | 26.6.4, very active |
| moria + mithril | C++20 / MIT | Yes, in-process | Sq, UBI, JFFS2, YAFFS, EROFS, F2FS, ext, FAT; QNX IFS WIP | No | No | secrets only | JSON | L/M (W unverified) | v0.2.1, published 2026-09-08 |
| FACT | Py / GPL-3 | Yes | via unpackers | file hashes | No | crypto, strings, CVE | web | Linux server only | v4.4.1 |
| EMBA | Bash / GPL-3 | wraps unblob/binwalk | via unblob | No | No | creds, CVE, SBOM | HTML | Linux only | v2.0.3 |
| OFRAK | Py / source-available | Yes | Sq, JFFS2, UBI, ext | No | No | No | GUI | L/M/W | 3.3.0 |
| Sleuth Kit / Autopsy | C, Java / IPL-CPL | No | YAFFS2, ext4 only | Yes | Yes | keyword | Yes | W/L/M | 4.15 / 4.23 |
| UBIFT | Py / MIT | No | UBIFS | No | Yes (UBIFS) | No | Autopsy module | L | dormant since 2024 |
| qnxprobe | Py / MIT | partitions | QNX6/4/ETFS/EFS/IFS, F2FS, ext, FAT, NTFS | self-test | NTFS/FAT/F2FS | No | manifest | W/M/L | v1.29, very active |
| VLEAPP / ALEAPP | Py / MIT | No | n/a | No | No | vehicle & Android artifacts | HTML/TSV | W/M/L | active |
| bulk_extractor | C++ | No | n/a | No | carve | PII (email, URL, phone) | histograms | W/M/L | 2.2.0 |
| plaso | Py / Apache | No | ext/FAT/NTFS | No | No | timeline | Yes | W/M/L | 20260720 |
| Berla iVe, AXIOM, Cellebrite, Oxygen, XRY | commercial | limited | none of the flash FSes | Yes | some | Yes | Yes | Windows | active |

**Direct competitors:** none does the whole pipeline. The nearest are **moria/mithril** (same language and single-binary philosophy, no forensic layer, two weeks old), **FACT** (web UI plus hashing, but Linux-server, GPL, vuln-oriented) and **qnxprobe** (forensic provenance plus infotainment filesystems, but Python with no recursive container unpacking or rules). Commercial suites own the courtroom side but cannot open SquashFS/UBIFS/JFFS2/QNX6 natively; Berla owns infotainment but is closed and vehicle-model bound.

**White space OmniTrace v2 owns:**
1. Recursive firmware extraction plus chain of custody (image and per-file hashes, provenance manifest) plus examiner reports, in one open-source tool.
2. Deleted and superseded file recovery across flash filesystems (JFFS2 obsolete nodes, UBIFS journal, YAFFS2 chunk history, QNX6 old superblock) in one engine. Today only UBIFT (dormant) and TSK (YAFFS2/ext4) cover fragments of this.
3. Raw NAND dumps (OOB/ECC stripping, bad blocks) as a first-class input.
4. Evidence-oriented artifact hunting with user-supplied YAML rules and YAML/Markdown output for agents.
5. Cross-platform single binary with a local web UI.
6. OS-aware analyzers (Linux, Android, QNX, RTOS) mapping filesystems to evidence categories.

**Reuse, wrap, or port:** unblob (optional subprocess plugin for vendor container long tail), moria (design reference and parity baseline only, never a dependency; see §13 and `docs/MORIA_SPIKE.md`), libtsk (ext/FAT/YAFFS2 recovery), UBIFT (port UBIFS recovery), qnxmount/qnxprobe/dumpifs (QNX references), bulk_extractor (C++ scanner design), fwanalyzer/firmwalker (seed rules), VLEAPP/ALEAPP (artifact catalogue), plaso (timeline export). GPL-3 code (FACT, EMBA, sasquatch) is reference-only under Apache-2.0.

---

## 3. Architecture

### 3.1 Process model

One binary, three entry modes:

```
omnitrace analyze <image> --out <case-dir>      # batch: writes case-dir/{manifest.yaml, *.md, extracted/}
omnitrace serve   [--case <case-dir>] [--port]  # local HTTP API + embedded web UI on 127.0.0.1
omnitrace report  <case-dir> --format html|md   # regenerate report from manifests
```

Long-running analysis in `serve` mode runs on a worker thread pool inside the same process. Job state is persisted to the case directory so a crash/restart resumes from the last completed stage. This directly addresses v1's stated primary blocker (job lifecycle: no lease heartbeat, unconsumed cancellation, non-idempotent reclaim).

### 3.2 Layering

```
┌──────────────────────────────────────────────────────────────┐
│  apps/                                                        │
│    cli/          CLI11 front end                              │
│    server/       cpp-httplib REST + static UI (embedded)      │
│    web/          React + TS + Vite (built assets embedded)    │
├──────────────────────────────────────────────────────────────┤
│  libomnitrace/   (the product)                                │
│    core/         Evidence graph, Span, Hash, Case, Manifest   │
│    images/       Raw flash, MTD, eMMC/GPT/MBR, sparse, pkgs   │
│    containers/   tar, zip, cpio, gzip/xz/lz4/zstd/lzma, ar    │
│    filesystems/  SquashFS, UBIFS, JFFS2, YAFFS2, ext*, FAT,   │
│                  QNX6, QNX IFS, cramfs, romfs                 │
│    discovery/    Signature scan, validation, carving, entropy │
│    analyzers/    Linux, Android, QNX, RTOS platform models    │
│    artifacts/    Network, users, certs, logs, DBs, execs      │
│    rules/        YAML search packs, regex/glob engine         │
│    recovery/     Deleted/superseded file reconstruction       │
│    output/       YAML + Markdown manifest writers             │
├──────────────────────────────────────────────────────────────┤
│  omnireport/     Standalone typed-document → HTML/MD renderer │
│                  (C++ lib + C ABI + pybind11)                  │
├──────────────────────────────────────────────────────────────┤
│  third_party via vcpkg manifest                               │
│    zlib, liblzma, lz4, zstd, libarchive, sqlite3, openssl     │
│    libmagic, yaml-cpp, nlohmann-json, re2, spdlog, CLI11,     │
│    cpp-httplib, Catch2, sleuthkit (libtsk)                    │
└──────────────────────────────────────────────────────────────┘
```

Rules that keep this honest:

- `libomnitrace` never touches the network, never spawns a shell, and never calls the wall clock outside `core/Clock` (injectable for deterministic tests).
- Every parser works on a `Span` (offset + length over a memory-mapped `Source`), never on a file path. Nested extraction is a graph of Spans, so a file inside a SquashFS inside a UBI volume inside a raw NAND dump has a full provenance chain back to byte offsets in the original image.
- External tools (unblob, binwalk, dumpifs, qnxmount) are **optional plugins** invoked via a subprocess adapter with explicit argv, recorded in the manifest with version and exit status. They are never required for a supported format and their absence is reported as a coverage limit, not silently skipped (carried forward from v1).

### 3.3 Cross-platform strategy

| Concern | Decision |
|---|---|
| Build | CMake ≥ 3.28 presets + Ninja; vcpkg manifest mode for all deps; static CRT on Windows, static libstdc++ on Linux |
| Compilers | GCC 14+, Clang 17+, MSVC 19.40+. C++20, no modules yet |
| File I/O | `std::filesystem` + a thin `MappedFile` wrapper (mmap / MapViewOfFile). Large images (>4 GiB eMMC) are windowed, not fully mapped |
| Paths inside images | Always stored as UTF-8 forward-slash strings; never used to touch the host FS without normalization (zip-slip / `..` / absolute / symlink escape checks) |
| Hashing | OpenSSL EVP (MD5, SHA-1, SHA-256) — vcpkg builds it on all three OSes |
| Regex | RE2 (linear time, safe on hostile input). PCRE2 optional for lookbehind packs later |
| FUSE mounting | Not in MVP (not portable to Windows). Extraction to disk instead |
| CI | GitHub Actions matrix: ubuntu-24.04, windows-2022, macos-14 (arm64) + macos-13 (x64). Release job produces signed-hash tarballs/zips |

### 3.4 Web stack (deferred: core capabilities first, UI in Phase 4)

- **Server:** cpp-httplib (header-only, TLS off, bind `127.0.0.1` by default). JSON via nlohmann. Server-Sent Events for job progress. Static assets embedded with CMake `file(EMBED)`-style generated object (cmrc).
- **Frontend:** React 19 + TypeScript + Vite. Hard rule from v1's post-mortem: **no file over 400 lines**, one component per file, feature folders. State via TanStack Query against the REST API. No Redux.
- **Design system:** the `ui-layout` skill (Industrial Split-Panel: 120 px text nav | content viewer | 30 % tabbed sidebar; brass/crimson/phosphor on near-black; Rajdhani + JetBrains Mono; viewport-locked with `min-height:0` chain; dashed-outline empty states; overlay settings not modals). Light-mode token set from `omnisonde/templates/index.html` is included. **One palette across app, report, and docs** — v1 shipped three.
- **Dev loop:** `vite dev` proxies `/api` to `omnitrace serve --dev`. Production build is embedded; no Node at runtime.

### 3.5 Data model (core/)

```
Case            id, created, examiner, notes[], evidence[]
Evidence        id, path, size, md5/sha1/sha256, acquired_at, source_note
Node            id, parent, kind(Image|Partition|Container|Filesystem|File|Region|Artifact)
                span{source_id, offset, length}, name, format, confidence, warnings[]
FileEntry       node + mode/uid/gid/mtime/ctime/atime, is_deleted, is_superseded,
                version_index, inode/ino, link_target, hashes
Artifact        node + category, rule_id, matched_text, context, location(FileEntry+offset)
Finding         id, artifact_ids[], severity, examiner_disposition, note
Coverage        format, status(supported|partial|unsupported|tool_missing), detail
ToolRecord      name, version, argv, exit, duration
```

All of the above serialize 1:1 to the YAML manifest (§6). SQLite (`case.db`) is a rebuildable index for the UI: FTS5 over file paths and artifact text, plus keyset-paginated file trees (v1 streamed 427 k entries; v2 must handle 1 M+).

---

## 4. Repository shape

```
omnitrace-v2/
├── CMakeLists.txt, CMakePresets.json, vcpkg.json
├── cmake/                      toolchain helpers, embed-assets, warnings
├── include/omnitrace/          public headers (mirrors src/)
├── src/
│   ├── core/  images/  containers/  filesystems/  discovery/
│   ├── analyzers/  artifacts/  rules/  recovery/  output/
├── omnireport/                 separate CMake target + its own tests + python/
├── apps/cli/  apps/server/  apps/web/
├── rules/                      built-in YAML packs (linux, android, qnx, pii, network, credentials)
├── tests/
│   ├── unit/                   Catch2, one file per parser
│   ├── fixtures/               generated by tests/fixtures/build.sh (see §9)
│   ├── corpus/                 optional real-firmware tests, skipped if OMNITRACE_CORPUS unset
│   └── parity/                 harness that diffs our extraction vs unblob/binwalk in Docker
├── docs/                       mkdocs-material; COMPETITIVE_LANDSCAPE.md; format notes per FS
├── plugins/                    external-tool adapters (unblob, binwalk, dumpifs, qnxmount)
└── scripts/                    release, fixture generation, corpus runner
```

---

## 5. Evidence and analysis pipeline

Every stage reads Nodes, emits Nodes, and appends to the manifest. Stages are idempotent and keyed by (node id, stage name, parser version) so re-runs skip done work.

### 5.1 Ingest
- Copy or reference evidence (config choice); hash with three algorithms in a single pass; record size, mtime, examiner note.
- Detect **container first** (tar/zip/7z/ar/cpio/gz/xz/bz2/lz4/zstd) via libarchive + own magic. Unpack recursively into `extracted/` with path normalization and a depth/size/entry budget (zip-bomb guard).

### 5.2 Discovery (raw images)
- **Structured headers first:** MBR/EBR, GPT, Android sparse (`0xED26FF3A`), Android boot images (v0–v4; reuse `android-boot-extract` skill logic), U-Boot legacy/FIT (with DTB parsing to find partitions), MTD/UBI (EC/VID headers → volumes), vendor tables (IP camera, Ubiquiti, Broadcom TRX, another vendor, uImage chains), eMMC boot partitions (boot0/boot1/RPMB regions when present in the dump).
- **Signature scan second:** a compact rule set (SquashFS `hsqs`/`sqsh`/`shsq`, JFFS2 `0x1985`, UBI `UBI#`/`UBI!`, YAFFS OOB patterns, ext superblock `0xEF53` at +0x438, FAT BPB, cramfs, romfs, QNX6 `0x68191122`, QNX IFS startup header, LZMA/XZ/gzip streams, x509 DER, SSH keys). Each hit is **validated** by parsing the header and computing a plausible end offset before it becomes a Node. This is what distinguishes unblob-style accuracy from binwalk-style noise; the parity harness (§9) measures it.
- **Entropy + unmapped regions:** anything not claimed becomes a `Region` node (high-entropy → likely encrypted/compressed; zero/FF → erased). Regions feed the carver in Phase 2.
- **NAND specifics:** detect OOB/spare-area interleaving (page + spare sizes 2048+64, 4096+128/224, etc.) by scanning for repeating ECC patterns; offer a "strip OOB" derived Source. Bad-block markers recorded.

### 5.3 Filesystems (native readers)

| FS | Read | Deleted/superseded recovery | Reference implementation to port from |
|---|---|---|---|
| SquashFS 4 (gzip/xz/lzo/lz4/zstd/lzma) | MVP | N/A (read-only image) but detect **multiple SquashFS in one partition** (old A/B updates) | squashfuse (BSD-2, C) |
| JFFS2 | MVP | **Yes** — walk all inode/dirent nodes, keep every version; obsolete nodes = prior file contents and deleted dirents | jefferson (Python), Linux `fs/jffs2` |
| UBI / UBIFS | MVP | **Yes** — UBIFS journal + old LEB copies; UBI old-version PEBs | ubi_reader (Python), Linux `fs/ubifs` |
| YAFFS2 | MVP | **Yes** — object headers with sequence numbers; unlinked/deleted directories | yaffs2utils, yaffshiv |
| ext2/3/4 | MVP | Via libtsk (orphan inodes, unallocated dirents) | Sleuth Kit |
| FAT12/16/32, exFAT | MVP | Via libtsk | Sleuth Kit |
| QNX6 | Phase 1b | Superblock ping-pong gives a **second older snapshot** for free | qnxmount (Python) |
| QNX IFS | Phase 1b | N/A | dumpifs (C), `ifs-extraction` skill |
| cramfs, romfs | Phase 1b | N/A | Linux fs/ |
| F2FS, NTFS, HFS+ | Post-MVP | libtsk | — |

The recovery column is the product's forensic edge: log-structured flash filesystems retain history by design, and no mainstream forensic suite surfaces it. Each recovered version is a `FileEntry` with `is_superseded`/`is_deleted` and `version_index`, so the UI can show "this `wpa_supplicant.conf` had 4 prior versions; here is the diff".

### 5.4 Analyzers (platform models)
Detect platform from filesystem evidence and produce a `Platform` summary:
- **Linux:** `/etc/os-release`, busybox version, init system, kernel version from uImage/vmlinux strings, `/etc/passwd|shadow`, `/etc/network`, systemd units, `/var/log`, `/etc/wpa_supplicant`, `/etc/dropbear`.
- **Android:** `build.prop`, `packages.xml`, `/data/system/users`, `/data/misc/wifi`, `/data/data/*/databases`, Bluetooth `bt_config.conf`, boot image metadata.
- **QNX:** `/etc/system/config`, `.boot`, IFS startup scripts, `dmtree/`, PPS objects, qconn/telnet configs. Seeds from the `infotainment-forensics` skill.
- **RTOS/bare-metal:** no filesystem; string tables, version banners, embedded certs, MAC OUIs, URL/IP literals, FreeRTOS/Zephyr/ThreadX signatures.

### 5.5 Artifact extractors
Each is a small C++ class with `bool applies(FileEntry)` + `vector<Artifact> extract(...)`:
- **Network:** interfaces, hosts, resolv.conf, wpa_supplicant (SSID/PSK), NetworkManager profiles, `dhcp.leases`, iptables saves, hostapd; MAC addresses anywhere (with OUI lookup table baked in).
- **Users:** passwd/shadow/group, `authorized_keys`, `known_hosts`, sudoers, Android `accounts.db`.
- **Certificates & keys:** PEM/DER/PKCS#12/JKS scanning across all files and raw regions; parsed subject/issuer/validity/SAN via OpenSSL.
- **Logs:** syslog/journald/logcat/dmesg/QNX slog; timestamp normalization into a per-case timeline.
- **Databases:** SQLite discovery (including deleted rows in freelist pages), schema dump, table previews; targeted parsers for known schemas (Bluetooth pairings, call logs, nav history, Wi-Fi).
- **Executables:** ELF/PE/QNX arch + stripped flag + linked libs + notable strings (URLs, IPs, credentials); no disassembly.
- **PII:** emails, phone numbers (E.164 + national), VINs (with check digit), GPS coordinates, names from contacts DBs.
- **Connection history:** paired BT devices, Wi-Fi networks seen/joined, USB device tables, cellular IMSI/IMEI.

### 5.6 Search rules (user-extensible)
YAML pack format, importable via CLI/UI, editable in UI, exported back to YAML:

```yaml
pack: automotive-basics
version: 1
rules:
  - id: vin
    category: pii
    kind: regex            # regex | literal | glob-path | hex
    pattern: '\b[A-HJ-NPR-Z0-9]{17}\b'
    validate: vin-checksum # optional built-in post-filter
    severity: medium
    scope: [files, regions]  # search extracted files, unallocated regions, or both
  - id: shadow-file
    kind: glob-path
    pattern: '**/etc/shadow'
    severity: high
  - id: aws-key
    kind: regex
    pattern: 'AKIA[0-9A-Z]{16}'
```

Engine: RE2 set-matching over memory-mapped file contents and regions, with a size budget and binary/text heuristics. Hits carry file, offset, ±80 byte context, rule id/version.

---

## 6. Output contract (the Phase 1 deliverable)

The case directory is the API. It follows the examiner's extraction template (decided 2026-09-19): the original image stays untouched, every partition and every nested find is carved to its own file, a mount script is generated, and an INFO pair describes the image for people and agents.

```
case-dir/
├── INFO.yaml               # the manifest: run info, evidence hashes, the whole Node graph, coverage, tools, diagnostics
├── INFO.md                 # summary, partition map, carved-partition table, coverage, diagnostics (rendered from INFO.yaml)
├── flash/SOURCE.yaml       # path, size, MD5/SHA-1/SHA-256, acquisition time of the original (image copied only with --copy-image)
├── partitions/
│   ├── p6-system.bin       # GPT entry: "p<index>-<label>.bin"; MBR entry: "p<index>.bin"
│   ├── 0x03100000-squashfs.bin   # nested find with no table entry: "0x<offset,8 hex>-<format>.bin"
│   └── mount.sh            # examiner template with PARTITION_NAMES / PARTITION_TYPES filled in
├── filesystems/<node-id>/
│   ├── listing.yaml        # every FileEntry incl. deleted/superseded, with hashes
│   ├── listing.md
│   └── files/              # extracted tree (superseded versions in .omnitrace-versions/)
├── artifacts.yaml, artifacts.md     # Phase 2
├── findings.yaml                    # examiner dispositions (Phase 2)
├── timeline.csv                     # Phase 2
├── report/index.html                # Phase 2
└── manifest.yaml, summary.md, partitions.md   # compatibility names for INFO.yaml / INFO.md sections
```

Rules: carving streams and hashes; a partition above `--max-carve-bytes` (default 4 GiB) is skipped with a Coverage row and a node diagnostic, never silently. Names pass through `safe_filename_component`. Partition tables are sized to the table itself and never absorb the findings inside them; a missing primary GPT is recovered from the backup header with a `gpt-primary-missing` diagnostic. Word-swapped dumps are detected and analysed through a derived view, with `image-word-swapped` recorded on the image node.

Manifest schema versioned (`schema: omnitrace/1`), JSON-Schema published in `docs/schema/`, validated in CI. Markdown files are generated from the YAML by `output/`, never hand-edited.

## 7. Reporting (`omnireport`)

Port v1's `src/omnitrace/reporting/{model,render}.py` to C++:

- Typed document model: `Meta`, `Section`, `Paragraph`, `Callout`, `Table`, `KeyValueRows`, `CodeBlock`, `SpanMap`, `Figure(base64)`.
- Renderers: self-contained HTML (inline CSS with the brass design tokens + light print stylesheet), Markdown, and later JSON. Deterministic output: same document → byte-identical file. Every string escaped.
- Integrity: report embeds evidence hashes, re-hashed at generation time; mismatch aborts with an explicit error (v1's `ReportIntegrityError` gate).
- Packaging: C++ library with C ABI (`omnireport.h`), pybind11 module, and a tiny CLI (`omnireport render doc.yaml`). OmniSonde migrates from its pandoc/eisvogel pipeline to this (the pipeline was already rejected in v1 for provenance, escaping, and toolchain reasons; OmniSonde's own audit files agree).

---

## 8. Web experience (deferred to Phase 4)

Until then the CLI plus the case directory (§6) is the whole product, and every capability below must work without a UI. Screens (each a feature folder in `apps/web/src/features/`):

1. **Cases** — create/open a case directory; evidence list with hashes.
2. **Map** — partition/format map as a horizontal span bar (offset ruler, colored by type, hover = header details); click drills into the node tree.
3. **Files** — virtualized tree + table (path, size, mtime, hashes, deleted/superseded badge); preview pane (hex/text/SQLite/cert/image); "versions" drawer for superseded entries with diff.
4. **Search** — pack manager (import YAML, edit rules, run), hit list with context, disposition buttons (relevant / not relevant / needs review).
5. **Artifacts** — per-category tabs (Network, Users, Certs, Logs, Databases, Executables, PII), each a table + detail sidebar.
6. **Timeline** — merged log/mtime timeline with filters.
7. **Report** — section toggles, examiner notes editor, generate, open.

Right sidebar is context-sensitive (node details, coverage warnings, job progress via SSE). Keyboard-first: `j/k` navigation, `/` search, `?` help overlay — matching OmniSonde conventions.

---

## 9. Testing and parity

- **Unit:** one Catch2 file per parser; header-level golden tests; fuzz targets (libFuzzer) for every filesystem reader, run nightly under ASan/UBSan.
- **Synthetic fixtures (public, reproducible):** `tests/fixtures/build.sh` generates images with `mksquashfs`, `mkfs.jffs2`, `mkfs.ubifs`+`ubinize`, `mkyaffs2image`, `mkfs.ext4`+`debugfs`, `mkfs.vfat`, then **writes, overwrites, and deletes known files** so recovery tests have ground truth. Wraps them in MBR/GPT/UBI/tar/zip layers. Committed as a Docker build so Windows/macOS CI can fetch prebuilt fixtures. v1 lacked this and its corpus tests were unrunnable outside one machine — fix that first.
- **Parity harness:** `tests/parity/` runs unblob and binwalk (Docker) over the same fixtures and real corpus and diffs (files found, byte-exact content, offsets) against OmniTrace. Report as a table in CI; regressions fail.
- **Real corpus:** local-only, `OMNITRACE_CORPUS=/path` (existing uconnect5, rh850, emmc, snk-android material). Results recorded as coverage snapshots, not asserted byte-for-byte.
- **Performance targets (MVP):** 8 GiB eMMC dump: discovery < 60 s, full extraction + hashing < 10 min on a laptop, peak RSS < 1 GiB. 1 M file entries browsable at 60 fps in the UI.
- **E2E:** Playwright against `omnitrace serve` with fixture cases.

---

## 10. Security and forensic integrity

- Loopback bind default; `--bind 0.0.0.0` requires an explicit flag and prints a warning.
- No `system()`/shell; subprocess adapters use argv arrays and inherit no env beyond PATH.
- Archive/file extraction: reject absolute paths, `..`, symlink escapes, device nodes; cap depth, count, and total bytes; write with `O_EXCL`.
- Every parser fuzzed; all size math via checked helpers (`core/Checked.h`).
- Read-only evidence: original image opened read-only; extracted copies get hashes; report embeds `ToolRecord`s and OmniTrace's own version + git SHA.
- Append-only `audit.log` in the case dir (examiner actions, dispositions, report generations) — hash-chained, no auth layer.

---

## 11. Delivery roadmap

> **Status, 2026-09-23.** Phases 0-2 are done; `docs/ROADMAP.md` describes what
> the code supports today and is generated against the registries, so where
> this section and that page differ, that page is right. Two corrections this
> plan earned by contact with evidence:
>
> * **§7's port path is wrong.** v1's `src/omnitrace/reporting/{model,render}.py`
>   does not exist. What OmniSonde has is `analysis/report_generator.py`, which
>   builds Markdown by concatenation and shells out to pandoc in a container --
>   the pipeline §7 itself says to replace. `src/report/` is therefore not a
>   port but what this section describes, built fresh: a typed Document,
>   rendered once, depending on `core` alone so it can still be lifted out as
>   `omnireport`.
> * **§5.5's list mostly already existed by the time it was reached.** The
>   rules packs cover MACs, SSIDs and PSKs, IPs, URLs and PII; the analyzers
>   cover passwd, shadow, group and network configuration. An artifact
>   extractor earns its place by *parsing* something a pattern cannot reach,
>   which is why certificates came first and SQLite, logs and ELF metadata are
>   what remain.
>
> Phase 1's parity criterion (≥ 95 % vs unblob and moria) has **never been
> measured**. The harness exists and the extraction work is done; the number
> does not. It is listed as a task in `docs/ROADMAP.md` rather than quietly
> treated as met.


Weeks are estimates for one primary developer with agent assistance. Each phase ends with a tagged release and a CI-green matrix. **Core first: Phases 0 to 3 are CLI and library only. The web UI is Phase 4.**

### Phase 0 — Foundation (2 weeks)
- Repo skeleton (§4), CMake presets, vcpkg manifest, CI matrix (Linux/Windows/macOS), clang-tidy/format, sanitizer builds.
- `core/`: Source/Span/MappedFile (POSIX + Win32), hashing, Node graph, YAML/Markdown writers, manifest schema v1.
- `Sink` interface carrying full metadata (mode, uid/gid, mtime/ctime/atime, inode, link target, deleted/superseded/version). `DiskSink` hashes while writing with the openat/O_NOFOLLOW safe-path walk; `ListingSink` lists without extracting.
- `discovery/`: signature-set format (TOML), multi-pattern scanner, validator interface, confidence tiers, conflict resolution, diagnostics codes.
- `tests/fixtures/build.sh` + Docker image: SquashFS, JFFS2, UBIFS, YAFFS2, ext4, FAT images with a scripted create/overwrite/delete history so recovery tests have ground truth.
- `tests/parity/`: runs unblob, binwalk and moria over fixtures and corpus, diffs file sets and bytes against ours.
- Exit: `omnitrace scan router.bin` reports uboot, uImage, SquashFS and JFFS2 at the offsets moria and unblob report; `manifest.yaml` validates against the schema.

### Phase 1 — Discovery, extraction, parity (6 weeks)
- 1a (3 wk): containers (tar/zip/cpio/gzip/xz/lz4/zstd via libarchive + own stream detection); MBR/EBR/GPT, Android sparse/boot, uImage/FIT, UBI volume rebuild; SquashFS (gzip/xz/lzo/lz4/zstd/lzma), JFFS2, UBIFS, YAFFS2 readers; ext/FAT via libtsk. Acceptance per reader: byte-identical to the reference tool on fixtures and corpus, timestamps and ownership preserved in the listing.
- 1b (2 wk): QNX6 + QNX IFS readers (port from qnxmount/dumpifs behaviour; the `qnx-extraction-tooling` skill documents known-good invocations); cramfs/romfs; NAND OOB/ECC stripping source layer; vendor partition tables (TRX, IP camera, another vendor); eMMC boot0/boot1/RPMB regions.
- 1c (1 wk): parity pass; fix the top gaps; `docs/formats/*.md` per reader with references and the diagnostics it can emit.
- Exit: parity ≥ 95 % files recovered vs unblob and moria on fixtures and corpus; all §6 outputs populated from the CLI; Windows and macOS binaries in CI artifacts.

### Phase 2 — Recovery, artifacts, reporting (6 weeks)
- 2a (2 wk): history mode for JFFS2/UBIFS/YAFFS2 (every (inode, version) as a superseded entry, every unlink dirent as a deletion record, QNX6 old-superblock snapshot); libtsk orphan recovery for ext/FAT; `.omnitrace-versions/` layout; `timeline.csv`. Validated against the router JFFS2 census (248 deleted inodes, 239 multi-version files).
- 2b (2 wk): rules engine (RE2) + built-in packs (network, users, credentials, certs, PII, automotive); artifact extractors (§5.5); platform analyzers (§5.4); `artifacts.yaml/md`.
- 2c (2 wk): `omnireport` library + HTML/MD renderers + integrity gate; `omnitrace report`; pybind11 wheel; OmniSonde adoption spike.
- Exit: end-to-end on the eMMC and router corpora produces a report an examiner would hand over; every unsupported thing appears as a Coverage entry.

### Phase 3 — Hardening and CLI release (3 weeks)
- Fuzzing campaign (libFuzzer target per reader under ASan/UBSan), performance pass on 8 GiB images (peak RSS target < 1 GiB; moria measured 1.46 GB extracting 3.7 GB, so windowed mapping matters), Windows path/Unicode edge cases, macOS notarization, signed release artifacts, docs site, `--json` output, plugin adapter docs (unblob, binwalk, moria, dumpifs).
- Exit: v2.0.0 CLI on GitHub Releases for all three OSes.

### Phase 4 — Web UI (after core is released; 4 weeks)
- cpp-httplib server embedded in the binary, SSE job progress, React + TS + Vite front end with the `ui-layout` design system (§3.4, §8). Everything the UI shows comes from the case directory and `case.db`, so nothing in Phases 0 to 3 changes.

### Post-MVP tracks
- Carving in unallocated regions (bulk_extractor-style scanners), F2FS/NTFS/EROFS readers, encrypted-partition detection with key-search hints, FUSE mount on Linux/macOS, native PDF, case archive export/import, multi-image diffing (A/B slots, before/after update), RTOS memory-layout analyzers, MCP server exposing the case API to agents.

---

## 12. Immediate backlog (first two weeks, in order)

1. `git init`, Apache-2.0 license, `CMakeLists.txt`, `vcpkg.json`, `CMakePresets.json` with `linux-gcc`, `linux-clang`, `windows-msvc`, `macos-clang`.
2. `core/`: `Source`, `Span`, `MappedFile` (POSIX + Win32), `Hasher`, `Node`, `Manifest` + YAML round-trip test.
3. `Sink` interface + `DiskSink` (safe-path walk, hashing) + `ListingSink`.
4. `output/`: Markdown table writer, YAML emitter; JSON-Schema for `manifest.yaml`.
5. `discovery/`: TOML signature loader, scanner, validator registry, confidence tiers; the ten MVP magics with validators for SquashFS, JFFS2, UBI, ext, MBR/GPT, uImage.
6. `filesystems/squashfs/` reader with gzip/xz/lz4/zstd (first real reader; establishes the pattern); acceptance test: byte-identical to unsquashfs on `router.bin`.
7. `tests/fixtures/build.sh` generating SquashFS + JFFS2 + UBIFS + YAFFS2 + ext4 images with a documented create/overwrite/delete script; Docker image so CI on Windows/macOS can fetch prebuilt fixtures.
8. `tests/parity/` harness invoking unblob (Docker), binwalk, and moria (built from source in a container) and diffing against ours.
9. CLI `analyze` end-to-end on fixtures and `router.bin`.
10. GitHub Actions matrix green on all three OSes.

---

## 13. Open decisions

- **moria as extraction core: RESOLVED 2026-09-19, own implementation.** Owner decision: OmniTrace writes its own readers; moria is a design reference and a parity baseline in `tests/parity/`, never a dependency and never vendored. The spike (`docs/MORIA_SPIKE.md`) still stands as the acceptance bar: byte-identical to unsquashfs/debugfs, JFFS2 newest-version-wins correctness, 3.7 GB eMMC mapped in seconds. Gaps moria has that we avoid from the start: sink drops metadata, newest-version-only, POSIX-only file layer, listing requires extraction.
- **libtsk via vcpkg** builds cleanly on Linux/macOS; Windows MSVC build needs verification in Phase 0. Fallback: implement ext4 natively (moderate effort) and defer FAT.
- **React vs. a lighter framework:** React is kept for velocity and v1 code reuse, with the 400-line file rule enforced by ESLint. If bundle size or embed complexity bites, Preact is a drop-in.
- **Python bindings for `libomnitrace`** (not just `omnireport`): desirable for agent workflows; scheduled after Phase 2 unless Phase 1 shows the CLI + YAML contract is insufficient.
