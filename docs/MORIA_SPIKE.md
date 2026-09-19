# moria spike: extraction core for OmniTrace v2

Date: 2026-09-19. Ran on Linux x86-64 (GCC 16.2, CMake 4.4). Windows and macOS builds were not attempted here; moria's own CI covers linux-x64, linux-arm64 and macos-arm64, and there is no Windows job.

Repo: https://github.com/nmatt0/moria at commit `30e4038` (v0.2.1 plus 2026-09-19 UBIFS orphan-recovery merge). MIT. 78 commits since 2026-09-06, 67 by the author, six other contributors.

## Decision

**Implement OmniTrace's own extraction engine, using moria as a design reference and parity baseline. Do not vendor or fork it.** (Owner decision, 2026-09-19.)

What that means in practice:

- moria stays a build-time optional external tool for the parity harness only, like unblob and binwalk. It is never a dependency of `libomnitrace`.
- Its source is read for understanding on-disk formats, edge cases and guard rails, then our readers are written independently against our own `Span`/`Source`/`Sink` model. No source is copied; format handling is a clean reimplementation. Where a moria design choice is adopted (confidence tiers, TOML signature sets, openat-based safe writer), `docs/formats/*.md` cites it.
- The spike's correctness results are the acceptance bar: our SquashFS and ext4 readers must be byte-identical to unsquashfs and debugfs, and our JFFS2 reader must reproduce the newest-version-wins results moria got right where jefferson was wrong.
- Phase 1a keeps its original three-week estimate. What the spike bought is a verified reference implementation and a corpus of known-good answers, not a shortcut.

## What was measured

### Build

| | |
|---|---|
| Configure + build (Ninja, Release) | 9 s wall |
| Dependencies | zlib, liblzma, lz4, zstd, threads. tomlplusplus vendored. Nothing else |
| Binary | 2.9 MB, 107 translation units, ~23 k lines C++20 |
| Unit tests | 154 checks, 0 failures |
| POSIX-only files | 4: `file_map.hpp` (mmap), `extract/safepath.cpp` (openat/O_NOFOLLOW), `extract/android_sparse.cpp`, `main.cpp` |

### Identification on the local corpus

| Image | Size | Time | Result |
|---|---|---|---|
| router.bin (OpenWrt) | 16 MB | 0.39 s | uboot, uboot_env, uImage (MIPS, lzma), SquashFS v4 xz, JFFS2 |
| full-emmc.bin | 3.7 GB | 1.5 s | MBR + 16 ext partitions (A/B slots), entropy per partition |
| pi-image.bin | 15 GB | 0.02 s | MBR, FAT32, ext |
| 10_ext.tar | 7 MB | 0.01 s | tar |
| recovered_flash.bin | 3.3 MB | 0.10 s | uboot_env, uboot (binwalk: CRC table only) |
| test.bin, spi-image.bin, bank0.bin, vip_firmware_flat.bin | 0.25–16 MB | <0.8 s | nothing (binwalk also nothing; these are bare-metal/RTOS images) |

Peak RSS: 793 MB identifying the 3.7 GB image (mmap-resident pages), 1.46 GB extracting it.

### Extraction correctness

| Filesystem | Reference | Result |
|---|---|---|
| SquashFS v4 xz (router) | `unsquashfs` 4.x | **byte-identical**: 2,716 files, 438 symlinks, 0 diffs. Mode bits preserved (`etc/shadow` 0600). Absolute symlink targets preserved (unblob/sasquatch rewrites them to relative) |
| ext4 (eMMC p6, 512 MB) | `debugfs rdump` | **byte-identical**: 3,557 files, 668 symlinks, 0 content diffs |
| JFFS2 (router, 3.6 MB) | unblob 26.6.4 / jefferson | moria 37 files, jefferson 58. Both disagreements resolved **in moria's favour** by independent reassembly: `network.lua` in moria matches newest-version-wins kernel semantics, jefferson's copy does not; `upper/etc/` (dropbear, wireless, uci-defaults) is live in the dirent log and jefferson omitted it. jefferson's 21 extra entries are orphaned inodes from deleted directories emitted without provenance |
| Nested (uImage → lzma → kernel, ext → tar.gz members) | | recursed automatically, manifest records offset, type, status, counts, depth |

Timing: router.bin full extraction 10.4 s (moria) vs 3.9 s (unblob in Docker) vs 0.1 s (binwalk 3, which extracted one file because sasquatch/jefferson are not installed). moria's SquashFS path is single-threaded; parallel block decompression is an easy win later.

### Gaps found (things our implementation avoids from the start)

1. **No library boundary.** Recursion and orchestration live in `main.cpp` (`extract_findings`, `descend`, ~200 lines). Extractors have the signature `bool(const Reader&, const Finding&, SafeRoot&, subdir, Extracted&)` and write files directly.
2. **`SafeRoot::write_file(rel, bytes, mode)` drops metadata.** No uid/gid, no mtime/ctime/atime, no inode number, no xattrs. Extracted `etc/passwd` carries today's timestamp. For forensics every FileEntry needs these in the manifest regardless of what lands on the host filesystem.
3. **Newest-version-only.** JFFS2 `scan_nodes` parses every inode and dirent node, then keeps only the highest version and discards unlink dirents. UBIFS picks highest sqnum per LEB and per key (it does recover unreachable inodes into `lost+found`). YAFFS2 same pattern. The router's JFFS2 partition has 330 inodes with data, 82 live, **248 deleted with recoverable data, 381 explicit unlink records, 239 files with multi-version history**. None of that is surfaced by moria, unblob, or binwalk.
4. **No listing without extraction** for filesystems (`--list` covers tar/cpio/zip only).
5. **Precision:** a `yaffs2 structural` false positive inside WAV files on the eMMC rootfs produced eight spurious `.extracted` directories. The YAFFS2 validator needs a stronger check when the candidate is inside an already-identified regular file.
6. **Windows:** four POSIX files, no CI. Needs `MapViewOfFile` and a `CreateFileW`-based safe writer.
7. **Bus factor:** one primary author, project is eleven days old. Another reason not to depend on it.

### What we get for free

- Signature engine: TOML signature sets embedded at build time, Aho-Corasick multi-pattern scan, structural validators per format, deterministic three-pass conflict resolution, confidence tiers (magic/structural/consistent/verified) with evidence strings, diagnostics with stable codes.
- Bounds-checked `Reader` over a `span<const uint8_t>`; every parser already works on spans, which maps directly onto our `Span`/`Source` model.
- Readers for SquashFS (all codecs incl. LZO via own lzo1x), ext2/3/4, F2FS, FAT/exFAT, NTFS, HFS+, XFS, btrfs, EROFS, JFFS2, UBI/UBIFS, YAFFS2, cramfs, romfs, ISO9660, LittleFS, SPIFFS, plus containers (tar, cpio, zip, gzip/xz/lz4/zstd, uImage, FIT, Android sparse/boot, U-Boot env, ESP32 partitions/NVS, UPX, vendor formats).
- Zip-bomb and path-traversal hardening already done (`SafeRoot` uses openat + O_NOFOLLOW; depth/files/bytes/ratio guards).
- Partition tables: MBR/EBR chains (verified on the 16-partition eMMC), GPT, ESP32.
- Synthetic sample generator (`tests/gen_samples.py`) for identification tests and a differential harness against file/binwalk/unblob.

## What to take from moria (design, not code)

1. **One bounds-checked reader.** Every byte access through a `Reader` over a span returning `optional`; no raw pointer arithmetic outside it. Our `Span` gets the same rule.
2. **Signature engine shape.** Declarative TOML signature sets embedded at build time, multi-pattern scan (Aho-Corasick), a small C++ validator only where a CRC or cross-block pointer is needed, deterministic conflict resolution, and confidence tiers (magic / structural / consistent / verified) with an evidence string. Our `discovery/` adopts the shape; the signatures and validators are ours.
3. **Diagnostics with stable codes** (`yaffs2-no-oob`, `uboot-env-crc-unverified`) attached to findings. Maps straight onto our `Coverage` and `warnings[]`.
4. **Safe writer**: openat + O_NOFOLLOW component walk, refuse absolute and `..`, bounded depth/files/bytes/ratio, tripped guard stops the branch and keeps what was recovered. We add the Win32 equivalent from day one and carry full metadata in the sink call.
5. **Recursion as a graph, not directories.** moria's `0x<offset>-<type>/` layout and `manifest.json` are the right idea; ours emits Nodes with spans and provenance instead.
6. **What to do differently from the start**: the sink carries mode, uid, gid, timestamps, inode, link target and version flags; filesystem readers expose listing without extraction; log-structured readers keep every (inode, version) and every unlink record; the YAFFS2 validator requires OOB or a second consistent chunk before accepting a hit inside an already-identified file.
7. **Tests.** Mirror `gen_samples.py` (synthetic headers per format) and `diff_harness.py` (normalized verdict diff against file/binwalk/unblob/moria) in our own test tree.

## Not covered by this spike

- UBI/UBIFS and YAFFS2 extraction were not exercised on real images (none in the local corpus; `mkfs.ubifs`/`mkyaffs2image` are not installed). Build them into the fixture set in Phase 0.
- QNX6 and QNX IFS: moria has neither (issue #20 open). Our own readers, ported from qnxmount/dumpifs, stay on the Phase 1b list.
- NAND OOB stripping: moria reports `yaffs2-no-oob` diagnostics but has no OOB-aware source layer. Ours.
