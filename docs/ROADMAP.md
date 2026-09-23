# Roadmap

This page is for a contributor deciding what to build next. It states what the code supports today (taken from the registries, not the plan), the order of the next work, and a list of self-contained first improvements with the file to open for each. After reading it you can pick a task, find its starting point, and know what "done" means for it. `DEVELOPMENT_PLAN.md` at the repository root is the long form; where the two differ, this page describes the code.

## What OmniTrace does today

Eight things, in the order a case moves through them. Counts come from the
registries via `scripts/gen_docs.py`, so they cannot drift from the code;
`docs/reference/FORMATS.md` is the per-format matrix and
`docs/reference/DIAGNOSTICS.md` the 450-code catalogue.

### 1. Identify — 58 signatures over 40 formats, 32 validators

A magic hit is a guess. A validator parses the structure behind it and places
the finding on a confidence ladder (magic 25, structural 60, consistent 85,
verified 99), sizes it when it can, and says why in `evidence`. A structure it
walked but could not size carries `extent: unknown` and is never handed to a
reader — an eMMC image holds hundreds of accidental magics.

**When a magic is too weak to trust, a checksum or an exhausted input is what
earns an extent.** Four formats share that rule: a GPT header whose signature
was cleared is read because its CRC32 covers the signature bytes; an
unterminated `tar` claims only the bytes whose member checksums verified; an
Android `super` map is described but claims nothing until its SHA-256 matches;
and a compressed stream the data ran out underneath is sized because it
consumed every available byte. The rule lives where both the validator and the
reader call it, or they drift.

### 2. Extract — 11 filesystem readers, 18 container formats

squashfs, ext2/3/4, jffs2, qnx6, qnx-ifs, ubifs, yaffs2, cramfs, romfs; gzip,
bzip2, xz, lzma, lz4, zstd, lzop, tar, cpio, zip, 7z, uimage, fit, ubi,
android-boot, android-vendor-boot, android-sparse, android-super. **Every
format with a signature has a reader.**

Every extracted file is re-scanned, so chains resolve to the end:
`boot.img → ramdisk → gzip → cpio → rootfs`. The router-wrt image resolves five
levels deep to the router's OpenSSL libraries.

### 3. Recover — `--history`, and partial structures

Superseded and deleted versions from ext, JFFS2, QNX6, UBIFS and YAFFS2, and
superseded logical erase blocks from UBI. Damaged structures give up what they
have rather than nothing: an archive with no end marker, a stream whose data
ran out, a GPT readable only from its backup.

### 4. Understand the bytes — entropy, word-swap

Every unidentified region is profiled (`erased`, `sparse`, `text`, `binary`,
`packed`, `random`). `random` deliberately stops short of claiming encryption:
xz output is statistically indistinguishable from AES. Word-swapped dumps are
detected and analysed through a corrected view that is written to `flash/`, so
every offset in the manifest refers to a file that exists.

### 5. Understand the system — 3 platform analyzers

Linux, QNX and Android. One report per filesystem, because an image routinely
holds several systems. Every fact is `(key, value, source)` where source is the
file it was read from, so an examiner can open it and disagree. Precedence is
by **rank, not score**: a QNX root matches five Linux markers, and counting
cannot settle which answer is more precise.

### 6. Search — 4 rule packs, 52 rules

network, credentials, pii, rtos. Compiled into one RE2 set — linear time
regardless of the pattern, because a pack is untrusted input. Runs over every
extracted file and every region no signature claimed.

### 7. Parse — 1 artifact extractor

Certificates: subject, issuer, validity, key type and length, SAN, and private
keys. A search pack can say a `-----BEGIN CERTIFICATE-----` block is present;
only a parser can say it is self-signed `CN=router` with its RSA-2048 private
key in the same file.

### 8. Report — a typed document, and an integrity gate

`report.html` and `report.md`, built as data and rendered once rather than
concatenated. Before rendering, every piece of evidence is **re-hashed** and
the result stated in the first section. A mismatch is reported, not
suppressed: every offset in a report refers to the bytes the case recorded.

`omnitrace report <case>` re-examines a finished case rather than re-rendering
the manifest: it reads every `listing.yaml` back and runs the analyzers and
the extractors again over the recovered entries. That is the decoupling in §5
and §7 being spent — those layers take entries and nothing about how the
extraction happened, so a case directory alone is enough.

### Throughout

Coverage rows state what was *not* done. 450 diagnostic codes, each catalogued
with a meaning and an action. `analyze` will not fill the disk it writes to.
867 tests across 9 suites; gcc, clang and ASan all green.

## Phases

| phase | state |
|---|---|
| 0 — Foundation | complete |
| 1 — Discovery, extraction, parity | complete **except parity, which has never been measured** |
| 2 — Recovery, artifacts, reporting | complete; exit criterion verified on both the router and the 7.8 GB auto-emmc eMMC corpora |
| 3 — Hardening and release | not started |
| 4 — Web UI | not started, and deliberately after a release (`core-before-ui`) |

**Phase 1's parity gap is worth stating plainly.** Its exit criterion is
"parity ≥ 95 % files recovered vs unblob and moria on fixtures and corpus".
The harness exists (`tests/parity/run.py`) and the Windows and macOS CI
builds do too, but no parity run is recorded anywhere in the tree. The
extraction work is done and the corpus exercises it hard; the *number* has
never been produced. Running it is a concrete task, not a formality — it is
the only external check on whether the readers miss things nobody noticed.

## Next, in order

1. **Measure parity.** Close Phase 1's open criterion with a real number
   against unblob, binwalk and moria on the fixtures and the corpus.

2. **Validate the Android analyzer against a real Android tree.** Its markers
   come from documented AOSP layout, not evidence; the automotive Android unit's `la_super`
   is the image to check them against. The QNX model *was* aimed at evidence
   and the corpus still corrected six things its fixtures could not, including
   a `Tree` bug that silently disabled its strongest marker.
   `docs/ANALYZERS.md` says which parts are guesses.

3. **More artifact extractors** (§5.5): SQLite with freelist recovery, logs
   with a normalised timeline, ELF metadata. Certificates came first because
   the corpus had 131 of them and most of the rest of §5.5 overlaps what the
   packs and analyzers already do — an extractor earns its place by *parsing*
   something, not by matching it.

4. **Phase 3**: fuzzing per reader under ASan/UBSan, a performance pass on
   large images, signed release artifacts for all three platforms.

5. **Phase 4**: web UI, only after the CLI and library are released.

## Good first improvements

Each of these is a single pull request with a clear test. The definition of done in `CONTRIBUTING.md` applies.

| Improvement | Start here | Done when |
|---|---|---|
| Add a vendor partition-table validator (Broadcom TRX, IP camera, another vendor) | copy the shape of `src/discovery/validators/mbr.cpp`, add a `[[signature]]` with `category = "partition-table"` to `signatures/core.toml`, an anchor line in `src/discovery/validators/builtin.cpp`; `src/discovery/Recurse.cpp:617` (`analyze_span`) turns any partition-table finding into nodes | a synthetic header in `tests/unit/discovery/partition_test.cpp` yields table plus entry nodes; a truncated header is rejected or downgraded with a diagnostic |
| Add a magic-only signature for a format you meet (EROFS, F2FS, BTRFS, ...) | `signatures/core.toml`; the schema is in `docs/formats/signatures.md` | `scan --json` reports it at tier `magic` on a hand-made buffer in `tests/unit/discovery/toml_test.cpp` or `scan_test.cpp` |
| Add a fixture (cramfs via `mkcramfs`, romfs via `genromfs`, ext2) | `tests/fixtures/generate.py` (`build_ext4` at line 850 is the template for a debugfs-driven image, `build_squashfs` at 370 for a mkfs-driven one), the tool into `tests/fixtures/Dockerfile` | `scripts/fixtures.sh check` still passes and the new `expected.yaml` lists the tree; the validator test picks it up through `fixture_path` in `tests/unit/discovery/helpers.h:91` |
| Add a parity tool (for example `sasquatch` or `jefferson` standalone) | `tests/parity/run.py`: `Runner` (line 216) gets `run_<name>`, a `parse_<name>` beside `parse_unblob` (433), the name in `ALL_TOOLS` (54), aliases in `FORMAT_ALIASES` (66) | a test in `tests/parity/test_run.py` built from a hand-written raw report passes |
| Improve a diagnostic message | `analyze-no-reader` at `src/discovery/Recurse.cpp:461` and `:843` could name the format and the roadmap entry; `region-unidentified` at `:570` could say whether the region is uniform fill | the message is a full sentence a non-developer can act on; the code is unchanged; `tests/unit/discovery/recurse_test.cpp` asserts on the code, not the text |
| Honour an `OMNITRACE_CORPUS` environment variable | `tests/unit/core/swap_test.cpp:77` (`corpus_path`) and `tests/unit/filesystems/squashfs_test.cpp` build the path from `OMNITRACE_SOURCE_DIR` | tests find images under `$OMNITRACE_CORPUS` first and fall back to `corpus/`; `CONTRIBUTING.md` is updated |
| Add `--json` to `analyze` stdout | `apps/cli/analyze_commands.cpp:422` (`register_analyze_commands`); `scan --json` at `:424` is the pattern | the JSON is byte-identical run to run and validated in `tests/unit/output/schema_test.cpp` |

## Not planned

FUSE mounting (not portable to Windows; extraction to disk instead), disassembly, emulation, and a network-facing server. Post-MVP ideas (carving in unallocated space, F2FS / NTFS / EROFS readers, multi-image diffing, an MCP server) are in `DEVELOPMENT_PLAN.md` under "Post-MVP tracks".
