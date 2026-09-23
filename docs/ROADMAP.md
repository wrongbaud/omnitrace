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
| 1 — Discovery, extraction, parity | **complete** — parity measured and met against both baselines (`docs/PARITY.md`) |
| 2 — Recovery, artifacts, reporting | complete; exit criterion verified on both the router and the 7.8 GB auto-emmc eMMC corpora |
| 3 — Hardening and release | not started |
| 4 — Web UI | not started, and deliberately after a release (`core-before-ui`) |

**Phase 1's parity criterion is measured and met**, over all 35 images — 20
fixtures and the whole 15-image corpus, up to a 15.7 GB eMMC — counting
distinct regular-file contents by sha256:

| baseline | pooled | verdict |
|---|---:|---|
| moria 0.2.1 | **99.9 %** | met — 31 of 32 images at or above 95 % |
| unblob 26.6.4 | **99.5 %** | met — 65.7 % when first measured, see below |
| ground truth (`expected.yaml`) | **100.0 %** | every file of every fixture, 179 of 179 |

It did exactly what it was supposed to do: it found real gaps nobody had
noticed, and the largest is now closed. **SquashFS v1–v3 was detected but
never sized**, so the router-wrt image's v3 Broadcom filesystem was seen at the
right offset, carried `extent: unknown`, was never handed to a reader, and
3,903 contents went with it — 72 % of the whole unblob shortfall. Reading
v1–v3 took that image from 0.1 % to 98.8 % and the pooled figure from 65.7 %
to 95.1 %.

**FAT was not identified at all** — no signature, so `fat32.img` extracted
nothing, and it was the *entire* difference from ground truth. FAT12/16/32 are
now identified, sized and read, with deleted-file recovery under `--history`,
and the fixture set is exact.

**`ar` static libraries were not opened**, worth 1,224 contents on the auto-ivi
eMMC; they are now read, with the GNU and BSD long-name dialects resolved, and
that image went from 93.4 % to 99.8 % of unblob.

The last open question — whether to carve a structure found inside a payload
the way unblob does — is **decided and done**. One corpus dongle's xz payload
is 222 complete ARM shared objects that were located, sized and typed but had
no digests at all, so they could not be matched against a known-file set; they
are now carved. That image went from 16.8 % to 91.6 % of unblob.
`docs/PARITY.md` has the method, the numbers and the evidence.

Every corpus image is in that number. The 7.8 GB auto-emmc eMMC is 99.7 % of
unblob and 100.0 % of moria, the 7.8 GB audio 98.4 % and 100.0 %, the 3.8 GB
Auto-ivi 99.8 % and 100.0 %. The 15.7 GB QNX unit scores 50 % of unblob, which
is the one figure not to read as a score: neither baseline reads QNX6 or
QNX-IFS, so OmniTrace recovers **23,833** contents there against unblob's 8
and moria's 11, and "50 %" is four of eight (`docs/PARITY.md` §7).

## Next, in order

1. **Decompress the streams inside a QNX filesystem that the baselines do.**
   The only piece of named work the finished measurement leaves: three gzip
   payloads and one LZMA payload that unblob and moria decompress out of the
   middle of the QNX unit's filesystems, which OmniTrace extracts the files of
   but does not decompress (`docs/PARITY.md` §7). Everything else in the
   difference is a recorded policy choice or a history fixture that is already
   100 % of ground truth.

2. **Finish the parity measurement** on the two remaining multi-gigabyte
   corpus images, `qnx` (15.7 GB) and `audio` (7.8 GB). Four tools over that
   much evidence needs a disk budget and a long wall clock; everything else is
   measured.

3. **Validate the Android analyzer against a real Android tree.** Its markers
   come from documented AOSP layout, not evidence; the automotive Android unit's `la_super`
   is the image to check them against. The QNX model *was* aimed at evidence
   and the corpus still corrected six things its fixtures could not, including
   a `Tree` bug that silently disabled its strongest marker.
   `docs/ANALYZERS.md` says which parts are guesses.

4. **More artifact extractors** (§5.5): SQLite with freelist recovery, logs
   with a normalised timeline, ELF metadata. Certificates came first because
   the corpus had 131 of them and most of the rest of §5.5 overlaps what the
   packs and analyzers already do — an extractor earns its place by *parsing*
   something, not by matching it.

5. **Phase 3**: fuzzing per reader under ASan/UBSan, a performance pass on
   large images, signed release artifacts for all three platforms.

6. **Phase 4**: web UI, only after the CLI and library are released.

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
