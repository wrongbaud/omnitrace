# Roadmap

This page is for a contributor deciding what to build next. It states what the code supports today (taken from the registries, not the plan), the order of the next work, and a list of self-contained first improvements with the file to open for each. After reading it you can pick a task, find its starting point, and know what "done" means for it. `DEVELOPMENT_PLAN.md` at the repository root is the long form; where the two differ, this page describes the code.

## Current state

Phase 0 is complete. The pipeline in `src/discovery/Recurse.cpp:1203` (`analyze`) hashes the image, scans it, builds the evidence graph partition-first, walks every filesystem that has a reader, carves partitions and nested finds, generates `mount.sh`, and writes the case directory of `CASE_LAYOUT.md`. `INFO.yaml` round-trips through `output/Yaml.cpp` byte-identically, and the CLI refuses to exit 0 otherwise.

### Identification and extraction

`docs/reference/FORMATS.md` is the matrix, per format id: whether a hit is
magic-only or validated and to which tier, whether its extent is known, whether
a reader extracts it, whether history is recovered, and how `partitions/mount.sh`
treats it. It is generated from `signatures/*.toml`, the validators and the
reader registries by `scripts/gen_docs.py` and checked by `scripts/check_docs.py`,
so it cannot drift from the code the way a table written here would.

Today that is 55 signatures over 39 format ids, 31 validators, 9 filesystem
readers (`squashfs`, `ext2`/`ext3`/`ext4`, `jffs2`, `qnx6`, `qnx-ifs`,
`ubifs`, `yaffs2`) and 17 container formats read by 11 readers: `gzip`,
`bzip2`, `xz`, `lzma`, `lz4` and `zstd` (one `StreamReader`), `lzop`, `tar`,
`cpio`, `zip`, `7z`, `uimage`, `fit`, `ubi`, `android-boot` and
`android-vendor-boot` (one reader), and `android-sparse`. **Every *container*
format with a signature has a reader.** Two filesystems do not: `cramfs` and
`romfs` validate to `verified` and then have nothing to walk them, which the
full-corpus run caught -- the audio image holds a real romfs that comes out as
an `unsupported` coverage row with no extracted tree. `--history` is recovered
by the ext, JFFS2, QNX6, UBIFS and YAFFS2 readers, and by the UBI reader for
superseded logical erase blocks.

Nested analysis runs for extracted files: every file a walk writes to the host
is re-scanned, and one holding a filesystem or a partition table at Structural
or better and at least `min_region_bytes` long is analysed again with the File node as its parent
(`descend_into_file` in `src/discovery/Recurse.cpp`), bounded by
`Limits::max_depth`. A container payload is walked into
`containers/<node-id>/files` by `process_container` and then re-scanned the
same way, so a `.tar.gz` holding a filesystem is followed to the end. Every
container format with a signature has a reader now, so the `unsupported`
Coverage row and its `analyze-no-reader` diagnostic are for a format that is
identified but has none -- which today means `cramfs` and `romfs`.

Every stream format says what its payload is worth. `compress::stream_check`
reads the check a gzip, zlib, bzip2, xz, lz4 or zstd stream records over
itself, and because each library verifies that check while decoding, the
`StreamReader` entry carries `checksum` = `ok`, `mismatch`, `none` or
`unchecked` the way `LzopReader`'s does. A stream that decoded whole and then
failed its own check is still sized, read and emitted, flagged
`compressed-stream-checksum-mismatch` and `container-checksum-mismatch`:
the router-wrt image has one, a damaged 1 MB gzip holding a tar that was previously
reported only as an unmeasured magic. `docs/formats/compressed-streams.md`
has the per-format table and the two limits.

Every unidentified region says what its bytes look like: `omnitrace::entropy`
(`src/core/Entropy.h`) profiles it in sampled windows and the node carries
`entropy`, `entropy_chi2` and `entropy_class` (erased, sparse, text, binary,
packed, random), with `region-high-entropy` on the two high classes. It is
what turns "no signature matched" into something actionable -- the two IP camera
images that yield nothing are one 8 MB region at 7.955 bits/byte and chi2/df
1.2, uniform and magic-free end to end. `random` deliberately stops short of
claiming encryption: xz output is statistically indistinguishable from AES
(`docs/formats/entropy.md` has the measurements).

Word-swapped dumps are detected by `detect_word_swap` (`src/core/Swap.cpp:334`)
and analysed through a `SwappedSource` view; the Image node gets
`image-word-swapped`, and the view the analysis actually read is written to
`flash/<stem>-swap32.bin` with its own hashes in `flash/SOURCE.yaml`. Without
that file every offset in the manifest, and every carved partition, would
describe bytes that exist on no disk anywhere.

### Test assets

18 fixture images with `expected.yaml` ground truth (`tests/fixtures/out/`, built by `tests/fixtures/generate.py`), a parity harness for unblob, binwalk, moria and OmniTrace (`tests/parity/run.py`), and unit tests per layer under `tests/unit/`.

## Next, in order

Items 1-4 of the original list are done: the ext4, JFFS2, QNX6 and QNX IFS
readers, and both halves of the container work (readers plus the payload
recursion). See the section above.

1. **Walk an archive that has no end marker but real members.** A damaged
   `tar` reports `tar-no-end-marker`, keeps `extent: unknown` and is therefore
   never handed to its reader, so the members it *did* parse are lost. The
   Router-wrt image has one inside a CRC-failed gzip: two members, 998331 bytes,
   none extracted. The `extent: unknown` rule is right in general; the
   question is whether a reader that counted members should be allowed to
   emit them over the bytes it accounted for.
2. **Phase 2**: artifact extractors, YAML rule packs under `rules/`,
   `omnitrace report`. `DEVELOPMENT_PLAN.md` §5.4 to §7.
3. **Phase 4**: web UI, only after the CLI and library are released (decision
   `core-before-ui`).

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
