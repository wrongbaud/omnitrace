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

Today that is 54 signatures over 38 format ids, 29 validators, 9 filesystem
readers (`squashfs`, `ext2`/`ext3`/`ext4`, `jffs2`, `qnx6`, `qnx-ifs`,
`ubifs`, `yaffs2`) and 15 container formats read by 9 readers: `gzip`, `bzip2`, `xz`,
`lzma`, `lz4` and `zstd` (one `StreamReader`), `tar`, `cpio`, `zip`,
`uimage`, `fit`, `ubi`, `android-boot` and `android-vendor-boot` (one
reader), and `android-sparse`. `--history` is recovered by the ext, JFFS2,
QNX6, UBIFS and YAFFS2 readers, and by the UBI reader for superseded logical
erase blocks.

Nested analysis runs for extracted files: every file a walk writes to the host
is re-scanned, and one holding a filesystem or a partition table at Structural
or better and at least `min_region_bytes` long is analysed again with the File node as its parent
(`descend_into_file` in `src/discovery/Recurse.cpp`), bounded by
`Limits::max_depth`. A container payload is walked into
`containers/<node-id>/files` by `process_container` and then re-scanned the
same way, so a `.tar.gz` holding a filesystem is followed to the end. A
container whose format has no registered reader (`7z` is the only one left) is
a Coverage row with status `unsupported` and an `analyze-no-reader`
diagnostic.

Word-swapped dumps are detected by `detect_word_swap` (`src/core/Swap.cpp:334`)
and analysed through a `SwappedSource` view; the Image node gets
`image-word-swapped`.

### Test assets

18 fixture images with `expected.yaml` ground truth (`tests/fixtures/out/`, built by `tests/fixtures/generate.py`), a parity harness for unblob, binwalk, moria and OmniTrace (`tests/parity/run.py`), and unit tests per layer under `tests/unit/`.

## Next, in order

Items 1-4 of the original list are done: the ext4, JFFS2, QNX6 and QNX IFS
readers, and both halves of the container work (readers plus the payload
recursion). See the section above.

1. **The lzop file format** (`89 4c 5a 4f 00 0d 0a 1a 0a`), the last
   compressed format with no signature. It needs no new dependency -- the
   in-tree LZO1X decoder already serves SquashFS and JFFS2 -- but it is a
   multi-block container rather than a single-payload stream, so it is shaped
   like `CpioReader` rather than `StreamReader`.
2. **The `7z` container reader**, the last container format with a signature
   and no reader.
3. **Verify a stream against its own checksum.** Every compressed format here
   carries one (gzip CRC32, xz check, lz4 and zstd content checksums) and none
   is compared against the decoded payload, so `verified` is unreachable for
   all five. The decode already happens; only the comparison is missing.
4. **Write the corrected view of a word-swapped image** into the case directory
   (today only the detection is recorded; `src/discovery/Recurse.cpp`
   `ImageViewHook` is the extension point).
5. **Phase 2**: artifact extractors, YAML rule packs under `rules/`,
   `omnitrace report`. `DEVELOPMENT_PLAN.md` §5.4 to §7.
6. **Phase 4**: web UI, only after the CLI and library are released (decision
   `core-before-ui`).

## Good first improvements

Each of these is a single pull request with a clear test. The definition of done in `CONTRIBUTING.md` applies.

| Improvement | Start here | Done when |
|---|---|---|
| Add a vendor partition-table validator (Broadcom TRX, IP camera, another vendor) | copy the shape of `src/discovery/validators/mbr.cpp`, add a `[[signature]]` with `category = "partition-table"` to `signatures/core.toml`, an anchor line in `src/discovery/validators/builtin.cpp`; `src/discovery/Recurse.cpp:617` (`analyze_span`) turns any partition-table finding into nodes | a synthetic header in `tests/unit/discovery/partition_test.cpp` yields table plus entry nodes; a truncated header is rejected or downgraded with a diagnostic |
| Add a magic-only signature for a format you meet (EROFS, F2FS, BTRFS, ...) | `signatures/core.toml`; the schema is in `docs/formats/signatures.md` | `scan --json` reports it at tier `magic` on a hand-made buffer in `tests/unit/discovery/toml_test.cpp` or `scan_test.cpp` |
| Give gzip a size: walk the deflate stream with zlib and report the end | `src/discovery/validators/gzip.cpp` (returns size 0 today); `src/core/Compression.cpp` has the inflate helpers | tier rises to `consistent` on `tests/fixtures/out/nested.tar.gz` and a truncated stream reports `gzip-truncated` |
| Give zip a size from the end-of-central-directory record | new `src/discovery/validators/zip.cpp`; register the name in the `zip` signature in `signatures/core.toml` | a zip built in the test is sized; a zip with a bad central-directory offset is downgraded |
| Add a fixture (cramfs via `mkcramfs`, romfs via `genromfs`, ext2) | `tests/fixtures/generate.py` (`build_ext4` at line 850 is the template for a debugfs-driven image, `build_squashfs` at 370 for a mkfs-driven one), the tool into `tests/fixtures/Dockerfile` | `scripts/fixtures.sh check` still passes and the new `expected.yaml` lists the tree; the validator test picks it up through `fixture_path` in `tests/unit/discovery/helpers.h:91` |
| Add a parity tool (for example `sasquatch` or `jefferson` standalone) | `tests/parity/run.py`: `Runner` (line 216) gets `run_<name>`, a `parse_<name>` beside `parse_unblob` (433), the name in `ALL_TOOLS` (54), aliases in `FORMAT_ALIASES` (66) | a test in `tests/parity/test_run.py` built from a hand-written raw report passes |
| Improve a diagnostic message | `analyze-no-reader` at `src/discovery/Recurse.cpp:461` and `:843` could name the format and the roadmap entry; `region-unidentified` at `:570` could say whether the region is uniform fill | the message is a full sentence a non-developer can act on; the code is unchanged; `tests/unit/discovery/recurse_test.cpp` asserts on the code, not the text |
| Honour an `OMNITRACE_CORPUS` environment variable | `tests/unit/core/swap_test.cpp:77` (`corpus_path`) and `tests/unit/filesystems/squashfs_test.cpp` build the path from `OMNITRACE_SOURCE_DIR` | tests find images under `$OMNITRACE_CORPUS` first and fall back to `corpus/`; `CONTRIBUTING.md` is updated |
| Add `--json` to `analyze` stdout | `apps/cli/analyze_commands.cpp:422` (`register_analyze_commands`); `scan --json` at `:424` is the pattern | the JSON is byte-identical run to run and validated in `tests/unit/output/schema_test.cpp` |

## Not planned

FUSE mounting (not portable to Windows; extraction to disk instead), disassembly, emulation, and a network-facing server. Post-MVP ideas (carving in unallocated space, F2FS / NTFS / EROFS readers, multi-image diffing, an MCP server) are in `DEVELOPMENT_PLAN.md` under "Post-MVP tracks".
