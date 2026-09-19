# Roadmap

This page is for a contributor deciding what to build next. It states what the code supports today (taken from the registries, not the plan), the order of the next work, and a list of self-contained first improvements with the file to open for each. After reading it you can pick a task, find its starting point, and know what "done" means for it. `DEVELOPMENT_PLAN.md` at the repository root is the long form; where the two differ, this page describes the code.

## Current state

Phase 0 is complete. The pipeline in `src/discovery/Recurse.cpp:1203` (`analyze`) hashes the image, scans it, builds the evidence graph partition-first, walks every filesystem that has a reader, carves partitions and nested finds, generates `mount.sh`, and writes the case directory of `CASE_LAYOUT.md`. `INFO.yaml` round-trips through `output/Yaml.cpp` byte-identically, and the CLI refuses to exit 0 otherwise.

### Identification

21 validators are registered (`src/discovery/validators/builtin.cpp` lists their anchors) over 50 signatures in `signatures/core.toml` and `signatures/crypto.toml`.

| Validator (`src/discovery/validators/`) | Formats | Best tier | Sizes the find |
|---|---|---|---|
| `squashfs.cpp` | squashfs (LE, BE, `shsq`, `qshs`) | consistent | yes |
| `jffs2.cpp` | jffs2 (LE, BE) | verified | yes |
| `ubi.cpp` | ubi | verified | yes |
| `ubifs.cpp` | ubifs | verified | yes |
| `ext.cpp` | ext2 / ext3 / ext4 | verified | yes |
| `cramfs.cpp` | cramfs (both orders) | verified | yes |
| `romfs.cpp` | romfs | verified | yes |
| `mbr.cpp` | mbr (with EBR chains) | consistent | table only |
| `gpt.cpp` | gpt (512 and 4 KiB sectors, primary and backup) | verified | table only |
| `uimage.cpp` | uimage / kernel | verified | yes |
| `fit.cpp` | fit and dtb | verified / consistent | yes |
| `android_boot.cpp` | android-boot, android-vendor-boot | consistent | yes |
| `android_sparse.cpp` | android-sparse | consistent | yes |
| `gzip.cpp`, `xz.cpp`, `lz4.cpp`, `zstd.cpp` | compressed streams | structural | no |
| `elf.cpp` | elf | consistent | yes |
| `luks.cpp` | luks | consistent | yes |
| `verity.cpp` | dm-verity | consistent | yes |

Magic-only signatures (tier `magic`, size unknown, so they claim no bytes): cpio (newc, crc, odc), tar, zip, 7z, qnx6 (LE, BE), qnx-ifs, PEM certificate / request / CRL / keys, OpenSSH and PGP keys. yaffs2 has no signature yet because a useful one needs OOB-aware validation.

Word-swapped dumps are detected by `detect_word_swap` (`src/core/Swap.cpp:334`) and analysed through a `SwappedSource` view; the Image node gets `image-word-swapped`.

### Extraction

| Registry | Readers registered |
|---|---|
| `fs::FilesystemRegistry` (`src/filesystems/Registry.cpp:15`) | `squashfs` (`src/filesystems/squashfs/SquashfsReader.cpp`; gzip, xz, lzo, lz4, zstd, lzma) |
| `container::ContainerRegistry` (`src/containers/Registry.cpp`) | none |

Every other filesystem and container the scanner identifies is a `Coverage` row with status `unsupported` and an `analyze-no-reader` diagnostic (`src/discovery/Recurse.cpp:460`, `:841`). Nested recursion (re-scanning a container payload) is not implemented; the hand-off point is the comment at `src/discovery/Recurse.cpp:850`. `--history` is accepted but no registered reader records history yet.

### Test assets

18 fixture images with `expected.yaml` ground truth (`tests/fixtures/out/`, built by `tests/fixtures/generate.py`), a parity harness for unblob, binwalk, moria and OmniTrace (`tests/parity/run.py`), and unit tests per layer under `tests/unit/`.

## Next, in order

1. **ext4 reader** (`src/filesystems/ext/`). Fixture `ext4.img` already carries three freed inodes with `dtime` set and unlinked directory entries, so history can be tested from day one. Byte-identity against `debugfs` is the acceptance bar.
2. **JFFS2 reader with history** (`src/filesystems/jffs2/`). The validator already walks and CRC-checks every node (`src/discovery/validators/jffs2.cpp`); the reader replays inode and dirent versions, newest wins for the live tree, every older version becomes `superseded`, every `ino == 0` dirent a `deleted` record. Ground truth: `jffs2-history.expected.yaml`.
3. **QNX6 and QNX IFS readers**, with a sizing validator for the `qnx6` and `qnx-ifs` magics so they stop being magic-only.
4. **Container readers: FIT, gzip, xz** (`src/containers/`), registered with `OMNITRACE_REGISTER_CONTAINER` (`include/omnitrace/containers/Container.h`), and the recursion step at `src/discovery/Recurse.cpp:850` that scans a payload with `analyze_span`.
5. **UBIFS and YAFFS2 readers**, both with history (UBIFS sqnum order, YAFFS2 sequence numbers); fixtures `ubifs.img`, `ubi.img`, `yaffs2.img`, `yaffs2-yaffsecc.img` exist.
6. **Sizing validators for zip, gzip and the QNX magics**, so a zip inside a partition claims its bytes and nested finds are parented correctly.
7. **Write the corrected view of a word-swapped image** into the case directory (today only the detection is recorded; `src/discovery/Recurse.cpp:1233` is the extension point).
8. **Phase 2**: artifact extractors, YAML rule packs under `rules/`, `omnitrace report`. `DEVELOPMENT_PLAN.md` §5.4 to §7.
9. **Phase 4**: web UI, only after the CLI and library are released (decision `core-before-ui`).

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
