# Format pages

This index is for anyone who needs to know how OmniTrace handles one format
and for contributors adding a validator or reader. After reading it you can
find the page for any format id that appears in `omnitrace scan` output or
`INFO.yaml`, see at a glance which formats have a reader, and know what a new
page must contain. The generated matrix in
[`../reference/FORMATS.md`](../reference/FORMATS.md) is the machine-checked
version of the middle column; this page is the human entry point.

## How discovery works

[`signatures.md`](signatures.md) explains the pipeline every page below
plugs into: TOML signatures, the multi-pattern scanner, the validator
contract, the confidence tiers (`magic` 25, `structural` 60, `consistent` 85,
`verified` 99) and deterministic conflict resolution.
[`word-swap.md`](word-swap.md) covers the byte-reversed dumps some flash
readers produce, which is handled before any signature runs.
[`entropy.md`](entropy.md) covers what happens after every signature has run
and matched nothing: what an unidentified region's bytes look like
statistically, and why "high entropy" is a lead rather than proof of
encryption.

## Pages

| page | format ids | validator | reader | extraction |
|---|---|---|---|---|
| [squashfs.md](squashfs.md) | `squashfs` | `squashfs` (consistent) | `SquashfsReader` | yes: files, metadata, xattr counts |
| [jffs2.md](jffs2.md) | `jffs2` | `jffs2` (verified) | none | no; `mount.sh` mtdram comment |
| [ubifs.md](ubifs.md) | `ubifs` | `ubifs` (verified) | none | no; `mount.sh` nandsim comment |
| [ubi.md](ubi.md) | `ubi` | `ubi` (verified) | none | no; volumes not rebuilt |
| [ext.md](ext.md) | `ext`, reported as `ext2` / `ext3` / `ext4` | `ext` (verified) | none | no; `mount.sh` type `ext4` |
| [fat.md](fat.md) | `fat`, reported as `fat12` / `fat16` / `fat32` | `fat` (consistent) | `FatReader` | yes: files, long names, deleted entries with `--history` |
| [cramfs.md](cramfs.md) | `cramfs` | `cramfs` (verified) | none | no; `mount.sh` type `cramfs` |
| [romfs.md](romfs.md) | `romfs` | `romfs` (verified) | none | no; `mount.sh` type `romfs` |
| [partition-tables.md](partition-tables.md) | `mbr`, `gpt` | `mbr` (consistent), `gpt` (verified) | n.a. | entries carved to `partitions/` |
| [uimage.md](uimage.md) | `uimage` | `uimage` (verified) | none | no; carved |
| [fit.md](fit.md) | `fit` | `fit` (verified) | none | no; images listed in attrs |
| [dtb.md](dtb.md) | `dtb` | `dtb` (consistent) | n.a. | model / compatible in attrs |
| [android-boot.md](android-boot.md) | `android-boot`, `android-vendor-boot` | `android-boot` (consistent) | none | no; sections in attrs |
| [android-sparse.md](android-sparse.md) | `android-sparse` | `android-sparse` (consistent) | none | no; not expanded |
| [android-super.md](android-super.md) | `android-super` | `android_super` (verified on the map SHA-256) | none | yes; one entry per logical partition |
| [compressed-streams.md](compressed-streams.md) | `gzip`, `xz`, `lz4`, `zstd` | one each (structural) | none | no; size unknown |
| [elf.md](elf.md) | `elf` | `elf` (consistent) | n.a. | arch / type in attrs |
| [luks.md](luks.md) | `luks` | `luks` (consistent) | n.a. | header fields only |
| [verity.md](verity.md) | `dm-verity` | `verity` (consistent) | n.a. | hash-tree extent only |
| [qnx6.md](qnx6.md) | `qnx6` | `qnx6` (verified) | `Qnx6Reader` | yes: files, metadata, snapshot history |
| [qnx-ifs.md](qnx-ifs.md) | `qnx-ifs` | `qnx-ifs` (verified) | `QnxIfsReader` | yes: files, metadata; zlib/lzo/ucl/lz4 blocks decompressed |

Plain magics without a validator (`tar`, `zip`, `7z`, `cpio`,
PEM / OpenSSH / PGP key blocks) are listed in
[`signatures.md`](signatures.md); they stay at the `magic` tier with an
unknown size. `yaffs2` has no signature yet.

Everything with "none" under reader is a Phase 1 item in
`DEVELOPMENT_PLAN.md`; the plan's tables describe intent, the pages here
describe what the code does today.

## Writing a page

`docs/ARCHITECTURE.md` (step 4 of "Adding a filesystem reader") and
`scripts/check_docs.py` require a page per validator and per reader. One page
may cover several format ids when they share a validator or a family
(`partition-tables.md`, `compressed-streams.md`); register the alias in
`DOC_ALIASES` in `scripts/gen_docs.py` so the check knows. Use
[squashfs.md](squashfs.md) as the model for a reader page and
[jffs2.md](jffs2.md) for a validator-only page. Each page has, in order:

1. one paragraph naming the reader, validator, signatures and what the page
   lets the reader do;
2. the on-disk layout the code actually reads (a field table with offsets);
3. what the validator checks per tier, and how the size is computed;
4. what the reader captures (`FileMeta`, `FilesystemInfo`), if there is one;
5. attributes, one line each, matching `docs/reference/attrs.yaml`;
6. diagnostics, a table of code / severity / meaning, matching
   `docs/reference/diagnostics.yaml`;
7. history: what superseded / deleted data the format keeps and whether the
   reader recovers it;
8. what is verified on (fixtures under `tests/fixtures/out`, a local corpus);
9. not yet supported / known gaps;
10. references: the specification or kernel source read for understanding,
    and the reference tool used by the tests.

Keep every code, attr key, path and line reference real: `scripts/check_docs.py`
runs in CI and in `ctest` (`tests/unit/discovery/docs_check_test.cpp`).
