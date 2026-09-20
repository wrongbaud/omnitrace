# OmniTrace v2

OmniTrace is an offline, cross-platform forensic analysis tool for embedded systems, written in C++20. Give it a raw SPI, NAND or eMMC dump and it hashes the evidence, maps the partitions and filesystems inside it, carves each one to its own file, extracts what it can read, and writes the whole result as a case directory that people read as Markdown and tools read as YAML.

It is for forensic examiners who receive flash dumps rather than phone extractions, embedded security researchers who want a traceable map of an image before they start digging, and agents or scripts that consume `INFO.yaml` and never look at a terminal.

**Status:** Phase 0 complete: format identification (27 validators, 52 signatures), MBR/EBR/GPT partition tables and the examiner case layout. Phase 1 in progress: SquashFS, ext2/3/4, JFFS2, QNX6 and QNX IFS filesystem readers; gzip, bzip2, xz, lzma, lz4, zstd, tar, cpio, zip, uImage, Android boot and Android sparse container readers; history recovery for ext/JFFS2/QNX6; and nested analysis, so `boot.img -> ramdisk -> gzip -> cpio -> rootfs` and `uImage -> lzma -> squashfs` are followed to the end. UBIFS, YAFFS2 and the FIT reader are next. See [docs/ROADMAP.md](docs/ROADMAP.md) and [docs/reference/FORMATS.md](docs/reference/FORMATS.md).

## Quick start

```sh
cmake --preset linux-gcc
cmake --build --preset linux-gcc --parallel
ctest --preset linux-gcc
./build/linux-gcc/apps/cli/omnitrace analyze router.bin --out case-router
less case-router/INFO.md
```

Linux presets use system packages; `CONTRIBUTING.md` lists them per distro and covers macOS and Windows through vcpkg.

`router.bin` stands for any raw dump you have; on a 16 MB OpenWrt SPI dump the run takes about a second and `INFO.md` starts like this (trimmed):

```
## Evidence

| Id | Path       | Size               | MD5      | SHA-1    | SHA-256                                                          |
|----|------------|--------------------|----------|----------|------------------------------------------------------------------|
| e1 | router.bin | 16.0 MiB (16777216)| 87243471…| 6783d6c1…| 56a97e35baf7f6fd9c40047c3a2727b35aa6af40d8eb9beb13b979b8a4e5eea9 |

## Map

- `n000001` image raw "router.bin" @ 0x0 16.0 MiB (16777216) [verified (99)]
  - `n000002` region "unidentified" @ 0x0 320.0 KiB (327680) [reject (0)]
  - `n000003` container uimage "MIPS OpenWrt Linux-4.14.63" @ 0x50000 1.5 MiB (1544773) [verified (99)]
  - `n000004` filesystem squashfs "squashfs" @ 0x1c9245 10.5 MiB (11055104) [consistent (85)]
  - `n003388` region "unidentified" @ 0xc54245 47.4 KiB (48571) [reject (0)]
  - `n003389` filesystem jffs2 "jffs2" @ 0xc60000 3.6 MiB (3735564) [verified (99)]
  - `n003390` region "unidentified" @ 0xff000c 64.0 KiB (65524) [reject (0)]

# Partitions carved

| File                             | Offset   | Size     | Kind                | SHA-256   |
|----------------------------------|----------|----------|---------------------|-----------|
| partitions/0x00050000-uimage.bin | 0x50000  | 1.5 MiB  | container/uimage    | 477f0b77… |
| partitions/0x001c9245-squashfs.bin | 0x1c9245 | 10.5 MiB | filesystem/squashfs | cd810305… |
| partitions/0x00c60000-jffs2.bin  | 0xc60000 | 3.6 MiB  | filesystem/jffs2    | 335b5a3f… |

# Coverage

| Format   | Status      | Detail                          |
|----------|-------------|---------------------------------|
| uimage   | supported   |                                 |
| squashfs | supported   |                                 |
| jffs2    | supported   |                                 |
| carve    | supported   |                                 |
```

The coverage table is the honest part: a format the scanner recognises but cannot yet extract is reported, never skipped. On this image the uImage is opened too, and its LZMA payload decompressed, so the kernel's device tree and initramfs are reachable below it.

## What you get

`analyze` writes one case directory. The image itself is never modified and never copied unless you pass `--copy-image`.

- `INFO.yaml`: the manifest (schema `omnitrace/1`): run info, evidence hashes, every node with its byte range, coverage, diagnostics. `manifest.yaml` is an alias.
- `INFO.md`: the same, rendered for people: summary, partition map, carved-partition table, coverage.
- `flash/SOURCE.yaml`: path, size, MD5/SHA-1/SHA-256 and acquisition time of the evidence.
- `partitions/<name>.bin`: one file per partition entry or nested find, hashed as it is written; `p6-system.bin` from a GPT label, `0x001c9245-squashfs.bin` for a find without a table entry.
- `partitions/mount.sh`: a loop-mount script with `PARTITION_NAMES` and `PARTITION_TYPES` filled in.
- `filesystems/<node-id>/listing.yaml`, `listing.md` and `files/`: the inventory (mode, uid/gid, timestamps, inode, digests) and the extracted tree of every filesystem with a reader.

The full contract is [docs/CASE_LAYOUT.md](docs/CASE_LAYOUT.md); the commands and flags are in [docs/CLI.md](docs/CLI.md).

## Where to go next

| You want to | Read |
|---|---|
| find any document in the project | [docs/README.md](docs/README.md) |
| build on your OS, run the tests, send a change | [CONTRIBUTING.md](CONTRIBUTING.md) |
| understand the layers and the data flow in an hour | [docs/CODE_TOUR.md](docs/CODE_TOUR.md) |
| add a validator, a reader, a signature or a CLI command | [docs/EXTENDING.md](docs/EXTENDING.md) |
| read the public headers in order or build the API reference | [docs/API.md](docs/API.md) |
| know which formats are identified, sized and extracted today | [docs/reference/FORMATS.md](docs/reference/FORMATS.md) |
| know the rules every change must follow | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| see what is next and where to start | [docs/ROADMAP.md](docs/ROADMAP.md) |

## License

Apache-2.0. See [LICENSE](LICENSE).
