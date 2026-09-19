# OmniTrace v2

Open-source, offline, cross-platform forensic analysis for embedded systems. Feed it a raw SPI/eMMC/NAND dump, an MTD partition, or a firmware update package and get back a traceable evidence graph: image, partition, filesystem, file (including deleted and superseded versions), byte range, artifact, report.

Status: Phase 0 (foundation). See `DEVELOPMENT_PLAN.md`, `docs/ARCHITECTURE.md`, `docs/COMPETITIVE_LANDSCAPE.md`, `docs/MORIA_SPIKE.md`.

## Build

```
cmake --preset linux-gcc        # or linux-clang, linux-asan, windows-msvc, macos-clang
cmake --build --preset linux-gcc --parallel
ctest --preset linux-gcc
./build/linux-gcc/apps/cli/omnitrace --help
```

Linux presets use system packages (zlib, xz, lz4, zstd, openssl, yaml-cpp, nlohmann-json, CLI11, spdlog, gtest). The `windows-msvc`, `macos-clang` and `linux-vcpkg` presets use vcpkg manifest mode and need `VCPKG_ROOT` set.

## Layout

```
include/omnitrace/   public headers (the contracts)
src/core             Source, Span, Hash, Node, Manifest, Sink, Clock, Compression
src/discovery        signatures (TOML), scanner, validators, conflict resolution
src/containers       tar, zip, cpio, gzip/xz/lz4/zstd, uImage, FIT, sparse, boot
src/images           partition tables, UBI, NAND OOB, vendor layouts
src/filesystems      squashfs, jffs2, ubifs, yaffs2, ext, fat, qnx6, qnxifs, cramfs, romfs
src/output           YAML manifest, Markdown renderers, JSON schema
apps/cli             the omnitrace binary
signatures/          *.toml signature sets, embedded at build time
tests/unit/<layer>   GoogleTest, globbed per layer
tests/fixtures       synthetic image generator (Docker) with known deleted/overwritten files
tests/parity         diff harness vs unblob, binwalk, moria
```

License: Apache-2.0.
