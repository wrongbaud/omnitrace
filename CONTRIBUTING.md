# Contributing

This guide is for anyone about to change OmniTrace: it gets you from a clean machine to a green build on Linux, macOS or Windows, tells you what a finished change looks like, and points at where the work is. After reading it you can build every preset, run one test, format and lint your change, and open a pull request that CI will accept.

## Prerequisites

The build needs CMake 3.28 or newer, Ninja, a C++20 compiler (GCC 14+, Clang 17+, MSVC 19.40+) and the libraries in the table. `cmake/Deps.cmake` finds them with `find_package`; `tomlplusplus`, RE2 (with Abseil) and GoogleTest fall back to `FetchContent` when the system does not have them, so a fresh clone builds with network access even without them.

| Library | Used for | Arch | Debian / Ubuntu |
|---|---|---|---|
| zlib | gzip, SquashFS gzip blocks, CRC32 | `zlib` | `zlib1g-dev` |
| xz (liblzma) | xz and LZMA streams | `xz` | `liblzma-dev` |
| bzip2 (libbz2) | bzip2 streams | `bzip2` | `libbz2-dev` |
| lz4 | LZ4 blocks and frames | `lz4` | `liblz4-dev` |
| zstd | zstd blocks | `zstd` | `libzstd-dev` |
| OpenSSL | MD5 / SHA-1 / SHA-256 | `openssl` | `libssl-dev` |
| yaml-cpp | reading `manifest.yaml` back, parsing rule packs | `yaml-cpp` | `libyaml-cpp-dev` |
| RE2 | the rules engine; linear-time matching so a user-supplied pattern cannot hang a scan | `re2` | `libre2-dev` |
| nlohmann-json | `scan --json`, JSON schema | `nlohmann-json` | `nlohmann-json3-dev` |
| CLI11 | the command line | `cli11` | `libcli11-dev` |
| spdlog (needs fmt >= 10) | logging | `spdlog` | `libspdlog-dev` |
| GoogleTest | unit tests | `gtest` | `libgtest-dev` |
| pkg-config | locating lz4 / zstd on distros without CMake configs | `pkgconf` | `pkg-config` |

Linux, Arch:

```sh
sudo pacman -S --needed cmake ninja gcc clang pkgconf zlib xz bzip2 lz4 zstd openssl yaml-cpp nlohmann-json cli11 spdlog gtest re2
```

Linux, Debian / Ubuntu (the same list CI installs in `.github/workflows/ci.yml`):

```sh
sudo apt-get install -y cmake ninja-build g++ clang pkg-config zlib1g-dev liblzma-dev libbz2-dev liblz4-dev libzstd-dev \
  libssl-dev libyaml-cpp-dev nlohmann-json3-dev libcli11-dev libspdlog-dev libgtest-dev libre2-dev
```

macOS: install vcpkg, set `VCPKG_ROOT`, and use the `macos-clang` preset. `vcpkg.json` is the manifest; the preset points CMake at `$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake` and vcpkg builds every dependency on the first configure.

```sh
git clone https://github.com/microsoft/vcpkg ~/vcpkg && ~/vcpkg/bootstrap-vcpkg.sh
export VCPKG_ROOT=~/vcpkg
cmake --preset macos-clang
```

Windows: Visual Studio 2022 with the "Desktop development with C++" workload, vcpkg with `VCPKG_ROOT` set, and the `windows-msvc` preset from a Developer PowerShell (it uses the `x64-windows-static-md` triplet). CI runs this exact path on `windows-2022`.

```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg; C:\vcpkg\bootstrap-vcpkg.bat
$env:VCPKG_ROOT = "C:\vcpkg"
cmake --preset windows-msvc
```

## Presets

`CMakePresets.json` defines one configure, build and test preset per name, so every command below takes the same `--preset`.

| Preset | Compiler / libs | Use it for |
|---|---|---|
| `linux-gcc` | g++, system packages, Release | the default day-to-day build |
| `linux-clang` | clang++, system packages, Release | catching warnings GCC does not emit |
| `linux-asan` | clang++, Debug, `-fsanitize=address,undefined` | every reader and validator change; hostile-input bugs show up here first |
| `linux-vcpkg` | vcpkg manifest on Linux | reproducing the CI dependency set locally |
| `macos-clang` | Apple clang, vcpkg | macOS |
| `windows-msvc` | MSVC x64, vcpkg static CRT | Windows |

All presets build into `build/<preset>/` and write `compile_commands.json` there; `compile_commands.json` at the repo root is a symlink to the `linux-gcc` one for clangd.

## Build and test

```sh
cmake --preset linux-gcc
cmake --build --preset linux-gcc --parallel
ctest --preset linux-gcc
```

`ctest` runs one executable per layer (`test_core`, `test_output`, `test_discovery`, `test_filesystems`). To run a single GoogleTest case, call the executable with a filter:

```sh
./build/linux-gcc/src/filesystems/test_filesystems --gtest_filter='SquashfsSynth.*'
./build/linux-gcc/src/discovery/test_discovery --gtest_filter='*Gpt*'
```

Before you push a reader or validator change, also build and test under the sanitizer preset, because a bounds bug that is silent in Release is a hard failure there:

```sh
cmake --preset linux-asan && cmake --build --preset linux-asan --parallel && ctest --preset linux-asan
```

Tests that need a synthetic image look under `tests/fixtures/out/` (`OMNITRACE_TEST_DATA_DIR` is compiled in by `cmake/Warnings.cmake:48`) and skip with a message when the image is not there. Build the fixtures once with `scripts/fixtures.sh build`; the whole harness, including the parity runs against unblob, binwalk and moria, is described in [docs/TESTING.md](docs/TESTING.md).

## Formatting and linting

`.clang-format` is `BasedOnStyle: Google` with a 4-space indent, 100 columns and left-aligned pointers. Format what you touched before committing, so diffs stay about the change:

```sh
clang-format -i src/discovery/validators/ext.cpp tests/unit/discovery/validators_test.cpp
git ls-files '*.cpp' '*.h' | xargs clang-format --dry-run --Werror   # the whole tree, no edits
```

`.clang-tidy` enables the `bugprone`, `cert`, `clang-analyzer`, `misc`, `modernize`, `performance` and `readability` groups with a few noisy checks turned off. Run it against a configured build directory:

```sh
clang-tidy -p build/linux-gcc src/core/Span.cpp
```

The documentation is checked the same way. `python3 scripts/check_docs.py` (stdlib only, no build needed) fails when `docs/reference/*.md` is stale, a validator or reader has no `docs/formats/<format>.md`, a CLI flag is missing from `docs/CLI.md`, or a relative link in `README.md` or `docs/**/*.md` is dead; `ctest` runs it through `tests/unit/discovery/docs_check_test.cpp` and CI runs it first. When it reports a missing entry, add the line to `docs/reference/diagnostics.yaml` or `attrs.yaml` and run `python3 scripts/gen_docs.py` to regenerate the reference pages:

```sh
python3 scripts/check_docs.py          # "check_docs.py: ok" or a list of what drifted
python3 scripts/gen_docs.py            # rewrite docs/reference/{DIAGNOSTICS,FORMATS,ATTRS,CLI_FLAGS}.md
```

Warnings are the compiler's job as well: `cmake/Warnings.cmake` applies `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wnon-virtual-dtor -Wold-style-cast -Wimplicit-fallthrough` (or `/W4 /permissive-` on MSVC) to every target, and `-DOMNITRACE_WERROR=ON` turns them into errors.

## How the CMake layout works

You never edit a CMake file to add a source or a test. `cmake/Warnings.cmake:22` defines `omnitrace_module(<name> DEPS ...)`; each `src/<layer>/CMakeLists.txt` calls it once, and the function globs `src/<layer>/**/*.cpp` into the static library `omnitrace_<layer>` and `tests/unit/<layer>/**/*.cpp` into `test_<layer>`. The globs use `CONFIGURE_DEPENDS`, so after adding a file you re-run the configure step (or just build; Ninja re-checks the globs) and the file is in.

```sh
touch src/discovery/validators/trx.cpp tests/unit/discovery/trx_test.cpp
cmake --build --preset linux-gcc --parallel      # "Re-checking globbed directories..." then compiles both
```

Two things do need a one-line edit, because a static library drops object files nothing references: a new validator adds a line to `src/discovery/validators/builtin.cpp`, and a new filesystem reader adds a line to `src/filesystems/Registry.cpp:15`. Signatures under `signatures/*.toml` are embedded by `src/discovery/cmake/embed_signatures.cmake` at build time; add a file or edit one and the generated translation unit is rebuilt.

The dependency direction is `apps/cli -> output, discovery, containers, images, filesystems -> core`, and `core` depends on nothing in the project; see the top of [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## The rules

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) is the contract; read it before writing code. Its fifteen rules, one line each:

1. Every evidence byte is read through `Span` (`include/omnitrace/core/Span.h:62`); no pointer arithmetic outside `src/core/`, saturating arithmetic for header values.
2. Readers never touch the host filesystem; extraction goes through `Sink` (`include/omnitrace/core/Sink.h:75`).
3. Bad input never throws; return `Status::fail` or `nullopt` and attach a `Diagnostic` with a stable kebab-case code.
4. Every cap is a `Limits` field (`include/omnitrace/core/Limits.h`) or a `Signature::extra` TOML key; a tripped guard records a warning and keeps what was recovered.
5. Output is deterministic: no clock outside `core/Clock`, no unordered containers in anything serialised, tables first then byte order, and the manifest must round-trip.
6. Capture everything the filesystem knows about an entry into `FileMeta` (`include/omnitrace/core/Node.h:70`), including history when `WalkOptions::history` is set.
7. Silence is a bug: a recognised but unprocessed format, a tripped limit, a skipped carve each become a `Coverage` row and a diagnostic.
8. POSIX-only code lives in `src/core/Source.cpp`, `Sink.cpp` and `Clock.cpp` behind `#ifdef _WIN32`, with the Win32 branch beside it.
9. Warnings are the compiler's review: every target links `omnitrace_warnings` and must build clean with `-DOMNITRACE_WERROR=ON`; use `static_cast`, never C casts.
10. Tests ship with code: a synthetic instance, a hostile instance, a real-tool round trip when the mkfs tool exists, and a fixture comparison when a fixture exists.
11. Partition tables never absorb other findings and are never absorbed by anything but another table; a table's extent is the table itself.
12. Size-0 (magic-only) findings claim nothing: they parent no node and split no gap.
13. Every evidence string goes through `sanitize_utf8` before output and every file name through `safe_filename_component`.
14. Anything registered from a static constructor (validators, readers) also defines an anchor the layer's `link_builtin_*()` calls, or the static library drops it.
15. Sources and tests are globbed per layer by `omnitrace_module()`; feature work never edits a shared CMake file.

## Definition of done

A change is done when all of the following hold. The list is what a reviewer checks, so checking it yourself first saves a round trip.

- Unit tests in `tests/unit/<layer>/` cover the happy path and hostile input (truncated header, absurd sizes, self-referencing pointers, limits tripping).
- A new format has a page `docs/formats/<name>.md`: on-disk layout, references, the diagnostic codes it emits, what history it can recover, known gaps.
- Every new diagnostic code is stable, kebab-case, listed on the format page, and has an entry in `docs/reference/diagnostics.yaml` (attrs keys in `docs/reference/attrs.yaml`); `python3 scripts/gen_docs.py` has been run so `docs/reference/*.md` matches.
- `python3 scripts/check_docs.py` prints `check_docs.py: ok` (ctest runs it too, so the discovery test fails otherwise).
- `clang-format` reports no changes on the files you touched.
- `linux-gcc`, `linux-clang` and `linux-asan` all configure, build and pass `ctest`.
- `omnitrace analyze` on a fixture still writes an `INFO.yaml` that round-trips (the CLI refuses to exit 0 otherwise).

## Commits and pull requests

Commit messages have an imperative subject line under 72 characters and a body that explains why, not what (the diff already says what). A `Co-Authored-By:` trailer is fine and is how agent-assisted commits are recorded in this repository.

```
Add TRX partition-table validator

Broadcom TRX headers carry three partition offsets and a CRC over the
payload; without a validator the magic hit stayed at tier magic and the
partitions inside were parented under the image instead of the table.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>
```

Work on a feature branch off `main` and open a pull request. `.github/workflows/ci.yml` runs `linux-gcc`, `linux-clang` and `linux-asan` on Ubuntu 24.04 plus `windows-msvc` and `macos-clang` through vcpkg; every job must be green before merge. Do not commit anything under `build/`, `tests/fixtures/out/` or `corpus/` (all are in `.gitignore`).

## Fixtures and parity

`scripts/fixtures.sh build` generates the synthetic images (SquashFS with every compressor, JFFS2 with a scripted overwrite/delete history, UBI/UBIFS, YAFFS2, ext4, FAT32, MBR, GPT, uImage, nested tar.gz) and a ground-truth `*.expected.yaml` beside each one; `scripts/fixtures.sh check` proves the build is byte-reproducible. `tests/parity/run.py IMAGE` runs unblob, binwalk, moria and the OmniTrace CLI over one image and diffs findings and files. Both are documented end to end in [docs/TESTING.md](docs/TESTING.md).

## Working with a private corpus

Real firmware images are never committed. Keep them in `corpus/` at the repo root, which `.gitignore` excludes, laid out as `corpus/<name>/flash/<image>` (the same shape `analyze` writes for a case). Tests that want a real image locate it through `OMNITRACE_SOURCE_DIR` and skip when it is absent (`tests/unit/core/swap_test.cpp:77`), so the suite passes on a clone with no corpus. `DEVELOPMENT_PLAN.md` reserves an `OMNITRACE_CORPUS` environment variable for pointing tests at a corpus outside the tree; no code reads it yet, so the in-tree `corpus/` directory is the convention today. In documentation and commit messages refer to it as "a local corpus" and never paste device identifiers, serials or paths from it.

## Where to make improvements

[docs/ROADMAP.md](docs/ROADMAP.md) lists what is supported, what comes next in order, and a "good first improvements" list with the file to start from for each. [docs/EXTENDING.md](docs/EXTENDING.md) has the step-by-step for each kind of addition, and [docs/CODE_TOUR.md](docs/CODE_TOUR.md) walks the layers.
