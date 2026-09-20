# Extending OmniTrace

This is for a contributor who has read [CODE_TOUR.md](CODE_TOUR.md) and wants
to add something: a signature, a validator, a reader, a subcommand, a
diagnostic, a fixture, a parity tool or a Coverage row. Each recipe is a
checklist that ends with how to verify it, and every path and name in it
exists in the tree today. Keep [ARCHITECTURE.md](ARCHITECTURE.md) open; its
rules are the review checklist.

Build and test loop used throughout:

```sh
cmake --preset linux-gcc && cmake --build --preset linux-gcc --parallel && ctest --preset linux-gcc
./build/linux-gcc/apps/cli/omnitrace scan /home/wrongbaud/projects/omnitrace/firmware/router.bin
```

## Add a signature (TOML only)

Use this when a format is identified well enough by magic bytes and needs no
structural check yet. Magic-only findings stay at `Confidence::Magic` with
size 0, so they never claim bytes or parent anything.

1. Pick the file: `signatures/core.toml` for filesystems, containers,
   kernels and partition tables; `signatures/crypto.toml` for LUKS,
   dm-verity and key material.
2. Append a `[[signature]]` table. The schema is in
   [formats/signatures.md](formats/signatures.md); the minimum is:

   ```toml
   [[signature]]
   name = "toyfs"              # unique across every .toml
   format = "toyfs"            # Node::format and the reader lookup key
   category = "filesystem"     # filesystem | container | partition-table | kernel | bootloader | compressed | crypto | other
   magic = "TOY!"              # or hex = "544f5921"; at least 2 bytes
   magic_offset = 0            # where the magic sits inside the structure
   endian = "little"           # optional
   alignment = 1               # optional; use 512 for sector structures, 4096 for QNX6-style
   description = "toyfs superblock"
   references = ["https://example.invalid/toyfs"]
   ```

3. Rebuild. `src/discovery/CMakeLists.txt` re-runs `embed_signatures.cmake`
   whenever a `.toml` changes; nothing else to register.
4. If the magic is short (2 to 4 bytes) expect noise on random data and plan
   a validator; `TEST(Scan, BuiltinSetOnRandomDataIsQuiet)`
   ([scan_test.cpp:195](../tests/unit/discovery/scan_test.cpp#L195)) will tell
   you.

How to verify:

```sh
cmake --build --preset linux-gcc --parallel && ./build/linux-gcc/src/discovery/test_discovery --gtest_filter='SignatureToml.*:Scan.*'
./build/linux-gcc/apps/cli/omnitrace scan <image-with-the-format> | grep toyfs
```

`SignatureToml.BuiltinMatchesSourceFilesAndNamesRegisteredValidators`
([toml_test.cpp:125](../tests/unit/discovery/toml_test.cpp#L125)) fails if
the embedded set drifts from the files or names an unregistered validator.

## Add a validator

A validator parses the structure behind a magic and decides tier, size,
attrs and diagnostics. Copy the shape of
[src/discovery/validators/romfs.cpp](../src/discovery/validators/romfs.cpp).

Checklist:

- [ ] `src/discovery/validators/<name>.cpp` with a function
      `optional<Finding>(const Span&, uint64_t start, const Signature&)`.
- [ ] Reads only through `Span` accessors; no raw pointers, no exceptions.
- [ ] `OMNITRACE_REGISTER_VALIDATOR("<name>", fn)` at namespace scope.
- [ ] `OMNITRACE_VALIDATOR_ANCHOR(<name>)` at the end of the file.
- [ ] `OMNITRACE_DECLARE_ANCHOR(<name>)` and `OMNITRACE_TOUCH_ANCHOR(<name>)`
      lines in [src/discovery/validators/builtin.cpp](../src/discovery/validators/builtin.cpp).
- [ ] `validator = "<name>"` on the signature in `signatures/*.toml`; any
      tunable (a name length, a chain limit) as an extra TOML key read with
      `extra_u64`, not as a constant.
- [ ] Tests in `tests/unit/discovery/validators2_test.cpp` (or a new file in
      that directory; it is globbed). `scan_one()` and `has_diag()` are
      file-local helpers at the top of `validators2_test.cpp`, not in
      `helpers.h`; a new file copies those ten lines.
- [ ] `docs/formats/<name>.md` with layout, tiers, attrs, diagnostics, gaps.
- [ ] One entry per new diagnostic code in
      `docs/reference/diagnostics.yaml` (`meaning` + `action`) and one
      section per source file with its attrs keys in
      `docs/reference/attrs.yaml`, then `python3 scripts/gen_docs.py` to
      regenerate `docs/reference/*.md`. `ctest` runs `scripts/check_docs.py`
      (`tests/unit/discovery/docs_check_test.cpp`) and the discovery test
      fails with `diagnostics.yaml: missing entry for code ...` until this is
      done.

A complete minimal validator that compiles with the project's warning set:

```cpp
// toyfs.cpp — toyfs superblock validator.
//
// Little-endian header: 0 "TOY!", 4 total size u32, 8 version u16, 10 label
// (NUL-terminated, at most max_name_len bytes). Padded to 512 bytes.
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kDefaultMaxName = 32;

std::optional<Finding> validate_toyfs(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    const auto total = span.at<std::uint32_t>(start + 4, Endian::Little);
    const auto version = span.at<std::uint16_t>(start + 8, Endian::Little);
    if (!total || !version) {
        diag(f, Severity::Warning, "toyfs-truncated-header",
             "fewer than 10 bytes available for the superblock");
        return f;
    }
    if (*version != 1) {
        diag(f, Severity::Warning, "toyfs-unsupported-version",
             "version " + dec(*version) + " is not 1");
        return f;
    }
    if (*total < 512) {
        // Short magic (4 bytes) and the only discriminator failed: noise, reject.
        return std::nullopt;
    }
    const std::uint64_t max_name = extra_u64(sig, "max_name_len").value_or(kDefaultMaxName);
    const auto label = span.cstring(start + 10, static_cast<std::size_t>(max_name));
    f.confidence = Confidence::Structural;
    f.attrs["version"] = dec(*version);
    if (label && !label->empty()) f.attrs["label"] = *label;
    bool truncated = false;
    f.size = clamp_size(span, start, *total, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "toyfs-truncated",
             "total size " + dec(*total) + " extends past the available data");
        return f;
    }
    f.confidence = Confidence::Consistent;
    f.evidence = "toyfs v" + dec(*version) + ", " + dec(*total) + " bytes";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("toyfs", validate_toyfs);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(toyfs)
```

Then in `builtin.cpp` add `OMNITRACE_DECLARE_ANCHOR(toyfs)` next to the other
declarations and `OMNITRACE_TOUCH_ANCHOR(toyfs)` inside
`link_builtin_validators()`. Without those two lines the static library
drops `toyfs.o` and the scanner reports `validator-missing` on every hit;
that is the whole reason the anchors exist
([anchors.h](../src/discovery/validators/anchors.h)).

Decisions the example shows:

- Return `nullopt` when the magic is short and the only discriminator
  failed; return a `Magic` finding with a diagnostic when the magic is long
  and the header is merely corrupt (see the rule in
  [formats/signatures.md](formats/signatures.md#validator-contract)).
- Clamp the size with `clamp_size` and add `<fmt>-truncated` rather than
  claim bytes past the Span.
- `Verified` is reserved for a checksum or a decode probe; `Consistent` for
  cross-field checks; `Structural` for a parsed header.
- Set `f.attrs["also_covers"] = "off:len;..."` if the structure has member
  blocks that carry the same magic and must not become findings of their own
  (see [mbr.cpp:188](../src/discovery/validators/mbr.cpp#L188)).

Test template (same shape as `TEST(RomfsValidator, ...)` at
[validators2_test.cpp:626](../tests/unit/discovery/validators2_test.cpp#L626)):
a builder that returns a minimal valid image as `Bytes`, one test that scans
it with `test::only({"toyfs"})` and expects the intended tier and attrs, one
`HostileVariants` test that flips the version, shrinks the size, truncates
the buffer and expects the exact diagnostic codes, and a fixture test guarded
by `test::fixture_exists()` when `tests/fixtures/generate.py` can build one.

How to verify:

```sh
cmake --build --preset linux-gcc --parallel
./build/linux-gcc/src/discovery/test_discovery --gtest_filter='ToyfsValidator.*:SignatureToml.*'
python3 scripts/check_docs.py      # catalogue entries, format page, generated reference all in sync
./build/linux-gcc/apps/cli/omnitrace scan <image> --json | python3 -c 'import json,sys; [print(f["offset_hex"], f["tier"], f["evidence"]) for f in json.load(sys.stdin)["findings"] if f["format"]=="toyfs"]'
cmake --preset linux-asan && cmake --build --preset linux-asan --parallel && ./build/linux-asan/src/discovery/test_discovery --gtest_filter='Toyfs*'
```

## Add a filesystem reader

A reader turns a filesystem Span into `FileMeta` entries and data streamed
to a `Sink`. The contract is `fs::FilesystemReader`
([Filesystem.h:81](../include/omnitrace/filesystems/Filesystem.h#L81)); the
worked example is [SquashfsReader](../src/filesystems/squashfs/SquashfsReader.cpp).

Checklist:

- [ ] Validator and signature exist (previous recipe); `format` there is the
      key `analyze()` uses to look the reader up.
- [ ] `src/filesystems/<name>/<Name>Reader.{h,cpp}`.
- [ ] `OMNITRACE_REGISTER_FILESYSTEM("<format>", <Name>Reader)` in the `.cpp`.
- [ ] Anchor: `void omnitrace_fs_anchor_<name>() {}` in `fs::detail` in the
      `.cpp`, declared in the `.h`, and a declaration plus call in
      [src/filesystems/Registry.cpp:15](../src/filesystems/Registry.cpp#L15).
- [ ] Diagnostic codes as `constexpr const char*` at the top of the `.cpp`.
- [ ] Every cap reads a `Limits` field.
- [ ] `tests/unit/filesystems/<name>_test.cpp`.
- [ ] `docs/formats/<name>.md`.
- [ ] `docs/reference/diagnostics.yaml` entries for every code the reader
      emits (`attrs.yaml` too if it sets attrs), then
      `python3 scripts/gen_docs.py`; `ctest` fails through
      `scripts/check_docs.py` otherwise.
- [ ] `mount_type_for()` ([Recurse.cpp:1035](../src/discovery/Recurse.cpp#L1035))
      knows the `mount -t` type, or the format is in the MTD comment branch
      of `mount_script_text()`, if a carved copy can be mounted on Linux.

Skeleton:

```cpp
// ToyfsReader.h
#pragma once
#include <memory>
#include <string>

#include "omnitrace/filesystems/Filesystem.h"

namespace omnitrace::fs {

class ToyfsReader final : public FilesystemReader {
   public:
    ToyfsReader();
    ~ToyfsReader() override;
    std::string format() const override;          // "toyfs"
    Status open(const Span& span) override;       // parse the superblock, fail on a non-instance
    FilesystemInfo info() const override;         // label, size, block_size, compression, attrs
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

namespace detail {
void omnitrace_fs_anchor_toyfs();
}

}  // namespace omnitrace::fs
```

```cpp
// ToyfsReader.cpp (the parts that matter)
namespace omnitrace::fs {
namespace detail { void omnitrace_fs_anchor_toyfs() {} }

namespace {
constexpr const char* kCodeMetadataCorrupt = "toyfs-metadata-corrupt";
constexpr const char* kCodeLimitFiles = "toyfs-limit-files";
}  // namespace

// ... Impl, open(), info() ...

Status ToyfsReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    out = WalkResult{};
    // for every entry, in on-disk order:
    FileMeta m;
    m.path = "etc/config";          // relative, '/'-separated, no leading '/'
    m.kind = EntryKind::Regular;
    m.mode = 0644; m.uid = 0; m.gid = 0; m.size = 12; m.inode = 7; m.nlink = 1;
    m.mtime = 1700000000;            // every timestamp the FS records
    EntryResult r;
    if (Status s = sink.begin_file(m); !s) {          // unsafe path or a sink limit
        out.diagnostics.push_back({Severity::Warning, "toyfs-sink-error", s.error});
    } else {
        if (opts.extract_data) {
            // decode one block at a time; never the whole file
            std::vector<std::uint8_t> block = /* decoded bytes */ {};
            if (Status s2 = sink.write(block); !s2) r.truncated = true;
        }
        (void)sink.end_file(r);                        // digests, host_path, written
        out.entries++; out.files++; out.bytes += r.digests.bytes;
        out.entries_out.push_back(std::move(r));
    }
    // directories, symlinks, devices: fill FileMeta (link_target, rdev_*) and call sink.entry(m, r)
    // a limit tripped (opts.limits.max_nodes_per_fs, sink.limits()...):
    //   out.truncated = true; push {Warning, kCodeLimitFiles, ...}; stop this branch, keep the rest
    return Status::success();
}

OMNITRACE_REGISTER_FILESYSTEM("toyfs", ToyfsReader);
}  // namespace omnitrace::fs
```

History entries (JFFS2 versions, UBIFS sqnum, YAFFS2 sequence): when
`opts.history` is set, emit an older version as a normal entry with
`m.superseded = true` and `m.version = <n>`, and a deletion record with
`m.deleted = true`; count them in `out.superseded` / `out.deleted`. The
`DiskSink` places them under `.omnitrace-versions/<path>/v<n>` by itself
([Sink.cpp:169](../src/core/Sink.cpp#L169)); the reader never chooses host
paths.

Diagnostic codes to define (see the naming rule below): `<fmt>-metadata-corrupt`
(Error when the root is unreadable, Warning when a subtree is skipped),
`<fmt>-block-corrupt`, `<fmt>-data-truncated`, `<fmt>-bad-<field>` for each
field you validate, `<fmt>-limit-nodes`, `<fmt>-limit-files`,
`<fmt>-limit-file-bytes`, `<fmt>-sink-error`, `<fmt>-unsupported-version`,
`<fmt>-unsupported-compression`. The SquashFS list at
[SquashfsReader.cpp:74](../src/filesystems/squashfs/SquashfsReader.cpp#L74)
is a good starting set.

Test template (`tests/unit/filesystems/<name>_test.cpp`, mirroring
[squashfs_test.cpp](../tests/unit/filesystems/squashfs_test.cpp)):

1. **Synthetic**: build a minimal image byte by byte in the test (root dir,
   a regular file spanning two blocks, a symlink, a device), walk it into a
   `ListingSink` and a `DiskSink` under a temp dir, assert every `FileMeta`
   field and sha256.
2. **Real-tool round trip**: if the mkfs tool exists on the host
   (`tool_exists("/usr/bin/mkfs.<x>")`), stage a tree, run the tool with
   `std::system`, walk the image through `DiskSink`, then `diff -r` the
   result against the staged tree and compare every entry's mode, owner and
   mtime. Parameterise over the tool's compressors as `SquashfsMksquashfs`
   does ([squashfs_test.cpp:1082](../tests/unit/filesystems/squashfs_test.cpp#L1082)).
3. **Hostile**: truncate the synthetic image at every offset; corrupt every
   superblock pointer and size; point a directory at its ancestor; flip
   random bytes with a fixed seed. Nothing may crash, every result must be
   `Status` or a diagnostic, and the test binary must pass under
   `linux-asan`.
4. **Fixture**: when `tests/fixtures/out/<name>.img` exists, compare the walk
   against the `tree` (and `history`) sections of `<name>.expected.yaml`.
5. **Registry**: `FilesystemRegistry::instance().create("<format>")` returns
   a reader (this is what catches a missing anchor).

`docs/formats/<name>.md` template (follow [formats/squashfs.md](formats/squashfs.md)):

```
# <Format>
Reader / validator / test paths, one paragraph on where the format appears.
## On-disk layout        superblock and structures as tables, byte order
## What the reader captures    FileMeta fields, attrs, extra["..."]
## Diagnostics           | code | severity | when |
## History               what versions/deletions it can recover, or "none"
## Known gaps
## References            kernel sources, specs, reference tools (read, never copied)
```

How to verify:

```sh
cmake --build --preset linux-gcc --parallel && ./build/linux-gcc/src/filesystems/test_filesystems
python3 scripts/check_docs.py
./build/linux-gcc/apps/cli/omnitrace analyze <image> --out /tmp/case && cat /tmp/case/INFO.md | sed -n '/## Coverage/,$p'
cmake --build --preset linux-asan --parallel && ./build/linux-asan/src/filesystems/test_filesystems
tests/parity/run.py <image> --tools unblob,moria,omnitrace --omnitrace build/linux-gcc/apps/cli/omnitrace
```

Coverage must say `<format> supported`; the parity report must show the
file set identical to the reference tool, or explain each difference.

## Add a container reader

Same shape, different registry. `container::ContainerReader`
([Container.h:40](../include/omnitrace/containers/Container.h#L40)) has
`format()`, `open()`, `info()` and `walk()`; single-payload wrappers (gzip, xz,
uImage) emit one entry named `payload`.

The worked example is `src/containers/stream/StreamReader.{h,cpp}`, which
serves both `gzip` and `xz` from one class, with
`tests/unit/containers/stream_test.cpp` as the test shape.

1. `src/containers/<name>/<Name>Reader.{h,cpp}`, registered with
   `OMNITRACE_REGISTER_CONTAINER("<format>", <Name>Reader)`.
2. Anchor: define `omnitrace_container_anchor_<name>()` and call it from
   `link_builtin_containers()` in
   [src/containers/Registry.cpp](../src/containers/Registry.cpp), beside
   `omnitrace_container_anchor_stream()`.
3. Tests in `tests/unit/containers/` (`omnitrace_module` globs the directory).

That is all: `analyze()` looks the reader up through
`AnalyzeOptions::open_container`, which the CLI fills from the registry, walks
it into `containers/<node-id>/files/` and re-scans every file it wrote, so a
payload that is itself an image is followed automatically. Nothing in
`Recurse.cpp` needs editing.

Two things worth copying from `StreamReader`:

* **Report an extent.** `info().size` is the input length the container
  actually used; `analyze` gives it to the node when the validator left the
  finding unsized, which is what stops an `unidentified` region being reported
  over the container's own bytes. For a compressed stream, sizing it in the
  *validator* (`compressed_stream_length` in
  `src/discovery/validators/common.h`) is better still, because gap and
  parenting decisions happen before any reader runs.
* **Use literal diagnostic codes.** A code built at run time
  (`format_ + "-failed"`) is invisible to `scripts/gen_docs.py`, so it would
  reach manifests without a catalogue entry. `StreamReader` uses layer-scoped
  literals (`container-decompress-failed`, ...) for exactly that reason.

How to verify: `./build/linux-gcc/src/containers/test_containers`, and
`ContainerRegistry::instance().create("<format>")` returning non-null.

## Add a CLI subcommand

`main.cpp` only wires modules together; each module registers its own
subcommands.

1. Create `apps/cli/<module>_commands.cpp` with
   `void register_<module>_commands(CLI::App& app)`, following
   [analyze_commands.cpp:422](../apps/cli/analyze_commands.cpp#L422):
   `app.add_subcommand(...)`, options bound to a `std::shared_ptr` args
   struct, and a `->callback([...]{ ... })` that throws
   `CLI::RuntimeError(1)` on failure.
2. Declare it in [apps/cli/commands.h](../apps/cli/commands.h).
3. Call it in [apps/cli/main.cpp:48](../apps/cli/main.cpp#L48) next to
   `register_analyze_commands(app)`. `main.cpp` stays under 100 lines.
4. Document it in [CLI.md](CLI.md). If it writes a manifest, set
   `m.run.argv` from `set_process_argv` and time stamps from `Clock`, and
   round-trip the YAML before exiting 0 as `cmd_analyze` does
   ([analyze_commands.cpp:362](../apps/cli/analyze_commands.cpp#L362)).

How to verify: `./build/linux-gcc/apps/cli/omnitrace <cmd> --help`, then
the command on `router.bin`; exit status must be 0 or 1 and nothing may
write to the image.

## Add a diagnostic code

Codes are the API tests and downstream agents key on, so they are stable
once released.

- Name: `<format>-<what>`, kebab-case, lowercase. `<format>` is the
  signature format (`squashfs`, `gpt`, `jffs2`) or the subsystem (`sink`,
  `carve`, `analyze`, `partition`, `scan`, `manifest`, `image`). `<what>` is
  a noun phrase: `truncated`, `truncated-header`, `crc-mismatch`,
  `bad-<field>`, `unsupported-version`, `limit-<what>`, `no-reader`.
- Severity: `Error` when the structure could not be processed at all (open
  failed, root unreadable, host write failed); `Warning` when something was
  lost or degraded but the rest continued (a limit, a bad block, a skipped
  entry, a mismatching CRC); `Info` when nothing was lost and the examiner
  should merely know (`partition-rescan`, `also-matched`, `region-unidentified`).
- Define it once as a `constexpr const char*` (readers) or use it in one
  `diag()` call per meaning (validators). The message is a human sentence
  with the offending values; the code never changes with the values.
- Assert it in a test by code, never by message.
- Document it in `docs/formats/<name>.md` under Diagnostics, and add an
  entry (`meaning`, `action`, one line each, alphabetical) to
  `docs/reference/diagnostics.yaml`. `docs/reference/DIAGNOSTICS.md` is
  generated from the source and that YAML by `python3 scripts/gen_docs.py`;
  run it after editing the YAML and commit the result, never edit the `.md`
  by hand. `scripts/gen_docs.py` finds codes by scanning `src/` and `apps/`
  for `diag(target, Severity::X, code, message)` calls,
  `{Severity::X, code, message}` initialisers (a literal, a `kCode*`
  constant, or a variable assigned one of those in the same file),
  `fail_code("<code>", ...)` and `Status::fail("<code>: <detail>")`
  literals. A `kCode*` constant that only reaches `Status::fail` is not
  seen, so give the status string the `"<code>: <detail>"` shape.

How to verify: `grep -rn '"<code>"' src tests docs/formats` shows the
definition, a test and a doc row, and `python3 scripts/check_docs.py` prints
`check_docs.py: ok`.

## Add a fixture image

Fixtures are the ground truth reader tests compare against.
[tests/fixtures/generate.py](../tests/fixtures/generate.py) builds every
image from the same file tree with pinned timestamps and content.

1. Write `build_<name>(ctx: Ctx) -> Optional[dict]` next to the others
   (`build_squashfs` at [generate.py:370](../tests/fixtures/generate.py#L370)
   is the simplest). Stage the tree with `stage()`, run the mkfs tool through
   `ctx.run()`, pin whatever the tool leaves non-deterministic, and return
   `image_doc(name, fmt, img, tool, argv, features, tree, **extra)`.
   Return `None` to decline.
2. Add a row to `BUILDERS`
   ([generate.py:1194](../tests/fixtures/generate.py#L1194)): name, the
   tools it needs, the function.
3. If the tool is not in the Docker image, add it to
   `tests/fixtures/Dockerfile`.
4. `expected.yaml` is written by `write_yaml` from the dict you return; the
   `tree` section lists every live entry (path, kind, mode, uid, gid, size,
   sha256, link_target, mtime), `features` says what the format cannot
   represent, and `history` (`superseded`, `current`, `deleted`) is only
   present when the builder scripted one. Formats: [TESTING.md](TESTING.md).

How to verify:

```sh
scripts/fixtures.sh build --native --only <name>   # or without --native for Docker
scripts/fixtures.sh check                           # two builds, byte-identical
scripts/fixtures.sh verify
./build/linux-gcc/src/filesystems/test_filesystems --gtest_filter='*Fixture*'
```

## Add a parity tool

[tests/parity/run.py](../tests/parity/run.py) normalises every tool's output
into one shape and diffs pairs.

1. Add `run_<tool>(self) -> ToolResult` to `Runner` (see `run_moria` at
   [run.py:326](../tests/parity/run.py#L326)) producing raw output under
   `<out>/<tool>/`.
2. Add a pure `parse_<tool>(...) -> list[Finding]` beside `parse_omnitrace`
   ([run.py:530](../tests/parity/run.py#L530)).
3. Add the name to `ALL_TOOLS` ([run.py:54](../tests/parity/run.py#L54)) and
   its format names to `FORMAT_ALIASES`.
4. Add a test to `tests/parity/test_run.py` built from a hand-written raw
   report and a temporary extraction tree.

How to verify: `python3 -m unittest tests/parity/test_run.py`, then
`tests/parity/run.py tests/fixtures/out/squashfs-gzip.img --tools <tool>,expected`.

## Add a Coverage row

A Coverage row is how "we saw it but could not do it" reaches the examiner.
Rows are `{format, status, detail}` with status `supported`, `partial`,
`unsupported` or `tool-missing`.

- Inside `analyze()`, call `set_coverage(c, format, status, detail)`
  ([Recurse.cpp:145](../src/discovery/Recurse.cpp#L145)). One row per format
  is kept and `partial` is never downgraded to `supported`.
- For carving, use `carve_partial(c, detail)`
  ([Recurse.cpp:161](../src/discovery/Recurse.cpp#L161)); details accumulate
  with `; `.
- Pair every non-`supported` row with a Diagnostic on the node it concerns,
  so the reason is visible both in the table and next to the evidence.
- Anything outside `Recurse` (a future `report` command) appends to
  `Manifest::coverage` directly and keeps the same statuses.

How to verify: the row appears in `INFO.yaml` under `coverage:`, in the
`## Coverage` table of `INFO.md`, and on the CLI's `coverage:` lines; a test
in `recurse_test.cpp` asserts it (see
`TEST(Analyze, ContainerWithoutReaderIsCoveredNotSilent)` at
[recurse_test.cpp:411](../tests/unit/discovery/recurse_test.cpp#L411)).

## Debugging a bad identification

When `scan` reports the wrong format, the wrong tier or the wrong size:

1. Get the machine view:

   ```sh
   omnitrace scan image.bin --json > scan.json
   python3 -c 'import json; d=json.load(open("scan.json"));
   [print(f["offset_hex"], f["format"], f["tier"], f["size"], "|", f["evidence"]) for f in d["findings"]]'
   ```

   `evidence` is the validator's own sentence about why it chose that tier;
   `diagnostics[].code` names what failed.
2. Look inside `also_matched` on the finding that covers the offset you
   care about. A finding you expected but do not see is usually there,
   absorbed by a higher-confidence neighbour, and the `also-matched` Info
   diagnostic on the node says at which offset and confidence.
3. Carve the slice and scan it on its own, so partition parenting and
   same-signature coverage cannot interfere:

   ```sh
   dd if=image.bin of=slice.bin bs=1 skip=$((0x1c9245)) count=$((0xa8a000)) status=none
   omnitrace scan slice.bin
   ```

   For a reader problem, `omnitrace analyze slice.bin --out /tmp/slice`
   and read the `diagnostics:` of the filesystem node in `INFO.yaml`.
4. Reproduce in a test with `test::only({"<signature>"})` and
   `span_of(bytes)` from
   [tests/unit/discovery/helpers.h](../tests/unit/discovery/helpers.h) so
   only that validator runs.
5. Run the same under the sanitizer preset before trusting a fix:

   ```sh
   cmake --preset linux-asan && cmake --build --preset linux-asan --parallel
   ./build/linux-asan/src/discovery/test_discovery --gtest_filter='<Suite>.*'
   ./build/linux-asan/apps/cli/omnitrace scan slice.bin
   ```

6. If the fix changes a tier or a size, update `docs/formats/<name>.md` and
   the corpus expectations in `router_test.cpp` / `Corpus2` tests.
