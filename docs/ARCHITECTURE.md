# Architecture and contributor contract

This file is the rulebook for anyone, human or agent, adding code. It is
deliberately short: after reading it you know the layers, the rules a review
will hold you to, and the confidence and output contracts. The public headers
under `include/omnitrace/` are the contract; read them before the plan. For
the walk-through see [CODE_TOUR.md](CODE_TOUR.md); for step-by-step recipes
see [EXTENDING.md](EXTENDING.md).

## Layers and dependencies

```
apps/cli  →  output, discovery, containers, images, filesystems  →  core
          →  analyzers, rules  →  core, output
```

`core` depends on nothing in the project. Nothing depends on `apps/cli`.

`analyzers` and `rules` are **post-analysis** layers and depend on neither
`discovery` nor any reader. They take what the extraction produced — a set of
`(node id, entries)` pairs, and for `rules` a Span over the image — and
nothing about how it was produced. That is what lets a finished case be
re-analysed or re-swept without re-extracting it, and it is checkable: the
only `omnitrace::` symbols `libomnitrace_analyzers.a` leaves undefined are its
own and `output::`. A `discovery::` type in either layer's interface would be
a review finding.
`filesystems`, `containers` and `images` depend on `core` and `discovery`
only (for `Finding`/`Signature`), never on each other. Recursion across
layers is orchestrated in `discovery/Recurse` (`analyze()`), which takes
readers through the `AnalyzeOptions::open_reader` callback rather than
linking the reader libraries. It descends into every extracted file that is
itself an image and opens every container that has a registered reader,
bounded by `Limits::max_depth`, so chains such as
`boot.img -> ramdisk -> gzip -> cpio -> rootfs` resolve to the end. Container
readers come through `AnalyzeOptions::open_container`, the twin of
`open_reader`, for the same layering reason.

Each layer is one static library built by `omnitrace_module()` in
`cmake/Warnings.cmake`, which globs `src/<layer>/**/*.cpp` and
`tests/unit/<layer>/**/*.cpp`. Add files; never edit a shared CMake file.

## Non-negotiable rules

1. **All evidence bytes go through `Span`.** No raw pointer arithmetic outside `src/core/`. Every accessor returns `std::optional`; a bad offset yields `nullopt`, never UB. Sizes and offsets are `uint64_t`; use `Span::sub()` to narrow and saturating arithmetic (`sat_add`) for header values. Why: every offset in a header is attacker-controlled.
2. **Readers never touch the host filesystem.** Extraction goes through `Sink`. Readers never call `std::filesystem`, `fopen`, `open`, or the clock. Why: the Sink's `openat`/`O_NOFOLLOW` walk is the only path-safety boundary, and a reader with its own I/O would bypass it.
3. **No exceptions for bad input.** Hostile images are the normal case. Return `Status::fail` / `nullopt` and attach a `Diagnostic` with a stable kebab-case `code`. Exceptions are for programmer errors only. Why: a throw from deep inside a parser loses the partial result the examiner still wants.
4. **Every limit is a `Limits` field.** No hard-coded caps in readers; validator tunables come from `Signature::extra` (TOML). When a guard trips, stop that branch, record `Diagnostic{Warning, "<fmt>-limit-<what>"}`, set `truncated`, keep what was recovered. Why: the examiner sets the budget per case, and a hidden constant cannot be raised on an 8 GiB eMMC.
5. **Deterministic output.** No wall-clock reads outside `core/Clock`; no unordered containers in anything that serializes; nodes are inserted tables-first then in byte order, so ids are stable. Same input, byte-identical `INFO.yaml`, and the CLI refuses to exit 0 unless the manifest round-trips. Why: reproducibility is what makes the output evidence.
6. **Capture everything the FS knows about an entry** into `FileMeta`: mode, uid, gid, all timestamps, inode, link target, device numbers. If the FS records history (JFFS2 versions, UBIFS sqnum, YAFFS2 sequence), keep it (`version`, `superseded`, `deleted`) when `WalkOptions::history` is set. Why: metadata that is not captured at walk time is gone from the listing for good.
7. **Silence is a bug.** A format we recognise but cannot process becomes a `Coverage` row (`unsupported`, `partial`, `tool-missing`) and a Diagnostic; a limit that trips, a carve that is skipped and a table recovered from a backup all get a row. Never skip quietly. Why: an examiner must be able to say what the tool did not look at.
8. **Portable.** POSIX-only code lives only in `src/core/Source.cpp`, `src/core/Sink.cpp` and `src/core/Clock.cpp`, behind `#ifdef _WIN32` branches with a Win32 implementation beside them. Everything else is standard C++20. Why: examiners run Windows and macOS, and a stray `<unistd.h>` breaks the CI matrix.
9. **Warnings are the compiler's review.** Every target links `omnitrace_warnings` (`-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wnon-virtual-dtor -Wold-style-cast -Wimplicit-fallthrough`, `/W4 /permissive-` on MSVC); `-Werror` is enabled with `-DOMNITRACE_WERROR=ON` and code must build clean with it. Use `static_cast`, never C casts. Why: implicit narrowing on a size read from evidence is exactly the bug class these flags catch.
10. **Tests ship with code.** Every reader gets `tests/unit/<layer>/<name>_test.cpp` with: a synthetic minimal instance built in the test, a hostile instance (truncated at every offset, absurd sizes, self-referencing pointers), a real-tool round trip when the mkfs tool is on the host, and, when `tests/fixtures/out/` has the fixture, a check against its `expected.yaml`. Why: a reader is only as trustworthy as the worst input it has been shown.
11. **Partition tables never absorb, and are never absorbed by anything but another table.** A table finding's extent is the table itself (sector or header plus entry array), so the filesystems inside its entries stay visible; conflict resolution's `may_absorb` only lets a table absorb a table. Why: a filesystem at LBA 0 or a stray zip magic must not hide the map everything else is placed on.
12. **Size-0 findings claim nothing.** A magic-only finding (unknown extent) parents no node and splits no gap. Why: one stray zip magic would otherwise swallow every finding after it.
13. **Every evidence string is sanitized before output.** Names, labels, paths and messages go through `sanitize_utf8` in every serializer (YAML, JSON, Markdown, stdout), and file names through `safe_filename_component`. Why: a filename is evidence bytes, and a serializer that aborts on them loses the case.
14. **Registries need force-link anchors.** Anything registered from a static object's constructor (validators, filesystem readers, container readers) also defines an anchor function that the layer's `link_builtin_*()` calls. Why: a static library drops an object file nothing references, and with it the registration.
15. **Per-layer CMake globbing.** Sources and tests are globbed by `omnitrace_module()`; a new file needs no CMake edit and the shared `CMakeLists.txt` files are not touched by feature work. Why: parallel contributors never conflict on a build file.

## Adding a filesystem reader

1. `src/filesystems/<name>/<Name>Reader.{h,cpp}` implementing `fs::FilesystemReader`; register with `OMNITRACE_REGISTER_FILESYSTEM("<format>", <Name>Reader)` and add the anchor line to `src/filesystems/Registry.cpp` (rule 14).
2. `src/discovery/validators/<name>.cpp` with a `Validator` registered as `OMNITRACE_REGISTER_VALIDATOR("<name>", fn)`, its `OMNITRACE_VALIDATOR_ANCHOR` and the `builtin.cpp` lines; it parses the superblock and returns the structure size and confidence tier.
3. `signatures/<category>.toml` entry naming the validator.
4. `docs/formats/<name>.md`: on-disk layout summary, references, diagnostics codes the reader emits, what history it can recover, known gaps. Every new diagnostic code and attrs key also gets a one-line entry in `docs/reference/diagnostics.yaml` / `attrs.yaml`; then run `python3 scripts/gen_docs.py` to regenerate `docs/reference/*.md` (`ctest` runs `scripts/check_docs.py` and fails otherwise).
5. Tests as in rule 10. Fixture in `tests/fixtures/generate.py` if a mkfs tool exists.

Full checklists, a compiling example validator and the test template are in [EXTENDING.md](EXTENDING.md).

## Adding a CLI subcommand

Each module exposes `void register_<module>_commands(CLI::App&)` from `apps/cli/<module>_commands.cpp`, declared in `apps/cli/commands.h` and called from `main.cpp`, which stays under 100 lines.

## Confidence tiers

| Tier | Score | Meaning |
|---|---|---|
| magic | 25 | magic bytes matched; nothing else checked, or the header was corrupt |
| structural | 60 | header parsed; all hard constraints hold (sizes in range, version known) |
| consistent | 85 | cross-field consistency: table pointers land inside the structure, counts agree |
| verified | 99 | CRC/checksum verified or a decode probe succeeded |

Conflict resolution between overlapping findings is deterministic (`resolve()` in `src/discovery/Scan.cpp`): findings are ordered by offset, then higher confidence, then larger size, then signature name; a finding at the same offset as a kept one, or fully inside a kept one that outranks it, moves into that finding's `also_matched`. Outranking is strictly higher confidence, or — for a compressed stream inside anything that is not one — containment alone, at any tier, because such a hit is the enclosing structure's data rather than a separate find. Equal-confidence nesting is otherwise kept, and partial overlaps are kept. Details and the partition-table exception: `docs/formats/signatures.md`.

## Output contract

The case directory is the API; `docs/CASE_LAYOUT.md` is the contract and `DEVELOPMENT_PLAN.md` §6 the rationale. `INFO.yaml` (schema `omnitrace/1`, aliased as `manifest.yaml`) is the source of truth; every `.md` is rendered from it, and `docs/schema/manifest.schema.json` must equal `manifest_json_schema()`.

## Design references

moria (nmatt0, MIT) informed the Span/validator/confidence/safe-sink shape; see `docs/MORIA_SPIKE.md`. No source is copied from it or from any GPL project. Format knowledge comes from the Linux kernel sources (read for understanding), format specifications, and the tools listed per format in `docs/formats/`.
