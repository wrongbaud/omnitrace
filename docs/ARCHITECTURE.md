# Architecture and contributor contract

This file is the rulebook for anyone (human or agent) adding code. The public headers under `include/omnitrace/` are the contract; read them before the plan.

## Layers and dependencies

```
apps/cli  →  output, discovery, containers, images, filesystems  →  core
```

`core` depends on nothing in the project. Nothing depends on `apps/cli`. `filesystems`, `containers` and `images` depend on `core` and `discovery` only (for `Finding`/`Signature`), never on each other. Recursion across layers (a SquashFS inside a UBI volume inside a GPT partition) is orchestrated in `discovery/Recurse` (Phase 1a), not inside readers.

## Non-negotiable rules

1. **All evidence bytes go through `Span`.** No raw pointer arithmetic outside `src/core/`. Every accessor returns `std::optional`; a bad offset yields `nullopt`, never UB. Sizes and offsets are `uint64_t`; use `Span::sub()` to narrow, never compute `base + len` by hand without an overflow check.
2. **Readers never touch the host filesystem.** Extraction goes through `Sink`. Readers never call `std::filesystem`, `fopen`, `open`, or the clock.
3. **No exceptions for bad input.** Hostile images are the normal case. Return `Status::fail` / `nullopt` and attach a `Diagnostic` with a stable kebab-case `code`. Exceptions are for programmer errors only.
4. **Every limit is a `Limits` field.** No hard-coded caps in readers. When a guard trips, stop that branch, record `Diagnostic{Warning, "<fmt>-limit-<what>"}`, set `truncated`, keep what was recovered.
5. **Deterministic output.** No `Date.now`-style calls outside `core/Clock`; no unordered containers in anything that serializes; sort by offset then name. Same input, byte-identical `manifest.yaml`.
6. **Capture everything the FS knows about an entry** into `FileMeta`: mode, uid, gid, all timestamps, inode, link target, device numbers. If the FS records history (JFFS2 versions, UBIFS sqnum, YAFFS2 sequence), keep it (`version`, `superseded`, `deleted`) when `WalkOptions::history` is set.
7. **Silence is a bug.** A format we recognise but cannot process becomes a `Coverage` row (`unsupported`, `partial`, `tool-missing`) and a Diagnostic. Never skip quietly.
8. **Portable.** POSIX-only code lives only in `src/core/Source.cpp`, `src/core/Sink.cpp` and `src/core/Clock.cpp`, behind `#ifdef _WIN32` branches with a Win32 implementation beside them. Everything else is standard C++20.
9. **Warnings are errors in CI** (`-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion` / `/W4`). Use `static_cast`, never C casts.
10. **Tests ship with code.** Every reader gets `tests/unit/<layer>/<name>_test.cpp` with: a synthetic minimal instance built in the test, a hostile instance (truncated header, absurd sizes, self-referencing pointers), and, when `OMNITRACE_TEST_DATA_DIR` has the fixture, a byte-identity check against the reference tool's output.

## Adding a filesystem reader

1. `src/filesystems/<name>/<Name>Reader.{h,cpp}` implementing `fs::FilesystemReader`; register with `OMNITRACE_REGISTER_FILESYSTEM("<format>", <Name>Reader)`.
2. `src/discovery/validators/<name>.cpp` with a `Validator` registered as `OMNITRACE_REGISTER_VALIDATOR("<name>", fn)` that parses the superblock and returns the structure size and confidence tier.
3. `signatures/<category>.toml` entry naming the validator.
4. `docs/formats/<name>.md`: on-disk layout summary, references, diagnostics codes the reader emits, what history it can recover, known gaps.
5. Tests as above. Fixture in `tests/fixtures/build.sh` if a mkfs tool exists.

## Adding a CLI subcommand

Each layer may expose `void register_<layer>_commands(CLI::App&)` from `apps/cli/<layer>_commands.cpp`. `main.cpp` stays under 100 lines.

## Confidence tiers

| Tier | Score | Meaning |
|---|---|---|
| magic | 25 | magic bytes matched; nothing else checked |
| structural | 60 | header parsed; all hard constraints hold (sizes in range, version known) |
| consistent | 85 | cross-field consistency: table pointers land inside the structure, counts agree |
| verified | 99 | CRC/checksum verified or a decode probe succeeded |

Conflict resolution between overlapping findings is deterministic: higher confidence wins; tie → earlier offset; tie → larger size. Losers are kept in `also_matched`.

## Output contract

See `DEVELOPMENT_PLAN.md` §6. `manifest.yaml` (schema `omnitrace/1`) is the source of truth; every `.md` is rendered from it.

## Design references

moria (nmatt0, MIT) informed the Span/validator/confidence/safe-sink shape; see `docs/MORIA_SPIKE.md`. No source is copied from it or from any GPL project. Format knowledge comes from the Linux kernel sources (read for understanding), format specifications, and the tools listed per format in `docs/formats/`.
