# Code tour: one byte from evidence to the case directory

This tour is for a contributor who has cloned the repository and built it once
(`cmake --preset linux-gcc && cmake --build --preset linux-gcc --parallel`).
It follows a single evidence file through every layer, naming the type,
function and file:line responsible at each step. After reading it you will
know which target owns each concern, where a change belongs, and which test
proves it. Rules live in [ARCHITECTURE.md](ARCHITECTURE.md); recipes live in
[EXTENDING.md](EXTENDING.md); formats live in [formats/](formats/README.md).

## 1. Layers and targets

One static library per layer, one CMake function that builds them all:
`omnitrace_module()` in [cmake/Warnings.cmake:22](../cmake/Warnings.cmake#L22).
It globs `src/<layer>/**/*.cpp` into `omnitrace_<layer>` (alias
`omnitrace::<layer>`), globs `tests/unit/<layer>/**/*.cpp` into `test_<layer>`,
and registers that executable with CTest. A layer's `CMakeLists.txt` is two
lines (see [src/filesystems/CMakeLists.txt](../src/filesystems/CMakeLists.txt)),
so adding a source file never touches CMake. `src/images` has no sources yet
and becomes an INTERFACE target ([cmake/Warnings.cmake:29](../cmake/Warnings.cmake#L29)).

| Target | Directory | Links | What lives there |
|---|---|---|---|
| `omnitrace_core` | `src/core` | zlib, xz, lz4, zstd, OpenSSL, spdlog | Source, Span, Hash, Compression, Node, Manifest, Sink, Limits, Diagnostics, Clock, Text, Swap |
| `omnitrace_discovery` | `src/discovery` | core, tomlplusplus | TOML signatures (embedded), scanner, validators, conflict resolution, `Recurse` (the analysis driver) |
| `omnitrace_output` | `src/output` | core, yaml-cpp, nlohmann-json | YAML manifest and listings, JSON schema, Markdown renderers |
| `omnitrace_filesystems` | `src/filesystems` | core, discovery | `FilesystemReader` registry and readers (SquashFS today) |
| `omnitrace_containers` | `src/containers` | core, discovery | `ContainerReader` registry (no readers yet) |
| `omnitrace_images` | `src/images` | core, discovery | empty placeholder |
| `omnitrace` (CLI) | `apps/cli` | all of the above, CLI11 | `hash`, `scan`, `analyze` |

Dependency arrows, as declared in each `CMakeLists.txt`:

```
apps/cli ──> output ──> core
   │
   ├──────> discovery ──> core
   │            ▲
   ├──> filesystems ──┘   (filesystems, containers, images link core + discovery,
   ├──> containers ───┘    never each other)
   └──> images ───────┘
```

One header crosses the arrows: `discovery/Recurse.h` includes
`filesystems/Filesystem.h` for the `FilesystemReader` type, but the discovery
library never links `omnitrace_filesystems`. Readers reach `analyze()` only
through the `AnalyzeOptions::open_reader` callback
([Recurse.h:120](../include/omnitrace/discovery/Recurse.h#L120)), which the CLI
fills with `FilesystemRegistry::create`
([analyze_commands.cpp:324](../apps/cli/analyze_commands.cpp#L324)).

Every target compiles against `omnitrace_warnings`
([cmake/Warnings.cmake:2](../cmake/Warnings.cmake#L2)); `-Werror` is opt-in
through `OMNITRACE_WERROR`. Presets are in `CMakePresets.json`; `linux-asan`
turns on `OMNITRACE_SANITIZE`.

## 2. Data flow

```
 evidence file
      │  MappedFile::open              core/Source.h
      ▼
  Source ──── Span::whole ────────────► Span (bounds-checked window)
      │                                    │
      │ detect_word_swap  (core/Swap.h)    │ scan()            discovery/Signature.h
      │ SwappedSource view if needed       ▼
      │                              Finding[]  ◄── validators (src/discovery/validators/*.cpp)
      │                                    │ resolve()  (Scan.cpp)
      │                                    ▼
      │                          analyze_span()            discovery/Recurse.cpp
      │                       partitions → nesting → gaps → nodes
      │                                    │
      │              ┌─────────────────────┴───────────────────┐
      │              ▼                                         ▼
      │     FilesystemReader::walk(Sink)               carve_all() → partitions/*.bin
      │     (src/filesystems/…)                        + mount.sh
      │              │
      │              ▼
      │     DiskSink / ListingSink  ── EntryResult[] ──► File nodes
      │                                                   │
      ▼                                                   ▼
   Manifest (core/Manifest.h) ──► manifest_to_yaml ──► INFO.yaml / manifest.yaml
                                ──► summary_markdown ─► INFO.md, summary.md, partitions.md
                                ──► listing_to_yaml ──► filesystems/<id>/listing.yaml
```

## 3. Core types

Everything below is in `include/omnitrace/core/`. The headers are the
contract; read the comment at the top of each one.

### Source, MappedFile, SubSource, SwappedSource

`Source` ([Source.h:30](../include/omnitrace/core/Source.h#L30)) is the
read-only byte provider: `size()`, a stable `id()` for provenance, `read()`
(copy) and `map()` (zero-copy, may return empty). Implementations:

| Class | id() | Where |
|---|---|---|
| `MappedFile` | the path | [Source.h:88](../include/omnitrace/core/Source.h#L88); `mmap` at [Source.cpp:235](../src/core/Source.cpp#L235), `MapViewOfFile` at [Source.cpp:202](../src/core/Source.cpp#L202) |
| `MemorySource` | `mem:<label>` | [Source.h:59](../include/omnitrace/core/Source.h#L59); tests use it everywhere |
| `SubSource` | `<parent>@<off>+<len>` | [Source.h:124](../include/omnitrace/core/Source.h#L124), id at [Source.cpp:290](../src/core/Source.cpp#L290) |
| `SwappedSource` | `<parent>|swap16` or `|swap32` | [Swap.h:37](../include/omnitrace/core/Swap.h#L37); `map()` always returns empty, so readers fall back to `read()` |

`detect_word_swap()` ([Swap.h:77](../include/omnitrace/core/Swap.h#L77),
[Swap.cpp:334](../src/core/Swap.cpp#L334)) samples the image and decides
whether known magics and ASCII runs only appear under a 16- or 32-bit swap.
`analyze()` calls it once and runs the whole analysis on the corrected view
([Recurse.cpp:1246](../src/discovery/Recurse.cpp#L1246)); see
[formats/word-swap.md](formats/word-swap.md).

### Span and why every accessor returns optional

`Span` ([Span.h:62](../include/omnitrace/core/Span.h#L62)) is a window
`[base, base+len)` over a Source. Every offset a parser passes in comes from a
header inside the evidence, so it is attacker-controlled; an accessor that
returned a value for an out-of-range offset would be an out-of-bounds read.
Instead every accessor is range-checked and returns `std::optional` (or a
short count), and a bad offset is a normal `nullopt` branch, never undefined
behaviour.

| Accessor | Line | Returns |
|---|---|---|
| `sub(off, len)` | [Span.h:93](../include/omnitrace/core/Span.h#L93), [Span.cpp:35](../src/core/Span.cpp#L35) | narrower Span; empty (not invalid) when `off` is past the end |
| `at<T>(off, endian)` | [Span.h:101](../include/omnitrace/core/Span.h#L101) | `optional<T>` decoded through `load_int` ([Endian.h:46](../include/omnitrace/core/Endian.h#L46)) |
| `u8(off)` | [Span.h:107](../include/omnitrace/core/Span.h#L107) | `optional<uint8_t>` |
| `bytes(off, n)` | [Span.h:115](../include/omnitrace/core/Span.h#L115) | `optional<vector>` copy |
| `view(off, n)` | [Span.h:121](../include/omnitrace/core/Span.h#L121) | `optional<span>` zero-copy; `nullopt` when the Source cannot map, so callers must fall back to `bytes()`/`read()` |
| `read(off, out)` | [Span.h:126](../include/omnitrace/core/Span.h#L126) | bytes copied, short at the end |
| `matches_at(off, pattern)` | [Span.h:130](../include/omnitrace/core/Span.h#L130) | bool |
| `cstring(off, n)` | [Span.h:137](../include/omnitrace/core/Span.h#L137) | `optional<string>`, stops at NUL |

`absolute(rel)` and `source_id()` turn a Span-relative offset back into
evidence coordinates for `Node::location`.

### Hash

`Digests` ([Hash.h:20](../include/omnitrace/core/Hash.h#L20)) holds MD5,
SHA-1, SHA-256 and the byte count. `Hasher` computes all three in one pass
over OpenSSL EVP; `hash_span()` ([Hash.cpp:97](../src/core/Hash.cpp#L97)) walks
a Span in 8 MiB chunks so a 4 GiB image is never mapped whole, and
`hash_file()` ([Hash.cpp:112](../src/core/Hash.cpp#L112)) backs `omnitrace hash`.

### Compression codecs

`compress::Codec` ([Compression.h:28](../include/omnitrace/core/Compression.h#L28))
covers zlib, deflate, gzip, xz, lzma-alone, lz4 (frame and legacy), zstd,
LZO1X and JFFS2 rtime. `decompress()` takes an explicit `max_out` and fails
with `decompress-cap` instead of growing; `decompress_exact()` is the
block-oriented variant filesystems use. The dispatch is at
[Compression.cpp:470](../src/core/Compression.cpp#L470); LZO and rtime are
own implementations in `src/core/lzo1x.cpp` and `src/core/rtime.cpp`.

### Node, FileMeta, Location

The evidence graph is a flat vector of `Node`
([Node.h:94](../include/omnitrace/core/Node.h#L94)) linked by `parent_id`
and `child_ids`. `NodeKind` ([Node.h:28](../include/omnitrace/core/Node.h#L28))
is Image, Partition, Container, Filesystem, File, Region or Artifact.
`Location` ([Node.h:44](../include/omnitrace/core/Node.h#L44)) is
`{source_id, offset, length}`; length 0 means unknown. A File node carries a
`FileMeta` ([Node.h:70](../include/omnitrace/core/Node.h#L70)): path, kind,
mode, uid/gid, size, every timestamp the filesystem records, inode, nlink,
link target, device numbers, and the forensic flags `deleted`, `superseded`,
`version`. `Coverage` ([Node.h:115](../include/omnitrace/core/Node.h#L115)) is
the "what could we not do" row.

### Manifest and id assignment

`Manifest` ([Manifest.h:46](../include/omnitrace/core/Manifest.h#L46)) is
the whole case as data: `run`, `evidence`, `coverage`, `tools`, run-level
`diagnostics`, and the node vector. `add_node()`
([Manifest.cpp:24](../src/core/Manifest.cpp#L24)) assigns the id `n` + a
six-digit 1-based counter ([Manifest.cpp:16](../src/core/Manifest.cpp#L16))
and appends the id to the parent's `child_ids`; a missing parent is kept and
flagged `manifest-parent-missing`. Ids therefore depend only on insertion
order, which `Recurse` makes deterministic (section 6).

### Sink, DiskSink, ListingSink and the safe path walk

Readers never touch the host filesystem; they emit entries into a `Sink`
([Sink.h:75](../include/omnitrace/core/Sink.h#L75)): `begin_file` /
`write*` / `end_file` for regular files, `entry()` for everything else, and
each call returns an `EntryResult`
([Sink.h:44](../include/omnitrace/core/Sink.h#L44)) with the normalized
metadata, digests, host path and flags.

`DiskSink` ([Sink.h:128](../include/omnitrace/core/Sink.h#L128)) writes under a
root directory and hashes as it writes. Its path handling is the security
boundary of the whole tool:

1. `normalize_entry_path()` ([Sink.cpp:97](../src/core/Sink.cpp#L97))
   rejects NUL, empty, absolute, `..`, drive prefixes and reserved Windows
   names, and canonicalises separators.
2. `placement_path()` ([Sink.cpp:169](../src/core/Sink.cpp#L169)) moves
   superseded and deleted versions under `.omnitrace-versions/<path>/v<n>`
   so the live tree stays faithful.
3. The walk descends one component at a time with `openat(...,
   O_DIRECTORY | O_NOFOLLOW)` ([Sink.cpp:466](../src/core/Sink.cpp#L466)) and
   creates files with `O_CREAT | O_EXCL | O_NOFOLLOW`
   ([Sink.cpp:490](../src/core/Sink.cpp#L490)), so a symlink an earlier entry
   planted can never be written through. The Win32 branch does the same with
   reparse-point checks ([Sink.cpp:239](../src/core/Sink.cpp#L239)).
4. `clamp_write()` ([Sink.cpp:182](../src/core/Sink.cpp#L182)) enforces
   `max_file_bytes` and `max_bytes`; `check_file_count()` enforces
   `max_files`. A tripped limit returns a failed Status with a `sink-limit-*`
   code and marks the entry `truncated`.

`ListingSink` ([Sink.h:164](../include/omnitrace/core/Sink.h#L164)) runs the
same protocol and limits but writes nothing; `--no-extract` uses it.

### Limits

`Limits` ([Limits.h:18](../include/omnitrace/core/Limits.h#L18)) is the one
place caps live: `max_depth`, `max_files`, `max_bytes`, `max_file_bytes`,
`max_decompress_ratio`, `max_nodes_per_fs`. `AnalyzeOptions::limits` is
run-wide; `Recurse` hands each walk what is left
([Recurse.cpp:479](../src/discovery/Recurse.cpp#L479)).

### Diagnostics and Confidence

`Diagnostic` ([Diagnostics.h:30](../include/omnitrace/core/Diagnostics.h#L30))
is `{severity, code, message}`; `code` is a stable kebab-case slug tests key
on. `Confidence` ([Diagnostics.h:42](../include/omnitrace/core/Diagnostics.h#L42))
is an enum whose value is the score: Reject 0, Magic 25, Structural 60,
Consistent 85, Verified 99. `confidence_tier()`
([Diagnostics.cpp:18](../src/core/Diagnostics.cpp#L18)) snaps any score down
to its tier name.

### Clock

`Clock` ([Clock.h:26](../include/omnitrace/core/Clock.h#L26)) is the only
place wall-clock time is read; `set_override()`
([Clock.cpp:60](../src/core/Clock.cpp#L60)) lets tests pin it. Only the CLI
calls it, for `run.started_at` / `run.finished_at`.

### Text

Evidence strings are attacker bytes. `sanitize_utf8()`
([Text.h:27](../include/omnitrace/core/Text.h#L27)) escapes invalid
sequences and C0 controls as `\xNN`; `utf16le_to_utf8()` decodes GPT labels;
`safe_filename_component()` ([Text.h:50](../include/omnitrace/core/Text.h#L50))
makes a host-safe path component. Every serializer calls `sanitize_utf8`
before a string leaves the process: YAML at
[Yaml.cpp:83](../src/output/Yaml.cpp#L83), Markdown at
[Markdown.cpp:25](../src/output/Markdown.cpp#L25), the CLI tables at
[analyze_commands.cpp:172](../apps/cli/analyze_commands.cpp#L172).

## 4. Discovery: signatures, scanner, validators

### Embedded signatures

`signatures/*.toml` are compiled into the discovery library.
[src/discovery/CMakeLists.txt:9](../src/discovery/CMakeLists.txt#L9) globs
and sorts the files and runs
[src/discovery/cmake/embed_signatures.cmake](../src/discovery/cmake/embed_signatures.cmake),
which writes one generated translation unit holding each file as a hex byte
array plus a `kEmbedded[]` table. `SignatureSet::builtin()`
([Signature.cpp:264](../src/discovery/Signature.cpp#L264)) loads each embedded
file through `load_toml()` on first use; a malformed builtin file is a
programmer error and throws. `load_toml()` enforces the schema in
[formats/signatures.md](formats/signatures.md): required keys, known
categories ([Signature.cpp:62](../src/discovery/Signature.cpp#L62)), magics of
at least 2 bytes, unique names across files, and every unknown scalar key
goes into `Signature::extra` for the validator.

### The scanner

`scan()` ([Scan.cpp:192](../src/discovery/Scan.cpp#L192)) is a multi-pattern
search:

- **Chunking.** The Span is walked in 16 MiB chunks
  ([Scan.cpp:35](../src/discovery/Scan.cpp#L35)), zero-copy through
  `Span::view` when the Source maps, otherwise `Span::read` into a buffer.
  Chunks overlap by `max_magic_len - 1` so nothing straddling an edge is lost.
- **Probe table.** `compile()` ([Scan.cpp:48](../src/discovery/Scan.cpp#L48))
  builds a 64 Ki-entry flag table keyed by the first two magic bytes; the
  inner loop is one load and one probe per byte, and only a probe hit
  consults the candidate list.
- **magic_offset and alignment.** `on_hit()`
  ([Scan.cpp:217](../src/discovery/Scan.cpp#L217)) computes
  `start = hit - magic_offset` (an ext superblock magic sits at +0x438) and
  drops hits whose structure would begin before the Span or whose start is
  not a multiple of `alignment` (QNX6 uses 4096, JFFS2 4).
- **Same-signature coverage.** A finding at Consistent or better with a size
  records `covered_until` ([Scan.cpp:255](../src/discovery/Scan.cpp#L255));
  later hits of the same signature inside that range are skipped, which is
  why a JFFS2 with 2519 nodes is one finding.
- **also_covers.** A validator may set `attrs["also_covers"]` to
  `"offset:length;..."` ([Scan.cpp:99](../src/discovery/Scan.cpp#L99)); the
  MBR validator uses it to hide the EBR link sectors it already walked
  ([mbr.cpp:188](../src/discovery/validators/mbr.cpp#L188)).

### Validators, the registry and force-link anchors

A `Validator` ([Signature.h:105](../include/omnitrace/discovery/Signature.h#L105))
is `optional<Finding>(const Span&, uint64_t start, const Signature&)`.
`OMNITRACE_REGISTER_VALIDATOR` ([Signature.h:139](../include/omnitrace/discovery/Signature.h#L139))
expands to a namespace-scope static whose constructor calls
`ValidatorRegistry::add`. `src/discovery/validators/common.h` supplies
`make_finding`, `diag`, `extra_u64`, `clamp_size` and saturating arithmetic;
[romfs.cpp](../src/discovery/validators/romfs.cpp) is the smallest complete
example.

Static registration has a linker problem: `omnitrace_discovery` is a static
library, and the linker only pulls an object file out of an archive when
something references a symbol in it. Nothing references `romfs.o`, so its
registrar would be dropped and the validator silently missing. The fix is
[validators/anchors.h](../src/discovery/validators/anchors.h): every
validator file ends with `OMNITRACE_VALIDATOR_ANCHOR(name)`, which defines an
empty function; [validators/builtin.cpp:30](../src/discovery/validators/builtin.cpp#L30)
calls every anchor from `link_builtin_validators()`; and
`ValidatorRegistry::find()` ([Signature.cpp:45](../src/discovery/Signature.cpp#L45))
calls that. Pulling the registry in pulls every validator. The filesystem and
container registries use the same trick
([src/filesystems/Registry.cpp:15](../src/filesystems/Registry.cpp#L15),
[src/containers/Registry.cpp:14](../src/containers/Registry.cpp#L14)).

### Conflict resolution

`resolve()` ([Scan.cpp:149](../src/discovery/Scan.cpp#L149)) sorts findings by
the total order `before()` ([Scan.cpp:131](../src/discovery/Scan.cpp#L131)):
offset ascending, then confidence descending, then size descending, then
signature name, then format. It then keeps or absorbs each finding:

1. Same offset as a kept finding: absorbed into that finding's
   `also_matched` (the sort order already put the higher confidence, then
   larger, then alphabetically first one in front).
2. Fully inside a kept finding that outranks it (`outranks`,
   [Scan.cpp:160](../src/discovery/Scan.cpp#L160)): absorbed by the innermost
   such finding. Outranking is strictly higher confidence, or — for a
   compressed stream (category `compressed`) inside anything that is not one —
   containment at any tier.
3. Otherwise kept. Equal-confidence nesting and partial overlaps stay visible.
4. A partition-table finding is only ever absorbed by another partition
   table (`may_absorb`, [Scan.cpp:150](../src/discovery/Scan.cpp#L150)), so a
   filesystem at LBA 0 cannot hide the MBR beneath it.

Example, from `router.bin`: the SquashFS at `0x1c9245` is Consistent (85) with
a size, and every xz stream found inside it lands in its `also_matched`, so
`scan --json` reports three top-level findings (uimage, squashfs, jffs2) and
shows the streams nested under the SquashFS. How many appear there is an
artefact of the scan, not a contract: an xz stream that the validator measures
covers the blocks stored after it, and the same-signature coverage skip then
does not re-report those, so the list is shorter than the number of blocks.

The compressed-stream clause in rule 2 is what keeps that working when the
tiers move, and both of them do: a SquashFS whose `bytes_used` runs past the
data is demoted to Structural by `squashfs-truncated`, and a gzip or xz stream
the validator walked to its end is promoted to Consistent. Under strict ranking
a 1 GiB-truncated image from the QNX corpus reported 131 spurious top-level
containers instead of one filesystem. Tests:
[tests/unit/discovery/resolve_test.cpp](../tests/unit/discovery/resolve_test.cpp).

## 5. Recurse: the passes of analyze()

`analyze()` ([Recurse.cpp:1288](../src/discovery/Recurse.cpp#L1288)) is the
driver the CLI calls. In order:

| # | Pass | Where |
|---|---|---|
| 1 | Hash the image (`hash_span`), append an `Evidence` row and the Image node | [Recurse.cpp:1294](../src/discovery/Recurse.cpp#L1294), [:1303](../src/discovery/Recurse.cpp#L1303) |
| 2 | Word-swap detection; pick the Source view the rest runs on | [Recurse.cpp:1324](../src/discovery/Recurse.cpp#L1324) |
| 3 | `analyze_span()` scans the whole Span (`run_scanner`) | [Recurse.cpp:698](../src/discovery/Recurse.cpp#L698), [:705](../src/discovery/Recurse.cpp#L705) |
| 4 | Partition tables to Partition nodes: `choose_tables()` folds a GPT backup into its primary, each table becomes a `role: table` node plus one node per entry from `parse_partitions()`; a table lying inside an entry of an earlier table is kept as `nested: true` with no entries | [Recurse.cpp:710](../src/discovery/Recurse.cpp#L710), [:342](../src/discovery/Recurse.cpp#L342), [:252](../src/discovery/Recurse.cpp#L252) |
| 5 | Per-partition rescan: a partition with nothing at its first byte (and not uniformly filled) is scanned on its own sub-Span; hits at offset 0 are kept with `partition-rescan` | [Recurse.cpp:851](../src/discovery/Recurse.cpp#L851) |
| 6 | Claims and gaps: every sized finding claims `[offset, end)`; `note_gaps()` turns unclaimed space of at least `min_region_bytes` into gap items, at the top level and inside every partition | [Recurse.cpp:878](../src/discovery/Recurse.cpp#L878), [:679](../src/discovery/Recurse.cpp#L679) |
| 7 | Nodes in byte order: `parent_for()` picks the innermost enclosing extent (containment parenting), `kind_for()` maps category to NodeKind, gaps become `unidentified` Region nodes with `fill` when uniform | [Recurse.cpp:906](../src/discovery/Recurse.cpp#L906), [:180](../src/discovery/Recurse.cpp#L180), [:194](../src/discovery/Recurse.cpp#L194), [:638](../src/discovery/Recurse.cpp#L638) |
| 8 | Filesystem walks: `process_filesystem()` opens the reader over the finding's sub-Span, walks it through `walk_into_sink()` into a `DiskSink` or `ListingSink`, adds one File node per `EntryResult`, and records a Coverage row (`supported`, `partial`, `unsupported`) | [Recurse.cpp:515](../src/discovery/Recurse.cpp#L515), [:394](../src/discovery/Recurse.cpp#L394), [:441](../src/discovery/Recurse.cpp#L441) |
| 9 | Nested analysis: every file the walk wrote to the host is mapped and re-scanned by `descend_into_file()`; one holding a filesystem or a partition table at Structural or better and at least `min_region_bytes` long gets `nested_image: true` and the whole pass again with the File node as parent and `depth + 1`, so offsets under it are relative to that file and `Location::source_id` names it. `Ctx::extents` is swapped out for the nested call because extents are Span-relative, while the run-wide `max_files` / `max_bytes` budgets are deliberately shared. The depth cap is checked once per filesystem, not once per file | [Recurse.cpp:482](../src/discovery/Recurse.cpp#L482), [:596](../src/discovery/Recurse.cpp#L596) |
| 10 | Carving: `carve_all()` streams every partition entry and (with `Carve::All`) every nested find directly under the image or a partition to `partitions/<name>.bin`, hashing as it writes, then writes `mount.sh` from `mount_script_text()` | [Recurse.cpp:1005](../src/discovery/Recurse.cpp#L1005), [:946](../src/discovery/Recurse.cpp#L946), [:1133](../src/discovery/Recurse.cpp#L1133) |
| 11 | Coverage bookkeeping throughout: `set_coverage()` keeps one row per format and never lets `supported` overwrite `partial`; `carve_partial()` accumulates skipped carves | [Recurse.cpp:145](../src/discovery/Recurse.cpp#L145), [:161](../src/discovery/Recurse.cpp#L161) |

Two rules the code enforces that are easy to miss:

- A finding of size 0 claims no bytes and parents nothing
  ([Recurse.cpp:238](../src/discovery/Recurse.cpp#L238)); a magic-only zip
  hit never swallows the filesystems after it.
- Node insertion order is tables and entries first, then everything else in
  byte order, so ids are stable across runs
  ([Recurse.cpp:3](../src/discovery/Recurse.cpp#L3)).

`analyze_span()` is called recursively for extracted files (pass 9). The
container payload is the remaining case: a Container node is recognised and
carved but never opened, because no `container::ContainerReader` is registered,
so each one produces an `unsupported` Coverage row and an `analyze-no-reader`
diagnostic. The hand-off is the comment at the end of `analyze_span()`
([Recurse.cpp:933](../src/discovery/Recurse.cpp#L933)); the extracted-file path
already provides the depth accounting and the extent isolation it needs.

### The Node graph for router.bin

`omnitrace analyze router.bin --out case --no-extract` produces this Map in
`INFO.md` (files omitted; they are under `n000004`):

```
- n000001 image raw "router.bin" @ 0x0 16.0 MiB (16777216) [verified (99)]
  - n000002 region "unidentified" @ 0x0 320.0 KiB (327680) [reject (0)]
  - n000003 container uimage "MIPS OpenWrt Linux-4.14.63" @ 0x50000 1.5 MiB (1544773) [verified (99)]
  - n000004 filesystem squashfs "squashfs" @ 0x1c9245 10.5 MiB (11055104) [consistent (85)]
  - n003388 region "unidentified" @ 0xc54245 47.4 KiB (48571) [reject (0)]
  - n003389 filesystem jffs2 "jffs2" @ 0xc60000 3.6 MiB (3735564) [verified (99)]
  - n003390 region "unidentified" @ 0xff000c 64.0 KiB (65524) [reject (0)]
```

`n000005` to `n003387` are the 3383 File nodes the SquashFS reader emitted.
With `--no-extract` nothing reaches the host, so nothing is re-scanned; a run
that extracts also descends into every file either reader wrote.

## 6. Filesystems: the reader contract and SquashfsReader

`FilesystemReader` ([Filesystem.h:81](../include/omnitrace/filesystems/Filesystem.h#L81))
has four methods: `format()`, `open(span)`, `info()`, `walk(sink, opts, out)`.
`WalkOptions` carries `extract_data`, `history` and `Limits`; `WalkResult`
returns counts, `truncated`, diagnostics and every `EntryResult`.
Registration is `OMNITRACE_REGISTER_FILESYSTEM("format", Reader)`
([Filesystem.h:129](../include/omnitrace/filesystems/Filesystem.h#L129)) plus an
anchor line in [src/filesystems/Registry.cpp:15](../src/filesystems/Registry.cpp#L15).

[SquashfsReader](../src/filesystems/squashfs/SquashfsReader.cpp) is the
worked example; [formats/squashfs.md](formats/squashfs.md) has the layout.

| Step | Function | What it does |
|---|---|---|
| open | `open()` [:1308](../src/filesystems/squashfs/SquashfsReader.cpp#L1308) → `parse_superblock()` [:356](../src/filesystems/squashfs/SquashfsReader.cpp#L356) | picks byte order from the magic (vendor magics: whichever order reads major 4), validates block_log, `bytes_used`, table order; then `load_compressor_options()`, `load_id_table()`, `load_xattr_header()` |
| metadata cache | `meta_block()` [:528](../src/filesystems/squashfs/SquashfsReader.cpp#L528) | decodes one 8 KiB metadata block on demand into a 64-entry LRU ([:71](../src/filesystems/squashfs/SquashfsReader.cpp#L71)); `meta_read()` reads across block boundaries through a `MetaCursor` |
| inode walk | `walk()` [:1345](../src/filesystems/squashfs/SquashfsReader.cpp#L1345) → `walk_dir()` [:1157](../src/filesystems/squashfs/SquashfsReader.cpp#L1157) | iterative stack of directory frames (no recursion on hostile depth); `read_inode()` [:679](../src/filesystems/squashfs/SquashfsReader.cpp#L679) and `read_directory()` [:803](../src/filesystems/squashfs/SquashfsReader.cpp#L803) parse through the cursor; `make_meta()` [:872](../src/filesystems/squashfs/SquashfsReader.cpp#L872) fills `FileMeta` |
| streaming data | `emit_regular()` [:1128](../src/filesystems/squashfs/SquashfsReader.cpp#L1128) → `stream_file()` [:988](../src/filesystems/squashfs/SquashfsReader.cpp#L988) | `begin_file`, then one `write()` per decoded data block and the fragment tail, then `end_file`; never more than one block in memory; a Sink refusal or a limit marks the entry `truncated` |
| diagnostics | codes at [:74](../src/filesystems/squashfs/SquashfsReader.cpp#L74) | `squashfs-metadata-corrupt`, `squashfs-block-corrupt`, `squashfs-limit-*`, `squashfs-sink-error`, ...; open-time findings are replayed at the start of every walk |

The reader holds a `const Limits*` for the walk in progress
([:273](../src/filesystems/squashfs/SquashfsReader.cpp#L273)); every guard
reads a `Limits` field, never a constant.

`ContainerReader` ([Container.h:40](../include/omnitrace/containers/Container.h#L40))
has the identical shape for archives and wrappers; no container reader is
registered yet.

## 7. Output

- **YAML.** `manifest_to_yaml()` ([Yaml.cpp:945](../src/output/Yaml.cpp#L945))
  emits keys in a fixed order: `schema`, `run`, `evidence`, `nodes`,
  `coverage`, `tools`, `diagnostics`. Each node
  ([Yaml.cpp:224](../src/output/Yaml.cpp#L224)) is `id`, `parent`, `kind`,
  `name`, `format`, `location{source, offset, offset_hex, length}`,
  `confidence`, `evidence`, `endian`, `attrs`, then `file`, `digests` only
  when present, `diagnostics`, `children`. `attrs` is a `std::map`, so it is
  already sorted. Every string goes through `sanitize_utf8`
  ([Yaml.cpp:83](../src/output/Yaml.cpp#L83)). `manifest_from_yaml()`
  ([Yaml.cpp:1009](../src/output/Yaml.cpp#L1009)) parses it back, and the CLI
  refuses to exit 0 unless re-serialising is byte-identical.
- **JSON schema.** `manifest_json_schema()`
  ([Yaml.cpp:1075](../src/output/Yaml.cpp#L1075)) builds the draft 2020-12
  schema in code; `docs/schema/manifest.schema.json` must equal it
  ([schema_test.cpp:144](../tests/unit/output/schema_test.cpp#L144)).
- **Listings.** `listing_to_yaml()` ([Yaml.cpp:1052](../src/output/Yaml.cpp#L1052))
  writes one document per walked filesystem.
- **Markdown.** `summary_markdown()` ([Markdown.cpp:190](../src/output/Markdown.cpp#L190))
  renders Run, Evidence, Nodes by kind, Map, Coverage and Diagnostics;
  `partitions_markdown()` and `listing_markdown()` follow. All of them are
  rendered from the Manifest and never hand-edited; `md_escape` and
  `sanitize_utf8` run on every cell.

Determinism is tested end to end: `TEST(Analyze, Deterministic)`
([recurse_test.cpp:511](../tests/unit/discovery/recurse_test.cpp#L511)) and
`TEST(Yaml, Deterministic)` ([yaml_test.cpp:85](../tests/unit/output/yaml_test.cpp#L85)).

## 8. The CLI

| File | Role |
|---|---|
| [apps/cli/main.cpp](../apps/cli/main.cpp) | CLI11 app, `--version`, `-v`, the `hash` subcommand, and one `register_*_commands` call per module ([main.cpp:48](../apps/cli/main.cpp#L48)) |
| [apps/cli/commands.h](../apps/cli/commands.h) | declares `register_analyze_commands(CLI::App&)` and `set_process_argv` |
| [apps/cli/analyze_commands.cpp](../apps/cli/analyze_commands.cpp) | `cmd_scan()` ([:158](../apps/cli/analyze_commands.cpp#L158)) prints the table or JSON; `cmd_analyze()` ([:304](../apps/cli/analyze_commands.cpp#L304)) builds `AnalyzeOptions`, calls `analyze()`, writes the case directory, round-trips the manifest ([:362](../apps/cli/analyze_commands.cpp#L362)); `info_markdown()` ([:243](../apps/cli/analyze_commands.cpp#L243)), `source_yaml()` ([:229](../apps/cli/analyze_commands.cpp#L229)), `alias_manifest()` ([:276](../apps/cli/analyze_commands.cpp#L276)); options registered at [:422](../apps/cli/analyze_commands.cpp#L422) |

Flags and the case layout are documented in [CLI.md](CLI.md) and
[CASE_LAYOUT.md](CASE_LAYOUT.md). Failures throw `CLI::RuntimeError(1)` so
exit status is always 0 or 1.

## 9. Tests

`ctest --preset linux-gcc` runs four executables, one per layer with tests:
`core`, `output`, `discovery`, `filesystems`.

| Kind | Where | Feeds on |
|---|---|---|
| Core unit tests | `tests/unit/core/*_test.cpp` (span, source, sink, hash, compression, text, swap, clock, manifest, node, diagnostics) | in-memory bytes |
| Output snapshots and schema | `tests/unit/output/` with a shared full Manifest in [fixture.h](../tests/unit/output/fixture.h); `hostile_strings_test.cpp` feeds raw evidence bytes through every serializer | in-memory |
| Signature / scanner / resolver | `tests/unit/discovery/{toml,scan,resolve}_test.cpp` with helpers in [helpers.h](../tests/unit/discovery/helpers.h) (`span_of`, `NoMapSource`, `put_u32le`, `only({...})`, CRC oracles) | hand-built bytes |
| Validators | `validators_test.cpp`, `validators2_test.cpp`, `partition_test.cpp`: minimal accepted instance, corrupted and truncated variants, then `Fixture` cases guarded by `test::fixture_exists()` | `tests/fixtures/out/*.img` |
| Recurse | `recurse_test.cpp`, `swap_recurse_test.cpp`: `opts.scanner` and `opts.open_reader` are swapped for fakes so the graph logic is tested without real readers | in-memory |
| Corpus | `router_test.cpp`, `Corpus2` cases: skipped unless the image exists | `router.bin`, a local corpus |
| Readers | `tests/unit/filesystems/squashfs_test.cpp`: `SquashfsSynth` (byte-built image), `SquashfsHostile` (truncation at every offset, seeded flips), `SquashfsMksquashfs` (real `mksquashfs` round trip per codec, `diff -r` after DiskSink), `SquashfsFixture` (against `expected.yaml`), `SquashfsCorpus` (against `unsquashfs`) | tools on the host, fixtures, corpus |

`omnitrace_module` defines `OMNITRACE_TEST_DATA_DIR` as `tests/fixtures`
([cmake/Warnings.cmake:48](../cmake/Warnings.cmake#L48)); the helpers append
`/out`. Fixtures come from `tests/fixtures/generate.py` (run through
`scripts/fixtures.sh build`), which writes `<name>.expected.yaml` beside each
image; the parity harness `tests/parity/run.py` diffs OmniTrace against
unblob, binwalk and moria on the same images. Both are described in
[TESTING.md](TESTING.md).

## 10. Where to go next

- Adding a signature, validator, reader, subcommand, fixture or Coverage
  row: [EXTENDING.md](EXTENDING.md).
- The rules every change must keep: [ARCHITECTURE.md](ARCHITECTURE.md).
- Per-format layout, tiers and diagnostic codes: [formats/](formats/README.md).
- The case directory contract other tools read: [CASE_LAYOUT.md](CASE_LAYOUT.md).
