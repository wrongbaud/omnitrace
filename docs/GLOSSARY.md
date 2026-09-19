# Glossary

This page is for anyone reading OmniTrace code, output or docs who meets a project word and wants the one-paragraph meaning and the header that defines it. After reading it you can read `INFO.yaml`, a validator, or a reader test without guessing what a term implies.

Each entry names the C++ type or header where the word is defined so you can jump from the word to the contract.

**Span** (`include/omnitrace/core/Span.h:62`). A bounds-checked window `[base, base+len)` over a Source; every accessor (`at<T>`, `u8`, `bytes`, `view`, `read`, `cstring`, `matches_at`) returns `std::optional` or a byte count, so an attacker-controlled offset yields `nullopt`, never an out-of-bounds read. All evidence bytes in the project are read through a Span; `sub()` narrows it and `absolute()` maps back to Source coordinates for provenance.

**Source** (`include/omnitrace/core/Source.h:30`). A read-only byte provider with a stable `id()`: `MappedFile` (mmap / MapViewOfFile, `:88`), `MemorySource`, `SubSource` (a range of a parent, `:124`), and `SwappedSource` (`core/Swap.h:37`, a word-swap corrected view). Node locations record the Source id, so a finding read through `router.bin|swap32` says so.

**Node** (`include/omnitrace/core/Node.h:94`). One vertex of the evidence graph: the image, a partition, a container, a filesystem, a file, a region or (Phase 2) an artifact, with a `Location {source_id, offset, length}`, a confidence score, `attrs`, diagnostics and child ids. `Manifest::add_node` assigns ids `n` + six digits in insertion order, which is why the same image analysed twice gets the same ids.

**Finding** (`include/omnitrace/discovery/Signature.h:66`). What the scanner returns before anything becomes a Node: a structure start, a size (0 when unknown), format, category, the signature that hit, a confidence tier, evidence text, attrs and diagnostics. `also_matched` holds the lower-confidence findings that conflict resolution suppressed at the same bytes.

**Partition node vs table node** (`include/omnitrace/discovery/Recurse.h`, `docs/CASE_LAYOUT.md`). A partition-table finding becomes one Partition node for the table itself (`attrs.role: table`, sized to the sector or the GPT header plus entry array) and one Partition node per entry beneath it, named from the GPT label or the slot (`p6`). The table node never claims the disk, so the filesystems inside partitions are parented under the entries, not swallowed by the table.

**Sink** (`include/omnitrace/core/Sink.h:75`). Where readers send extracted entries instead of touching the host filesystem: `DiskSink` writes under a root with a safe path walk and hashes as it writes, `ListingSink` records metadata (and optional hashes) without writing. Every entry yields an `EntryResult` that becomes a File node.

**Coverage row** (`include/omnitrace/core/Node.h:115`). One `{format, status, detail}` record per capability the run exercised or could not: `supported`, `partial` (something was left behind, `detail` says what), `unsupported` (recognised, no reader), `tool-missing` (reserved for external tools). A coverage row is how "we saw JFFS2 but cannot extract it yet" is said out loud in `INFO.md`.

**Diagnostic code** (`include/omnitrace/core/Diagnostics.h:30`). A `Diagnostic {severity, code, message}` attached to a node, a finding, an entry or the run; `code` is a stable kebab-case slug such as `gpt-primary-missing` or `squashfs-limit-files` that tests and agents key on, `message` is the human sentence. Codes never change meaning once shipped, because downstream tools match on them.

**Confidence tier** (`include/omnitrace/core/Diagnostics.h:42`). The named score a validator assigns: `magic` (25, bytes matched only), `structural` (60, header parsed and hard constraints hold), `consistent` (85, cross-field checks hold), `verified` (99, a CRC or a decode probe succeeded); `reject` (0) is a Region. Conflict resolution and partition parenting compare these numbers, so a tier is a decision, not a label.

**Superseded vs deleted** (`include/omnitrace/core/Node.h:86`). Both are flags on `FileMeta`, set only when a reader runs with `WalkOptions::history`. `superseded` is an older version of a file that still has a live directory entry (JFFS2 keeps every version on flash); `deleted` is an entry with no live directory entry pointing at it. Both land under `files/.omnitrace-versions/<path>/v<version>` so the live tree stays a faithful copy.

**Carve** (`docs/CASE_LAYOUT.md`, `src/discovery/Recurse.cpp:1048` neighbourhood). Streaming the exact bytes of a node, `location.offset .. offset+length`, into `partitions/<name>.bin` while hashing, so an examiner can hash, mount or hand that file to another tool. `--carve none|table|all` chooses what is carved and `--max-carve-bytes` caps the size; a skipped carve is a `carve` coverage row, never a silent gap.

**Case directory** (`docs/CASE_LAYOUT.md`). The output of `omnitrace analyze`: `INFO.yaml` (the manifest), `INFO.md`, `flash/SOURCE.yaml`, `partitions/`, `filesystems/<node-id>/`. The directory is the API: people read the Markdown, agents read the YAML, and every partition is a file.

**Signature vs validator** (`include/omnitrace/discovery/Signature.h:45` and `:105`). A signature is a declarative TOML entry in `signatures/*.toml`: a magic, where it sits, a category and optionally the name of a validator. A validator is the C++ function registered with `OMNITRACE_REGISTER_VALIDATOR` that parses the structure behind the magic and decides the tier, the size and the attrs; a signature without a validator stays at tier `magic` with unknown size.

**Parity** (`tests/parity/run.py`, `docs/TESTING.md`). Running unblob, binwalk, moria and OmniTrace over the same image, normalising their findings and extracted files into one shape, and diffing by offset and by path plus SHA-256. Parity is the acceptance bar for readers: byte-identical to the reference tool where the reference tool is right, and explained where it is not.

**Fixture** (`tests/fixtures/generate.py`, `docs/TESTING.md`). A synthetic image built reproducibly inside Docker with a known file tree and, where the format keeps history, a scripted create/overwrite/delete script, plus a `<name>.expected.yaml` that states the ground truth. Unit tests find them under `tests/fixtures/out/` (`OMNITRACE_TEST_DATA_DIR`, compiled in as `tests/fixtures`, plus `/out`) and skip when a fixture is not built.
