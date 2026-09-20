# Signatures and validators

The discovery layer turns raw bytes into `Finding`s in two steps: a
multi-pattern magic scan driven by declarative TOML signatures, then an
optional C++ validator per signature that parses the structure behind the
magic and decides how much to trust it. Everything here lives in
`src/discovery/`, `signatures/*.toml` and `include/omnitrace/discovery/Signature.h`.

## TOML schema

Every file under `signatures/` is an array of tables:

```toml
[[signature]]
name = "squashfs-le"        # required, unique across all loaded files
format = "squashfs"         # required, canonical format id (Node::format, reader lookup)
category = "filesystem"     # required, one of the list below
magic = "hsqs"              # exactly one of magic (literal bytes) or hex
hex = "68737173"            #   hex accepts spaces, ':' or '_' separators and an 0x prefix
magic_offset = 0            # where the magic sits relative to the structure start
endian = "little"           # optional, "little" or "big": the byte order implied by this magic
validator = "squashfs"      # optional, registered validator name
alignment = 1               # optional, only accept hits whose structure start is a multiple
description = "..."         # optional
references = ["https://…"]  # optional array of strings
max_entries = 1024          # any other key is passed to the validator via Signature::extra
```

Categories: `filesystem`, `container`, `partition-table`, `kernel`,
`bootloader`, `compressed`, `crypto`, `other`.

Rules enforced by `SignatureSet::load_toml`:

* Magics are at least 2 bytes (the scanner indexes on the first two bytes).
* Unknown categories, negative offsets, bad hex, and non-scalar extra keys are errors.
* Duplicate `name`s are errors, also across files. Loading is all-or-nothing per file.
* Errors come back as `Status::fail("<origin>: signature[i] (name): …")`; nothing throws.

`SignatureSet::builtin()` returns the signatures embedded at build time from
`signatures/*.toml` (see `src/discovery/cmake/embed_signatures.cmake`; files
are embedded in sorted name order so the set is deterministic). `load_file`
and `load_toml` add user signatures to any set.

## Scanner

`scan(span, sigs, opts)` walks the Span in 16 MiB chunks (zero-copy through
`Span::view` when the Source maps, otherwise `Span::read` into a buffer),
overlapping chunks by `max_magic_len - 1` so nothing straddling an edge is
lost. A 64 Ki-entry table keyed by the first two magic bytes keeps the inner
loop to one probe per byte. For each hit:

1. `start = hit - magic_offset`; hits whose structure would begin before the
   Span are dropped, as are hits where `start % alignment != 0`.
2. If the signature names a validator and `opts.validate` is set, it runs.
   `nullopt` drops the hit. A validator name that is not registered produces
   a `Confidence::Magic` finding with diagnostic `validator-missing` (silence
   is a bug).
3. Otherwise the hit is a `Confidence::Magic` finding of unknown size (0).

**Same-signature coverage.** When a finding at `Consistent` or better reports
a size, later hits of the *same signature* inside that range are not
validated or reported: they are the nodes, erase blocks or archive members of
the structure already found (JFFS2, UBI, tar, cpio). This keeps the scan
linear on node-based formats. Hits of other signatures inside the range are
still validated and then subject to conflict resolution.

`opts.max_hits` stops the scan; the last finding carries `scan-hit-limit`.

## Conflict resolution

With `opts.resolve_conflicts` (default) findings are sorted by
`(offset, -confidence, -size, signature name, format)` and then:

* a finding at exactly the same offset as an already-kept finding is moved
  into that finding's `also_matched` (the higher confidence, then the larger,
  then the alphabetically first name wins);
* a finding whose `[offset, offset+size)` lies inside a kept finding's range
  with **strictly higher** confidence is moved into that finding's
  `also_matched` (innermost container wins);
* the one exception: a finding of category `compressed` is absorbed by any
  enclosing finding that is not itself a compressed stream, **at any tier**;
* everything else is kept. Equal-confidence nesting is otherwise kept (an ext4
  inside an MBR partition stays visible), and partial overlaps are kept.

The exception exists because a SquashFS or JFFS2 is *built out of* gzip, xz,
lz4 and zstd blocks: those hits are the filesystem's data, not separate finds.
Tier ordering is the wrong instrument for saying so, and both sides of the
comparison move. A SquashFS cut short by an extraction limit is demoted to
`structural` by `squashfs-truncated`, because a cut image cannot show its
tables; a gzip or xz stream the validator walked to its end reaches
`consistent`. Either one alone flips a strict comparison, and the truncated
case produced 131 spurious top-level containers out of one filesystem.
Containment is the real argument — bytes inside a sized structure belong to it
— so that is what the rule uses. Only a sized finding can own anything (a
size-0 finding has no extent), so a bare magic hit cannot swallow a stream,
and absorption is one-directional, so two nested streams both stay visible.

Without resolution the same total order is still applied, so output is
byte-identical run to run.

## Validator contract

```cpp
using Validator = std::function<std::optional<Finding>(const Span& span, std::uint64_t start, const Signature& sig)>;
OMNITRACE_REGISTER_VALIDATOR("name", fn);
```

* Read only through `Span` accessors (`at<T>`, `u8`, `bytes`, `read`,
  `cstring`, `matches_at`). Never throw; never assume the structure fits.
* Return `nullopt` to reject a hit that is noise. Prefer downgrading to
  `Confidence::Magic` with a diagnostic when the magic is long enough that a
  random hit is implausible (8-byte "EFI PART") and the header is merely
  corrupt; prefer rejecting when the magic is short (2-byte JFFS2, ext 0xEF53,
  MBR 0x55AA) and the only discriminator failed.
* Fill `confidence`, `size` (0 = unknown), `attrs`, `evidence`, `diagnostics`,
  `endian`; `format`/`category` may be overridden (ext → `ext4`, uImage kernel
  → `kernel`). The scanner fills `signature` and prefixes the magic evidence.
* Clamp `size` to the Span and add a `<fmt>-truncated` diagnostic rather than
  claiming bytes that do not exist.
* Limits that a validator needs (EBR chain length, GPT entry cap, gzip name
  length) come from `Signature::extra`, i.e. from the TOML, not from constants.
* Diagnostics use stable kebab-case codes: `<fmt>-truncated`,
  `<fmt>-…-crc-mismatch`, `<fmt>-bad-<field>`, `<fmt>-unsupported-version`.

The validator's `.cpp` also carries `OMNITRACE_VALIDATOR_ANCHOR(name)` and a
line in `src/discovery/validators/builtin.cpp`, so the static library keeps
the object file (see `validators/anchors.h`).

## Confidence tiers

| Tier | Score | Assigned when |
|---|---|---|
| magic | 25 | magic matched; nothing else checked, or the header was corrupt |
| structural | 60 | header parsed and every hard constraint holds |
| consistent | 85 | cross-field checks hold (tables inside `bytes_used`, counts agree, chunk list closes) |
| verified | 99 | a CRC checked out (JFFS2 node header, UBI EC header, uImage header, GPT header + entries, ext4 `metadata_csum`) |

## Builtin validators

| validator | format(s) | tier reachable | size |
|---|---|---|---|
| squashfs | squashfs (LE/BE/vendor magics) | consistent | bytes_used rounded up to 4 KiB |
| jffs2 | jffs2 | verified | walk of nodes across erased/dirty gaps up to `max_gap` (obsolete nodes CRC-checked with the accurate bit re-set); trailing erased space excluded; erase size inferred from cleanmarkers |
| ubi | ubi | verified | PEB size derived from the next EC header; walk of PEBs |
| ext | ext2 / ext3 / ext4 | verified (metadata_csum) | blocks_count × block_size |
| mbr | mbr | consistent | 512 (the table sector); the disk is described in attrs (`disk_size`), EBR chains walked and their sectors hidden via `also_covers` |
| gpt | gpt | verified | the table's own extent: LBA 0 through the end of the entry array (primary) or entry array plus header sector (backup); the disk extent is attrs `disk_size` / `disk_offset` |
| uimage | uimage (category kernel for kernels) | verified | 64 + data size; payload CRC checked |
| gzip | gzip | structural | unknown |
| xz | xz | structural (flags CRC guards it; mismatch drops to magic) | unknown |
| lz4 | lz4 | structural | unknown |
| zstd | zstd | structural | unknown |
| android-sparse | android-sparse | consistent | chunk walk |
| dtb | dtb | consistent | FDT `totalsize`; header and token stream validated ([dtb.md](dtb.md)) |
| fit | fit | verified (crc32/md5/sha1/sha256 image hashes) | `totalsize` or the end of external image data ([fit.md](fit.md)) |
| verity | dm-verity | consistent | superblock block + computed hash tree ([verity.md](verity.md)) |
| luks | luks | consistent | LUKS1 payload offset; LUKS2 `hdr_size` x 2 ([luks.md](luks.md)) |
| romfs | romfs | verified (header checksum) | full size rounded to 1 KiB ([romfs.md](romfs.md)) |
| cramfs | cramfs (both orders) | verified (image CRC) | superblock size field ([cramfs.md](cramfs.md)) |
| android-boot | android-boot, android-vendor-boot | consistent | sum of page-aligned sections, v0-v4 ([android-boot.md](android-boot.md)) |
| ubifs | ubifs | verified (superblock node CRC) | `leb_size` x `leb_cnt`; aligned hits only ([ubifs.md](ubifs.md)) |
| elf | elf | consistent | max extent of program/section headers and segments; unaligned hits must reach consistent ([elf.md](elf.md)) |

| qnx6 | qnx6-le, qnx6-be | verified (superblock CRC-32) | `data_start + num_blocks x blocksize` plus the trailing superblock; `alignment = 4096` ([qnx6.md](qnx6.md)) |
| qnx-ifs | qnx-ifs | verified (image / compressed-area checksum) | stored size, or the walked compressed block chain ([qnx-ifs.md](qnx-ifs.md)) |

Plain magics (no validator) in `core.toml`: cpio (newc/crc/odc), tar (ustar at
257), zip, 7z, PEM certificate / key / CRL labels, OpenSSH and PGP keys.
yaffs2 is deliberately absent until OOB-aware validation exists.

`crypto.toml` holds the LUKS and dm-verity signatures. The FDT magic
`0xd00dfeed` is claimed by two signatures: `fit-dtb` (validator `dtb`,
format `dtb`) and `fit` (validator `fit`, format `fit`). At the same offset
the dtb validator steps back to structural when the root has `/images`, so
the FIT wins and the DTB lands in `also_matched`; DTB images inside a
verified FIT are absorbed by the nesting rule.

Signature keys read by validators through `Signature::extra`: `max_gap`
(jffs2), `max_nodes` / `max_props` / `max_depth` (dtb, fit), `max_hash_bytes` (fit), `max_json`
(luks), `max_name_len` (romfs, gzip), `ebr_max_chain` (mbr), `max_entries`
(gpt).

## Adding a signature or validator

1. Add a `[[signature]]` to the right `signatures/<category>.toml`. Rebuild;
   the file is embedded automatically.
2. For a validator, add `src/discovery/validators/<name>.cpp` following the
   contract above, register it with `OMNITRACE_REGISTER_VALIDATOR`, add the
   anchor and the `builtin.cpp` line.
3. Tests in `tests/unit/discovery/`: a hand-built minimal structure that is
   accepted at the intended tier, a corrupted one that is rejected or
   downgraded with the expected diagnostic code, truncated and absurd-size
   variants, and a fixture check when `tests/fixtures/out/` has one.
4. Document the on-disk layout and diagnostic codes in `docs/formats/<name>.md`.
