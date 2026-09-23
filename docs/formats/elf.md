# ELF

`src/discovery/validators/elf.cpp` (validator `elf`), signature `elf` in
`signatures/core.toml` (format `elf`, category `other`).

## On-disk layout

`e_ident`: `\x7fELF`, `EI_CLASS` (1 = 32-bit, 2 = 64-bit), `EI_DATA` (1 =
little, 2 = big), `EI_VERSION` (1), `EI_OSABI`. Then `e_type` u16,
`e_machine` u16, `e_version` u32 (1), `e_entry`, `e_phoff`, `e_shoff`
(class-sized), `e_flags` u32, `e_ehsize` u16 (52 / 64), `e_phentsize` u16
(32 / 56), `e_phnum`, `e_shentsize` u16 (40 / 64), `e_shnum`, `e_shstrndx`.

## Validation

Hard constraints (failure = reject, since the 4-byte magic occurs in
compressed and random data): class and data encoding in range, both
version fields 1, `e_ehsize` matching the class, `e_phentsize` /
`e_shentsize` matching the class when the table exists, tables not inside
the header, `e_shstrndx < e_shnum` (or `SHN_XINDEX`), `e_type` in the
defined or OS/processor-specific ranges.

Extent: the program header table, the section header table, every
`p_offset + p_filesz` and every non-`SHT_NOBITS` `sh_offset + sh_size`; the
maximum is the file size. A table or segment that runs past the data means
the header is not describing these bytes: at a 4-aligned offset the finding
is kept at structural with `size` 0 and `elf-truncated` (an ELF file cut by
a partition boundary); at an unaligned offset it is dropped, because files
inside filesystems and archives are at least 4-aligned and a magic in the
middle of compressed data is the usual cause (30+ such hits on the auto-emmc
eMMC image).

## Tiers

| tier | when |
|---|---|
| rejected | a hard constraint fails, or an unaligned hit does not reach consistent |
| structural | header sane, tables absent or outside the data |
| consistent | all tables and segments inside the data; `size` = extent |

## Attributes

`class` (32/64), `endian`, `type` (relocatable / executable /
shared-object / core / os- or processor-specific), `machine` (name for
common `e_machine` values, else `unknown(n)`), `machine_id`, `osabi`,
`entry`, `flags`, `program_headers`, `section_headers`.

## Diagnostics

`elf-truncated` (warning), `elf-no-tables` (info), `elf-extended-numbering`
(info: `PN_XNUM` / section-0 counts are not followed).

## Carving: an ELF inside a payload is written out

**Decision, and why.** An ELF found inside an extracted file — a decompressed
kernel, a firmware payload — is carved to `partitions/` with its digests, the
same as a nested find in the image itself. It was not, and the reason to
change it is narrow and concrete.

The dongle dongle's xz payload is one 23 MB file holding **222 complete ARM32
shared objects**, back to back, covering 96 % of it with thirteen gaps. They
are not fragments: each has section headers inside its claimed extent and a
dynamic section naming the libraries it needs. OmniTrace already located,
sized and typed every one of them — and gave them **no digests at all**,
because digests come from carving.

That is the whole argument. A forensic tool that can say "there is a complete
ARM shared object at offset 30984, 396,124 bytes long" but cannot say what it
hashes to has stopped one step short of useful: an examiner cannot match it
against a known-file set, cannot show two images carry the same library, and
cannot cite it in a report. Locating a binary and being unable to identify it
is the gap, not the missing bytes on disk — the bytes were always inside the
payload.

unblob reaches the same place from the other direction, writing each as
`<range>.elf32_extract/carved.elf`. The 252 contents it had and OmniTrace did
not, which `docs/PARITY.md` counted as a policy difference, were mostly this.

### What is and is not carved

A find inside an extracted file is carved when it is a **strict sub-range** of
that file, and not when it is the whole of it: the extracted file already is
those bytes, and carving would write a byte-identical second copy.

"The whole of it" is measured against the file's own size, which is the part
that is easy to get wrong. A File node's `location` is a position in the
*enclosing* structure — for a file inside a filesystem, its `length` is the
filesystem's length, not the file's — so comparing against that makes every
whole-file find look like a sub-range. Doing exactly that duplicated 52
tarballs and 52 gzip streams out of one router image before the rule was
fixed to use `file.size`.

Carved sub-ranges are named `<owner node>-<offset>-<format>.bin`, because an
offset alone does not say which payload it is an offset into, and two payloads
in one image routinely hold something at the same place.

The usual limits apply: `--carve none` turns it off, `--carve table` keeps only
partition entries, and `--max-carve-bytes` and the free-space guard bound it
as they bound every other carve.

### The cost

On the dongle dongle this takes `partitions/` from 14 files to 237, and from
15 MB to 37 MB for a 16 MB image — the payload's contents are stored twice,
once inside it and once beside it. That is the price of a hash per binary, and
it is bounded: every other corpus image gains between one and three carved
sub-ranges, because no other one holds a blob of concatenated executables.

## Known gaps

* Section names, dynamic sections, notes and build IDs are not read, so a
  carved shared object is named by its offset rather than by its `SONAME`.
  The name is right there in the file: reading it would turn
  `n000096-0x00007908-elf.bin` into `libcrypto.so`, which is the single
  biggest improvement available here.
* Extended numbering (`e_phnum == 0xffff`) is reported, not resolved.
