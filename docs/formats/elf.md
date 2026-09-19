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

## Known gaps

* Section names, dynamic sections, notes and build IDs are not read.
* Extended numbering (`e_phnum == 0xffff`) is reported, not resolved.
