# ar (static libraries, .deb, .ipk)

Reader: `src/containers/ar/ArReader.{h,cpp}` (`container::ContainerReader`,
format id `ar`). Validator: `src/discovery/validators/ar.cpp`.
Tests: `tests/unit/containers/archive_test.cpp` (`ArContainer.*`).

`!<arch>\n`, then nothing but 60-byte member headers each followed by its data
padded to an even offset. No directory, no trailer, no nesting, no
compression — the simplest archive here, and the one that turns up inside
embedded root filesystems as `libgcc.a`, `libc.a` and every other static
library a cross toolchain left behind. A Debian or OpenWrt package is also an
ar archive, of three members.

Parity measured it as 1,224 of the 1,229 contents unblob recovered from the
Auto-ivi eMMC that OmniTrace did not (`docs/PARITY.md`).

## Member header

Every field is ASCII, space padded, and **not** NUL terminated.

```
offset  size  field
     0    16  name
    16    12  mtime   decimal, seconds
    28     6  uid     decimal
    34     6  gid     decimal
    40     8  mode    octal
    48    10  size    decimal, data bytes
    58     2  "`\n"   the only per-member check the format has
```

Data follows immediately and is padded with one byte to an even offset when
the size is odd. That padding byte belongs to nobody: counting it as data
shifts every later member by one and the walk falls apart on the next header.

## A name is not a name

Three dialects, and a reader that emits the name field verbatim produces a
directory full of files called `/108`:

| written as | means |
|---|---|
| `name.o/` | **GNU short** — the slash marks where the name ends, so a trailing space can be part of it |
| `/108` | **GNU long** — offset 108 into the `//` member, one string table holding every name too long for 16 bytes, each terminated `/\n` |
| `#1/13` | **BSD long** — the first 13 bytes of the *data* are the name, and the recorded size covers them |

A cross toolchain's `libgcc.a` is almost entirely long names, so this is not
an edge case: the arm-none-eabi one in the reference set is 1,771 members and
every one of them is a `/N`.

## Two members are not files

`/` (or `__.SYMDEF` on BSD) is the symbol index and `//` is the string table.
`ar t` does not list them and neither does unblob; emitting them would put two
files in every extracted static library that were never in the source tree.
They are skipped, and their presence recorded in `attrs` as `symbol_table` and
`string_table` so nothing disappears silently. `attrs.members` counts the
files, not the tables.

## Confidence

The format has no checksum and no length field, so the extent is whatever the
walk accounts for — the offset after the last member whose header verified.
That is the same rule tar and GPT follow: when a magic is too weak to trust,
something per-record has to earn the extent.

| tier | when |
|---|---|
| `Magic` | the magic matched but no member header follows (`ar-no-members`) |
| `Structural` | members verified and then the data ran out inside one (`ar-truncated`), or the member cap was hit |
| `Consistent` | exactly one member verified and the walk ended without running out — one header is a weaker claim than a chain of them |
| `Verified` | two or more members verified and the walk ended without running out |

`Verified` is the tier the definition allows for "a decode probe succeeded".
Each header carries its two-byte terminator **and** has to land exactly where
the previous member's size said it would; two members chained that way is a
claim about the bytes between them, not a guess about the magic.

It also has a consequence worth stating, because it is the reason the tier is
not simply `Consistent`. Absorbing nested findings needs *strictly higher*
confidence than what is absorbed (`outranks` in `src/discovery/Scan.cpp`), and
a static library is hundreds of ELF members that each match the `elf`
signature at `Consistent`. At `Consistent` the scan reported all 298 members
of one `libgcc.a` as separate top-level regions, on top of the 298 files the
reader extracts. Nothing is lost by absorbing them: every member is emitted as
a file and the nested analysis looks at each one.

**Bytes that stop looking like a member header are not a warning** once a
member has verified. With no trailer, that is simply where the archive ends —
the normal case for one embedded in a larger image — and warning there would
put a diagnostic on every static library in a root filesystem.

## What the reader captures

`mode` (octal), `uid`, `gid` and `mtime` from the header; every member is a
regular file with `nlink` 1. There are no directories, symlinks or devices in
an ar archive, and no per-member compression.

A member whose name is empty or is not a usable path component — a separator,
`.` or `..` — is emitted as `member-<n>` with `ar-bad-name`, rather than
dropped or written where the name pointed.

## Known gaps

* The symbol table is skipped rather than parsed. It maps symbol names to
  member offsets, which would let a report say which member defines a symbol;
  nothing needs that yet.
* A `.deb` is recognised as the ar archive it is, and its `control.tar.*` and
  `data.tar.*` members are extracted and then identified by the nested
  analysis. There is no package-level view that names the package or reads its
  control fields.
* Thin archives (`ar T`, where members are references to files on disk rather
  than copies) hold no data to extract; they parse, and their members come out
  empty.
* The 4.4BSD/macOS `__.SYMDEF SORTED` variant is treated as a symbol table by
  prefix, which is right for skipping it but is not parsed either.

## References

* `ar.h`; the System V and BSD archive formats
* `binutils` `bfd/archive.c` — the reference implementation of all three name
  dialects (read for understanding; no code copied)
* `deb(5)` — the Debian package format, which is an ar archive
