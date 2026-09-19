# Flattened device tree (DTB)

Validator `dtb` in `src/discovery/validators/fit.cpp` (shared FDT parser),
signature `fit-dtb` in `signatures/core.toml` (format `dtb`, category
`other`; the name is historical, the signature now validates plain DTBs and
steps back for FIT images).

## On-disk layout

Header of ten big-endian u32 at offset 0:

| offset | field | constraint applied |
|---|---|---|
| 0 | `magic` | `0xd00dfeed` |
| 4 | `totalsize` | >= 40 |
| 8 | `off_dt_struct` | 4-aligned, 40 <= x < totalsize |
| 12 | `off_dt_strings` | 40 <= x <= totalsize |
| 16 | `off_mem_rsvmap` | 8-aligned, 40 <= x < totalsize |
| 20 | `version` | 16 or 17 |
| 24 | `last_comp_version` | 16 <= x <= version |
| 28 | `boot_cpuid_phys` | |
| 32 | `size_dt_strings` | off_dt_strings + x <= totalsize |
| 36 | `size_dt_struct` | off_dt_struct + x <= totalsize |

Structure block tokens (u32 BE): `BEGIN_NODE` (1) + NUL-terminated name
padded to 4, `END_NODE` (2), `PROP` (3) + `len` + `nameoff` + data padded
to 4, `NOP` (4), `END` (9). Property names are NUL-terminated strings in the
strings block at `nameoff`.

## Tiers

| tier | when |
|---|---|
| rejected | any header constraint fails (4-byte magic inside other data) |
| structural | header sane but `totalsize` runs past the data, or the token stream does not parse to END, or the root has `/images` (a FIT: the `fit` signature reports it) |
| consistent | complete, balanced tree; `size` = `totalsize` |

## Attributes

`version`, `totalsize`, `struct_size`, `strings_size`, `nodes`,
`properties`, `model`, `compatible` (comma-joined string list).

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `dtb-truncated` | warning | `totalsize` extends past the available data |
| `dtb-is-fit` | info | root has `/images`; see the `fit` finding at the same offset |
| `fdt-struct-overrun` | warning | token stream ran past `size_dt_struct` |
| `fdt-bad-node-name` | warning | node name not terminated inside the block, or an unnamed non-root node |
| `fdt-multiple-roots` | warning | a second top-level BEGIN_NODE |
| `fdt-unbalanced` | warning | END_NODE without a node, or END with nodes open |
| `fdt-prop-outside-node` | warning | PROP before the root node |
| `fdt-prop-overrun` | warning | property data runs past the block |
| `fdt-bad-prop-name` | warning | `nameoff` outside the strings block |
| `fdt-bad-token` | warning | unknown token |
| `fdt-no-root` | warning | END before any node |
| `fdt-limit-nodes` / `-props` / `-depth` | warning | a signature limit (`max_nodes`, `max_props`, `max_depth`) stopped the walk |

## Known gaps

* Version 1-15 blobs (pre-2008) are rejected as unsupported.
* Memory reservation entries are not listed.
