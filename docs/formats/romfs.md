# romfs

`src/discovery/validators/romfs.cpp` (validator `romfs`), signature `romfs`
in `signatures/core.toml` (format `romfs`, category `filesystem`).

## On-disk layout (big-endian)

| offset | field | constraint |
|---|---|---|
| 0 | `-rom1fs-` | magic |
| 8 | `full size` u32 | >= 16 + name field + 16 |
| 12 | `checksum` u32 | u32 sum of the first min(512, full size) bytes is zero |
| 16 | volume name | NUL-terminated printable ASCII, padded to 16 bytes |
| 16 + name | first file header | `next` (low 4 bits = type), `spec`, `size`, `checksum`, name |

Images are padded to 1024 bytes; `size` = full size rounded up to 1024.

## Tiers

| tier | when |
|---|---|
| magic | volume name is not printable ASCII (`-rom1fs-` inside a string table: seen next to `squashfs`, `NSR02`, `BEA01` in a blkid table on the audio image), or full size cannot hold a header |
| structural | fields sane, image runs past the data, or the first file header points outside |
| consistent | inside the data |
| verified | checksum sums to zero |

## Attributes

`volume_name`, `full_size`, `checksum` (`ok` / `mismatch`).

## Diagnostics

`romfs-truncated-header`, `romfs-bad-name`, `romfs-bad-size` (magic);
`romfs-truncated`, `romfs-bad-first-header` (structural);
`romfs-checksum-mismatch` (consistent, not verified). The name length limit
is `max_name_len` from the signature.

## Known gaps

* File headers beyond the first are not walked.
