# U-Boot FIT image

`src/discovery/validators/fit.cpp` (validator `fit`, signature `fit` in
`signatures/core.toml`, format `fit`, category `container`). The FDT parser
in the same file also backs the `dtb` validator ([dtb.md](dtb.md)).

## On-disk layout

A FIT is a flattened device tree (magic `0xd00dfeed`, big-endian; header and
token stream as in [dtb.md](dtb.md)) whose root holds an `/images` node.
Each `/images/<name>` node describes one payload:

| property | meaning |
|---|---|
| `data` | inline payload (the property bytes) |
| `data-position` + `data-size` | external payload at an absolute offset from the FIT start |
| `data-offset` + `data-size` | external payload relative to the 4-aligned end of the tree |
| `type`, `compression`, `description`, `arch`, `os`, `load`, `entry` | metadata |
| `hash*` subnodes | `algo` (crc32, md5, sha1, sha256, sha512) and `value` |
| `signature*` subnodes | RSA/ECDSA signatures over hashed nodes (not verified here) |

`/configurations/<name>` nodes name a `kernel`, `fdt`, `ramdisk`,
`firmware` or `loadables` set; `/configurations/default` picks one.

## Validation and tiers

| tier | when |
|---|---|
| rejected | header fails the FDT constraints, the tree does not fit in the data, or the root has no `/images` |
| structural | `/images` present but the tree did not parse to END, an image payload is missing, or the data is truncated |
| consistent | tree complete, every image payload inside the data (inline ones are inside `totalsize` by construction) |
| verified | at least one hash checked out and none failed (crc32 = zlib CRC-32; md5/sha1/sha256 via `core/Hash`) |

`size` = `totalsize`, or the end of the furthest external payload when
larger; clamped to the data. A DTB hit at the same offset (the FIT is a
valid FDT) is downgraded by the `dtb` validator so this finding wins, and
DTB images inside the FIT are absorbed into `also_matched` once the FIT is
verified. When the FIT cannot be verified (no hashes, or only unsupported
algorithms) inner DTBs stay visible as equal-confidence nested findings.

## Attributes

`description`, `timestamp`, `version`, `totalsize`, `struct_size`,
`strings_size`, `image_count`, `images` =
`name:offset:size:type:compression;...` (offset relative to the FIT start,
`missing` when the payload is outside the data), `configurations` =
`name:kernel=..,fdt=..;...`, `default_configuration`, `hash_ok`,
`hash_failed`, `hash_unsupported`, `images_without_hash`.

## Diagnostics

| code | severity | meaning |
|---|---|---|
| `fdt-*` (see dtb.md) | warning | the structure block did not parse |
| `fit-truncated` | warning | image data extends past the available data |
| `fit-data-missing` | warning | an image has no payload inside the data |
| `fit-no-images` | warning | `/images` has no subnodes |
| `fit-hash-mismatch` | warning | a hash does not match its payload |
| `fit-hash-unsupported` | info | a hash uses an algorithm not checked here (sha512, ...), or was skipped by `max_hash_bytes` |
| `fit-limit-hash-bytes` | warning | the payloads named by hash nodes exceed `max_hash_bytes`; the remaining hashes were not verified |

Limits from the signature: `max_nodes`, `max_props`, `max_depth`,
`max_hash_bytes` (bytes one FIT may hash while verifying its images, default
1 GiB; a hostile FIT could otherwise name thousands of multi-GiB payloads
inside a large image).

## Verified on

* `spi-example` at `0x30000`: 3 images (fdt, kernel, ramdisk), sha256 hashes
  verified, 3979178 bytes; previously two magic-only `dtb` hits.
* `audio-example` at `0x8001b4`: 22 images, crc32 hashes verified,
  11946312 bytes.

## Known gaps

* Signature nodes are listed by their presence only; no RSA/ECDSA check.
* sha512 hashes are counted as unsupported.
