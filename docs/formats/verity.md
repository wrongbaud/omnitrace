# dm-verity hash device

`src/discovery/validators/verity.cpp` (validator `verity`), signature
`dm-verity` in `signatures/crypto.toml` (format `dm-verity`, category
`crypto`).

## On-disk layout

512-byte superblock, little-endian (Linux `drivers/md/dm-verity-target.c`
`struct verity_sb`; cryptsetup `lib/verity/verity.c`):

| offset | field | constraint |
|---|---|---|
| 0 | `signature[8]` | `verity\0\0` |
| 8 | `version` u32 | 1 |
| 12 | `hash_type` u32 | 0 (Chrome OS) or 1 (normal) |
| 16 | `uuid[16]` | |
| 32 | `algorithm[32]` | sha256, sha1 or sha512 (case-insensitive; uppercase seen in the wild) |
| 64 | `data_block_size` u32 | power of two, 512..65536 |
| 68 | `hash_block_size` u32 | power of two, 512..65536 |
| 72 | `data_blocks` u64 | |
| 80 | `salt_size` u16 | <= 256 |
| 88 | `salt[256]` | |

The superblock occupies the first hash block. The hash tree follows: with
`per_block = hash_block_size / digest_size` hashes per block, level sizes are
`ceil(data_blocks / per_block)`, then `ceil(that / per_block)`, ... down to
one root block. `size` = `(1 + sum of level blocks) * hash_block_size`.
Forward-error-correction data, when present, follows and is device-specific;
it is not claimed.

## Tiers

| tier | when |
|---|---|
| magic | a constraint above fails (diagnostic names the field) |
| structural | fields sane but the tree runs past the data (`size` clamped) |
| consistent | superblock plus computed tree inside the data and `data_blocks` > 0 |

## Attributes

`version`, `hash_type`, `uuid`, `algorithm` (lowercased),
`data_block_size`, `hash_block_size`, `data_blocks`, `data_bytes`
(`data_blocks * data_block_size`: the size of the protected region, which
matches the filesystem the hash device follows), `salt` (hex),
`hash_tree_blocks`.

## Diagnostics

`verity-truncated-header`, `verity-unsupported-version`,
`verity-bad-hash-type`, `verity-bad-block-size`, `verity-bad-algorithm`,
`verity-bad-salt-size` (all warning, tier magic), `verity-truncated`
(warning, tier structural).

## Verified on

* `spi-example` at `0x9ba000`: sha256, 1298 data blocks of 4096 = 5316608
  bytes, exactly the SquashFS at `0x4a0000`; 12 tree blocks, size 53248.
* `audio-example` at `0x51a4000`: sha256, 14756 data blocks, 117 tree blocks.

## Known gaps

* The root hash is not stored in the superblock (it lives in the boot
  arguments or a vbmeta), so the tree cannot be checked against anything;
  the tier stays at consistent.
