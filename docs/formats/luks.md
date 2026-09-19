# LUKS encrypted volumes

`src/discovery/validators/luks.cpp` (validator `luks`), signature `luks` in
`signatures/crypto.toml` (format `luks`, category `crypto`). Nothing here
decrypts anything; the finding tells the examiner a region is encrypted, how,
and where the ciphertext starts, so the region lands in the coverage table
as `encrypted` rather than as unexplained high-entropy bytes.

## LUKS1 (592-byte header, big-endian integers)

| offset | field | constraint |
|---|---|---|
| 0 | magic `LUKS\xba\xbe` | |
| 6 | `version` u16 | 1 |
| 8 | `cipher-name[32]` | printable token (`aes`, `serpent`, ...) |
| 40 | `cipher-mode[32]` | token (`xts-plain64`, `cbc-essiv:sha256`, ...) |
| 72 | `hash-spec[32]` | token (`sha256`, `sha1`, ...) |
| 104 | `payload-offset` u32 | sectors of 512; > 0 |
| 108 | `key-bytes` u32 | 1..4096 |
| 112 | `mk-digest[20]`, 132 `mk-digest-salt[32]`, 164 `mk-digest-iter` u32 | |
| 168 | `uuid[40]` | 8-4-4-4-12 text |
| 208 | 8 key slots x 48 | `active` u32 (`0x00AC71F3` enabled, `0x0000DEAD` disabled), `iterations`, `salt[32]`, `key-material-offset` u32 (sectors, < payload offset), `stripes` u32 |

`size` = `payload-offset * 512` (header plus key material).

## LUKS2 (4096-byte binary header + JSON area, repeated as a secondary copy at `hdr_size`)

| offset | field | constraint |
|---|---|---|
| 0 | magic (`LUKS\xba\xbe` primary; `SKUL\xba\xbe` secondary, not scanned) | |
| 6 | `version` u16 | 2 |
| 8 | `hdr_size` u64 | power of two, 16 KiB..4 MiB |
| 16 | `seqid` u64, 24 `label[48]`, 72 `csum_alg[32]`, 104 `salt[64]` | tokens |
| 168 | `uuid[40]`, 208 `subsystem[48]`, 256 `hdr_offset` u64 | |
| 4096 | JSON | starts with `{`, has `keyslots` and `segments` |

`size` = `hdr_size * 2`. The cipher (`segments.*.encryption`), payload
offset (`segments.*.offset`, bytes), digest hash and keyslot KDF are pulled
from the JSON with a bounded string search (`max_json` from the signature).

## Tiers

| tier | when |
|---|---|
| magic | version not 1/2, non-token fields, bad payload offset / key size (v1), bad `hdr_size` (v2) |
| structural | v1 with an unknown key-slot state or key material past the payload; v2 with an unparseable JSON area |
| consistent | v1: all slots sane and uuid well-formed; v2: JSON sane, uuid well-formed, `hdr_offset` 0 |

## Attributes

Common: `version`, `uuid`, `cipher`, `mode`, `hash`, `payload_offset`
(bytes). v1: `key_bits`, `payload_offset_sectors`, `mk_digest_iterations`,
`key_slots_enabled`. v2: `hdr_size`, `seqid`, `checksum_alg`, `label`,
`subsystem`, `hdr_offset`, `cipher_spec`, `kdf`.

## Diagnostics

`luks-truncated-header`, `luks-unsupported-version`, `luks-bad-header`,
`luks-bad-hdr-size` (magic); `luks-bad-keyslots`, `luks-bad-json`
(structural); `luks-truncated` (size clamped); `luks-bad-uuid` (info).

## Verified on

* `audio-example` at `0x12000000`: LUKS1 aes / xts-plain64 / sha256, 256-bit
  key, one key slot, payload at sector 4096.

## Known gaps

* The LUKS2 secondary header (`SKUL`) has no signature; it is inside the
  primary finding's range.
* Detached headers and LUKS2 with `hdr_offset != 0` stay at structural.
