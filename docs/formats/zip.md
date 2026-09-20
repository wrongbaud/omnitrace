# ZIP

Validator `src/discovery/validators/zip.cpp` (signature `zip` in
`signatures/core.toml`), reader `src/containers/zip/ZipReader.{h,cpp}`
registered as `zip`, tests `tests/unit/containers/archive_test.cpp`.

ZIP is the packaging of Android APKs, OTA update payloads, vendor firmware
bundles and the occasional configuration blob. It is also the format whose
magic turns up most often by accident: `PK\x03\x04` is four bytes, and a
14.7 GiB eMMC image holds hundreds of them inside compressed data.

After reading this you know how the extent is found, why the reader goes
through the central directory rather than the local headers, and what is not
decoded.

## On-disk layout

Five record types, each starting with `PK` and a two-byte tag:

```
50 4b 03 04  local file header    30 bytes + name + extra, then the data
50 4b 07 08  data descriptor      only when flag bit 3 defers the sizes
50 4b 01 02  central directory     46 bytes + name + extra + comment
50 4b 06 06  zip64 EOCD            56 bytes
50 4b 06 07  zip64 EOCD locator    20 bytes
50 4b 05 06  EOCD                  22 bytes + comment
```

An archive is the members, then the central directory, then the end record.
The directory repeats every member's metadata and adds the offset of its local
header; the EOCD says where the directory starts and how long it is.

**Numbers** are little-endian. A field that would overflow 32 bits holds
`0xFFFFFFFF` and the real value lives in a zip64 extra field (id `0x0001`),
which carries only the values whose 32-bit slot held the marker, in the order
uncompressed size, compressed size, local header offset.

**External attributes** hold the Unix `st_mode` in their top 16 bits when the
"version made by" high byte says Unix (3). That is where the mode and the
symlink bit come from; without it, only a trailing `/` marks a directory.

## The extent

The signature matches the local file header, at the start of the archive, and
no header there says how long the archive is. The validator therefore walks
forward: local headers to the central directory, directory entries to the end
record, and the archive ends after the EOCD's comment. Every field but the
sizes is fixed-width, so this is a hop per member and reads no file data.

Three things complicate the walk, and all three are common:

* **Deferred sizes.** A streaming writer sets flag bit 3 and leaves the sizes
  zero, putting them in a data descriptor after the data. The walk searches
  forward for a descriptor whose compressed-size field equals the distance it
  sits at — a precise check, not a signature search, because the signature
  alone matches compressed bytes.
* **zip64 sizes in the local header.** Read from the `0x0001` extra field.
* **A gap before the directory.** Android inserts an *APK Signing Block*
  between the last member and the central directory; that is how v2 and v3
  signatures are carried. The walk searches forward for a directory entry
  whose own name, extra and comment lengths land on another entry or on an end
  record, so a `PK\x01\x02` inside compressed data is not mistaken for one.
  `gap_before_directory` records how many bytes were skipped.

When the walk cannot finish, the finding keeps size 0 and records `extent:
unknown` with the reason. It then claims no bytes, parents nothing, and is not
handed to the reader — which is what keeps the hundreds of accidental
`PK\x03\x04` hits in an eMMC image from each producing an empty walk.

As a last cross-check the EOCD's own `cd_offset` is compared with where the
walk found the directory; agreement lifts the finding to `consistent`, and a
mismatch is reported (`zip-cd-offset-mismatch`) because it usually means the
archive is appended to something else.

## What the reader captures

The reader goes through the **central directory**, not the local headers. The
directory is the archive's own index: it is what every correct implementation
uses, it is where the sizes are reliable even for a streamed archive, and a
member deleted from the directory but still present in the file is correctly
not treated as live. `open()` finds the EOCD by searching back from the end of
the Span over the largest comment the format allows, follows the zip64 locator
when present, and falls back to the directory immediately before the EOCD when
`cd_offset` does not land on one (an appended or self-extracting archive).

`FileMeta`: `path` (trailing `/` removed), `kind` (from the Unix mode, else
the trailing `/`), `mode`, `mtime` (converted from the MS-DOS date and time,
read as UTC), `link_target` for a symlink, `size`, and `extra["method"]`.

`ContainerInfo`: `format`, `size`, and attrs `entries`, `declared_entries`
(what the EOCD claims, so a disagreement is visible) and `zip64`.

Stored members are streamed 1 MiB at a time; deflated members are inflated
whole, bounded by `Limits::max_file_bytes`. Any other method is reported and
the member is emitted empty rather than dropped, so the listing still shows it.

## Diagnostics

| code | severity | when |
|---|---|---|
| `zip-no-central-directory` | Info | the walk never reached the directory; no extent |
| `zip-deferred-sizes` | Info | a data descriptor or zip64 extra field could not be read; no extent |
| `zip-no-eocd` | Warning | the directory does not end in an end record |
| `zip-cd-offset-mismatch` | Warning | the EOCD and the walk disagree about where the directory is |
| `zip-truncated` | Warning | a member or the archive runs past the available data |
| `zip-bad-entry` | Warning | a directory entry or a local header is unreadable |
| `zip-decompress-failed` | Warning | a deflated member did not inflate; emitted empty |
| `zip-unsupported-method` | Warning | a method other than stored or deflate; emitted empty |
| `zip-limit-entries` | Warning | `max_nodes_per_fs` or the signature's `max_entries` reached |
| `container-sink-error` | Warning | the Sink refused an entry; the walk continues |

## Known gaps

* Only stored (0) and deflate (8) are decoded. bzip2 (12), LZMA (14), xz (95)
  and zstd (93) members are listed but emitted empty.
* Encrypted members are not decrypted and fail to inflate.
* The CRC32 each member carries is read but not checked against the data.
* Multi-disk archives are not assembled; only the disk in hand is read.
* Extra fields other than zip64 (NTFS and Unix timestamps, Info-ZIP Unicode
  paths) are not read, so sub-second and post-2107 timestamps are lost and a
  non-UTF-8 name is sanitized rather than re-decoded.

## Verified on

* `zip -r`, `zip -0 -r` and a Python streaming writer (deferred sizes), each
  compared against `unzip` with no mismatch in name, kind, size, mode or
  content.
* A zip64 archive written with `force_zip64`, whose sizes live in local-header
  extra fields.
* `org.fdroid.fdroid` 1.21, a real 11.9 MB APK: 1251 members with an APK
  Signing Block before the directory, extracted byte-identically to `unzip` in
  0.7 s.

## References

* PKWARE APPNOTE.TXT 6.3.10, sections 4.3.6 to 4.3.16
* Android "APK Signature Scheme v2", the APK Signing Block layout
* Info-ZIP `unzip` as the parity tool
