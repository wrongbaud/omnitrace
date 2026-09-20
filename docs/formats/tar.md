# tar (ustar, GNU, pax)

Validator `src/discovery/validators/tar.cpp` (signature `tar-ustar` in
`signatures/core.toml`), reader `src/containers/tar/TarReader.{h,cpp}`
registered as `tar`, tests `tests/unit/containers/archive_test.cpp`.

tar is the packaging of firmware update bundles, of the `.tar.gz` payloads
inside them, and of vendor "ota" blobs. It carries full POSIX metadata, so an
examiner gets owner, mode and mtime for every member without mounting
anything.

After reading this you know how the extent is found (it is not in any header),
which of the three long-path conventions are handled, and what is not read.

## On-disk layout

A flat sequence of 512-byte blocks. Each member is one header block, then its
data padded up to 512. The archive ends with two zero blocks, followed by
padding to the writer's blocking factor (GNU tar uses 20 blocks, 10 KiB).

Header block:

| off | size | field | off | size | field |
|---|---|---|---|---|---|
| 0 | 100 | name | 157 | 100 | linkname |
| 100 | 8 | mode | 257 | 6 | magic |
| 108 | 8 | uid | 263 | 2 | version |
| 116 | 8 | gid | 265 | 32 | uname |
| 124 | 12 | size | 297 | 32 | gname |
| 136 | 12 | mtime | 329 | 8 | devmajor |
| 148 | 8 | chksum | 337 | 8 | devminor |
| 156 | 1 | typeflag | 345 | 155 | prefix (ustar) / atime, ctime (GNU) |

The signature matches `ustar` at offset 257, so the finding's structure starts
257 bytes *before* the hit. Pre-POSIX v7 archives have no magic there and are
therefore not found at all.

**Numeric fields** are NUL- or space-terminated ASCII octal. A value that does
not fit is written by GNU in base 256, flagged by bit 7 of the first byte; both
encodings are read.

**The checksum** is the sum of the header bytes with the checksum field itself
taken as eight spaces. Historic writers disagreed on whether those bytes are
signed, so both sums are accepted. A matching checksum is what lifts the
finding to `verified`; a mismatch stops the walk, because in practice it means
the `ustar` string was sitting inside other data.

**Type flags.** `0` and NUL regular, `1` hard link, `2` symlink, `3` char
device, `4` block device, `5` directory, `6` fifo, `7` contiguous (read as
regular), `L`/`K` the GNU long-name and long-link members, `x`/`g` the pax
extended headers.

**Long paths** arrive three ways, and firmware uses all of them:

* ustar splits the path across `prefix` (155 bytes) and `name` (100);
* GNU writes an `L` member whose *data* is the next member's name, and `K` for
  its link target;
* pax writes an `x` member of `"<len> <key>=<value>\n"` records. `path`,
  `linkpath`, `size`, `mtime`, `uid` and `gid` are applied to the member that
  follows; a `g` member sets the same keys for the rest of the archive.

## The extent

No header says how long the archive is, so the validator walks the member
headers to the end-of-archive blocks. That costs one hop per member and reads
no data. Without those blocks the finding keeps size 0 and records
`tar-no-end-marker`: claiming bytes there would let a stray `ustar` inside a
binary swallow whatever follows it.

The trailing padding is claimed only when it really is zeros, checked at both
512 and 10240 bytes, so a structure stored immediately after the archive is
never absorbed.

## What the reader captures

`FileMeta`: `path` (assembled from prefix/name or the GNU/pax override, with
a leading `./` and a trailing `/` removed), `kind`, `mode` (permission bits),
`uid`/`gid`, `mtime`, `link_target`, `rdev_major`/`rdev_minor`, `size`, and
`extra["uname"]` / `extra["gname"]` — the *names* tar records alongside the
numeric ids, which often survive when the ids mean nothing on the examiner's
host.

`ContainerInfo`: `format`, `size` (the archive's extent), and attrs `variant`
(`ustar` / `gnu` / `pax`) and `entries`.

Members are streamed to the Sink 1 MiB at a time, so a 4 GiB member costs one
buffer, and path safety is the Sink's (`openat`/`O_NOFOLLOW`, no `..`).

## Diagnostics

| code | severity | when |
|---|---|---|
| `tar-checksum-mismatch` | Warning | a header does not match its own checksum; the walk stops there (validator) |
| `tar-bad-header` | Warning | a header's size or checksum field is unreadable; the walk stops there |
| `tar-truncated` | Warning | a member or the archive runs past the available data |
| `tar-no-end-marker` | Info | no end-of-archive block; the finding has no extent and claims no bytes |
| `tar-bad-pax-record` | Warning | a pax record length is missing or overruns its block; the rest of that block is ignored and the member keeps its ustar name |
| `tar-limit-entries` | Warning | `Limits::max_nodes_per_fs` (reader) or the signature's `max_entries` (validator) reached |
| `container-sink-error` | Warning | the Sink refused an entry; the walk continues |

## Known gaps

* Pre-POSIX v7 archives have no `ustar` magic and are not detected.
* GNU sparse members (`S`, and the pax `GNU.sparse.*` keys) are extracted as
  their stored data, not expanded into the sparse file they describe.
* Hard links become empty entries with `nlink = 2` and the target in
  `extra["hardlink"]`; the Sink has no hard-link primitive.
* `atime`/`ctime` from the GNU header and from pax records are not applied.
* Multi-volume archives (`M`) are read as far as the volume goes.
* The pax `charset`, `comment` and vendor `SCHILY.*` keys are ignored.

## References

* GNU tar manual, "Basic Tar Format"
  (https://www.gnu.org/software/tar/manual/html_node/Standard.html)
* POSIX.1-2017 `pax` Interchange Format
* GNU tar `src/tar.h`, `src/list.c` (read for understanding; nothing copied)
* GNU `tar` as the parity tool: the reader is compared against `tar xf` in
  the tests for ustar, GNU and pax archives, including 90-character paths.
