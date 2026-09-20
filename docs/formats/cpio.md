# cpio (newc, crc, odc)

Validator `src/discovery/validators/cpio.cpp` (signatures `cpio-newc`,
`cpio-crc`, `cpio-odc` in `signatures/core.toml`), reader
`src/containers/cpio/CpioReader.{h,cpp}` registered as `cpio`, tests
`tests/unit/containers/archive_test.cpp`.

cpio is what a Linux initramfs is: the kernel's early userspace is a cpio
archive, usually gzipped, usually inside an Android boot image or a uImage
ramdisk. Finding one means finding the init scripts, the device nodes and the
early `/etc` of the device under examination.

After reading this you know the three header flavours, how the extent is
found, and what is not read.

## On-disk layout

A flat sequence of members, each a header, a NUL-terminated name and the data,
ending with a member named `TRAILER!!!`. The archive is written out padded to
a 512-byte block.

**SVR4 `newc` (`070701`) and `crc` (`070702`)** use a 110-byte header of
8-digit ASCII hex fields:

| off | field | off | field |
|---|---|---|---|
| 0 | magic (6 bytes) | 62 | devmajor |
| 6 | ino | 70 | devminor |
| 14 | mode | 78 | rdevmajor |
| 22 | uid | 86 | rdevminor |
| 30 | gid | 94 | namesize |
| 38 | nlink | 102 | check |
| 46 | mtime | | |
| 54 | filesize | | |

The name follows the header and the pair is padded to a 4-byte boundary; the
data follows and is padded the same way. `crc` differs only in that `check`
holds a simple sum of the data bytes rather than zero.

**POSIX `odc` (`070707`)** uses a 76-byte header of 6- and 11-digit ASCII
octal fields (`dev`, `ino`, `mode`, `uid`, `gid`, `nlink`, `rdev`, `mtime`,
`namesize`, `filesize`) and pads nothing at all.

`mode` is the full `st_mode`, so the entry kind is in its top bits, and a
symlink's target is its data.

## The extent

No header says how long the archive is, so the validator walks the member
headers to the `TRAILER!!!` member. That costs one hop per member and reads no
data, so sizing a 100 MB initramfs is a few thousand header reads. Without a
trailer the finding keeps size 0 and records `cpio-no-trailer`: a stray
`070701` in text must not claim whatever follows it.

The 512-byte block padding is claimed only when it really is zeros, so a
structure stored immediately after the archive is never absorbed. An initramfs
is often several archives concatenated; each is found and sized on its own.

## What the reader captures

`FileMeta`: `path` (with a leading `./` and a trailing `/` removed), `kind`
from the mode's type bits, `mode` (permission bits), `uid`/`gid`, `mtime`,
`inode`, `nlink`, `link_target` (a symlink's data), and
`rdev_major`/`rdev_minor` for device nodes.

`ContainerInfo`: `format`, `size` (the archive's extent), and attrs `variant`
(`newc` / `crc` / `odc`) and `entries`.

Members are streamed to the Sink 1 MiB at a time, and path safety is the
Sink's. Device nodes, fifos and sockets are recorded in `listing.yaml` but not
created (`sink-special-skipped`), which is what an initramfs full of `/dev`
entries needs.

## Diagnostics

| code | severity | when |
|---|---|---|
| `cpio-bad-header` | Warning | a member header is unreadable; the walk stops there |
| `cpio-truncated` | Warning | a member or the archive runs past the available data |
| `cpio-no-trailer` | Info | no `TRAILER!!!`; the finding has no extent and claims no bytes |
| `cpio-limit-entries` | Warning | `Limits::max_nodes_per_fs` (reader) or the signature's `max_entries` (validator) reached |
| `container-sink-error` | Warning | the Sink refused an entry; the walk continues |

## Known gaps

* The `crc` variant's checksum field is read but not verified against the
  data, so a `crc` archive reaches `consistent` rather than `verified`.
* Hard links (`nlink > 1`) are emitted as independent entries. cpio stores the
  data on the last link, so the earlier ones are empty; `nlink` says so.
* The old binary formats (`070707` little- and big-endian binary, magic
  `0x71c7`) have no signature: two bytes is too short to search for.
* `TRAILER!!!` members in the middle of a concatenated stream end the walk for
  that archive; the next one is found by the scan as its own finding.

## References

* Linux kernel, "initramfs buffer format"
  (https://www.kernel.org/doc/html/latest/driver-api/early-userspace/buffer-format.html)
* POSIX.1-2017 `pax`, the `cpio` Interchange Format (odc)
* GNU `cpio` as the parity tool: the reader is compared against `cpio -i` in
  the tests for all three flavours.
