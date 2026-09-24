# Parity: measured

Phase 1's exit criterion is "parity ≥ 95 % files recovered vs unblob and
moria on fixtures and corpus". It had never been run. This page is the
measurement, how to reproduce it, and what it found.

**Result, over all 35 images** — 20 fixtures and the whole 15-image corpus,
up to a 15.7 GB eMMC — counting distinct regular-file contents by sha256:

| baseline | pooled | per-image mean | images ≥ 95 % | verdict |
|---|---:|---:|---:|---|
| **moria** 0.2.1 | **99.9 %** | 98.7 % | 31 / 32 | **criterion met** |
| **ground truth** (`expected.yaml`) | **100.0 %** | 100.0 % | 19 / 19 | every file of every fixture |
| **unblob** 26.6.4 | **99.5 %** | 96.8 % | 26 / 32 | **criterion met** |
| binwalk 3.1.0 | 16.0 % | 66.8 % | 9 / 17 | not a like-for-like baseline (§6) |

The unblob figure was **65.7 %** when this was first measured, and ground
truth **94.4 %**. Closing §2 (SquashFS v1–v3) took one image from 0.1 % to
98.8 %, §1 (FAT) took ground truth to **every file of every fixture**, §4
(`ar`) took the 3.8 GB auto-ivi eMMC from 93.4 % to 99.8 %, and §3 (carving a
structure inside a payload) took the dongle dongle from 16.8 % to 91.6 %.
Pooled against unblob: 65.7 % → 99.6 %.

The large images are the evidence that this scales: the 7.8 GB auto-emmc eMMC is
**99.7 % of unblob and 100.0 % of moria**, the 7.8 GB audio **98.4 % and
100.0 %**, and the 3.8 GB auto-ivi **99.8 % and 100.0 %**. The one image below
95 % of moria is the 15.7 GB QNX unit, and it is the case where the ratio
stops meaning anything — §7.

Three images (`auto-ivi MX25L165D.bin`, camera v4 and v5) yield **no
files from any of the four tools** — the two camera images are vendor-signed by
their own filenames — so they neither help nor hurt any share. All four tools
exit cleanly on them; OmniTrace is the only one that reports the region at
all, with an entropy class, rather than saying nothing.

## What is being counted

**Distinct regular-file contents, by sha256, image-wide**, regardless of which
finding produced them or what path they were written to. The share is
`|subject ∩ baseline| / |baseline|`.

That unit was chosen after two others turned out to measure bookkeeping:

* **Per-finding path diffs** (what `run.py` already did) only compare files
  inside findings that matched at the same offset *and* format. A container
  and its payload sit at different offsets by design — unblob's `lzma` at
  `0x50040` is OmniTrace's `uimage` at `0x50000` — so the files of a matched
  pair are a fraction of what either tool recovered.
* **Counting symlinks** is not comparable between tools. A symlink's target
  resolves against the directory the link is in, and every tool writes a
  nested extraction under a prefix of its own
  (`filesystem@1.extracted/0x0-squashfs/bin/ash` in moria,
  `filesystems/n000021/files/bin/ash` here), so one link anchors to two
  different absolute paths. That artifact alone read as **226 missing files**
  on the router-nand image and 31 on the SPI one — both of which are 100 % and
  99.3 % on regular files. A symlink carries no data, so leaving it out costs
  the measurement nothing and removes an ambiguity. The symlink-inclusive
  figure is still reported, in the last column of `sweep.md`.

A file recovered under a different path counts as recovered, which is the
honest reading of "files recovered". A file nobody can produce the bytes of
does not count, however it is named.

**Zero-filled blobs are counted separately.** A tool that finds a file's
metadata but cannot reconstruct its data often writes the right number of NUL
bytes. 28 of the 30 contents moria has and OmniTrace does not, on
`router.bin`, are exactly that — moria's JFFS2 reader reports `partial` and
emits zero-filled placeholders where OmniTrace emits the file. Counting those
as "recovered by moria, missed by us" would penalise this tool for not
reproducing another's failure, so `sweep.md` reports the count in its own
column rather than silently dropping or silently including it.

## Reproducing it

```sh
docker pull ghcr.io/onekey-sec/unblob:latest
docker build -f tests/parity/moria.Dockerfile -t omnitrace-parity-moria tests/parity

ls tests/fixtures/out/*.img tests/fixtures/out/*.tar.gz > /var/tmp/images.txt
find corpus -maxdepth 3 -type f \( -name '*.bin' -o -name '*.BIN' \) -size -100M >> /var/tmp/images.txt

scripts/fixtures.sh sweep --list /var/tmp/images.txt --out /var/tmp/parity \
    --omnitrace build/linux-gcc/apps/cli/omnitrace
```

`sweep.md` and `sweep.json` land in `--out`. The extraction trees are deleted
as each image finishes (`--keep` retains them); the `*.normalized.json` files
keep every path and hash, so the numbers stay auditable without keeping
evidence-derived bytes, and `--reuse` re-aggregates from them without
re-running a tool.

## What it found

### 1. FAT was not identified at all — **closed**

`signatures/*.toml` had no FAT entry. `partitions/mount.sh` knew how to mount
one (`fat → vfat`) and `FORMAT_ALIASES` in the harness knew the name, but
nothing detected one, so `fat32.img` extracted zero files and `gpt.img` lost
the file in its FAT `boot` partition. That was the *entire* difference from
ground truth: every other fixture already scored 100 %.

**Fixed.** FAT12/16/32 are identified, sized and read, with deleted-file
recovery under `--history`. Both images are now **100 % of ground truth,
unblob and moria**, and the fixture set as a whole is 179 of 179 contents.

The format has no magic: what the signature matches is the file-system type
string, which Microsoft's specification says "is not required to be correct".
It is treated as a screen and the BPB decides everything — which matters,
because three corpus images carry `FAT32   `, `FAT12   ` and `FAT16   ` within
twenty bytes of each other, a driver's string table that the validator now
rejects on its geometry. `docs/formats/fat.md` has the detail, including what
can and cannot honestly be recovered from a deleted entry.

### 2. SquashFS v1–v3 is detected but never sized, so never read — **closed**

`squashfs-vendor-shsq` matches the router-wrt wrt-router image at `0x12eae4` — the same
offset unblob reports — but the validator parses v4 only
(`squashfs-unsupported-version`), so the finding carries `extent: unknown`,
and by the rule in `docs/ARCHITECTURE.md` an unsized structure is never handed
to a reader. unblob calls it `squashfs_v3_broadcom` and recovers 5,372 files
from it.

```
0x12eae4:  73 68 73 71   "shsq"  -- "hsqs" with each 16-bit word swapped
0x12eb00:  03 00 00 00           -- s_major 3, s_minor 0
```

```console
$ omnitrace scan "corpus/router-wrt-example/flash/wrt-router.bin" --json
  "offset_hex": "0x12eae4",  "format": "squashfs",  "tier": "magic",
  "confidence": 25,          "size": 0,
  "signature": "squashfs-vendor-shsq",
  "evidence": "magic \"shsq\" at 0x12eae4",
  "attrs": {"version": "3.0"},
  "diagnostics": [{"code": "squashfs-unsupported-version", "severity": "warning",
                   "message": "SquashFS 3.0 superblock; only v4 is parsed"}]
```

The signature and the endianness logic already handle the vendor magic; it is
the superblock parse that stops at v4.

**This one image was 3,903 of the 5,430-content shortfall against unblob — 72 %
of it.**

**Fixed.** The validator now parses the packed v1–v3 superblock and sizes it
from `bytes_used`; the reader walks the v1–v3 inode, directory and owner
structures and decodes the DD-WRT/Broadcom LZMA1 those vendor images use.
`docs/formats/squashfs.md` has the layout and how it was established — every
offset was read off evidence, because the published structures are bitfields
whose wire layout is the compiler's choice rather than the format's.

On this image OmniTrace now recovers **3,861 of unblob's 3,909 regular-file
contents (98.8 %, from 0.1 %)**, and extracts three files unblob does not: one
whose LZMA block is corrupt — zero-filled, flagged `squashfs-block-corrupt`
and emitted rather than dropped — and two symlinks unblob refuses as path
traversal.

### 3. Carving a structure inside a payload — **decided, and done**

On the dongle dongle, 221 of unblob's 247 extra contents are
`xz.uncompressed_extract/<range>.elf32_extract/carved.elf` — individual ELF
binaries cut out of one decompressed payload — plus `*.unknown` gaps around
them. The same pattern accounts for the 4 extra contents on `router.bin`'s
LZMA kernel and 4 on the SPI image.

**No data was missing**: those byte ranges are inside the payload OmniTrace
emits whole. What was missing was a *hash*.

**Decided: carve them.** The dongle payload is one 23 MB file holding 222
complete ARM32 shared objects — each with section headers inside its claimed
extent and a dynamic section naming the libraries it needs, which `readelf`
parses straight out of the payload. OmniTrace already located, sized and typed
all 222 and gave them **no digests at all**, because digests come from carving.
A tool that can say "a complete ARM shared object at offset 30984, 396,124
bytes" but not what it hashes to has stopped one step short of useful: an
examiner cannot match it against a known-file set or cite it in a report.

A find inside an extracted file is now carved when it is a strict sub-range of
that file, and not when it is the whole of it. `docs/formats/elf.md` records
the decision, the rule and the cost (that dongle goes from 14 carved files to
237, and 15 MB to 37 MB for a 16 MB image; every other corpus image gains
between none and three).

**The harness was also measuring the wrong thing.** It counted files under
`filesystems/` and `containers/` but not carved ones, while counting unblob's
`carved.elf` — so it measured the harness rather than the tools. With carved
files counted and all 33 images re-run, the dongle goes from 16.8 % to 91.6 %
and the pooled unblob figure from 98.9 % to 99.6 %.

### 4. `ar` static libraries were not opened — **closed**

On the 3.8 GB auto-ivi eMMC, OmniTrace recovered **exactly** what moria does —
17,352 of 17,352 — but only 93.4 % of what unblob does. Of unblob's 1,229
extra contents, **1,224 were `libgcc.a_extract/*.o`**: members of `ar` static
archives, which unblob descends into and OmniTrace treated as opaque files.

**Fixed.** `ar` is identified, sized and read, with the GNU and BSD long-name
dialects resolved — a cross toolchain's `libgcc.a` is 1,771 members of which
every one is a `/N` offset into the archive's string table, so resolving them
is the difference between member names and a directory of files called
`/108`. That image is now **99.8 % of unblob** (18,552 of 18,579 contents, up
from 17,352) and still 100 % of moria. `docs/formats/ar.md` has the format and
why the validator reaches `Verified`.

The 27 contents still only unblob's are the ELF/unknown carving of §3.

### 5. The history fixtures look like losses against unblob and are not

`ubifs-history` (80 %), `yaffs2-history` (87.5 %) and `jffs2-history` (90 %)
each miss one or two contents that unblob has. Those are **deleted and
superseded nodes that jefferson emits into the live tree**. OmniTrace records
them as deleted, keeps them out of the live listing, and recovers them under
`--history` into `.omnitrace-versions/`; the harness excludes deleted and
superseded entries deliberately.

All three are **100 % of ground truth**, which is what settles it. This is the
case `docs/TESTING.md` already described and the measurement confirms it.

### 6. binwalk is not a like-for-like baseline here

binwalk 3.1.0 on this host has none of its external extractors
(`sasquatch`, `jefferson`, `ubireader`), so it identifies filesystems without
extracting them — 1 file from `router.bin`, 269 contents over the whole set.
Its 14.9 % is a statement about this host's binwalk installation, not about
either tool. It is kept in the table because binwalk's *identification* is
still a useful cross-check.

### 7. A ratio needs a denominator: the QNX unit

The 15.7 GB QNX infotainment image is the worst score in the set — **62.5 % of
unblob, 63.6 % of moria** — and it is the one number here that should not be
read as a score at all.

| tool | distinct regular-file contents |
|---|---:|
| **OmniTrace** | **62,352** |
| moria 0.2.1 | 11 |
| unblob 26.6.4 | 8 |

Neither baseline reads QNX6 or QNX-IFS, so neither gets into the filesystems
that hold the unit's 105,645 files; what they recover is a handful of
compressed streams they found by scanning raw bytes. "62.5 % of unblob" means
five of unblob's eight, and it is arithmetic on a denominator of eight.

#### The gap that was hiding behind those streams

The missing contents were first read as a decompression gap — OmniTrace
extracted the filesystems but "did not appear to decompress these particular
streams". **That diagnosis was wrong**, and how it was wrong is the useful
part.

`--max-file-bytes` defaulted to a flat 1 GiB, and this image holds two
1054 MiB SquashFS images (`app.img` and `os_a.img`) stored as ordinary files
inside its QNX6 filesystem. Both were cut at exactly 1,073,741,824 bytes. A
SquashFS keeps the tables naming its contents at the *end*, so a truncated
copy is not a partial filesystem — it is no filesystem at all. Both walked to
**zero files**, and everything inside them went with them.

Nothing said so out loud. The cap is a `Limits` field with a warning behind
it and the warning fired, but what an examiner saw downstream was two
SquashFS nodes reporting `entries=0 files=0`, which reads like an empty
filesystem rather than a decapitated one.

The cap now tracks the evidence the way `--max-bytes` already did
(`core/Limits.h`): the default is the larger of 1 GiB and the image size,
because **a stored entry cannot be larger than the image that holds it**, so
any cap below the image size can only ever cut real content. The bomb guard
this appears to loosen was never this field's job — a stored entry's size is
known from its metadata before a byte is written, and a *decompressed* entry,
whose size is not, is bounded by `max_decompress_ratio` instead (widest real
expansion measured across the corpus: 32x, against a 1000x cap).

The same command with no flags now recovers **62,352** contents where it
recovered 23,833, and **105,645** files where it recovered 31,454 — and one
more of unblob's eight streams, which is the whole of the 50.0 % → 62.5 %
move. The cost of a cap that does not track the evidence was about two thirds
of this image.

#### A truncated entry that was not an entry

Reproducing that cap on a fixture turned up a worse defect standing behind
it. A tar holding a 319 KiB SquashFS, analysed with `--max-file-bytes
200000`, left a 200,000-byte file in the case directory while its
`listing.yaml` said `entries: []` and the manifest said `files=0`.

`emit_span_file` closed the cut entry correctly and filled in an
`EntryResult` — host path, digests over the bytes that landed, `truncated`
set — and then returned the failed write Status. Every container reader
follows "a refusal applies to that entry only: record the Status and
continue", so all eight of them dropped it. `Sink::file` had the same shape,
and so did the cramfs and FAT readers.

A file in a case directory that the listing does not name has no hash, no
source offset and no provenance, which is the one thing a forensic output may
not produce. The rule is now stated in `Sink.h`: **only `begin_file` can
refuse an entry outright.** Once it succeeds, bytes may already be on disk, so
a limit tripping mid-`write` is not a reason to skip the entry. A cut entry is
counted, listed with digests over what was recovered, marked `truncated`,
carries the `sink-limit-*` diagnostic naming the cap — and is descended into,
which is what turns a lost subtree into a partial one.

#### What the remaining streams actually are

Four gzip payloads moria finds (raw offsets 0x1E803000, 0x1E814000,
0x26923000, 0x34CEE000) and three unblob finds decompress to QNX **slog
device logs**. They are not a decompression gap either: all seven sit inside
GPT partition 9 `storage`, which is one 15.2 GB QNX6 filesystem, and none of
their bytes belong to any live file in it — a search of all 7,359 extracted
files for the first stream's header finds nothing.

They are **unallocated space**. The baselines find them because they scan raw
bytes and do not care what owns them; OmniTrace walks the filesystem and sees
only what its metadata still points at. Recovering them is free-space carving
inside a filesystem, which is a capability this tool does not have yet rather
than a bug in one it does — and, since they are deleted device logs, a
capability squarely inside what Phase 2 is for. That is the honest name for
what this image still says to look at.

The same shape, less extremely, is why the per-image **mean** is reported
beside the pooled figure. Pooling weights an image by how much is in it, which
is right for "how much of the data did we recover"; the mean weights every
image alike, which is what catches an image going wrong.

## Standing

| criterion | state |
|---|---|
| ≥ 95 % vs moria | **met** — 99.9 % pooled; 31 of 32 images at or above 95 %, the exception being the QNX unit of §7 |
| ≥ 95 % vs unblob | **met** — 99.5 % pooled, up from 65.7 % as first measured |
| fixtures vs ground truth | **100 %** — 179 of 179 contents, every file of every fixture |
| corpus coverage | **complete** — all 15 corpus images and all 20 fixtures |

**Phase 1's exit criterion is met against both baselines, the fixtures are
exact, every named format gap is closed, the one open decision is made, and
every image in the corpus has been measured.** The criterion is closed.

What is left is 152 contents out of 32,467. Of the six images below 95 % of
unblob, three are the history fixtures of §5, where unblob's jefferson
resurrects deleted nodes into the live tree and OmniTrace records them as
deleted — all **100 % of ground truth**; one is `ubi.img` for the same
reason; one is the dongle dongle at 91.6 %, the remainder of §3's carving
difference; and one is the QNX unit of §7, where the denominator is eight.

The only thing in that list that names work to do is §7's remaining compressed
streams, and §7 now says what they are: gzipped QNX device logs sitting in the
**unallocated space** of a 15.2 GB QNX6 filesystem, which both baselines reach
by scanning raw bytes and OmniTrace does not reach at all, because it walks the
filesystem's metadata. Free-space carving inside a filesystem is the capability
that would close it.
