# Parity: measured

Phase 1's exit criterion is "parity ≥ 95 % files recovered vs unblob and
moria on fixtures and corpus". It had never been run. This page is the
measurement, how to reproduce it, and what it found.

**Result, over 33 images** (20 fixtures, 13 corpus, including a 3.8 GB and a
7.8 GB eMMC), counting distinct regular-file contents by sha256:

| baseline | pooled | per-image mean | images ≥ 95 % | verdict |
|---|---:|---:|---:|---|
| **moria** 0.2.1 | **99.8 %** | 96.2 % | 28 / 30 | **criterion met** |
| **ground truth** (`expected.yaml`) | **94.4 %** | 94.3 % | 17 / 19 | 100 % on every fixture that is not FAT |
| **unblob** 26.6.4 | **83.0 %** | 88.2 % | 21 / 30 | criterion not met |
| binwalk 3.1.0 | 14.9 % | 64.4 % | 8 / 15 | not a like-for-like baseline (§6) |

The two largest images are the best evidence that this scales: the 7.8 GB
Auto-emmc eMMC is **99.7 % of unblob and 100.0 % of moria**, and the 3.8 GB
Auto-ivi eMMC is **93.4 % of unblob and 100.0 % of moria** — 17,352 of 17,352
contents, exactly. Only two of moria's 30 images fall below 95 %, and both are
the FAT fixtures.

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

### 1. FAT is not identified at all — the whole ground-truth shortfall

`signatures/*.toml` has no FAT entry. `partitions/mount.sh` knows how to mount
one (`fat → vfat`) and `FORMAT_ALIASES` in the harness knows the name, but
nothing detects one, so `fat32.img` extracts zero files and `gpt.img` loses
the file in its FAT `boot` partition.

That is the *entire* difference from ground truth: **every fixture that is not
FAT scores 100 % — 175 of 175 contents.** All 10 missing contents are FAT.

FAT12/16/32 is the boot partition of a large share of embedded devices. This
is the single highest-value format to add.

### 2. SquashFS v1–v3 is detected but never sized, so never read

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

**This one image is 3,903 of the 5,430-content shortfall against unblob — 72 %
of it, and it was 93 % before the two multi-gigabyte images were added.**
Sizing and reading v3, with its vendor word-swapped header, is the single
largest recovery available.

### 3. unblob carves sub-ranges out of decompressed blobs; OmniTrace does not

On the dongle dongle, 221 of unblob's 247 extra contents are
`xz.uncompressed_extract/<range>.elf32_extract/carved.elf` — individual ELF
binaries cut out of one decompressed payload — plus `*.unknown` gaps around
them. The same pattern accounts for the 4 extra contents on `router.bin`'s
LZMA kernel and 4 on the SPI image.

**No data is missing**: those byte ranges are inside the payload OmniTrace
emits whole. It is a difference in what counts as a file, and it is the second
largest contributor to the unblob gap (247 contents). Whether to carve ELFs
out of a decompressed kernel is a product decision, not a bug — but it should
be a decision on record rather than an accident, and carving them would make
the two tools comparable on this axis.

### 4. `ar` static libraries are not opened

On the 3.8 GB auto-ivi eMMC, OmniTrace recovers **exactly** what moria does —
17,352 of 17,352 — and 93.4 % of what unblob does. Of unblob's 1,229 extra
contents, **1,224 are `libgcc.a_extract/*.o`**: members of `ar` static
archives, which unblob descends into and OmniTrace treats as files.

`ar` is a real container format, not a carving heuristic, so this is a genuine
(if low-value-for-forensics) gap. The remaining 5 are the ELF/unknown carving
of §3.

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

## Standing

| criterion | state |
|---|---|
| ≥ 95 % vs moria | **met** — 99.8 % pooled, 28 of 30 images ≥ 95 %, the two exceptions being the FAT fixtures |
| ≥ 95 % vs unblob | **not met** — 83.0 % pooled; 94.6 % excluding the router-wrt v3 SquashFS, 99.4 % also excluding `ar` members and unblob's ELF carving |
| fixtures vs ground truth | 100 % of every non-FAT fixture (175 / 175); FAT is the only gap |
| large corpus images | 2 of 4 run (3.8 GB auto-ivi, 7.8 GB auto-emmc); `qnx` (15.7 GB) and `audio` (7.8 GB) outstanding |

Closing order, by contents recovered per unit of work: **SquashFS v1–v3**
(3,903 contents), then **FAT** (10 contents here, but the whole ground-truth
gap and very common in the field), then **`ar`** (1,224), then a decision on
record about ELF carving (252).
