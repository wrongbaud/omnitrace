# Word-swapped images

Some flash dumpers, and some captures of 16- or 32-bit parallel flash, store
the image with the bytes of every 16-bit or 32-bit word reversed. Nothing in
the image is wrong, only its byte order within each word, so every magic and
every string is scrambled and a signature scan finds nothing. The corpus image
`auto-ivi-example/flash/MX25L165D.bin` (2 MiB SPI NOR, MediaTek SNOR
preloader) is stored this way: the raw bytes read `erP[daol1 reI tsegampme`,
which is `[Preloader 1st Image empty]` with every 4-byte group reversed, and
the ARM code at `0x20000`-`0xc0000` is swapped the same way.

OmniTrace does not rewrite the evidence. It detects the swap, records the
decision on the Image node, and analyses a derived view (`SwappedSource`) that
presents the corrected byte stream without copying the image.

## SwappedSource (core/Swap.h)

`SwappedSource(parent, SwapKind::Swap16 | Swap32)` is a `Source`:

- `size()` is the parent's size; offsets are unchanged.
- `id()` is `<parent id>|swap16` or `<parent id>|swap32`. Every node found on
  the view carries that id in `location.source`, so provenance says which
  bytes were read through the swap. `SwapKind::None` is a pass-through with
  the parent's id.
- `read(off, out)` reads the aligned words that cover `[off, off+len)` from
  the parent (word alignment is absolute, from parent offset 0), reverses the
  bytes of every complete word, and copies the requested window out, so an
  unaligned read is byte-identical to the same range of a reference swap of the
  whole image. Short reads at the end behave like the parent's.
- A trailing partial word (parent size not a multiple of the word size) is
  passed through unchanged. The analysis driver reports it on the Image node
  (`image-word-swap-tail`, Info) with the number of bytes.
- `map()` always returns an empty span: a swapped view cannot be zero-copy
  mapped, so readers fall back to `read()` (which is what `Span::bytes` does).

## Detection (detect_word_swap)

`detect_word_swap(span, budget = 64 MiB)` samples the span in 64 KiB windows.
When the span is smaller than the budget every window is read; otherwise
`budget / 64 KiB` windows are spread evenly over the span, aligned to 64 KiB,
so the whole of a 2 MiB SPI dump and a slice of every region of a 15 GiB eMMC
dump are examined for the same bounded cost. Sampling is deterministic.

For each window the raw bytes, the swap16 rendering and the swap32 rendering
are scored:

**Structure score** = `8 x strong + 1 x weak` where

- strong hits are a fixed table of full magics: ELF `7f 45 4c 46`, uImage
  `27 05 19 56`, SquashFS `hsqs`/`sqsh`, JFFS2 `0x1985` with its node type
  (dirent, inode, cleanmarker; LE and BE), UBI `UBI#`, UBIFS `31 18 10 06`,
  xz `fd 37 7a 58 5a 00`, zstd `28 b5 2f fd`, LZ4 frame `04 22 4d 18`, lzop
  `89 4c 5a 4f 00 0d 0a 1a 0a`, the bzip2 block magic `31 41 59 26 53 59`, 7z
  `37 7a bc af 27 1c`, zip `PK 03 04`, cpio-newc `070701`, DTB
  `d0 0d fe ed`, cramfs `45 3d cd 28`, romfs `-rom1fs-`, `ANDROID!`,
  `U-Boot`, `Linux version`, `-----BEGIN`, and the ARM NOP word `0xE1A00000`
  at 4-byte alignment;
- weak hits are gzip `1f 8b 08` (three bytes; a chance hit every 16 MiB) and
  ARM forward-branch words `0xEA00xxxx` at 4-byte alignment (vector tables and
  literal-pool jumps; one chance hit per 65536 words).

**Text score** = number of printable-ASCII runs (`0x20`-`0x7e`, tab, LF, CR)
of at least 6 characters, plus the number of uppercase-then-lowercase pairs
inside those runs. A word swap only permutes bytes within a word, so a
printable string stays printable and the run counts of the three views are
nearly equal; the case-shape term is the only asymmetric part (a real word is
capitalised at its front, a reversed one at its back). Text therefore reports
what the examiner will see but decides only when no view has any structure.

Decision, in order:

1. **Veto.** If the raw view has any hit of an unambiguous strong magic, the
   answer is `None`: the raw view already yields findings. Magics whose own
   swap is another listed magic (`hsqs` <-> `sqsh` under swap32, JFFS2 LE <->
   BE under swap16) cannot tell the views apart and never veto; they still
   score.
2. **Basis.** The decision uses the structure score if any of the three views
   has one, else the text score.
3. **Candidate.** The swapped view with the higher basis score; a tie is
   broken by the text score; a full tie is `None`.
4. **Margin.** The candidate must score at least **2x the raw view** on the
   basis (`kMarginRatio = 2`) and at least 8 points (`kMinScore`, one strong
   hit). Otherwise `None`.
5. **Confidence** is the lower of a ratio tier and a volume tier:
   ratio >= 2x -> 60, >= 4x -> 85, >= 8x -> 99; candidate score >= 8 -> 60,
   >= 32 -> 85, >= 128 -> 99. One lone magic with nothing else is 60
   (structural), a swapped firmware with code and banners is 99.

The evidence string always carries the three views' counts, e.g.
`swap32 structure score 3736 is 207.5x the raw view's 18: raw 18/1182 (0
magics, 18 code words, 1182 ASCII runs), swap16 ..., swap32 3736/1086 (4
magics, 3704 code words, 1086 ASCII runs) [structure/text] in 2097152 sampled
bytes`, and on `None` it says which rule stopped the claim.

On the corpus: `MX25L165D.bin` -> Swap32 at confidence 99; `router.bin`
(uImage + SquashFS in the raw view) -> None by the veto; random bytes and
erased (`0xFF`) flash -> None (all three views score alike).

A format missing from the veto table is not a small omission. A bare `.bz2`
of high-entropy data has no structure in any view, so the decision falls
through to the text score, where a handful of accidental ASCII runs in the
swap32 rendering beat the raw view's — and the whole file is then analysed
swapped, its magic destroyed, and reported as one unidentified region.
bzip2's own "BZh" is three bytes and level-dependent, so the entry is the
48-bit block magic behind it, whose first copy is byte-aligned at offset 4.
Anything with a strong magic that a reader can open belongs here.

## In the analysis driver (discovery/Recurse)

At the word-swap extension point, before the whole-image scan, `analyze()`
runs `detect_word_swap` on the image unless the caller supplied
`AnalyzeOptions::image_view` (the hook wins and detection is skipped). When
the verdict is Swap16 or Swap32:

- the Image node gets `attrs.word_swap = swap32`,
  `attrs.word_swap_confidence`, and
  `Diagnostic{Warning, "image-word-swapped", <evidence>}`; a partial trailing
  word adds `Diagnostic{Info, "image-word-swap-tail", ...}`;
- a Coverage row `{"word-swap", "supported", "swap32 applied"}` is added (it
  appears in INFO.md's Coverage table);
- a `SwappedSource` over the image becomes the view the whole analysis runs
  on: scan, partition tables, re-scans, filesystem walks and carving. Every
  node below the Image carries `<image id>|swap32` in `location.source`; the
  Image node keeps the evidence's own id and hashes;
- carved files hold the corrected bytes and their names carry the suffix:
  `partitions/p1-swap32.bin`, `partitions/0x00100000-squashfs-swap32.bin`;
  `mount.sh` lists those names.

## Diagnostics

| code | severity | on | meaning |
|---|---|---|---|
| `image-word-swapped` | Warning | Image | the image is analysed through a swap16/swap32 view; message is the detection evidence |
| `image-word-swap-tail` | Info | Image | image size is not a multiple of the word size; the last 1-3 bytes are passed through unswapped |

## Known gaps

- Only whole-image swaps are handled. A dump where one partition is swapped
  and another is not, or where the swap unit differs by region, is analysed
  under the single verdict for the image.
- A 64-bit word swap and a nibble/bit-order reversal are not detected.
- Text-only images (no magic, no ARM code) are only detected when the
  case-shape asymmetry is large; an all-lowercase text partition stored
  swapped stays undetected and yields the usual `region-unidentified` nodes.
- Word alignment is taken from the start of the span given to
  `detect_word_swap`; the driver passes the whole image, which is what the
  swap unit is aligned to.
- Big-endian ARM code words are not in the table.
