# Entropy: what unidentified bytes look like

`omnitrace analyze` reports a `region` node for every run of bytes no
signature matched, and a real image is mostly regions. "Unidentified" on its
own tells an examiner nothing, so every region also carries what its bytes
look like statistically: erased flash they can ignore, a config area worth
reading, or a payload that cannot be read at all.

This is the capability `binwalk -E` provides as a plot. Here it is a
measurement attached to the node, because the manifest is the product.

## What is measured

`omnitrace::entropy` (`include/omnitrace/core/Entropy.h`,
`src/core/Entropy.cpp`) profiles a span in windows and reports:

| field | meaning |
|---|---|
| `mean` | Shannon entropy in bits per byte, averaged over windows (0.0 to 8.0) |
| `min`, `max` | the quietest and busiest window, which finds a run of padding inside an otherwise busy region |
| `chi_square` | chi-square of the pooled byte histogram against a uniform distribution, divided by its 255 degrees of freedom |
| `printable` | fraction of bytes that are printable ASCII, tab, LF or CR |
| `uniform_fill`, `fill_byte` | every sampled byte was the same value |
| `sampled`, `windows` | how much was actually read |

A window is 4096 bytes by default — a flash page, and large enough that text,
code and compressed data each read the way an examiner would call them.
Entropy is a property of a window, not of a byte: too small and everything
looks random, too large and a short compressed run is averaged away.

Reads are bounded at 8 MiB by default and sampled in evenly spread windows,
the same way `detect_word_swap` samples an image, so profiling a 15 GiB
region costs the same as profiling a 16 MiB one. Sampling is deterministic,
so the manifest stays reproducible.

## The classes

| class | what it means |
|---|---|
| `erased` | one byte value throughout: erased NOR flash (`0xFF`), zero fill. Holds no data. |
| `sparse` | nearly one value: padding, a sparse table, a mostly-blank area |
| `text` | mostly printable: configuration, logs, scripts, PEM |
| `binary` | structured non-text: code, filesystem metadata, mixed data |
| `packed` | high entropy but measurably non-uniform: compressed data |
| `random` | high entropy *and* uniform: compressed or encrypted |
| `unknown` | too few bytes to say (under 256 by default) |

The thresholds are in `src/core/Entropy.cpp` as named constants, and they are
conventions rather than laws — the class tells an examiner where to look
first, and `Profile` keeps the raw numbers for anyone who disagrees with
where the lines fall.

## Why `random` does not say "encrypted"

Entropy cannot prove encryption. A good compressor's output is *meant* to
look random, and it does. The chi-square test is the sharpest line available
— it separates uniform from merely-nearly-uniform — and measured against real
compressors it only gets part of the way:

| input | mean bits/byte | chi²/df | class |
|---|---|---|---|
| erased flash (`0xFF`) | 0.000 | huge | `erased` |
| `/etc/passwd`-like text | 3.868 | 5683 | `text` |
| an ELF executable | 5.677 | 38871 | `binary` |
| gzip -9 | 7.928 | 15.19 | `packed` |
| bzip2 -9 | 7.935 | 7.28 | `packed` |
| zstd -19 | 7.950 | 4.25 | `packed` |
| **xz -9** | **7.951** | **0.995** | **`random`** |
| **AES-256-CBC** | **7.954** | **0.971** | **`random`** |
| `/dev/urandom` | 7.953 | 0.882 | `random` |

(The same 1 MiB executable compressed each way, profiled with the defaults.)

gzip, bzip2 and zstd are separable from cipher output. **xz is not** — at
0.995 against AES's 0.971 it is statistically indistinguishable, and no
threshold can split them. That is not a gap to be closed later; it is what
LZMA's range coder is for. So `random` is documented as "compressed or
encrypted, which these numbers cannot tell apart", and nothing in the
manifest ever asserts a cipher from a measurement.

What makes the signal useful anyway is the company it keeps. A compressed
payload in firmware normally arrives with a header this tool already
recognises, so it becomes a `container` node, not a region. A `random` region
is high-entropy bytes that *also* carry no magic anywhere across their whole
length — which is a real lead, just not a verdict.

## On the node

An unidentified region gets:

```yaml
attrs:
  entropy: "7.955"
  entropy_chi2: "1.213"
  entropy_class: random
diagnostics:
  - severity: info
    code: region-high-entropy
    message: "8128512 bytes at 7.955 bits/byte (random): high entropy and uniform:
      compressed or encrypted, which these numbers cannot tell apart. No signature
      matched, so it is either a format this build does not know, a headerless
      compressed stream, or ciphertext"
```

`region-high-entropy` is raised only for `packed` and `random`. Saying so on
every text or binary region would be noise.

`fill` is kept alongside `entropy_class: erased` and still means what it
always did: *every* byte of the region is that value. It comes from a full
scan that stops at the first byte that differs, not from the sample, because
it is an exact claim and a sampled profile could not make it.

## Verified on

* `corpus/camera-example-3` and `-4` (camera v4 and v5): the whole image is
  one region at **7.955 bits/byte, chi²/df 1.21 and 1.14**, `random`, with no
  signature anywhere in 8 MB. Their v1 and v2 siblings from the same product
  line extract fully and show `binary` and `sparse` regions instead. Consistent
  with whole-image encryption, which the filenames (`up_boot-signed`) support
  and these numbers alone do not prove.
* Across the rest of the corpus the classifier produces `erased`, `sparse`,
  `text`, `binary` and `packed` regions and **no `random` ones**, so the class
  that matters is not being handed out to ordinary firmware.

## Not yet supported

* No per-window series is exported, so nothing can plot the profile of an
  image the way `binwalk -E` draws it.
* Only `region` nodes are profiled. Partitions, filesystems and containers
  carry no entropy attr, so a report cannot yet show the profile of each
  partition the way moria does.
* Nothing uses the profile to *decide* anything: a `random` region is not
  carved differently, and the class never changes a finding's confidence.
