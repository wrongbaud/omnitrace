# Artifact extractors

Three layers now answer three different questions about the same bytes, and it
is worth being precise about which is which:

| layer | question | output |
|---|---|---|
| `rules` | *does this pattern appear anywhere?* | a hit: offset and context |
| `analyzers` | *what kind of system is this?* | one report per filesystem |
| `artifacts` | *this file is a known thing; what does it contain?* | one record per object, with fields |

The difference is **parsing**. A search pack can say a
`-----BEGIN CERTIFICATE-----` block is present. Only a parser can say it was
issued to `CN=router` by itself, is valid until 2039, and has its **private
key sitting in the same file**.

Like the analyzers, this layer takes what the extraction produced and nothing
about how it was produced — a list of `(node id, entries)` pairs, no Span, no
Manifest, no `discovery::` type — so a finished case can be re-examined
without re-extracting it. `omnitrace report <case>` does exactly that: it
reads the listings back and runs the extractors again over the recovered
entries (`docs/CASE_LAYOUT.md`, "Reading a case back").

## Two rules the output follows

**Nothing secret is copied into a record.** A private key's record says a key
is present, what kind it is and how long. It never contains key material, and
a test asserts the serialised output holds no PEM body. This is the same
argument the analyzers make about password hashes: an examiner needs to know a
secret exists and how weak it is, and a report that quoted it would be a
credential store.

**Records that describe the same thing merge.** An extractor that summarises
emits one record per file it saw, keyed on the *thing* rather than the file,
and `collect()` adds them up: a numeric field sums, anything else keeps the
first value. Without it the corpus router's CA trust store is 127 rows that
each say "one CA certificate" and bury the one certificate the device actually
uses.

## certificates

Parses PEM certificates and private keys.

| kind | fields |
|---|---|
| `certificate` | `subject`, `issuer`, `not_before`, `not_after`, `self_signed`, `ca`, `key_type`, `key_bits`, `signature`, `dns_names` |
| `private-key` | `key_type`, `key_bits` — and a note that the material is deliberately absent |
| `certificate-bundle` | `certificates`, `expired_by_own_dates`, `first_subject` — one row per trust store, keyed on its directory |

A file under `etc/ssl/certs/`, `usr/share/ca-certificates/` or the Android
`cacerts` path is treated as a trust store: it shipped with the firmware and
says nothing about the device. Anything else was put there *for* this device
and gets a record of its own.

Validity is reported and never judged against the wall clock — the library
does not read one outside `core/Clock`, so "expired now" is the examiner's
call against `not_after`. The one thing judged is a certificate whose
`notAfter` precedes its `notBefore`, which was never valid at any time and
needs no clock to say so.

What the corpus holds, all of it found by this extractor:

| image | finding |
|---|---|
| router | `etc/lighttpd/server.pem` — self-signed `CN=router, O=vendor`, **with its RSA-2048 private key in the same file** |
| router | `etc/ssl/certs` — 252 CA certificates, counted |
| router-nand | `.android/adbkey` — an ADB authentication private key |
| router-nand | `etc/nginx/cert.key` — the web server's private key |
| camera-1 | `etc/vendor_mgmt/priv-key.pem` — RSA, **1024 bits** |

## kmodule

A Linux kernel module is an ELF relocatable object carrying a `.modinfo`
section of NUL-separated `key=value` records. That section is where a driver
states what hardware it is for, who wrote it, what licence it ships under and
which kernel it was built against, and it is the only place any of that is
written down.

This is the division of labour with the Linux analyzer, which also looks at
modules (`docs/ANALYZERS.md`). The analyzer answers *how many drivers and what
are they called* from the paths alone, and reads one `vermagic` to corroborate
the kernel release it took from the directory name. It stops there on purpose:
an analyzer that opened two hundred files to describe a platform would be
doing an extractor's job. This opens all of them.

| field | from |
|---|---|
| `module` | `name=`, or the file name, which is what modprobe would use |
| `description`, `author`, `license`, `depends`, `vermagic`, `firmware`, `srcversion` | the matching `.modinfo` record |
| `arch` | the ELF header's `e_machine`, so it is there even when the module carries no vermagic |
| `aliases`, `parameters` | **counts** of the repeating `alias=` and `parm=` records |

`alias` is how the kernel matches a module to hardware and a wireless driver
carries hundreds of them; a table of every alias is not a report, so they are
counted. The count is still a rough measure of how much a driver claims to
drive.

Two things are worth a diagnostic:

* `kmodule-vermagic-path-mismatch` — a module built for one kernel and
  installed under another **cannot load**. The platform report says a
  filesystem has the problem; this names the module, which is what an examiner
  needs to act on it.
* `kmodule-proprietary-license` — a licence that is not GPL, BSD, MIT or dual
  means the source was never published. The router-nand image has four
  (`ae_wan`, `eth`, `hw_nat`, `mt_wifi` — MediaTek's radio, switch and
  NAT-offload drivers), on a router whose firmware is otherwise GPL.

Measured across the corpus: 207 modules on the router image, 174 on router-nand,
116 on router-wrt, 14 on the camera v1.

## linux-kernel

A kernel image says two things about itself, and the first is the more widely
useful.

**The banner** is a plain string: `Linux version 5.4.55 (jenkins@...) (gcc
version 8.4.0 (OpenWrt GCC 8.4.0 unknown)) #0 SMP Fri Aug 15 02:53:20 2025`.
It names the kernel, the toolchain and the build date, and it is the *only*
source for any of them when a system has no `lib/modules` to read a release
out of. All four Linux images in the corpus give one up.

`Linux version ` has no magic behind it, so it has to earn the claim: the text
after it must parse as a release (digits, a dot, digits). Without that check
the router-wrt image produced a kernel record from the sentence *"Linux version of
the hub software for the Direct Connect network"*, whose version was `of`.
Same rule as every weak magic here.

**The symbol table.** A kernel that is not an ELF has no symbol table a normal
reader can use, so `CONFIG_KALLSYMS` puts one inside the image — the kernel
needs it to print names in an oops. `src/artifacts/kernel/Kallsyms.h` explains
how it is found; the short version is that none of its four structures has a
magic number, so it is read back to front from the one that is
self-describing, and accepted only when the names it produces look like
symbols.

| field | from |
|---|---|
| `version`, `banner`, `compiler` | the build banner |
| `arch` | the ELF header, when the image is an unstripped `vmlinux` |
| `symbols`, `symbol_types` | the kallsyms table: a count, and a histogram of nm type letters |
| `word_size`, `endian` | how the table was laid out, which is how the kernel was built |
| `loadable_modules` | whether `module_layout`/`load_module` is among the symbols |
| `address_mode`, `load_address`, `text_start`, `address_span`, `relative_base` | the address array (below) |

### Addresses

The names alone say what a kernel contains; the addresses say where it runs.
They live in a second array immediately before `kallsyms_num_syms`, which is
already known by the time the names decode, so this one is found by arithmetic
rather than by searching. What has to be *decided* is which of three forms it
is, because all three sit in the same place:

| mode | layout |
|---|---|
| `absolute` | `kallsyms_addresses`: one word per symbol, the address itself |
| `relative` | `kallsyms_offsets`: a u32 per symbol added to `kallsyms_relative_base`; the default since 4.6 |
| `relative-percpu` | `--absolute-percpu`: a *positive* entry is an absolute address, a negative one is `relative_base - 1 - entry` |

Base-relative is tested first because its `relative_base` word sits exactly
where an absolute array's last address would be, and reading that word as an
address is the obvious way to get this wrong.

The test that decides between them is that the **resolved** addresses ascend —
kallsyms is sorted by address — not that the stored entries do. They do not
always: under `--absolute-percpu` an ordinary symbol is stored as
`base - 1 - address`, so rising addresses are a *falling* raw array, and a
check on the entries rejects exactly the form it was meant to find. The
highest symbol must also look like a kernel address, which is the top half of
the address space on every architecture this meets.

Measured on the router-nand image: `relative`, `relative_base` `0xc0088000`,
`load_address` and `text_start` both `0xc0100000` — the ARM text base — over a
`0x9289ec` span.

The two halves are found separately on purpose. A table whose addresses cannot
be read still yields its names, and `symbols` is reported without the address
fields rather than the whole table being discarded.

`loadable_modules` is the one worth explaining. It decides what an empty
`lib/modules` means: a kernel that cannot load modules at all has its drivers
built in, and one that can is missing them.

Measured: the router-nand image decodes to **29,793 symbols** (`T=15300, t=14297,
W=195, D=1`), 32-bit little-endian, loadable modules yes.

## Known gaps

* **Two of three corpus kernels have no symbols to read.** The router image
  was built without `CONFIG_KALLSYMS` and says so
  (`kernel-no-symbol-table`). The camera v1's 3.10 kernel *does* carry a
  token table — its tokens read `_read`, `tion`, `attr`, `fs_`, `v4l` — and
  its markers array is found, but the names do not validate against it, so
  this build reports no symbols rather than guessing at some. That image is
  the one to aim the next attempt at.
* **Symbol names are not emitted, only counted.** Thirty thousand names is not
  a report, and the record has nowhere to put them; what an examiner gets is
  the histogram and the presence tests. Writing the table out as its own file
  in the case directory would need a new output, which is not modelled.
* **A kernel mapped low is not addressed.** Deciding which address array a
  kernel has rests on kernel addresses living in the top half of the address
  space, which is true of every architecture in the corpus and not of a nommu
  build or an unusual VA split. Such an image reports its symbols without
  addresses rather than reporting wrong ones.


* **Compressed modules are not parsed by name.** `.ko.gz`, `.ko.xz` and
  `.ko.zst` are modules but are not ELF until something decompresses them.
  Nested analysis does decompress them, and the payload reaches this extractor
  on its own; what is lost is the original path, so such a record names the
  payload rather than `lib/modules/…`. No corpus image ships compressed
  modules.
* **Built-in drivers are invisible.** A driver compiled into the kernel rather
  than built as a module has no `.ko` and no `.modinfo`; `modules.builtin`
  lists them by name and is not read yet. A system with no `lib/modules` at
  all is usually this, not a system with no drivers.
* **DER, PKCS#12 and JKS are not read.** Only PEM. A binary certificate store
  is passed over silently, which is why `applies()` also accepts a `.crt` or
  `.cer` by extension and reports `artifact-certificate-unparsable` when it
  turns out not to be PEM.
* **Encrypted private keys are not distinguished.** `PEM_read_bio_PrivateKey`
  is called without a passphrase callback, so an encrypted key simply fails to
  parse and is reported as unparsable rather than as "a key that is protected".
  That understates a file's contents and is worth fixing.
* **Certificates inside unidentified regions are not parsed**, only ones in
  extracted files. The rules pack still finds the block.

## Adding an extractor

1. `src/artifacts/<name>/<Name>Extractor.cpp`, registered with
   `OMNITRACE_REGISTER_EXTRACTOR("<name>", <Name>Extractor)`.
2. An anchor function, called from `link_builtin_extractors()` in
   `src/artifacts/Registry.cpp`.
3. Tests in `tests/unit/artifacts/` — including hostile input, since an
   extractor is handed every file in a case.
4. Diagnostic codes in `docs/reference/diagnostics.yaml`.

`applies()` runs for **every extracted file in the case**, so it must be a
path or magic test and must never parse. `extract()` is only called on files
it claimed.
