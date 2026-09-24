# Platform analyzers

Discovery answers *what is this?* and the search packs answer *is the thing an
examiner came looking for in here?*. The analyzers answer the question between
them: **what kind of system is this, and what does it say about itself?**

A case that lists 2,716 files is an inventory. One that says *OpenWrt 18.06.1,
ramips/mt76x8, mipsel_24kc, seven accounts, and root logs in with no password*
is a starting point.

Output is `platform.yaml` and `platform.md` in the case directory, written by
`analyze` before the search packs run — a platform report is the context the
hits should be read in.

## One report per filesystem

Not one per case. An image routinely holds several systems: an automotive Android unit infotainment
unit carries QNX IFS images and an Android `super` in the same eMMC, and
collapsing that to a single answer loses the more interesting half. A
filesystem that nothing recognises is counted and reported
(`platform-unrecognised`) rather than passed over — a data partition has no
platform, and a system this build does not model is worth knowing about.

## An analyzer never sees the extraction

`survey()` takes a list of `(node id, entries)` pairs — `EntryResult` values
and nothing else. No `Span`, no `Source`, no `Manifest`, no `discovery::`
type; `src/analyzers/` depends on `core` and `output` and does not link
against `discovery` at all.

That is a deliberate constraint rather than an accident of ordering. An
analyzer that reached back into the scan would answer questions about *how the
bytes were found* when it is supposed to answer questions about *what the
system is*, and the two drift apart the moment a filesystem arrives some other
way — nested three levels down, carved by hand, or read back from a case made
last year.

`omnitrace report <case>` is what spends it. It reconstructs the entries from
`filesystems/<node>/listing.yaml` and runs the same `survey()` over them, so a
case directory alone is enough to re-derive every platform report without
re-extracting anything (`docs/CASE_LAYOUT.md`, "Reading a case back"). The
extractors in `src/artifacts/` take the same shape for the same reason.

## Every fact names its source

A report is a set of `(key, value, source)` triples where `source` is the entry
path the value came from, after symlink resolution. That is what makes it
checkable: an examiner can open `etc/openwrt_release` in the case directory and
disagree. Nothing is inferred from a file that could not be read — if the bytes
are not there, the fact is absent rather than guessed.

Where two files answer the same question and agree, it is said once. Where they
disagree, both are kept with their sources and
`platform-release-disagrees` says so; a vendor rebuild that edits one release
file and not the other looks exactly like that.

## The `Tree` resolves symlinks inside the filesystem

`/etc/os-release` is a symlink to `../usr/lib/os-release` on every modern
Linux, and one corpus router has **438 symlinks** in a single tree. An analyzer
that only looked at regular files would miss the most useful file on the
system.

Resolution walks the reader's listing, never the host filesystem. A link target
of `../../../../../../etc/passwd` resolves within the tree exactly as the
filesystem itself would clamp it at its own root, so it cannot reach outside
the case directory; loops and absurd chains stop at 16 hops. Deleted and
superseded entries are excluded — history has its own value, but describing a
running system from a deleted file describes a machine that no longer existed.

## Detection: score, then rank

Each analyzer returns a count of markers it matched; 0 means "not mine". When
two analyzers both claim a tree the **higher rank wins regardless of score**,
because the question is which answer is more precise, not which found more
files. Android is Linux: a Linux analyzer will always also match an Android
tree, and no amount of marker counting fixes that.

| analyzer | rank | state |
|---|---|---|
| Linux | 1 | implemented |
| QNX | 2 | implemented |
| Android | 2 | implemented — **never run against a real Android image** |
| RTOS | 0 | not yet |

QNX outranking Linux is not theoretical. A QNX root carries `etc/passwd`,
`etc/group`, `etc/shadow`, `proc/` and `usr/lib`, so the Linux analyzer scores
**five** markers on the automotive Android unit's IFS images and would report an infotainment
unit as Linux.

## Linux

Markers are things a Linux root has and a QNX IFS, a FAT data partition or a
firmware blob does not — `etc/passwd`, `etc/inittab`, `bin/busybox`,
`etc/init.d/`, a release file. Deliberately not "does `/etc` exist".

What it reports:

| keys | from |
|---|---|
| `os.pretty_name`, `os.name`, `os.id`, `os.version`, `os.version_id`, `os.build_id` | `os-release`, `lsb-release` |
| `os.target`, `os.arch` | `openwrt_release` (os-release does not carry these) |
| `os.hostname`, `os.banner` | `etc/hostname`, `etc/banner` |
| `users.count`, `users.with_password`, `user.uid0`, `user.<name>.password` | `etc/passwd`, `etc/shadow` |
| `network.*` | `etc/config/network`, `etc/config/wireless`, `etc/resolv.conf` |
| `init.dir`, `init.count`, `init.services`, `service.ssh`, `service.telnet`, `userland.busybox` | `etc/init.d`, `etc/rc.d`, binaries |
| `kernel.version`, `kernel.vermagic`, `kernel.modules.*` | `lib/modules/<release>/`, a module's `.modinfo` |

### The kernel, and the drivers it carries

`lib/modules/<release>/` answers both questions at once: the directory name
**is** `uname -r`, and everything under it is the module set. That beats the
alternatives available inside a root filesystem — os-release says nothing about
the kernel, and the `Linux version` banner lives in the kernel image, which is
a *different node* and so outside what a per-filesystem analyzer can see.

Two layouts exist and the corpus has both. `make modules_install` writes
`lib/modules/<rel>/kernel/<subsystem>/…`, which classifies every driver for
free and becomes `kernel.modules.subsystems`. OpenWrt installs every module
into one flat directory, where there is no subsystem to report and the module
name is **not** guessed at from a list of known driver names.

The release is taken from the union of the directory entries under
`lib/modules` and the first path component of the modules themselves, because
either source alone has a hole: an archive built without directory members has
no directories to list, and a release directory holding no modules has no
module paths.

A module's `vermagic` is then a second, independent witness:

| image | `kernel.version` | `kernel.vermagic` |
|---|---|---|
| router-wrt-example | 2.6.22.19 | `2.6.22.19 mod_unload MIPS32_R2 32BIT` |
| camera-example-1 | 3.10.27 | `3.10.27 preempt mod_unload RLX 32BIT` |
| router-example | 4.14.63 | *(its modules carry none)* |
| router-nand-example | 5.4.55 | `5.4.55 SMP mod_unload ARMv7 p2v8` |

Agreement is worth nothing to report; **disagreement is the reason it is
read**. Modules built against a different kernel than the one they are
installed under do not load, and on a device that is a mismatched vendor
update (`platform-linux-kernel-mismatch`). The string also carries the CPU
architecture, which nothing else in the filesystem states — `RLX` on the camera is a Realtek Lexra core, and no release file says so.

`kernel.modules.autoload` is a shorter and more telling list than the module
set: it is what the system loads at boot, from `etc/modules.d/` (OpenWrt, one
file per module) or `etc/modules`.

The `.modinfo` lookup here is deliberately crude — it finds one key in the
sanitised bytes rather than parsing ELF section headers — because it exists
only to corroborate a version already established from the directory name. The
full per-module inventory, parsed properly, is an artifact extractor's job
(`docs/ARTIFACTS.md`).

**The password field means different things in the two files**, and getting
that wrong misreports whether a system could be logged into. In `passwd`, `x`
means "the secret is in shadow" and is the normal case. In `shadow`, `x` is not
a crypt string at all, so nothing a user types can ever match it and the
account cannot be logged into. An *empty* field in either means the account
authenticates with **no password**. All three are in the corpus:

| image | root | meaning |
|---|---|---|
| router-example | `root::` in shadow | logs in with no password (`platform-account-no-password`) |
| router-nand-example | `$1$…` in shadow | md5, cracks quickly (`platform-account-weak-hash`) |
| camera-example-1 | `$1$…` in **passwd**, `x` in shadow | the hash sits in the world-readable file |

**The hash itself is never copied into the report.** What matters is that an
account has one and how well it resists cracking; a report that quoted hashes
would be a credential store. Read it from the named file if it is needed.

## QNX

Markers are things only a QNX *system* has: `proc/boot` (where the IFS is
mounted), `etc/system/config`, `qconn`, the secpol tooling, and QNX's
resource-manager naming — `devb-*` block drivers, `devc-*` character drivers,
`io-*` stacks. Nothing on Linux is called `devb-umass` or `io-pkt`. At least
one of those is required before anything is claimed.

**`.boot` is deliberately not a marker.** Every QNX6 *filesystem* has an empty
`.boot` directory at its root — it is where the boot file lives — so it says
the partition is QNX6, which discovery already reports as the format, and
nothing about whether a system is on it. Using it claimed five pure data
partitions in the corpus (`deviceInfo/DID/keymgr-store`, `bt/dbus/IPC/mdnsd`)
as QNX systems, each on that single marker with an empty fact table.

What it reports:

| keys | from |
|---|---|
| `build.id`, `build.timestamp`, `build.product`, `build.secure_boot`, `build.soc`, `build.vendor.*` | the other automotive vendor's `Buildinfo.txt` — QNX itself has no `os-release` |
| `build.part_number`, `build.group`, `build.jenkins`, `build.git_commit`, `build.guid`, `build.components` | one automotive vendor's `artifact.json` |
| `users.*`, `user.<name>.password` | `etc/passwd`/`shadow`, **or `proc/boot/passwd`** |
| `service.<name>`, `services.inetd` | `etc/inetd.conf`, with the user each service runs as |
| `security.secpol`, `security.secpol_files`, `security.chroot` | `proc/boot/secpol*`, `etc/secpolgenerate.cfg` |

**Accounts can live in the boot image.** The automotive QNX unit in the QNX corpus has
`proc/boot/passwd`, `proc/boot/group` and an entirely empty `/etc`; looking
only at `etc/passwd` reported nothing at all about a 945-entry system.

**QNX's hash format is not crypt(3).** It writes `@S@<base64>@<base64>`. A
crypt-only reader calls that "unrecognised", which would report a *hashed*
root account as having no usable password — the opposite of the truth. That is
why `hash_kind` lives in `src/analyzers/Common.h` and not in either analyzer.

## Android

> **This model has never seen a real Android tree.** Every marker and fact key
> comes from the documented AOSP layout, not from evidence: the only Android
> image this project can reach is the automotive Android unit's `la_super`, whose drive was
> disconnected before it was written, and no corpus image contains Android
> (`ro.build.fingerprint`, `ro.build.version.release` and
> `ro.product.manufacturer` score zero across all of them). The QNX model,
> which *was* aimed at evidence, had six things corrected by the corpus that
> its fixtures could not catch. Treat this as a first draft to be checked
> against `la_super`, not as something shown to work.

Strong markers are `build.prop` (at the tree root *or* under `system/`, since
system-as-root moved it), `bin/app_process*`, `framework/framework.jar`,
`etc/permissions/`, `priv-app/`, `apex/`, and `system/packages.xml`. At least
one is required.

**A device is several partitions, not one filesystem.** `system`, `vendor`,
`product`, `system_ext`, `data` and the boot ramdisk arrive separately and say
different things, so the model reports `android.partition` — user data is not
firmware, and calling both "android" loses the distinction that matters most.

| keys | from |
|---|---|
| `os.fingerprint`, `os.version`, `os.sdk`, `os.security_patch` | `build.prop` |
| `device.model`, `device.manufacturer`, `device.brand`, `device.abi`, `device.soc` | `build.prop` |
| `security.debuggable`, `security.secure`, `security.verified_boot` | `build.prop` |
| `users.count`, `apps.packages_xml`, `apps.data_dirs` | a `data` partition |

`os.security_patch` is reported and never judged: deciding whether a patch
level is "old" needs a clock, and the library does not read one outside
`core/Clock`.

### Build manifests

QNX carries no `os-release`, so what identifies a shipped unit is the
integrator's own manifest — and integrators do not agree on a format. The other automotive vendor
writes `Buildinfo.txt` as `KEY=VALUE`; One automotive vendor writes `artifact.json`, reached on
the corpus unit through a symlink from the tree root to the **absolute** path
`/fs/os/artifact.json`, which `Tree` roots at the filesystem rather than the
host. Both are read, and each fact names the file it came from.

The JSON reader keeps **only the top level**: scalar members as strings, and
the element *count* of array members. Two reasons, both about evidence rather
than convenience:

* **A bill of materials is counted, not listed.** The automotive QNX unit manifest's
  `component` array has 181 entries of twelve fields each. 2,172 facts is not
  a report; `build.components` says the list is there and names the file.
  Enumerating it is artifact-extractor work.
* **It is parsed through a SAX handler with a depth limit**, never into a
  document. A recursive-descent parse of deeply nested JSON is a stack
  overflow rather than a parse error, and a manifest is a flat record — 32
  levels is already generous. A document past the limit is refused whole,
  yielding nothing rather than a partial read, and says so with
  `platform-manifest-unreadable`.

## How accounts are reported

An account gets its own row only when it has a **real hash** or an **empty
password** — the two states an examiner acts on. Every other state is counted
(`users.password_locked`, `users.password_invalid`, …), because the automotive QNX unit boot
image has 286 accounts and 286 rows reading `in-shadow` is not a report.

Counts come from the authoritative file: `shadow` when there is one, `passwd`
otherwise. The same count key means different things in the two files, so
emitting from both makes them collide.

## Adding an analyzer

1. `src/analyzers/<name>/<Name>Analyzer.cpp`, registered with
   `OMNITRACE_REGISTER_ANALYZER(Platform::X, XAnalyzer)`.
2. An anchor function, called from `link_builtin_analyzers()` in
   `src/analyzers/Registry.cpp`, so static linking keeps the registrar.
3. Tests in `tests/unit/analyzers/` (the directory is globbed).
4. A row in the rank table above, and diagnostic codes in
   `docs/reference/diagnostics.yaml`.

Detection should be cheap and path-based; `describe()` is only called on the
winner, so that is where parsing belongs.
