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
| Android | 2 | not yet |
| QNX | 2 | not yet |
| RTOS | 0 | not yet |

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
