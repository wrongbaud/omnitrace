# Diff: what changed between two cases

`omnitrace diff <case-a> <case-b>` answers the question an examiner with two
units of the same model actually has: **what is different about this one?**

It is asked of *cases*, not of images. Both sides are read back with
`output::load_case_listings` and the analyzers re-run over the recovered
entries, so it works months later on evidence that is no longer attached —
the same decoupling `omnitrace report` spends (`docs/REPORT.md`). Neither case
is modified; `diff.md` and `diff.yaml` go to `--out`, or to the working
directory.

## Nothing is matched on node id

Node ids are assigned in discovery order. The same filesystem is `n000018` in
one case and `n000021` in the other as soon as anything earlier in the image
differs by a byte, so matching on them would report two acquisitions of one
device as having nothing in common.

Files are compared **by path**, and separately **by content**. That second
view is what survives a vendor moving a directory, and it is the same lesson
the parity harness learned about comparing tools (`docs/PARITY.md`): a file
that moved is one removal and one addition by path and neither by content, and
the gap between the two numbers is the interesting part.

| row | means |
|---|---|
| Same path, same contents | unchanged |
| Same path, different contents | edited |
| Only in A / Only in B | added or removed, *by path* |
| Contents in both | distinct sha256 present on both sides |
| …under no shared path | **moved or renamed** rather than edited |

A path that occurs in more than one filesystem keeps every digest found at it,
so a case that ships two copies of a file is not reported as disagreeing with
itself.

**Deleted and superseded entries are not compared.** A file recovered from one
case and not the other says something about recovery, not about the device.

## What each system says about itself

The analyzers are re-run over both cases and their facts keyed on the fact's
own name, across every filesystem — again because the reports carrying them
are identified by node id. A key a case states more than once keeps every
value, so a disagreement *inside* one case is not mistaken for a difference
*between* them; those show up as `a | b` in a cell.

## Parsed records

Certificates, private keys, kernel modules and kernels are compared by **what
each kind says identifies it**, not by where the file sat. `Artifact::identity`
is set by the extractor, because only the extractor knows:

| kind | identity |
|---|---|
| `certificate` | the SHA-256 fingerprint of its DER |
| `kernel-module` | the module name |
| `linux-kernel` | the build banner |
| anything else (`private-key`, `certificate-bundle`) | none; the path is used |

A vendor moving `server.pem` has not issued a new certificate, so that is
reported as the same record *moved* — where a key lives is part of what it
protects. A **reissued** certificate has the same subject and a different
fingerprint and is a different record; keying on the subject would hide
exactly the event an examiner is looking for.

A private key has no identity by design: its material is deliberately never
recorded (`docs/ARTIFACTS.md`), so nothing distinguishes two of them but where
they were found.

For a record in both cases, every field is compared and the ones that disagree
are listed. A module rebuilt against a new kernel keeps its name and changes
its `srcversion`, which is what says it was rebuilt.

**The count is of distinct records, not of rows.** Two files holding the same
certificate are one certificate, so `same + changed + only-in-A` is exactly
`records_a`; reporting the row count instead would leave a gap with nothing to
explain it.

### On two OpenWrt routers

```
parsed records: 211 in A, 181 in B; same 0, changed 66, only in A 145, only in B 115
```

`CN=router, O=vendor` on one and `CN=ROUTER, O=vendor.example` on the other; a CA
trust store at the same path holding **252 certificates in one and 148 in the
other**.

## Kernel symbols

Compared **by name**, from the `symbols/*.txt` tables (`docs/ARTIFACTS.md`).
Addresses move whenever anything is recompiled, so comparing those would
report every kernel as entirely different; a name appearing or disappearing is
what says a driver was added or removed. Names are deduplicated, so the count
here is a little under the table's line count — a kernel has several symbols
sharing a name.

When only one case has a table there is nothing to compare against, and
"14,589 symbols only in A" is simply every symbol A has. The count stays, the
names are not listed, and `diff-symbols-one-sided` says why.

## Worked example

The two camera firmware images in the corpus, one release apart:

```
omnitrace diff case-c100v1 case-c100v2
```

```
files: 697 in A, 740 in B
same 499, changed 182, only in A 5, only in B 48, moved 0
platform facts that differ: 5
```

What it surfaces, none of which is visible in either case alone:

| fact | A | B |
|---|---|---|
| `os.build_id` | `41bbac3d…` | `f1ba935f…` |
| `service.telnet` | — | `usr/sbin/telnetd` |

The newer firmware ships a **telnet daemon** and a `telnet` init service that
the older one does not. That is the kind of finding this exists for.

## Limits

Lists are capped at `DiffLimits::max_listed` (200) per category; **the totals
are always exact and are taken before the capping**. Reporting a capped list's
length as the count is how a diff comes to understate what it found.

## Known gaps

* **Filesystems are not matched, only flattened.** Every path in a case is
  compared against every path in the other regardless of which filesystem it
  came from. For two dumps of one model that is what you want; for a case
  holding two unrelated roots with overlapping paths it merges them.
* **Only live regular files.** Directories, symlinks and device nodes are not
  compared, so a file becoming a symlink reads as a removal.
* **A record with no identity is keyed by path.** Private keys and trust
  stores move as often as anything else, and one that did reads as a removal
  and an addition rather than a move.
* **No image-level diff.** Partition tables, carved regions and unidentified
  areas are not compared — only what was extracted.
