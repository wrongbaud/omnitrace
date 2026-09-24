# Reports

`analyze` writes `report.html` and `report.md` at the end of every run, and
`omnitrace report <case>` re-renders a finished case directory.

## A report is data, not a string

The previous generation of this built Markdown by concatenation and shelled
out to pandoc in a container to get HTML. That was rejected for three reasons
and all three still hold:

* **Provenance.** A report is evidence. It must not depend on a toolchain that
  may not be installed, or that differs between machines.
* **Escaping.** String concatenation puts a device's own bytes into markup. A
  partition named `<script>alert(1)</script>`, a certificate subject with a
  pipe in it, a banner with an embedded newline — all attacker-controlled.
* **Determinism.** The same case must render byte-identically every time, or
  two reports of the same evidence cannot be compared.

So a report is built as a typed `Document` — sections of `Paragraph`, `Table`,
`KeyValues`, `Callout`, `CodeBlock` and `BulletList` — and rendered once.
A caller never writes markup, and each renderer escapes for its own format.
Ragged tables are squared to the header width rather than emitted, so a short
or over-long row cannot produce broken output.

`src/report/` depends on **core and nothing else**, which is what makes it
liftable into the standalone `omnireport` of DEVELOPMENT_PLAN §7. It knows
about sections and tables and nothing about filesystems, platforms or
certificates; `apps/cli/report_document.cpp` has that knowledge and builds the
Document.

## The integrity gate

A report is a claim about specific bytes. Before rendering, every piece of
evidence the case names is **re-hashed and compared** with what the case
recorded, and the result is a table in the report's first section:

| state | meaning |
|---|---|
| `verified` | still hashes to what the case recorded |
| `MISMATCH` | the file has changed — `report-integrity-mismatch` |
| `missing` / `unreadable` | not where the case left it — `report-evidence-missing` |
| `no recorded hash` | nothing to check against — `report-evidence-unhashed` |

A mismatch does not suppress the report; it is stated in it. Every offset in a
report refers to the bytes the case recorded, and if those are not the bytes on
disk now, the only honest thing is to say so where the reader will see it.
Nothing checked is **not** the same as everything passing, so a case with no
evidence rows is not "verified" either.

## Sections

| section | from |
|---|---|
| Examiner's notes | `--notes`, when given (see below) |
| Evidence | the manifest's evidence rows, plus the live integrity check |
| Structure | node counts, formats identified, the partition and filesystem map |
| Platforms | the analyzers (`docs/ANALYZERS.md`) |
| Extracted artifacts | the extractors (`docs/ARTIFACTS.md`) |
| Search hits | the packs (`docs/RULES.md`), summarised by severity and rule |
| Coverage and limits | what was **not** extracted, and why |
| Diagnostics | every code the run produced, by frequency |

A section whose data was not produced is left out entirely rather than
rendered empty: a missing section says less than one claiming nothing was
found.

## `omnitrace report <case>`

Reads `INFO.yaml` and every `filesystems/<node>/listing.yaml` back, then
**re-runs the analyzers and the extractors over the recovered entries** before
rendering. A case directory is enough to re-examine; the evidence itself is
read only to verify it.

That works because the post-analysis layers take a list of `(node id,
entries)` pairs and nothing about how the extraction happened — the
decoupling that `docs/ANALYZERS.md` argues for is what this subcommand spends.
A case made on another machine, by an older build, or from evidence that is no
longer attached still produces platforms and artifacts.

**The search packs are the one thing not re-run**, and they do not need to be.
A sweep wants the image rather than the case, and re-reading a 16 GiB dump to
re-find hits already written to `artifacts.yaml` is work for no gain — so the
hits are read back out of that file instead (`rules::artifacts_from_yaml`).
What the section shows is therefore the sweep that happened, not a second
opinion about it.

That reader is stricter than it looks, for one reason. A file cut short while
being written parses perfectly well and yields fewer hits than its own
`summary.hits` claims, and a report quietly printing the smaller number as a
finding is the most misleading thing this could produce. A disagreement is a
**failure**, and the CLI says `report-hits-unreadable` and omits the section
rather than understating it. A case with no `artifacts.yaml` at all is a
different thing — no packs ran — and the section is simply absent.

What a moved or gutted case does:

| the case | what the report says |
|---|---|
| in place | everything, as `analyze` wrote it |
| copied or moved | everything; the files beside each listing are read, and `case-relocated` says the recorded paths no longer match |
| `files/` deleted | metadata-only facts (paths, counts, names); anything needing file contents is simply absent, never guessed |

A recorded `host_path` outside the case directory is **never** followed. It
belongs to another machine or another case, and following it produced a report
about somebody else's bytes — which is the bug that rule exists to prevent.

The claim is measured rather than argued: re-rendering a *copy* of the
110,937-node QNX case reproduces **all seven sections byte-identically** to
the ones `analyze` wrote, 53,402 search hits included. The only difference in
the whole document is the case directory's name in the subtitle, which is
correct — it is a different directory.

The integrity check runs either way, and is reason enough on its own:
re-hashing evidence months later, against a case made then, is exactly the
question to answer before relying on anything in it.

`--out DIR` writes the two files somewhere else and leaves the case untouched.

## Who says so

A report that cannot name the person making its claims is not much use outside
the machine that produced it. `analyze` and `report` both take `--case-id`,
`--examiner` and `--notes`, and `analyze` writes them into `INFO.yaml` under
`case:` so that re-rendering the case years later still names them.

Nothing here is derived. Every other field in the header comes from the tool
or from the evidence and can be checked against something; these come from the
examiner, are checked against nothing, and are repeated as **their** claim.
That is why they are a separate `CaseInfo` rather than more fields on
`RunInfo`, which records only what the tool did.

`--case-id` and `--examiner` are rows in the header grid. `--notes` is its own
section, because free text of any length does not belong in a two-column grid.
A flag given to `report` overrides that one field and leaves the others alone:
adding a case number to an old case must not silently drop the examiner's
name. The block is written only when at least one field is set, so a case made
without them is byte-identical to one made before the flags existed.

These strings reach the markup like any other, and the renderers escape them
for their own format — a case number containing `|` does not break a Markdown
table and one containing `<script>` does not survive into the HTML. The
threat model is not a hostile examiner; it is a case number pasted from a
system that allows anything.

## Known gaps

* **No PDF.** HTML that prints well is the substitute, and the print
  stylesheet inverts the palette for paper.
* **No figures.** §7's `Figure(base64)` block is not modelled; nothing in a
  firmware report needs one yet.
* **No C ABI or pybind11 module.** §7 wants both so OmniSonde can adopt this;
  the layer is shaped for it (core-only, no exceptions across the boundary)
  but neither is written.
