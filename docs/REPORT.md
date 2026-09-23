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

Reads `INFO.yaml` back and rebuilds the sections the manifest holds —
Evidence, Structure, Coverage, Diagnostics — and runs the integrity check.

**The platform, artifact and search sections are not among them.** Recovering
those needs readers for `platform.yaml`, `certificates.yaml` and
`artifacts.yaml`, which do not exist yet; `analyze` writes the full report
because it has all four results in hand. The subcommand earns its place on the
integrity check alone: re-hashing evidence months later, against a case made
then, is exactly the question to answer before relying on anything in it.

## Known gaps

* **No PDF.** HTML that prints well is the substitute, and the print
  stylesheet inverts the palette for paper.
* **No figures.** §7's `Figure(base64)` block is not modelled; nothing in a
  firmware report needs one yet.
* **The standalone path is partial**, as above. A `listing.yaml` reader would
  close it and would also give the analyzers and extractors the standalone
  path they were designed for.
* **No C ABI or pybind11 module.** §7 wants both so OmniSonde can adopt this;
  the layer is shaped for it (core-only, no exceptions across the boundary)
  but neither is written.
