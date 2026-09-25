# OmniTrace v2

OmniTrace is an offline, cross-platform forensic analysis tool for embedded systems, written in C++20. Give it a raw SPI, NAND or eMMC dump and it hashes the evidence, maps the partitions and filesystems inside it, carves each one to its own file, extracts what it can read, and writes the result as a case directory that people read as Markdown and tools read as YAML.

It is for forensic examiners who receive flash dumps rather than phone extractions, embedded security researchers who want a traceable map of an image, and agents that consume `INFO.yaml`.

**Status:** Phases 0-2 complete — identification, extraction, recovery, search, platform analysis, artifact parsing, reporting, two-case comparison and handover. Phase 1's parity criterion is measured and met against unblob and moria. See the [roadmap](ROADMAP.md).

## Quick start

```sh
cmake --preset linux-gcc
cmake --build --preset linux-gcc --parallel
ctest --preset linux-gcc
./build/linux-gcc/apps/cli/omnitrace analyze router.bin --out case-router
less case-router/INFO.md
```

`CONTRIBUTING.md` at the repository root lists the packages per OS.

## Find a document

| You want to | Read |
|---|---|
| run the tool and understand its flags | [CLI](CLI.md) |
| know what is in a case directory and what to rely on | [Case layout](CASE_LAYOUT.md) |
| see which formats are handled and how well | [Formats](reference/FORMATS.md) |
| learn the project vocabulary | [Glossary](GLOSSARY.md) |
| follow the rules every change must obey | [Architecture](ARCHITECTURE.md) |
| walk the code in an hour | [Code tour](CODE_TOUR.md) |
| read the public headers in order, or build the Doxygen reference | [API](API.md) |
| add a validator, reader, signature or command | [Extending](EXTENDING.md) |
| build the fixtures and run the parity harness | [Testing](TESTING.md) |
| pick something to work on | [Roadmap](ROADMAP.md) |

The full grouped index, including every format page and the background documents, is in `docs/README.md` in the repository; the navigation on the left mirrors it.
