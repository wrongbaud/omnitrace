#!/usr/bin/env python3
"""check_docs.py - fail when the documentation no longer matches the code.

Python 3 standard library only; no build needed. Run from anywhere:

    python3 scripts/check_docs.py

Exit status is non-zero when any of these holds:

1. docs/reference/*.md differ from what scripts/gen_docs.py generates, or a
   diagnostic code / attrs key lacks its curated YAML entry (or vice versa);
2. a registered validator or reader has no docs/formats/<format>.md, allowing
   for pages that cover several ids (gen_docs.DOC_ALIASES: partition-tables
   for mbr/gpt, compressed-streams for gzip/xz/lz4/zstd, ...);
3. a CLI flag defined in apps/cli/*.cpp is not mentioned in docs/CLI.md;
4. a relative Markdown link in README.md or any docs/**/*.md points at a file
   that does not exist.

CI runs it as the first job (.github/workflows/ci.yml); the discovery unit
tests run it too when python3 is on the PATH (tests/unit/discovery/docs_check_test.cpp).
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_docs  # noqa: E402

ROOT = gen_docs.ROOT
LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def check_generated(problems: list[str]) -> None:
    files, catalogue = gen_docs.generate()
    problems.extend(catalogue)
    for relpath, content in files.items():
        path = ROOT / relpath
        if not path.exists():
            problems.append(f"{relpath}: missing; run scripts/gen_docs.py")
        elif gen_docs.read(path) != content:
            problems.append(f"{relpath}: stale; run scripts/gen_docs.py")


def check_format_pages(problems: list[str]) -> None:
    sigs = gen_docs.parse_toml_signatures()
    validator_formats: dict[str, str] = {}
    for s in sigs:
        if s.get("validator"):
            validator_formats.setdefault(s["format"], s["validator"])
    readers = dict(gen_docs.registrations("OMNITRACE_REGISTER_FILESYSTEM"))
    readers.update(gen_docs.registrations("OMNITRACE_REGISTER_CONTAINER"))
    wanted = {fmt: f"validator `{v}`" for fmt, v in validator_formats.items()}
    for fmt, (file, line) in readers.items():
        wanted[fmt] = f"reader at {file}:{line}"
    for fmt in sorted(wanted):
        page = gen_docs.DOC_ALIASES.get(fmt, fmt)
        if not (ROOT / "docs" / "formats" / f"{page}.md").exists():
            problems.append(
                f"docs/formats/{page}.md: missing for format `{fmt}` ({wanted[fmt]}); "
                "write it or add an alias in gen_docs.DOC_ALIASES"
            )
    for fmt, page in gen_docs.DOC_ALIASES.items():
        if not (ROOT / "docs" / "formats" / f"{page}.md").exists():
            problems.append(f"gen_docs.DOC_ALIASES: `{fmt}` points at docs/formats/{page}.md, which does not exist")


def check_cli_doc(problems: list[str]) -> None:
    doc = ROOT / "docs" / "CLI.md"
    if not doc.exists():
        problems.append("docs/CLI.md: missing")
        return
    text = gen_docs.read(doc)
    for flag in gen_docs.cli_flag_names(gen_docs.collect_cli()):
        if flag not in text:
            problems.append(f"docs/CLI.md: flag `{flag}` (apps/cli) is not mentioned")


def check_links(problems: list[str]) -> None:
    pages = [ROOT / "README.md"] + sorted((ROOT / "docs").rglob("*.md"))
    for page in pages:
        if not page.exists():
            continue
        text = gen_docs.read(page)
        # drop fenced code blocks: they hold examples, not links
        text = re.sub(r"```.*?```", "", text, flags=re.S)
        for m in LINK.finditer(text):
            target = m.group(1)
            if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                continue  # http(s):, mailto:, or an in-page anchor
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (page.parent / target).resolve()
            if not resolved.exists():
                problems.append(f"{gen_docs.rel(page)}: link `{m.group(1)}` -> {target} does not exist")


def main() -> int:
    problems: list[str] = []
    for check in (check_generated, check_format_pages, check_cli_doc, check_links):
        try:
            check(problems)
        except SystemExit as e:  # gen_docs uses sys.exit on malformed YAML
            problems.append(str(e))
    if problems:
        print("check_docs.py: documentation is out of sync with the code:", file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 1
    print("check_docs.py: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
