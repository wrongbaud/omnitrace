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
   that does not exist;
5. CONTRIBUTING.md documents an apt package that .github/workflows/ci.yml
   does not install;
6. a case directory (device evidence) has been committed.

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


# Packages the GitHub runner image already provides, so CI never installs them.
RUNNER_PROVIDED = {"cmake", "g++", "gcc", "git", "python3"}
APT = re.compile(r"apt-get install[^\n`]*")


def apt_packages(text: str) -> set[str]:
    """Every package named on an `apt-get install` line, flags dropped."""
    out: set[str] = set()
    for line in APT.findall(text.replace("\\\n", " ")):
        for tok in line.split():
            if tok.startswith("-") or tok in {"apt-get", "install", "sudo", "&&", "apt-get"}:
                continue
            out.add(tok)
    return out


def check_ci_packages(problems: list[str]) -> None:
    """CI must install what CONTRIBUTING.md tells a contributor to install.

    These two lists drifted once and it cost a red matrix: bzip2 was added as a
    dependency and got its find_package, its module DEPS and its CONTRIBUTING
    row, but nothing added libbz2-dev to the workflow, so every Linux job
    failed at configure on `Could NOT find BZip2`. The documented list is the
    source of truth; this makes the workflow answer to it.
    """
    contributing = ROOT / "CONTRIBUTING.md"
    workflow = ROOT / ".github" / "workflows" / "ci.yml"
    if not contributing.exists() or not workflow.exists():
        return
    documented = apt_packages(gen_docs.read(contributing))
    installed = apt_packages(gen_docs.read(workflow))
    if not documented or not installed:
        problems.append("check_ci_packages: found no apt-get line to compare; the check is not working")
        return
    for pkg in sorted(documented - installed - RUNNER_PROVIDED):
        problems.append(
            f".github/workflows/ci.yml: CONTRIBUTING.md says to install `{pkg}`, "
            "but the Linux job does not; add it or stop documenting it"
        )


# A case directory is evidence output: carved partitions, extracted trees and
# the manifests over them. None of it belongs in the repository, and the names
# are unmistakable.
CASE_MARKERS = ("INFO.yaml", "SOURCE.yaml", "listing.yaml")
# The bulk of a case: carved partitions and the extracted tree.
CASE_BULK = re.compile(r"(^|/)(partitions|filesystems|containers)/.*(/files/|\.bin$)")


def check_no_case_output(problems: list[str]) -> None:
    """Fail if a case directory has been committed.

    .gitignore guards the common accident, but it only names the manifests --
    a case also holds carved partitions and an extracted tree, and `git add
    -f` ignores it entirely. This is the part that actually holds: a case is
    real device evidence, and publishing one is not undoable.
    """
    import subprocess

    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT,
                             capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return  # no git (source tarball); nothing to check
    if out.returncode != 0:
        return
    for path in out.stdout.split("\0"):
        if not path:
            continue
        name = path.rsplit("/", 1)[-1]
        why = ""
        if name in CASE_MARKERS:
            why = "a case manifest"
        elif CASE_BULK.search(path):
            why = "carved or extracted case content"
        elif path.lower().endswith((".bin", ".img", ".dd", ".raw")):
            why = "a disk image"
        if why:
            problems.append(
                f"{path}: {why}, tracked by git; this is device evidence and must not be "
                "committed (see .gitignore)"
            )


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
    for check in (check_generated, check_format_pages, check_cli_doc, check_ci_packages, check_no_case_output, check_links):
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
