#!/usr/bin/env python3
"""gen_docs.py - generate docs/reference/*.md from the source tree.

Python 3 standard library only. Deterministic and idempotent: the same tree
produces byte-identical files, so `--check` can tell whether the committed
reference is stale.

Generated files (docs/reference/):
  DIAGNOSTICS.md  every diagnostic code emitted in src/ and apps/, joined with the
                  curated meaning/action from docs/reference/diagnostics.yaml
  FORMATS.md      support matrix from signatures/*.toml, the OMNITRACE_REGISTER_*
                  macros, the validators and docs/formats/*.md presence
  ATTRS.md        attrs keys emitted per validator / reader / driver, joined with
                  the curated meanings from docs/reference/attrs.yaml
  CLI_FLAGS.md    every CLI11 option and flag defined in apps/cli/*.cpp

Usage:
  scripts/gen_docs.py              write the four files
  scripts/gen_docs.py --check      exit 1 when a committed file differs
  scripts/gen_docs.py --list-codes print every code found in source (and which
                                   ones the YAML lacks); same for --list-attrs

The script fails (exit 2) when a code or attrs key found in source has no YAML
entry, or a YAML entry no longer has a source, so the catalogues cannot rot.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "docs" / "reference"
SOURCE_DIRS = ("src", "apps")
VALIDATOR_DIR = ROOT / "src" / "discovery" / "validators"

KEBAB = r"[a-z][a-z0-9]*(?:-[a-z0-9]+)+"
SEVERITY_ORDER = {"info": 0, "warning": 1, "error": 2}
CATEGORY_ORDER = [
    "filesystem",
    "container",
    "compressed",
    "partition-table",
    "kernel",
    "bootloader",
    "crypto",
    "other",
]

# docs/formats/<page>.md that documents several format ids. Keep in sync with
# scripts/check_docs.py (it imports this table).
DOC_ALIASES = {
    "mbr": "partition-tables",
    "gpt": "partition-tables",
    "gzip": "compressed-streams",
    "xz": "compressed-streams",
    "lz4": "compressed-streams",
    "zstd": "compressed-streams",
    "lzma": "compressed-streams",
    "bzip2": "compressed-streams",
    "ext2": "ext",
    "ext3": "ext",
    "ext4": "ext",
    "android-vendor-boot": "android-boot",
    "dm-verity": "verity",
}

# attrs keys set through a variable rather than a literal index. Each entry is
# verified against the named line so the list cannot rot.
DYNAMIC_ATTRS = {
    "src/discovery/Recurse.cpp": [("boot", 'fld == "boot"'), ("logical", 'fld == "logical"')],
}

# Per-format notes that cannot be derived from the code mechanically.
FORMAT_NOTES = {
    "ubi": "size known only when a second EC header fixes the PEB size (`ubi-single-peb` otherwise)",
    "jffs2": "one finding per partition: nodes coalesced across gaps up to `max_gap`; obsolete nodes CRC-checked",
    "mbr": "size is the 512-byte table sector; EBR chain sectors hidden through `also_covers`",
    "gpt": "size is the table extent (header + entry array); the disk extent is `disk_size`",
    "ext": "native reader; history from freed inodes and slack directory entries",
    "dtb": "steps back to structural when the root has `/images` so the `fit` finding wins",
    "elf": "unaligned hits must reach consistent or they are dropped",
    "ubifs": "aligned hits only (`min_io_size` or 512); inside UBI the size is not meaningful",
    "qnx6": "size covers both superblocks; second-superblock hits with a corrupt primary are placed at the filesystem start",
    "qnx-ifs": "compressed images sized by walking the block chain; startup checksum reported but never lowers the tier",
    "yaffs2": "no signature until OOB-aware validation exists (signatures.md)",
    "android-sparse": "size is the chunk walk; no reader expands the image yet",
    "uimage": "kernel and kernel_noload types are re-categorised as `kernel`",
    "android-boot": "size is the sum of page-aligned sections, header v0-v4",
}


# ----------------------------------------------------------------- utilities


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments, keeping every newline so line numbers hold.

    String and character literals are respected so a "//" inside a message is
    left alone.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"' or (ch == "'" and not (i > 0 and text[i - 1].isalnum())):
            quote = ch
            out.append(ch)
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    out.append(text[i : i + 2])
                    i += 2
                    continue
                out.append(text[i])
                i += 1
            if i < n:
                out.append(quote)
                i += 1
            continue
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append("".join("\n" if c == "\n" else " " for c in text[i:end]))
            i = end
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def balanced(text: str, start: int) -> int:
    """Index one past the bracket that closes the one at `start`."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    stack = [pairs[text[start]]]
    i = start + 1
    n = len(text)
    while i < n and stack:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif ch == "'" and not text[i - 1].isalnum():
            i += 1
            while i < n and text[i] != "'":
                i += 2 if text[i] == "\\" else 1
        elif ch in pairs:
            stack.append(pairs[ch])
        elif ch == stack[-1]:
            stack.pop()
        i += 1
    return i


def split_args(s: str) -> list[str]:
    """Split at top-level commas, respecting brackets and string literals."""
    out, depth, cur, i, n = [], 0, [], 0, len(s)
    while i < n:
        ch = s[i]
        if ch == '"' or (ch == "'" and not (i > 0 and s[i - 1].isalnum())):
            j = i + 1
            while j < n and s[j] != ch:
                j += 2 if s[j] == "\\" else 1
            cur.append(s[i : j + 1])
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def literals(expr: str) -> list[str]:
    return [m.group(1).replace('\\"', '"') for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', expr)]


def scan_outside_strings(expr: str):
    """Yield (index, depth, char) for every character outside string literals."""
    depth, i, n = 0, 0, len(expr)
    while i < n:
        ch = expr[i]
        if ch == '"' or (ch == "'" and not (i > 0 and expr[i - 1].isalnum())):
            quote = ch
            i += 1
            while i < n and expr[i] != quote:
                i += 2 if expr[i] == "\\" else 1
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        yield i, depth, ch
        i += 1


def mark_ternaries(expr: str) -> str:
    """Turn every `cond ? a : b` into `cond ? a + " | " + b` so both branches render."""
    while True:
        q = next((i for i, _d, ch in scan_outside_strings(expr) if ch == "?"), None)
        if q is None:
            return expr
        depth_q = next(d for i, d, _ch in scan_outside_strings(expr) if i == q)
        colon = next((i for i, d, ch in scan_outside_strings(expr) if i > q and d == depth_q and ch == ":"), None)
        if colon is None:
            return expr
        expr = expr[:q] + " " + expr[q + 1 : colon] + ' + " | " + ' + expr[colon + 1 :]


def message_template(expr: str) -> str:
    """Render a C++ message expression: literals kept, everything else is `...`.

    A conditional expression (`cond ? "a" : "b"`) is rendered as `a | b`.
    """
    expr = mark_ternaries(expr)
    parts = []
    pos = 0
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', expr):
        gap = expr[pos : m.start()].strip(" +\n\t")
        if gap and gap not in ("std::string(", ")"):
            if not parts or parts[-1] != "...":
                parts.append("...")
        parts.append(m.group(1).replace('\\"', '"'))
        pos = m.end()
    if expr[pos:].strip(" +\n\t)") and (not parts or parts[-1] != "..."):
        parts.append("...")
    text = "".join(parts).strip()
    if not text:
        return "..."
    return text


def md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def sources() -> list[Path]:
    files = []
    for d in SOURCE_DIRS:
        files += (ROOT / d).rglob("*.cpp")
        files += (ROOT / d).rglob("*.h")
    return sorted(set(files))


# ------------------------------------------------------- curated YAML subset


def load_yaml_map(path: Path) -> dict[str, dict[str, str]]:
    """Read the two-level `key:\\n  sub: value` YAML subset used by the catalogues.

    Values are one line, plain or double-quoted. A top-level key may be a path
    (attrs.yaml). Anything else is a hard error, on purpose: the file is data
    for this script and nothing else.
    """
    out: dict[str, dict[str, str]] = {}
    if not path.exists():
        return out
    current = None
    for n, raw in enumerate(read(path).splitlines(), 1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            if not line.endswith(":"):
                sys.exit(f"{rel(path)}:{n}: expected 'key:'")
            current = line[:-1].strip().strip('"')
            if current in out:
                sys.exit(f"{rel(path)}:{n}: duplicate key {current!r}")
            out[current] = {}
            continue
        if current is None or not line.startswith("  ") or line.startswith("   "):
            sys.exit(f"{rel(path)}:{n}: expected two-space indented 'sub: value'")
        m = re.match(r"^  ([A-Za-z_][\w-]*):\s*(.*)$", line)
        if not m:
            sys.exit(f"{rel(path)}:{n}: expected 'sub: value'")
        value = m.group(2).strip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1].replace('\\"', '"')
        out[current][m.group(1)] = value
    return out


# --------------------------------------------------------------- diagnostics


class Site:
    __slots__ = ("code", "severity", "file", "line", "message")

    def __init__(self, code: str, severity: str, file: str, line: int, message: str):
        self.code, self.severity, self.file, self.line, self.message = (
            code,
            severity,
            file,
            line,
            message,
        )


def sev_name(expr: str) -> str | None:
    m = re.search(r"Severity::(\w+)", expr)
    return m.group(1).lower() if m else None


def codes_in(expr: str, constants: dict[str, str]) -> list[str]:
    """Kebab-case literal codes and kCode constants referenced by an expression."""
    found = [lit for lit in literals(expr) if re.fullmatch(KEBAB, lit)]
    for m in re.finditer(r"\b(kCode\w+)\b", expr):
        if m.group(1) in constants:
            found.append(constants[m.group(1)])
    return found


def scan_diagnostics(path: Path) -> tuple[list[Site], list[Site]]:
    """All Diagnostic construction sites and Status failure codes in one file."""
    text = strip_comments(read(path))
    file = rel(path)
    constants = {
        m.group(1): m.group(2)
        for m in re.finditer(r"\b(kCode\w+)\s*=\s*\"(" + KEBAB + r")\"", text)
    }
    sites: list[Site] = []
    indirect: list[tuple[str, str, int, str]] = []  # (var, severity, line, message)

    def record(code_expr: str, severity: str, line: int, message: str) -> None:
        codes = codes_in(code_expr, constants)
        if codes:
            for code in codes:
                sites.append(Site(code, severity, file, line, message))
            return
        var = re.sub(r"^\*", "", code_expr.strip())
        var = re.split(r"\.|->", var)[-1]
        if re.fullmatch(r"\w+", var):
            indirect.append((var, severity, line, message))

    # Pattern A: diag(target, Severity::X, code, message) helper calls.
    for m in re.finditer(r"\bdiag\s*\(", text):
        end = balanced(text, m.end() - 1)
        args = split_args(text[m.end() : end - 1])
        if len(args) < 4:
            continue
        sev = sev_name(args[1])
        if not sev:
            continue
        record(args[2], sev, line_of(text, m.start()), message_template(args[3]))

    # Pattern B: {Severity::X, code, message} aggregate initialisation.
    for m in re.finditer(r"\{\s*Severity::(\w+)\s*,", text):
        end = balanced(text, m.start())
        args = split_args(text[m.start() + 1 : end - 1])
        if len(args) < 3:
            continue
        record(args[1], m.group(1).lower(), line_of(text, m.start()), message_template(args[2]))

    # Indirect codes: the variable passed to diag() is assigned a literal or a
    # constant elsewhere in the file (SquashfsReader `code`, fit.cpp `t.problem`).
    by_var: dict[str, list[tuple[str, int]]] = {}
    for var, sev, line, _message in indirect:
        by_var.setdefault(var, []).append((sev, line))
    for var, uses in by_var.items():
        pat = re.compile(r"(?<!\w)\*?" + re.escape(var) + r"\s*=\s*(\"" + KEBAB + r"\"|kCode\w+)")
        emitted = ", ".join(f"{file}:{line}" for _sev, line in sorted(set(uses), key=lambda u: u[1]))
        message = f"(assigned to `{var}`; emitted at {emitted})"
        for a in pat.finditer(text):
            for code in codes_in(a.group(1), constants):
                for sev in sorted({u[0] for u in uses}):
                    sites.append(Site(code, sev, file, line_of(text, a.start()), message))

    statuses: list[Site] = []
    for m in re.finditer(r"\bfail_code\s*\(\s*\"(" + KEBAB + r")\"\s*,\s*", text):
        end = balanced(text, text.rfind("(", 0, m.end()))
        rest = text[m.end() : end - 1]
        statuses.append(Site(m.group(1), "status", file, line_of(text, m.start()), message_template(rest)))
    for m in re.finditer(r"Status::fail\s*\(\s*\"(" + KEBAB + r"):\s*", text):
        paren = text.rfind("(", 0, m.end())
        args = split_args(text[paren + 1 : balanced(text, paren) - 1])
        msg = message_template(args[0]) if args else "..."
        msg = msg[len(m.group(1)) + 1 :].strip() if msg.startswith(m.group(1) + ":") else msg
        statuses.append(Site(m.group(1), "status", file, line_of(text, m.start()), msg))
    return sites, statuses


def collect_diagnostics() -> tuple[dict[str, list[Site]], dict[str, list[Site]]]:
    diags: dict[str, list[Site]] = {}
    statuses: dict[str, list[Site]] = {}
    for path in sources():
        d, s = scan_diagnostics(path)
        for site in d:
            diags.setdefault(site.code, []).append(site)
        for site in s:
            statuses.setdefault(site.code, []).append(site)
    for table in (diags, statuses):
        for code in table:
            table[code].sort(key=lambda s: (s.file, s.line))
    return diags, statuses


def where_cell(sites: list[Site], limit: int = 3) -> str:
    seen: list[str] = []
    for s in sites:
        ref = f"{s.file}:{s.line}"
        if ref not in seen:
            seen.append(ref)
    shown = ", ".join(f"`{r}`" for r in seen[:limit])
    if len(seen) > limit:
        shown += f" (+{len(seen) - limit} more)"
    return shown


def render_diagnostics(diags: dict[str, list[Site]], statuses: dict[str, list[Site]], curated) -> str:
    lines = [
        "# Diagnostic codes",
        "",
        "<!-- generated by scripts/gen_docs.py from src/ and apps/; do not edit. Meanings live in diagnostics.yaml. -->",
        "",
        "This catalogue is for examiners reading `INFO.yaml` / `listing.yaml` and for",
        "contributors adding a reader. After reading it you can tell, for any `code`",
        "in a manifest, which source line emitted it, how bad it is, and what to do",
        "about the evidence. Codes are stable kebab-case slugs (`Diagnostic::code`,",
        "`include/omnitrace/core/Diagnostics.h`); the message beside them is",
        "human text and may change. `scripts/gen_docs.py` extracts every",
        "construction site (`diag(...)`, `{Severity::..., \"code\", ...}`, the",
        "`kCode*` constants and the codes assigned to a variable before the call)",
        "and joins them with `docs/reference/diagnostics.yaml`; `scripts/check_docs.py`",
        "fails when either side is missing an entry.",
        "",
        "Severity is the value as emitted (`info` / `warning` / `error`, the names",
        "`INFO.yaml` uses). A code listed with two severities is emitted at both;",
        "`where` names every site, `message` is the literal with runtime parts as `...`.",
        "",
        f"{len(diags)} diagnostic codes, {len(statuses)} status codes.",
        "",
        "## Diagnostics",
        "",
        "| code | severity | where | message | meaning | examiner action |",
        "|---|---|---|---|---|---|",
    ]
    for code in sorted(diags):
        sites = diags[code]
        sevs = sorted({s.severity for s in sites}, key=lambda s: SEVERITY_ORDER[s])
        entry = curated.get(code, {})
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} |".format(
                code,
                ", ".join(sevs),
                where_cell(sites),
                md_cell(sites[0].message),
                md_cell(entry.get("meaning", "")),
                md_cell(entry.get("action", "")),
            )
        )
    lines += [
        "",
        "## Status codes",
        "",
        "A `Status::fail` carries `\"<code>: <detail>\"` in `Status::error`. These are",
        "not diagnostics on their own: they surface as the `message` of",
        "`analyze-open-failed`, `analyze-walk-failed`, `analyze-sink-failed` and",
        "`sink-io-error`, and as the CLI's error line.",
        "",
        "| code | where | message | meaning | examiner action |",
        "|---|---|---|---|---|",
    ]
    for code in sorted(statuses):
        sites = statuses[code]
        entry = curated.get(code, {})
        lines.append(
            "| `{}` | {} | {} | {} | {} |".format(
                code,
                where_cell(sites),
                md_cell(sites[0].message),
                md_cell(entry.get("meaning", "")),
                md_cell(entry.get("action", "")),
            )
        )
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------- formats


def parse_toml_signatures() -> list[dict[str, str]]:
    """Minimal reader for the [[signature]] tables: `key = value` lines only."""
    sigs: list[dict[str, str]] = []
    for path in sorted((ROOT / "signatures").glob("*.toml")):
        cur = None
        for raw in read(path).splitlines():
            line = raw.split("#", 1)[0].strip() if not raw.strip().startswith('"') else raw.strip()
            if not line:
                continue
            if line == "[[signature]]":
                cur = {"_file": rel(path)}
                sigs.append(cur)
                continue
            if cur is None:
                continue
            m = re.match(r"^([A-Za-z_][\w-]*)\s*=\s*(.*)$", line)
            if not m:
                continue
            key, value = m.group(1), m.group(2).strip()
            if value.startswith('"'):
                value = literals(value)[0] if literals(value) else value
            cur[key] = value
    return sigs


def registrations(macro: str) -> dict[str, tuple[str, int]]:
    """format id -> (file, line) for OMNITRACE_REGISTER_<X>("id", ...) uses."""
    out: dict[str, tuple[str, int]] = {}
    pat = re.compile(r"\b" + macro + r"\s*\(\s*\"([^\"]+)\"\s*,")
    for path in sources():
        text = strip_comments(read(path))
        for m in pat.finditer(text):
            out[m.group(1)] = (rel(path), line_of(text, m.start()))
    return out


def validator_registrations() -> dict[str, tuple[str, int, str]]:
    """validator name -> (file, line, function name)."""
    out: dict[str, tuple[str, int, str]] = {}
    pat = re.compile(r"\bOMNITRACE_REGISTER_VALIDATOR\s*\(\s*\"([^\"]+)\"\s*,\s*(\w+)\s*\)")
    for path in sorted(VALIDATOR_DIR.glob("*.cpp")):
        text = strip_comments(read(path))
        for m in pat.finditer(text):
            out[m.group(1)] = (rel(path), line_of(text, m.start()), m.group(2))
    return out


def function_slice(text: str, fn: str) -> str:
    """Body of `std::optional<Finding> fn(` (the validator), or the whole file."""
    m = re.search(r"std::optional<Finding>\s+" + re.escape(fn) + r"\s*\(", text)
    if not m:
        return text
    brace = text.find("{", balanced(text, m.end() - 1))
    return text[brace : balanced(text, brace)]


TIER_RANK = {"magic": 1, "structural": 2, "consistent": 3, "verified": 4}


def validator_facts(fn_text: str) -> dict[str, object]:
    tiers = set()
    for m in re.finditer(r"Confidence::(Magic|Structural|Consistent|Verified)", fn_text):
        # Only assignments and make_finding(...) arguments count as reachable tiers.
        before = fn_text[max(0, m.start() - 40) : m.start()]
        if re.search(r"(=|\?|:|make_finding\([^;]*,)\s*$", before):
            tiers.add(m.group(1).lower())
    top = max(tiers, key=lambda t: TIER_RANK[t]) if tiers else "magic"
    sized = bool(re.search(r"\bf\.size\s*=", fn_text))
    formats = sorted(set(literals(x) [0] for x in re.findall(r"f\.format\s*=\s*(\"[^\"]+\")", fn_text)))
    categories = sorted(set(literals(x)[0] for x in re.findall(r"f\.category\s*=\s*(\"[^\"]+\")", fn_text)))
    return {"tier": top, "sized": sized, "formats": formats, "categories": categories}


def mount_types() -> tuple[dict[str, str], list[str]]:
    text = strip_comments(read(ROOT / "src" / "discovery" / "Recurse.cpp"))
    m = re.search(r"std::string mount_type_for\s*\([^)]*\)\s*\{", text)
    body = text[m.end() : balanced(text, m.end() - 1)] if m else ""
    types: dict[str, str] = {}
    for cond, ret in re.findall(r"if\s*\((.*?)\)\s*return\s+\"(\w+)\"\s*;", body, re.S):
        for fmt in re.findall(r"format\s*==\s*\"([^\"]+)\"", cond):
            types[fmt] = ret
    mtd = re.search(r"else if\s*\(([^()]*)\)\s*mtd\.emplace_back", text, re.S)
    mtd_formats = re.findall(r"format\s*==\s*\"([^\"]+)\"", mtd.group(1)) if mtd else []
    return types, mtd_formats


def doc_page(fmt: str) -> str | None:
    page = DOC_ALIASES.get(fmt, fmt)
    return page if (ROOT / "docs" / "formats" / f"{page}.md").exists() else None


def render_formats() -> str:
    sigs = parse_toml_signatures()
    validators = validator_registrations()
    fs_readers = registrations("OMNITRACE_REGISTER_FILESYSTEM")
    ct_readers = registrations("OMNITRACE_REGISTER_CONTAINER")
    mounts, mtd = mount_types()

    # A file that registers one validator is read whole (helpers such as
    # luks1()/luks2() assign tiers too); a file with several (fit.cpp: dtb and
    # fit) is sliced per function.
    per_file: dict[str, int] = {}
    for _name, (file, _line, _fn) in validators.items():
        per_file[file] = per_file.get(file, 0) + 1
    facts: dict[str, dict[str, object]] = {}
    for name, (file, _line, fn) in validators.items():
        text = strip_comments(read(ROOT / file))
        facts[name] = validator_facts(text if per_file[file] == 1 else function_slice(text, fn))

    rows: dict[str, dict[str, object]] = {}
    for s in sigs:
        fmt = s.get("format", "?")
        row = rows.setdefault(
            fmt,
            {"category": s.get("category", "?"), "signatures": [], "validators": set(), "files": set()},
        )
        row["signatures"].append(s.get("name", "?"))
        row["files"].add(s["_file"])
        if s.get("validator"):
            row["validators"].add(s["validator"])
    for fmt in list(fs_readers) + list(ct_readers):
        rows.setdefault(fmt, {"category": "filesystem" if fmt in fs_readers else "container",
                              "signatures": [], "validators": set(), "files": set()})

    lines = [
        "# Format support matrix",
        "",
        "<!-- generated by scripts/gen_docs.py from signatures/*.toml, the validators, the reader registries and docs/formats/; do not edit. -->",
        "",
        "This matrix is for anyone deciding whether OmniTrace can handle an image and",
        "for contributors choosing what to build next. After reading it you know, per",
        "format id, whether a hit is only a magic match or a validated structure, whether",
        "its extent is known, whether a reader extracts it, whether history is recovered,",
        "how `partitions/mount.sh` treats it, and where its page is. Rows come from",
        "`signatures/*.toml`; `identify` and `sized` are read out of each validator's",
        "code (the highest `Confidence::` tier it assigns and whether it sets `f.size`).",
        "",
        "| column | meaning |",
        "|---|---|",
        "| identify | `magic-only` (no validator; `Confidence::Magic`, size unknown) or `validated to <tier>`: the best tier the validator can assign (`docs/ARCHITECTURE.md`) |",
        "| sized | the validator sets the finding's extent, so the finding can be carved and can parent nested finds |",
        "| reader | a `FilesystemReader` / `ContainerReader` is registered for the format id and `analyze` walks it |",
        "| history | the reader recovers superseded / deleted versions with `--history`; `n.a.` for anything that is not a filesystem |",
        "| mount.sh | the `mount -t` type `discovery::mount_type_for` assigns to a carved file, `mtd (comment)` for flash filesystems listed in the mtdram/nandsim comment block, `-` when not loop-mountable |",
        "",
        "| format | category | identify | sized | reader | history | mount.sh | docs page | notes |",
        "|---|---|---|---|---|---|---|---|---|",
    ]

    def sort_key(item):
        fmt, row = item
        cat = row["category"]
        return (CATEGORY_ORDER.index(cat) if cat in CATEGORY_ORDER else 99, fmt)

    for fmt, row in sorted(rows.items(), key=sort_key):
        vals = sorted(row["validators"])
        if vals:
            best = max((facts[v]["tier"] for v in vals if v in facts), key=lambda t: TIER_RANK[t], default="magic")
            identify = f"validated to {best} (`{'`, `'.join(vals)}`)"
            sized = "yes" if any(facts[v]["sized"] for v in vals if v in facts) else "no"
        else:
            identify, sized = "magic-only", "no"
        reader = "-"
        if fmt in fs_readers:
            reader = f"yes (`{fs_readers[fmt][0]}:{fs_readers[fmt][1]}`)"
        elif fmt in ct_readers:
            reader = f"yes (`{ct_readers[fmt][0]}:{ct_readers[fmt][1]}`)"
        else:
            reader = "no"
        if row["category"] != "filesystem":
            history = "n.a."
        elif fmt in fs_readers:
            reader_text = read(ROOT / fs_readers[fmt][0])
            history = "yes" if re.search(r"\bsuperseded\s*=\s*true|opts\.history", reader_text) else "no"
        else:
            history = "no (no reader)"
        mount = mounts.get(fmt) or ("mtd (comment)" if fmt in mtd else "-")
        page = doc_page(fmt)
        if page:
            docs = f"[{page}.md](../formats/{page}.md)"
        elif not vals:
            docs = "[signatures.md](../formats/signatures.md) (plain magic)"
        else:
            docs = "MISSING"
        notes = []
        for v in vals:
            if v in facts and facts[v]["formats"]:
                notes.append("validator reports " + "/".join(facts[v]["formats"]))
            if v in facts and facts[v]["categories"]:
                notes.append("may re-categorise as " + "/".join(facts[v]["categories"]))
        if fmt in FORMAT_NOTES:
            notes.append(FORMAT_NOTES[fmt])
        if row["signatures"]:
            notes.append("signatures: " + ", ".join(f"`{s}`" for s in row["signatures"]))
        lines.append(
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                fmt, row["category"], identify, sized, reader, history,
                f"`{mount}`" if mount not in ("-", "mtd (comment)") else mount,
                docs, md_cell("; ".join(notes)),
            )
        )
    lines += [
        "",
        "## Counts",
        "",
        f"- {len(sigs)} signatures over {len(rows)} format ids",
        f"- {len(validators)} validators, {len(fs_readers)} filesystem reader(s), {len(ct_readers)} container reader(s)",
        f"- mount.sh types: " + ", ".join(f"`{k}` -> `{v}`" for k, v in sorted(mounts.items())),
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------- attrs


def attrs_sections() -> dict[str, dict[str, object]]:
    """rel path -> {title, keys: {key: first line}}."""
    sections: dict[str, dict[str, object]] = {}
    validators = validator_registrations()
    by_file: dict[str, list[str]] = {}
    for name, (file, _line, _fn) in validators.items():
        by_file.setdefault(file, []).append(name)
    candidates = sorted(VALIDATOR_DIR.glob("*.cpp")) + sorted((ROOT / "src" / "filesystems").rglob("*.cpp"))
    candidates += [ROOT / "src" / "discovery" / "Recurse.cpp"]
    for path in candidates:
        text = strip_comments(read(path))
        keys: dict[str, int] = {}
        for m in re.finditer(r"\battrs\[\s*\"([A-Za-z_][\w-]*)\"\s*\]", text):
            keys.setdefault(m.group(1), line_of(text, m.start()))
        if "option_attrs[name]" in text:  # SquashfsReader compressor options
            for m in re.finditer(r"\bu(?:16|32)\(\s*\d+\s*,\s*\"(\w+)\"\s*\)", text):
                keys.setdefault(m.group(1), line_of(text, m.start()))
        for key, needle in DYNAMIC_ATTRS.get(rel(path), []):
            idx = text.find(needle)
            if idx < 0:
                sys.exit(f"gen_docs.py: DYNAMIC_ATTRS entry {key!r} no longer matches {rel(path)}")
            keys.setdefault(key, line_of(text, idx))
        if not keys:
            continue
        file = rel(path)
        if file in by_file:
            title = "validator " + ", ".join(f"`{v}`" for v in sorted(by_file[file]))
        elif "filesystems" in file:
            title = "filesystem reader (`FilesystemInfo::attrs`)"
        else:
            title = "analysis driver (node attrs set by `analyze`)"
        sections[file] = {"title": title, "keys": keys}
    return sections


def render_attrs(sections: dict[str, dict[str, object]], curated) -> str:
    lines = [
        "# Finding and node attrs",
        "",
        "<!-- generated by scripts/gen_docs.py from src/; do not edit. Meanings live in attrs.yaml. -->",
        "",
        "This page is for anyone reading the `attrs` map of a finding (`omnitrace scan`)",
        "or a node (`INFO.yaml`) and for contributors who need to know which keys a",
        "validator already emits before adding one. After reading it you can decode",
        "every key, know which source file sets it, and see where a value is a packed",
        "list rather than a scalar. Keys are grouped by the file that emits them;",
        "`scripts/gen_docs.py` greps `attrs[\"key\"]` (plus the SquashFS compressor",
        "option names and the two MBR flags set through a variable) and joins them",
        "with `docs/reference/attrs.yaml`; `scripts/check_docs.py` fails when a key",
        "lacks a meaning or a meaning lacks a key.",
        "",
        "All values are strings. Numbers are decimal unless the meaning says hex;",
        "lists use `;` between items and `:` between fields (`list_safe` replaces",
        "those characters inside evidence text).",
        "",
    ]
    total = 0
    for file in sorted(sections):
        sec = sections[file]
        keys: dict[str, int] = sec["keys"]  # type: ignore[assignment]
        total += len(keys)
        lines += [f"## {sec['title']}", "", f"Source: `{file}` ({len(keys)} keys)", "", "| key | first set at | meaning |", "|---|---|---|"]
        entries = curated.get(file, {})
        for key in sorted(keys):
            lines.append(f"| `{key}` | `{file}:{keys[key]}` | {md_cell(entries.get(key, ''))} |")
        lines.append("")
    lines.insert(18, f"{total} keys across {len(sections)} source files.")
    lines.insert(19, "")
    return "\n".join(lines)


# ----------------------------------------------------------------------- CLI


def cli_statements(text: str) -> list[tuple[int, str]]:
    """(line, statement) pairs split at semicolons outside parentheses.

    Braces are ignored on purpose: the calls live inside function bodies, and a
    lambda passed to add_flag_callback sits inside the call's parentheses.
    """
    out, depth, start, i, n = [], 0, 0, 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"' or (ch == "'" and not (i > 0 and text[i - 1].isalnum())):
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                i += 2 if text[i] == "\\" else 1
        elif ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == ";" and depth == 0:
            stmt = text[start:i]
            out.append((line_of(text, start + (len(stmt) - len(stmt.lstrip()))), stmt))
            start = i + 1
        i += 1
    return out


def collect_cli() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted((ROOT / "apps" / "cli").glob("*.cpp")):
        text = strip_comments(read(path))
        subs = {"app": "(global)"}
        defaults: dict[str, str] = {}
        for m in re.finditer(r"\b(\w+)\s*=\s*[^;]*add_subcommand\(\s*\"(\w+)\"", text):
            subs[m.group(1)] = m.group(2)
        # struct field initialisers (AnalyzeArgs) and Limits.h defaults.
        for m in re.finditer(r"^\s*[\w:<>]+\s+(\w+)\s*=\s*([^;{]+);", text, re.M):
            defaults.setdefault(m.group(1), m.group(2).strip())
        limits = strip_comments(read(ROOT / "include" / "omnitrace" / "core" / "Limits.h"))
        for m in re.finditer(r"^\s*[\w:<>]+\s+(\w+)\s*=\s*([^;]+);", limits, re.M):
            defaults.setdefault("limits." + m.group(1), m.group(2).strip().replace("'", ""))
        for line, stmt in cli_statements(text):
            m = re.search(r"\b(\w+)\s*(?:->|\.)\s*(add_option|add_flag|add_flag_callback|set_version_flag)\s*\(", stmt)
            if not m:
                continue
            owner = subs.get(m.group(1), m.group(1))
            end = balanced(stmt, m.end() - 1)
            args = split_args(stmt[m.end() : end - 1])
            if not args:
                continue
            names = literals(args[0])[0] if literals(args[0]) else args[0]
            help_text = "".join(literals(args[-1])) if len(args) > 1 else ""
            if m.group(2) == "set_version_flag":
                help_text = "print the version (OMNITRACE_VERSION) and exit"
            kind = "flag" if m.group(2) in ("add_flag", "add_flag_callback", "set_version_flag") else "option"
            if kind == "option" and not names.startswith("-"):
                kind = "positional"
            chain = stmt[end:]
            constraints = []
            if "->required()" in chain.replace(" ", ""):
                constraints.append("required")
            for c in re.findall(r"check\(\s*CLI::(\w+)(?:\(\{([^}]*)\}\))?", chain):
                constraints.append(c[0] + ("{" + c[1].replace('"', "").replace(" ", "") + "}" if c[1] else ""))
            for c in re.findall(r"transform\(\s*CLI::(\w+)", chain):
                constraints.append(c)
            default = ""
            if "capture_default_str" in chain and len(args) > 1:
                var = re.sub(r"^\w+->", "", args[1].strip())
                default = defaults.get(var, "")
                if default:
                    default = re.sub(r"ull?\b", "", default).replace('"', "")
                    shift = re.fullmatch(r"\s*(\d+)\s*<<\s*(\d+)\s*", default)
                    if shift:
                        default = str(int(shift.group(1)) << int(shift.group(2)))
            rows.append({
                "command": owner, "names": names, "kind": kind, "help": help_text,
                "constraints": ", ".join(constraints), "default": default,
                "where": f"{rel(path)}:{line}",
            })
    order = {"(global)": 0}
    return sorted(rows, key=lambda r: (order.get(r["command"], 1), r["command"], r["where"]))


def render_cli(rows: list[dict[str, str]]) -> str:
    lines = [
        "# CLI flags",
        "",
        "<!-- generated by scripts/gen_docs.py from apps/cli/*.cpp; do not edit. -->",
        "",
        "This page is for anyone scripting `omnitrace` and for contributors adding an",
        "option. After reading it you know every option and flag the binary accepts,",
        "its help text, constraints and default, and the line that defines it. It is",
        "extracted from the CLI11 `add_option` / `add_flag` calls in `apps/cli/*.cpp`",
        "(`--help` and `-h` are CLI11 built-ins and not listed). The narrative is in",
        "`docs/CLI.md`; `scripts/check_docs.py` fails when a flag here is missing there.",
        "",
        f"{len(rows)} entries.",
        "",
        "| command | option | kind | help | constraints | default | where |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            "| `{}` | `{}` | {} | {} | {} | {} | `{}` |".format(
                r["command"], r["names"], r["kind"], md_cell(r["help"]),
                md_cell(r["constraints"]) or "-", f"`{r['default']}`" if r["default"] else "-", r["where"],
            )
        )
    lines.append("")
    return "\n".join(lines)


def cli_flag_names(rows: list[dict[str, str]]) -> list[str]:
    """Every long (or only) spelling, e.g. `--out`, `--json`, `--version`."""
    out = []
    for r in rows:
        if r["kind"] == "positional":
            continue
        parts = [p.strip() for p in r["names"].split(",")]
        longest = max(parts, key=len)
        out.append(longest)
    return out


# ---------------------------------------------------------------------- main


def generate() -> tuple[dict[str, str], list[str]]:
    """Return {relative path: content} and a list of catalogue problems."""
    problems: list[str] = []
    diags, statuses = collect_diagnostics()
    diag_yaml = load_yaml_map(REF / "diagnostics.yaml")
    all_codes = set(diags) | set(statuses)
    for code in sorted(all_codes - set(diag_yaml)):
        problems.append(f"diagnostics.yaml: missing entry for code `{code}` ({where_cell(diags.get(code) or statuses[code], 1)})")
    for code in sorted(set(diag_yaml) - all_codes):
        problems.append(f"diagnostics.yaml: entry `{code}` has no source")
    for code, entry in diag_yaml.items():
        for field in ("meaning", "action"):
            if not entry.get(field):
                problems.append(f"diagnostics.yaml: `{code}` lacks `{field}`")

    sections = attrs_sections()
    attrs_yaml = load_yaml_map(REF / "attrs.yaml")
    for file in sorted(set(sections) - set(attrs_yaml)):
        problems.append(f"attrs.yaml: missing section `{file}`")
    for file in sorted(set(attrs_yaml) - set(sections)):
        problems.append(f"attrs.yaml: section `{file}` emits no attrs")
    for file, sec in sections.items():
        have = attrs_yaml.get(file, {})
        for key in sorted(set(sec["keys"]) - set(have)):  # type: ignore[arg-type]
            problems.append(f"attrs.yaml: `{file}` lacks key `{key}`")
        for key in sorted(set(have) - set(sec["keys"])):  # type: ignore[arg-type]
            problems.append(f"attrs.yaml: `{file}` key `{key}` is not emitted")

    files = {
        "docs/reference/DIAGNOSTICS.md": render_diagnostics(diags, statuses, diag_yaml),
        "docs/reference/FORMATS.md": render_formats(),
        "docs/reference/ATTRS.md": render_attrs(sections, attrs_yaml),
        "docs/reference/CLI_FLAGS.md": render_cli(collect_cli()),
    }
    return files, problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="compare with the committed files instead of writing")
    ap.add_argument("--list-codes", action="store_true", help="print every diagnostic/status code found in source")
    ap.add_argument("--list-attrs", action="store_true", help="print every attrs key found in source")
    args = ap.parse_args(argv)

    if args.list_codes:
        diags, statuses = collect_diagnostics()
        for code in sorted(diags):
            s = diags[code]
            print(f"{code}\t{','.join(sorted({x.severity for x in s}))}\t{s[0].file}:{s[0].line}\t{s[0].message}")
        for code in sorted(statuses):
            s = statuses[code]
            print(f"{code}\tstatus\t{s[0].file}:{s[0].line}\t{s[0].message}")
        return 0
    if args.list_attrs:
        for file, sec in attrs_sections().items():
            for key, line in sorted(sec["keys"].items()):  # type: ignore[union-attr]
                print(f"{file}\t{key}\t{line}")
        return 0

    files, problems = generate()
    if problems:
        print("gen_docs.py: catalogue problems:", file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 2
    stale = []
    for relpath, content in files.items():
        path = ROOT / relpath
        if args.check:
            if not path.exists() or read(path) != content:
                stale.append(relpath)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists() or read(path) != content:
                path.write_text(content, encoding="utf-8")
                print(f"wrote {relpath}")
    if args.check and stale:
        print("gen_docs.py --check: stale generated files (run scripts/gen_docs.py):", file=sys.stderr)
        for s in stale:
            print("  " + s, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
