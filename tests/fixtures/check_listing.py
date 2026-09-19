#!/usr/bin/env python3
"""Compare OmniTrace listings against the fixtures' ground truth.

Two modes:

  check_listing.py <expected.yaml> <listing.yaml> [--history]

    One filesystem. Exit 0 when every `tree` entry is present in the listing
    with matching kind, mode, owner, size, link target, mtime, nlink and
    SHA-256 (regular files), the live listing has no extra paths, and
    hard-linked pairs share an inode. With --history the `history` section is
    checked too: every `superseded` entry must appear with `superseded: true`
    and the same `version`, every `deleted` entry with `deleted: true`, each
    with matching size, sha256 (unless `content_recoverable: false`) and
    mtime. Otherwise each mismatch is printed and the exit status is 1.

  check_listing.py --cases DIR [--fixtures tests/fixtures/out] [--history]

    A directory of case outputs, one `omnitrace analyze` case per fixture:
    `DIR/<fixture-name>/` (or DIR itself when it holds a single case, named
    after its evidence file). Every case is matched with
    `<fixtures>/<name>.expected.yaml`; a wrapper fixture (MBR/GPT
    `partitions:`) is checked partition by partition against the inner
    fixtures named in its YAML, using the manifest's filesystem node offsets.
    Prints one PASS / FAIL / SKIP line per fixture and a totals line; exit 1
    when any fixture failed.

Entries flagged `deleted` or `superseded` in a listing never count as live
entries, so a listing produced with `--history` passes the tree check as well.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

FILE_SUFFIXES = (".expected.yaml", ".tar.gz", ".img", ".bin")


# --------------------------------------------------------------------------
# one filesystem
# --------------------------------------------------------------------------


def load(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def is_historical(entry) -> bool:
    f = entry.get("file") or {}
    return bool(f.get("deleted")) or bool(f.get("superseded"))


def index_live(entries):
    return {e["file"]["path"]: e for e in entries if not is_historical(e)}


def mismatches(row, entry, fields, resolution=1):
    """Compare `fields` (name -> (want, have)); mtime tolerates < resolution."""
    out = []
    for name, (want, have) in fields.items():
        if want is None:
            continue
        if name == "mtime" and want is not None and have is not None:
            if abs(int(want) - int(have)) < max(1, int(resolution)):
                continue
        if want != have:
            out.append(f"{name} expected {want!r} got {have!r}")
    return out


def check_tree(exp, entries, allowed_extra=()):
    tree = exp.get("tree") or []
    features = exp.get("features") or {}
    resolution = features.get("mtime_resolution", 1)
    ours = index_live(entries)
    errors = []
    seen = set()
    for row in tree:
        p = row["path"]
        seen.add(p)
        e = ours.get(p)
        if e is None:
            errors.append(f"{p}: missing from listing")
            continue
        f = e["file"]
        checks = {
            "kind": (row.get("kind"), f.get("kind")),
            "uid": (row.get("uid") if features.get("owner", True) else None, f.get("uid")),
            "gid": (row.get("gid") if features.get("owner", True) else None, f.get("gid")),
            "mtime": (row.get("mtime"), f.get("mtime")),
        }
        if features.get("mode", True) and row.get("mode") is not None:
            want = int(str(row["mode"]), 8) & 0o7777
            have = f.get("mode")
            checks["mode"] = (f"{want:04o}", f"{int(have) & 0o7777:04o}" if have is not None else None)
        if row.get("kind") != "directory":
            checks["size"] = (row.get("size"), f.get("size"))
        if "link_target" in row:
            checks["link_target"] = (row["link_target"], f.get("link_target"))
        if "nlink" in row and f.get("nlink"):
            checks["nlink"] = (row["nlink"], f.get("nlink"))
        if "sha256" in row:
            digests = e.get("digests") or {}
            checks["sha256"] = (row["sha256"], digests.get("sha256"))
            if row.get("size") is not None:
                checks["bytes"] = (row["size"], digests.get("bytes"))
        for m in mismatches(row, e, checks, resolution):
            errors.append(f"{p}: {m}")
        if "hardlink_of" in row:
            other = ours.get(row["hardlink_of"])
            if other is None:
                errors.append(f"{p}: hardlink target {row['hardlink_of']} missing")
            elif not f.get("inode") or other["file"].get("inode") != f.get("inode"):
                errors.append(
                    f"{p}: inode {f.get('inode')} != {row['hardlink_of']} inode {other['file'].get('inode')}"
                )
    for p in sorted(set(ours) - seen):
        if any(p == a or p.startswith(a + "/") for a in allowed_extra):
            continue
        errors.append(f"{p}: unexpected extra entry in listing")
    return errors, len(tree), len(ours)


def find_superseded(hist, row):
    for e in hist:
        f = e["file"]
        if f.get("superseded") and f["path"] == row["path"] and f.get("version") == row.get("version"):
            return e
    return None


def find_deleted(hist, row):
    orphan = f"lost+found/{row['inode']}" if row.get("inode") is not None else None
    first = None
    for e in hist:
        f = e["file"]
        if not f.get("deleted") or f["path"] not in (row["path"], orphan):
            continue
        if row.get("sha256") and (e.get("digests") or {}).get("sha256") == row["sha256"]:
            return e
        first = first or e
    return first


def version_fields(row, e, resolution):
    f = e["file"]
    digests = e.get("digests") or {}
    checks = {
        "size": (row.get("size"), f.get("size")),
        "inode": (row.get("inode"), f.get("inode")),
        "mtime": (row.get("mtime"), f.get("mtime")),
    }
    if row.get("content_recoverable", True) and row.get("sha256"):
        checks["sha256"] = (row["sha256"], digests.get("sha256"))
    return mismatches(row, e, checks, resolution)


def check_history(exp, entries):
    hist = [e for e in entries if is_historical(e)]
    section = exp.get("history") or {}
    features = exp.get("features") or {}
    resolution = features.get("mtime_resolution", 1)
    errors = []
    for row in section.get("superseded") or []:
        e = find_superseded(hist, row)
        label = f"superseded {row['path']} v{row.get('version')}"
        if e is None:
            seen = [f"v{x['file'].get('version', 0)}" for x in hist if x["file"]["path"] == row["path"]]
            errors.append(f"{label}: not in listing (versions seen: {' '.join(seen) or 'none'})")
            continue
        errors.extend(f"{label}: {m}" for m in version_fields(row, e, resolution))
    for row in section.get("deleted") or []:
        e = find_deleted(hist, row)
        label = f"deleted {row['path']}"
        if e is None:
            errors.append(f"{label}: not in listing with deleted: true")
            continue
        errors.extend(f"{label}: {m}" for m in version_fields(row, e, resolution))
    live = index_live(entries)
    for row in section.get("current") or []:
        e = live.get(row["path"])
        if e and e["file"].get("version") and row.get("version") is not None:
            if e["file"]["version"] != row["version"]:
                errors.append(f"current {row['path']}: version expected {row['version']} got {e['file']['version']}")
    for e in hist:
        f = e["file"]
        if f.get("superseded") and not f.get("version"):
            errors.append(f"superseded {f['path']}: version missing or 0")
    return errors, len(section.get("superseded") or []) + len(section.get("deleted") or []), len(hist)


def check_one(exp, got, history: bool, allowed_extra=()):
    """Returns (errors, summary line)."""
    entries = got.get("entries") or []
    errors, n_tree, n_live = check_tree(exp, entries, allowed_extra)
    summary = f"{n_tree} expected, {n_live} listed"
    if history:
        herr, n_hist, n_got = check_history(exp, entries)
        errors.extend(herr)
        summary += f", history {n_hist} expected, {n_got} listed"
    return errors, summary


def allowed_extras_for(exp) -> tuple:
    fmt = str((exp.get("image") or {}).get("format", ""))
    return ("lost+found",) if fmt.startswith("ext") else ()


def main_pair(expected_path: str, listing_path: str, history: bool) -> int:
    exp = load(expected_path)
    got = load(listing_path)
    errors, summary = check_one(exp, got, history, allowed_extras_for(exp))
    for err in errors:
        print(err)
    print(f"{exp.get('name', expected_path)}: {summary}, {len(errors)} mismatch(es)")
    return 1 if errors else 0


# --------------------------------------------------------------------------
# a directory of cases
# --------------------------------------------------------------------------


def manifest_of(case_dir: Path):
    for name in ("INFO.yaml", "manifest.yaml"):
        p = case_dir / name
        if p.exists():
            return load(p)
    return None


def filesystem_listings(case_dir: Path):
    """[(node offset or None, format, listing path)] for every listing in the case."""
    manifest = manifest_of(case_dir)
    nodes = {}
    for n in (manifest or {}).get("nodes") or []:
        if n.get("kind") == "filesystem":
            nodes[n["id"]] = ((n.get("location") or {}).get("offset"), n.get("format", ""))
    out = []
    for listing in sorted(case_dir.glob("filesystems/*/listing.yaml")):
        node_id = listing.parent.name
        offset, fmt = nodes.get(node_id, (None, ""))
        out.append((offset, fmt, listing))
    return out


def case_name(case_dir: Path) -> str:
    manifest = manifest_of(case_dir)
    for ev in (manifest or {}).get("evidence") or []:
        name = Path(ev.get("path", "")).name
        for suffix in FILE_SUFFIXES:
            if name.endswith(suffix):
                return name[: -len(suffix)]
        if name:
            return name
    return case_dir.name


def check_case(name: str, case_dir: Path, fixtures: Path, history: bool):
    """Returns (status, detail lines)."""
    expected_path = fixtures / f"{name}.expected.yaml"
    if not expected_path.exists():
        return "SKIP", [f"no {expected_path.name} in {fixtures}"]
    exp = load(expected_path)
    listings = filesystem_listings(case_dir)
    details = []

    if "tree" in exp:
        if not listings:
            return "FAIL", ["no filesystems/*/listing.yaml in the case (reader missing or open failed)"]
        chosen = [l for l in listings if l[0] == 0] or listings[:1]
        errors, summary = check_one(exp, load(chosen[0][2]), history, allowed_extras_for(exp))
        details.append(f"{chosen[0][2].relative_to(case_dir)}: {summary}")
        details.extend(errors)
        return ("FAIL" if errors else "PASS"), details

    members = [(p.get("name"), p.get("fixture"), p.get("offset")) for p in exp.get("partitions") or [] if p.get("fixture")]
    if members:
        status = "PASS"
        for pname, fixture, offset in members:
            inner_path = fixtures / f"{fixture}.expected.yaml"
            if not inner_path.exists():
                details.append(f"{pname}: inner fixture {fixture} has no expected.yaml")
                status = "FAIL"
                continue
            inner = load(inner_path)
            match = [l for l in listings if l[0] == offset]
            if not match:
                details.append(f"{pname} ({fixture} at {offset}): no listing (reader missing or open failed)")
                if inner.get("tree"):
                    status = "FAIL"
                continue
            errors, summary = check_one(inner, load(match[0][2]), history, allowed_extras_for(inner))
            details.append(f"{pname} ({fixture} at {offset}): {summary}")
            details.extend(f"  {e}" for e in errors)
            if errors:
                status = "FAIL"
        return status, details

    inner_names = [v.get("fixture") for v in exp.get("volumes") or [] if v.get("fixture")]
    if inner_names and listings:
        status = "PASS"
        for fixture in inner_names:
            inner_path = fixtures / f"{fixture}.expected.yaml"
            if not inner_path.exists():
                details.append(f"volume fixture {fixture} has no expected.yaml")
                status = "FAIL"
                continue
            inner = load(inner_path)
            fmt = str((inner.get("image") or {}).get("format", ""))
            match = [l for l in listings if l[1] == fmt] or listings
            errors, summary = check_one(inner, load(match[0][2]), history, allowed_extras_for(inner))
            details.append(f"volume {fixture}: {summary}")
            details.extend(f"  {e}" for e in errors)
            if errors:
                status = "FAIL"
        return status, details
    return "SKIP", ["wrapper fixture (volumes/layers/payload) whose contents analyze() does not open yet"]


def main_cases(cases_dir: str, fixtures_dir: str, history: bool) -> int:
    root = Path(cases_dir)
    fixtures = Path(fixtures_dir)
    if manifest_of(root) is not None:
        cases = [(case_name(root), root)]
    else:
        cases = sorted((d.name, d) for d in root.iterdir() if d.is_dir() and manifest_of(d) is not None)
    if not cases:
        print(f"{root}: no case directories (INFO.yaml / manifest.yaml) found")
        return 2
    counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
    for name, case_dir in cases:
        status, details = check_case(name, case_dir, fixtures, history)
        counts[status] += 1
        print(f"{status:4} {name}")
        for line in details:
            print(f"     {line}")
    print(f"{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped")
    return 1 if counts["FAIL"] else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*", help="<expected.yaml> <listing.yaml>")
    ap.add_argument("--history", action="store_true", help="also check the history section")
    ap.add_argument("--cases", metavar="DIR", help="a directory of analyze() case outputs, one per fixture")
    ap.add_argument(
        "--fixtures",
        metavar="DIR",
        default=str(Path(__file__).resolve().parent / "out"),
        help="where the <name>.expected.yaml files are (default: %(default)s)",
    )
    args = ap.parse_args(argv)
    if args.cases:
        if args.paths:
            ap.error("--cases takes no positional arguments")
        return main_cases(args.cases, args.fixtures, args.history)
    if len(args.paths) != 2:
        ap.print_help()
        return 2
    return main_pair(args.paths[0], args.paths[1], args.history)


if __name__ == "__main__":
    sys.exit(main())
