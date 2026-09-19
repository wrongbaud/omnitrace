#!/usr/bin/env python3
"""Compare an OmniTrace listing.yaml against a fixture's <name>.expected.yaml.

usage: check_listing.py <expected.yaml> <listing.yaml>

Exit 0 when every expected entry is present with matching kind, mode, owner,
size, link target, mtime, nlink and SHA-256 (regular files), the listing has
no extra paths, and hard-linked pairs share an inode. Otherwise prints each
mismatch and exits 1.
"""
import sys

import yaml


def index(entries):
    return {e["file"]["path"]: e for e in entries}


def main(expected_path, listing_path):
    exp = yaml.safe_load(open(expected_path))
    got = yaml.safe_load(open(listing_path))
    tree = exp["tree"]
    ours = index(got["entries"])
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
            "mode": (row.get("mode"), f.get("mode_octal")),
            "uid": (row.get("uid"), f.get("uid")),
            "gid": (row.get("gid"), f.get("gid")),
            "size": (row.get("size"), f.get("size")),
            "mtime": (row.get("mtime"), f.get("mtime")),
        }
        if "link_target" in row:
            checks["link_target"] = (row["link_target"], f.get("link_target"))
        if "nlink" in row:
            checks["nlink"] = (row["nlink"], f.get("nlink"))
        if "sha256" in row:
            checks["sha256"] = (row["sha256"], (e.get("digests") or {}).get("sha256"))
        for name, (want, have) in checks.items():
            if want is None:
                continue
            if want != have:
                errors.append(f"{p}: {name} expected {want!r} got {have!r}")
        if "hardlink_of" in row:
            other = ours.get(row["hardlink_of"])
            if other is None:
                errors.append(f"{p}: hardlink target {row['hardlink_of']} missing")
            elif other["file"].get("inode") != f.get("inode"):
                errors.append(f"{p}: inode {f.get('inode')} != {row['hardlink_of']} inode {other['file'].get('inode')}")
    extra = sorted(set(ours) - seen)
    for p in extra:
        errors.append(f"{p}: unexpected extra entry in listing")
    for err in errors:
        print(err)
    print(f"{exp.get('name', expected_path)}: {len(tree)} expected, {len(ours)} listed, {len(errors)} mismatch(es)")
    return 1 if errors else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
