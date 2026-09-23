#!/usr/bin/env python3
"""Run the parity harness over many images and aggregate one number.

`run.py` answers "how do the tools compare on this image". Phase 1's exit
criterion is a claim about a *set* of images -- parity >= 95% of the files
unblob and moria recover, over the fixtures and the corpus -- so something has
to run the harness across a list and pool the results. This is that.

    tests/parity/sweep.py tests/fixtures/out/*.img corpus/*/flash/*.bin
    tests/parity/sweep.py --list images.txt --out /var/tmp/parity
    tests/parity/sweep.py IMAGE... --reuse          # re-aggregate, run nothing

Two numbers are reported for each baseline, because they answer different
questions and a single one can flatter:

* **pooled** -- every recovered content across every image in one set:
  `common / baseline`. This is the corpus-wide recall, and a 7 GB eMMC counts
  for more than a 1 MiB fixture, which is the right weighting for "did we
  recover the data".
* **per-image mean** -- the unweighted mean of the per-image percentages, plus
  the worst image. A format that only appears in one small fixture can fail
  completely without moving the pooled number, and that is exactly the kind of
  regression this is supposed to catch.

Disk: the extraction trees of four tools over a corpus are tens of gigabytes,
so each image's trees are deleted once its summary has been read. The
`*.normalized.json` files keep every path and hash, so a number stays
auditable without keeping the bytes -- and the bytes are evidence-derived and
must not accumulate in the tree (CLAUDE.md). `--keep` turns that off.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import shutil
import statistics
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RUN = HERE / "run.py"
sys.path.insert(0, str(HERE))
import run as harness  # noqa: E402  the metric lives there; this never re-implements it
SCHEMA = "omnitrace-parity-sweep/1"
# `expected` is a fixture's ground truth (tests/fixtures/out/<name>.expected.yaml),
# not a tool. It is first because it is the only one that settles who is right
# when OmniTrace and a baseline disagree -- the others are peers, not oracles.
BASELINES = ["expected", "unblob", "moria", "binwalk"]
SUBJECT = "omnitrace"


def human(n: float) -> str:
    return f"{n:,.1f}%"


def pct(part: int, whole: int) -> Optional[float]:
    return None if whole == 0 else 100.0 * part / whole


def recovery_from_normalized(dest: Path) -> Optional[dict]:
    """Rebuild the recovery block from `<tool>.normalized.json`."""
    results: dict[str, harness.ToolResult] = {}
    for f in sorted(dest.glob("*.normalized.json")):
        try:
            doc = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if doc.get("status") != "ok":
            continue
        findings = []
        for x in doc.get("findings", []):
            fi = harness.Finding(int(x["offset"]), x["format"], x.get("raw_format", ""), x.get("size"))
            fi.files = [harness.FileRec(r["relpath"], int(r.get("size", 0)), r.get("sha256", ""),
                                        r.get("kind", "regular"), r.get("target", ""))
                        for r in x.get("files", [])]
            findings.append(fi)
        results[doc["tool"]] = harness.ToolResult(doc["tool"], findings=findings)
    if not results:
        return None
    return harness.recovery_report(results)


def label_of(img: Path) -> str:
    """How an image is named in the report and on disk.

    The corpus holds four `UserData.BIN` from four different vehicles. Keying
    on the basename put three of them in one output directory, where each run
    overwrote the last and the report showed the same name three times. The
    path relative to the repository is unique and still readable.
    """
    try:
        rel = img.resolve().relative_to(REPO)
    except ValueError:
        return img.name
    parts = [x for x in rel.parts if x not in ("flash", "out")]
    return "-".join(parts[-2:]) if len(parts) > 1 else rel.name


def run_one(img: Path, out: Path, opts: argparse.Namespace) -> Optional[dict]:
    """Run the harness for one image and return its summary.json."""
    dest = out / label_of(img)
    summary = dest / "summary.json"
    if not (opts.reuse and summary.exists()):
        argv = [sys.executable, str(RUN), str(img), "--out", str(dest)]
        if opts.tools:
            argv += ["--tools", opts.tools]
        if opts.omnitrace:
            argv += ["--omnitrace", opts.omnitrace]
        if opts.timeout:
            argv += ["--timeout", str(opts.timeout)]
        if opts.extra:
            argv += opts.extra
        print(f"== {label_of(img)}", flush=True)
        r = subprocess.run(argv, cwd=REPO)
        if not summary.exists():
            print(f"   !! no summary.json (exit {r.returncode})", flush=True)
            return None
    doc = json.loads(summary.read_text())
    # Recompute the recovery block from the per-tool normalized.json rather
    # than trusting what summary.json recorded. The normalised files hold every
    # path and hash, so the metric can change without re-running four tools
    # over a corpus -- which matters because the extraction trees are deleted
    # below and cannot be re-hashed.
    rec = recovery_from_normalized(dest)
    if rec is not None:
        doc["recovery"] = rec
    if not opts.keep:
        # Keep summary.json, report.md and the *.normalized.json; drop the
        # extracted trees, which are the whole of the size.
        for child in dest.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
    return doc


def pair_of(rec: dict, a: str, b: str) -> Optional[dict]:
    """The recovery row for {a, b} in either order, oriented so that `a` is A.

    Two metrics come back. `regular_*` counts distinct regular-file contents by
    sha256 and is the headline, because a sha256 means the same thing in every
    tool. `common`/`a_total` additionally count symlinks, and those are only
    approximately comparable: a symlink's target has to be resolved against the
    directory the link is in, and each tool writes a nested extraction under a
    prefix of its own (`filesystem@1.extracted/0x0-squashfs/bin/ash` in moria,
    `filesystems/n000021/files/bin/ash` here), so the same link anchors to two
    different absolute paths. That artifact alone read as 226 missing files on
    one router image and 31 on another, both of which are 100% and 99.3% on the
    regular-file measure. A symlink carries no data, so the headline is not
    worse for leaving it out -- it is just unambiguous.
    """
    for d in rec.get("pairs", []):
        if d["a"] == a and d["b"] == b:
            return {"common": d["common"], "a_total": d["common"] + d["only_a"],
                    "b_total": d["common"] + d["only_b"], "subject_of_baseline": d["b_of_a"],
                    "regular_common": d["regular_common"],
                    "regular_a_total": d["regular_common"] + d.get("only_a_regular", 0),
                    "regular_share": d["regular_b_of_a"],
                    "zero_fill": d.get("only_a_zero_fill", 0)}
        if d["a"] == b and d["b"] == a:
            return {"common": d["common"], "a_total": d["common"] + d["only_b"],
                    "b_total": d["common"] + d["only_a"], "subject_of_baseline": d["a_of_b"],
                    "regular_common": d["regular_common"],
                    "regular_a_total": d["regular_common"] + d.get("only_b_regular", 0),
                    "regular_share": d["regular_a_of_b"],
                    "zero_fill": d.get("only_b_zero_fill", 0)}
    return None


def aggregate(rows: list[dict]) -> dict:
    """Pool every image, and also keep the per-image spread."""
    out: dict[str, Any] = {}
    for base in BASELINES:
        common = total = 0
        per_image: list[tuple[str, float]] = []
        covered = 0
        rc = rt = 0
        for row in rows:
            d = row["baselines"].get(base)
            if not d:
                continue
            covered += 1
            common += d["common"]
            total += d["a_total"]
            rc += d["regular_common"]
            rt += d["regular_a_total"]
            if d["regular_share"] is not None:
                per_image.append((row["image"], d["regular_share"]))
        if not covered:
            continue
        per_image.sort(key=lambda t: t[1])
        out[base] = {
            "images": covered,
            "images_with_files": len(per_image),
            "common": common,
            "baseline_total": total,
            "pooled_with_symlinks": pct(common, total),
            "regular_common": rc,
            "regular_total": rt,
            "pooled": pct(rc, rt),
            "mean": statistics.fmean([p for _, p in per_image]) if per_image else None,
            "median": statistics.median([p for _, p in per_image]) if per_image else None,
            "worst": per_image[0] if per_image else None,
            "below_95": [[n, p] for n, p in per_image if p < 95.0],
        }
    return out


def render(doc: dict, cap: int) -> str:
    L = [f"# Parity sweep: `{SUBJECT}` vs {', '.join(BASELINES)}", "",
         f"- images: {len(doc['images'])}", f"- generated: {doc['generated']}", ""]
    L += ["## Headline", "",
          "Share of each baseline's recovered **regular-file contents** (distinct",
          "sha256) that OmniTrace also recovered. Pooled is every content across",
          "every image in one set; the mean is unweighted per image, so one small",
          "image failing shows up. The last column adds symlinks, which are only",
          "approximately comparable between tools -- see `pair_of` in sweep.py.", "",
          "| baseline | images | pooled | per-image mean | median | worst image | with symlinks |",
          "|---|---:|---:|---:|---:|---|---:|"]
    for base, a in doc["aggregate"].items():
        worst = f"{a['worst'][0]} ({human(a['worst'][1])})" if a["worst"] else "-"
        sym = a.get("pooled_with_symlinks")
        L.append(f"| {base} | {a['images']} | {human(a['pooled']) if a['pooled'] is not None else '-'} | "
                 f"{human(a['mean']) if a['mean'] is not None else '-'} | "
                 f"{human(a['median']) if a['median'] is not None else '-'} | {worst} | "
                 f"{human(sym) if sym is not None else '-'} |")
    for base, a in doc["aggregate"].items():
        if a["below_95"]:
            L += ["", f"Images below 95% of {base}:", ""]
            L += [f"- {n}: {human(p)}" for n, p in a["below_95"][:cap]]
    L += ["", "## Per image", "",
          "Counts are distinct regular-file contents (sha256); the shares are of "
          "that unit.", "",
          "| image | size | omnitrace | expected | unblob | moria | of expected | of unblob | of moria |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for row in doc["images"]:
        def tot(t: str) -> str:
            v = row["per_tool"].get(t)
            return f"{v['regular_hashes']:,}" if v else "-"

        def share(b: str) -> str:
            d = row["baselines"].get(b)
            return human(d["regular_share"]) if d and d["regular_share"] is not None else "-"
        L.append(f"| {row['image']} | {row['size']:,} | {tot(SUBJECT)} | {tot('expected')} | {tot('unblob')} | {tot('moria')} | "
                 f"{share('expected')} | {share('unblob')} | {share('moria')} |")
    notes = [r for r in doc["images"] if r["notes"]]
    if notes:
        L += ["", "## Tool status", ""]
        for row in notes:
            for n in row["notes"]:
                L.append(f"- {row['image']}: {n}")
    return "\n".join(L) + "\n"


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("images", nargs="*", help="images to run")
    ap.add_argument("--list", help="file with one image path per line (# comments allowed)")
    ap.add_argument("--out", default=str(HERE / "out"), help="where each image's run lands")
    ap.add_argument("--tools", help="passed through to run.py")
    ap.add_argument("--omnitrace", help="passed through to run.py")
    ap.add_argument("--timeout", type=int, help="passed through to run.py")
    ap.add_argument("--reuse", action="store_true", help="re-aggregate existing runs, run nothing")
    ap.add_argument("--keep", action="store_true", help="keep the extraction trees (they are large)")
    ap.add_argument("--max-list", type=int, default=40, help="cap on listed images in the report")
    ap.add_argument("--extra", nargs=argparse.REMAINDER, default=[], help="further run.py arguments")
    opts = ap.parse_args(argv)

    images = [Path(p) for p in opts.images]
    if opts.list:
        for line in Path(opts.list).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                images.append(Path(line))
    if not images:
        ap.error("no images given")

    out = Path(opts.out)
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for img in images:
        if not img.is_file():
            print(f"   !! {img}: not a file, skipped", flush=True)
            continue
        doc = run_one(img, out, opts)
        if doc is None:
            continue
        rec = doc.get("recovery") or {}
        row = {
            "image": label_of(img), "name": img.name, "path": str(img), "size": doc["image"]["size"],
            "sha256": doc["image"]["sha256"],
            "per_tool": rec.get("per_tool", {}),
            "baselines": {b: d for b in BASELINES if (d := pair_of(rec, b, SUBJECT))},
            "notes": [f"{t}: {v['status']}" + (f" - {v['message']}" if v.get("message") else "")
                      for t, v in doc.get("tools", {}).items() if v.get("status") != "ok"],
        }
        rows.append(row)
        for b in BASELINES:
            d = row["baselines"].get(b)
            if d and d["subject_of_baseline"] is not None:
                print(f"   {SUBJECT} recovered {d['subject_of_baseline']:.1f}% of {b}", flush=True)

    doc = {
        "schema": SCHEMA,
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "subject": SUBJECT, "baselines": BASELINES,
        "images": rows,
        "aggregate": aggregate(rows),
    }
    (out / "sweep.json").write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")
    (out / "sweep.md").write_text(render(doc, opts.max_list))
    print(f"\nwrote {out}/sweep.md and sweep.json")
    for base, a in doc["aggregate"].items():
        if a["pooled"] is not None:
            print(f"  vs {base}: pooled {a['pooled']:.1f}%, mean {a['mean']:.1f}%, "
                  f"worst {a['worst'][0]} {a['worst'][1]:.1f}%" if a["mean"] is not None
                  else f"  vs {base}: pooled {a['pooled']:.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
