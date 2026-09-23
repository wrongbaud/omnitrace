#!/usr/bin/env python3
"""OmniTrace parity harness.

Runs unblob (Docker), binwalk 3 (host), moria (Docker, tests/parity/moria.Dockerfile)
and, when it exists, the OmniTrace CLI over one image, normalises every tool's
output into the same shape, diffs the tools pairwise and writes a Markdown
report plus a JSON summary.

Normalised shape, written to <out>/<tool>.normalized.json for every tool:

    {"tool": "unblob", "findings": [
        {"offset": 1872453, "format": "squashfs", "raw_format": "squashfs_v4_le",
         "size": 11054868, "files": [{"relpath": "bin/busybox", "size": 1, "sha256": "..."}]}]}

Findings are the tool's *top-level* results (chunks / signatures / nodes found
directly in the image); the files of a finding are everything the tool
extracted for it, recursively, relative to that finding's extraction root, so
nested extraction directories (unblob's `*_extract`, moria's `payload.extracted`)
show up as path prefixes and are compared like any other path.

Diffing: findings match on exact offset, then on canonical format (see
FORMAT_ALIASES: squashfs_v4_le -> squashfs, jffs2_new -> jffs2, ...). Files of a
matched finding are compared by relpath (same path: hashes equal or not) and by
content (sha256 present in one tool only).

A fixture's ground truth (tests/fixtures/out/<name>.expected.yaml) can be added
as the pseudo-tool `expected` with --expected, or automatically when the image
sits next to its expected.yaml.

    tests/parity/run.py /path/to/router.bin
    tests/parity/run.py tests/fixtures/out/jffs2-history.img --tools unblob,moria
    tests/parity/run.py image.bin --reuse      # re-normalise existing tool output

See docs/TESTING.md.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

SCHEMA = "omnitrace-parity/1"
ALL_TOOLS = ["unblob", "binwalk", "moria", "omnitrace"]
DEFAULT_UNBLOB_IMAGE = "ghcr.io/onekey-sec/unblob:latest"
DEFAULT_MORIA_IMAGE = "omnitrace-parity-moria"
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

# --------------------------------------------------------------------------
# Format names
# --------------------------------------------------------------------------

# Tool-specific name -> canonical name. Anything not listed goes through
# canonical_format()'s suffix stripping (version / endianness / variant).
FORMAT_ALIASES: dict[str, str] = {
    # squashfs
    "squashfs_v4_le": "squashfs", "squashfs_v4_be": "squashfs", "squashfs_v4_broadcom": "squashfs",
    "squashfs_v3": "squashfs", "squashfs_v3_broadcom": "squashfs", "squashfs_v3_ddwrt": "squashfs",
    "squashfs_v3_nonstandard": "squashfs", "squashfs_v2": "squashfs", "squashfs_v2_nonstandard": "squashfs",
    "squashfs_v1": "squashfs", "squashfs_legacy": "squashfs", "sqsh": "squashfs",
    # jffs2 / ubi / yaffs
    "jffs2_new": "jffs2", "jffs2_old": "jffs2", "jffs2": "jffs2",
    "ubi": "ubi", "ubifs": "ubifs",
    "yaffs": "yaffs2", "yaffs2": "yaffs2", "yaffsv2": "yaffs2", "yaffs1": "yaffs1",
    # block filesystems
    "extfs": "ext", "ext": "ext", "ext2": "ext", "ext3": "ext", "ext4": "ext", "linux_ext": "ext",
    "fat": "fat", "fat32": "fat", "vfat": "fat", "fat16": "fat", "fat12": "fat", "dos": "fat",
    "cramfs": "cramfs", "romfs": "romfs", "erofs": "erofs", "f2fs": "f2fs", "ntfs": "ntfs",
    "iso9660": "iso9660", "iso": "iso9660",
    # partition tables
    "mbr": "mbr", "dos_mbr": "mbr", "gpt": "gpt", "efi_gpt": "gpt",
    # containers / compression
    "uimage": "uimage", "u-boot": "uimage", "uboot": "uboot", "uboot_env": "uboot_env",
    "lzma": "lzma", "lzma_alone": "lzma", "xz": "xz", "gzip": "gzip", "bzip2": "bzip2", "bz2": "bzip2",
    "zstd": "zstd", "lz4": "lz4", "lz4_default": "lz4", "lz4_legacy": "lz4", "lz4_skippable": "lz4",
    "lzo": "lzo", "lzop": "lzo", "lzip": "lzip", "zlib": "zlib", "compress": "compress",
    "tar": "tar", "tarball": "tar", "posix_tar": "tar", "ustar": "tar",
    "cpio": "cpio", "cpio_binary": "cpio", "cpio_portable_ascii": "cpio", "cpio_portable_ascii_crc": "cpio",
    "cpio_portable_old_ascii": "cpio",
    "zip": "zip", "sevenzip": "7z", "7z": "7z", "7-zip": "7z", "rar": "rar", "ar": "ar", "arj": "arj",
    "cab": "cab", "elf": "elf", "elf32": "elf", "elf64": "elf",
    "sparse": "android_sparse", "android_sparse": "android_sparse", "android_boot": "android_boot",
    "trx": "trx", "trx_v1": "trx", "trx_v2": "trx", "dtb": "dtb", "device_tree": "dtb", "fdt": "dtb",
    "encrpted_img": "dlink_encrpted_img", "dlink_encrpted_img": "dlink_encrpted_img",
    "shrs": "dlink_shrs", "dlink_shrs": "dlink_shrs",
}
_STRIP = re.compile(r"(_v\d+|_le|_be|_new|_old|_legacy|_default|_nonstandard|_built_in)+$")


def canonical_format(name: Any) -> str:
    """Map a tool's format label to the canonical name used for diffing."""
    s = str(name or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not s:
        return "unknown"
    if s in FORMAT_ALIASES:
        return FORMAT_ALIASES[s]
    stripped = _STRIP.sub("", s)
    if stripped in FORMAT_ALIASES:
        return FORMAT_ALIASES[stripped]
    return stripped or s


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclasses.dataclass
class FileRec:
    relpath: str
    size: int
    sha256: str
    kind: str = "regular"  # regular | symlink
    target: str = ""


@dataclasses.dataclass
class Finding:
    offset: int
    format: str
    raw_format: str
    size: Optional[int] = None
    extracted: Optional[bool] = None  # None: the tool does not extract this kind
    root: Optional[str] = None  # extraction root, relative to the tool's out dir
    files: list[FileRec] = dataclasses.field(default_factory=list)
    extra: dict = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class ToolResult:
    tool: str
    status: str = "ok"  # ok | skipped | failed
    message: str = ""
    version: str = ""
    seconds: float = 0.0
    argv: list[str] = dataclasses.field(default_factory=list)
    exit_code: Optional[int] = None
    findings: list[Finding] = dataclasses.field(default_factory=list)

    def normalized(self) -> dict:
        return {
            "tool": self.tool,
            "status": self.status,
            "message": self.message,
            "version": self.version,
            "findings": [
                {
                    "offset": f.offset,
                    "format": f.format,
                    "raw_format": f.raw_format,
                    "size": f.size,
                    "extracted": f.extracted,
                    "root": f.root,
                    "files": [dataclasses.asdict(x) for x in f.files],
                    **({"extra": f.extra} if f.extra else {}),
                }
                for f in sorted(self.findings, key=lambda f: (f.offset, f.format))
            ],
        }


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_tree(root: Path) -> list[FileRec]:
    """Every regular file and symlink under `root`, sorted by relpath.
    Directories are implied; devices/fifos are skipped; symlinks are not followed."""
    out: list[FileRec] = []
    if not root.is_dir():
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]):
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if os.path.islink(p):
                try:
                    tgt = os.readlink(p)
                except OSError:
                    tgt = ""
                out.append(FileRec(rel, len(tgt.encode("utf-8", "surrogateescape")), "", "symlink", tgt))
            elif os.path.isfile(p):
                try:
                    out.append(FileRec(rel, st.st_size, sha256_file(p)))
                except OSError:
                    continue
    out.sort(key=lambda r: r.relpath)
    return out


# --------------------------------------------------------------------------
# Running tools
# --------------------------------------------------------------------------


class Runner:
    def __init__(self, img: Path, out: Path, opts: argparse.Namespace):
        self.img = img.resolve()
        self.out = out.resolve()
        self.opts = opts

    def log(self, msg: str) -> None:
        print(msg, file=sys.stderr, flush=True)

    def docker_user(self) -> list[str]:
        if self.opts.no_docker_user or os.name != "posix":
            return []
        return ["-u", f"{os.getuid()}:{os.getgid()}"]

    def fresh(self, name: str) -> Path:
        d = self.out / name
        if d.exists() and not self.opts.reuse:
            shutil.rmtree(d)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def exec(self, argv: list[str], res: ToolResult, stdout: Optional[Path] = None, stderr: Optional[Path] = None) -> subprocess.CompletedProcess:
        res.argv = argv
        self.log("  $ " + " ".join(argv))
        t0 = time.monotonic()
        so = open(stdout, "wb") if stdout else subprocess.DEVNULL
        se = open(stderr, "wb") if stderr else subprocess.DEVNULL
        try:
            r = subprocess.run(argv, stdout=so, stderr=se, timeout=self.opts.timeout, check=False)
        finally:
            res.seconds = time.monotonic() - t0
            for fh in (so, se):
                if hasattr(fh, "close"):
                    fh.close()
        res.exit_code = r.returncode
        return r

    @staticmethod
    def version_of(argv: list[str]) -> str:
        try:
            r = subprocess.run(argv, capture_output=True, timeout=120, check=False)
            text = (r.stdout + r.stderr).decode(errors="replace").strip()
            return text.splitlines()[0].strip() if text else "unknown"
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"

    # ---- unblob -------------------------------------------------------

    def run_unblob(self) -> ToolResult:
        res = ToolResult("unblob")
        if not shutil.which("docker"):
            res.status, res.message = "skipped", "docker not found"
            return res
        outdir = self.fresh("unblob")
        report = outdir / "report.json"
        res.version = self.version_of(["docker", "run", "--rm", self.opts.unblob_image, "--version"])
        if not (self.opts.reuse and report.exists()):
            argv = [
                "docker", "run", "--rm", *self.docker_user(),
                "-v", f"{self.img.parent}:/data:ro", "-v", f"{outdir}:/out", "-w", "/out",
                self.opts.unblob_image,
                "-e", "/out", "--report", "/out/report.json", "--log", "/out/unblob.log",
                "-p", str(self.opts.jobs), f"/data/{self.img.name}",
            ]
            try:
                r = self.exec(argv, res, stdout=outdir / "stdout.txt", stderr=outdir / "stderr.txt")
            except subprocess.TimeoutExpired:
                res.status, res.message = "failed", f"timeout after {self.opts.timeout}s"
                return res
            if r.returncode != 0 and not report.exists():
                res.status, res.message = "failed", f"exit {r.returncode}; see {outdir / 'stderr.txt'}"
                return res
        try:
            res.findings = parse_unblob(json.loads(report.read_text(encoding="utf-8")), outdir, "/out", f"/data/{self.img.name}")
        except (OSError, ValueError, KeyError) as ex:
            res.status, res.message = "failed", f"cannot parse {report}: {ex}"
        return res

    # ---- binwalk ------------------------------------------------------

    def run_binwalk(self) -> ToolResult:
        res = ToolResult("binwalk")
        exe = self.opts.binwalk or shutil.which("binwalk")
        if not exe:
            res.status, res.message = "skipped", "binwalk not found"
            return res
        outdir = self.fresh("binwalk")
        log = outdir / "binwalk.json"
        res.version = self.version_of([exe, "--version"])
        if not (self.opts.reuse and log.exists()):
            argv = [exe, "-e", "-C", str(outdir), "-l", str(log)]
            if self.opts.binwalk_matryoshka:
                argv.append("-M")
            argv.append(str(self.img))
            try:
                r = self.exec(argv, res, stdout=outdir / "stdout.txt", stderr=outdir / "stderr.txt")
            except subprocess.TimeoutExpired:
                res.status, res.message = "failed", f"timeout after {self.opts.timeout}s"
                return res
            if not log.exists():
                res.status, res.message = "failed", f"exit {r.returncode}, no JSON log; see {outdir / 'stderr.txt'}"
                return res
        try:
            res.findings = parse_binwalk(json.loads(log.read_text(encoding="utf-8")), self.img.name)
        except (OSError, ValueError, KeyError) as ex:
            res.status, res.message = "failed", f"cannot parse {log}: {ex}"
        return res

    # ---- moria --------------------------------------------------------

    def run_moria(self) -> ToolResult:
        res = ToolResult("moria")
        if not shutil.which("docker"):
            res.status, res.message = "skipped", "docker not found"
            return res
        outdir = self.fresh("moria")
        js = outdir / "moria.json"
        if not self.opts.reuse or not js.exists():
            if not docker_image_exists(self.opts.moria_image):
                if self.opts.no_build:
                    res.status, res.message = "skipped", f"docker image {self.opts.moria_image} missing (built from tests/parity/moria.Dockerfile)"
                    return res
                self.log(f"  building {self.opts.moria_image} from {HERE / 'moria.Dockerfile'}")
                b = subprocess.run(["docker", "build", "-q", "-f", str(HERE / "moria.Dockerfile"), "-t", self.opts.moria_image, str(HERE)], capture_output=True, check=False)
                if b.returncode != 0:
                    res.status, res.message = "failed", "docker build failed: " + b.stderr.decode(errors="replace")[-400:]
                    return res
        res.version = self.version_of(["docker", "run", "--rm", self.opts.moria_image, "--version"])
        if not (self.opts.reuse and js.exists()):
            argv = [
                "docker", "run", "--rm", *self.docker_user(),
                "-v", f"{self.img.parent}:/data:ro", "-v", f"{outdir}:/out",
                self.opts.moria_image, "-j", "-e", "-C", "/out", f"/data/{self.img.name}",
            ]
            try:
                r = self.exec(argv, res, stdout=js, stderr=outdir / "stderr.txt")
            except subprocess.TimeoutExpired:
                res.status, res.message = "failed", f"timeout after {self.opts.timeout}s"
                return res
            if js.stat().st_size == 0:
                res.status, res.message = "failed", f"exit {r.returncode}, empty JSON; see {outdir / 'stderr.txt'}"
                return res
        try:
            res.findings = parse_moria(json.loads(js.read_text(encoding="utf-8")), outdir)
        except (OSError, ValueError, KeyError) as ex:
            res.status, res.message = "failed", f"cannot parse {js}: {ex}"
        return res

    # ---- omnitrace ----------------------------------------------------

    def find_omnitrace(self) -> Optional[str]:
        if self.opts.omnitrace:
            return self.opts.omnitrace
        exe = shutil.which("omnitrace")
        if exe:
            return exe
        for cand in sorted((REPO / "build").glob("*/apps/cli/omnitrace")) + sorted((REPO / "build").glob("*/omnitrace")):
            if os.access(cand, os.X_OK):
                return str(cand)
        return None

    def run_omnitrace(self) -> ToolResult:
        res = ToolResult("omnitrace")
        exe = self.find_omnitrace()
        if not exe:
            res.status, res.message = "skipped", "omnitrace CLI not found (pass --omnitrace or build apps/cli)"
            return res
        outdir = self.fresh("omnitrace")
        manifest = outdir / "manifest.yaml"
        res.version = self.version_of([exe, "--version"])
        if not (self.opts.reuse and manifest.exists()):
            argv = [exe, "analyze", str(self.img), "--out", str(outdir)]
            try:
                r = self.exec(argv, res, stdout=outdir / "stdout.txt", stderr=outdir / "stderr.txt")
            except subprocess.TimeoutExpired:
                res.status, res.message = "failed", f"timeout after {self.opts.timeout}s"
                return res
            if not manifest.exists():
                err = (outdir / "stderr.txt").read_text(errors="replace")[-300:]
                kind = "skipped" if re.search(r"subcommand|unknown|not (yet )?implemented|unrecognized", err, re.I) else "failed"
                res.status, res.message = kind, f"exit {r.returncode}, no manifest.yaml: {err.strip()}"
                return res
        try:
            res.findings = parse_omnitrace(manifest, outdir)
        except Exception as ex:  # noqa: BLE001 - tolerant of a manifest schema still in flux
            res.status, res.message = "failed", f"cannot parse {manifest}: {ex}"
        return res

    # ---- expected.yaml ------------------------------------------------

    def run_expected(self, path: Path) -> ToolResult:
        res = ToolResult("expected", version=f"{path.name}")
        try:
            res.findings = parse_expected(path)
        except Exception as ex:  # noqa: BLE001
            res.status, res.message = "failed", f"cannot read {path}: {ex}"
        return res


def docker_image_exists(tag: str) -> bool:
    r = subprocess.run(["docker", "image", "inspect", tag], capture_output=True, check=False)
    return r.returncode == 0


# --------------------------------------------------------------------------
# Parsers (pure functions; unit-tested in test_run.py)
# --------------------------------------------------------------------------


def _container_to_host(path: str, prefix: str, host: Path) -> Path:
    if path == prefix:
        return host
    if path.startswith(prefix + "/"):
        return host / path[len(prefix) + 1 :]
    return host / path.lstrip("/")


def parse_unblob(report: list[dict], outdir: Path, out_prefix: str, image_path: str) -> list[Finding]:
    """unblob --report JSON: a list of tasks. The depth-0 task for the image
    carries one ChunkReport per top-level chunk; each chunk's extraction
    directory is the subtask whose blob_id equals the chunk id."""
    findings: list[Finding] = []
    for task in report:
        t = task.get("task", {})
        if t.get("depth", -1) != 0 or t.get("path") != image_path:
            continue
        subtasks = {s.get("blob_id"): s.get("path") for s in task.get("subtasks", []) if s.get("path")}
        for rep in task.get("reports", []):
            tn = rep.get("__typename__")
            if tn == "ChunkReport":
                f = Finding(int(rep["start_offset"]), canonical_format(rep.get("handler_name")), str(rep.get("handler_name")), int(rep.get("size", 0)))
                f.extra = {"end_offset": rep.get("end_offset"), "is_encrypted": rep.get("is_encrypted"), "chunk_id": rep.get("id")}
                errs = [e for e in rep.get("extraction_reports", []) if "Error" in str(e.get("__typename__", "")) or e.get("severity") == "ERROR"]
                sub = subtasks.get(rep.get("id"))
                if sub:
                    root = _container_to_host(sub, out_prefix, outdir)
                    f.root = root.relative_to(outdir).as_posix() if root != outdir else "."
                    f.files = hash_tree(root)
                    f.extracted = root.exists() and not errs
                else:
                    f.extracted = False
                if errs:
                    f.extra["extraction_errors"] = [str(e.get("__typename__")) for e in errs]
                findings.append(f)
            elif tn == "UnknownChunkReport":
                f = Finding(int(rep["start_offset"]), "unknown", "unknown", int(rep.get("size", 0)))
                f.extra = {"end_offset": rep.get("end_offset")}
                findings.append(f)
    findings.sort(key=lambda f: (f.offset, f.format))
    return findings


def parse_binwalk(log: list[dict], image_name: str) -> list[Finding]:
    """binwalk 3 -l JSON: [{"Analysis": {file_path, file_map: [...], extractions: {id: {...}}}}]."""
    analysis: Optional[dict] = None
    for entry in log:
        a = entry.get("Analysis") or entry
        if os.path.basename(str(a.get("file_path", ""))) == image_name:
            analysis = a
            break
    if analysis is None and log:
        analysis = log[0].get("Analysis") or log[0]
    if not analysis:
        return []
    ext = analysis.get("extractions", {}) or {}
    findings: list[Finding] = []
    for m in analysis.get("file_map", []) or []:
        f = Finding(int(m["offset"]), canonical_format(m.get("name")), str(m.get("name")), int(m.get("size", 0)) or None)
        f.extra = {"description": m.get("description", ""), "confidence": m.get("confidence")}
        e = ext.get(m.get("id"))
        if e is not None:
            f.extracted = bool(e.get("success"))
            f.extra["extractor"] = e.get("extractor")
            od = e.get("output_directory")
            if od:
                root = Path(od)
                f.root = od
                f.files = hash_tree(root)
        findings.append(f)
    findings.sort(key=lambda f: (f.offset, f.format))
    return findings


def parse_moria(doc: dict, outdir: Path) -> list[Finding]:
    """moria -j JSON: findings[] with offset/type/size; extraction.extracted[]
    with depth==1 rows naming each finding's extraction root under -C."""
    roots: dict[int, dict] = {}
    for row in (doc.get("extraction") or {}).get("extracted", []) or []:
        if row.get("depth", 1) == 1:
            roots[int(row["offset"])] = row
    findings: list[Finding] = []
    for m in doc.get("findings", []) or []:
        f = Finding(int(m["offset"]), canonical_format(m.get("type")), str(m.get("type")), int(m.get("size", 0)) or None)
        f.extra = {k: m[k] for k in ("confidence", "confidence_tier", "category", "compression", "endian", "evidence") if k in m}
        row = roots.get(f.offset)
        if row:
            f.extracted = row.get("status") in ("ok", "partial")
            f.extra["extraction_status"] = row.get("status")
            f.root = row.get("root")
            f.files = hash_tree(outdir / str(row.get("root")))
        findings.append(f)
    findings.sort(key=lambda f: (f.offset, f.format))
    return findings


def _load_yaml(path: Path) -> Any:
    try:
        import yaml  # type: ignore
    except ImportError as ex:  # pragma: no cover
        raise RuntimeError("PyYAML is required to read YAML (python3-yaml)") from ex
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _abs_target(r: FileRec) -> str:
    """A symlink's target as an absolute path inside its own filesystem."""
    t = r.target
    if t.startswith("/"):
        return posixpath.normpath(t)
    return posixpath.normpath(posixpath.join(posixpath.dirname("/" + r.relpath), t))


def parse_omnitrace(manifest: Path, outdir: Path) -> list[Finding]:
    """manifest.yaml (schema omnitrace/1): a node graph, `parent` and
    `children` naming ids (docs/CASE_LAYOUT.md).

    Top-level findings are the children of the Image node. A `region` child is
    an unclaimed gap and is reported as `unknown`, which is what unblob calls
    the same thing, so the two line up in the findings table.

    A finding's files are everything extracted *below* it, the way the other
    tools report theirs: its own `filesystems/<id>/files` or
    `containers/<id>/files`, plus the directory of every filesystem or
    container node nested under it, whose paths are prefixed with that
    directory so they stay traceable in the case. Without the nested half a
    `.tar.gz` holding a rootfs would score zero files against unblob, which
    reports the same bytes under a `_extract` prefix inside its top-level
    chunk.

    When nothing was extracted (`--no-extract`), the File nodes' recorded
    digests stand in.
    """
    doc = _load_yaml(manifest) or {}
    nodes = doc.get("nodes", []) or []
    by_id = {n.get("id"): n for n in nodes}
    roots = {n.get("id") for n in nodes if str(n.get("kind", "")).lower() == "image"}
    if nodes and not roots:
        raise ValueError(f"no image node in {manifest}: schema drift, or not an omnitrace manifest")

    def files_dir_of(n: dict) -> Optional[Path]:
        kind = str(n.get("kind", "")).lower()
        sub = {"filesystem": "filesystems", "container": "containers"}.get(kind)
        if not sub:
            return None
        d = outdir / sub / str(n.get("id")) / "files"
        return d if d.is_dir() else None

    def descendants(n: dict) -> list[dict]:
        out, stack = [], list(n.get("children", []) or [])
        while stack:
            c = by_id.get(stack.pop())
            if c is None:
                continue
            out.append(c)
            stack.extend(c.get("children", []) or [])
        return out

    findings: list[Finding] = []
    for n in nodes:
        kind = str(n.get("kind", "")).lower()
        if n.get("parent") not in roots or kind not in ("partition", "container", "filesystem", "region"):
            continue
        loc = n.get("location") or {}
        fmt = n.get("format") or ("unknown" if kind == "region" else "")
        f = Finding(int(loc.get("offset", 0)), canonical_format(fmt), str(fmt),
                    int(loc.get("length", 0)) or None)
        f.extra = {"node": n.get("id"), "confidence": n.get("confidence"), "kind": kind}

        recs: list[FileRec] = []
        own = files_dir_of(n)
        if own is not None:
            f.root = own.relative_to(outdir).as_posix()
            recs += hash_tree(own)
        kids = descendants(n)
        # Carved files count. A find that no reader can open -- a complete ELF
        # sitting inside a decompressed payload -- is written to partitions/
        # with its digests, which is materially what unblob does when it emits
        # `<range>.elf32_extract/carved.elf`. Counting one and not the other
        # measures the harness, not the tools.
        for c in [n] + kids:
            carved = ((c.get("attrs") or {}).get("carved_path") or "")
            if not carved:
                continue
            fp = outdir / carved
            if not fp.is_file():
                continue
            recs.append(FileRec(carved, fp.stat().st_size, sha256_file(fp)))
        for c in kids:
            d = files_dir_of(c)
            if d is None:
                continue
            prefix = d.relative_to(outdir).as_posix()
            for r in hash_tree(d):
                if r.kind == "symlink":
                    # Resolve the target against the entry's place in *its own*
                    # tree before the prefix is applied, and keep it absolute.
                    # `bin/sh -> busybox` means /bin/busybox in that filesystem;
                    # prefixed first it would mean
                    # /filesystems/n7/files/bin/busybox and match nothing.
                    r = dataclasses.replace(r, target=_abs_target(r))
                recs.append(dataclasses.replace(r, relpath=posixpath.join(prefix, r.relpath)))
        if recs:
            f.files = sorted(recs, key=lambda r: r.relpath)
            f.extracted = True
        else:
            # Listing only: the File nodes carry the digests instead.
            for c in kids:
                fm = c.get("file")
                if str(c.get("kind", "")).lower() != "file" or not fm:
                    continue
                if fm.get("deleted") or fm.get("superseded"):
                    continue
                ek = str(fm.get("kind", "regular")).lower()
                if ek == "regular":
                    recs.append(FileRec(str(fm.get("path")), int(fm.get("size", 0)),
                                        str((c.get("digests") or {}).get("sha256", ""))))
                elif ek == "symlink":
                    recs.append(FileRec(str(fm.get("path")), int(fm.get("size", 0)), "",
                                        "symlink", str(fm.get("link_target", ""))))
            if recs:
                f.files = sorted(recs, key=lambda r: r.relpath)
                f.extracted = False
        findings.append(f)
    findings.sort(key=lambda f: (f.offset, f.format))
    return findings


def _expected_files(doc: dict) -> list[FileRec]:
    recs = []
    for e in doc.get("tree", []) or []:
        k = e.get("kind")
        if k == "regular":
            recs.append(FileRec(e["path"], int(e.get("size", 0)), str(e.get("sha256", ""))))
        elif k == "symlink":
            recs.append(FileRec(e["path"], int(e.get("size", 0)), "", "symlink", str(e.get("link_target", ""))))
    return sorted(recs, key=lambda r: r.relpath)


def parse_expected(path: Path) -> list[Finding]:
    """Ground truth from tests/fixtures/out/<name>.expected.yaml as findings:
    one per partition (MBR/GPT), one per volume (UBI) or one at offset 0."""
    doc = _load_yaml(path) or {}
    img = doc.get("image") or {}
    fmt = str(img.get("format", "unknown"))
    findings: list[Finding] = []
    if doc.get("partitions"):
        for p in doc["partitions"]:
            sub = path.with_name(f"{p.get('fixture')}.expected.yaml")
            subdoc = _load_yaml(sub) if sub.exists() else {}
            sfmt = str((subdoc.get("image") or {}).get("format", "unknown")) if subdoc else "unknown"
            f = Finding(int(p["offset"]), canonical_format(sfmt), sfmt, int(p.get("size", 0)), extracted=True)
            f.files = _expected_files(subdoc) if subdoc else []
            f.extra = {"partition": p.get("name"), "fixture": p.get("fixture"), "content_sha256": p.get("content_sha256")}
            findings.append(f)
        findings.insert(0, Finding(0, canonical_format(fmt), fmt, int(img.get("size", 0)), extracted=None, extra={"table": True}))
    else:
        f = Finding(0, canonical_format(fmt), fmt, int(img.get("size", 0)), extracted=True)
        if doc.get("volumes"):
            for v in doc["volumes"]:
                sub = path.with_name(f"{v.get('fixture')}.expected.yaml")
                if sub.exists():
                    f.files += _expected_files(_load_yaml(sub) or {})
            f.extra = {"volumes": [v.get("name") for v in doc["volumes"]]}
        else:
            f.files = _expected_files(doc)
        if doc.get("payload"):
            f.extra = {"payload": doc["payload"].get("format"), "payload_offset": doc["payload"].get("offset")}
        findings.append(f)
    return findings


# --------------------------------------------------------------------------
# Diff
# --------------------------------------------------------------------------


def content_key(r: FileRec) -> str:
    """What "same content" means: the sha256 for a regular file; for a symlink
    the in-tree path it points at, so `etc/TZ -> ../tmp/TZ` (unblob rewrites
    absolute targets to relative ones) equals `etc/TZ -> /tmp/TZ`."""
    if r.kind != "symlink":
        return r.sha256
    t = r.target
    if not t.startswith("/"):
        t = posixpath.join(posixpath.dirname("/" + r.relpath), t)
    return "symlink:" + posixpath.normpath(t)


def diff_files(a: list[FileRec], b: list[FileRec]) -> dict:
    A = {r.relpath: r for r in a}
    B = {r.relpath: r for r in b}
    same, differ = [], []
    for p in sorted(A.keys() & B.keys()):
        (same if content_key(A[p]) == content_key(B[p]) else differ).append(p)
    only_a = sorted(A.keys() - B.keys())
    only_b = sorted(B.keys() - A.keys())
    ha = {r.sha256 for r in a if r.kind == "regular" and r.sha256}
    hb = {r.sha256 for r in b if r.kind == "regular" and r.sha256}
    content_only_a = sorted({r.relpath for r in a if r.kind == "regular" and r.sha256 and r.sha256 not in hb})
    content_only_b = sorted({r.relpath for r in b if r.kind == "regular" and r.sha256 and r.sha256 not in ha})
    return {
        "total_a": len(a), "total_b": len(b),
        "same": len(same), "differ": differ, "only_a": only_a, "only_b": only_b,
        "content_only_a": content_only_a, "content_only_b": content_only_b,
        "hashes_common": len(ha & hb),
    }


# --------------------------------------------------------------------------
# Image-wide recovery
# --------------------------------------------------------------------------


ZERO_FILL_MAX = 64 << 20  # do not hash a zero run larger than this to test it


def zero_fill_hashes(sizes: set[int]) -> dict[str, int]:
    """sha256 of a run of NULs, for each size asked about.

    A tool that finds a file's metadata but cannot reconstruct its data often
    writes the right number of zero bytes -- moria does this for 28 of the 39
    files in the router's JFFS2 overlay. Those are not recovered data, and a
    recall number that counts them makes a tool look worse for *not*
    reproducing another tool's failure. They are reported separately rather
    than dropped, because an image can legitimately hold a zero-filled file
    and it is not this harness's place to decide which.
    """
    out: dict[str, int] = {}
    for n in sorted(sizes):
        if n <= 0 or n > ZERO_FILL_MAX:
            continue
        h = hashlib.sha256()
        left = n
        block = b"\0" * min(n, 1 << 20)
        while left > 0:
            h.update(block[: min(left, len(block))])
            left -= min(left, len(block))
        out[h.hexdigest()] = n
    return out


def recovery_keys(findings: list[Finding]) -> tuple[set[str], set[str]]:
    """Every distinct thing a tool got out of one image, ignoring which finding
    it came from and what it was called.

    The pairwise file diff above only compares files inside findings that
    matched at the same offset *and* format, which is the right unit for "do
    these two tools agree about this structure" and the wrong one for "what
    fraction of the data did each tool recover". A container and its payload
    sit at different offsets by design -- unblob's `lzma` at 0x50040 is
    OmniTrace's `uimage` at 0x50000 -- and a nested extraction shows up under a
    path prefix in one tool and as its own finding in another. Neither is a
    missing file, but both make a per-finding path diff say so.

    So the recovery metric is set-of-contents, image-wide: the sha256 of every
    regular file, plus every symlink as its normalised in-tree target (the same
    `content_key` the file diff uses, so `etc/TZ -> ../tmp/TZ` and
    `etc/TZ -> /tmp/TZ` are one thing). A file recovered under a different path
    counts as recovered, which is the honest reading of "files recovered", and
    a file nobody can produce the bytes of does not count however it is named.

    Returns (all content keys, regular-file sha256 only).
    """
    keys: set[str] = set()
    regular: set[str] = set()
    for f in findings:
        for r in f.files:
            if r.kind == "symlink":
                keys.add(content_key(r))
            elif r.sha256:
                keys.add(r.sha256)
                regular.add(r.sha256)
    return keys, regular


def _sizes_by_hash(findings: list[Finding]) -> dict[str, int]:
    return {r.sha256: r.size for f in findings for r in f.files if r.kind != "symlink" and r.sha256}


def _pct(part: int, whole: int) -> Optional[float]:
    return None if whole == 0 else round(100.0 * part / whole, 2)


def recovery_report(results: dict[str, ToolResult]) -> dict:
    """Per tool, and for every ordered pair, what fraction of one tool's
    contents the other also produced."""
    names = [n for n, r in results.items() if r.status == "ok"]
    sets = {n: recovery_keys(results[n].findings) for n in names}
    per_tool = {
        n: {"content_keys": len(sets[n][0]), "regular_hashes": len(sets[n][1]),
            "files": sum(len(f.files) for f in results[n].findings)}
        for n in names
    }
    sizes = {n: _sizes_by_hash(results[n].findings) for n in names}
    pairs = []
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            ka, kb = sets[a][0], sets[b][0]
            ra, rb = sets[a][1], sets[b][1]
            oa, ob = ka - kb, kb - ka
            za = zero_fill_hashes({sizes[a][k] for k in oa if k in sizes[a]})
            zb = zero_fill_hashes({sizes[b][k] for k in ob if k in sizes[b]})
            pairs.append({
                "a": a, "b": b,
                "common": len(ka & kb), "only_a": len(oa), "only_b": len(ob),
                # Of the contents only one tool has, how many are a run of NULs
                # -- a file whose data that tool could not reconstruct.
                "only_a_zero_fill": sum(1 for k in oa if k in za),
                "only_b_zero_fill": sum(1 for k in ob if k in zb),
                # "b recovered this much of what a did", and the reverse.
                "b_of_a": _pct(len(ka & kb), len(ka)),
                "a_of_b": _pct(len(ka & kb), len(kb)),
                "regular_common": len(ra & rb),
                "only_a_regular": len(ra - rb),
                "only_b_regular": len(rb - ra),
                "regular_b_of_a": _pct(len(ra & rb), len(ra)),
                "regular_a_of_b": _pct(len(ra & rb), len(rb)),
            })
    return {"per_tool": per_tool, "pairs": pairs}


def diff_pair(a: ToolResult, b: ToolResult) -> dict:
    fa: dict[int, list[Finding]] = {}
    fb: dict[int, list[Finding]] = {}
    for f in a.findings:
        fa.setdefault(f.offset, []).append(f)
    for f in b.findings:
        fb.setdefault(f.offset, []).append(f)
    matched, mismatch, only_a, only_b, files = [], [], [], [], {}
    for off in sorted(fa.keys() | fb.keys()):
        la, lb = fa.get(off, []), fb.get(off, [])
        if la and lb:
            pa = {f.format for f in la}
            pb = {f.format for f in lb}
            common = sorted(pa & pb)
            for fmt in common:
                xa = next(f for f in la if f.format == fmt)
                xb = next(f for f in lb if f.format == fmt)
                matched.append({"offset": off, "format": fmt, "raw_a": xa.raw_format, "raw_b": xb.raw_format, "size_a": xa.size, "size_b": xb.size})
                if xa.extracted is not None or xb.extracted is not None:
                    files[str(off)] = {"format": fmt, **diff_files(xa.files, xb.files)}
            if not common:
                mismatch.append({"offset": off, "formats_a": sorted(pa), "formats_b": sorted(pb)})
        elif la:
            only_a += [{"offset": off, "format": f.format, "raw": f.raw_format, "size": f.size} for f in la]
        else:
            only_b += [{"offset": off, "format": f.format, "raw": f.raw_format, "size": f.size} for f in lb]
    tot = {"files_same": 0, "files_differ": 0, "files_only_a": 0, "files_only_b": 0, "content_only_a": 0, "content_only_b": 0}
    for d in files.values():
        tot["files_same"] += d["same"]
        tot["files_differ"] += len(d["differ"])
        tot["files_only_a"] += len(d["only_a"])
        tot["files_only_b"] += len(d["only_b"])
        tot["content_only_a"] += len(d["content_only_a"])
        tot["content_only_b"] += len(d["content_only_b"])
    return {
        "a": a.tool, "b": b.tool,
        "findings": {"matched": matched, "format_mismatch": mismatch, "only_a": only_a, "only_b": only_b,
                     "counts": {"matched": len(matched), "format_mismatch": len(mismatch), "only_a": len(only_a), "only_b": len(only_b)}},
        "files": {"per_finding": files, "totals": tot},
    }


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------


def fmt_cell(f: dict) -> str:
    """One findings-table cell from a findings_union per_tool row."""
    s = f["format"] if f["format"] == f["raw_format"] else f"{f['format']} ({f['raw_format']})"
    if f.get("size"):
        s += f" {f['size']:,}B"
    if f.get("extracted") is True:
        s += f" [{f.get('files', 0)} files]"
    elif f.get("extracted") is False:
        s += " [not extracted]"
    return s


def _list(items: list, cap: int) -> str:
    if not items:
        return "_none_"
    shown = items[:cap]
    s = "\n".join(f"  - `{x}`" for x in shown)
    if len(items) > cap:
        s += f"\n  - ... {len(items) - cap} more (see JSON)"
    return s


def render_markdown(summary: dict, results: dict[str, ToolResult], cap: int) -> str:
    img = summary["image"]
    L = [f"# Parity report: `{img['name']}`", ""]
    L += [f"- size: {img['size']:,} bytes", f"- sha256: `{img['sha256']}`", f"- generated: {summary['generated']}", ""]
    L += ["## Tools", "", "| tool | status | version | seconds | findings | files |", "|---|---|---|---:|---:|---:|"]
    for name, r in results.items():
        nfiles = sum(len(f.files) for f in r.findings)
        L.append(f"| {name} | {r.status}{(' - ' + r.message) if r.message else ''} | {r.version} | {r.seconds:.1f} | {len(r.findings)} | {nfiles} |")
    L += ["", "## Findings by offset", ""]
    tools = list(results.keys())
    L.append("| offset | hex | " + " | ".join(tools) + " |")
    L.append("|---:|---:|" + "|".join("---" for _ in tools) + "|")
    for row in summary["findings_union"]:
        cells = []
        for t in tools:
            fs = row["per_tool"].get(t, [])
            cells.append("<br>".join(fmt_cell(f) for f in fs) or "")
        L.append(f"| {row['offset']} | 0x{row['offset']:x} | " + " | ".join(cells) + " |")
    rec = summary.get("recovery") or {}
    if rec.get("per_tool"):
        L += ["", "## Recovery (image-wide)", "",
              "Distinct file contents each tool produced from this image, regardless of which",
              "finding they came from or what path they were written to: the sha256 of every",
              "regular file plus every symlink's normalised target. This is the unit for \"how",
              "much of the data did it recover\"; the per-finding tables below are the unit for",
              "\"do the tools agree about this structure\".", "",
              "| tool | files | distinct contents | distinct regular files |",
              "|---|---:|---:|---:|"]
        for name, d in rec["per_tool"].items():
            L.append(f"| {name} | {d['files']:,} | {d['content_keys']:,} | {d['regular_hashes']:,} |")
        L += ["", "| pair | common | only in A | only in B | B recovered of A | A recovered of B |",
              "|---|---:|---:|---:|---:|---:|"]
        for d in rec["pairs"]:
            bo = "-" if d["b_of_a"] is None else f"{d['b_of_a']:.1f}%"
            ao = "-" if d["a_of_b"] is None else f"{d['a_of_b']:.1f}%"
            L.append(f"| {d['a']} (A) vs {d['b']} (B) | {d['common']:,} | {d['only_a']:,} | {d['only_b']:,} | {bo} | {ao} |")
    L += ["", "## Pairwise comparison", ""]
    for pair in summary["pairs"]:
        a, b = pair["a"], pair["b"]
        c = pair["findings"]["counts"]
        t = pair["files"]["totals"]
        L += [f"### {a} vs {b}", "",
              f"Findings: {c['matched']} matched, {c['format_mismatch']} same offset but different format, {c['only_a']} only in {a}, {c['only_b']} only in {b}.", "",
              f"Files (over matched findings): {t['files_same']} identical, {t['files_differ']} same path different content, "
              f"{t['files_only_a']} paths only in {a}, {t['files_only_b']} paths only in {b}; "
              f"content only in {a}: {t['content_only_a']}, content only in {b}: {t['content_only_b']}.", ""]
        if pair["findings"]["only_a"]:
            L += [f"- findings only in {a}:", _list([f"{x['offset']} (0x{x['offset']:x}) {x['raw']}" for x in pair["findings"]["only_a"]], cap)]
        if pair["findings"]["only_b"]:
            L += [f"- findings only in {b}:", _list([f"{x['offset']} (0x{x['offset']:x}) {x['raw']}" for x in pair["findings"]["only_b"]], cap)]
        if pair["findings"]["format_mismatch"]:
            L += ["- same offset, different format:", _list([f"{x['offset']}: {a}={x['formats_a']} {b}={x['formats_b']}" for x in pair["findings"]["format_mismatch"]], cap)]
        for off, d in pair["files"]["per_finding"].items():
            L += ["", f"#### {a} vs {b} at offset {off} ({d['format']})", "",
                  f"{a}: {d['total_a']} files, {b}: {d['total_b']} files, identical: {d['same']}, differing content: {len(d['differ'])}, "
                  f"paths only in {a}: {len(d['only_a'])}, paths only in {b}: {len(d['only_b'])}, "
                  f"content only in {a}: {len(d['content_only_a'])}, content only in {b}: {len(d['content_only_b'])}.", ""]
            if d["differ"]:
                L += ["- same path, different content:", _list(d["differ"], cap)]
            if d["only_a"]:
                L += [f"- paths only in {a}:", _list(d["only_a"], cap)]
            if d["only_b"]:
                L += [f"- paths only in {b}:", _list(d["only_b"], cap)]
        L.append("")
    return "\n".join(L) + "\n"


def build_summary(img: Path, results: dict[str, ToolResult], timestamp: str) -> dict:
    union: dict[int, dict[str, list[dict]]] = {}
    for name, r in results.items():
        for f in r.findings:
            union.setdefault(f.offset, {}).setdefault(name, []).append(
                {"offset": f.offset, "format": f.format, "raw_format": f.raw_format, "size": f.size, "extracted": f.extracted, "files": len(f.files)}
            )
    names = [n for n, r in results.items() if r.status == "ok"]
    pairs = [diff_pair(results[a], results[b]) for i, a in enumerate(names) for b in names[i + 1 :]]
    return {
        "schema": SCHEMA,
        "generated": timestamp,
        "image": {"path": str(img), "name": img.name, "size": img.stat().st_size, "sha256": sha256_file(img)},
        "tools": {
            name: {
                "status": r.status, "message": r.message, "version": r.version, "seconds": round(r.seconds, 2),
                "argv": r.argv, "exit_code": r.exit_code, "findings": len(r.findings),
                "files": sum(len(f.files) for f in r.findings),
                "extracted_findings": sum(1 for f in r.findings if f.extracted),
            }
            for name, r in results.items()
        },
        "findings_union": [{"offset": off, "per_tool": per} for off, per in sorted(union.items())],
        "pairs": pairs,
        "recovery": recovery_report(results),
    }


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def find_expected(img: Path, explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        return Path(explicit)
    stem = img.name
    for suffix in (".img", ".bin", ".tar.gz", ".tgz"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    cand = img.with_name(f"{stem}.expected.yaml")
    return cand if cand.exists() else None


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("image", type=Path)
    ap.add_argument("--out", type=Path, help="output directory (default tests/parity/out/<image name>)")
    ap.add_argument("--tools", default=",".join(ALL_TOOLS), help=f"comma list from {','.join(ALL_TOOLS)}")
    ap.add_argument("--expected", help="fixture ground truth YAML to include as the pseudo-tool 'expected' (auto-detected next to the image)")
    ap.add_argument("--no-expected", action="store_true", help="do not auto-detect <image>.expected.yaml")
    ap.add_argument("--unblob-image", default=DEFAULT_UNBLOB_IMAGE)
    ap.add_argument("--moria-image", default=DEFAULT_MORIA_IMAGE)
    ap.add_argument("--no-build", action="store_true", help="never docker-build the moria image; skip moria if missing")
    ap.add_argument("--binwalk", help="binwalk executable (default: from PATH)")
    ap.add_argument("--binwalk-matryoshka", action="store_true", help="pass -M to binwalk (recursive extraction, like the other tools)")
    ap.add_argument("--omnitrace", help="omnitrace CLI executable (default: PATH, then build/*/apps/cli/omnitrace)")
    ap.add_argument("--jobs", type=int, default=max(1, min(8, os.cpu_count() or 1)), help="unblob worker processes")
    ap.add_argument("--timeout", type=int, default=3600, help="seconds per tool")
    ap.add_argument("--reuse", action="store_true", help="do not rerun a tool whose raw output already exists in --out")
    ap.add_argument("--no-docker-user", action="store_true", help="do not pass -u uid:gid to docker run")
    ap.add_argument("--max-list", type=int, default=40, help="max entries per list in the Markdown report")
    ap.add_argument("--timestamp", help="fixed 'generated' value for reproducible reports")
    a = ap.parse_args(argv)

    img = a.image.resolve()
    if not img.is_file():
        print(f"error: {img} is not a file", file=sys.stderr)
        return 2
    tools = [t.strip() for t in a.tools.split(",") if t.strip()]
    bad = [t for t in tools if t not in ALL_TOOLS]
    if bad:
        print(f"error: unknown tool(s) {bad}; choose from {ALL_TOOLS}", file=sys.stderr)
        return 2
    out = (a.out or (HERE / "out" / img.name)).resolve()
    out.mkdir(parents=True, exist_ok=True)
    runner = Runner(img, out, a)

    results: dict[str, ToolResult] = {}
    exp = None if a.no_expected else find_expected(img, a.expected)
    if exp:
        runner.log(f"expected: {exp}")
        results["expected"] = runner.run_expected(exp)
    for t in tools:
        runner.log(f"== {t}")
        r = getattr(runner, f"run_{t}")()
        results[t] = r
        runner.log(f"   {r.status}{(': ' + r.message) if r.message else ''}  findings={len(r.findings)} files={sum(len(f.files) for f in r.findings)} ({r.seconds:.1f}s)")
        (out / f"{t}.normalized.json").write_text(json.dumps(r.normalized(), indent=1, sort_keys=False) + "\n", encoding="utf-8")
    if "expected" in results:
        (out / "expected.normalized.json").write_text(json.dumps(results["expected"].normalized(), indent=1) + "\n", encoding="utf-8")

    ts = a.timestamp or _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
    summary = build_summary(img, results, ts)
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    (out / "report.md").write_text(render_markdown(summary, results, a.max_list), encoding="utf-8")
    runner.log(f"wrote {out / 'report.md'} and {out / 'summary.json'}")
    for p in summary["pairs"]:
        c, t = p["findings"]["counts"], p["files"]["totals"]
        runner.log(f"{p['a']} vs {p['b']}: findings matched={c['matched']} mismatch={c['format_mismatch']} only_a={c['only_a']} only_b={c['only_b']}; "
                   f"files same={t['files_same']} differ={t['files_differ']} only_a={t['files_only_a']} only_b={t['files_only_b']}")
    return 0 if all(r.status != "failed" for r in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
