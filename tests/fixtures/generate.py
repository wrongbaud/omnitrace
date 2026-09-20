#!/usr/bin/env python3
"""OmniTrace synthetic fixture builder.

Produces a small but forensically rich file tree, packs it into every
filesystem / container / partition-table format OmniTrace must read, and writes
a `<name>.expected.yaml` ground-truth file next to every image. Unit tests and
the parity harness (tests/parity) read the YAML, never the images' own metadata.

Determinism
-----------
Same tools + same script => byte-identical images. Every source of entropy is
pinned: file content is derived from SHA-256 chains, timestamps are fixed
(SOURCE_DATE_EPOCH / E2FSPROGS_FAKE_TIME / explicit tool flags), inputs are
sorted, UUIDs / volume ids / image sequence numbers are constants, and the
staging tree is created fresh for every image.

Ownership
---------
The tree wants uid 1000 / gid 100 (and a few root-owned entries). When we run
as root (the Docker path) the staging tree is simply chown'ed. Unprivileged
runs use each tool's own mechanism (mksquashfs pseudo files, mkfs.jffs2 and
mkfs.ubifs device tables, debugfs set_inode_field); the expected YAML always
records what the *image* contains, computed from the mechanism actually used.

Run `generate.py --help`. See docs/TESTING.md for the YAML schema.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import gzip
import lzma
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path
from typing import Callable, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("generate.py needs PyYAML (python3-yaml)")

SCHEMA = "omnitrace-fixture/1"
T0 = 1700000000  # 2023-11-14T22:13:20Z. Even, so FAT's 2-second mtime keeps it.
UID, GID = 1000, 100
ERASE_64K = 0x10000

# --------------------------------------------------------------------------
# Deterministic content
# --------------------------------------------------------------------------


def blob(tag: str, size: int) -> bytes:
    """`size` pseudo-random, incompressible bytes derived from `tag` only."""
    seed = b"omnitrace-fixture:" + tag.encode()
    out = bytearray()
    n = 0
    while len(out) < size:
        out += hashlib.sha256(seed + n.to_bytes(8, "little")).digest()
        n += 1
    return bytes(out[:size])


def text(tag: str, lines: int) -> bytes:
    body = "".join(
        f"{T0 + i * 7}  {tag} line {i:04d}  token={blob(f'{tag}:{i}', 6).hex()}\n"
        for i in range(lines)
    )
    return body.encode()


PASSWD = (
    b"root:x:0:0:root:/root:/bin/sh\n"
    b"daemon:x:1:1:daemon:/usr/sbin:/bin/false\n"
    b"admin:x:1000:100:Admin User,,,:/home/admin:/bin/sh\n"
    b"nobody:x:65534:65534:nobody:/nonexistent:/bin/false\n"
)
INTERFACES = (
    b"auto lo\niface lo inet loopback\n\n"
    b"auto eth0\niface eth0 inet static\n"
    b"    address 192.168.1.1\n    netmask 255.255.255.0\n"
    b"    hwaddress ether 00:11:22:33:44:55\n\n"
    b"auto wlan0\niface wlan0 inet dhcp\n    wpa-ssid omnitrace-lab\n"
)
CONFIG_V1 = b"# device config v1\nhostname=omnitrace-fixture\nchannel=6\nssid=lab-v1\n"
CONFIG_V2 = (
    b"# device config v2\nhostname=omnitrace-fixture\nchannel=11\nssid=lab-v2\n"
    b"admin_pw=changeme\n"
)
CONFIG_V3 = (
    b"# device config v3\nhostname=omnitrace-fixture\nchannel=1\nssid=lab-v3\n"
    b"admin_pw=hunter2\nremote_syslog=10.0.0.5\n"
)
DELETED_TXT = (
    b"this file is unlinked in the *-history / ext4 / fat32 fixtures.\n"
    b"its bytes stay on flash; a forensic reader must surface them.\n"
    + text("deleted", 20)
)
UNICODE_TXT = "ünïcödé content ✓ ファイル\n".encode() * 8


def sparse_content() -> bytes:
    # 4 KiB marker, 192 KiB of zeros, 4 KiB marker: crosses several blocks on
    # every FS, and lets sparse-aware writers/readers show their behaviour.
    return blob("sparse-head", 4096) + b"\0" * (192 * 1024) + blob("sparse-tail", 4096)


# --------------------------------------------------------------------------
# The tree
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Entry:
    path: str
    kind: str  # directory | regular | symlink | hardlink
    mode: int = 0o644
    uid: int = UID
    gid: int = GID
    mtime: int = T0
    content: bytes = b""
    target: str = ""  # symlink target or hard link source path


def base_tree() -> list[Entry]:
    t = T0
    e = [
        Entry("bin", "directory", 0o755, mtime=t + 2),
        Entry("bin/busybox", "regular", 0o755, mtime=t + 4, content=blob("busybox", 300 * 1024)),
        Entry("bin/ash", "hardlink", 0o755, mtime=t + 4, target="bin/busybox"),
        Entry("bin/sh", "symlink", 0o777, mtime=t + 6, target="busybox"),
        Entry("etc", "directory", 0o755, uid=0, gid=0, mtime=t + 8),
        Entry("etc/passwd", "regular", 0o644, uid=0, gid=0, mtime=t + 10, content=PASSWD),
        Entry("etc/secret.key", "regular", 0o600, mtime=t + 12, content=blob("secret", 1024)),
        Entry("etc/network", "directory", 0o755, mtime=t + 14),
        Entry("etc/network/interfaces", "regular", 0o644, mtime=t + 16, content=INTERFACES),
        Entry("data", "directory", 0o755, mtime=t + 18),
        Entry("data/dir with spaces", "directory", 0o755, mtime=t + 20),
        Entry(
            "data/dir with spaces/ünïcödé ファイル.txt",
            "regular",
            0o644,
            mtime=t + 22,
            content=UNICODE_TXT,
        ),
        Entry("data/sparse.bin", "regular", 0o644, mtime=t + 24, content=sparse_content()),
        Entry("empty.txt", "regular", 0o644, mtime=t + 26),
        Entry("history", "directory", 0o755, mtime=t + 28),
        Entry("history/config.txt", "regular", 0o644, mtime=t + 30, content=CONFIG_V1),
        Entry("history/deleted.txt", "regular", 0o644, mtime=t + 32, content=DELETED_TXT),
        Entry("var", "directory", 0o755, uid=0, gid=0, mtime=t + 34),
        Entry("var/log", "directory", 0o755, uid=0, gid=0, mtime=t + 36),
        Entry("var/log/messages", "regular", 0o644, uid=0, gid=0, mtime=t + 38, content=text("syslog", 40)),
    ]
    return e


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def resolve_content(tree: list[Entry], e: Entry) -> bytes:
    if e.kind == "hardlink":
        return next(x for x in tree if x.path == e.target).content
    return e.content


@dataclasses.dataclass
class Features:
    """What the target filesystem can represent. Drives both the staging
    tree (unsupported entries are dropped) and the expected listing."""

    symlink: bool = True
    hardlink: bool = True
    mode: bool = True
    owner: bool = True
    mtime_resolution: int = 1
    owner_method: str = "chown"  # chown | pseudo | devtable | debugfs | none
    empty_file: bool = True
    # Paths the chosen mechanism could not address (unprivileged runs only);
    # they keep the host's uid/gid and the expected YAML says so.
    host_owned: set = dataclasses.field(default_factory=set)


def filtered_tree(tree: list[Entry], f: Features) -> list[Entry]:
    out = []
    for e in tree:
        if e.kind == "symlink" and not f.symlink:
            continue
        if e.kind == "hardlink" and not f.hardlink:
            continue
        if e.kind == "regular" and not e.content and not f.empty_file:
            continue
        out.append(e)
    return out


def effective_owner(e: Entry, f: Features) -> tuple[Optional[int], Optional[int]]:
    """uid/gid the image will actually contain for `e`."""
    if not f.owner:
        return None, None
    if f.owner_method == "chown" or os.geteuid() == 0:
        return e.uid, e.gid
    if e.path in f.host_owned:
        return os.getuid(), os.getgid()
    if f.owner_method in ("pseudo", "debugfs", "devtable"):
        return e.uid, e.gid
    return os.getuid(), os.getgid()


def expected_entries(tree: list[Entry], f: Features) -> list[dict]:
    rows = []
    for e in sorted(tree, key=lambda x: x.path):
        uid, gid = effective_owner(e, f)
        row: dict = {"path": e.path, "kind": "regular" if e.kind == "hardlink" else e.kind}
        if f.mode:
            row["mode"] = f"0{e.mode:o}"
        if f.owner:
            row["uid"], row["gid"] = uid, gid
        if e.kind == "directory":
            row["size"] = 0
        elif e.kind == "symlink":
            row["size"] = len(e.target.encode())
            row["link_target"] = e.target
        else:
            content = resolve_content(tree, e)
            row["size"] = len(content)
            row["sha256"] = sha256(content)
        if e.kind == "hardlink":
            row["hardlink_of"] = e.target
            row["nlink"] = 2
        elif e.kind == "regular" and any(x.kind == "hardlink" and x.target == e.path for x in tree) and f.hardlink:
            row["nlink"] = 2
        row["mtime"] = e.mtime - (e.mtime % f.mtime_resolution)
        rows.append(row)
    return rows


def stage(root: Path, tree: list[Entry]) -> None:
    """Materialise `tree` under `root`, fixed mtimes, chown when root."""
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    dirs: list[Entry] = []
    for e in tree:
        p = root / e.path
        if e.kind == "directory":
            p.mkdir()
            p.chmod(e.mode)
            dirs.append(e)
        elif e.kind == "regular":
            p.write_bytes(e.content)
            p.chmod(e.mode)
        elif e.kind == "symlink":
            p.symlink_to(e.target)
        elif e.kind == "hardlink":
            os.link(root / e.target, p)
    for e in tree:
        if e.kind == "directory":
            continue
        os.utime(root / e.path, (e.mtime, e.mtime), follow_symlinks=False)
    for e in reversed(dirs):  # children first, then parents
        os.utime(root / e.path, (e.mtime, e.mtime))
    os.utime(root, (T0, T0))
    root.chmod(0o755)
    if os.geteuid() == 0:
        for e in tree:
            os.chown(root / e.path, e.uid, e.gid, follow_symlinks=False)
        os.chown(root, 0, 0)


# --------------------------------------------------------------------------
# Tool plumbing
# --------------------------------------------------------------------------


class Ctx:
    def __init__(self, out: Path, work: Path, verbose: bool):
        self.out = out
        self.work = work
        self.verbose = verbose
        self.tools: dict[str, str] = {}
        self.env = dict(os.environ)
        self.env.update(
            {
                "TZ": "UTC",
                "LC_ALL": "C.UTF-8",
                "LANG": "C.UTF-8",
                "E2FSPROGS_FAKE_TIME": str(T0),
                "MTOOLS_SKIP_CHECK": "1",
            }
        )
        # Every tool gets its timestamps as explicit flags; mksquashfs refuses
        # to accept both, so the variable is dropped even if the caller set it.
        self.env.pop("SOURCE_DATE_EPOCH", None)

    def have(self, tool: str) -> bool:
        return shutil.which(tool, path=self.env.get("PATH")) is not None

    def run(self, argv: list[str], cwd: Optional[Path] = None, input_: Optional[bytes] = None, check: bool = True) -> subprocess.CompletedProcess:
        if self.verbose:
            print("  $", " ".join(argv), file=sys.stderr)
        r = subprocess.run(argv, cwd=cwd, env=self.env, input=input_, capture_output=True, check=False)
        if check and r.returncode != 0:
            sys.stderr.write(r.stdout.decode(errors="replace"))
            sys.stderr.write(r.stderr.decode(errors="replace"))
            raise RuntimeError(f"{argv[0]} failed with {r.returncode}")
        return r

    def version(self, tool: str, argv: list[str]) -> str:
        if tool in self.tools:
            return self.tools[tool]
        try:
            r = self.run(argv, check=False)
            line = (r.stdout + r.stderr).decode(errors="replace").strip().splitlines()
            v = line[0].strip() if line else "unknown"
        except FileNotFoundError:
            v = "missing"
        self.tools[tool] = v
        return v


def write_yaml(path: Path, doc: dict) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(f"# Generated by tests/fixtures/generate.py. Do not edit; regenerate.\n")
        yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True, default_flow_style=False, width=120)


def image_doc(name: str, fmt: str, img: Path, tool: str, argv: list[str], features: Features, tree: list[Entry], **extra) -> dict:
    data = img.read_bytes()
    doc = {
        "schema": SCHEMA,
        "name": name,
        "image": {"file": img.name, "format": fmt, "size": len(data), "sha256": sha256(data), "builder": tool, "argv": argv},
        "features": {
            "symlink": features.symlink,
            "hardlink": features.hardlink,
            "mode": features.mode,
            "owner": features.owner,
            "mtime_resolution": features.mtime_resolution,
        },
        "tree": expected_entries(tree, features),
    }
    doc.update(extra)
    return doc


# --------------------------------------------------------------------------
# SquashFS
# --------------------------------------------------------------------------


def pseudo_file(tree: list[Entry], path: Path) -> None:
    lines = []
    for e in tree:
        if e.kind == "hardlink":
            continue  # shares the inode of its target
        lines.append(f'"{e.path}" m {e.mode:o} {e.uid} {e.gid}')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_squashfs(ctx: Ctx, comp: str) -> Optional[dict]:
    name = f"squashfs-{comp}"
    features = Features(owner_method="pseudo")
    tree = filtered_tree(base_tree(), features)
    stg = ctx.work / f"stage-{name}"
    stage(stg, tree)
    pf = ctx.work / f"{name}.pseudo"
    pseudo_file(tree, pf)
    img = ctx.out / f"{name}.img"
    img.unlink(missing_ok=True)
    argv = ["mksquashfs", str(stg), str(img)]
    if comp == "none":
        # Compressor id in the superblock is still gzip; every inode, data,
        # fragment and xattr block is stored uncompressed. Exercises the
        # reader's raw-block path and gives the uImage wrapper a compressible
        # payload (a kernel-like blob), which is what real firmware carries.
        argv += ["-noI", "-noD", "-noF", "-noX"]
    else:
        argv += ["-comp", comp]
    argv += [
        "-b", "131072", "-noappend", "-no-xattrs", "-no-progress", "-quiet",
        "-mkfs-time", str(T0), "-root-time", str(T0), "-root-mode", "755", "-root-uid", "0", "-root-gid", "0",
        "-pf", str(pf),
    ]
    ctx.run(argv)
    attrs = {"compression": comp, "block_size": 131072, "version": "4.0", "endian": "little", "mkfs_time": T0}
    if comp == "none":
        attrs["compressor_id"] = "gzip"
        attrs["note"] = "-noI -noD -noF -noX: superblock names gzip, all blocks stored uncompressed"
    return image_doc(name, "squashfs", img, ctx.version("mksquashfs", ["mksquashfs", "-version"]), argv[1:], features, tree, attrs=attrs)


# --------------------------------------------------------------------------
# JFFS2 (mkfs.jffs2 + hand-assembled history nodes)
# --------------------------------------------------------------------------

JFFS2_MAGIC = 0x1985
JFFS2_NODETYPE_DIRENT = 0xE001
JFFS2_NODETYPE_INODE = 0xE002
JFFS2_NODETYPE_CLEANMARKER = 0x2003
JFFS2_NODETYPE_PADDING = 0x2004
JFFS2_COMPR_NONE = 0x00
DT_REG = 8
JFFS2_INODE_HDR = 68  # sizeof(struct jffs2_raw_inode)
JFFS2_DIRENT_HDR = 40  # sizeof(struct jffs2_raw_dirent)


def jffs2_crc32(data: bytes) -> int:
    """JFFS2's crc32: the standard reflected 0xEDB88320 table, seed 0, no
    final xor (Linux crc32_le(0, ...)). zlib's crc32 pre- and post-inverts, so
    seeding it with ~0 and inverting the result yields the same value."""
    return (zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def _jffs2_crc32_reference(data: bytes) -> int:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    crc = 0
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


assert _jffs2_crc32_reference(b"omnitrace") == jffs2_crc32(b"omnitrace")


@dataclasses.dataclass
class JNode:
    offset: int
    nodetype: int
    totlen: int
    raw: bytes


def jffs2_parse(img: bytes, endian: str) -> list[JNode]:
    """Walk every node. Verifies hdr_crc so a mis-implemented CRC or a wrong
    endianness fails loudly instead of producing a bad fixture."""
    p = "<" if endian == "little" else ">"
    nodes = []
    off = 0
    n = len(img)
    while off + 12 <= n:
        magic, nodetype, totlen, hdr_crc = struct.unpack_from(p + "HHII", img, off)
        if magic == 0xFFFF and nodetype == 0xFFFF:  # erased / padding
            off += 4
            continue
        if magic != JFFS2_MAGIC:
            raise RuntimeError(f"jffs2: bad magic {magic:#x} at {off:#x}")
        if jffs2_crc32(img[off : off + 8]) != hdr_crc:
            raise RuntimeError(f"jffs2: hdr_crc mismatch at {off:#x}")
        if totlen < 12 or off + totlen > n:
            raise RuntimeError(f"jffs2: bad totlen {totlen} at {off:#x}")
        nodes.append(JNode(off, nodetype, totlen, img[off : off + totlen]))
        off += (totlen + 3) & ~3
    return nodes


def jffs2_lookup(nodes: list[JNode], endian: str) -> tuple[dict[tuple[int, str], int], int, dict[int, bytes]]:
    """(pino, name) -> ino for live dirents, highest version seen, ino -> newest raw inode node."""
    p = "<" if endian == "little" else ">"
    dirents: dict[tuple[int, str], tuple[int, int]] = {}
    latest_inode: dict[int, tuple[int, bytes]] = {}
    maxver = 0
    for nd in nodes:
        if nd.nodetype == JFFS2_NODETYPE_DIRENT:
            pino, version, ino, _mctime, nsize, _typ = struct.unpack_from(p + "IIIIBB", nd.raw, 12)
            name = nd.raw[JFFS2_DIRENT_HDR : JFFS2_DIRENT_HDR + nsize].decode()
            key = (pino, name)
            if key not in dirents or dirents[key][0] < version:
                dirents[key] = (version, ino)
            maxver = max(maxver, version)
        elif nd.nodetype == JFFS2_NODETYPE_INODE:
            ino, version = struct.unpack_from(p + "II", nd.raw, 12)
            if ino not in latest_inode or latest_inode[ino][0] < version:
                latest_inode[ino] = (version, nd.raw)
            maxver = max(maxver, version)
    live = {k: v[1] for k, v in dirents.items() if v[1] != 0}
    return live, maxver, {k: v[1] for k, v in latest_inode.items()}


def jffs2_ino_of(live: dict[tuple[int, str], int], path: str) -> int:
    ino = 1  # root
    for part in path.split("/"):
        ino = live[(ino, part)]
    return ino


def jffs2_inode_node(endian: str, ino: int, version: int, mode: int, uid: int, gid: int, when: int, data: bytes) -> bytes:
    """One uncompressed jffs2_raw_inode carrying `data` at file offset 0.

    Layout (all integers in the image's byte order):
      0  u16 magic 0x1985      2  u16 nodetype 0xE002   4  u32 totlen (68 + len(data))
      8  u32 hdr_crc = crc(bytes 0..8)
     12  u32 ino               16  u32 version          20  u32 mode (S_IFREG | perms)
     24  u16 uid               26  u16 gid              28  u32 isize (new file size)
     32  u32 atime             36  u32 mtime            40  u32 ctime
     44  u32 offset (0)        48  u32 csize            52  u32 dsize
     56  u8  compr (0 = none)  57  u8  usercompr        58  u16 flags
     60  u32 data_crc = crc(data)                       64  u32 node_crc = crc(bytes 0..60)
     68  data
    node_crc covers sizeof(jffs2_raw_inode) - 8 = 60 bytes, i.e. everything
    before data_crc (fs/jffs2/scan.c, mkfs.jffs2); data_crc is not part of it.
    A reader that honours versions sees the newest node's bytes; the older
    nodes stay on flash as superseded history.
    """
    p = "<" if endian == "little" else ">"
    totlen = JFFS2_INODE_HDR + len(data)
    head = struct.pack(p + "HHI", JFFS2_MAGIC, JFFS2_NODETYPE_INODE, totlen)
    head += struct.pack(p + "I", jffs2_crc32(head))
    body = struct.pack(
        p + "IIIHHIIIIIIIBBH",
        ino, version, mode, uid, gid, len(data), when, when, when, 0, len(data), len(data),
        JFFS2_COMPR_NONE, JFFS2_COMPR_NONE, 0,
    )
    node_crc = jffs2_crc32(head + body)  # bytes 0..60: data_crc is excluded
    node = head + body + struct.pack(p + "II", jffs2_crc32(data), node_crc)
    assert len(node) == JFFS2_INODE_HDR
    return node + data


def jffs2_dirent_node(endian: str, pino: int, version: int, ino: int, when: int, name: bytes, dtype: int) -> bytes:
    """One jffs2_raw_dirent. `ino == 0` is how JFFS2 records an unlink.

    Layout:
      0  u16 magic   2 u16 nodetype 0xE001   4 u32 totlen (40 + nsize)   8 u32 hdr_crc
     12  u32 pino   16 u32 version   20 u32 ino   24 u32 mctime
     28  u8 nsize   29 u8 type (DT_*)   30 u8[2] unused
     32  u32 node_crc = crc(bytes 0..32)   36 u32 name_crc = crc(name)   40 name
    """
    p = "<" if endian == "little" else ">"
    totlen = JFFS2_DIRENT_HDR + len(name)
    head = struct.pack(p + "HHI", JFFS2_MAGIC, JFFS2_NODETYPE_DIRENT, totlen)
    head += struct.pack(p + "I", jffs2_crc32(head))
    body = struct.pack(p + "IIIIBBBB", pino, version, ino, when, len(name), dtype, 0, 0)
    node = head + body
    node += struct.pack(p + "I", jffs2_crc32(node))
    node += struct.pack(p + "I", jffs2_crc32(name))
    assert len(node) == JFFS2_DIRENT_HDR
    return node + name


def jffs2_cleanmarker(endian: str) -> bytes:
    p = "<" if endian == "little" else ">"
    head = struct.pack(p + "HHI", JFFS2_MAGIC, JFFS2_NODETYPE_CLEANMARKER, 12)
    return head + struct.pack(p + "I", jffs2_crc32(head))


class JAppender:
    """Appends nodes to a mkfs.jffs2 image without crossing erase blocks."""

    def __init__(self, img: bytearray, endian: str, erase: int, cleanmarkers: bool):
        self.buf = img
        self.endian = endian
        self.erase = erase
        self.cleanmarkers = cleanmarkers
        self.log: list[dict] = []
        # mkfs.jffs2 leaves the image at the last node's padded end.
        while len(self.buf) % 4:
            self.buf.append(0xFF)

    def _pad_to(self, n: int) -> None:
        self.buf += b"\xff" * (n - len(self.buf))

    def add(self, node: bytes, what: dict) -> int:
        end_of_block = (len(self.buf) // self.erase + 1) * self.erase
        if len(self.buf) + len(node) > end_of_block:
            self._pad_to(end_of_block)
            if self.cleanmarkers:
                self.buf += jffs2_cleanmarker(self.endian)
        off = len(self.buf)
        self.buf += node
        while len(self.buf) % 4:
            self.buf.append(0xFF)
        self.log.append({**what, "offset": off, "length": len(node)})
        return off

    def finish(self) -> bytes:
        self._pad_to(((len(self.buf) + self.erase - 1) // self.erase) * self.erase)
        return bytes(self.buf)


def devtable(tree: list[Entry], path: Path, features: Features) -> list[str]:
    """mtd-utils device table (mkfs.jffs2 -D / mkfs.ubifs -D). Returns the
    argv fragment to pass, empty when running as root (chown already did the
    job). The parser splits on whitespace and knows only files and dirs, so
    names with spaces and symlinks stay host-owned; hard links share their
    target's inode."""
    if os.geteuid() == 0:
        return []
    lines = ["# name type mode uid gid major minor start inc count"]
    for e in tree:
        if e.kind == "hardlink":
            continue
        if e.kind == "symlink" or any(c.isspace() for c in e.path):
            features.host_owned.add(e.path)
            continue
        t = "d" if e.kind == "directory" else "f"
        lines.append(f"/{e.path} {t} {e.mode:o} {e.uid} {e.gid} - - - - -")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return ["-D", str(path)]


def build_jffs2(ctx: Ctx, endian: str, history: bool) -> Optional[dict]:
    name = "jffs2-history" if history else f"jffs2-{'le' if endian == 'little' else 'be'}"
    features = Features(owner_method="devtable")
    tree = filtered_tree(base_tree(), features)
    stg = ctx.work / f"stage-{name}"
    stage(stg, tree)
    dt = ctx.work / f"{name}.devtable"
    img = ctx.out / f"{name}.img"
    img.unlink(missing_ok=True)
    argv = ["mkfs.jffs2", "-r", str(stg), "-o", str(img), "-e", str(ERASE_64K)] + devtable(tree, dt, features)
    if endian == "big":
        argv.append("--big-endian")
    else:
        argv.append("--little-endian")
    if not history:
        argv.append("--pad")
    ctx.run(argv)
    extra: dict = {"attrs": {"endian": endian, "erase_size": ERASE_64K, "cleanmarkers": True}}
    if history:
        raw = bytearray(img.read_bytes())
        nodes = jffs2_parse(bytes(raw), endian)
        live, maxver, latest = jffs2_lookup(nodes, endian)
        cleanmarkers = bool(nodes) and nodes[0].nodetype == JFFS2_NODETYPE_CLEANMARKER
        app = JAppender(raw, endian, ERASE_64K, cleanmarkers)
        p = "<" if endian == "little" else ">"

        cfg_ino = jffs2_ino_of(live, "history/config.txt")
        hist_ino = jffs2_ino_of(live, "history")
        del_ino = jffs2_ino_of(live, "history/deleted.txt")
        mode, uid, gid = struct.unpack_from(p + "IHH", latest[cfg_ino], 20)
        cfg_v1_version = struct.unpack_from(p + "I", latest[cfg_ino], 16)[0]

        v = maxver
        superseded = [
            {"path": "history/config.txt", "inode": cfg_ino, "version": cfg_v1_version, "size": len(CONFIG_V1), "sha256": sha256(CONFIG_V1), "mtime": T0 + 30},
        ]
        for i, data in enumerate((CONFIG_V2, CONFIG_V3)):
            v += 1
            when = T0 + 100 + 10 * i
            off = app.add(jffs2_inode_node(endian, cfg_ino, v, mode, uid, gid, when, data), {"node": "inode", "ino": cfg_ino, "version": v})
            row = {"path": "history/config.txt", "inode": cfg_ino, "version": v, "size": len(data), "sha256": sha256(data), "mtime": when, "node_offset": off}
            if data is CONFIG_V2:
                superseded.append(row)
            else:
                current = row
        v += 1
        unlink_when = T0 + 130
        off = app.add(jffs2_dirent_node(endian, hist_ino, v, 0, unlink_when, "deleted.txt".encode(), DT_REG), {"node": "dirent-unlink", "pino": hist_ino, "version": v})
        img.write_bytes(app.finish())
        # Re-parse: every appended node must verify, including its CRC.
        jffs2_parse(img.read_bytes(), endian)

        # The live tree now carries config v3 and no deleted.txt.
        for e in tree:
            if e.path == "history/config.txt":
                e.content, e.mtime = CONFIG_V3, current["mtime"]
        tree = [e for e in tree if e.path != "history/deleted.txt"]
        extra["history"] = {
            "superseded": superseded,
            "current": [current],
            "deleted": [
                {"path": "history/deleted.txt", "inode": del_ino, "size": len(DELETED_TXT), "sha256": sha256(DELETED_TXT), "mtime": T0 + 32, "unlink_node_offset": off, "unlink_version": v, "content_recoverable": True},
            ],
            "appended_nodes": app.log,
            "note": (
                "Nodes appended after the mkfs.jffs2 output; versions continue from the highest version mkfs wrote. "
                "config.txt: two uncompressed jffs2_raw_inode nodes (offset 0, full content) with increasing version; "
                "deleted.txt: a jffs2_raw_dirent with ino 0. The original inode nodes of both files remain on flash."
            ),
        }
    return image_doc(name, "jffs2", img, ctx.version("mkfs.jffs2", ["mkfs.jffs2", "--version"]), argv[1:], features, tree, **extra)


# --------------------------------------------------------------------------
# UBIFS + UBI
# --------------------------------------------------------------------------

UBIFS_NODE_MAGIC = 0x06101831
UBIFS_INO_NODE = 0
UBIFS_SB_NODE = 6
UBIFS_UUID = bytes.fromhex("0a0b0c0d0e0f10111213141516171819")


def ubifs_crc32(data: bytes) -> int:
    """UBIFS: crc32_le seeded with ~0 and *no* final inversion."""
    return (zlib.crc32(data, 0) ^ 0xFFFFFFFF) & 0xFFFFFFFF


def ubifs_pin(img: bytearray, leb_size: int) -> dict:
    """Make a mkfs.ubifs image byte-reproducible.

    mkfs.ubifs has no UUID flag and copies atime/ctime from stat(2), which an
    unprivileged build cannot pin (ctime is the wall clock, atime moves when
    the tool reads the file). Rewrite: superblock uuid := constant; every
    inode node's atime/ctime := its mtime, nanoseconds := 0; node CRCs are
    recomputed (crc32 seeded ~0, no final xor, over bytes 8..len).
    """
    magic, _crc, _sq, length, ntype = struct.unpack_from("<IIQIB", img, 0)
    if magic != UBIFS_NODE_MAGIC or ntype != UBIFS_SB_NODE:
        raise RuntimeError("ubifs: superblock node not at LEB 0")
    # struct ubifs_sb_node: ch[24] padding[2] key_hash key_fmt flags[4]
    # min_io_size[4] leb_size[4] leb_cnt[4] max_leb_cnt[4] max_bud_bytes[8]
    # log_lebs[4] lpt_lebs[4] orph_lebs[4] jhead_cnt[4] fanout[4] lsave_cnt[4]
    # fmt_version[4] default_compr[2] padding1[2] rp_uid[4] rp_gid[4]
    # rp_size[8] time_gran[4] uuid[16] -> uuid at 108.
    img[108:124] = UBIFS_UUID
    struct.pack_into("<I", img, 4, ubifs_crc32(bytes(img[8:length])))
    patched = 0
    for leb in range(0, len(img), leb_size):
        off = leb
        end = min(leb + leb_size, len(img))
        while off + 24 <= end:
            magic, _crc, _sq, length, ntype = struct.unpack_from("<IIQIB", img, off)
            if magic != UBIFS_NODE_MAGIC or length < 24 or off + length > end:
                break
            if ntype == UBIFS_INO_NODE:
                # struct ubifs_ino_node: ch[24] key[16] creat_sqnum[8] size[8]
                # atime_sec[8] ctime_sec[8] mtime_sec[8] atime_nsec[4] ctime_nsec[4] mtime_nsec[4]
                mtime = struct.unpack_from("<Q", img, off + 72)[0]
                struct.pack_into("<QQ", img, off + 56, mtime, mtime)
                struct.pack_into("<III", img, off + 80, 0, 0, 0)
                struct.pack_into("<I", img, off + 4, ubifs_crc32(bytes(img[off + 8 : off + length])))
                patched += 1
            off += (length + 7) & ~7
    return {"uuid": UBIFS_UUID.hex(), "inode_nodes_pinned": patched}


UBIFS_DATA_NODE = 1
UBIFS_DENT_NODE = 2
UBIFS_PAD_NODE = 5
UBIFS_MST_NODE = 7
UBIFS_REF_NODE = 8
UBIFS_CS_NODE = 10
UBIFS_KEY_INO, UBIFS_KEY_DATA, UBIFS_KEY_DENT = 0, 1, 2
UBIFS_ITYPE_REG = 0
UBIFS_LOG_LNUM = 3


def ubifs_node(ntype: int, body: bytes, sqnum: int) -> bytes:
    """One node: the 24-byte common header, then `body`.

    Header: magic u32, crc u32, sqnum u64, len u32, node_type u8,
    group_type u8, pad[2]. crc covers bytes 8..len.
    """
    length = 24 + len(body)
    head = struct.pack("<IIQIBBH", UBIFS_NODE_MAGIC, 0, sqnum, length, ntype, 0, 0)
    node = bytearray(head + body)
    struct.pack_into("<I", node, 4, ubifs_crc32(bytes(node[8:])))
    return bytes(node)


def ubifs_key(inum: int, ktype: int, extra: int = 0) -> bytes:
    """The 8-byte simple key, padded to the 16 bytes the nodes reserve."""
    return struct.pack("<II", inum, (ktype << 29) | extra) + bytes(8)


def ubifs_data_node_bytes(inum: int, block: int, payload: bytes, sqnum: int) -> bytes:
    """One data node holding `block` uncompressed (struct ubifs_data_node:
    ch[24] key[16] size[4] compr_type[2] compr_size[2] data[])."""
    body = ubifs_key(inum, UBIFS_KEY_DATA, block)
    body += struct.pack("<IHH", len(payload), 0, 0) + payload
    return ubifs_node(UBIFS_DATA_NODE, body, sqnum)


def ubifs_ino_node_bytes(src: bytes, size: int, when: int, sqnum: int) -> bytes:
    """A new inode node copied from `src` with a new size, times and sqnum, and
    no inline data. Keeps the mode, owner and link count mkfs.ubifs wrote."""
    body = bytearray(src[24:24 + 136])  # struct ubifs_ino_node without data[]
    struct.pack_into("<Q", body, 48 - 24, size)              # size
    struct.pack_into("<QQQ", body, 56 - 24, when, when, when)  # atime, ctime, mtime
    struct.pack_into("<III", body, 80 - 24, 0, 0, 0)         # the nsec fields
    struct.pack_into("<I", body, 112 - 24, 0)                # data_len
    return ubifs_node(UBIFS_INO_NODE, bytes(body), sqnum)


def ubifs_dent_node_bytes(parent: int, name: bytes, child: int, itype: int, sqnum: int,
                          nhash: int) -> bytes:
    """One directory entry (struct ubifs_dent_node: ch[24] key[16] inum[8]
    padding1[1] type[1] nlen[2] cookie[4] name[]). `child == 0` is the record
    UBIFS writes on unlink."""
    body = ubifs_key(parent, UBIFS_KEY_DENT, nhash)
    body += struct.pack("<QBBHI", child, 0, itype, len(name), 0) + name
    return ubifs_node(UBIFS_DENT_NODE, body, sqnum)


def ubifs_ref_node_bytes(lnum: int, offs: int, sqnum: int) -> bytes:
    """A log reference node naming a bud (ch[24] lnum[4] offs[4] jhead[4]
    padding[28]); UBIFS_REF_NODE_SZ is 64."""
    return ubifs_node(UBIFS_REF_NODE, struct.pack("<III", lnum, offs, 0) + bytes(28), sqnum)


def ubifs_sweep(img: bytes, leb_size: int) -> list[dict]:
    """Every node on the medium, found by sweeping for the magic at every
    8-byte boundary and keeping what verifies. The same thing the reader does,
    written independently so the fixture is not checked against itself."""
    out = []
    for lnum in range(len(img) // leb_size):
        base = lnum * leb_size
        for i in range(0, leb_size - 4, 8):
            if struct.unpack_from("<I", img, base + i)[0] != UBIFS_NODE_MAGIC:
                continue
            crc, sqnum, length = struct.unpack_from("<IQI", img, base + i + 4)
            if length < 24 or i + length > leb_size:
                continue
            if ubifs_crc32(img[base + i + 8 : base + i + length]) != crc:
                continue
            out.append({"lnum": lnum, "offs": i, "off": base + i, "len": length,
                        "sqnum": sqnum, "type": img[base + i + 20],
                        "raw": img[base + i : base + i + length]})
    return out


def ubifs_tree(nodes: list[dict]) -> tuple[dict, dict]:
    """(path -> inode, inode -> inode node) from the dent and inode nodes."""
    inodes, dents = {}, {}
    for n in nodes:
        if n["len"] < 32:
            continue  # a pad node is 28 bytes and has no key
        inum, word = struct.unpack_from("<II", n["raw"], 24)
        ktype = word >> 29
        if n["type"] == UBIFS_INO_NODE and n["len"] >= 160 and ktype == UBIFS_KEY_INO:
            inodes[inum] = n
        elif n["type"] == UBIFS_DENT_NODE and n["len"] > 56 and ktype == UBIFS_KEY_DENT:
            child = struct.unpack_from("<Q", n["raw"], 40)[0]
            nlen = struct.unpack_from("<H", n["raw"], 50)[0]
            name = n["raw"][56:56 + nlen].decode("utf-8", "surrogateescape")
            dents.setdefault(inum, []).append((name, child, n["raw"][49], word & ((1 << 29) - 1)))
    paths = {}

    def walk(ino, prefix):
        for name, child, itype, nhash in sorted(dents.get(ino, [])):
            path = f"{prefix}{name}"
            paths[path] = {"inum": child, "type": itype, "parent": ino, "hash": nhash}
            if itype == 1:
                walk(child, path + "/")

    walk(1, "")
    return paths, inodes


def build_ubifs_history(ctx: Ctx) -> Optional[dict]:
    """The base tree, then the journal a running device would have left.

    mkfs.ubifs only ever writes a clean image: everything is in the index and
    the log holds nothing but a commit-start node. The states a forensic
    reader has to recover -- an older version of a file, and a file that was
    deleted -- only exist once something has been written *since* the last
    commit. So this appends a bud: two further versions of history/config.txt
    and an unlink record for history/deleted.txt, with a reference node in the
    log pointing at it, which is byte for byte the state the medium is in
    after those three operations.

    What the reader must then show: config.txt with its third content, no
    deleted.txt, and, with --history, the first two versions of config.txt and
    the deleted file's contents.
    """
    leb, min_io = 129024, 2048
    features = Features(owner_method="devtable")
    tree = filtered_tree(base_tree(), features)
    stg = ctx.work / "stage-ubifs-history"
    stage(stg, tree)
    dt = ctx.work / "ubifs-history.devtable"
    img = ctx.out / "ubifs-history.img"
    img.unlink(missing_ok=True)
    argv = ["mkfs.ubifs", "-r", str(stg), "-m", str(min_io), "-e", str(leb), "-c", "128",
            "-x", "zlib", "-o", str(img)] + devtable(tree, dt, features)
    ctx.run(argv)
    raw = bytearray(img.read_bytes())
    pinned = ubifs_pin(raw, leb)

    nodes = ubifs_sweep(bytes(raw), leb)
    paths, inodes = ubifs_tree(nodes)
    cfg, dele = paths["history/config.txt"], paths["history/deleted.txt"]
    hi = max(n["sqnum"] for n in nodes)

    # A bud has to go in an erase block nothing else uses.
    free = [i for i in range(len(raw) // leb)
            if all(b == 0xFF for b in raw[i * leb:(i + 1) * leb])]
    if not free:
        raise RuntimeError("ubifs-history: no free erase block for a bud")
    bud = free[0]

    appended, at, sq = [], 0, hi
    def put(node: bytes, what: dict) -> int:
        nonlocal at, sq
        off = bud * leb + at
        if at + len(node) > leb:
            raise RuntimeError("ubifs-history: the bud does not fit in one erase block")
        raw[off:off + len(node)] = node
        appended.append({**what, "lnum": bud, "offs": at, "offset": off, "length": len(node)})
        at = (at + len(node) + 7) & ~7
        return off

    src_ino = inodes[cfg["inum"]]["raw"]
    versions = []
    for i, data in enumerate((CONFIG_V2, CONFIG_V3)):
        when = T0 + 100 + 10 * i
        sq += 1
        put(ubifs_data_node_bytes(cfg["inum"], 0, data, sq), {"node": "data", "ino": cfg["inum"]})
        sq += 1
        off = put(ubifs_ino_node_bytes(src_ino, len(data), when, sq),
                  {"node": "inode", "ino": cfg["inum"], "sqnum": sq})
        versions.append({"data": data, "mtime": when, "sqnum": sq, "node_offset": off})
    sq += 1
    unlink_off = put(
        ubifs_dent_node_bytes(dele["parent"], b"deleted.txt", 0, UBIFS_ITYPE_REG, sq,
                              dele["hash"]),
        {"node": "dent-unlink", "parent": dele["parent"], "sqnum": sq})
    unlink_sqnum = sq

    # The log: a reference node right after the commit-start node the master
    # node points at, which is what makes the bud part of this commit.
    mst = min((n for n in nodes if n["type"] == UBIFS_MST_NODE), key=lambda n: n["lnum"])
    log_lnum = struct.unpack_from("<I", mst["raw"], 44)[0]
    cs = [n for n in nodes if n["lnum"] == log_lnum and n["type"] == UBIFS_CS_NODE]
    if not cs or cs[0]["offs"] != 0:
        raise RuntimeError("ubifs-history: no commit-start node at the log head")
    # Walk past the commit-start node and the padding that fills out its
    # minimum-I/O unit, the way UBIFS itself would before writing a reference
    # node: a pad node is 28 bytes plus pad_len zeros, and the whole run is
    # skipped as one.
    off = 0
    while True:
        magic, _c, _sq, length = struct.unpack_from("<IIQI", raw, log_lnum * leb + off)
        if magic != UBIFS_NODE_MAGIC:
            break
        if raw[log_lnum * leb + off + 20] == UBIFS_PAD_NODE:
            pad_len = struct.unpack_from("<I", raw, log_lnum * leb + off + 24)[0]
            off += (length + pad_len + 7) & ~7
        else:
            off += (length + 7) & ~7
    if off % min_io:
        raise RuntimeError(f"ubifs-history: the log head ends at {off}, not a min_io boundary")
    ref_at = log_lnum * leb + off
    sq += 1
    ref = ubifs_ref_node_bytes(bud, 0, sq)
    raw[ref_at:ref_at + len(ref)] = ref
    appended.append({"node": "ref", "lnum": log_lnum, "offs": ref_at - log_lnum * leb,
                     "offset": ref_at, "length": len(ref), "bud_lnum": bud})
    img.write_bytes(bytes(raw))

    # Re-sweep: every appended node must verify on its own terms.
    after = ubifs_sweep(img.read_bytes(), leb)
    if len(after) != len(nodes) + len(appended):
        raise RuntimeError(f"ubifs-history: swept {len(after)} nodes, expected "
                           f"{len(nodes) + len(appended)}")

    # The live tree now carries config v3 and no deleted.txt.
    for e in tree:
        if e.path == "history/config.txt":
            e.content, e.mtime = CONFIG_V3, versions[-1]["mtime"]
    tree = [e for e in tree if e.path != "history/deleted.txt"]

    del_ino_node = inodes[dele["inum"]]["raw"]
    return image_doc(
        "ubifs-history", "ubifs", img, ctx.version("mkfs.ubifs", ["mkfs.ubifs", "-V"]),
        argv[1:], features, tree,
        attrs={"min_io_size": min_io, "leb_size": leb, "max_leb_cnt": 128,
               "compression": "zlib", "bud_lnum": bud, **pinned},
        history={
            "superseded": [
                {"path": "history/config.txt", "inode": cfg["inum"], "version": 1,
                 "size": len(CONFIG_V1), "sha256": sha256(CONFIG_V1), "mtime": T0 + 30},
                {"path": "history/config.txt", "inode": cfg["inum"], "version": 2,
                 "size": len(CONFIG_V2), "sha256": sha256(CONFIG_V2),
                 "mtime": versions[0]["mtime"], "node_offset": versions[0]["node_offset"]},
            ],
            "current": [
                {"path": "history/config.txt", "inode": cfg["inum"], "version": 0,
                 "size": len(CONFIG_V3), "sha256": sha256(CONFIG_V3),
                 "mtime": versions[1]["mtime"], "node_offset": versions[1]["node_offset"]},
            ],
            "deleted": [
                {"path": "history/deleted.txt", "inode": dele["inum"], "version": 1,
                 "size": len(DELETED_TXT), "sha256": sha256(DELETED_TXT),
                 "mtime": struct.unpack_from("<Q", del_ino_node, 72)[0],
                 "unlink_node_offset": unlink_off, "unlink_sqnum": unlink_sqnum,
                 "content_recoverable": True},
            ],
            "appended_nodes": appended,
            "note": (
                "Nodes appended after the mkfs.ubifs output, in erase block %d, with a reference "
                "node in the log so the journal replay reaches them: two (data, inode) pairs for "
                "history/config.txt and a directory entry pointing at inode 0 for "
                "history/deleted.txt, which is how UBIFS records an unlink. sqnum continues from "
                "the highest mkfs wrote. The original nodes of both files stay where they were." % bud
            ),
        },
    )


def build_ubifs(ctx: Ctx) -> Optional[dict]:
    features = Features(owner_method="devtable")
    tree = filtered_tree(base_tree(), features)
    stg = ctx.work / "stage-ubifs"
    stage(stg, tree)
    dt = ctx.work / "ubifs.devtable"
    img = ctx.out / "ubifs.img"
    img.unlink(missing_ok=True)
    argv = ["mkfs.ubifs", "-r", str(stg), "-m", "2048", "-e", "129024", "-c", "128", "-x", "zlib", "-o", str(img)] + devtable(tree, dt, features)
    ctx.run(argv)
    raw = bytearray(img.read_bytes())
    pinned = ubifs_pin(raw, 129024)
    img.write_bytes(raw)
    doc = image_doc("ubifs", "ubifs", img, ctx.version("mkfs.ubifs", ["mkfs.ubifs", "-V"]), argv[1:], features, tree,
                    attrs={"min_io_size": 2048, "leb_size": 129024, "max_leb_cnt": 128, "compression": "zlib", **pinned,
                           "pinned_note": "after mkfs.ubifs: superblock UUID set to a constant, every inode's atime/ctime set to its mtime (nsec 0), node CRCs recomputed"})
    # UBI container around it.
    cfg = ctx.work / "ubinize.cfg"
    cfg.write_text(
        "[rootfs]\nmode=ubi\nimage=%s\nvol_id=0\nvol_size=%d\nvol_type=dynamic\nvol_name=rootfs\nvol_flags=autoresize\n" % (img, 129024 * 100),
        encoding="utf-8",
    )
    ubi = ctx.out / "ubi.img"
    ubi.unlink(missing_ok=True)
    argv2 = ["ubinize", "-o", str(ubi), "-m", "2048", "-p", "131072", "-s", "2048", "-O", "2048", "-Q", "305419896", str(cfg)]
    ctx.run(argv2)
    doc2 = image_doc("ubi", "ubi", ubi, ctx.version("ubinize", ["ubinize", "-V"]), argv2[1:], features, tree,
                     attrs={"peb_size": 131072, "min_io_size": 2048, "vid_hdr_offset": 2048, "image_seq": 305419896},
                     volumes=[{"vol_id": 0, "name": "rootfs", "type": "dynamic", "format": "ubifs", "fixture": "ubifs", "content_sha256": sha256(img.read_bytes())}])
    return {"ubifs": doc, "ubi": doc2}


# --------------------------------------------------------------------------
# YAFFS2
# --------------------------------------------------------------------------


YAFFS_OH_ATIME, YAFFS_OH_MTIME, YAFFS_OH_CTIME = 280, 284, 288  # struct yaffs_obj_hdr


def yaffs2_pin(img: bytearray, page: int, spare: int, tags_off: int) -> int:
    """Set atime/ctime := mtime in every object header so the image does not
    carry the build host's clock. Header chunks are found through the packed
    tags in the spare area (chunk_id 0); mkyaffs2 writes no page-data ECC, so
    the data rewrite needs no fix-up. Returns the number of headers patched."""
    n = 0
    chunk = page + spare
    for off in range(0, len(img) - chunk + 1, chunk):
        _seq, obj_id, chunk_id, _n_bytes = struct.unpack_from("<IIII", img, off + page + tags_off)
        if chunk_id != 0 or obj_id in (0, 0xFFFFFFFF):
            continue
        mtime = img[off + YAFFS_OH_MTIME : off + YAFFS_OH_MTIME + 4]
        img[off + YAFFS_OH_ATIME : off + YAFFS_OH_ATIME + 4] = mtime
        img[off + YAFFS_OH_CTIME : off + YAFFS_OH_CTIME + 4] = mtime
        n += 1
    return n


def build_yaffs2(ctx: Ctx, variant: str) -> Optional[dict]:
    """mkyaffs2 (yaffs2utils) always emits page+spare (OOB) images; the tags
    live in the spare area and there is no inband-tags mode, so a "without OOB"
    variant cannot be produced by this tool. Two spare layouts are made instead."""
    if os.geteuid() != 0:
        print("  yaffs2: mkyaffs2 needs root to preserve ownership; skipping (run through Docker)", file=sys.stderr)
        return None
    name = "yaffs2" if variant == "mtd" else "yaffs2-yaffsecc"
    features = Features(owner_method="chown")
    tree = filtered_tree(base_tree(), features)
    stg = ctx.work / f"stage-{name}"
    stage(stg, tree)
    img = ctx.out / f"{name}.img"
    img.unlink(missing_ok=True)
    argv = ["mkyaffs2", "-p", "2048", "-s", "64"]
    if variant == "yaffs":
        argv.append("--yaffs-ecclayout")
    argv += [str(stg), str(img)]
    ctx.run(argv)
    raw = bytearray(img.read_bytes())
    tags_off = 2 if variant == "mtd" else 0  # first oobfree byte of the layout
    headers = yaffs2_pin(raw, 2048, 64, tags_off)
    if headers < len(tree):
        raise RuntimeError(f"yaffs2: only {headers} object headers found for {len(tree)} entries")
    img.write_bytes(raw)
    return image_doc(name, "yaffs2", img, ctx.version("mkyaffs2", ["mkyaffs2", "-h"]), argv[1:], features, tree,
                     attrs={"page_size": 2048, "spare_size": 64, "oob": True, "spare_layout": "linux-mtd" if variant == "mtd" else "yaffs",
                            "tags_offset_in_spare": tags_off, "endian": "little", "object_headers_pinned": headers,
                            "pinned_note": "after mkyaffs2: every object header's atime/ctime set to its mtime"})


# --------------------------------------------------------------------------
# ext4 via debugfs
# --------------------------------------------------------------------------

EXT4_UUID = "12345678-1234-1234-1234-123456789abc"
EXT4_HASH_SEED = "11111111-2222-3333-4444-555555555555"


def dq(s: str) -> str:
    return '"' + s.replace('"', '\\"') + '"'


def ext4_stat_inode(ctx: Ctx, img: Path, path: str) -> int:
    r = ctx.run(["debugfs", "-R", f"stat {dq(path)}", str(img)])
    for line in r.stdout.decode(errors="replace").splitlines():
        if line.startswith("Inode:"):
            return int(line.split()[1])
    raise RuntimeError(f"debugfs: no inode for {path}")


def build_ext4(ctx: Ctx) -> Optional[dict]:
    features = Features(owner_method="debugfs")
    tree = filtered_tree(base_tree(), features)
    stg = ctx.work / "stage-ext4"
    stage(stg, tree)
    img = ctx.out / "ext4.img"
    img.unlink(missing_ok=True)
    argv = [
        "mkfs.ext4", "-q", "-F", "-b", "4096", "-I", "256", "-L", "omnitrace", "-U", EXT4_UUID,
        "-E", f"hash_seed={EXT4_HASH_SEED},lazy_itable_init=0,lazy_journal_init=0",
        "-O", "^has_journal,^metadata_csum_seed", str(img), "16M",
    ]
    ctx.run(argv)

    ts = lambda e: [f"sif {dq(e.path)} {f} @{e.mtime}" for f in ("mtime", "atime", "ctime", "crtime")]
    script: list[str] = []
    for e in tree:  # tree is in creation order: parents before children
        if e.kind == "directory":
            script.append(f"mkdir {dq(e.path)}")
        elif e.kind == "regular":
            script.append(f"write {dq(str(stg / e.path))} {dq(e.path)}")
        elif e.kind == "symlink":
            script.append(f"symlink {dq(e.path)} {dq(e.target)}")
        elif e.kind == "hardlink":
            script.append(f"ln {dq(e.target)} {dq(e.path)}")
            script.append(f"sif {dq(e.target)} links_count 2")
            continue
        if e.kind != "symlink":
            typebits = 0o040000 if e.kind == "directory" else 0o100000
            script.append(f"sif {dq(e.path)} mode 0{typebits | e.mode:o}")
        script += [f"sif {dq(e.path)} uid {e.uid}", f"sif {dq(e.path)} gid {e.gid}"] + ts(e)
    # Versions 2 and 3 of config.txt are written up front so the three inodes
    # own three distinct block runs; the unlink/kill/link dance below then
    # allocates nothing, leaving every superseded and deleted block intact.
    v2 = ctx.work / "ext4-config-v2"
    v3 = ctx.work / "ext4-config-v3"
    v2.write_bytes(CONFIG_V2)
    v3.write_bytes(CONFIG_V3)
    for tmp, host, when in ((".config.v2", v2, T0 + 100), (".config.v3", v3, T0 + 110)):
        script.append(f"write {dq(str(host))} {dq('history/' + tmp)}")
        script.append(f"sif {dq('history/' + tmp)} mode 0100644")
        script += [f"sif {dq('history/' + tmp)} uid {UID}", f"sif {dq('history/' + tmp)} gid {GID}"]
        script += [f"sif {dq('history/' + tmp)} {f} @{when}" for f in ("mtime", "atime", "ctime", "crtime")]
    for d in reversed([e for e in tree if e.kind == "directory"]):
        script += ts(d)
    script += [f"sif / {f} @{T0}" for f in ("mtime", "atime", "ctime")]
    sc = ctx.work / "ext4-populate.debugfs"
    sc.write_text("\n".join(script) + "\n", encoding="utf-8")
    ctx.run(["debugfs", "-w", "-f", str(sc), str(img)])

    ino_v1 = ext4_stat_inode(ctx, img, "history/config.txt")
    ino_v2 = ext4_stat_inode(ctx, img, "history/.config.v2")
    ino_v3 = ext4_stat_inode(ctx, img, "history/.config.v3")
    ino_del = ext4_stat_inode(ctx, img, "history/deleted.txt")

    hist = [
        # v1 -> v2: drop the name, free v1's inode (dtime set, blocks released, not reused), re-point the name.
        "unlink history/config.txt",
        f"kill_file <{ino_v1}>",
        "link history/.config.v2 history/config.txt",
        "unlink history/.config.v2",
        # v2 -> v3
        "unlink history/config.txt",
        f"kill_file <{ino_v2}>",
        "link history/.config.v3 history/config.txt",
        "unlink history/.config.v3",
        # plain deletion
        "rm history/deleted.txt",
    ]
    hist += [f"sif history {f} @{T0 + 130}" for f in ("mtime", "ctime")]
    sc2 = ctx.work / "ext4-history.debugfs"
    sc2.write_text("\n".join(hist) + "\n", encoding="utf-8")
    ctx.run(["debugfs", "-w", "-f", str(sc2), str(img)])
    assert ext4_stat_inode(ctx, img, "history/config.txt") == ino_v3

    for e in tree:
        if e.path == "history/config.txt":
            e.content, e.mtime = CONFIG_V3, T0 + 110
        if e.path == "history":
            e.mtime = T0 + 130
    tree = [e for e in tree if e.path != "history/deleted.txt"]
    # No journal was ever written, so a reader can only see what the freed
    # inodes and the slack directory entries say: v1's entry was overwritten
    # in place by the later `link` of the same name (its inode is nameless,
    # readers emit it under lost+found/#<inode>), v2 is named only by the
    # unlinked ".config.v2" entry, and ".config.v3" names the live inode.
    # Neither can be tied to "history/config.txt" without a journal, so
    # they are deleted files with content, not superseded versions.
    history = {
        "superseded": [],
        "current": [{"path": "history/config.txt", "inode": ino_v3, "version": 3, "size": len(CONFIG_V3), "sha256": sha256(CONFIG_V3), "mtime": T0 + 110}],
        "deleted": [
            {"path": "history/deleted.txt", "inode": ino_del, "size": len(DELETED_TXT), "sha256": sha256(DELETED_TXT), "mtime": T0 + 32, "dtime": T0, "content_recoverable": True},
            {"path": "history/config.txt", "inode": ino_v1, "size": len(CONFIG_V1), "sha256": sha256(CONFIG_V1), "mtime": T0 + 30, "dtime": T0, "content_recoverable": True,
             "name_recoverable": False, "recovered_as": f"lost+found/#{ino_v1}",
             "state": "config.txt v1: inode freed, dtime set, data blocks released but not reused; its directory entry was overwritten by the later link of the same name"},
            {"path": "history/.config.v2", "inode": ino_v2, "size": len(CONFIG_V2), "sha256": sha256(CONFIG_V2), "mtime": T0 + 100, "dtime": T0, "content_recoverable": True,
             "state": "config.txt v2: inode freed, dtime set, data blocks released but not reused; only the unlinked temporary name survives"},
        ],
        "deleted_names": [
            {"path": "history/.config.v2", "inode": ino_v2, "note": "temporary name, unlinked; inode later freed"},
            {"path": "history/.config.v3", "inode": ino_v3, "note": "temporary name, unlinked; inode is live as history/config.txt"},
        ],
        "note": (
            "Populated with debugfs (no kernel, no journal). Unlinked directory entries stay in the directory block "
            "with their names; freed inodes keep size/blocks/extent tree with dtime set (E2FSPROGS_FAKE_TIME). "
            "Without a journal the older config.txt inodes cannot be tied to that path, so they are listed under "
            "deleted (v1 nameless, v2 under its temporary name) rather than superseded."
        ),
    }
    return image_doc("ext4", "ext4", img, ctx.version("mkfs.ext4", ["mkfs.ext4", "-V"]), argv[1:], features, tree,
                     attrs={"block_size": 4096, "uuid": EXT4_UUID, "label": "omnitrace", "journal": False}, history=history)


# --------------------------------------------------------------------------
# FAT32 via mkfs.vfat + mtools
# --------------------------------------------------------------------------

FAT_VOLID = "12345678"


def build_fat32(ctx: Ctx) -> Optional[dict]:
    features = Features(symlink=False, hardlink=False, mode=False, owner=False, mtime_resolution=2, owner_method="none")
    tree = filtered_tree(base_tree(), features)
    stg = ctx.work / "stage-fat32"
    stage(stg, tree)
    img = ctx.out / "fat32.img"
    img.unlink(missing_ok=True)
    argv = ["mkfs.vfat", "-F", "32", "-S", "512", "-s", "1", "-n", "OMNITRACE", "-i", FAT_VOLID, "--invariant", "-C", str(img), "33792"]
    ctx.run(argv)
    m = ["-i", str(img)]
    for e in sorted((e for e in tree if "/" not in e.path), key=lambda x: x.path):
        rec = ["-s"] if e.kind == "directory" else []
        ctx.run(["mcopy"] + m + rec + ["-m", e.path, f"::/{e.path}"], cwd=stg)
    # history: overwrite config.txt twice (new dirent+clusters each time via
    # delete+copy, which is what mtools does for -o), then delete deleted.txt.
    for data, when in ((CONFIG_V2, T0 + 100), (CONFIG_V3, T0 + 110)):
        h = ctx.work / "fat-config"
        h.write_bytes(data)
        os.utime(h, (when, when))
        ctx.run(["mcopy"] + m + ["-o", "-m", str(h), "::/history/config.txt"])
    ctx.run(["mdel"] + m + ["::/history/deleted.txt"])
    for e in tree:
        if e.path == "history/config.txt":
            e.content, e.mtime = CONFIG_V3, T0 + 110
    tree = [e for e in tree if e.path != "history/deleted.txt"]
    history = {
        "superseded": [
            {"path": "history/config.txt", "version": 1, "size": len(CONFIG_V1), "sha256": sha256(CONFIG_V1), "mtime": T0 + 30, "content_recoverable": False},
            {"path": "history/config.txt", "version": 2, "size": len(CONFIG_V2), "sha256": sha256(CONFIG_V2), "mtime": T0 + 100, "content_recoverable": False},
        ],
        "current": [{"path": "history/config.txt", "version": 3, "size": len(CONFIG_V3), "sha256": sha256(CONFIG_V3), "mtime": T0 + 110}],
        "deleted": [
            {"path": "history/deleted.txt", "size": len(DELETED_TXT), "sha256": sha256(DELETED_TXT), "mtime": T0 + 32, "content_recoverable": True, "dirent_state": "first byte 0xE5, LFN entries remain, start cluster and size intact"},
        ],
        "note": (
            "mtools rewrites a file by deleting the entry and allocating afresh; the old clusters of config.txt may have been "
            "reused, so only the deleted.txt bytes are guaranteed recoverable. Timestamps are local time with TZ=UTC."
        ),
    }
    return image_doc("fat32", "fat32", img, ctx.version("mkfs.vfat", ["mkfs.vfat", "--help"]), argv[1:], features, tree,
                     attrs={"sector_size": 512, "cluster_size": 512, "label": "OMNITRACE", "volume_id": FAT_VOLID, "timezone": "UTC"}, history=history)


# --------------------------------------------------------------------------
# Wrappers: MBR, GPT, tar.gz, uImage
# --------------------------------------------------------------------------

SECTOR = 512
MIB = 1 << 20


def align_up(n: int, a: int) -> int:
    return (n + a - 1) // a * a


def read_fixture(ctx: Ctx, name: str) -> bytes:
    p = ctx.out / f"{name}.img"
    if not p.exists():
        raise RuntimeError(f"{name}.img must be built first")
    return p.read_bytes()


def part_row(name: str, fixture: str, offset: int, data: bytes, **kw) -> dict:
    return {"name": name, "fixture": fixture, "offset": offset, "size": len(data), "content_sha256": sha256(data), **kw}


def build_mbr(ctx: Ctx) -> Optional[dict]:
    parts = [("rootfs_a", "ext4", 0x83), ("rootfs_b", "squashfs-gzip", 0x83)]
    blobs = [read_fixture(ctx, f) for _, f, _ in parts]
    layout, off = [], MIB
    for (name, fixture, ptype), data in zip(parts, blobs):
        layout.append((name, fixture, ptype, off, data))
        off = align_up(off + len(data), MIB)
    total = off
    img = bytearray(total)
    mbr = bytearray(SECTOR)
    mbr[0:8] = b"OMNITRAC"  # harmless boot-code area marker
    struct.pack_into("<I", mbr, 0x1B8, 0x0BADC0DE)  # disk signature
    for i, (name, fixture, ptype, o, data) in enumerate(layout):
        lba, count = o // SECTOR, align_up(len(data), SECTOR) // SECTOR
        e = 0x1BE + 16 * i
        mbr[e] = 0x80 if i == 0 else 0x00
        mbr[e + 1 : e + 4] = b"\xfe\xff\xff"  # CHS start: beyond CHS range
        mbr[e + 4] = ptype
        mbr[e + 5 : e + 8] = b"\xfe\xff\xff"
        struct.pack_into("<II", mbr, e + 8, lba, count)
        img[o : o + len(data)] = data
    mbr[510:512] = b"\x55\xaa"
    img[0:SECTOR] = mbr
    out = ctx.out / "mbr-two-partitions.img"
    out.write_bytes(img)
    return {
        "schema": SCHEMA,
        "name": "mbr-two-partitions",
        "image": {"file": out.name, "format": "mbr", "size": total, "sha256": sha256(bytes(img)), "builder": "generate.py", "argv": []},
        "attrs": {"disk_signature": "0x0badc0de", "sector_size": SECTOR},
        "partitions": [
            part_row(name, fixture, o, data, index=i + 1, type=f"0x{ptype:02x}", lba=o // SECTOR, sectors=align_up(len(data), SECTOR) // SECTOR, bootable=(i == 0))
            for i, (name, fixture, ptype, o, data) in enumerate(layout)
        ],
    }


GPT_DISK_GUID = "6f1a2c3e-0001-4d5e-8f90-0123456789ab"
GPT_LINUX_FS = "0fc63daf-8483-4772-8e79-3d69d8477de4"
GPT_MS_BASIC = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"


def guid_bytes(s: str) -> bytes:
    h = s.replace("-", "")
    d1, d2, d3, rest = int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16), bytes.fromhex(h[16:])
    return struct.pack("<IHH", d1, d2, d3) + rest


def build_gpt(ctx: Ctx) -> Optional[dict]:
    parts = [("boot", "fat32", GPT_MS_BASIC, "6f1a2c3e-1001-4d5e-8f90-0123456789ab"), ("rootfs", "squashfs-xz", GPT_LINUX_FS, "6f1a2c3e-1002-4d5e-8f90-0123456789ab")]
    blobs = [read_fixture(ctx, f) for _, f, _, _ in parts]
    entries_lba, entries_count, entry_size = 2, 128, 128
    entries_bytes = entries_count * entry_size  # 16 KiB = 32 sectors
    first_usable = MIB // SECTOR
    layout, off = [], MIB
    for (name, fixture, tguid, pguid), data in zip(parts, blobs):
        layout.append((name, fixture, tguid, pguid, off, data))
        off = align_up(off + len(data), MIB)
    backup_entries_off = off
    total = backup_entries_off + entries_bytes + SECTOR
    last_usable_lba = backup_entries_off // SECTOR - 1
    last_lba = total // SECTOR - 1
    img = bytearray(total)

    entries = bytearray(entries_bytes)
    for i, (name, fixture, tguid, pguid, o, data) in enumerate(layout):
        e = i * entry_size
        entries[e : e + 16] = guid_bytes(tguid)
        entries[e + 16 : e + 32] = guid_bytes(pguid)
        struct.pack_into("<QQQ", entries, e + 32, o // SECTOR, (o + align_up(len(data), SECTOR)) // SECTOR - 1, 0)
        entries[e + 56 : e + 56 + 72] = name.encode("utf-16-le").ljust(72, b"\0")
        img[o : o + len(data)] = data
    entries_crc = zlib.crc32(bytes(entries)) & 0xFFFFFFFF

    def header(my_lba: int, alt_lba: int, ent_lba: int) -> bytes:
        h = bytearray(92)
        h[0:8] = b"EFI PART"
        struct.pack_into("<IIII", h, 8, 0x00010000, 92, 0, 0)
        struct.pack_into("<QQQQ", h, 24, my_lba, alt_lba, first_usable, last_usable_lba)
        h[56:72] = guid_bytes(GPT_DISK_GUID)
        struct.pack_into("<QIII", h, 72, ent_lba, entries_count, entry_size, entries_crc)
        struct.pack_into("<I", h, 16, zlib.crc32(bytes(h)) & 0xFFFFFFFF)
        return bytes(h).ljust(SECTOR, b"\0")

    # protective MBR
    pm = bytearray(SECTOR)
    pm[0x1BE] = 0x00
    pm[0x1BF : 0x1C2] = b"\x00\x02\x00"
    pm[0x1C2] = 0xEE
    pm[0x1C3 : 0x1C6] = b"\xff\xff\xff"
    struct.pack_into("<II", pm, 0x1C6, 1, min(last_lba, 0xFFFFFFFF))
    pm[510:512] = b"\x55\xaa"
    img[0:SECTOR] = pm
    img[SECTOR : 2 * SECTOR] = header(1, last_lba, entries_lba)
    img[2 * SECTOR : 2 * SECTOR + entries_bytes] = entries
    img[backup_entries_off : backup_entries_off + entries_bytes] = entries
    img[last_lba * SECTOR : (last_lba + 1) * SECTOR] = header(last_lba, 1, backup_entries_off // SECTOR)
    out = ctx.out / "gpt.img"
    out.write_bytes(img)
    return {
        "schema": SCHEMA,
        "name": "gpt",
        "image": {"file": out.name, "format": "gpt", "size": total, "sha256": sha256(bytes(img)), "builder": "generate.py", "argv": []},
        "attrs": {"disk_guid": GPT_DISK_GUID, "sector_size": SECTOR, "entries": entries_count, "entry_size": entry_size, "backup_header_lba": last_lba},
        "partitions": [
            part_row(name, fixture, o, data, index=i + 1, type_guid=tguid, partition_guid=pguid, first_lba=o // SECTOR, last_lba=(o + align_up(len(data), SECTOR)) // SECTOR - 1)
            for i, (name, fixture, tguid, pguid, o, data) in enumerate(layout)
        ],
    }


def build_nested_tar(ctx: Ctx) -> Optional[dict]:
    inner = read_fixture(ctx, "squashfs-gzip")
    readme = b"OmniTrace nested fixture: squashfs-gzip.img inside tar inside gzip\n"
    out = ctx.out / "nested.tar.gz"
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tf:
            for name, data, mode in (("firmware/README.txt", readme, 0o644), ("firmware/squashfs-gzip.img", inner, 0o644)):
                ti = tarfile.TarInfo(name)
                ti.size, ti.mode, ti.uid, ti.gid, ti.mtime = len(data), mode, UID, GID, T0 + 40
                ti.uname, ti.gname = "admin", "users"
                tf.addfile(ti, io.BytesIO(data))
    out.write_bytes(buf.getvalue())
    return {
        "schema": SCHEMA,
        "name": "nested",
        "image": {"file": out.name, "format": "gzip", "size": len(buf.getvalue()), "sha256": sha256(buf.getvalue()), "builder": "python tarfile/gzip", "argv": []},
        "layers": ["gzip", "tar"],
        "tree": [
            {"path": "firmware/README.txt", "kind": "regular", "mode": "0644", "uid": UID, "gid": GID, "size": len(readme), "sha256": sha256(readme), "mtime": T0 + 40},
            {"path": "firmware/squashfs-gzip.img", "kind": "regular", "mode": "0644", "uid": UID, "gid": GID, "size": len(inner), "sha256": sha256(inner), "mtime": T0 + 40, "fixture": "squashfs-gzip"},
        ],
    }


IH_MAGIC = 0x27051956
IH_OS_LINUX, IH_ARCH_ARM, IH_TYPE_FILESYSTEM, IH_COMP_LZMA = 5, 2, 7, 3


def build_uimage(ctx: Ctx) -> Optional[dict]:
    # The payload must be compressible (a kernel is); an already-compressed
    # squashfs would make the LZMA stream larger than its output, which
    # unblob's LZMA handler rejects as invalid.
    inner = read_fixture(ctx, "squashfs-none")
    comp = lzma.compress(inner, format=lzma.FORMAT_ALONE, filters=[{"id": lzma.FILTER_LZMA1, "preset": 6, "dict_size": 1 << 20}])
    # Python writes the .lzma "alone" header with an unknown (-1) size; U-Boot
    # and most extractors want the real uncompressed size there.
    comp = comp[:5] + struct.pack("<Q", len(inner)) + comp[13:]
    name = b"omnitrace rootfs".ljust(32, b"\0")
    hdr = bytearray(struct.pack(">IIIIIIIBBBB", IH_MAGIC, 0, T0, len(comp), 0x80000000, 0x80000000, zlib.crc32(comp) & 0xFFFFFFFF, IH_OS_LINUX, IH_ARCH_ARM, IH_TYPE_FILESYSTEM, IH_COMP_LZMA) + name)
    struct.pack_into(">I", hdr, 4, zlib.crc32(bytes(hdr)) & 0xFFFFFFFF)
    data = bytes(hdr) + comp
    out = ctx.out / "uimage-lzma.img"
    out.write_bytes(data)
    return {
        "schema": SCHEMA,
        "name": "uimage-lzma",
        "image": {"file": out.name, "format": "uimage", "size": len(data), "sha256": sha256(data), "builder": "python lzma", "argv": []},
        "header": {"magic": "0x27051956", "time": T0, "size": len(comp), "load": "0x80000000", "entry": "0x80000000", "os": "linux", "arch": "arm", "type": "filesystem", "compression": "lzma", "name": "omnitrace rootfs", "data_crc": f"0x{zlib.crc32(comp) & 0xFFFFFFFF:08x}"},
        "payload": {"offset": 64, "size": len(comp), "format": "lzma", "sha256": sha256(comp), "decompressed_size": len(inner), "decompressed_sha256": sha256(inner), "fixture": "squashfs-none"},
    }


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

BUILDERS: list[tuple[str, list[str], Callable[[Ctx], Optional[dict]]]] = [
    ("squashfs-gzip", ["mksquashfs"], lambda c: build_squashfs(c, "gzip")),
    ("squashfs-xz", ["mksquashfs"], lambda c: build_squashfs(c, "xz")),
    ("squashfs-lz4", ["mksquashfs"], lambda c: build_squashfs(c, "lz4")),
    ("squashfs-zstd", ["mksquashfs"], lambda c: build_squashfs(c, "zstd")),
    ("squashfs-none", ["mksquashfs"], lambda c: build_squashfs(c, "none")),
    ("jffs2-le", ["mkfs.jffs2"], lambda c: build_jffs2(c, "little", False)),
    ("jffs2-be", ["mkfs.jffs2"], lambda c: build_jffs2(c, "big", False)),
    ("jffs2-history", ["mkfs.jffs2"], lambda c: build_jffs2(c, "little", True)),
    ("ubifs", ["mkfs.ubifs", "ubinize"], build_ubifs),
    ("ubifs-history", ["mkfs.ubifs"], build_ubifs_history),
    ("yaffs2", ["mkyaffs2"], lambda c: build_yaffs2(c, "mtd")),
    ("yaffs2-yaffsecc", ["mkyaffs2"], lambda c: build_yaffs2(c, "yaffs")),
    ("ext4", ["mkfs.ext4", "debugfs"], build_ext4),
    ("fat32", ["mkfs.vfat", "mcopy", "mdel"], build_fat32),
    ("mbr-two-partitions", [], build_mbr),
    ("gpt", [], build_gpt),
    ("nested", [], build_nested_tar),
    ("uimage-lzma", [], build_uimage),
]


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "out")
    ap.add_argument("--only", action="append", default=[], help="build only these fixtures (repeatable)")
    ap.add_argument("--skip-missing", action="store_true", help="skip fixtures whose tools are absent instead of failing")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    a.out = a.out.resolve()

    a.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="omnitrace-fixtures-") as tmp:
        ctx = Ctx(a.out, Path(tmp), a.verbose)
        index: dict = {"schema": SCHEMA, "generator": "tests/fixtures/generate.py", "epoch": T0, "uid": UID, "gid": GID, "fixtures": [], "skipped": [], "tools": {}}
        failed = 0
        for name, tools, fn in BUILDERS:
            if a.only and name not in a.only:
                continue
            missing = [t for t in tools if not ctx.have(t)]
            if missing:
                msg = f"{name}: missing {', '.join(missing)}"
                if a.skip_missing:
                    print(f"skip  {msg}", file=sys.stderr)
                    index["skipped"].append({"name": name, "reason": f"missing tools: {', '.join(missing)}"})
                    continue
                print(f"error {msg}", file=sys.stderr)
                return 2
            print(f"build {name}", file=sys.stderr)
            try:
                doc = fn(ctx)
            except Exception as ex:  # a builder failure is a fixture bug: report and continue
                print(f"FAIL  {name}: {ex}", file=sys.stderr)
                failed += 1
                continue
            if doc is None:
                index["skipped"].append({"name": name, "reason": "builder declined (see log)"})
                continue
            docs = doc if "schema" not in doc else {name: doc}
            for n, d in docs.items():
                d["tools"] = dict(sorted(ctx.tools.items()))
                write_yaml(a.out / f"{n}.expected.yaml", d)
                index["fixtures"].append({"name": n, "image": d["image"]["file"], "format": d["image"]["format"], "size": d["image"]["size"], "sha256": d["image"]["sha256"], "expected": f"{n}.expected.yaml"})
                print(f"  -> {d['image']['file']}  {d['image']['size']} bytes  sha256 {d['image']['sha256'][:16]}...", file=sys.stderr)
        index["tools"] = dict(sorted(ctx.tools.items()))
        write_yaml(a.out / "index.yaml", index)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
