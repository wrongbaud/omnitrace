#!/usr/bin/env python3
"""Unit tests for the parity harness normalisers and diff (no tools needed).

    python3 -m unittest tests/parity/test_run.py -v
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as harness  # noqa: E402


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def make_tree(root: Path, files: dict[str, bytes], links: dict[str, str] | None = None) -> None:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    for rel, target in (links or {}).items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, p)


class CanonicalFormat(unittest.TestCase):
    def test_aliases(self):
        cases = {
            "squashfs_v4_le": "squashfs", "squashfs_v4_be": "squashfs", "SquashFS": "squashfs", "squashfs_v3_ddwrt": "squashfs",
            "jffs2_new": "jffs2", "jffs2_old": "jffs2", "JFFS2": "jffs2",
            "extfs": "ext", "ext4": "ext", "EXT": "ext", "fat32": "fat", "vfat": "fat",
            "yaffs": "yaffs2", "YAFFSv2": "yaffs2", "uimage": "uimage", "uImage": "uimage",
            "cpio_portable_ascii": "cpio", "lz4_legacy": "lz4", "sevenzip": "7z", "elf64": "elf",
            "trx_v2": "trx", "uboot_env": "uboot_env",
        }
        for raw, want in cases.items():
            self.assertEqual(harness.canonical_format(raw), want, raw)

    def test_fallback_strips_variant_suffixes(self):
        self.assertEqual(harness.canonical_format("frobfs_v2_le"), "frobfs")
        self.assertEqual(harness.canonical_format("thing_built_in"), "thing")
        self.assertEqual(harness.canonical_format(""), "unknown")
        self.assertEqual(harness.canonical_format(None), "unknown")


class HashTree(unittest.TestCase):
    def test_lists_files_and_symlinks_sorted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            make_tree(root, {"b/two.bin": b"22", "a.txt": b"1", "b/c/empty": b""}, {"b/link": "two.bin"})
            recs = harness.hash_tree(root)
            self.assertEqual([r.relpath for r in recs], ["a.txt", "b/c/empty", "b/link", "b/two.bin"])
            self.assertEqual(recs[0].sha256, sha(b"1"))
            self.assertEqual(recs[1].sha256, sha(b""))
            self.assertEqual(recs[2].kind, "symlink")
            self.assertEqual(recs[2].target, "two.bin")
            self.assertEqual(recs[3].size, 2)

    def test_missing_root(self):
        self.assertEqual(harness.hash_tree(Path("/nonexistent/omnitrace-parity")), [])


class ParseUnblob(unittest.TestCase):
    def test_top_level_chunks_and_extraction_roots(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            make_tree(out / "fw.bin_extract" / "100-200.squashfs_v4_le_extract", {"etc/passwd": b"root:x:0:0\n"})
            report = [
                {
                    "task": {"path": "/data/fw.bin", "depth": 0, "blob_id": ""},
                    "reports": [
                        {"__typename__": "StatReport", "size": 300},
                        {"__typename__": "UnknownChunkReport", "start_offset": 0, "end_offset": 100, "size": 100},
                        {"__typename__": "ChunkReport", "id": "1:1", "handler_name": "squashfs_v4_le", "start_offset": 100, "end_offset": 200, "size": 100, "extraction_reports": []},
                        {"__typename__": "ChunkReport", "id": "1:2", "handler_name": "jffs2_new", "start_offset": 200, "end_offset": 300, "size": 100,
                         "extraction_reports": [{"__typename__": "ExtractCommandFailedReport", "severity": "ERROR"}]},
                    ],
                    "subtasks": [{"path": "/out/fw.bin_extract/100-200.squashfs_v4_le_extract", "depth": 1, "blob_id": "1:1"}],
                },
                {"task": {"path": "/out/fw.bin_extract/100-200.squashfs_v4_le_extract", "depth": 1, "blob_id": "1:1"}, "reports": [], "subtasks": []},
            ]
            fs = harness.parse_unblob(report, out, "/out", "/data/fw.bin")
            self.assertEqual([(f.offset, f.format) for f in fs], [(0, "unknown"), (100, "squashfs"), (200, "jffs2")])
            self.assertEqual(fs[1].raw_format, "squashfs_v4_le")
            self.assertTrue(fs[1].extracted)
            self.assertEqual([r.relpath for r in fs[1].files], ["etc/passwd"])
            self.assertEqual(fs[1].files[0].sha256, sha(b"root:x:0:0\n"))
            self.assertFalse(fs[2].extracted)
            self.assertEqual(fs[2].extra["extraction_errors"], ["ExtractCommandFailedReport"])

    def test_ignores_other_tasks(self):
        report = [{"task": {"path": "/data/other.bin", "depth": 0}, "reports": [{"__typename__": "ChunkReport", "id": "x", "handler_name": "tar", "start_offset": 0, "size": 1}], "subtasks": []}]
        self.assertEqual(harness.parse_unblob(report, Path("/tmp"), "/out", "/data/fw.bin"), [])


class ParseBinwalk(unittest.TestCase):
    def test_file_map_and_extractions(self):
        with tempfile.TemporaryDirectory() as d:
            outdir = Path(d) / "fw.bin.extracted" / "0"
            make_tree(outdir, {"kernel.bin": b"\x7fELF"})
            log = [{"Analysis": {
                "file_path": "/x/fw.bin",
                "file_map": [
                    {"offset": 0, "id": "id-1", "size": 64, "name": "uimage", "confidence": 250, "description": "uImage"},
                    {"offset": 4096, "id": "id-2", "size": 0, "name": "SquashFS", "confidence": 250, "description": "SquashFS"},
                ],
                "extractions": {
                    "id-1": {"size": 64, "success": True, "extractor": "uimage_built_in", "output_directory": str(outdir)},
                    "id-2": {"size": 0, "success": False, "extractor": "sasquatch", "output_directory": str(Path(d) / "missing")},
                },
            }}]
            fs = harness.parse_binwalk(log, "fw.bin")
            self.assertEqual([(f.offset, f.format, f.extracted) for f in fs], [(0, "uimage", True), (4096, "squashfs", False)])
            self.assertEqual([r.relpath for r in fs[0].files], ["kernel.bin"])
            self.assertIsNone(fs[1].size)
            self.assertEqual(fs[1].files, [])

    def test_empty(self):
        self.assertEqual(harness.parse_binwalk([], "fw.bin"), [])


class ParseMoria(unittest.TestCase):
    def test_findings_and_depth1_roots(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            make_tree(out / "0x100-squashfs", {"bin/busybox": b"bb"}, {"bin/sh": "busybox"})
            doc = {
                "findings": [
                    {"offset": 0, "size": 16, "type": "uboot", "confidence": 25, "confidence_tier": "magic"},
                    {"offset": 256, "size": 4096, "type": "squashfs", "confidence": 85, "compression": "xz"},
                ],
                "extraction": {"extracted": [
                    {"offset": 256, "type": "squashfs", "root": "0x100-squashfs", "status": "ok", "depth": 1},
                    {"offset": 999, "type": "cpio", "root": "0x100-squashfs/payload.extracted/0x3e7-cpio", "status": "ok", "depth": 2},
                ]},
            }
            fs = harness.parse_moria(doc, out)
            self.assertEqual([(f.offset, f.format, f.extracted) for f in fs], [(0, "uboot", None), (256, "squashfs", True)])
            self.assertEqual([(r.relpath, r.kind) for r in fs[1].files], [("bin/busybox", "regular"), ("bin/sh", "symlink")])
            self.assertEqual(fs[1].extra["compression"], "xz")


class ParseOmnitrace(unittest.TestCase):
    def test_manifest_nodes(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest("PyYAML not installed")
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            make_tree(out / "filesystems" / "n2" / "files", {"etc/passwd": b"root\n"})
            # A filesystem nested under the uImage: its own case directory,
            # which the finding at 60 has to account for the way unblob
            # accounts for a nested extraction inside its top-level chunk.
            make_tree(out / "filesystems" / "n5" / "files", {"bin/sh": b"shell"})
            # Real key names: `parent` and `children` (docs/CASE_LAYOUT.md).
            # This test used to say parent_id/child_ids, matched nothing, and
            # reported 0 findings as a pass.
            manifest = {
                "schema": "omnitrace/1",
                "nodes": [
                    {"id": "n1", "parent": "", "kind": "image", "format": "raw", "location": {"offset": 0, "length": 100}, "children": ["n2", "n3", "n6"]},
                    {"id": "n2", "parent": "n1", "kind": "filesystem", "format": "squashfs", "location": {"offset": 10, "length": 50}, "confidence": 99, "children": []},
                    {"id": "n3", "parent": "n1", "kind": "container", "format": "uimage", "location": {"offset": 60, "length": 40}, "children": ["n4"]},
                    {"id": "n4", "parent": "n3", "kind": "file", "file": {"path": "payload", "kind": "regular", "size": 3}, "digests": {"sha256": sha(b"abc")}, "children": ["n5"]},
                    {"id": "n5", "parent": "n4", "kind": "filesystem", "format": "cramfs", "location": {"offset": 64, "length": 20}, "children": []},
                    {"id": "n6", "parent": "n1", "kind": "region", "format": "", "location": {"offset": 90, "length": 10}},
                ],
            }
            import yaml
            (out / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
            fs = harness.parse_omnitrace(out / "manifest.yaml", out)
            # A region is reported as `unknown`, which is unblob's name for an
            # unclaimed gap, so the two line up in the findings table.
            self.assertEqual([(f.offset, f.format) for f in fs],
                             [(10, "squashfs"), (60, "uimage"), (90, "unknown")])
            self.assertTrue(fs[0].extracted)
            self.assertEqual(fs[0].files[0].relpath, "etc/passwd")
            # The nested filesystem's files belong to the top-level finding,
            # prefixed with where they are in the case.
            self.assertTrue(fs[1].extracted)
            self.assertEqual([r.relpath for r in fs[1].files], ["filesystems/n5/files/bin/sh"])
            self.assertEqual(fs[1].files[0].sha256, sha(b"shell"))

    def test_a_nested_symlink_resolves_in_its_own_tree(self):
        """`bin/sh -> busybox` means /bin/busybox in the filesystem it is in.
        Prefixing the path first made it /filesystems/n5/files/bin/busybox,
        which matches nothing any other tool reports -- every fixture with a
        partition table lost its `bin/sh` that way, and it read as a missing
        file rather than as a harness bug."""
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            nested = out / "filesystems" / "n3" / "files" / "bin"
            nested.mkdir(parents=True)
            (nested / "busybox").write_bytes(b"bb")
            (nested / "sh").symlink_to("busybox")
            manifest = {"schema": "omnitrace/1", "nodes": [
                {"id": "n1", "parent": "", "kind": "image", "format": "raw", "location": {"offset": 0, "length": 10}, "children": ["n2"]},
                {"id": "n2", "parent": "n1", "kind": "partition", "format": "gpt", "location": {"offset": 0, "length": 10}, "children": ["n3"]},
                {"id": "n3", "parent": "n2", "kind": "filesystem", "format": "squashfs", "location": {"offset": 0, "length": 10}, "children": []},
            ]}
            (out / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
            fs = harness.parse_omnitrace(out / "manifest.yaml", out)
            link = next(r for r in fs[0].files if r.relpath.endswith("/sh"))
            self.assertEqual(harness.content_key(link), "symlink:/bin/busybox")
            # and an unprefixed tree agrees, which is the whole point
            plain = harness.FileRec("bin/sh", 7, "", "symlink", "busybox")
            self.assertEqual(harness.content_key(plain), harness.content_key(link))

    def test_listing_only_falls_back_to_recorded_digests(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            manifest = {"schema": "omnitrace/1", "nodes": [
                {"id": "n1", "parent": "", "kind": "image", "format": "raw", "location": {"offset": 0, "length": 100}, "children": ["n2"]},
                {"id": "n2", "parent": "n1", "kind": "filesystem", "format": "squashfs", "location": {"offset": 0, "length": 100}, "children": ["n3", "n4", "n5"]},
                {"id": "n3", "parent": "n2", "kind": "file", "file": {"path": "bin/sh", "kind": "regular", "size": 3}, "digests": {"sha256": sha(b"abc")}},
                {"id": "n4", "parent": "n2", "kind": "file", "file": {"path": "etc/TZ", "kind": "symlink", "size": 7, "link_target": "/tmp/TZ"}},
                {"id": "n5", "parent": "n2", "kind": "file", "file": {"path": "gone", "kind": "regular", "size": 1, "deleted": True}, "digests": {"sha256": sha(b"d")}},
            ]}
            (out / "manifest.yaml").write_text(yaml.safe_dump(manifest), encoding="utf-8")
            fs = harness.parse_omnitrace(out / "manifest.yaml", out)
            self.assertEqual(len(fs), 1)
            self.assertFalse(fs[0].extracted)
            # A deleted entry is history, not something the tool recovered from
            # the live tree, so it is not counted against the other tools.
            self.assertEqual([r.relpath for r in fs[0].files], ["bin/sh", "etc/TZ"])

    def test_a_manifest_it_cannot_read_is_an_error_not_zero_findings(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            # Nodes, but none of them an image: the shape changed under us.
            # Reporting "ok, 0 findings" is how the parent_id drift survived.
            (out / "manifest.yaml").write_text(
                yaml.safe_dump({"schema": "omnitrace/1", "nodes": [{"id": "n1", "kind": "widget"}]}),
                encoding="utf-8")
            with self.assertRaises(ValueError):
                harness.parse_omnitrace(out / "manifest.yaml", out)


class ParseExpected(unittest.TestCase):
    def test_partition_table_pulls_in_member_fixtures(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML not installed")
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            (out / "ext4.expected.yaml").write_text(yaml.safe_dump({"image": {"format": "ext4", "size": 10}, "tree": [
                {"path": "a", "kind": "regular", "size": 1, "sha256": sha(b"a")},
                {"path": "l", "kind": "symlink", "size": 1, "link_target": "a"},
                {"path": "d", "kind": "directory", "size": 0}]}), encoding="utf-8")
            (out / "mbr.expected.yaml").write_text(yaml.safe_dump({"image": {"format": "mbr", "size": 100}, "partitions": [
                {"name": "p1", "fixture": "ext4", "offset": 1048576, "size": 10}]}), encoding="utf-8")
            fs = harness.parse_expected(out / "mbr.expected.yaml")
            self.assertEqual([(f.offset, f.format) for f in fs], [(0, "mbr"), (1048576, "ext")])
            self.assertEqual([(r.relpath, r.kind) for r in fs[1].files], [("a", "regular"), ("l", "symlink")])


class Diff(unittest.TestCase):
    def test_diff_files(self):
        a = [harness.FileRec("same", 1, sha(b"x")), harness.FileRec("moved", 1, sha(b"m")), harness.FileRec("changed", 1, sha(b"1")), harness.FileRec("onlya", 1, sha(b"oa")),
             harness.FileRec("ln", 1, "", "symlink", "t")]
        b = [harness.FileRec("same", 1, sha(b"x")), harness.FileRec("moved2", 1, sha(b"m")), harness.FileRec("changed", 1, sha(b"2")), harness.FileRec("onlyb", 1, sha(b"ob")),
             harness.FileRec("ln", 1, "", "symlink", "other")]
        d = harness.diff_files(a, b)
        self.assertEqual(d["same"], 1)
        self.assertEqual(d["differ"], ["changed", "ln"])
        self.assertEqual(d["only_a"], ["moved", "onlya"])
        self.assertEqual(d["only_b"], ["moved2", "onlyb"])
        self.assertEqual(d["content_only_a"], ["changed", "onlya"])  # "moved" has the same content under another name
        self.assertEqual(d["content_only_b"], ["changed", "onlyb"])

    def test_symlink_targets_compare_by_resolved_path(self):
        k = harness.content_key
        self.assertEqual(k(harness.FileRec("etc/TZ", 0, "", "symlink", "../tmp/TZ")), k(harness.FileRec("etc/TZ", 0, "", "symlink", "/tmp/TZ")))
        self.assertEqual(k(harness.FileRec("usr/bin/free", 0, "", "symlink", "../../bin/busybox")), "symlink:/bin/busybox")
        self.assertNotEqual(k(harness.FileRec("bin/sh", 0, "", "symlink", "busybox")), k(harness.FileRec("bin/sh", 0, "", "symlink", "/sbin/busybox")))

    def test_diff_pair_matches_on_offset_then_format(self):
        A = harness.ToolResult("A", findings=[
            harness.Finding(0, "uimage", "uimage", 10),
            harness.Finding(100, "squashfs", "squashfs_v4_le", 50, True, files=[harness.FileRec("f", 1, sha(b"f"))]),
            harness.Finding(200, "jffs2", "jffs2_new", 50, False),
        ])
        B = harness.ToolResult("B", findings=[
            harness.Finding(100, "squashfs", "squashfs", 50, True, files=[harness.FileRec("f", 1, sha(b"f")), harness.FileRec("g", 1, sha(b"g"))]),
            harness.Finding(200, "cramfs", "cramfs", 50),
            harness.Finding(300, "gzip", "gzip", 5),
        ])
        p = harness.diff_pair(A, B)
        c = p["findings"]["counts"]
        self.assertEqual((c["matched"], c["format_mismatch"], c["only_a"], c["only_b"]), (1, 1, 1, 1))
        self.assertEqual(p["findings"]["only_a"][0]["offset"], 0)
        self.assertEqual(p["findings"]["only_b"][0]["offset"], 300)
        self.assertEqual(p["findings"]["format_mismatch"][0], {"offset": 200, "formats_a": ["jffs2"], "formats_b": ["cramfs"]})
        self.assertEqual(p["files"]["totals"], {"files_same": 1, "files_differ": 0, "files_only_a": 0, "files_only_b": 1, "content_only_a": 0, "content_only_b": 1})

    def test_summary_and_markdown_are_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            img = Path(d) / "x.bin"
            img.write_bytes(b"\0" * 16)
            res = {
                "A": harness.ToolResult("A", findings=[harness.Finding(0, "jffs2", "jffs2_new", 16, True, "r", [harness.FileRec("a", 1, sha(b"a"))])]),
                "B": harness.ToolResult("B", status="skipped", message="not here"),
                "C": harness.ToolResult("C", findings=[harness.Finding(0, "jffs2", "jffs2", 16, True, "r", [])]),
            }
            s1 = harness.build_summary(img, res, "T")
            s2 = harness.build_summary(img, res, "T")
            self.assertEqual(json.dumps(s1), json.dumps(s2))
            self.assertEqual([(p["a"], p["b"]) for p in s1["pairs"]], [("A", "C")])  # skipped tools are not paired
            md = harness.render_markdown(s1, res, 10)
            self.assertIn("| A | ok |", md)
            self.assertIn("skipped - not here", md)
            self.assertIn("jffs2 (jffs2_new) 16B [1 files]", md)
            self.assertIn("paths only in A", md)


class Recovery(unittest.TestCase):
    """The image-wide metric. It exists because the per-finding diff cannot
    answer "what fraction did it recover": the same bytes routinely land at a
    different offset and under a different path in two tools."""

    def test_same_bytes_at_a_different_offset_and_path_still_count(self):
        # A finds one chunk holding two files; B finds two chunks, at other
        # offsets, and writes the same bytes under a nested prefix. Nothing
        # matches per-finding; everything was recovered.
        A = harness.ToolResult("A", findings=[
            harness.Finding(0, "squashfs", "squashfs_v4_le", 50, True, "r",
                            [harness.FileRec("bin/sh", 1, sha(b"sh")), harness.FileRec("etc/x", 1, sha(b"x"))]),
        ])
        B = harness.ToolResult("B", findings=[
            harness.Finding(64, "uimage", "uimage", 50, True, "u",
                            [harness.FileRec("img_extract/bin/sh", 1, sha(b"sh"))]),
            harness.Finding(900, "cpio", "cpio", 10, True, "c",
                            [harness.FileRec("etc/x", 1, sha(b"x"))]),
        ])
        r = harness.recovery_report({"A": A, "B": B})
        d = r["pairs"][0]
        self.assertEqual((d["common"], d["only_a"], d["only_b"]), (2, 0, 0))
        self.assertEqual(d["b_of_a"], 100.0)
        self.assertEqual(d["a_of_b"], 100.0)

    def test_a_missed_file_is_counted_as_missed(self):
        A = harness.ToolResult("A", findings=[harness.Finding(0, "x", "x", 1, True, "r", [
            harness.FileRec("a", 1, sha(b"a")), harness.FileRec("b", 1, sha(b"b")),
            harness.FileRec("c", 1, sha(b"c")), harness.FileRec("d", 1, sha(b"d"))])])
        B = harness.ToolResult("B", findings=[harness.Finding(0, "x", "x", 1, True, "r", [
            harness.FileRec("a", 1, sha(b"a")), harness.FileRec("b", 1, sha(b"b")),
            harness.FileRec("c", 1, sha(b"c"))])])
        d = harness.recovery_report({"A": A, "B": B})["pairs"][0]
        self.assertEqual((d["common"], d["only_a"], d["only_b"]), (3, 1, 0))
        self.assertEqual(d["b_of_a"], 75.0)   # B recovered 3 of A's 4
        self.assertEqual(d["a_of_b"], 100.0)  # A recovered all of B's 3

    def test_symlinks_count_by_normalised_target_not_by_spelling(self):
        A = harness.ToolResult("A", findings=[harness.Finding(0, "x", "x", 1, True, "r", [
            harness.FileRec("etc/TZ", 6, "", "symlink", "/tmp/TZ")])])
        B = harness.ToolResult("B", findings=[harness.Finding(0, "x", "x", 1, True, "r", [
            harness.FileRec("etc/TZ", 9, "", "symlink", "../tmp/TZ")])])
        d = harness.recovery_report({"A": A, "B": B})["pairs"][0]
        self.assertEqual((d["common"], d["only_a"], d["only_b"]), (1, 0, 0))
        # and they are not counted among the regular files
        self.assertEqual(d["regular_common"], 0)
        self.assertIsNone(d["regular_b_of_a"])

    def test_duplicate_content_is_one_recovered_thing(self):
        # The same bytes at five paths is one content. Otherwise a tool that
        # writes a file once scores badly against one that writes it five times.
        A = harness.ToolResult("A", findings=[harness.Finding(0, "x", "x", 1, True, "r",
            [harness.FileRec(f"p{i}", 1, sha(b"same")) for i in range(5)])])
        B = harness.ToolResult("B", findings=[harness.Finding(0, "x", "x", 1, True, "r",
            [harness.FileRec("q", 1, sha(b"same"))])])
        d = harness.recovery_report({"A": A, "B": B})["pairs"][0]
        self.assertEqual((d["common"], d["only_a"], d["only_b"]), (1, 0, 0))
        self.assertEqual(d["b_of_a"], 100.0)

    def test_skipped_tools_and_empty_sets(self):
        A = harness.ToolResult("A", findings=[harness.Finding(0, "x", "x", 1, True, "r", [])])
        B = harness.ToolResult("B", status="skipped")
        r = harness.recovery_report({"A": A, "B": B})
        self.assertEqual(list(r["per_tool"].keys()), ["A"])
        self.assertEqual(r["pairs"], [])
        # A tool that recovered nothing gives no percentage rather than 0% or a
        # division by zero: "nothing to compare" is not "recovered none of it".
        C = harness.ToolResult("C", findings=[harness.Finding(0, "x", "x", 1, True, "r", [])])
        d = harness.recovery_report({"A": A, "C": C})["pairs"][0]
        self.assertIsNone(d["b_of_a"])
        self.assertIsNone(d["a_of_b"])


if __name__ == "__main__":
    unittest.main()
