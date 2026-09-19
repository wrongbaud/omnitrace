// markdown_test.cpp — helpers (escape/table/human_bytes/hex) and snapshot
// renderings of summary.md, partitions.md and listing.md.
#include "omnitrace/output/Markdown.h"

#include <gtest/gtest.h>

#include <string>

#include "fixture.h"

namespace omnitrace::output {
namespace {

TEST(Markdown, EscapePipesAndControlChars) {
    EXPECT_EQ(md_escape("a|b"), "a\\|b");
    EXPECT_EQ(md_escape("line1\nline2"), "line1\\nline2");
    EXPECT_EQ(md_escape("tab\there\r\n"), "tab\\there\\r\\n");
    EXPECT_EQ(md_escape(std::string("nul\0byte", 8)), "nul\\x00byte");
    EXPECT_EQ(md_escape("\x01\x1f\x7f"), "\\x01\\x1f\\x7f");
    EXPECT_EQ(md_escape("back\\slash"), "back\\\\slash");
    EXPECT_EQ(md_escape("plain text, ünïcödé ファイル"), "plain text, ünïcödé ファイル");
    EXPECT_EQ(md_escape(""), "");
}

TEST(Markdown, TableIsUnpaddedAndDeterministic) {
    const std::string t = md_table({"A", "B"}, {{"1", "2"}, {"only"}, {"x", "y", "extra"}});
    EXPECT_EQ(t,
              "| A | B |\n"
              "|---|---|\n"
              "| 1 | 2 |\n"
              "| only |  |\n"
              "| x | y |\n");
    EXPECT_EQ(md_table({"H"}, {}), "| H |\n|---|\n");
}

TEST(Markdown, HumanBytes) {
    EXPECT_EQ(human_bytes(0), "0 B");
    EXPECT_EQ(human_bytes(1023), "1023 B");
    EXPECT_EQ(human_bytes(1024), "1.0 KiB");
    EXPECT_EQ(human_bytes(1536), "1.5 KiB");
    EXPECT_EQ(human_bytes(1024 * 1024 - 1), "1024.0 KiB");
    EXPECT_EQ(human_bytes(1024 * 1024), "1.0 MiB");
    EXPECT_EQ(human_bytes(0x3f0000), "3.9 MiB");
    EXPECT_EQ(human_bytes(16u << 20), "16.0 MiB");
    EXPECT_EQ(human_bytes(3ull << 30), "3.0 GiB");
    EXPECT_EQ(human_bytes((3ull << 30) + (1ull << 29)), "3.5 GiB");
    EXPECT_EQ(human_bytes(1ull << 40), "1.0 TiB");
    EXPECT_EQ(human_bytes(1ull << 50), "1.0 PiB");
    EXPECT_EQ(human_bytes(1ull << 60), "1.0 EiB");
    EXPECT_EQ(human_bytes(~0ull), "16.0 EiB");
}

TEST(Markdown, Hex) {
    EXPECT_EQ(hex(0), "0x0");
    EXPECT_EQ(hex(0xdeadBEEF), "0xdeadbeef");
    EXPECT_EQ(hex(~0ull), "0xffffffffffffffff");
}

TEST(Markdown, SummarySnapshot) {
    const std::string md = summary_markdown(test::full_manifest());
    const std::string want =
        "# OmniTrace summary\n"
        "\n"
        "## Run\n"
        "\n"
        "| Field | Value |\n"
        "|---|---|\n"
        "| tool | omnitrace |\n"
        "| version | 0.1.0 |\n"
        "| git_sha | 0123abcd |\n"
        "| started_at | 2026-01-02T03:04:05Z |\n"
        "| finished_at | 2026-01-02T03:04:09Z |\n"
        "| host_os | linux |\n"
        "| argv | omnitrace analyze --out case dir evidence\\|weird.bin |\n"
        "\n"
        "## Evidence\n"
        "\n"
        "| Id | Path | Size | MD5 | SHA-1 | SHA-256 | Acquired | Note |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| e1 | /cases/router/spi-flash.bin | 16.0 MiB (16777216) | " +
        std::string(32, 'a') + " | " + std::string(40, 'a') + " | " + std::string(64, 'a') +
        " | 2025-12-31T23:59:59Z | SPI dump via flashrom |\n"
        "\n"
        "## Nodes by kind\n"
        "\n"
        "| Kind | Count |\n"
        "|---|---|\n"
        "| image | 1 |\n"
        "| partition | 1 |\n"
        "| container | 1 |\n"
        "| filesystem | 1 |\n"
        "| file | 3 |\n"
        "| region | 1 |\n"
        "| artifact | 1 |\n"
        "| total | 9 |\n"
        "\n"
        "## Map\n"
        "\n"
        "- `n000001` image raw \"spi-flash.bin\" @ 0x0 16.0 MiB (16777216) [verified (99)]\n"
        "  - `n000002` partition mtd \"rootfs\" @ 0x100000 4.0 MiB (4194304) [consistent (85)]\n"
        "    - `n000003` filesystem squashfs \"squashfs\" @ 0x100000 3.9 MiB (4128768) [structural "
        "(60)]\n"
        "  - `n000007` container uimage \"kernel\" @ 0x40000 768.0 KiB (786432) [magic (25)]\n"
        "    - `n000008` region \"trailing\" @ 0xf0000 64.0 KiB (65536) [reject (0)]\n"
        "\n"
        "## Coverage\n"
        "\n"
        "| Format | Status | Detail |\n"
        "|---|---|---|\n"
        "| squashfs | supported |  |\n"
        "| ubifs | tool-missing | no ubireader |\n"
        "\n"
        "## Diagnostics\n"
        "\n"
        "| Severity | Code | Message |\n"
        "|---|---|---|\n"
        "| info | run-note | everything fine |\n";
    EXPECT_EQ(md, want);
    EXPECT_EQ(summary_markdown(test::full_manifest()), md);
}

TEST(Markdown, PartitionsSnapshot) {
    const std::string md = partitions_markdown(test::full_manifest());
    const std::string want =
        "# Partitions\n"
        "\n"
        "| Offset | Size | Kind | Format | Confidence | Name | Warnings |\n"
        "|---|---|---|---|---|---|---|\n"
        "| 0x0 | 16.0 MiB (16777216) | image | raw | verified (99) | `n000001` spi-flash.bin | 0 "
        "|\n"
        "| 0x100000 | 4.0 MiB (4194304) | partition | mtd | consistent (85) |   `n000002` rootfs | "
        "0 |\n"
        "| 0x100000 | 3.9 MiB (4128768) | filesystem | squashfs | structural (60) |     `n000003` "
        "squashfs | 1 |\n"
        "| 0x40000 | 768.0 KiB (786432) | container | uimage | magic (25) |   `n000007` kernel | 0 "
        "|\n"
        "| 0xf0000 | 64.0 KiB (65536) | region | - | reject (0) |     `n000008` trailing | 1 |\n";
    EXPECT_EQ(md, want);
}

TEST(Markdown, PartitionsHandlesEmptyAndOrphansAndCycles) {
    Manifest empty;
    EXPECT_EQ(partitions_markdown(empty),
              "# Partitions\n\n| Offset | Size | Kind | Format | Confidence | Name | Warnings "
              "|\n|---|---|---|---|---|---|---|\n");
    EXPECT_NE(summary_markdown(empty).find("(no structural nodes)"), std::string::npos);

    // Orphan (dangling parent) still shows as a root; unknown length shows as such.
    Manifest orphan;
    Node n;
    n.kind = NodeKind::Partition;
    n.parent_id = "n004242";
    n.name = "lost";
    orphan.add_node(n);
    const std::string md = partitions_markdown(orphan);
    EXPECT_NE(md.find("| 0x0 | unknown | partition | - | reject (0) | `n000001` lost | 1 |"),
              std::string::npos);

    // A cycle made by hand (child links back to an ancestor) terminates.
    Manifest cyc;
    Node a;
    a.kind = NodeKind::Image;
    cyc.add_node(a);
    Node b;
    b.kind = NodeKind::Partition;
    b.parent_id = "n000001";
    cyc.add_node(b);
    cyc.find("n000002")->child_ids.push_back("n000001");
    const std::string cmd = partitions_markdown(cyc);
    EXPECT_EQ(cmd.find("n000001"), cmd.rfind("n000001"));
}

TEST(Markdown, ListingSnapshotWithEscaping) {
    const std::string md = listing_markdown("n000003", test::sample_entries());
    const std::string want =
        "# Listing for `n000003`\n"
        "\n"
        "| Path | Kind | Size | Mode | Owner | Mtime | SHA-256 | Flags | Version |\n"
        "|---|---|---|---|---|---|---|---|---|\n"
        "| etc/config/network.conf | regular | 4096 | 0644 | 1000:100 | 2023-11-14T22:13:20Z | "
        "cccccccccccc | DS | 7 |\n"
        "| weird\\|name\\nwith newline | directory | 0 | 0755 | 0:0 | - | - | - | 0 |\n"
        "| bin/sh -> busybox | symlink | 0 | 0777 | 0:0 | 2023-11-14T22:13:26Z | - | - | 0 |\n";
    EXPECT_EQ(md, want);
    EXPECT_EQ(listing_markdown("n000003", test::sample_entries()), md);
    EXPECT_EQ(listing_markdown("x", {}),
              "# Listing for `x`\n\n| Path | Kind | Size | Mode | Owner | Mtime | SHA-256 | Flags "
              "| Version |\n"
              "|---|---|---|---|---|---|---|---|---|\n");
}

TEST(Markdown, ListingFlagsIndividually) {
    EntryResult d;
    d.meta.path = "gone";
    d.meta.deleted = true;
    d.meta.mtime = -1;  // 1969-12-31T23:59:59Z
    EntryResult s;
    s.meta.path = "old";
    s.meta.superseded = true;
    s.meta.version = 3;
    s.meta.mode = 0104755;  // setuid + type bits: only the low 12 bits show
    const std::string md = listing_markdown("n1", {d, s});
    EXPECT_NE(md.find("| gone | regular | 0 | 0000 | 0:0 | 1969-12-31T23:59:59Z | - | D | 0 |"),
              std::string::npos);
    EXPECT_NE(md.find("| old | regular | 0 | 4755 | 0:0 | - | - | S | 3 |"), std::string::npos);
}

}  // namespace
}  // namespace omnitrace::output
