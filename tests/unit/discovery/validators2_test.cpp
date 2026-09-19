// validators2_test.cpp — JFFS2 coalescing plus the fit/dtb, dm-verity, LUKS,
// romfs, cramfs, Android boot, UBIFS and ELF validators: hand-built minimal
// structures (accept), hostile variants (reject or downgrade), and corpus
// slices when the evidence images are present (GTEST_SKIP otherwise).
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <map>

#include "helpers.h"
#include "omnitrace/core/Hash.h"

using namespace omnitrace;
using namespace omnitrace::discovery;
using test::Bytes;

namespace {

std::vector<Finding> scan_one(const Bytes& buf, const char* signature) {
    return scan(test::span_of(buf), test::only({signature}));
}

bool has_diag(const Finding& f, const char* code) {
    for (const Diagnostic& d : f.diagnostics)
        if (d.code == code) return true;
    return false;
}

std::size_t count_format(const std::vector<Finding>& v, const std::string& format) {
    std::size_t n = 0;
    for (const Finding& f : v) n += f.format == format;
    return n;
}

const std::string kCorpus = "/home/wrongbaud/projects/omnitrace-v2/corpus/";

// A Span over [off, off+len) of a corpus image, or nullopt when it is absent.
// The file is mapped whole (lazily); only the slice is ever read.
std::optional<Span> corpus_slice(const std::string& rel, std::uint64_t off, std::uint64_t len,
                                 std::shared_ptr<MappedFile>& keep) {
    const std::string path = kCorpus + rel;
    if (!std::filesystem::exists(path)) return std::nullopt;
    const Status st = MappedFile::open(path, keep);
    if (!st) return std::nullopt;
    return Span::whole(keep).sub(off, len);
}

// ------------------------------------------------------------------- jffs2

void jffs2_node(Bytes& b, std::size_t off, std::uint16_t type, std::uint32_t totlen,
                bool obsolete = false) {
    // The CRC is always computed with the accurate bit set; an obsolete node
    // has it cleared in place afterwards (fs/jffs2/scan.c).
    test::put_u16le(b, off, 0x1985);
    test::put_u16le(b, off + 2, static_cast<std::uint16_t>(type | 0x2000));
    test::put_u32le(b, off + 4, totlen);
    test::put_u32le(b, off + 8, test::crc_jffs2(b, off, 8));
    if (obsolete) test::put_u16le(b, off + 2, static_cast<std::uint16_t>(type & ~0x2000));
}

TEST(Jffs2Coalesce, ObsoleteNodesDirtyGapsAndEraseSize) {
    Bytes b(32768 * 3, 0xFF);
    jffs2_node(b, 0, 0x2003, 12);                         // cleanmarker
    jffs2_node(b, 12, 0xE002, 40);                        // inode -> 52
    jffs2_node(b, 52, 0xE002, 48, true);                  // obsolete inode -> 100
    jffs2_node(b, 100, 0xE001, 30);                       // dirent, padded -> 132
    for (std::size_t i = 200; i < 300; ++i) b[i] = 0x55;  // dirty bytes before the next node
    jffs2_node(b, 300, 0xE002, 20);                       // -> 320
    jffs2_node(b, 32768, 0x2003, 12);                     // block 1: cleanmarker only
    jffs2_node(b, 65536, 0x2003, 12);                     // block 2
    jffs2_node(b, 65548, 0xE002, 16);                     // -> 65564, then erased tail
    const auto f = scan_one(b, "jffs2-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 0u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].size, 65564u);
    EXPECT_EQ(f[0].attrs.at("nodes"), "8");
    EXPECT_EQ(f[0].attrs.at("inode_nodes"), "4");
    EXPECT_EQ(f[0].attrs.at("dirent_nodes"), "1");
    EXPECT_EQ(f[0].attrs.at("cleanmarkers"), "3");
    EXPECT_EQ(f[0].attrs.at("obsolete_nodes"), "1");
    EXPECT_EQ(f[0].attrs.at("dirty_gap_bytes"), "168");  // 132..300
    EXPECT_EQ(f[0].attrs.at("erased_gap_bytes"), std::to_string((32768 - 320) + (65536 - 32780)));
    EXPECT_EQ(f[0].attrs.at("gaps"), "3");
    EXPECT_EQ(f[0].attrs.at("erase_size"), "32768");
    EXPECT_EQ(f[0].attrs.at("erased_blocks"), "1");
    EXPECT_EQ(f[0].attrs.at("aligned_size"), "98304");
    EXPECT_TRUE(has_diag(f[0], "jffs2-dirty-gaps"));
}

TEST(Jffs2Coalesce, GapBeyondMaxGapSplitsUnlessRaised) {
    Bytes b(400 * 1024, 0xFF);
    jffs2_node(b, 0, 0x2003, 12);
    jffs2_node(b, 12, 0xE002, 40);
    jffs2_node(b, 300 * 1024, 0x2003, 12);  // 300 KiB later: past the 128 KiB window
    jffs2_node(b, 300 * 1024 + 12, 0xE002, 40);
    auto f = scan_one(b, "jffs2-le");
    ASSERT_EQ(f.size(), 2u);
    EXPECT_EQ(f[0].size, 52u);
    EXPECT_EQ(f[1].offset, 300u * 1024u);
    EXPECT_TRUE(has_diag(f[0], "jffs2-no-erase-size"));

    SignatureSet raised = test::only({"jffs2-le"});
    raised.signatures[0].extra["max_gap"] = "400000";
    f = scan(test::span_of(b), raised);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].size, 300u * 1024u + 52u);
    EXPECT_EQ(f[0].attrs.at("nodes"), "4");
}

TEST(Jffs2Coalesce, ObsoleteBitWithWrongCrcIsStillRejected) {
    Bytes b(4096, 0xFF);
    jffs2_node(b, 0, 0x2003, 12);
    jffs2_node(b, 12, 0xE002, 40, true);
    b[12 + 9] ^= 0x01;  // neither the stored nor the accurate-bit CRC matches now
    jffs2_node(b, 52, 0xE002, 40);
    const auto f = scan_one(b, "jffs2-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].attrs.at("nodes"), "2");  // cleanmarker + node at 52
    EXPECT_EQ(f[0].attrs.at("dirty_gap_bytes"), "40");
    EXPECT_EQ(f[0].size, 92u);
}

// --------------------------------------------------------------- fdt / fit

// Minimal FDT builder: tokens into a structure block, names into a strings
// block, then a version-17 header in front.
struct FdtBuilder {
    Bytes structure, strings;
    std::map<std::string, std::uint32_t> names;

    std::uint32_t name_off(const std::string& n) {
        const auto it = names.find(n);
        if (it != names.end()) return it->second;
        const auto off = static_cast<std::uint32_t>(strings.size());
        strings.insert(strings.end(), n.begin(), n.end());
        strings.push_back(0);
        names[n] = off;
        return off;
    }
    void u32(std::uint32_t v) {
        const std::size_t o = structure.size();
        structure.resize(o + 4);
        test::put_u32be(structure, o, v);
    }
    void pad() {
        while (structure.size() % 4 != 0) structure.push_back(0);
    }
    void begin(const std::string& name) {
        u32(1);
        structure.insert(structure.end(), name.begin(), name.end());
        structure.push_back(0);
        pad();
    }
    void end() { u32(2); }
    void prop(const std::string& name, const Bytes& data) {
        u32(3);
        u32(static_cast<std::uint32_t>(data.size()));
        u32(name_off(name));
        structure.insert(structure.end(), data.begin(), data.end());
        pad();
    }
    void prop_str(const std::string& name, const std::string& v) {
        Bytes d(v.begin(), v.end());
        d.push_back(0);
        prop(name, d);
    }
    void prop_u32(const std::string& name, std::uint32_t v) {
        Bytes d(4);
        test::put_u32be(d, 0, v);
        prop(name, d);
    }
    // Offset of the next property's data relative to the blob start.
    std::uint64_t next_data_offset() const { return 56 + structure.size() + 12; }
    Bytes finish(std::uint32_t version = 17, std::uint32_t last_comp = 16) {
        u32(9);  // END
        Bytes out(40, 0);
        out.resize(56);  // one empty memory reservation (8-aligned at 40)
        out.insert(out.end(), structure.begin(), structure.end());
        const auto strings_off = static_cast<std::uint32_t>(out.size());
        out.insert(out.end(), strings.begin(), strings.end());
        test::put_u32be(out, 0, 0xd00dfeed);
        test::put_u32be(out, 4, static_cast<std::uint32_t>(out.size()));
        test::put_u32be(out, 8, 56);
        test::put_u32be(out, 12, strings_off);
        test::put_u32be(out, 16, 40);
        test::put_u32be(out, 20, version);
        test::put_u32be(out, 24, last_comp);
        test::put_u32be(out, 28, 0);
        test::put_u32be(out, 32, static_cast<std::uint32_t>(strings.size()));
        test::put_u32be(out, 36, static_cast<std::uint32_t>(structure.size()));
        return out;
    }
};

Bytes payload(std::size_t n, std::uint8_t seed) {
    Bytes p(n);
    for (std::size_t i = 0; i < n; ++i) p[i] = static_cast<std::uint8_t>(seed + i * 7);
    return p;
}

Bytes plain_dtb() {
    FdtBuilder b;
    b.begin("");
    b.prop_str("model", "Test Board");
    Bytes compat{'v', 'e', 'n', 'd', 'o', 'r', ',', 'x', 0, 'g', 'e', 'n', 0};
    b.prop("compatible", compat);
    b.begin("cpus");
    b.begin("cpu@0");
    b.prop_str("device_type", "cpu");
    b.end();
    b.end();
    b.end();
    return b.finish();
}

// FIT with one inline image (crc32 hash) and one external image (sha256).
Bytes fit_image(bool good_hash = true, bool external_present = true) {
    const Bytes kernel = payload(1000, 3);
    const Bytes ext = payload(500, 9);
    FdtBuilder b;
    b.begin("");
    b.prop_str("description", "test fit");
    b.prop_u32("timestamp", 1700000000);
    b.begin("images");
    b.begin("kernel@1");
    b.prop_str("type", "kernel");
    b.prop_str("compression", "gzip");
    b.prop("data", kernel);
    b.begin("hash@1");
    b.prop_str("algo", "crc32");
    b.prop_u32("value", test::crc_zlib(kernel, 0, kernel.size()) ^ (good_hash ? 0u : 1u));
    b.end();
    b.end();
    b.begin("fdt@1");
    b.prop_str("type", "flat_dt");
    b.prop_u32("data-size", static_cast<std::uint32_t>(ext.size()));
    b.prop_u32("data-position", 0);  // patched below once totalsize is known
    b.end();
    b.end();
    b.begin("configurations");
    b.prop_str("default", "conf@1");
    b.begin("conf@1");
    b.prop_str("kernel", "kernel@1");
    b.prop_str("fdt", "fdt@1");
    b.end();
    b.end();
    b.end();
    Bytes out = b.finish();
    const std::uint32_t total = static_cast<std::uint32_t>(out.size());
    const std::uint32_t ext_pos = (total + 3u) & ~3u;
    // Patch data-position: find the property by its (unique) zero u32 after "data-size".
    for (std::size_t i = 56; i + 4 <= out.size(); i += 4) {
        // token PROP, len 4, nameoff of "data-position", then the value
        if (test::Bytes(out.begin() + static_cast<std::ptrdiff_t>(i),
                        out.begin() + static_cast<std::ptrdiff_t>(i + 4)) == Bytes{0, 0, 0, 3} &&
            i + 16 <= out.size() && out[i + 7] == 4) {
            const std::uint32_t nameoff = static_cast<std::uint32_t>(
                (out[i + 8] << 24) | (out[i + 9] << 16) | (out[i + 10] << 8) | out[i + 11]);
            if (nameoff == b.names.at("data-position")) {
                test::put_u32be(out, i + 12, external_present ? ext_pos : 0x7fffff00u);
                break;
            }
        }
    }
    out.resize(ext_pos, 0);
    out.insert(out.end(), ext.begin(), ext.end());
    out.resize(out.size() + 64, 0xAA);  // unrelated trailing bytes
    return out;
}

TEST(DtbValidator, AcceptsPlainTreeAndSetsSize) {
    Bytes b = plain_dtb();
    const std::size_t total = b.size();
    b.resize(total + 100, 0xEE);
    const auto f = scan_one(b, "fit-dtb");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].format, "dtb");
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, total);
    EXPECT_EQ(f[0].attrs.at("model"), "Test Board");
    EXPECT_EQ(f[0].attrs.at("compatible"), "vendor,x,gen");
    EXPECT_EQ(f[0].attrs.at("nodes"), "3");
    EXPECT_EQ(f[0].attrs.at("version"), "17");
    EXPECT_EQ(f[0].endian, Endian::Big);
    EXPECT_TRUE(scan_one(b, "fit").empty()) << "no /images: the fit signature must not fire";
}

TEST(DtbValidator, HostileHeadersAndTrees) {
    Bytes b = plain_dtb();
    const std::size_t total = b.size();
    // Truncated: totalsize past the buffer -> structural with a diagnostic.
    Bytes t(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(total - 20));
    auto f = scan_one(t, "fit-dtb");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "dtb-truncated"));
    // Struct offset outside totalsize: the 4-byte magic is noise.
    Bytes s = b;
    test::put_u32be(s, 8, 0x7fffff00);
    EXPECT_TRUE(scan_one(s, "fit-dtb").empty());
    // Unknown version.
    Bytes v = b;
    test::put_u32be(v, 20, 3);
    EXPECT_TRUE(scan_one(v, "fit-dtb").empty());
    // Unbalanced structure: END where the root's END_NODE was due (the
    // structure block ends 4 bytes before the strings block).
    Bytes u = b;
    const std::size_t strings_off = (static_cast<std::size_t>(b[12]) << 24) |
                                    (static_cast<std::size_t>(b[13]) << 16) |
                                    (static_cast<std::size_t>(b[14]) << 8) | b[15];
    test::put_u32be(u, strings_off - 8, 9);
    f = scan_one(u, "fit-dtb");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "fdt-unbalanced"));
    // Property name offset outside the strings block.
    Bytes p = b;
    test::put_u32be(p, 56 + 8 + 8, 0xFFFF);  // nameoff of "model" (root token is 8 bytes)
    f = scan_one(p, "fit-dtb");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "fdt-bad-prop-name"));
    // Node limit from the signature.
    SignatureSet lim = test::only({"fit-dtb"});
    lim.signatures[0].extra["max_nodes"] = "2";
    f = scan(test::span_of(b), lim);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "fdt-limit-nodes"));
}

TEST(FitValidator, InlineAndExternalImagesVerified) {
    const Bytes b = fit_image();
    const auto f = scan_one(b, "fit");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].format, "fit");
    EXPECT_EQ(f[0].category, "container");
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].size, b.size() - 64);  // through the external image, not the trailer
    EXPECT_EQ(f[0].attrs.at("description"), "test fit");
    EXPECT_EQ(f[0].attrs.at("timestamp"), "1700000000");
    EXPECT_EQ(f[0].attrs.at("image_count"), "2");
    EXPECT_EQ(f[0].attrs.at("hash_ok"), "1");
    EXPECT_EQ(f[0].attrs.at("hash_failed"), "0");
    EXPECT_EQ(f[0].attrs.at("images_without_hash"), "1");
    EXPECT_EQ(f[0].attrs.at("default_configuration"), "conf@1");
    EXPECT_EQ(f[0].attrs.at("configurations"), "conf@1:kernel=kernel@1,fdt=fdt@1");
    const std::string images = f[0].attrs.at("images");
    EXPECT_EQ(images.rfind("kernel@1:", 0), 0u) << images;
    EXPECT_NE(images.find(":1000:kernel:gzip;fdt@1:"), std::string::npos) << images;
    EXPECT_NE(images.find(":500:flat_dt:"), std::string::npos) << images;
}

TEST(FitValidator, HostileVariants) {
    // Hash mismatch: consistent, not verified.
    auto f = scan_one(fit_image(false), "fit");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_TRUE(has_diag(f[0], "fit-hash-mismatch"));
    // External data outside the span: structural, payload missing.
    f = scan_one(fit_image(true, false), "fit");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "fit-data-missing"));
    EXPECT_NE(f[0].attrs.at("images").find("fdt@1:missing:"), std::string::npos);
    // Tree cut short: the fit validator cannot classify it and stays silent;
    // the dtb validator still reports the header.
    Bytes cut = fit_image();
    cut.resize(200);
    EXPECT_TRUE(scan_one(cut, "fit").empty());
    f = scan_one(cut, "fit-dtb");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "dtb-truncated"));
    // Bad strings offset: rejected by both.
    Bytes bad = fit_image();
    test::put_u32be(bad, 12, 0x7fffff00);
    EXPECT_TRUE(scan_one(bad, "fit").empty());
    EXPECT_TRUE(scan_one(bad, "fit-dtb").empty());
}

TEST(FitValidator, WinsOverDtbAtSameOffsetAndAbsorbsInnerDtb) {
    // A FIT whose kernel image is itself a DTB: two dtb hits inside the FIT.
    const Bytes inner = plain_dtb();
    FdtBuilder b;
    b.begin("");
    b.begin("images");
    b.begin("fdt@1");
    b.prop_str("type", "flat_dt");
    b.prop("data", inner);
    b.begin("hash@1");
    b.prop_str("algo", "sha256");
    Bytes digest(32);
    const Digests d = Hasher::of(std::span<const std::uint8_t>(inner.data(), inner.size()));
    for (std::size_t i = 0; i < 32; ++i)
        digest[i] = static_cast<std::uint8_t>(std::stoul(d.sha256.substr(i * 2, 2), nullptr, 16));
    b.prop("value", digest);
    b.end();
    b.end();
    b.end();
    b.end();
    const Bytes fit = b.finish();
    const auto found = scan(test::span_of(fit), test::only({"fit", "fit-dtb"}));
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].format, "fit");
    EXPECT_EQ(found[0].confidence, Confidence::Verified);
    ASSERT_EQ(found[0].also_matched.size(), 2u);
    EXPECT_EQ(found[0].also_matched[0].format, "dtb");
    EXPECT_EQ(found[0].also_matched[0].offset, 0u);
    EXPECT_EQ(found[0].also_matched[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(found[0].also_matched[0], "dtb-is-fit"));
    EXPECT_EQ(found[0].also_matched[1].format, "dtb");
    EXPECT_EQ(found[0].also_matched[1].size, inner.size());
    EXPECT_EQ(found[0].also_matched[1].confidence, Confidence::Consistent);
}

// ------------------------------------------------------------------ verity

Bytes verity_sb(std::uint64_t data_blocks = 1298, const char* algo = "sha256",
                std::uint32_t block = 4096, std::size_t buffer = 64 * 1024) {
    Bytes b(buffer, 0x11);
    std::fill(b.begin(), b.begin() + 512, 0);
    test::put_bytes(b, 0, "verity");
    test::put_u32le(b, 8, 1);
    test::put_u32le(b, 12, 1);
    for (std::size_t i = 0; i < 16; ++i) b[16 + i] = static_cast<std::uint8_t>(i);
    test::put_bytes(b, 32, algo);
    test::put_u32le(b, 64, block);
    test::put_u32le(b, 68, block);
    test::put_u64le(b, 72, data_blocks);
    test::put_u16le(b, 80, 4);
    b[88] = 0xde;
    b[89] = 0xad;
    b[90] = 0xbe;
    b[91] = 0xef;
    return b;
}

TEST(VerityValidator, AcceptsSuperblockAndSizesTree) {
    const auto f = scan_one(verity_sb(), "dm-verity");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].format, "dm-verity");
    EXPECT_EQ(f[0].category, "crypto");
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].attrs.at("algorithm"), "sha256");
    EXPECT_EQ(f[0].attrs.at("data_blocks"), "1298");
    EXPECT_EQ(f[0].attrs.at("data_block_size"), "4096");
    EXPECT_EQ(f[0].attrs.at("hash_block_size"), "4096");
    EXPECT_EQ(f[0].attrs.at("hash_type"), "1");
    EXPECT_EQ(f[0].attrs.at("salt"), "deadbeef");
    EXPECT_EQ(f[0].attrs.at("uuid"), "00010203-0405-0607-0809-0a0b0c0d0e0f");
    // 1298 leaves / 128 per block = 11 blocks, then 1 root: 12 tree blocks + superblock.
    EXPECT_EQ(f[0].attrs.at("hash_tree_blocks"), "12");
    EXPECT_EQ(f[0].size, 13u * 4096u);
    // Uppercase algorithm names (seen in the wild) are normalised.
    const auto up = scan_one(verity_sb(1, "SHA256"), "dm-verity");
    ASSERT_EQ(up.size(), 1u);
    EXPECT_EQ(up[0].attrs.at("algorithm"), "sha256");
    EXPECT_EQ(up[0].attrs.at("hash_tree_blocks"), "0");
    EXPECT_EQ(up[0].size, 4096u);
}

TEST(VerityValidator, HostileVariants) {
    auto f = scan_one(verity_sb(10, "sha256", 1000), "dm-verity");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "verity-bad-block-size"));
    f = scan_one(verity_sb(10, "whirlpool"), "dm-verity");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "verity-bad-algorithm"));
    Bytes v2 = verity_sb();
    test::put_u32le(v2, 8, 2);
    f = scan_one(v2, "dm-verity");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "verity-unsupported-version"));
    // Tree past the buffer: structural, clamped.
    f = scan_one(verity_sb(1298, "sha256", 4096, 8192), "dm-verity");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].size, 8192u);
    EXPECT_TRUE(has_diag(f[0], "verity-truncated"));
    Bytes cut = verity_sb();
    cut.resize(100);
    f = scan_one(cut, "dm-verity");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "verity-truncated-header"));
}

// -------------------------------------------------------------------- luks

Bytes luks1_header(std::uint32_t payload_sectors = 16) {
    Bytes b(payload_sectors * 512 + 1024, 0x77);
    std::fill(b.begin(), b.begin() + 592, 0);
    test::put_bytes(b, 0, "LUKS");
    b[4] = 0xba;
    b[5] = 0xbe;
    test::put_u16be(b, 6, 1);
    test::put_bytes(b, 8, "aes");
    test::put_bytes(b, 40, "xts-plain64");
    test::put_bytes(b, 72, "sha256");
    test::put_u32be(b, 104, payload_sectors);
    test::put_u32be(b, 108, 32);
    test::put_u32be(b, 164, 1000);
    test::put_bytes(b, 168, "ddc8d4d8-d296-43e2-bb9e-76e1f9ee39f0");
    for (std::size_t s = 0; s < 8; ++s) {
        const std::size_t so = 208 + s * 48;
        test::put_u32be(b, so, s == 0 ? 0x00AC71F3u : 0x0000DEADu);
        test::put_u32be(b, so + 4, 1000);
        test::put_u32be(b, so + 40, static_cast<std::uint32_t>(8 + s));
        test::put_u32be(b, so + 44, 4000);
    }
    return b;
}

TEST(LuksValidator, Luks1) {
    const auto f = scan_one(luks1_header(), "luks");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].format, "luks");
    EXPECT_EQ(f[0].category, "crypto");
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, 16u * 512u);
    EXPECT_EQ(f[0].attrs.at("version"), "1");
    EXPECT_EQ(f[0].attrs.at("cipher"), "aes");
    EXPECT_EQ(f[0].attrs.at("mode"), "xts-plain64");
    EXPECT_EQ(f[0].attrs.at("hash"), "sha256");
    EXPECT_EQ(f[0].attrs.at("key_bits"), "256");
    EXPECT_EQ(f[0].attrs.at("payload_offset"), "8192");
    EXPECT_EQ(f[0].attrs.at("key_slots_enabled"), "1");
    EXPECT_EQ(f[0].attrs.at("uuid"), "ddc8d4d8-d296-43e2-bb9e-76e1f9ee39f0");
    EXPECT_EQ(f[0].endian, Endian::Big);
}

TEST(LuksValidator, Luks1Hostile) {
    Bytes b = luks1_header();
    b[10] = 0x01;  // control byte inside the cipher name
    auto f = scan_one(b, "luks");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "luks-bad-header"));
    b = luks1_header();
    test::put_u32be(b, 208 + 48, 0x1234);  // slot 1 in an unknown state
    f = scan_one(b, "luks");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "luks-bad-keyslots"));
    b = luks1_header();
    test::put_u16be(b, 6, 3);
    f = scan_one(b, "luks");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "luks-unsupported-version"));
    b = luks1_header(4096);  // payload 2 MiB away
    b.resize(65536);
    f = scan_one(b, "luks");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].size, 65536u);
    EXPECT_TRUE(has_diag(f[0], "luks-truncated"));
}

Bytes luks2_header(const std::string& json, std::uint64_t hdr_size = 16384) {
    Bytes b(32768, 0);
    test::put_bytes(b, 0, "LUKS");
    b[4] = 0xba;
    b[5] = 0xbe;
    test::put_u16be(b, 6, 2);
    test::put_u64be(b, 8, hdr_size);
    test::put_u64be(b, 16, 3);
    test::put_bytes(b, 24, "data");
    test::put_bytes(b, 72, "sha256");
    test::put_bytes(b, 168, "0e9b1c8a-5b0a-4f4c-9e2f-1c3d4e5f6a7b");
    test::put_u64be(b, 256, 0);
    std::copy(json.begin(), json.end(), b.begin() + 4096);
    return b;
}

TEST(LuksValidator, Luks2) {
    const std::string json =
        "{\"keyslots\":{\"0\":{\"type\":\"luks2\",\"kdf\":{\"type\":\"argon2id\"}}},"
        "\"segments\":{\"0\":{\"type\":\"crypt\",\"offset\":\"16777216\","
        "\"encryption\":\"aes-xts-plain64\"}},"
        "\"digests\":{\"0\":{\"type\":\"pbkdf2\",\"hash\":\"sha256\"}}}";
    auto f = scan_one(luks2_header(json), "luks");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, 32768u);
    EXPECT_EQ(f[0].attrs.at("version"), "2");
    EXPECT_EQ(f[0].attrs.at("label"), "data");
    EXPECT_EQ(f[0].attrs.at("checksum_alg"), "sha256");
    EXPECT_EQ(f[0].attrs.at("cipher"), "aes");
    EXPECT_EQ(f[0].attrs.at("mode"), "xts-plain64");
    EXPECT_EQ(f[0].attrs.at("payload_offset"), "16777216");
    EXPECT_EQ(f[0].attrs.at("hash"), "sha256");
    EXPECT_EQ(f[0].attrs.at("kdf"), "argon2id");
    f = scan_one(luks2_header("garbage"), "luks");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "luks-bad-json"));
    f = scan_one(luks2_header(json, 1000), "luks");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "luks-bad-hdr-size"));
}

// ------------------------------------------------------------------- romfs

Bytes romfs_image(const char* name = "test", std::uint32_t full = 0) {
    Bytes b(2048, 0);
    test::put_bytes(b, 0, "-rom1fs-");
    test::put_bytes(b, 16, name);
    const std::size_t name_field = ((std::strlen(name) + 1) + 15) & ~std::size_t{15};
    const std::size_t first = 16 + name_field;
    test::put_u32be(b, first, 0x00000000 | 1);  // next = 0 (last), type 1 = directory
    test::put_u32be(b, first + 4, 0);           // spec
    test::put_u32be(b, first + 8, 0);           // size
    test::put_bytes(b, first + 16, ".");
    test::put_u32be(b, 8, full != 0 ? full : static_cast<std::uint32_t>(first + 32));
    std::uint32_t sum = 0;
    for (std::size_t o = 0; o < 512; o += 4)
        sum += static_cast<std::uint32_t>((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) |
                                          b[o + 3]);
    test::put_u32be(b, 12, 0u - sum);
    return b;
}

TEST(RomfsValidator, AcceptsAndVerifiesChecksum) {
    const auto f = scan_one(romfs_image(), "romfs");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].size, 1024u);
    EXPECT_EQ(f[0].attrs.at("volume_name"), "test");
    EXPECT_EQ(f[0].attrs.at("checksum"), "ok");
    EXPECT_EQ(f[0].endian, Endian::Big);
}

TEST(RomfsValidator, HostileVariants) {
    Bytes b = romfs_image();
    b[12] ^= 0x10;
    auto f = scan_one(b, "romfs");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_TRUE(has_diag(f[0], "romfs-checksum-mismatch"));
    b = romfs_image();
    b[17] = 0x01;  // name with a control byte: the magic sits in other data
    f = scan_one(b, "romfs");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "romfs-bad-name"));
    f = scan_one(romfs_image("test", 8), "romfs");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "romfs-bad-size"));
    f = scan_one(romfs_image("test", 1u << 20), "romfs");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].size, 2048u);
    EXPECT_TRUE(has_diag(f[0], "romfs-truncated"));
}

// ------------------------------------------------------------------ cramfs

Bytes cramfs_image(bool big = false, std::uint32_t flags = 0x3) {
    Bytes b(4096, 0x5A);
    auto u32 = [&](std::size_t o, std::uint32_t v) {
        big ? test::put_u32be(b, o, v) : test::put_u32le(b, o, v);
    };
    std::fill(b.begin(), b.begin() + 76, 0);
    u32(0, 0x28cd3d45);
    u32(4, 4096);
    u32(8, flags);
    test::put_bytes(b, 16, "Compressed ROMFS");
    u32(36, 0);  // edition
    u32(40, 1);  // blocks
    u32(44, 2);  // files
    test::put_bytes(b, 48, "cram");
    u32(32, test::crc_zlib(b, 0, b.size()));
    return b;
}

TEST(CramfsValidator, BothByteOrdersVerified) {
    auto f = scan_one(cramfs_image(false), "cramfs-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].size, 4096u);
    EXPECT_EQ(f[0].attrs.at("name"), "cram");
    EXPECT_EQ(f[0].attrs.at("files"), "2");
    EXPECT_EQ(f[0].attrs.at("crc_check"), "ok");
    EXPECT_EQ(f[0].endian, Endian::Little);
    f = scan_one(cramfs_image(true), "cramfs-be");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].endian, Endian::Big);
}

TEST(CramfsValidator, HostileVariants) {
    Bytes b = cramfs_image();
    b[20] = 'X';  // signature broken: reject outright
    EXPECT_TRUE(scan_one(b, "cramfs-le").empty());
    b = cramfs_image();
    b[100] ^= 0xFF;  // payload changed: CRC mismatch
    auto f = scan_one(b, "cramfs-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_TRUE(has_diag(f[0], "cramfs-crc-mismatch"));
    b = cramfs_image();
    test::put_u32le(b, 4, 1u << 30);
    f = scan_one(b, "cramfs-le");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].size, 4096u);
    EXPECT_TRUE(has_diag(f[0], "cramfs-truncated"));
    f = scan_one(cramfs_image(false, 0x2), "cramfs-le");  // v1: no size field
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].size, 0u);
    EXPECT_TRUE(has_diag(f[0], "cramfs-v1-no-size"));
}

// ------------------------------------------------------------ android boot

Bytes boot_image(std::uint32_t hv, std::uint32_t page = 4096, std::uint32_t kernel = 5000,
                 std::uint32_t ramdisk = 3000, std::size_t buffer = 16384) {
    Bytes b(buffer, 0xC3);
    std::fill(b.begin(), b.begin() + 2048, 0);
    test::put_bytes(b, 0, "ANDROID!");
    if (hv >= 3) {
        test::put_u32le(b, 8, kernel);
        test::put_u32le(b, 12, ramdisk);
        test::put_u32le(b, 16, (12u << 25) | (23u << 4) | 5u);
        test::put_u32le(b, 20, hv == 3 ? 1580 : 1584);
        test::put_u32le(b, 40, hv);
        test::put_bytes(b, 44, "console=ttyS0\x01quiet");
        if (hv == 4) test::put_u32le(b, 1580, 0);
    } else {
        test::put_u32le(b, 8, kernel);
        test::put_u32le(b, 12, 0x10008000);
        test::put_u32le(b, 16, ramdisk);
        test::put_u32le(b, 20, 0x11000000);
        test::put_u32le(b, 24, 0);
        test::put_u32le(b, 32, 0x10000100);
        test::put_u32le(b, 36, page);
        test::put_u32le(b, 40, hv);
        test::put_u32le(b, 44, (12u << 25) | (23u << 4) | 5u);
        test::put_bytes(b, 48, "brd");
        test::put_bytes(b, 64, "console=ttyS0\x01quiet");
        for (std::size_t i = 0; i < 32; ++i) b[576 + i] = static_cast<std::uint8_t>(i);
        if (hv >= 1) {
            test::put_u32le(b, 1632, 0);
            test::put_u32le(b, 1644, hv == 1 ? 1648 : 1660);
        }
        if (hv >= 2) test::put_u32le(b, 1648, 100);
    }
    return b;
}

TEST(AndroidBootValidator, VersionsZeroToFour) {
    auto f = scan_one(boot_image(0), "android-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, 4096u + 8192u + 4096u);
    EXPECT_EQ(f[0].attrs.at("header_version"), "0");
    EXPECT_EQ(f[0].attrs.at("page_size"), "4096");
    EXPECT_EQ(f[0].attrs.at("kernel_size"), "5000");
    EXPECT_EQ(f[0].attrs.at("ramdisk_size"), "3000");
    EXPECT_EQ(f[0].attrs.at("os_version"), "12.0.0");
    EXPECT_EQ(f[0].attrs.at("os_patch_level"), "2023-05");
    EXPECT_EQ(f[0].attrs.at("cmdline"), "console=ttyS0_quiet");
    EXPECT_EQ(f[0].attrs.at("name"), "brd");
    EXPECT_EQ(f[0].attrs.at("id").substr(0, 8), "00010203");
    f = scan_one(boot_image(2, 4096, 5000, 3000, 20480), "android-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].size, 4096u + 8192u + 4096u + 4096u);  // + dtb
    EXPECT_EQ(f[0].attrs.at("dtb_size"), "100");
    EXPECT_EQ(f[0].attrs.at("header_size"), "1660");
    f = scan_one(boot_image(3), "android-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, 16384u);
    EXPECT_EQ(f[0].attrs.at("page_size"), "4096");
    EXPECT_EQ(f[0].attrs.at("cmdline"), "console=ttyS0_quiet");
    f = scan_one(boot_image(4), "android-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].attrs.at("signature_size"), "0");
    EXPECT_EQ(f[0].size, 16384u);
    // 16 KiB pages (as on the auto-ivi head unit).
    f = scan_one(boot_image(0, 16384, 5000, 0, 65536), "android-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].size, 32768u);
}

TEST(AndroidBootValidator, HostileVariants) {
    Bytes b = boot_image(0);
    test::put_u32le(b, 40, 9);
    auto f = scan_one(b, "android-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "android-boot-bad-header"));
    f = scan_one(boot_image(0, 1000), "android-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    f = scan_one(boot_image(0, 4096, 0, 0), "android-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "android-boot-empty"));
    f = scan_one(boot_image(0, 4096, 5000, 3000, 8192), "android-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].size, 8192u);
    EXPECT_TRUE(has_diag(f[0], "android-boot-truncated"));
    Bytes cut = boot_image(0);
    cut.resize(100);
    f = scan_one(cut, "android-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "android-boot-truncated-header"));
}

TEST(AndroidBootValidator, VendorBoot) {
    Bytes b(16384, 0);
    test::put_bytes(b, 0, "VNDRBOOT");
    test::put_u32le(b, 8, 4);
    test::put_u32le(b, 12, 4096);
    test::put_u32le(b, 24, 3000);
    test::put_bytes(b, 28, "vendor cmd");
    test::put_bytes(b, 2080, "vb");
    test::put_u32le(b, 2096, 2128);
    test::put_u32le(b, 2100, 100);
    test::put_u32le(b, 2112, 108);
    test::put_u32le(b, 2124, 0);
    const auto f = scan_one(b, "android-vendor-boot");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].format, "android-vendor-boot");
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, 16384u);
    EXPECT_EQ(f[0].attrs.at("vendor_ramdisk_size"), "3000");
    EXPECT_EQ(f[0].attrs.at("cmdline"), "vendor cmd");
    EXPECT_EQ(f[0].attrs.at("name"), "vb");
}

// ------------------------------------------------------------------- ubifs

Bytes ubifs_sb(std::size_t at = 0, std::uint32_t leb_cnt = 12, std::uint32_t max_leb_cnt = 128) {
    const std::uint32_t leb_size = 129024;
    Bytes b(at + static_cast<std::size_t>(leb_size) * leb_cnt, 0xFF);
    std::fill(b.begin() + static_cast<std::ptrdiff_t>(at),
              b.begin() + static_cast<std::ptrdiff_t>(at + 4096), 0);
    test::put_u32le(b, at, 0x06101831);
    test::put_u64le(b, at + 8, 166);
    test::put_u32le(b, at + 16, 4096);
    b[at + 20] = 6;
    test::put_u32le(b, at + 32, 2048);
    test::put_u32le(b, at + 36, leb_size);
    test::put_u32le(b, at + 40, leb_cnt);
    test::put_u32le(b, at + 44, max_leb_cnt);
    test::put_u64le(b, at + 48, 0x1d8800);
    test::put_u32le(b, at + 56, 4);
    test::put_u32le(b, at + 60, 2);
    test::put_u32le(b, at + 64, 1);
    test::put_u32le(b, at + 68, 1);
    test::put_u32le(b, at + 72, 8);
    test::put_u32le(b, at + 76, 256);
    test::put_u32le(b, at + 80, 4);
    test::put_u16le(b, at + 84, 2);
    test::put_u32le(b, at + 104, 1000000000);
    for (std::size_t i = 0; i < 16; ++i) b[at + 108 + i] = static_cast<std::uint8_t>(0xA0 + i);
    test::put_u32le(b, at + 4, test::crc_ubi(b, at + 8, 4088));
    return b;
}

TEST(UbifsValidator, AcceptsSuperblockNode) {
    const Bytes b = ubifs_sb();
    const auto f = scan_one(b, "ubifs");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_EQ(f[0].size, b.size());
    EXPECT_EQ(f[0].attrs.at("leb_size"), "129024");
    EXPECT_EQ(f[0].attrs.at("leb_cnt"), "12");
    EXPECT_EQ(f[0].attrs.at("min_io_size"), "2048");
    EXPECT_EQ(f[0].attrs.at("fmt_version"), "4");
    EXPECT_EQ(f[0].attrs.at("default_compr"), "zlib");
    EXPECT_EQ(f[0].attrs.at("uuid"), "a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf");
    EXPECT_EQ(f[0].attrs.at("crc_check"), "ok");
}

TEST(UbifsValidator, HostileVariants) {
    Bytes b = ubifs_sb();
    b[500] = 1;  // inside the CRC'd body
    auto f = scan_one(b, "ubifs");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_TRUE(has_diag(f[0], "ubifs-crc-mismatch"));
    b = ubifs_sb();
    b[20] = 1;  // an inode node, not a superblock
    EXPECT_TRUE(scan_one(b, "ubifs").empty());
    EXPECT_TRUE(scan_one(ubifs_sb(100), "ubifs").empty()) << "unaligned copy";
    f = scan_one(ubifs_sb(2048), "ubifs");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 2048u);
    f = scan_one(ubifs_sb(0, 200, 128), "ubifs");  // leb_cnt > max_leb_cnt
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "ubifs-bad-superblock"));
    b = ubifs_sb();
    b.resize(500000);  // fewer LEBs present than leb_cnt claims
    f = scan_one(b, "ubifs");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].size, 500000u);
    EXPECT_TRUE(has_diag(f[0], "ubifs-truncated"));
}

TEST(UbifsValidator, Fixture) {
    if (!test::fixture_exists("ubifs.img")) GTEST_SKIP();
    std::shared_ptr<MappedFile> file;
    ASSERT_TRUE(MappedFile::open(test::fixture_path("ubifs.img"), file));
    const auto found = scan(Span::whole(file), SignatureSet::builtin());
    const Finding* f = test::find_at(found, 0, "ubifs");
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->confidence, Confidence::Verified);
    EXPECT_EQ(f->attrs.at("leb_size"), "129024");
    EXPECT_EQ(f->attrs.at("leb_cnt"), "15");
    EXPECT_EQ(f->size, std::filesystem::file_size(test::fixture_path("ubifs.img")));
    EXPECT_EQ(count_format(found, "ubifs"), 1u);
}

// --------------------------------------------------------------------- elf

// ELF64 LE aarch64 executable: one PT_LOAD and two sections; extent 0x1290.
Bytes elf64(std::size_t at = 0) {
    Bytes b(at + 0x2000, 0x9C);
    std::fill(b.begin() + static_cast<std::ptrdiff_t>(at),
              b.begin() + static_cast<std::ptrdiff_t>(at + 0x1300), 0);
    test::put_bytes(b, at,
                    "\x7f"
                    "ELF");
    b[at + 4] = 2;
    b[at + 5] = 1;
    b[at + 6] = 1;
    test::put_u16le(b, at + 16, 2);
    test::put_u16le(b, at + 18, 183);
    test::put_u32le(b, at + 20, 1);
    test::put_u64le(b, at + 24, 0x400000);
    test::put_u64le(b, at + 32, 64);      // phoff
    test::put_u64le(b, at + 40, 0x1200);  // shoff
    test::put_u16le(b, at + 52, 64);
    test::put_u16le(b, at + 54, 56);
    test::put_u16le(b, at + 56, 1);
    test::put_u16le(b, at + 58, 64);
    test::put_u16le(b, at + 60, 2);
    test::put_u16le(b, at + 62, 1);
    test::put_u32le(b, at + 64, 1);  // PT_LOAD
    test::put_u64le(b, at + 64 + 8, 0x1000);
    test::put_u64le(b, at + 64 + 32, 0x200);
    // section 1: PROGBITS at 0x1280, 0x10 bytes
    test::put_u32le(b, at + 0x1200 + 64 + 4, 1);
    test::put_u64le(b, at + 0x1200 + 64 + 24, 0x1280);
    test::put_u64le(b, at + 0x1200 + 64 + 32, 0x10);
    return b;
}

TEST(ElfValidator, Elf64AndElf32) {
    auto f = scan_one(elf64(), "elf");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, 0x1290u);
    EXPECT_EQ(f[0].attrs.at("class"), "64");
    EXPECT_EQ(f[0].attrs.at("endian"), "little");
    EXPECT_EQ(f[0].attrs.at("machine"), "aarch64");
    EXPECT_EQ(f[0].attrs.at("type"), "executable");
    EXPECT_EQ(f[0].attrs.at("entry"), "0x0000000000400000");
    EXPECT_EQ(f[0].attrs.at("program_headers"), "1");
    EXPECT_EQ(f[0].attrs.at("section_headers"), "2");
    // ELF32 big-endian MIPS shared object, program headers only.
    Bytes b(0x1000, 0);
    test::put_bytes(b, 0,
                    "\x7f"
                    "ELF");
    b[4] = 1;
    b[5] = 2;
    b[6] = 1;
    test::put_u16be(b, 16, 3);
    test::put_u16be(b, 18, 8);
    test::put_u32be(b, 20, 1);
    test::put_u32be(b, 28, 52);  // phoff
    test::put_u16be(b, 40, 52);
    test::put_u16be(b, 42, 32);
    test::put_u16be(b, 44, 2);
    test::put_u16be(b, 46, 40);
    test::put_u32be(b, 52 + 4, 0x100);   // p_offset
    test::put_u32be(b, 52 + 16, 0x300);  // p_filesz
    test::put_u32be(b, 84 + 4, 0x500);
    test::put_u32be(b, 84 + 16, 0x80);
    f = scan_one(b, "elf");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_EQ(f[0].size, 0x580u);
    EXPECT_EQ(f[0].attrs.at("class"), "32");
    EXPECT_EQ(f[0].attrs.at("endian"), "big");
    EXPECT_EQ(f[0].attrs.at("machine"), "mips");
    EXPECT_EQ(f[0].attrs.at("type"), "shared-object");
    EXPECT_EQ(f[0].endian, Endian::Big);
}

TEST(ElfValidator, HostileAndUnaligned) {
    Bytes b = elf64();
    test::put_u32le(b, 20, 2);  // e_version
    EXPECT_TRUE(scan_one(b, "elf").empty());
    b = elf64();
    test::put_u16le(b, 52, 60);  // e_ehsize
    EXPECT_TRUE(scan_one(b, "elf").empty());
    b = elf64();
    test::put_u16le(b, 62, 5);  // shstrndx >= shnum
    EXPECT_TRUE(scan_one(b, "elf").empty());
    b = elf64();
    test::put_u64le(b, 40, 0x7fff0000);  // shoff outside: aligned -> structural, no size
    auto f = scan_one(b, "elf");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_EQ(f[0].size, 0u);
    EXPECT_TRUE(has_diag(f[0], "elf-truncated"));
    Bytes u = elf64(3);  // same at an unaligned offset: dropped
    test::put_u64le(u, 3 + 40, 0x7fff0000);
    EXPECT_TRUE(scan_one(u, "elf").empty());
    f = scan_one(elf64(3), "elf");  // unaligned but fully consistent: kept
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 3u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    // SHT_NOBITS with a huge size does not extend the file.
    b = elf64();
    test::put_u32le(b, 0x1200 + 64 + 4, 8);
    test::put_u64le(b, 0x1200 + 64 + 32, 0x7fffffff);
    f = scan_one(b, "elf");
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].size, 0x1280u);
    Bytes cut = elf64();
    cut.resize(40);
    EXPECT_TRUE(scan_one(cut, "elf").empty());
}

// ------------------------------------------------------------- signatures

TEST(Signatures2, NewSignaturesAndAlignments) {
    const SignatureSet& b = SignatureSet::builtin();
    std::map<std::string, const Signature*> by_name;
    for (const Signature& s : b.signatures) by_name[s.name] = &s;
    for (const char* n : {"luks", "dm-verity", "fit", "fit-dtb", "android-vendor-boot"})
        EXPECT_NE(by_name.count(n), 0u) << n;
    ASSERT_NE(by_name.count("qnx6-le"), 0u);
    EXPECT_EQ(by_name["qnx6-le"]->alignment, 4096u);
    EXPECT_EQ(by_name["qnx6-be"]->alignment, 4096u);
    EXPECT_TRUE(by_name["qnx6-le"]->validator.empty());
    for (const char* n : {"dtb", "fit", "verity", "luks", "romfs", "cramfs", "android-boot",
                          "ubifs", "elf", "jffs2"})
        EXPECT_NE(ValidatorRegistry::instance().find(n), nullptr) << n;
    EXPECT_EQ(by_name["jffs2-le"]->extra.at("max_gap"), "131072");
}

// ------------------------------------------------------------------ corpus

TEST(Corpus2, SpiExampleJffs2FitVerity) {
    std::shared_ptr<MappedFile> file;
    const auto span = corpus_slice("spi-example/flash/XT25F128F@SOP8.BIN", 0, 16u << 20, file);
    if (!span) GTEST_SKIP() << "spi-example image not available";
    const auto found = scan(*span, SignatureSet::builtin());
    // One JFFS2 filesystem, not one finding per obsolete node or erase block.
    EXPECT_EQ(count_format(found, "jffs2"), 1u);
    const Finding* j = test::find_at(found, 0xfa0000, "jffs2");
    ASSERT_NE(j, nullptr);
    EXPECT_EQ(j->confidence, Confidence::Verified);
    EXPECT_EQ(j->attrs.at("erase_size"), "32768");  // cleanmarkers every 32 KiB
    EXPECT_EQ(j->attrs.at("obsolete_nodes"), "61");
    EXPECT_EQ(j->attrs.at("cleanmarkers"), "9");
    EXPECT_EQ(j->attrs.at("dirty_gap_bytes"), "0");
    // Walk ends after the last cleanmarker (0xfe8000 + 12); the trailing erased
    // part of that block is excluded, so the aligned extent is 10 x 32 KiB.
    EXPECT_EQ(j->offset + j->size, 0xfe800cu);
    EXPECT_EQ(j->attrs.at("aligned_size"), "327680");
    // The 64 KiB at 0xff0000 is a different structure (serial/board data).
    EXPECT_EQ(test::find_at(found, 0xff0000), nullptr);

    const Finding* fit = test::find_at(found, 0x30000, "fit");
    ASSERT_NE(fit, nullptr);
    EXPECT_EQ(fit->confidence, Confidence::Verified);
    EXPECT_EQ(fit->size, 3979178u);
    EXPECT_EQ(fit->attrs.at("image_count"), "3");
    EXPECT_EQ(fit->attrs.at("hash_ok"), "3");
    EXPECT_EQ(fit->attrs.at("default_configuration"), "conf");
    EXPECT_EQ(count_format(found, "dtb"), 0u) << "DTBs live in also_matched only";
    std::size_t dtb_inside = 0;
    for (const Finding& a : fit->also_matched) dtb_inside += a.format == "dtb";
    EXPECT_EQ(dtb_inside, 2u);  // the FIT container itself and its fdt image

    const Finding* v = test::find_at(found, 0x9ba000, "dm-verity");
    ASSERT_NE(v, nullptr);
    EXPECT_EQ(v->confidence, Confidence::Consistent);
    EXPECT_EQ(v->attrs.at("algorithm"), "sha256");
    EXPECT_EQ(v->attrs.at("data_blocks"), "1298");
    EXPECT_EQ(v->attrs.at("hash_tree_blocks"), "12");
    EXPECT_EQ(v->size, 13u * 4096u);
    // Its data_bytes equals the SquashFS it protects.
    const Finding* sq = test::find_at(found, 0x4a0000, "squashfs");
    ASSERT_NE(sq, nullptr);
    EXPECT_EQ(v->attrs.at("data_bytes"), std::to_string(sq->size));
}

TEST(Corpus2, SonosFitSlice) {
    std::shared_ptr<MappedFile> file;
    const auto span = corpus_slice("audio-example/flash/UserData.BIN", 0x800000, 16u << 20, file);
    if (!span) GTEST_SKIP() << "audio-example image not available";
    const auto found = scan(*span, SignatureSet::builtin());
    const Finding* fit = test::find_at(found, 0x1b4, "fit");
    ASSERT_NE(fit, nullptr);
    EXPECT_EQ(fit->confidence, Confidence::Verified);
    EXPECT_EQ(fit->attrs.at("image_count"), "22");
    EXPECT_EQ(fit->attrs.at("hash_ok"), "22");
    EXPECT_EQ(fit->size, 11946312u);
    EXPECT_EQ(count_format(found, "dtb"), 0u);
}

TEST(Corpus2, SonosLuks1Slice) {
    std::shared_ptr<MappedFile> file;
    const auto span = corpus_slice("audio-example/flash/UserData.BIN", 0x12000000, 1u << 20, file);
    if (!span) GTEST_SKIP() << "audio-example image not available";
    const auto found = scan(*span, SignatureSet::builtin());
    const Finding* l = test::find_at(found, 0, "luks");
    ASSERT_NE(l, nullptr);
    EXPECT_EQ(l->confidence, Confidence::Consistent);
    EXPECT_EQ(l->attrs.at("version"), "1");
    EXPECT_EQ(l->attrs.at("cipher"), "aes");
    EXPECT_EQ(l->attrs.at("mode"), "xts-plain64");
    EXPECT_EQ(l->attrs.at("hash"), "sha256");
    EXPECT_EQ(l->attrs.at("payload_offset"), "2097152");
    EXPECT_EQ(l->attrs.at("uuid"), "ddc8d4d8-d296-43e2-bb9e-76e1f9ee39f0");
}

TEST(Corpus2, SonosVerityAndRomfsStringTable) {
    std::shared_ptr<MappedFile> file;
    auto span = corpus_slice("audio-example/flash/UserData.BIN", 0x51a4000, 1u << 20, file);
    if (!span) GTEST_SKIP() << "audio-example image not available";
    auto found = scan(*span, SignatureSet::builtin());
    const Finding* v = test::find_at(found, 0, "dm-verity");
    ASSERT_NE(v, nullptr);
    EXPECT_EQ(v->confidence, Confidence::Consistent);
    EXPECT_EQ(v->attrs.at("algorithm"), "sha256");
    EXPECT_EQ(v->attrs.at("data_blocks"), "14756");
    EXPECT_EQ(v->attrs.at("hash_tree_blocks"), "117");
    EXPECT_EQ(v->size, 118u * 4096u);
    // "-rom1fs-" here is an entry in a filesystem-name string table (next to
    // "squashfs", "NSR02", "BEA01"), not a romfs: magic only, with the reason.
    std::shared_ptr<MappedFile> file2;
    span = corpus_slice("audio-example/flash/UserData.BIN", 0x120a805b, 4096, file2);
    ASSERT_TRUE(span);
    found = scan(*span, SignatureSet::builtin());
    const Finding* r = test::find_at(found, 0, "romfs");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(*r, "romfs-bad-name"));
}

TEST(Corpus2, SonosGzipNameField) {
    std::shared_ptr<MappedFile> file;
    const auto span = corpus_slice("audio-example/flash/UserData.BIN", 0x101c000, 64u << 10, file);
    if (!span) GTEST_SKIP() << "audio-example image not available";
    const auto found = scan(*span, SignatureSet::builtin());
    const Finding* g = test::find_at(found, 0x949, "gzip");
    ASSERT_NE(g, nullptr);
    EXPECT_EQ(g->attrs.at("flags"), "0x08");  // FNAME only: the name starts at byte 10
    // The stored FNAME really is "&]\xf0\xff...\xae_local.cpio" (the bytes at
    // 0x101c953 are 26 5d f0 ff ff ff ff ff ff ae): RFC 1952 field order is
    // right and the image itself carries a damaged name. Either a name that
    // still ends in "_local.cpio" or no name plus a diagnostic is acceptable.
    const auto it = g->attrs.find("original_name");
    if (it != g->attrs.end()) {
        const std::string& n = it->second;
        EXPECT_GE(n.size(), std::string("_local.cpio").size());
        EXPECT_EQ(n.substr(n.size() - 11), "_local.cpio") << n;
    } else {
        EXPECT_FALSE(g->diagnostics.empty());
    }
}

TEST(Corpus2, HyundaiAndroidBootSlice) {
    std::shared_ptr<MappedFile> file;
    const auto span =
        corpus_slice("auto-ivi-example/flash/UserData.BIN", 0x104400, 8u << 20, file);
    if (!span) GTEST_SKIP() << "auto-ivi-example image not available";
    const auto found = scan(*span, SignatureSet::builtin());
    const Finding* b = test::find_at(found, 0, "android-boot");
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(b->confidence, Confidence::Consistent);
    EXPECT_EQ(b->attrs.at("header_version"), "0");
    EXPECT_EQ(b->attrs.at("page_size"), "16384");
    EXPECT_GT(std::stoul(b->attrs.at("kernel_size")), 0u);
    EXPECT_EQ(b->attrs.at("kernel_size"), "6409432");
    EXPECT_EQ(b->size, 6438912u);
    EXPECT_EQ(b->attrs.at("cmdline").rfind("root=/dev/mmcblk0p2", 0), 0u);
}

}  // namespace
