// qnx_ifs_validator_test.cpp — the qnx-ifs validator: hand-built startup
// header + image filesystem (accept, every tier), hostile variants (reject or
// downgrade with the exact diagnostic), and corpus slices (skipped when the
// evidence images are absent).
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <map>

#include "helpers.h"

using namespace omnitrace;
using namespace omnitrace::discovery;
using test::Bytes;

// The anchor keeps the validator's object file linked into this binary even
// before validators/builtin.cpp lists it.
namespace omnitrace::discovery::detail {
void omnitrace_validator_anchor_qnx_ifs();
}

namespace {

SignatureSet qnx_ifs_sigs() {
    detail::omnitrace_validator_anchor_qnx_ifs();
    SignatureSet s = test::only({"qnx-ifs"});
    for (Signature& sig : s.signatures) sig.validator = "qnx-ifs";
    return s;
}

std::vector<Finding> scan_ifs(const Bytes& buf) {
    return scan(test::span_of(buf), qnx_ifs_sigs());
}

// The validator itself, for byte orders the LE signature cannot reach.
std::optional<Finding> validate_at(const Bytes& buf, std::uint64_t start) {
    const SignatureSet s = qnx_ifs_sigs();
    const Validator* v = ValidatorRegistry::instance().find("qnx-ifs");
    if (v == nullptr || s.signatures.empty()) return std::nullopt;
    return (*v)(test::span_of(buf), start, s.signatures[0]);
}

bool has_diag(const Finding& f, const char* code) {
    for (const Diagnostic& d : f.diagnostics)
        if (d.code == code) return true;
    return false;
}

std::string diags(const Finding& f) {
    std::string s;
    for (const Diagnostic& d : f.diagnostics) s += d.code + ": " + d.message + "\n";
    return s;
}

const std::string kCorpus = "/home/wrongbaud/projects/omnitrace-v2/corpus/";

std::optional<Span> corpus_slice(const std::string& rel, std::uint64_t off, std::uint64_t len,
                                 std::shared_ptr<MappedFile>& keep) {
    const std::string path = kCorpus + rel;
    if (!std::filesystem::exists(path)) return std::nullopt;
    if (!MappedFile::open(path, keep)) return std::nullopt;
    return Span::whole(keep).sub(off, len);
}

// ------------------------------------------------------------------- builder

void put16(Bytes& b, std::size_t off, std::uint16_t v, Endian e) {
    if (e == Endian::Little)
        test::put_u16le(b, off, v);
    else
        test::put_u16be(b, off, v);
}
void put32(Bytes& b, std::size_t off, std::uint32_t v, Endian e) {
    if (e == Endian::Little)
        test::put_u32le(b, off, v);
    else
        test::put_u32be(b, off, v);
}
std::uint32_t get32(const Bytes& b, std::size_t off, Endian e) {
    std::uint32_t v = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        const unsigned shift =
            e == Endian::Little ? 8 * static_cast<unsigned>(i) : 8 * static_cast<unsigned>(3 - i);
        v |= static_cast<std::uint32_t>(b[off + i]) << shift;
    }
    return v;
}
void pad4(Bytes& b) {
    while (b.size() % 4 != 0) b.push_back(0);
}
void seal(Bytes& b, std::size_t from, Endian e) {
    pad4(b);
    std::uint32_t sum = 0;
    for (std::size_t o = from; o + 4 <= b.size(); o += 4) sum += get32(b, o, e);
    b.resize(b.size() + 4);
    put32(b, b.size() - 4, static_cast<std::uint32_t>(0u - sum), e);
}

struct Layout {
    Bytes img;
    std::size_t startup_size = 0, stored_size = 0, image_size = 0, hdr_dir_size = 0, dir_offset = 0,
                comp_start = 0;
};

// An image filesystem with a root, one directory and two files (one the
// boot script), sealed with its checksum.
Bytes build_image(Endian e, std::uint32_t script_ino, std::size_t& hdr_dir_size,
                  std::size_t& dir_offset) {
    Bytes im(88, 0);
    std::memcpy(im.data(), "imagefs", 7);
    im[7] = static_cast<std::uint8_t>((e == Endian::Big ? 0x01 : 0x00) | 0x04);
    put32(im, 20, 0xe0000002u, e);  // boot_ino[0] with flag bits
    put32(im, 36, script_ino, e);
    im.push_back('/');
    im.push_back(0);
    pad4(im);
    dir_offset = im.size();
    put32(im, 16, static_cast<std::uint32_t>(dir_offset), e);
    auto dirent = [&](std::uint16_t size, std::uint32_t ino, std::uint32_t mode,
                      const std::string& path, std::uint32_t off, std::uint32_t len) {
        Bytes d(24, 0);
        put16(d, 0, size, e);
        put32(d, 4, ino, e);
        put32(d, 8, mode, e);
        put32(d, 20, 1700000000u, e);
        if ((mode & 0170000) == 0100000) {
            d.resize(32, 0);
            put32(d, 24, off, e);
            put32(d, 28, len, e);
        }
        for (const char c : path) d.push_back(static_cast<std::uint8_t>(c));
        d.push_back(0);
        d.resize(size, 0);
        im.insert(im.end(), d.begin(), d.end());
    };
    dirent(28, 1, 0040755, "", 0, 0);
    dirent(28, 4, 0040755, "etc", 0, 0);
    const std::size_t data_at = dir_offset + 28 + 28 + 44 + 52;
    dirent(44, 2, 0100644, "etc/passwd", static_cast<std::uint32_t>(data_at), 12);
    dirent(52, 3, 0100444, "proc/boot/.script", static_cast<std::uint32_t>(data_at + 12), 8);
    hdr_dir_size = im.size();
    put32(im, 12, static_cast<std::uint32_t>(hdr_dir_size), e);
    const std::string data = "root:x:0:0:\nscript!!";
    for (const char c : data) im.push_back(static_cast<std::uint8_t>(c));
    put32(im, 8, static_cast<std::uint32_t>(im.size() + 4), e);
    seal(im, 0, e);
    return im;
}

// codec 0: uncompressed. Otherwise a fake block chain (the validator never
// decodes): `blocks` random blocks of `block_len` bytes, a terminator,
// padding and the area checksum; codec 1 (zlib) is one gzip-looking stream.
Layout build(Endian e = Endian::Little, unsigned codec = 0, std::size_t blocks = 3,
             std::size_t block_len = 300, std::uint16_t machine = 183,
             std::uint32_t script_ino = 3) {
    Layout L;
    Bytes im = build_image(e, script_ino, L.hdr_dir_size, L.dir_offset);
    L.image_size = im.size();
    Bytes& img = L.img;
    img.assign(256, 0);
    if (e == Endian::Big) {
        img[0] = 0x00, img[1] = 0xff, img[2] = 0x7e, img[3] = 0xeb;
    } else {
        img[0] = 0xeb, img[1] = 0x7e, img[2] = 0xff, img[3] = 0x00;
    }
    put16(img, 4, 1, e);
    img[6] = static_cast<std::uint8_t>(0x01 | (e == Endian::Big ? 0x02 : 0) | (codec << 2));
    put16(img, 8, 256, e);
    put16(img, 10, machine, e);
    put32(img, 12, 0x82301800u, e);
    put32(img, 20, 0x82300000u, e);
    put32(img, 24, 0x82300000u, e);
    put32(img, 28, 0x100000u, e);
    L.startup_size = 256 + 252 + 4;
    put32(img, 32, static_cast<std::uint32_t>(L.startup_size), e);
    put32(img, 44, static_cast<std::uint32_t>(L.image_size), e);
    for (std::size_t i = 0; i < 252; ++i) img.push_back(static_cast<std::uint8_t>(i * 13 + 1));
    Bytes payload;
    if (codec == 0) {
        payload = im;
        L.stored_size = L.startup_size + payload.size();
    } else if (codec == 1) {
        payload = {0x1f, 0x8b, 0x08, 0x00};
        for (std::size_t i = 0; i < block_len; ++i) payload.push_back(static_cast<std::uint8_t>(i));
        L.stored_size = ((L.startup_size + payload.size() + 3) & ~std::size_t{3}) + 4;
    } else {
        std::uint8_t x = 17;
        for (std::size_t b = 0; b < blocks; ++b) {
            payload.push_back(static_cast<std::uint8_t>(block_len >> 8));
            payload.push_back(static_cast<std::uint8_t>(block_len & 0xff));
            for (std::size_t i = 0; i < block_len; ++i) {
                x = static_cast<std::uint8_t>(x * 31 + 7);
                payload.push_back(x);
            }
        }
        payload.push_back(0);
        payload.push_back(0);
        L.stored_size = ((L.startup_size + payload.size() + 3) & ~std::size_t{3}) + 4;
    }
    put32(img, 36, static_cast<std::uint32_t>(L.stored_size), e);
    seal(img, 0, e);
    L.comp_start = img.size();
    img.insert(img.end(), payload.begin(), payload.end());
    if (codec != 0) seal(img, L.comp_start, e);
    return L;
}

// ------------------------------------------------------------------- accept

TEST(QnxIfsValidator, UncompressedIsVerified) {
    const Layout L = build();
    const auto f = scan_ifs(L.img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 0u);
    EXPECT_EQ(f[0].format, "qnx-ifs");
    EXPECT_EQ(f[0].confidence, Confidence::Verified) << diags(f[0]);
    EXPECT_EQ(f[0].size, L.startup_size + L.image_size);
    EXPECT_EQ(f[0].size, L.stored_size);
    EXPECT_EQ(f[0].attrs.at("version"), "1");
    EXPECT_EQ(f[0].attrs.at("machine"), "aarch64");
    EXPECT_EQ(f[0].attrs.at("compressed"), "none");
    EXPECT_EQ(f[0].attrs.at("flags1"), "0x1");
    EXPECT_EQ(f[0].attrs.at("startup_size"), std::to_string(L.startup_size));
    EXPECT_EQ(f[0].attrs.at("stored_size"), std::to_string(L.stored_size));
    EXPECT_EQ(f[0].attrs.at("image_size"), std::to_string(L.image_size));
    EXPECT_EQ(f[0].attrs.at("imagefs_size"), std::to_string(L.image_size));
    EXPECT_EQ(f[0].attrs.at("hdr_dir_size"), std::to_string(L.hdr_dir_size));
    EXPECT_EQ(f[0].attrs.at("dir_offset"), std::to_string(L.dir_offset));
    EXPECT_EQ(f[0].attrs.at("entries"), "4");
    EXPECT_EQ(f[0].attrs.at("files"), "2");
    EXPECT_EQ(f[0].attrs.at("script"), "true");
    EXPECT_EQ(f[0].attrs.at("boot_ino"), "2");
    EXPECT_EQ(f[0].attrs.at("mountpoint"), "/");
    EXPECT_EQ(f[0].attrs.at("startup_checksum"), "ok");
    EXPECT_EQ(f[0].attrs.at("image_checksum"), "ok");
    EXPECT_EQ(f[0].attrs.at("image_flags"), "0x4");
    EXPECT_EQ(f[0].endian, Endian::Little);
    EXPECT_TRUE(f[0].diagnostics.empty()) << diags(f[0]);
    EXPECT_NE(f[0].evidence.find("uncompressed"), std::string::npos);
}

TEST(QnxIfsValidator, UncompressedBigEndian) {
    const Layout L = build(Endian::Big);
    const auto f = validate_at(L.img, 0);
    ASSERT_TRUE(f);
    EXPECT_EQ(f->confidence, Confidence::Verified) << diags(*f);
    EXPECT_EQ(f->endian, Endian::Big);
    EXPECT_EQ(f->attrs.at("entries"), "4");
    EXPECT_EQ(f->attrs.at("machine"), "aarch64");
    EXPECT_EQ(f->size, L.stored_size);
}

TEST(QnxIfsValidator, NoScriptAndUnalignedOffset) {
    Layout L = build(Endian::Little, 0, 3, 300, 183, 0);
    Bytes buf(777, 0x5a);
    buf.insert(buf.end(), L.img.begin(), L.img.end());
    const auto f = scan_ifs(buf);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 777u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified) << diags(f[0]);
    EXPECT_EQ(f[0].attrs.at("script"), "false");
}

TEST(QnxIfsValidator, CompressedChainIsVerifiedByStoredChecksum) {
    for (const unsigned codec : {2u, 3u, 4u}) {
        const Layout L = build(Endian::Little, codec, 3, 300);
        const auto f = scan_ifs(L.img);
        ASSERT_EQ(f.size(), 1u) << codec;
        EXPECT_EQ(f[0].confidence, Confidence::Verified) << diags(f[0]);
        EXPECT_EQ(f[0].size, L.stored_size);
        EXPECT_EQ(f[0].attrs.at("compressed"), codec == 2 ? "lzo" : codec == 3 ? "ucl" : "lz4");
        EXPECT_EQ(f[0].attrs.at("blocks"), "3");
        EXPECT_EQ(f[0].attrs.at("compressed_bytes"), "900");
        EXPECT_EQ(f[0].attrs.at("stored_checksum"), "ok");
        EXPECT_EQ(f[0].attrs.count("image_size"), 0u);
        EXPECT_TRUE(f[0].diagnostics.empty()) << diags(f[0]);
        EXPECT_NE(f[0].evidence.find("compressed"), std::string::npos);
    }
}

TEST(QnxIfsValidator, CompressedChainWithoutTrailerIsStructural) {
    // stored_size says the chain ends right after the terminator: no
    // checksum word to verify.
    Layout L = build(Endian::Little, 3, 2, 100);
    Bytes img = L.img;
    const std::size_t chain_end = L.comp_start + 2 * 102 + 2;
    test::put_u32le(img, 36, static_cast<std::uint32_t>(chain_end));
    img.resize(chain_end);
    // The startup checksum no longer holds: re-seal the startup region.
    std::uint32_t sum = 0;
    for (std::size_t o = 0; o + 4 < L.startup_size; o += 4) sum += get32(img, o, Endian::Little);
    test::put_u32le(img, L.startup_size - 4, 0u - sum);
    const auto f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural) << diags(f[0]);
    EXPECT_EQ(f[0].size, chain_end);
    EXPECT_EQ(f[0].attrs.at("stored_checksum"), "unverified");
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-stored-size-mismatch") || f[0].attrs.at("blocks") == "2");
}

TEST(QnxIfsValidator, ZlibStream) {
    const Layout L = build(Endian::Little, 1, 1, 300);
    auto f = scan_ifs(L.img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].attrs.at("compressed"), "zlib");
    EXPECT_EQ(f[0].confidence, Confidence::Verified) << diags(f[0]);
    EXPECT_EQ(f[0].size, L.stored_size);

    Bytes img = L.img;
    img[L.comp_start] = 0x00;  // no gzip magic
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-bad-compressed-block"));
}

// ------------------------------------------------------------------- hostile

TEST(QnxIfsValidator, NoiseIsRejected) {
    const Layout L = build();
    Bytes img = L.img;
    test::put_u16le(img, 4, 2);  // version
    EXPECT_TRUE(scan_ifs(img).empty());
    img = L.img;
    test::put_u16le(img, 8, 128);  // header_size
    EXPECT_TRUE(scan_ifs(img).empty());
    img = L.img;
    test::put_u16le(img, 50, 1);  // zero0
    EXPECT_TRUE(scan_ifs(img).empty());
    img = L.img;
    test::put_u32le(img, 56, 1);  // zero[1]
    EXPECT_TRUE(scan_ifs(img).empty());
    img = L.img;
    test::put_u32le(img, 60, 0x80000000u);  // zero[2]
    EXPECT_TRUE(scan_ifs(img).empty());
    // Magic alone at the end of a buffer: a Magic finding with a diagnostic.
    Bytes tail(100, 0);
    tail.insert(tail.end(), {0xeb, 0x7e, 0xff, 0x00, 0x01, 0x00});
    const auto f = scan_ifs(tail);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-truncated-header"));
}

TEST(QnxIfsValidator, HostileStartupHeader) {
    const Layout L = build();
    Bytes img = L.img;
    test::put_u32le(img, 32, static_cast<std::uint32_t>(L.stored_size + 4));  // startup > stored
    auto f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-bad-startup-size"));
    EXPECT_EQ(f[0].size, 0u);

    img = L.img;
    test::put_u32le(img, 32, 255);
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-bad-startup-size"));
    img = L.img;
    test::put_u32le(img, 32, 258);  // unaligned
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-bad-startup-size"));

    img = L.img;
    test::put_u32le(img, 32, 0xfffffffcu);
    test::put_u32le(img, 36, 0xffffffffu);
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-truncated"));
    EXPECT_EQ(f[0].size, img.size());

    img = L.img;
    test::put_u16le(img, 10, 999);  // machine
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-unknown-machine"));
    EXPECT_EQ(f[0].attrs.at("machine"), "unknown(0x3e7)");
    EXPECT_EQ(f[0].confidence, Confidence::Verified);  // the structure still verifies

    img = L.img;
    img[6] = static_cast<std::uint8_t>(img[6] | 0x1c);  // compression code 7
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-unsupported-compression"));
    EXPECT_EQ(f[0].attrs.at("compressed"), "unknown(7)");
    EXPECT_EQ(f[0].size, L.stored_size);

    img = L.img;
    img[300] ^= 0x40;  // startup code
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-startup-checksum-bad"));
    EXPECT_EQ(f[0].attrs.at("startup_checksum"), "mismatch");
    EXPECT_EQ(f[0].confidence, Confidence::Verified);  // the image checksum decides

    img = L.img;
    img[7] = 0x01;  // flags2 patched after mkifs
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    bool noted = false;
    for (const Diagnostic& d : f[0].diagnostics)
        if (d.code == "qnx-ifs-startup-checksum-bad" &&
            d.message.find("flags2") != std::string::npos)
            noted = true;
    EXPECT_TRUE(noted) << diags(f[0]);
}

TEST(QnxIfsValidator, HostileImageHeader) {
    const Layout L = build();
    const std::size_t ipos = L.startup_size;
    Bytes img = L.img;
    img[ipos] = 'X';  // no "imagefs"
    auto f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-no-image-header"));
    EXPECT_EQ(f[0].size, L.stored_size);

    img = L.img;
    test::put_u32le(img, ipos + 16, 0xffffffffu);  // dir_offset
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-bad-image-header"));

    img = L.img;
    test::put_u32le(img, ipos + 12, 0xffffffffu);  // hdr_dir_size
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-bad-image-header"));

    img = L.img;
    test::put_u32le(img, ipos + 8, 0xffffffffu);  // image_size
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-truncated"));
    EXPECT_EQ(f[0].size, img.size());

    img = L.img;
    test::put_u16le(img, ipos + L.dir_offset + 28, 0xffff);  // second dirent size
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-dirent-corrupt"));
    EXPECT_EQ(f[0].attrs.at("entries"), "1");

    img = L.img;
    img[ipos + L.hdr_dir_size + 2] ^= 0x01;  // file data: image checksum
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Consistent);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-image-checksum-bad"));
    EXPECT_EQ(f[0].attrs.at("image_checksum"), "mismatch");

    img = L.img;
    test::put_u32le(img, 36, static_cast<std::uint32_t>(L.stored_size - 8));  // stored_size short
    // re-seal startup
    std::uint32_t sum = 0;
    for (std::size_t o = 0; o + 4 < L.startup_size; o += 4) sum += get32(img, o, Endian::Little);
    test::put_u32le(img, L.startup_size - 4, 0u - sum);
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-stored-size-mismatch"));
    EXPECT_EQ(f[0].size, L.startup_size + L.image_size);
}

TEST(QnxIfsValidator, HostileCompressedChain) {
    const Layout L = build(Endian::Little, 3, 3, 300);
    Bytes img = L.img;
    img[L.comp_start] = 0;
    img[L.comp_start + 1] = 0;  // first block length zero
    auto f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-bad-compressed-block"));
    EXPECT_EQ(f[0].size, L.stored_size);

    img = L.img;
    img[L.comp_start] = 0xff;
    img[L.comp_start + 1] = 0xff;  // first block past the data
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Magic);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-bad-compressed-block"));

    img = L.img;
    img[L.comp_start + 302] = 0xff;
    img[L.comp_start + 303] = 0xff;  // second block past the data
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-truncated"));
    EXPECT_EQ(f[0].attrs.at("blocks"), "1");
    EXPECT_EQ(f[0].size, img.size());

    img = L.img;
    img[L.comp_start + 10] ^= 0x01;  // stored checksum
    f = scan_ifs(img);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Structural);
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-stored-checksum-bad"));
    EXPECT_EQ(f[0].attrs.at("stored_checksum"), "mismatch");
}

TEST(QnxIfsValidator, TruncatedAtEveryOffsetNeverCrashes) {
    for (const unsigned codec : {0u, 3u}) {
        const Layout L = build(Endian::Little, codec, 3, 100);
        for (std::size_t n = 1; n < L.img.size(); ++n) {
            const Bytes cut(L.img.begin(), L.img.begin() + static_cast<std::ptrdiff_t>(n));
            const auto f = scan_ifs(cut);
            for (const Finding& x : f) EXPECT_LE(x.offset + x.size, n);
        }
    }
}

TEST(QnxIfsValidator, MaxDirEntriesTunable) {
    const Layout L = build();
    SignatureSet s = qnx_ifs_sigs();
    s.signatures[0].extra["max_dir_entries"] = "2";
    const auto f = scan(test::span_of(L.img), s);
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].attrs.at("entries"), "2");
}

// ------------------------------------------------------------------- corpus

TEST(QnxIfsValidatorCorpus, IfsAIsVerifiedUcl) {
    std::shared_ptr<MappedFile> keep;
    const auto slice =
        corpus_slice("qnx-example/flash/UserData.BIN", 0x12800000, 32ull << 20, keep);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    const auto f = scan(*slice, qnx_ifs_sigs());
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].offset, 0u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified) << diags(f[0]);
    EXPECT_EQ(f[0].size, 0x544ea4u);
    EXPECT_EQ(f[0].attrs.at("compressed"), "ucl");
    EXPECT_EQ(f[0].attrs.at("machine"), "aarch64");
    EXPECT_EQ(f[0].attrs.at("blocks"), "196");
    EXPECT_EQ(f[0].attrs.at("startup_size"), "332040");
    EXPECT_EQ(f[0].attrs.at("stored_size"), "5525156");
    EXPECT_EQ(f[0].attrs.at("stored_checksum"), "ok");
    EXPECT_EQ(f[0].attrs.at("startup_checksum"), "mismatch");  // flags2 set after mkifs
    EXPECT_TRUE(has_diag(f[0], "qnx-ifs-startup-checksum-bad"));
    EXPECT_EQ(f[0].diagnostics.size(), 1u) << diags(f[0]);
}

TEST(QnxIfsValidatorCorpus, IfsRecoveryIsVerifiedUcl) {
    std::shared_ptr<MappedFile> keep;
    const auto slice =
        corpus_slice("qnx-example/flash/UserData.BIN", 0x2800000, 256ull << 20, keep);
    if (!slice) GTEST_SKIP() << "corpus image missing";
    const auto f = scan(*slice, qnx_ifs_sigs());
    ASSERT_EQ(f.size(), 1u);
    EXPECT_EQ(f[0].confidence, Confidence::Verified) << diags(f[0]);
    EXPECT_EQ(f[0].size, 0x1af19c0u);
    EXPECT_EQ(f[0].attrs.at("compressed"), "ucl");
    EXPECT_EQ(f[0].attrs.at("stored_checksum"), "ok");
}

TEST(QnxIfsValidatorCorpus, HyundaiSplashMagicsAreRejected) {
    std::shared_ptr<MappedFile> keep;
    const auto part =
        corpus_slice("auto-ivi-example/flash/UserData.BIN", 0x6e904400, 2ull << 20, keep);
    if (!part) GTEST_SKIP() << "corpus image missing";
    ScanOptions raw;
    raw.validate = false;
    EXPECT_EQ(scan(*part, qnx_ifs_sigs(), raw).size(), 2u);  // two magic hits
    EXPECT_TRUE(scan(*part, qnx_ifs_sigs()).empty());        // both rejected
}

}  // namespace
