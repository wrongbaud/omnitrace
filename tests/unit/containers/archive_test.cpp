// archive_test.cpp — the tar and cpio readers, and the two wrapper readers
// (uImage, Android boot).
//
// The archives are built here byte by byte rather than by shelling out, so
// the test is the same on every host and pins the exact layout each reader
// claims to read. Where the system tool exists, run.sh-style parity is left
// to the corpus harness; these cover the shapes and the hostile cases.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"

using namespace omnitrace;
using namespace omnitrace::container;

namespace {

using Bytes = std::vector<std::uint8_t>;

std::unique_ptr<ContainerReader> make(const std::string& format) {
    return ContainerRegistry::instance().create(format);
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

void put(Bytes& b, std::size_t off, const std::string& s) {
    for (std::size_t i = 0; i < s.size() && off + i < b.size(); ++i)
        b[off + i] = static_cast<std::uint8_t>(s[i]);
}

void put_be32(Bytes& b, std::size_t off, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = static_cast<std::uint8_t>(v >> (24 - 8 * i));
}

void put_le32(Bytes& b, std::size_t off, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
}

// ------------------------------------------------------------------ tar

std::string octal(std::uint64_t v, std::size_t width) {
    std::string s;
    for (std::size_t i = 0; i < width - 1; ++i) {
        s = static_cast<char>('0' + (v & 7U)) + s;
        v >>= 3;
    }
    return s + '\0';
}

// One 512-byte ustar header, checksum filled in.
Bytes tar_header(const std::string& name, std::uint64_t size, char typeflag,
                 const std::string& link = {}, const std::string& prefix = {},
                 bool gnu = false) {
    Bytes h(512, 0);
    put(h, 0, name);
    put(h, 100, octal(0644, 8));
    put(h, 108, octal(1000, 8));
    put(h, 116, octal(1000, 8));
    put(h, 124, octal(size, 12));
    put(h, 136, octal(1700000000, 12));
    h[156] = static_cast<std::uint8_t>(typeflag);
    put(h, 157, link);
    put(h, 257, gnu ? "ustar  " : "ustar");
    if (!gnu) put(h, 263, "00");
    put(h, 265, "root");
    put(h, 297, "root");
    put(h, 345, prefix);
    for (std::size_t i = 148; i < 156; ++i) h[i] = static_cast<std::uint8_t>(' ');
    std::uint64_t sum = 0;
    for (const std::uint8_t b : h) sum += b;
    put(h, 148, octal(sum, 8));
    h[154] = static_cast<std::uint8_t>(' ');
    return h;
}

void append(Bytes& out, const Bytes& part) {
    out.insert(out.end(), part.begin(), part.end());
}

void append_data(Bytes& out, const std::string& data) {
    out.insert(out.end(), data.begin(), data.end());
    out.resize((out.size() + 511) / 512 * 512, 0);
}

// ------------------------------------------------------------------ cpio

std::string hex8(std::uint64_t v) {
    static const char* d = "0123456789ABCDEF";
    std::string s(8, '0');
    for (int i = 7; i >= 0; --i) {
        s[static_cast<std::size_t>(i)] = d[v & 0xFU];
        v >>= 4;
    }
    return s;
}

void cpio_member(Bytes& out, const std::string& name, std::uint32_t mode,
                 const std::string& data) {
    std::string h = "070701";
    h += hex8(7);                 // ino
    h += hex8(mode);              // mode
    h += hex8(1000);              // uid
    h += hex8(1000);              // gid
    h += hex8(1);                 // nlink
    h += hex8(1700000000);        // mtime
    h += hex8(data.size());       // filesize
    h += hex8(0) + hex8(0);       // dev
    h += hex8(0) + hex8(0);       // rdev
    h += hex8(name.size() + 1);   // namesize (with NUL)
    h += hex8(0);                 // check
    out.insert(out.end(), h.begin(), h.end());
    out.insert(out.end(), name.begin(), name.end());
    out.push_back(0);
    out.resize((out.size() + 3) / 4 * 4, 0);
    out.insert(out.end(), data.begin(), data.end());
    out.resize((out.size() + 3) / 4 * 4, 0);
}

struct Walked {
    fs::WalkResult r;
    Status st = Status::success();
};

Walked walk_it(ContainerReader& reader, const Limits& lim = {}) {
    Walked w;
    ListingSink sink(true, lim);
    fs::WalkOptions opts;
    opts.limits = lim;
    w.st = reader.walk(sink, opts, w.r);
    return w;
}

const EntryResult* entry_named(const fs::WalkResult& r, const std::string& path) {
    for (const EntryResult& e : r.entries_out) {
        if (e.meta.path == path) return &e;
    }
    return nullptr;
}

bool has_code(const std::vector<Diagnostic>& ds, const std::string& code) {
    for (const Diagnostic& d : ds) {
        if (d.code == code) return true;
    }
    return false;
}

}  // namespace

// ------------------------------------------------------------------- tar

TEST(TarContainer, UstarMembersModesLinksAndDevices) {
    Bytes img;
    append(img, tar_header("etc/", 0, '5'));
    append(img, tar_header("etc/passwd", 11, '0'));
    append_data(img, "root:x:0:0\n");
    append(img, tar_header("bin/sh", 0, '2', "busybox"));
    append(img, tar_header("dev/null", 0, '3'));
    append(img, tar_header("dev/pipe", 0, '6'));
    img.resize(img.size() + 1024, 0);  // two zero blocks

    std::shared_ptr<const Source> keep;
    auto reader = make("tar");
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 5u);
    EXPECT_EQ(w.r.dirs, 1u);
    EXPECT_EQ(w.r.files, 1u);
    EXPECT_EQ(w.r.symlinks, 1u);
    EXPECT_EQ(w.r.others, 2u);

    const EntryResult* etc = entry_named(w.r, "etc");  // the trailing '/' is dropped
    ASSERT_NE(etc, nullptr);
    EXPECT_EQ(etc->meta.kind, EntryKind::Directory);
    const EntryResult* passwd = entry_named(w.r, "etc/passwd");
    ASSERT_NE(passwd, nullptr);
    EXPECT_EQ(passwd->meta.size, 11u);
    EXPECT_EQ(passwd->meta.mode, 0644u);
    EXPECT_EQ(passwd->meta.uid, 1000u);
    EXPECT_EQ(passwd->meta.mtime, 1700000000);
    EXPECT_EQ(passwd->meta.extra.at("uname"), "root");
    const EntryResult* sh = entry_named(w.r, "bin/sh");
    ASSERT_NE(sh, nullptr);
    EXPECT_EQ(sh->meta.kind, EntryKind::Symlink);
    EXPECT_EQ(sh->meta.link_target, "busybox");

    EXPECT_EQ(reader->info().attrs.at("variant"), "ustar");
    EXPECT_EQ(reader->info().size, img.size());
}

TEST(TarContainer, UstarPrefixJoinsTheLongPath) {
    const std::string prefix(120, 'p');
    Bytes img;
    append(img, tar_header("deep.txt", 3, '0', {}, prefix));
    append_data(img, "abc");
    img.resize(img.size() + 1024, 0);
    std::shared_ptr<const Source> keep;
    auto reader = make("tar");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_EQ(w.r.entries_out.size(), 1u);
    EXPECT_EQ(w.r.entries_out[0].meta.path, prefix + "/deep.txt");
}

TEST(TarContainer, GnuLongNameAndLongLinkMembers) {
    const std::string longname(180, 'n');
    const std::string longlink(190, 'l');
    Bytes img;
    append(img, tar_header("././@LongLink", longname.size() + 1, 'L', {}, {}, true));
    append_data(img, longname + '\0');
    append(img, tar_header("placeholder", 4, '0', {}, {}, true));
    append_data(img, "data");
    append(img, tar_header("././@LongLink", longlink.size() + 1, 'K', {}, {}, true));
    append_data(img, longlink + '\0');
    append(img, tar_header("placeholder2", 0, '2', "short", {}, true));
    img.resize(img.size() + 1024, 0);

    std::shared_ptr<const Source> keep;
    auto reader = make("tar");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_EQ(w.r.entries_out.size(), 2u);
    EXPECT_EQ(w.r.entries_out[0].meta.path, longname);
    EXPECT_EQ(w.r.entries_out[0].meta.size, 4u);
    EXPECT_EQ(w.r.entries_out[1].meta.link_target, longlink);
    EXPECT_EQ(reader->info().attrs.at("variant"), "gnu");
}

TEST(TarContainer, PaxRecordsOverrideNameSizeAndOwner) {
    const std::string path(150, 'q');
    auto rec = [](const std::string& kv) {
        // "<len> <kv>\n" where len counts itself.
        for (std::size_t len = kv.size() + 3; len < kv.size() + 8; ++len) {
            const std::string candidate = std::to_string(len) + " " + kv + "\n";
            if (candidate.size() == len) return candidate;
        }
        return std::string{};
    };
    const std::string records = rec("path=" + path) + rec("uid=4242") + rec("mtime=1600000000");
    ASSERT_FALSE(records.empty());

    Bytes img;
    append(img, tar_header("PaxHeaders/x", records.size(), 'x'));
    append_data(img, records);
    append(img, tar_header("short", 5, '0'));
    append_data(img, "hello");
    img.resize(img.size() + 1024, 0);

    std::shared_ptr<const Source> keep;
    auto reader = make("tar");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_EQ(w.r.entries_out.size(), 1u);
    EXPECT_EQ(w.r.entries_out[0].meta.path, path);
    EXPECT_EQ(w.r.entries_out[0].meta.uid, 4242u);
    EXPECT_EQ(w.r.entries_out[0].meta.mtime, 1600000000);
    EXPECT_EQ(reader->info().attrs.at("variant"), "pax");
}

TEST(TarContainer, HardLinkBecomesAnEmptyEntryNamingItsTarget) {
    Bytes img;
    append(img, tar_header("a.txt", 3, '0'));
    append_data(img, "abc");
    append(img, tar_header("b.txt", 0, '1', "a.txt"));
    img.resize(img.size() + 1024, 0);
    std::shared_ptr<const Source> keep;
    auto reader = make("tar");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    const EntryResult* b = entry_named(w.r, "b.txt");
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(b->meta.kind, EntryKind::Regular);
    EXPECT_EQ(b->meta.size, 0u);
    EXPECT_EQ(b->meta.nlink, 2u);
    EXPECT_EQ(b->meta.extra.at("hardlink"), "a.txt");
}

TEST(TarContainer, TruncatedArchiveKeepsWhatItHasAndSaysSo) {
    Bytes img;
    append(img, tar_header("big.bin", 100000, '0'));
    img.resize(img.size() + 4096, 0x41);  // far less than the header claims
    std::shared_ptr<const Source> keep;
    auto reader = make("tar");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_TRUE(w.r.truncated);
    EXPECT_TRUE(has_code(w.r.diagnostics, "tar-truncated"));
}

TEST(TarContainer, EntryLimitStopsTheWalk) {
    Bytes img;
    for (int i = 0; i < 40; ++i) {
        append(img, tar_header("f" + std::to_string(i), 1, '0'));
        append_data(img, "x");
    }
    img.resize(img.size() + 1024, 0);
    std::shared_ptr<const Source> keep;
    auto reader = make("tar");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    Limits lim;
    lim.max_nodes_per_fs = 5;
    const Walked w = walk_it(*reader, lim);
    EXPECT_EQ(w.r.entries, 5u);
    EXPECT_TRUE(w.r.truncated);
    EXPECT_TRUE(has_code(w.r.diagnostics, "tar-limit-entries"));
}

TEST(TarContainer, OpenRejectsWhatIsNotATar) {
    std::shared_ptr<const Source> keep;
    const Bytes junk(1024, 0x5A);
    EXPECT_FALSE(make("tar")->open(span_of(junk, keep)));
}

// ------------------------------------------------------------------ cpio

TEST(CpioContainer, NewcMembersKindsAndSymlink) {
    Bytes img;
    cpio_member(img, "etc", 0040755, "");
    cpio_member(img, "etc/passwd", 0100644, "root:x:0:0\n");
    cpio_member(img, "bin/sh", 0120777, "busybox");
    cpio_member(img, "dev/console", 0020600, "");
    cpio_member(img, "TRAILER!!!", 0, "");
    img.resize((img.size() + 511) / 512 * 512, 0);

    std::shared_ptr<const Source> keep;
    auto reader = make("cpio");
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 4u);
    EXPECT_EQ(w.r.dirs, 1u);
    EXPECT_EQ(w.r.files, 1u);
    EXPECT_EQ(w.r.symlinks, 1u);
    EXPECT_EQ(w.r.others, 1u);

    const EntryResult* passwd = entry_named(w.r, "etc/passwd");
    ASSERT_NE(passwd, nullptr);
    EXPECT_EQ(passwd->meta.mode, 0644u);
    EXPECT_EQ(passwd->meta.size, 11u);
    EXPECT_EQ(passwd->meta.mtime, 1700000000);
    const EntryResult* sh = entry_named(w.r, "bin/sh");
    ASSERT_NE(sh, nullptr);
    EXPECT_EQ(sh->meta.kind, EntryKind::Symlink);
    EXPECT_EQ(sh->meta.link_target, "busybox");
    EXPECT_EQ(entry_named(w.r, "dev/console")->meta.kind, EntryKind::CharDevice);

    EXPECT_EQ(reader->info().attrs.at("variant"), "newc");
    EXPECT_EQ(reader->info().size, img.size());  // padded to the 512-byte block
}

TEST(CpioContainer, LeadingDotSlashIsStripped) {
    Bytes img;
    cpio_member(img, "./etc/motd", 0100644, "hi\n");
    cpio_member(img, "TRAILER!!!", 0, "");
    std::shared_ptr<const Source> keep;
    auto reader = make("cpio");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_EQ(w.r.entries_out.size(), 1u);
    EXPECT_EQ(w.r.entries_out[0].meta.path, "etc/motd");
}

TEST(CpioContainer, NoTrailerIsReportedAndTheEntriesAreKept) {
    Bytes img;
    cpio_member(img, "a", 0100644, "aa");
    cpio_member(img, "b", 0100644, "bb");
    std::shared_ptr<const Source> keep;
    auto reader = make("cpio");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    EXPECT_EQ(w.r.entries, 2u);
    EXPECT_TRUE(w.r.truncated);
    EXPECT_TRUE(has_code(w.r.diagnostics, "cpio-truncated"));
}

TEST(CpioContainer, EntryLimitStopsTheWalk) {
    Bytes img;
    for (int i = 0; i < 40; ++i) cpio_member(img, "f" + std::to_string(i), 0100644, "x");
    cpio_member(img, "TRAILER!!!", 0, "");
    std::shared_ptr<const Source> keep;
    auto reader = make("cpio");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    Limits lim;
    lim.max_nodes_per_fs = 5;
    const Walked w = walk_it(*reader, lim);
    EXPECT_EQ(w.r.entries, 5u);
    EXPECT_TRUE(w.r.truncated);
    EXPECT_TRUE(has_code(w.r.diagnostics, "cpio-limit-entries"));
}

TEST(CpioContainer, OpenRejectsWhatIsNotACpio) {
    std::shared_ptr<const Source> keep;
    const Bytes junk(512, 0x5A);
    EXPECT_FALSE(make("cpio")->open(span_of(junk, keep)));
}

// ---------------------------------------------------------------- uimage

Bytes uimage(std::uint8_t type, const Bytes& payload) {
    Bytes img(64, 0);
    put_be32(img, 0, 0x27051956U);
    put_be32(img, 12, static_cast<std::uint32_t>(payload.size()));
    img[28] = 5;  // linux
    img[29] = 2;  // arm
    img[30] = type;
    img[31] = 0;  // no compression
    put(img, 32, "omnitrace test");
    img.insert(img.end(), payload.begin(), payload.end());
    return img;
}

TEST(UImageContainer, SinglePayload) {
    const Bytes data(5000, 'K');
    const Bytes img = uimage(2, data);
    std::shared_ptr<const Source> keep;
    auto reader = make("uimage");
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_EQ(w.r.entries_out.size(), 1u);
    EXPECT_EQ(w.r.entries_out[0].meta.path, "payload");
    EXPECT_EQ(w.r.entries_out[0].meta.size, data.size());
    EXPECT_EQ(reader->info().size, img.size());
    EXPECT_EQ(reader->info().attrs.at("type"), "kernel");
    EXPECT_EQ(reader->info().attrs.at("image_name"), "omnitrace test");
}

TEST(UImageContainer, MultiFileSplitsOnTheSizeTable) {
    Bytes payload(12, 0);
    put_be32(payload, 0, 10);
    put_be32(payload, 4, 7);
    put_be32(payload, 8, 0);  // terminator
    for (int i = 0; i < 10; ++i) payload.push_back('A');
    payload.resize(payload.size() + 2, 0);  // pad to 4
    for (int i = 0; i < 7; ++i) payload.push_back('B');

    const Bytes img = uimage(4, payload);
    std::shared_ptr<const Source> keep;
    auto reader = make("uimage");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_EQ(w.r.entries_out.size(), 2u);
    EXPECT_EQ(w.r.entries_out[0].meta.path, "image0");
    EXPECT_EQ(w.r.entries_out[0].meta.size, 10u);
    EXPECT_EQ(w.r.entries_out[1].meta.path, "image1");
    EXPECT_EQ(w.r.entries_out[1].meta.size, 7u);
}

TEST(UImageContainer, TruncatedPayloadIsCutAndReported) {
    Bytes img = uimage(2, Bytes(5000, 'K'));
    img.resize(64 + 1000);
    std::shared_ptr<const Source> keep;
    auto reader = make("uimage");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_EQ(w.r.entries_out.size(), 1u);
    EXPECT_EQ(w.r.entries_out[0].meta.size, 1000u);
    EXPECT_TRUE(w.r.truncated);
    EXPECT_TRUE(has_code(w.r.diagnostics, "container-section-truncated"));
}

TEST(UImageContainer, OpenRejectsWhatIsNotAUImage) {
    std::shared_ptr<const Source> keep;
    const Bytes junk(128, 0);
    EXPECT_FALSE(make("uimage")->open(span_of(junk, keep)));
}

// ----------------------------------------------------------- android boot

TEST(AndroidBootContainer, SectionsAreNamedAndPageAligned) {
    constexpr std::uint32_t kPage = 4096;
    constexpr std::uint32_t kKernel = 5000, kRamdisk = 3000, kSecond = 100, kDtb = 200;
    Bytes img(kPage, 0);
    put(img, 0, "ANDROID!");
    put_le32(img, 8, kKernel);
    put_le32(img, 16, kRamdisk);
    put_le32(img, 24, kSecond);
    put_le32(img, 36, kPage);
    put_le32(img, 40, 2);
    put(img, 48, "board");
    put_le32(img, 1632, 0);
    put_le32(img, 1648, kDtb);
    auto section = [&](std::uint32_t n, std::uint8_t fill) {
        const std::size_t pages = (n + kPage - 1) / kPage;
        Bytes sec(pages * kPage, 0);
        for (std::uint32_t i = 0; i < n; ++i) sec[i] = fill;
        img.insert(img.end(), sec.begin(), sec.end());
    };
    section(kKernel, 0xA1);
    section(kRamdisk, 0xB2);
    section(kSecond, 0xC3);
    section(kDtb, 0xD4);

    std::shared_ptr<const Source> keep;
    auto reader = make("android-boot");
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    ASSERT_EQ(w.r.entries_out.size(), 4u);
    EXPECT_EQ(w.r.entries_out[0].meta.path, "kernel");
    EXPECT_EQ(w.r.entries_out[0].meta.size, kKernel);
    EXPECT_EQ(w.r.entries_out[1].meta.path, "ramdisk");
    EXPECT_EQ(w.r.entries_out[1].meta.size, kRamdisk);
    EXPECT_EQ(w.r.entries_out[2].meta.path, "second");
    EXPECT_EQ(w.r.entries_out[3].meta.path, "dtb");
    EXPECT_EQ(reader->info().attrs.at("header_version"), "2");
    EXPECT_EQ(reader->info().attrs.at("board_name"), "board");
    EXPECT_EQ(reader->info().size, img.size());
}

TEST(AndroidBootContainer, EmptySectionsHaveNoEntry) {
    constexpr std::uint32_t kPage = 2048;
    Bytes img(kPage, 0);
    put(img, 0, "ANDROID!");
    put_le32(img, 8, 64);  // kernel only
    put_le32(img, 16, 0);
    put_le32(img, 24, 0);
    put_le32(img, 36, kPage);
    put_le32(img, 40, 0);
    img.resize(img.size() + kPage, 0x11);

    std::shared_ptr<const Source> keep;
    auto reader = make("android-boot");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_EQ(w.r.entries_out.size(), 1u);
    EXPECT_EQ(w.r.entries_out[0].meta.path, "kernel");
}

TEST(AndroidBootContainer, VendorBootUsesItsOwnLayout) {
    constexpr std::uint32_t kPage = 4096;
    constexpr std::uint32_t kRamdisk = 900, kDtb = 300;
    Bytes img(kPage, 0);
    put(img, 0, "VNDRBOOT");
    put_le32(img, 8, 3);      // header_version
    put_le32(img, 12, kPage); // page_size
    put_le32(img, 24, kRamdisk);
    put_le32(img, 2096, 2112);  // header_size
    put_le32(img, 2100, kDtb);
    put(img, 2080, "vb");
    img.resize(img.size() + kPage, 0xE1);  // vendor_ramdisk page
    img.resize(img.size() + kPage, 0xE2);  // dtb page

    std::shared_ptr<const Source> keep;
    auto reader = make("android-vendor-boot");
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_EQ(w.r.entries_out.size(), 2u);
    EXPECT_EQ(w.r.entries_out[0].meta.path, "vendor_ramdisk");
    EXPECT_EQ(w.r.entries_out[0].meta.size, kRamdisk);
    EXPECT_EQ(w.r.entries_out[1].meta.path, "dtb");
    EXPECT_EQ(reader->info().attrs.at("board_name"), "vb");
}

TEST(AndroidBootContainer, UnsupportedHeaderVersionIsRefused) {
    Bytes img(4096, 0);
    put(img, 0, "ANDROID!");
    put_le32(img, 36, 4096);
    put_le32(img, 40, 9);  // no such header version
    std::shared_ptr<const Source> keep;
    EXPECT_FALSE(make("android-boot")->open(span_of(img, keep)));
}

TEST(AndroidBootContainer, OpenRejectsWhatIsNotABootImage) {
    std::shared_ptr<const Source> keep;
    const Bytes junk(4096, 0x5A);
    EXPECT_FALSE(make("android-boot")->open(span_of(junk, keep)));
    EXPECT_FALSE(make("android-vendor-boot")->open(span_of(junk, keep)));
}
