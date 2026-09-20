// ubi_test.cpp — the UBI volume reassembly reader.
//
// The images are built here PEB by PEB rather than by shelling out to
// ubinize, so the test is the same on every host and pins what the reader
// claims: LEBs placed by their lnum and not by where they sit on the medium,
// static volumes cut to their declared size, the newest copy of a rewritten
// block winning, gaps filled rather than silently closed, and volume names
// coming from the layout volume. Parity with `ubireader_extract_images` is
// covered by the corpus harness.
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "../../../src/discovery/crc32.h"
#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"

using namespace omnitrace;
using namespace omnitrace::container;

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint64_t kPeb = 4096;   // small, so a test image is a few KiB
constexpr std::uint32_t kVidOff = 512;
constexpr std::uint32_t kDataOff = 1024;
constexpr std::uint64_t kLeb = kPeb - kDataOff;  // 3072
// UBI's internal volume holding the volume table. Written out rather than
// taken from the reader's header, so the test pins the value the format
// defines instead of echoing whatever the reader believes.
constexpr std::uint32_t kLayoutVolume = 0x7FFFEFFFU;

std::unique_ptr<ContainerReader> make_ubi() {
    return ContainerRegistry::instance().create("ubi");
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

template <class T>
void put_be(Bytes& b, std::size_t off, T v) {
    for (std::size_t i = 0; i < sizeof(T); ++i)
        b[off + i] = static_cast<std::uint8_t>(v >> (8 * (sizeof(T) - 1 - i)));
}
void put_be16(Bytes& b, std::size_t off, std::uint16_t v) { put_be<std::uint16_t>(b, off, v); }
void put_be32(Bytes& b, std::size_t off, std::uint32_t v) { put_be<std::uint32_t>(b, off, v); }
void put_be64(Bytes& b, std::size_t off, std::uint64_t v) { put_be<std::uint64_t>(b, off, v); }

// UBI headers carry crc32 with init 0xFFFFFFFF and no final xor, over the
// 60 bytes before the field.
void seal(Bytes& b, std::size_t at) {
    put_be32(b, at + 60,
             discovery::crc32_ubi(std::span<const std::uint8_t>(b.data() + at, 60)));
}

struct Vid {
    std::uint32_t vol_id = 0;
    std::uint32_t lnum = 0;
    bool is_static = false;
    std::uint32_t data_size = 0;
    std::uint32_t used_ebs = 0;
    std::uint64_t sqnum = 0;
    bool copy_flag = false;
};

/// A UBI image of `pebs` erase blocks, all erased (0xFF) until filled in.
class Image {
   public:
    explicit Image(std::size_t pebs) : bytes_(pebs * kPeb, 0xFF) {}

    /// Write an EC header into `peb`, with no VID header: an unmapped block.
    void ec(std::size_t peb) {
        const std::size_t at = peb * kPeb;
        std::fill(bytes_.begin() + static_cast<std::ptrdiff_t>(at),
                  bytes_.begin() + static_cast<std::ptrdiff_t>(at + kDataOff), 0xFF);
        put_be32(bytes_, at, 0x55424923);  // "UBI#"
        bytes_[at + 4] = 1;
        put_be64(bytes_, at + 8, 42);
        put_be32(bytes_, at + 16, kVidOff);
        put_be32(bytes_, at + 20, kDataOff);
        put_be32(bytes_, at + 24, 0xABCDEF01);
        for (std::size_t i = 28; i < 60; ++i) bytes_[at + i] = 0;
        seal(bytes_, at);
    }

    /// An EC header plus a VID header naming a volume and a logical block,
    /// with `fill` repeated through the block's data area.
    void leb(std::size_t peb, const Vid& v, std::uint8_t fill) {
        ec(peb);
        const std::size_t at = peb * kPeb + kVidOff;
        for (std::size_t i = 0; i < 64; ++i) bytes_[at + i] = 0;
        put_be32(bytes_, at, 0x55424921);  // "UBI!"
        bytes_[at + 4] = 1;
        bytes_[at + 5] = v.is_static ? 2 : 1;
        bytes_[at + 6] = v.copy_flag ? 1 : 0;
        bytes_[at + 7] = 0;
        put_be32(bytes_, at + 8, v.vol_id);
        put_be32(bytes_, at + 12, v.lnum);
        put_be32(bytes_, at + 20, v.data_size);
        put_be32(bytes_, at + 24, v.used_ebs);
        put_be32(bytes_, at + 28, 0);  // data_pad
        put_be64(bytes_, at + 40, v.sqnum);
        seal(bytes_, at);
        const std::size_t data = peb * kPeb + kDataOff;
        std::fill(bytes_.begin() + static_cast<std::ptrdiff_t>(data),
                  bytes_.begin() + static_cast<std::ptrdiff_t>(data + kLeb), fill);
    }

    /// One volume-table record inside the layout volume's LEB in `peb`.
    void vtbl_record(std::size_t peb, std::size_t index, const std::string& name,
                     bool is_static) {
        const std::size_t at = peb * kPeb + kDataOff + index * 172;
        for (std::size_t i = 0; i < 172; ++i) bytes_[at + i] = 0;
        put_be32(bytes_, at, 8);      // reserved_pebs, non-zero = a real volume
        put_be32(bytes_, at + 4, 1);  // alignment
        put_be32(bytes_, at + 8, 0);  // data_pad
        bytes_[at + 12] = is_static ? 2 : 1;
        put_be16(bytes_, at + 14, static_cast<std::uint16_t>(name.size()));
        for (std::size_t i = 0; i < name.size(); ++i)
            bytes_[at + 16 + i] = static_cast<std::uint8_t>(name[i]);
        put_be32(bytes_, at + 168,
                 discovery::crc32_ubi(std::span<const std::uint8_t>(bytes_.data() + at, 168)));
    }

    const Bytes& bytes() const { return bytes_; }

   private:
    Bytes bytes_;
};

struct Walked {
    fs::WalkResult r;
    Status st = Status::success();
};

Walked walk_it(ContainerReader& reader, bool history = false) {
    Walked w;
    const Limits lim;
    ListingSink sink(true, lim);
    fs::WalkOptions opts;
    opts.limits = lim;
    opts.history = history;
    w.st = reader.walk(sink, opts, w.r);
    return w;
}

const EntryResult* entry_named(const fs::WalkResult& r, const std::string& path) {
    for (const EntryResult& e : r.entries_out) {
        if (e.meta.path == path) return &e;
    }
    return nullptr;
}

/// The SHA-256 of `blocks` concatenated, to compare against what the Sink
/// hashed: the reader's entry is only right if its *bytes* are in LEB order,
/// not just its length.
std::string sha256_of(const std::vector<std::pair<std::uint8_t, std::uint64_t>>& blocks) {
    Hasher h;
    for (const auto& [fill, len] : blocks) {
        const Bytes b(static_cast<std::size_t>(len), fill);
        h.update(std::span<const std::uint8_t>(b.data(), b.size()));
    }
    return h.finish().sha256;
}

bool has_code(const std::vector<Diagnostic>& ds, const std::string& code) {
    for (const Diagnostic& d : ds) {
        if (d.code == code) return true;
    }
    return false;
}

/// A two-volume image: the layout volume in PEBs 0-1, then the data.
Image two_volumes() {
    Image img(8);
    img.leb(0, Vid{kLayoutVolume, 0, false, 0, 0, 1, false}, 0xFF);
    img.leb(1, Vid{kLayoutVolume, 1, false, 0, 0, 2, false}, 0xFF);
    for (std::size_t peb : {std::size_t{0}, std::size_t{1}}) {
        img.vtbl_record(peb, 0, "rootfs", false);
        img.vtbl_record(peb, 1, "cfg", true);
    }
    return img;
}

}  // namespace

TEST(UbiContainer, LebsArePlacedByTheirNumberNotTheirBlock) {
    Image img = two_volumes();
    // Deliberately out of order on the medium, which is what wear levelling
    // does: PEB 2 holds LEB 2, PEB 3 holds LEB 0, PEB 4 holds LEB 1.
    img.leb(2, Vid{0, 2, false, 0, 0, 30, false}, 0xC2);
    img.leb(3, Vid{0, 0, false, 0, 0, 10, false}, 0xC0);
    img.leb(4, Vid{0, 1, false, 0, 0, 20, false}, 0xC1);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubi();
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);

    const EntryResult* rootfs = entry_named(w.r, "rootfs");
    ASSERT_NE(rootfs, nullptr);
    EXPECT_EQ(rootfs->meta.size, 3 * kLeb);
    EXPECT_EQ(rootfs->meta.extra.at("vol_id"), "0");
    EXPECT_EQ(rootfs->meta.extra.at("vol_type"), "dynamic");
    EXPECT_EQ(rootfs->meta.extra.at("lebs"), "3");
    EXPECT_EQ(rootfs->meta.extra.at("leb_size"), std::to_string(kLeb));
    // LEB 0, then 1, then 2 -- the order the volume has, not PEB 2, 3, 4.
    EXPECT_EQ(rootfs->digests.sha256, sha256_of({{0xC0, kLeb}, {0xC1, kLeb}, {0xC2, kLeb}}));

    const ContainerInfo info = reader->info();
    EXPECT_EQ(info.format, "ubi");
    EXPECT_EQ(info.attrs.at("peb_size"), std::to_string(kPeb));
    EXPECT_EQ(info.attrs.at("leb_size"), std::to_string(kLeb));
    EXPECT_EQ(info.attrs.at("image_seq"), std::to_string(0xABCDEF01U));
    // The layout volume is read for names but is not a volume of its own.
    EXPECT_EQ(info.attrs.at("volumes"), "1");
    EXPECT_EQ(info.attrs.at("volume_table"), "0:rootfs:dynamic:3");
}

TEST(UbiContainer, AStaticVolumeIsCutToItsDeclaredDataSize) {
    Image img = two_volumes();
    img.leb(2, Vid{1, 0, true, static_cast<std::uint32_t>(kLeb), 2, 10, false}, 0xA0);
    img.leb(3, Vid{1, 1, true, 100, 2, 11, false}, 0xA1);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubi();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* cfg = entry_named(w.r, "cfg");
    ASSERT_NE(cfg, nullptr);
    // A dynamic volume would be 2 * kLeb; a static one stops where its last
    // block says the data stops.
    EXPECT_EQ(cfg->meta.size, kLeb + 100);
    EXPECT_EQ(cfg->digests.bytes, kLeb + 100);
    EXPECT_EQ(cfg->digests.sha256, sha256_of({{0xA0, kLeb}, {0xA1, 100}}));
    EXPECT_EQ(cfg->meta.extra.at("vol_type"), "static");
}

TEST(UbiContainer, TheNewestCopyOfARewrittenBlockWins) {
    Image img = two_volumes();
    img.leb(2, Vid{0, 0, false, 0, 0, 10, false}, 0xAA);  // the old copy
    img.leb(3, Vid{0, 1, false, 0, 0, 11, false}, 0xBB);
    img.leb(4, Vid{0, 0, false, 0, 0, 99, true}, 0xCC);   // rewritten, higher sqnum

    std::shared_ptr<const Source> keep;
    auto reader = make_ubi();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* rootfs = entry_named(w.r, "rootfs");
    ASSERT_NE(rootfs, nullptr);
    EXPECT_EQ(rootfs->meta.size, 2 * kLeb);  // two LEBs, not three
    EXPECT_EQ(rootfs->digests.sha256, sha256_of({{0xCC, kLeb}, {0xBB, kLeb}}));
    EXPECT_EQ(w.r.entries, 1u);
    // Without --history the old copy is reported, not dropped in silence.
    EXPECT_TRUE(has_code(w.r.diagnostics, "ubi-leb-superseded"));
    EXPECT_EQ(w.r.superseded, 0u);
}

TEST(UbiContainer, HistoryEmitsTheSupersededBlock) {
    Image img = two_volumes();
    img.leb(2, Vid{0, 0, false, 0, 0, 10, false}, 0xAA);
    img.leb(3, Vid{0, 0, false, 0, 0, 99, true}, 0xCC);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubi();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader, /*history=*/true);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 2u);
    EXPECT_EQ(w.r.superseded, 1u);
    const EntryResult* old = entry_named(w.r, "rootfs.leb0.sqnum10");
    ASSERT_NE(old, nullptr);
    EXPECT_TRUE(old->meta.superseded);
    EXPECT_EQ(old->meta.version, 10u);
    EXPECT_EQ(old->meta.size, kLeb);
    EXPECT_EQ(old->digests.sha256, sha256_of({{0xAA, kLeb}}));  // the pre-update bytes
    EXPECT_EQ(old->meta.extra.at("lnum"), "0");
    EXPECT_EQ(old->meta.extra.at("peb"), "2");
}

TEST(UbiContainer, AMissingBlockIsFilledSoTheOnesAfterItKeepTheirOffset) {
    Image img = two_volumes();
    img.leb(2, Vid{0, 0, false, 0, 0, 10, false}, 0x11);
    // No LEB 1 anywhere.
    img.leb(3, Vid{0, 2, false, 0, 0, 12, false}, 0x33);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubi();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* rootfs = entry_named(w.r, "rootfs");
    ASSERT_NE(rootfs, nullptr);
    // Three blocks long even though only two are present: LEB 2 must still
    // land where a filesystem on the volume expects it.
    EXPECT_EQ(rootfs->meta.size, 3 * kLeb);
    // The gap reads as erased flash, so LEB 2's bytes still start at 2 * kLeb.
    EXPECT_EQ(rootfs->digests.sha256, sha256_of({{0x11, kLeb}, {0xFF, kLeb}, {0x33, kLeb}}));
    EXPECT_TRUE(rootfs->truncated);
    EXPECT_TRUE(has_code(w.r.diagnostics, "ubi-leb-gap"));
    EXPECT_TRUE(w.r.truncated);
}

TEST(UbiContainer, WithoutAVolumeTableVolumesAreNamedByTheirId) {
    Image img(6);  // no layout volume at all
    img.leb(0, Vid{0, 0, false, 0, 0, 10, false}, 0x11);
    img.leb(1, Vid{7, 0, false, 0, 0, 11, false}, 0x22);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubi();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 2u);
    EXPECT_NE(entry_named(w.r, "vol0"), nullptr);
    EXPECT_NE(entry_named(w.r, "vol7"), nullptr);
    EXPECT_TRUE(has_code(w.r.diagnostics, "ubi-vtbl-unreadable"));
}

TEST(UbiContainer, AnUnmappedBlockIsCountedAndClaimedByNoVolume) {
    Image img = two_volumes();
    img.leb(2, Vid{0, 0, false, 0, 0, 10, false}, 0x11);
    img.ec(3);  // erased and returned to the pool: EC header, no VID header

    std::shared_ptr<const Source> keep;
    auto reader = make_ubi();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(entry_named(w.r, "rootfs")->meta.size, kLeb);
    EXPECT_EQ(reader->info().attrs.at("unmapped_pebs"), "1");
    EXPECT_FALSE(has_code(w.r.diagnostics, "ubi-leb-gap"));
}

TEST(UbiContainer, ALogicalBlockPastTheEndOfTheImageIsDropped) {
    Image img = two_volumes();
    img.leb(2, Vid{0, 0, false, 0, 0, 10, false}, 0x11);
    // A volume cannot have more logical blocks than the image has physical
    // ones. Believing this header would ask the gap fill for four billion
    // erased blocks before it wrote a byte of evidence.
    img.leb(3, Vid{0, 0xFFFFFFFE, false, 0, 0, 11, false}, 0x22);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubi();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* rootfs = entry_named(w.r, "rootfs");
    ASSERT_NE(rootfs, nullptr);
    EXPECT_EQ(rootfs->meta.size, kLeb);  // LEB 0 only
    EXPECT_TRUE(has_code(w.r.diagnostics, "ubi-bad-peb"));
}

TEST(UbiContainer, AnImageWithNoVolumeSaysSoRatherThanFailing) {
    Image img(4);
    img.ec(0);
    img.ec(1);

    std::shared_ptr<const Source> keep;
    auto reader = make_ubi();
    ASSERT_TRUE(reader->open(span_of(img.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 0u);
    EXPECT_TRUE(has_code(w.r.diagnostics, "ubi-no-volumes"));
}

TEST(UbiContainer, OpenRejectsWhatIsNotAUbiImage) {
    std::shared_ptr<const Source> keep;
    auto reader = make_ubi();
    const Bytes junk(4096, 0x5A);
    EXPECT_FALSE(reader->open(span_of(junk, keep)));

    // The magic with a broken CRC is refused: a corrupt first block cannot
    // anchor the walk that finds the erase-block size.
    Image img = two_volumes();
    Bytes bad = img.bytes();
    bad[60] ^= 0xFF;
    EXPECT_FALSE(reader->open(span_of(bad, keep)));

    // A lone PEB has no second EC header, so the block size is unknowable.
    Bytes one(img.bytes().begin(), img.bytes().begin() + kPeb);
    EXPECT_FALSE(reader->open(span_of(one, keep)));
}
