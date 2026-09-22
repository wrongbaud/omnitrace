// super_test.cpp — Android logical partitions (super): the shared liblp
// parser in core/Lp.h, the android_super validator's tiers, and the container
// reader that assembles partitions out of extents.
//
// Every image here is built by build_super(), which writes the layout liblp
// defines and computes the three SHA-256 checksums over it. That is the
// weakness of this file and it is worth stating: the builder is this author's
// reading of the format, so a misreading shared by builder and parser would
// pass. The independent check is that the field offsets agree with a
// third-party implementation of the same format (the automotive Android unit's own
// extract_super.py), which is what caught the geometry fields being four
// bytes out. Verification against a real super image is still owed.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Lp.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"

using namespace omnitrace;
using namespace omnitrace::container;

namespace {

using Bytes = std::vector<std::uint8_t>;

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

struct Walked {
    fs::WalkResult r;
    Status st = Status::success();
};

Walked walk_it(ContainerReader& reader) {
    Walked w;
    ListingSink sink(true, Limits{});
    w.st = reader.walk(sink, fs::WalkOptions{}, w.r);
    return w;
}

const EntryResult* entry_named(const fs::WalkResult& r, const std::string& path) {
    for (const EntryResult& e : r.entries_out)
        if (e.meta.path == path) return &e;
    return nullptr;
}

bool has_code(const std::vector<Diagnostic>& ds, const std::string& code) {
    for (const Diagnostic& d : ds)
        if (d.code == code) return true;
    return false;
}

std::string sha_of(const Bytes& b) {
    return Hasher::of(std::span<const std::uint8_t>(b)).sha256;
}

constexpr std::uint64_t kGeo = 4096, kMeta = 12288, kSlotMax = 4096, kSec = 512;

void put32(Bytes& b, std::size_t off, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
}
void put16(Bytes& b, std::size_t off, std::uint16_t v) {
    for (int i = 0; i < 2; ++i) b[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
}
void put64(Bytes& b, std::size_t off, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) b[off + i] = static_cast<std::uint8_t>(v >> (8 * i));
}
void put_name(Bytes& b, std::size_t off, const std::string& s, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) b[off + i] = 0;
    for (std::size_t i = 0; i < s.size() && i < width; ++i)
        b[off + i] = static_cast<std::uint8_t>(s[i]);
}
// SHA-256 of a range, written raw into `at`.
void put_sha(Bytes& b, std::size_t at, std::size_t from, std::size_t len) {
    const Digests d = Hasher::of(std::span<const std::uint8_t>(b.data() + from, len));
    for (std::size_t i = 0; i < 32; ++i) {
        const auto hex = [](char c) -> std::uint8_t {
            return static_cast<std::uint8_t>(c <= '9' ? c - '0' : c - 'a' + 10);
        };
        b[at + i] =
            static_cast<std::uint8_t>((hex(d.sha256[i * 2]) << 4) | hex(d.sha256[i * 2 + 1]));
    }
}

struct Ext {
    std::uint64_t sectors;
    std::uint32_t type;  // 0 linear, 1 zero
    std::uint64_t data;  // source sector
};
struct Part {
    std::string name;
    std::vector<Ext> extents;
};

enum class Damage : std::uint8_t { None, Tables, Geometry, ExtentPastEnd };

// A super image of `dev_size` bytes holding `parts`.
Bytes build_super(const std::vector<Part>& parts, std::uint64_t dev_size,
                  Damage damage = Damage::None) {
    Bytes img(static_cast<std::size_t>(dev_size), 0);

    std::vector<Ext> flat;
    Bytes ptab, etab;
    for (const Part& p : parts) {
        const std::size_t first = flat.size();
        Bytes row(52, 0);
        put_name(row, 0, p.name, 36);
        put32(row, 36, 0);
        put32(row, 40, static_cast<std::uint32_t>(first));
        put32(row, 44, static_cast<std::uint32_t>(p.extents.size()));
        put32(row, 48, 0);
        ptab.insert(ptab.end(), row.begin(), row.end());
        flat.insert(flat.end(), p.extents.begin(), p.extents.end());
    }
    for (const Ext& e : flat) {
        Bytes row(24, 0);
        put64(row, 0, e.sectors);
        put32(row, 8, e.type);
        put64(row, 12, e.data);
        put32(row, 20, 0);
        etab.insert(etab.end(), row.begin(), row.end());
    }
    Bytes gtab(44, 0);
    put_name(gtab, 0, "default", 36);
    put64(gtab, 36, dev_size);
    Bytes dtab(60, 0);
    put64(dtab, 0, 0);
    put32(dtab, 8, 1048576);
    put32(dtab, 12, 0);
    put64(dtab, 16, dev_size);
    put_name(dtab, 24, "super", 36);

    Bytes tables;
    for (const Bytes* t : {&ptab, &etab, &gtab, &dtab})
        tables.insert(tables.end(), t->begin(), t->end());

    constexpr std::size_t kHdr = 128;
    const std::size_t slot = static_cast<std::size_t>(kMeta);
    put32(img, slot, 0x414C5030);
    put16(img, slot + 4, 10);
    put16(img, slot + 6, 2);
    put32(img, slot + 8, kHdr);
    put32(img, slot + 44, static_cast<std::uint32_t>(tables.size()));
    // descriptors: {offset, count, entry_size} x 4
    const std::uint32_t po = 0, eo = static_cast<std::uint32_t>(ptab.size()),
                        go = eo + static_cast<std::uint32_t>(etab.size()),
                        dobj = go + static_cast<std::uint32_t>(gtab.size());
    put32(img, slot + 80, po);
    put32(img, slot + 84, static_cast<std::uint32_t>(parts.size()));
    put32(img, slot + 88, 52);
    put32(img, slot + 92, eo);
    put32(img, slot + 96, static_cast<std::uint32_t>(flat.size()));
    put32(img, slot + 100, 24);
    put32(img, slot + 104, go);
    put32(img, slot + 108, 1);
    put32(img, slot + 112, 44);
    put32(img, slot + 116, dobj);
    put32(img, slot + 120, 1);
    put32(img, slot + 124, 60);
    std::copy(tables.begin(), tables.end(), img.begin() + static_cast<std::ptrdiff_t>(slot + kHdr));
    // Checksum the tables as written, *then* damage them: hashing afterwards
    // would produce a checksum that matches the damage, which is the opposite
    // of what this is for.
    put_sha(img, slot + 48, slot + kHdr, tables.size());
    if (damage == Damage::Tables) img[slot + kHdr] ^= 0xFF;
    for (std::size_t i = 0; i < 32; ++i) img[slot + 12 + i] = 0;
    put_sha(img, slot + 12, slot, kHdr);

    for (const std::uint64_t at : {kGeo, kGeo + 4096}) {
        const std::size_t g = static_cast<std::size_t>(at);
        put32(img, g, 0x616C4467);
        put32(img, g + 4, 52);
        put32(img, g + 40, static_cast<std::uint32_t>(kSlotMax));
        put32(img, g + 44, 2);
        put32(img, g + 48, 4096);
        for (std::size_t i = 0; i < 32; ++i) img[g + 8 + i] = 0;
        put_sha(img, g + 8, g, 52);
        if (damage == Damage::Geometry) img[g + 44] = 0;  // slot_count 0
    }
    return img;
}

// Where a partition's payload can live without colliding with the metadata.
std::uint64_t first_free_sector() {
    return (kMeta + kSlotMax * 4) / kSec;
}

}  // namespace

TEST(SuperParser, ReadsGeometryMetadataAndExtents) {
    const std::uint64_t d = first_free_sector();
    const Bytes img = build_super(
        {{"system_a", {{64, 0, d}}}, {"vendor_a", {{32, 0, d + 64}, {16, 1, 0}}}}, 1u << 20);
    std::shared_ptr<const Source> keep;
    const Span span = span_of(img, keep);
    const auto m = lp::read(span, 0);
    ASSERT_TRUE(m.has_value());
    EXPECT_EQ(m->major_version, 10);
    EXPECT_EQ(m->minor_version, 2);
    EXPECT_EQ(m->geometry.logical_block_size, 4096u);
    ASSERT_EQ(m->partitions.size(), 2u);
    EXPECT_EQ(m->partitions[0].name, "system_a");
    EXPECT_EQ(m->partitions[1].name, "vendor_a");
    EXPECT_EQ(m->partition_size(m->partitions[0]), 64u * kSec);
    // A zero extent counts towards the size: the device reads those bytes.
    EXPECT_EQ(m->partition_size(m->partitions[1]), 48u * kSec);
    EXPECT_EQ(m->device_size(), 1u << 20);

    const lp::Checksums sums = lp::verify(span, 0, *m);
    EXPECT_TRUE(sums.geometry);
    EXPECT_TRUE(sums.header);
    EXPECT_TRUE(sums.tables);
}

TEST(SuperParser, DamagedTablesFailTheirChecksumButStillParse) {
    // The distinction the validator rests on: the map is readable, and known
    // to be untrustworthy. Parsing it is not the same as believing it.
    const std::uint64_t d = first_free_sector();
    const Bytes img = build_super({{"system_a", {{64, 0, d}}}}, 1u << 20, Damage::Tables);
    std::shared_ptr<const Source> keep;
    const Span span = span_of(img, keep);
    const auto m = lp::read(span, 0);
    ASSERT_TRUE(m.has_value());
    const lp::Checksums sums = lp::verify(span, 0, *m);
    EXPECT_TRUE(sums.geometry);
    EXPECT_FALSE(sums.tables);
}

TEST(SuperParser, RejectsAGeometryThatIsNotOne) {
    const std::uint64_t d = first_free_sector();
    std::shared_ptr<const Source> keep;
    Bytes img = build_super({{"system_a", {{64, 0, d}}}}, 1u << 20, Damage::Geometry);
    EXPECT_FALSE(lp::read_geometry(span_of(img, keep), 0).has_value())
        << "a slot count of 0 cannot describe a super";

    // The magic alone, in noise: four bytes at a fixed offset is what an eMMC
    // image produces by accident, and it must yield nothing.
    std::shared_ptr<const Source> keep2;
    Bytes noise(1u << 16);
    for (std::size_t i = 0; i < noise.size(); ++i)
        noise[i] = static_cast<std::uint8_t>((i * 37 + 11) & 0xFF);
    put32(noise, static_cast<std::size_t>(kGeo), 0x616C4467);
    EXPECT_FALSE(lp::read(span_of(noise, keep2), 0).has_value());
}

TEST(SuperParser, RefusesTablesThatRunOutsideTheSlot) {
    const std::uint64_t d = first_free_sector();
    std::shared_ptr<const Source> keep;
    Bytes img = build_super({{"system_a", {{64, 0, d}}}}, 1u << 20);
    // Point the partition table past the end of the metadata slot.
    put32(img, static_cast<std::size_t>(kMeta) + 80, 0xFFFFFF00);
    EXPECT_FALSE(lp::read(span_of(img, keep), 0).has_value());
}

TEST(SuperParser, RefusesAPartitionNamingExtentsThatAreNotThere) {
    const std::uint64_t d = first_free_sector();
    std::shared_ptr<const Source> keep;
    Bytes img = build_super({{"system_a", {{64, 0, d}}}}, 1u << 20);
    // num_extents = 99 with one extent in the table.
    const std::size_t prow = static_cast<std::size_t>(kMeta) + 128;
    put32(img, prow + 44, 99);
    EXPECT_FALSE(lp::read(span_of(img, keep), 0).has_value())
        << "a broken map is not a partition of unknown size";
}

TEST(SuperReader, AssemblesPartitionsFromTheirExtents) {
    const std::uint64_t d = first_free_sector();
    Bytes img = build_super(
        {{"system_a", {{64, 0, d}}}, {"vendor_a", {{32, 0, d + 64}, {16, 1, 0}}}}, 1u << 20);
    const char* tag1 = "SYSTEM_A_PAYLOAD";
    const char* tag2 = "VENDOR_A_PAYLOAD";
    std::memcpy(img.data() + d * kSec, tag1, 16);
    std::memcpy(img.data() + (d + 64) * kSec, tag2, 16);

    auto reader = ContainerRegistry::instance().create("android-super");
    ASSERT_NE(reader, nullptr) << "the reader must be registered and linked in";
    std::shared_ptr<const Source> keep;
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    EXPECT_EQ(reader->info().size, 1u << 20);

    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    ASSERT_EQ(w.r.entries, 2u);

    const EntryResult* sys = entry_named(w.r, "system_a");
    ASSERT_NE(sys, nullptr);
    EXPECT_EQ(sys->digests.bytes, 64u * kSec);
    Bytes want_sys(img.begin() + static_cast<std::ptrdiff_t>(d * kSec),
                   img.begin() + static_cast<std::ptrdiff_t>(d * kSec + 64 * kSec));
    EXPECT_EQ(sys->digests.sha256, sha_of(want_sys));

    // The multi-extent case real evidence does not exercise: a linear extent
    // followed by a zero one, concatenated in order. A zero extent is stored
    // nowhere and must read back as zeros.
    const EntryResult* ven = entry_named(w.r, "vendor_a");
    ASSERT_NE(ven, nullptr);
    EXPECT_EQ(ven->digests.bytes, 48u * kSec);
    Bytes want_ven(img.begin() + static_cast<std::ptrdiff_t>((d + 64) * kSec),
                   img.begin() + static_cast<std::ptrdiff_t>((d + 64) * kSec + 32 * kSec));
    want_ven.resize(48 * kSec, 0);
    EXPECT_EQ(ven->digests.sha256, sha_of(want_ven));
}

TEST(SuperReader, RefusesAMapThatDoesNotVerify) {
    // The romfs lesson: a reader more permissive than its validator turns a
    // guess into bytes on disk.
    const std::uint64_t d = first_free_sector();
    const Bytes img = build_super({{"system_a", {{64, 0, d}}}}, 1u << 20, Damage::Tables);
    auto reader = ContainerRegistry::instance().create("android-super");
    ASSERT_NE(reader, nullptr);
    std::shared_ptr<const Source> keep;
    EXPECT_FALSE(reader->open(span_of(img, keep)));
}

TEST(SuperReader, AnExtentPastTheEndShortensItsEntryAndSaysSo) {
    const std::uint64_t d = first_free_sector();
    // 4096 sectors from d is well past a 1 MiB super.
    const Bytes img = build_super({{"system_a", {{4096, 0, d}}}}, 1u << 20);
    auto reader = ContainerRegistry::instance().create("android-super");
    ASSERT_NE(reader, nullptr);
    std::shared_ptr<const Source> keep;
    ASSERT_TRUE(reader->open(span_of(img, keep)));

    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_TRUE(w.r.truncated);
    EXPECT_TRUE(has_code(w.r.diagnostics, "super-extent-outside"));
}
