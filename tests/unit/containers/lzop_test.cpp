// lzop_test.cpp — the lzop validator and reader.
//
// The files are built here byte by byte rather than by shelling out to lzop,
// so the test is the same on every host. Every block is a *stored* one --
// lzop writes those whenever compressing did not help -- which is what lets
// a test assemble a valid file without an LZO compressor, and still exercise
// the header, the block walk, the checksums and the member chaining. Parity
// with `lzop -d` on genuinely compressed files is covered by the corpus
// harness and recorded in docs/formats/lzop.md.
#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <zlib.h>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Lzop.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/discovery/Signature.h"

using namespace omnitrace;
using namespace omnitrace::container;

namespace {

using Bytes = std::vector<std::uint8_t>;

std::unique_ptr<ContainerReader> make_lzop() {
    return ContainerRegistry::instance().create("lzop");
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

void push_be16(Bytes& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}
void push_be32(Bytes& b, std::uint32_t v) {
    for (int i = 3; i >= 0; --i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}
void push_bytes(Bytes& b, const std::string& s) {
    b.insert(b.end(), s.begin(), s.end());
}

/// One lzop file. Members are appended; blocks are stored (compressed length
/// equal to uncompressed length), which is what lzop itself writes for data
/// that does not compress.
class File {
   public:
    /// Start a member. `flags` picks which checksums its blocks carry.
    void member(const std::string& name, std::uint32_t flags = lzop::kAdler32D,
                std::uint8_t method = lzop::kMethodLzo1x1, std::uint16_t version = 0x1040) {
        flags_ = flags;
        b_.insert(b_.end(), lzop::kMagic.begin(), lzop::kMagic.end());
        Bytes h;
        push_be16(h, version);
        push_be16(h, 0x20A0);  // LZO library version
        if (version >= 0x0940) push_be16(h, 0x0940);
        h.push_back(method);
        if (version >= 0x0940) h.push_back(5);  // level
        push_be32(h, flags);
        push_be32(h, 0100644);   // mode
        push_be32(h, 1700000000);  // mtime low
        if (version >= 0x0940) push_be32(h, 0);
        h.push_back(static_cast<std::uint8_t>(name.size()));
        push_bytes(h, name);
        // The checksum covers the header from the version through the name.
        const std::uint32_t sum =
            (flags & lzop::kHCrc32) != 0
                ? static_cast<std::uint32_t>(::crc32(0UL, h.data(), static_cast<uInt>(h.size())))
                : static_cast<std::uint32_t>(::adler32(1UL, h.data(), static_cast<uInt>(h.size())));
        header_sum_at_ = b_.size() + h.size();
        b_.insert(b_.end(), h.begin(), h.end());
        push_be32(b_, sum);
    }

    /// One stored block holding `data`.
    void block(const std::string& data) {
        const auto* p = reinterpret_cast<const std::uint8_t*>(data.data());
        const auto n = static_cast<std::uint32_t>(data.size());
        push_be32(b_, n);  // uncompressed length
        push_be32(b_, n);  // compressed length: equal, so the block is stored
        if ((flags_ & lzop::kAdler32D) != 0)
            push_be32(b_, static_cast<std::uint32_t>(::adler32(1UL, p, n)));
        if ((flags_ & lzop::kCrc32D) != 0)
            push_be32(b_, static_cast<std::uint32_t>(::crc32(0UL, p, n)));
        // The checksums of the compressed bytes are only written when there
        // are fewer of them, which a stored block never has.
        data_at_ = b_.size();
        push_bytes(b_, data);
    }

    /// The zero length that ends a member.
    void end() { push_be32(b_, 0); }

    void break_header_checksum() { b_[header_sum_at_ + 3] ^= 0xFF; }
    void break_last_block_data() { b_[data_at_] ^= 0x01; }

    const Bytes& bytes() const { return b_; }
    Bytes& bytes() { return b_; }

   private:
    Bytes b_;
    std::uint32_t flags_ = lzop::kAdler32D;
    std::size_t header_sum_at_ = 0, data_at_ = 0;
};

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

std::string sha256_of(const std::string& s) {
    Hasher h;
    h.update(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s.data()),
                                           s.size()));
    return h.finish().sha256;
}

/// One member called "hello.txt" holding one stored block.
File one_member(std::uint32_t flags = lzop::kAdler32D) {
    File f;
    f.member("hello.txt", flags);
    f.block("hello lzop world\n");
    f.end();
    return f;
}

}  // namespace

TEST(LzopContainer, ReadsAStoredBlock) {
    const File f = one_member();
    std::shared_ptr<const Source> keep;
    auto reader = make_lzop();
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(f.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    ASSERT_EQ(w.r.entries, 1u);

    const EntryResult* p = entry_named(w.r, "payload");
    ASSERT_NE(p, nullptr);
    EXPECT_EQ(p->meta.size, 17u);
    EXPECT_EQ(p->digests.sha256, sha256_of("hello lzop world\n"));
    // The name lzop recorded is metadata, never the path a Sink writes to.
    EXPECT_EQ(p->meta.extra.at("original_name"), "hello.txt");
    EXPECT_EQ(p->meta.extra.at("checksum"), "ok");
    EXPECT_EQ(p->meta.extra.at("method"), "lzo1x-1");
    EXPECT_EQ(p->meta.mtime, 1700000000);

    const ContainerInfo i = reader->info();
    EXPECT_EQ(i.format, "lzop");
    EXPECT_EQ(i.compression, "lzo1x-1");
    EXPECT_EQ(i.size, f.bytes().size());
    EXPECT_EQ(i.attrs.at("members"), "1");
    EXPECT_EQ(i.attrs.at("blocks"), "1");
}

TEST(LzopContainer, MembersLaidEndToEndBecomeNumberedPayloads) {
    File f;
    f.member("first.txt");
    f.block("one");
    f.end();
    f.member("second.txt");
    f.block("two");
    f.block("three");
    f.end();

    std::shared_ptr<const Source> keep;
    auto reader = make_lzop();
    ASSERT_TRUE(reader->open(span_of(f.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    ASSERT_EQ(w.r.entries, 2u);
    EXPECT_EQ(entry_named(w.r, "payload0")->digests.sha256, sha256_of("one"));
    // The blocks of one member are one payload, in order.
    EXPECT_EQ(entry_named(w.r, "payload1")->digests.sha256, sha256_of("twothree"));
    EXPECT_EQ(entry_named(w.r, "payload1")->meta.extra.at("original_name"), "second.txt");
    EXPECT_EQ(reader->info().attrs.at("members"), "2");
    EXPECT_EQ(reader->info().size, f.bytes().size());
}

TEST(LzopContainer, ABlockThatFailsItsChecksumIsStillEmittedAndFlagged) {
    File f = one_member();
    f.break_last_block_data();

    std::shared_ptr<const Source> keep;
    auto reader = make_lzop();
    ASSERT_TRUE(reader->open(span_of(f.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* p = entry_named(w.r, "payload");
    ASSERT_NE(p, nullptr);
    // The bytes are what is on the medium and are still recovered; what the
    // entry says is that they are not what lzop compressed.
    EXPECT_EQ(p->digests.bytes, 17u);
    EXPECT_EQ(p->meta.extra.at("checksum"), "mismatch");
    EXPECT_TRUE(has_code(w.r.diagnostics, "lzop-checksum-mismatch"));
}

TEST(LzopContainer, WithoutBlockChecksumsItSaysSoRatherThanOk) {
    // lzop -F writes no per-block checksum, so "ok" would be a claim nothing
    // supports.
    const File f = one_member(/*flags=*/0);
    std::shared_ptr<const Source> keep;
    auto reader = make_lzop();
    ASSERT_TRUE(reader->open(span_of(f.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(entry_named(w.r, "payload")->meta.extra.at("checksum"), "none");
}

TEST(LzopContainer, BothChecksumFlavoursVerify) {
    for (const std::uint32_t flags :
         {lzop::kAdler32D, lzop::kCrc32D, lzop::kAdler32D | lzop::kCrc32D,
          lzop::kAdler32D | lzop::kHCrc32}) {
        const File f = one_member(flags);
        std::shared_ptr<const Source> keep;
        auto reader = make_lzop();
        ASSERT_TRUE(reader->open(span_of(f.bytes(), keep))) << "flags " << flags;
        const Walked w = walk_it(*reader);
        ASSERT_TRUE(w.st);
        const EntryResult* p = entry_named(w.r, "payload");
        ASSERT_NE(p, nullptr) << "flags " << flags;
        EXPECT_EQ(p->digests.sha256, sha256_of("hello lzop world\n")) << "flags " << flags;
        EXPECT_EQ(p->meta.extra.at("checksum"), "ok") << "flags " << flags;
    }
}

TEST(LzopContainer, AMethodThisBuildCannotDecodeIsRefusedNotGuessed) {
    File f;
    f.member("z.txt", lzop::kAdler32D, lzop::kMethodZlib);
    f.block("whatever");
    f.end();

    std::shared_ptr<const Source> keep;
    auto reader = make_lzop();
    ASSERT_TRUE(reader->open(span_of(f.bytes(), keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 0u);
    EXPECT_TRUE(has_code(w.r.diagnostics, "lzop-unsupported-method"));
}

TEST(LzopContainer, OpenRejectsWhatIsNotAnLzopFile) {
    std::shared_ptr<const Source> keep;
    auto reader = make_lzop();
    EXPECT_FALSE(reader->open(span_of(Bytes(256, 0x5A), keep)));
    EXPECT_FALSE(reader->open(span_of(Bytes{}, keep)));

    // The magic with no terminator: the blocks never reach the end of a
    // member, so there is nothing whose extent is known.
    File f;
    f.member("t.txt");
    f.block("data");
    // no end()
    EXPECT_FALSE(reader->open(span_of(f.bytes(), keep)));
}

TEST(LzopValidator, IdentifiesTheFileAndItsExactLength) {
    File f = one_member();
    // Trailing bytes that are not another member: the finding must stop at
    // the terminator, not run on.
    f.bytes().insert(f.bytes().end(), 64, 0xAB);

    std::shared_ptr<const Source> keep;
    const std::vector<discovery::Finding> found =
        discovery::scan(span_of(f.bytes(), keep), discovery::SignatureSet::builtin(), {});
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].format, "lzop");
    EXPECT_EQ(found[0].offset, 0u);
    EXPECT_EQ(found[0].confidence, Confidence::Consistent);
    EXPECT_EQ(found[0].size, f.bytes().size() - 64);
    EXPECT_EQ(found[0].attrs.at("header_checksum"), "ok");
    EXPECT_EQ(found[0].attrs.at("method"), "lzo1x-1");
    EXPECT_EQ(found[0].attrs.at("members"), "1");
    EXPECT_EQ(found[0].attrs.at("payload_bytes"), "17");
    EXPECT_EQ(found[0].attrs.at("original_name"), "hello.txt");
}

TEST(LzopValidator, ADamagedHeaderIsReportedAndNotSized) {
    File f = one_member();
    f.break_header_checksum();

    std::shared_ptr<const Source> keep;
    const std::vector<discovery::Finding> found =
        discovery::scan(span_of(f.bytes(), keep), discovery::SignatureSet::builtin(), {});
    ASSERT_EQ(found.size(), 1u);
    // Nine bytes of magic is not a coincidence, so the hit stands -- but
    // nothing in a header that fails its own checksum can size it.
    EXPECT_EQ(found[0].confidence, Confidence::Magic);
    EXPECT_EQ(found[0].size, 0u);
    EXPECT_EQ(found[0].attrs.at("header_checksum"), "mismatch");
    EXPECT_TRUE(has_code(found[0].diagnostics, "lzop-header-checksum-mismatch"));
}

TEST(LzopValidator, BlocksThatDoNotReachATerminatorLeaveTheExtentUnknown) {
    File f;
    f.member("t.txt");
    f.block("data");
    // No terminator, so the walk runs off the end.

    std::shared_ptr<const Source> keep;
    const std::vector<discovery::Finding> found =
        discovery::scan(span_of(f.bytes(), keep), discovery::SignatureSet::builtin(), {});
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].confidence, Confidence::Structural);
    EXPECT_EQ(found[0].size, 0u);
    // A structure with no extent is never handed to a reader
    // (docs/ARCHITECTURE.md).
    EXPECT_EQ(found[0].attrs.at("extent"), "unknown");
    EXPECT_TRUE(has_code(found[0].diagnostics, "lzop-block-walk-failed"));
}
