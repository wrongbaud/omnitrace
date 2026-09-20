// sevenzip_test.cpp — the 7z validator and reader.
//
// The archives are built here byte by byte rather than by shelling out to
// 7-Zip, so the test is the same on every host. Every folder is a Copy one:
// that is a real thing 7-Zip writes (`-m0=Copy`) and it lets a test assemble
// a valid archive without a compressor while still exercising the signature
// header, the variable-length numbers, the folder graph, the substream split
// and the CRCs. Parity with `7z x` on LZMA2, LZMA1, BCJ, Delta, Deflate and
// BZip2 archives is recorded in docs/formats/7z.md.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <zlib.h>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Hash.h"
#include "omnitrace/core/SevenZip.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/discovery/Signature.h"

using namespace omnitrace;
using namespace omnitrace::container;

namespace {

using Bytes = std::vector<std::uint8_t>;

std::unique_ptr<ContainerReader> make_7z() {
    return ContainerRegistry::instance().create("7z");
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

void push_le32(Bytes& b, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}
void push_le64(Bytes& b, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
}

/// The format's variable-length NUMBER. Only the one-byte and two-byte forms
/// are needed here, which is what 7-Zip itself writes for small archives.
void push_num(Bytes& b, std::uint64_t v) {
    if (v < 0x80) {
        b.push_back(static_cast<std::uint8_t>(v));
        return;
    }
    if (v < 0x4000) {
        b.push_back(static_cast<std::uint8_t>(0x80 | (v >> 8)));
        b.push_back(static_cast<std::uint8_t>(v));
        return;
    }
    b.push_back(0xFF);
    push_le64(b, v);
}

std::uint32_t crc_of(const Bytes& b, std::size_t at, std::size_t n) {
    return static_cast<std::uint32_t>(::crc32(0UL, b.data() + at, static_cast<uInt>(n)));
}

/// One file to put in the archive.
struct Member {
    std::string name;
    std::string data;   // empty and `dir` false means an empty file
    bool dir = false;
};

/// A 7z archive of Copy folders, one per member with data.
class Archive {
   public:
    explicit Archive(std::vector<Member> members) : members_(std::move(members)) {}

    /// `encode_header` writes the header as a plain one; 7-Zip normally
    /// compresses it, which this cannot do without a compressor, so the
    /// encoded form is covered by the corpus parity instead.
    Bytes build() {
        Bytes packed;
        std::vector<std::uint64_t> sizes;
        std::vector<std::uint32_t> crcs;
        for (const Member& m : members_) {
            if (m.dir || m.data.empty()) continue;
            const std::size_t at = packed.size();
            packed.insert(packed.end(), m.data.begin(), m.data.end());
            sizes.push_back(m.data.size());
            crcs.push_back(crc_of(packed, at, m.data.size()));
        }

        Bytes h;
        h.push_back(0x01);  // kHeader
        if (!sizes.empty()) {
            h.push_back(0x04);  // kMainStreams
            // PackInfo
            h.push_back(0x06);
            push_num(h, 0);             // PackPos
            push_num(h, sizes.size());  // NumPackStreams
            h.push_back(0x09);          // kSize
            for (const std::uint64_t s : sizes) push_num(h, s);
            h.push_back(0x00);  // kEnd
            // UnpackInfo: one Copy folder per stream
            h.push_back(0x07);
            h.push_back(0x0B);              // kFolder
            push_num(h, sizes.size());      // NumFolders
            h.push_back(0x00);              // not external
            for (std::size_t i = 0; i < sizes.size(); ++i) {
                push_num(h, 1);   // one coder
                h.push_back(0x01);  // id size 1, no attributes, not complex
                h.push_back(0x00);  // Copy
            }
            h.push_back(0x0C);  // kCodersUnpackSize
            for (const std::uint64_t s : sizes) push_num(h, s);
            h.push_back(0x00);  // kEnd
            // SubStreamsInfo: one substream per folder, with its CRC
            h.push_back(0x08);
            h.push_back(0x0A);  // kCRC
            h.push_back(0x01);  // all defined
            for (const std::uint32_t c : crcs) push_le32(h, c);
            h.push_back(0x00);  // kEnd of SubStreamsInfo
            h.push_back(0x00);  // kEnd of StreamsInfo
        }

        // FilesInfo
        h.push_back(0x05);
        push_num(h, members_.size());
        {   // kEmptyStream
            Bytes v;
            std::uint8_t byte = 0, mask = 0x80;
            for (const Member& m : members_) {
                if (m.dir || m.data.empty()) byte |= mask;
                mask = static_cast<std::uint8_t>(mask >> 1);
                if (mask == 0) {
                    v.push_back(byte);
                    byte = 0;
                    mask = 0x80;
                }
            }
            if (mask != 0x80) v.push_back(byte);
            const bool any = std::any_of(members_.begin(), members_.end(),
                                         [](const Member& m) { return m.dir || m.data.empty(); });
            if (any) {
                h.push_back(0x0E);
                push_num(h, v.size());
                h.insert(h.end(), v.begin(), v.end());
                // kEmptyFile marks which of those are files rather than dirs.
                Bytes e;
                std::uint8_t b2 = 0, m2 = 0x80;
                std::size_t count = 0;
                for (const Member& m : members_) {
                    if (!(m.dir || m.data.empty())) continue;
                    if (!m.dir) b2 |= m2;
                    ++count;
                    m2 = static_cast<std::uint8_t>(m2 >> 1);
                    if (m2 == 0) {
                        e.push_back(b2);
                        b2 = 0;
                        m2 = 0x80;
                    }
                }
                if (m2 != 0x80) e.push_back(b2);
                const bool any_file = std::any_of(members_.begin(), members_.end(),
                                                  [](const Member& m) {
                                                      return !m.dir && m.data.empty();
                                                  });
                if (any_file && count != 0) {
                    h.push_back(0x0F);
                    push_num(h, e.size());
                    h.insert(h.end(), e.begin(), e.end());
                }
            }
        }
        {   // kName: UTF-16LE, NUL-terminated, external = 0
            Bytes n;
            n.push_back(0x00);
            for (const Member& m : members_) {
                for (const char c : m.name) {
                    n.push_back(static_cast<std::uint8_t>(c));
                    n.push_back(0);
                }
                n.push_back(0);
                n.push_back(0);
            }
            h.push_back(0x11);
            push_num(h, n.size());
            h.insert(h.end(), n.begin(), n.end());
        }
        h.push_back(0x00);  // kEnd of FilesInfo
        h.push_back(0x00);  // kEnd of Header

        Bytes out;
        out.insert(out.end(), sevenzip::kMagic.begin(), sevenzip::kMagic.end());
        out.push_back(0);  // version major
        out.push_back(4);  // version minor
        push_le32(out, 0); // StartHeaderCRC, filled in below
        push_le64(out, packed.size());  // NextHeaderOffset
        push_le64(out, h.size());       // NextHeaderSize
        push_le32(out, static_cast<std::uint32_t>(
                           ::crc32(0UL, h.data(), static_cast<uInt>(h.size()))));
        const std::uint32_t sh = crc_of(out, 12, 20);
        for (int i = 0; i < 4; ++i) out[8 + i] = static_cast<std::uint8_t>(sh >> (8 * i));
        out.insert(out.end(), packed.begin(), packed.end());
        out.insert(out.end(), h.begin(), h.end());
        return out;
    }

   private:
    std::vector<Member> members_;
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

Bytes simple() {
    return Archive({{"dir", "", true},
                    {"dir/one.txt", "first file\n", false},
                    {"dir/two.bin", "second\n", false},
                    {"dir/empty", "", false}})
        .build();
}

}  // namespace

TEST(SevenZipContainer, ReadsFilesDirectoriesAndEmptyEntries) {
    const Bytes img = simple();
    std::shared_ptr<const Source> keep;
    auto reader = make_7z();
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 4u);
    EXPECT_EQ(w.r.dirs, 1u);
    EXPECT_EQ(w.r.files, 3u);

    const EntryResult* one = entry_named(w.r, "dir/one.txt");
    ASSERT_NE(one, nullptr);
    EXPECT_EQ(one->meta.size, 11u);
    EXPECT_EQ(one->digests.sha256, sha256_of("first file\n"));
    // Every substream carries a CRC, so the entry can say it checked out.
    EXPECT_EQ(one->meta.extra.at("crc"), "ok");
    EXPECT_EQ(entry_named(w.r, "dir/two.bin")->digests.sha256, sha256_of("second\n"));
    EXPECT_EQ(entry_named(w.r, "dir/empty")->meta.size, 0u);
    EXPECT_EQ(entry_named(w.r, "dir")->meta.kind, EntryKind::Directory);

    const ContainerInfo i = reader->info();
    EXPECT_EQ(i.format, "7z");
    EXPECT_EQ(i.size, img.size());
    EXPECT_EQ(i.attrs.at("coders"), "copy");
    EXPECT_EQ(i.attrs.at("folders"), "2");
    EXPECT_EQ(i.attrs.at("entries"), "4");
    EXPECT_EQ(i.attrs.at("header_encoded"), "false");
}

TEST(SevenZipContainer, ACorruptedFileIsEmittedAndFlagged) {
    Bytes img = simple();
    // The packed bytes start right after the 32-byte signature header, and
    // the first folder is a stored one, so this is the file's own data.
    img[sevenzip::kSignatureHeaderSize] ^= 0xFF;

    std::shared_ptr<const Source> keep;
    auto reader = make_7z();
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    const EntryResult* one = entry_named(w.r, "dir/one.txt");
    ASSERT_NE(one, nullptr);
    // The bytes on the medium are still handed over; what the entry says is
    // that they are not what was archived.
    EXPECT_EQ(one->digests.bytes, 11u);
    EXPECT_EQ(one->meta.extra.at("crc"), "mismatch");
    EXPECT_TRUE(has_code(w.r.diagnostics, "7z-crc-mismatch"));
}

TEST(SevenZipContainer, OpenRejectsWhatIsNotAnArchive) {
    std::shared_ptr<const Source> keep;
    auto reader = make_7z();
    EXPECT_FALSE(reader->open(span_of(Bytes(256, 0x5A), keep)));
    EXPECT_FALSE(reader->open(span_of(Bytes{}, keep)));

    // The magic with a start header that does not check out.
    Bytes bad = simple();
    bad[12] ^= 0xFF;
    EXPECT_FALSE(reader->open(span_of(bad, keep)));

    // A header whose CRC does not match.
    Bytes bad2 = simple();
    bad2[bad2.size() - 1] ^= 0xFF;
    EXPECT_FALSE(reader->open(span_of(bad2, keep)));
}

TEST(SevenZipValidator, IdentifiesTheArchiveAndItsExactLength) {
    Bytes img = simple();
    const std::size_t archive_size = img.size();
    img.insert(img.end(), 128, 0xAB);  // trailing bytes that are not part of it

    std::shared_ptr<const Source> keep;
    const std::vector<discovery::Finding> found =
        discovery::scan(span_of(img, keep), discovery::SignatureSet::builtin(), {});
    ASSERT_GE(found.size(), 1u);
    EXPECT_EQ(found[0].format, "7z");
    EXPECT_EQ(found[0].offset, 0u);
    EXPECT_EQ(found[0].confidence, Confidence::Consistent);
    // The start header carries the extent and is CRC-covered, so this is
    // exact rather than a guess.
    EXPECT_EQ(found[0].size, archive_size);
    EXPECT_EQ(found[0].attrs.at("entries"), "4");
    EXPECT_EQ(found[0].attrs.at("files"), "3");
    EXPECT_EQ(found[0].attrs.at("directories"), "1");
    EXPECT_EQ(found[0].attrs.at("coders"), "copy");
    EXPECT_EQ(found[0].attrs.at("unpacked_bytes"), "18");
    EXPECT_EQ(found[0].attrs.at("header_encoded"), "false");
}

TEST(SevenZipValidator, ASixByteMagicWithNoStartHeaderIsNotAnArchive) {
    // The magic alone turns up in other data; without a start header that
    // matches its CRC there is nothing to report.
    Bytes junk(4096, 0x00);
    std::copy(sevenzip::kMagic.begin(), sevenzip::kMagic.end(), junk.begin() + 100);
    std::shared_ptr<const Source> keep;
    const std::vector<discovery::Finding> found =
        discovery::scan(span_of(junk, keep), discovery::SignatureSet::builtin(), {});
    for (const discovery::Finding& f : found) EXPECT_NE(f.format, "7z");
}

TEST(SevenZipValidator, ADamagedHeaderStillGivesTheExtent) {
    Bytes img = simple();
    img[img.size() - 2] ^= 0xFF;  // breaks the header, not the start header

    std::shared_ptr<const Source> keep;
    const std::vector<discovery::Finding> found =
        discovery::scan(span_of(img, keep), discovery::SignatureSet::builtin(), {});
    ASSERT_GE(found.size(), 1u);
    EXPECT_EQ(found[0].format, "7z");
    // The start header is CRC-covered and carries the whole extent, so the
    // archive is still sized and carved even when its header is unreadable.
    EXPECT_EQ(found[0].confidence, Confidence::Structural);
    EXPECT_EQ(found[0].size, img.size());
    EXPECT_TRUE(has_code(found[0].diagnostics, "7z-header-crc-mismatch"));
}

TEST(SevenZipCore, FolderHelpersDescribeWhatCanBeDecoded) {
    auto coder = [](std::initializer_list<std::uint8_t> id) {
        sevenzip::Coder c;
        c.id = std::vector<std::uint8_t>(id);
        return c;
    };
    std::string why;

    sevenzip::Folder copy_only;
    copy_only.coders.push_back(coder({0x00}));
    EXPECT_TRUE(sevenzip::folder_decodable(copy_only, &why));
    EXPECT_FALSE(sevenzip::folder_is_filtered_store(copy_only));

    sevenzip::Folder lzma2_bcj;
    lzma2_bcj.coders.push_back(coder({0x21}));
    lzma2_bcj.coders.push_back(coder({0x03, 0x03, 0x01, 0x03}));
    EXPECT_TRUE(sevenzip::folder_decodable(lzma2_bcj, &why));

    // Copy with a byte filter over it: the bytes are all there, but liblzma
    // has no way to run the filter without a compressor under it.
    sevenzip::Folder copy_bcj;
    copy_bcj.coders.push_back(coder({0x00}));
    copy_bcj.coders.push_back(coder({0x03, 0x03, 0x01, 0x03}));
    why.clear();
    EXPECT_FALSE(sevenzip::folder_decodable(copy_bcj, &why));
    std::string filter;
    EXPECT_TRUE(sevenzip::folder_is_filtered_store(copy_bcj, &filter));
    EXPECT_EQ(filter, "bcj-x86");

    // Deflate and bzip2 work on their own but cannot be chained.
    sevenzip::Folder deflate;
    deflate.coders.push_back(coder({0x04, 0x01, 0x08}));
    EXPECT_TRUE(sevenzip::folder_decodable(deflate, &why));
    sevenzip::Folder deflate_bcj = deflate;
    deflate_bcj.coders.push_back(coder({0x03, 0x03, 0x01, 0x03}));
    why.clear();
    EXPECT_FALSE(sevenzip::folder_decodable(deflate_bcj, &why));
    EXPECT_EQ(why, "deflate");

    sevenzip::Folder ppmd;
    ppmd.coders.push_back(coder({0x03, 0x04, 0x01}));
    why.clear();
    EXPECT_FALSE(sevenzip::folder_decodable(ppmd, &why));
    EXPECT_EQ(why, "ppmd");

    sevenzip::Folder aes;
    aes.coders.push_back(coder({0x06, 0xF1, 0x07, 0x01}));
    why.clear();
    EXPECT_FALSE(sevenzip::folder_decodable(aes, &why));
    EXPECT_EQ(why, "aes256-sha256");

    // BCJ2 takes four inputs, which is a graph rather than a chain.
    sevenzip::Folder bcj2;
    sevenzip::Coder c = coder({0x03, 0x03, 0x01, 0x1B});
    c.num_in = 4;
    bcj2.coders.push_back(c);
    why.clear();
    EXPECT_FALSE(sevenzip::folder_decodable(bcj2, &why));
    EXPECT_NE(why.find("bcj2"), std::string::npos);
}
