// cramfs_test.cpp — the cramfs reader.
//
// The images here are built in the test, in both byte orders, because the
// interesting part of cramfs is a bitfield layout that flips with endianness
// and a block-pointer table that a hostile image can point anywhere. The
// reader was developed against real `mkfs.cramfs` output (util-linux 2.41) in
// both `-N little` and `-N big`, and reproduced those trees byte for byte;
// what this file adds is the cases mkfs.cramfs will not produce.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <zlib.h>

#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/filesystems/Filesystem.h"

using namespace omnitrace;
using namespace omnitrace::fs;

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint32_t kMagic = 0x28cd3d45U;
constexpr std::size_t kBlockSize = 4096;
constexpr std::uint32_t kModeDir = 0040000U, kModeReg = 0100000U, kModeLink = 0120000U,
                        kModeChr = 0020000U, kModeFifo = 0010000U;

void put32(Bytes& b, std::size_t at, std::uint32_t v, bool le) {
    for (std::size_t i = 0; i < 4; ++i)
        b[at + i] = static_cast<std::uint8_t>(le ? v >> (8 * i) : v >> (24 - 8 * i));
}

void append32(Bytes& b, std::uint32_t v, bool le) {
    b.resize(b.size() + 4);
    put32(b, b.size() - 4, v, le);
}

Bytes deflate_block(const Bytes& in) {
    uLongf cap = compressBound(static_cast<uLong>(in.size())) + 32;
    Bytes out(cap);
    EXPECT_EQ(compress2(out.data(), &cap, in.data(), static_cast<uLong>(in.size()), 9), Z_OK);
    out.resize(cap);
    return out;
}

struct Ent {
    std::string name;
    std::uint32_t mode = kModeReg | 0644U;
    std::uint32_t uid = 0, gid = 0;
    Bytes data;
    std::vector<Ent> children;
    // Filled in by the writer; a test corrupts the image through these.
    mutable std::size_t inode_at = 0;
    mutable std::size_t data_at = 0;
};

Ent reg(std::string name, const std::string& data, std::uint32_t perm = 0644U) {
    Ent n;
    n.name = std::move(name);
    n.mode = kModeReg | perm;
    n.data.assign(data.begin(), data.end());
    return n;
}

Ent reg_bytes(std::string name, Bytes data) {
    Ent n;
    n.name = std::move(name);
    n.mode = kModeReg | 0644U;
    n.data = std::move(data);
    return n;
}

Ent dir_(std::string name, std::vector<Ent> kids, std::uint32_t perm = 0755U) {
    Ent n;
    n.name = std::move(name);
    n.mode = kModeDir | perm;
    n.children = std::move(kids);
    return n;
}

Ent lnk(std::string name, const std::string& target) {
    Ent n;
    n.name = std::move(name);
    n.mode = kModeLink | 0777U;
    n.data.assign(target.begin(), target.end());
    return n;
}

Ent dev(std::string name, std::uint32_t mode) {
    Ent n;
    n.name = std::move(name);
    n.mode = mode | 0644U;
    return n;
}

std::size_t name_field(const std::string& s) {
    return (s.size() + 3) & ~std::size_t{3};  // NUL-padded to a 4-byte unit
}

// Builds an image. Directory data is a run of inodes; a file's data is a
// block-pointer table followed by zlib blocks, each pointer being the offset
// one past its block.
class Writer {
   public:
    explicit Writer(bool little) : le_(little) {}

    Bytes build(std::vector<Ent>& root, const std::string& volume, std::uint32_t flags = 0x3) {
        img_.assign(76, 0);
        // Lay out every directory's inode run, then every file's data, in the
        // order the walk will meet them.
        std::size_t root_size = 0;
        write_dir(root, root_size);
        root_data_ = 76;
        root_size_ = root_size;

        put32(img_, 0, kMagic, le_);
        put32(img_, 4, static_cast<std::uint32_t>(img_.size()), le_);
        put32(img_, 8, flags, le_);
        const std::string sig = "Compressed ROMFS";
        std::copy(sig.begin(), sig.end(), img_.begin() + 16);
        put32(img_, 36, 0, le_);                                    // edition
        put32(img_, 40, static_cast<std::uint32_t>(blocks_), le_);  // blocks
        put32(img_, 44, static_cast<std::uint32_t>(files_), le_);   // files
        for (std::size_t i = 0; i < volume.size() && i < 16; ++i) img_[48 + i] = volume[i];
        write_inode(64, kModeDir | 0755U, 0, 0, root_size_, root_data_, "");
        // The CRC the validator checks: zlib crc32 over the image with the
        // field zeroed.
        put32(img_, 32, 0, le_);
        const std::uint32_t crc = static_cast<std::uint32_t>(
            ::crc32(::crc32(0, nullptr, 0), img_.data(), static_cast<uInt>(img_.size())));
        put32(img_, 32, crc, le_);
        return img_;
    }

   private:
    // An inode's `offset` field counts 4-byte units, so anything an inode
    // points at has to start on a 4-byte boundary. Compressed blocks are
    // arbitrary lengths, so the writer pads before every structure -- which is
    // what mkfs.cramfs does and what this test got wrong first time round.
    void align4() {
        while (img_.size() % 4 != 0) img_.push_back(0);
    }

    // Reserves the inode run for `kids`, then recurses. Returns its byte size.
    void write_dir(std::vector<Ent>& kids, std::size_t& size) {
        align4();
        const std::size_t start = img_.size();
        for (const Ent& k : kids) {
            k.inode_at = img_.size();
            img_.resize(img_.size() + 12 + name_field(k.name));
        }
        size = img_.size() - start;
        for (Ent& k : kids) {
            ++files_;
            if ((k.mode & 0170000U) == kModeDir) {
                std::size_t child_size = 0;
                align4();
                const std::size_t at = img_.size();
                write_dir(k.children, child_size);
                k.data_at = k.children.empty() ? 0 : at;
                write_inode(k.inode_at, k.mode, k.uid, k.gid, child_size, k.data_at, k.name);
            } else if (!k.data.empty()) {
                k.data_at = write_file(k.data);
                write_inode(k.inode_at, k.mode, k.uid, k.gid, k.data.size(), k.data_at, k.name);
            } else {
                write_inode(k.inode_at, k.mode, k.uid, k.gid, 0, 0, k.name);
            }
        }
    }

    std::size_t write_file(const Bytes& data) {
        align4();
        const std::size_t nblocks = (data.size() + kBlockSize - 1) / kBlockSize;
        const std::size_t table = img_.size();
        img_.resize(img_.size() + nblocks * 4);
        for (std::size_t b = 0; b < nblocks; ++b) {
            const std::size_t off = b * kBlockSize;
            const std::size_t n = std::min(kBlockSize, data.size() - off);
            const Bytes comp =
                deflate_block(Bytes(data.begin() + static_cast<std::ptrdiff_t>(off),
                                    data.begin() + static_cast<std::ptrdiff_t>(off + n)));
            img_.insert(img_.end(), comp.begin(), comp.end());
            put32(img_, table + b * 4, static_cast<std::uint32_t>(img_.size()), le_);
            ++blocks_;
        }
        return table;
    }

    void write_inode(std::size_t at, std::uint32_t mode, std::uint32_t uid, std::uint32_t gid,
                     std::size_t size, std::size_t offset, const std::string& name) {
        const std::uint32_t namelen = static_cast<std::uint32_t>(name_field(name) / 4);
        const std::uint32_t off4 = static_cast<std::uint32_t>(offset / 4);
        if (le_) {
            put32(img_, at + 0, (mode & 0xFFFFU) | (uid << 16), true);
            put32(img_, at + 4, (static_cast<std::uint32_t>(size) & 0xFFFFFFU) | (gid << 24), true);
            put32(img_, at + 8, (namelen & 0x3FU) | (off4 << 6), true);
        } else {
            put32(img_, at + 0, (mode << 16) | (uid & 0xFFFFU), false);
            put32(img_, at + 4, (static_cast<std::uint32_t>(size) << 8) | (gid & 0xFFU), false);
            put32(img_, at + 8, (namelen << 26) | (off4 & 0x03FFFFFFU), false);
        }
        for (std::size_t i = 0; i < name.size(); ++i) img_[at + 12 + i] = name[i];
    }

    bool le_;
    Bytes img_;
    std::size_t root_data_ = 0, root_size_ = 0, blocks_ = 0, files_ = 0;
};

std::unique_ptr<FilesystemReader> make() {
    return FilesystemRegistry::instance().create("cramfs");
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

WalkResult walk_image(const Bytes& img, std::unique_ptr<FilesystemReader>& reader,
                      std::shared_ptr<const Source>& keep, Status& open_status,
                      bool extract = true) {
    reader = make();
    WalkResult r;
    open_status = reader->open(span_of(img, keep));
    if (!open_status) return r;
    ListingSink sink(extract, Limits{});
    WalkOptions opts;
    opts.extract_data = extract;
    reader->walk(sink, opts, r);
    return r;
}

std::vector<std::string> paths_of(const WalkResult& r) {
    std::vector<std::string> out;
    for (const EntryResult& e : r.entries_out) out.push_back(e.meta.path);
    std::sort(out.begin(), out.end());
    return out;
}

const EntryResult* find(const WalkResult& r, const std::string& path) {
    for (const EntryResult& e : r.entries_out)
        if (e.meta.path == path) return &e;
    return nullptr;
}

// Every diagnostic on one line, so a failed expectation says why.
std::string diags(const WalkResult& r) {
    std::string out;
    for (const Diagnostic& x : r.diagnostics) out += "\n    [" + x.code + "] " + x.message;
    return out.empty() ? " (no diagnostics)" : out;
}

bool has_code(const std::vector<Diagnostic>& d, const std::string& code) {
    for (const Diagnostic& x : d)
        if (x.code == code) return true;
    return false;
}

}  // namespace

TEST(Cramfs, RegistryHasTheReader) {
    const auto formats = FilesystemRegistry::instance().formats();
    EXPECT_NE(std::find(formats.begin(), formats.end(), "cramfs"), formats.end());
    ASSERT_NE(make(), nullptr);
    EXPECT_EQ(make()->format(), "cramfs");
}

// The same tree in both byte orders must produce the same result, because the
// inode bitfields sit at different bit positions in each and a byte swap alone
// would not do it.
TEST(Cramfs, BothByteOrdersWalkToTheSameTree) {
    for (const bool le : {true, false}) {
        std::vector<Ent> root{
            dir_("etc", {reg("passwd", "root:x:0:0:root:/root:/bin/sh\n", 0600U),
                         reg("hostname", "cramfs-test\n")}),
            dir_("bin", {reg("sh", "#!/bin/sh\n", 0755U), lnk("link", "../etc/passwd")}),
            dir_("empty", {}),
            dev("console", kModeChr),
            dev("pipe", kModeFifo),
        };
        const Bytes img = Writer(le).build(root, "testvol");

        std::unique_ptr<FilesystemReader> reader;
        std::shared_ptr<const Source> keep;
        Status st = Status::success();
        const WalkResult r = walk_image(img, reader, keep, st);
        ASSERT_TRUE(st) << (le ? "little" : "big") << ": " << st.error;

        const FilesystemInfo info = reader->info();
        EXPECT_EQ(info.format, "cramfs");
        EXPECT_EQ(info.label, "testvol");
        EXPECT_EQ(info.compression, "zlib");
        EXPECT_EQ(info.endian, le ? Endian::Little : Endian::Big);

        EXPECT_EQ(paths_of(r),
                  (std::vector<std::string>{"bin", "bin/link", "bin/sh", "console", "empty", "etc",
                                            "etc/hostname", "etc/passwd", "pipe"}))
            << (le ? "little" : "big") << diags(r);

        const EntryResult* passwd = find(r, "etc/passwd");
        ASSERT_NE(passwd, nullptr);
        EXPECT_EQ(passwd->meta.mode, 0600U) << "the mode is read off the image, not synthesised";
        EXPECT_EQ(passwd->meta.size, 30u);
        EXPECT_EQ(passwd->digests.bytes, 30u);

        const EntryResult* sh = find(r, "bin/sh");
        ASSERT_NE(sh, nullptr);
        EXPECT_EQ(sh->meta.mode, 0755U);

        const EntryResult* link = find(r, "bin/link");
        ASSERT_NE(link, nullptr);
        EXPECT_EQ(link->meta.kind, EntryKind::Symlink);
        EXPECT_EQ(link->meta.link_target, "../etc/passwd")
            << "a symlink target is a compressed block like any other";

        EXPECT_EQ(find(r, "console")->meta.kind, EntryKind::CharDevice);
        EXPECT_EQ(find(r, "pipe")->meta.kind, EntryKind::Fifo);
        EXPECT_FALSE(r.truncated);
    }
}

// A file longer than one 4 KiB block exercises the pointer table: block 0 runs
// from the end of the table, every later block from the previous pointer.
TEST(Cramfs, MultiBlockFilesReassembleInOrder) {
    Bytes big(3 * kBlockSize + 1234);
    for (std::size_t i = 0; i < big.size(); ++i)
        big[i] = static_cast<std::uint8_t>((i * 7 + i / 251) & 0xFF);
    std::vector<Ent> root{reg_bytes("big", big), reg("after", "sentinel")};
    const Bytes img = Writer(true).build(root, "v");

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);

    const EntryResult* b = find(r, "big");
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(b->meta.size, big.size());
    EXPECT_EQ(b->digests.bytes, big.size()) << "every block was inflated and kept";
    EXPECT_NE(find(r, "after"), nullptr);
    EXPECT_FALSE(r.truncated) << diags(r);
}

TEST(Cramfs, OpenRejectsWhatIsNotCramfs) {
    std::shared_ptr<const Source> keep;
    EXPECT_FALSE(make()->open(span_of(Bytes(128, 0), keep)));
    EXPECT_FALSE(make()->open(span_of(Bytes{}, keep)));

    // Magic but no signature: the 4-byte magic alone turns up in noise.
    std::vector<Ent> root{reg("a", "1")};
    Bytes img = Writer(true).build(root, "v");
    img[16] ^= 0xFF;
    const Status st = make()->open(span_of(img, keep));
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("cramfs-bad-signature"), std::string::npos) << st.error;
}

TEST(Cramfs, WalkBeforeOpenFails) {
    auto reader = make();
    ListingSink sink(false, Limits{});
    WalkResult r;
    const Status st = reader->walk(sink, WalkOptions{}, r);
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("cramfs-not-open"), std::string::npos);
}

// A directory whose data offset points at a directory already walked is a
// loop; the offsets are raw and nothing in the format forbids it.
TEST(Cramfs, ADirectoryPointingAtAnAncestorIsCut) {
    std::vector<Ent> root{dir_("d", {reg("x", "z")})};
    Bytes img = Writer(true).build(root, "hostile");
    // Point 'd' at the root's own inode run.
    const std::size_t at = root[0].inode_at;
    const std::uint32_t namelen = static_cast<std::uint32_t>(name_field("d") / 4);
    put32(img, at + 8, (namelen & 0x3FU) | ((76U / 4) << 6), true);

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    EXPECT_TRUE(has_code(r.diagnostics, "cramfs-cycle"));
    EXPECT_TRUE(r.truncated);
}

TEST(Cramfs, ADirectoryPointingOutsideTheImageIsRefused) {
    std::vector<Ent> root{dir_("d", {reg("x", "z")})};
    Bytes img = Writer(true).build(root, "oob");
    const std::size_t at = root[0].inode_at;
    const std::uint32_t namelen = static_cast<std::uint32_t>(name_field("d") / 4);
    put32(img, at + 8, (namelen & 0x3FU) | (0x3FFFFFU << 6), true);

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    EXPECT_TRUE(has_code(r.diagnostics, "cramfs-bad-inode"));
    EXPECT_TRUE(r.truncated);
    EXPECT_NE(find(r, "d"), nullptr) << "the directory entry itself is still reported";
}

TEST(Cramfs, ABlockPointerOutsideTheImageIsRefused) {
    std::vector<Ent> root{reg("a", std::string(100, 'x'))};
    Bytes img = Writer(true).build(root, "badptr");
    // The file's data offset is its pointer table; wreck the first pointer.
    put32(img, root[0].data_at, 0xFFFFFF0U, true);

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    EXPECT_TRUE(has_code(r.diagnostics, "cramfs-bad-block"));
    EXPECT_TRUE(r.truncated);
    const EntryResult* a = find(r, "a");
    ASSERT_NE(a, nullptr) << "the entry is still listed with what was recoverable";
    EXPECT_TRUE(a->truncated);
}

TEST(Cramfs, ABlockThatDoesNotInflateIsReportedAndTheFileCutThere) {
    std::vector<Ent> root{reg("a", std::string(200, 'y'))};
    Bytes img = Writer(true).build(root, "badzlib");
    // Wreck the compressed bytes, not the pointers.
    const std::size_t block_start = root[0].data_at + 4;
    for (std::size_t i = 0; i < 8 && block_start + i < img.size(); ++i) img[block_start + i] = 0xAB;

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    EXPECT_TRUE(has_code(r.diagnostics, "cramfs-decompress-failed"));
    EXPECT_TRUE(r.truncated);
}

TEST(Cramfs, NoExtractStillListsEveryEntry) {
    std::vector<Ent> root{dir_("etc", {reg("passwd", "x")})};
    const Bytes img = Writer(true).build(root, "v");

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st, /*extract=*/false);
    ASSERT_TRUE(st);
    EXPECT_EQ(paths_of(r), (std::vector<std::string>{"etc", "etc/passwd"}));
    EXPECT_EQ(find(r, "etc/passwd")->digests.bytes, 0u);
}

TEST(Cramfs, MaxNodesStopsTheWalk) {
    std::vector<Ent> root;
    for (int i = 0; i < 40; ++i) root.push_back(reg("f" + std::to_string(i), "x"));
    const Bytes img = Writer(true).build(root, "many");

    auto reader = make();
    std::shared_ptr<const Source> keep;
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    ListingSink sink(true, Limits{});
    WalkOptions opts;
    opts.limits.max_nodes_per_fs = 10;
    WalkResult r;
    ASSERT_TRUE(reader->walk(sink, opts, r));
    EXPECT_TRUE(has_code(r.diagnostics, "cramfs-limit-nodes"));
    EXPECT_TRUE(r.truncated);
    EXPECT_LE(r.entries, 10u);
}

// EXT_BLOCK_POINTERS changes what a pointer's high bits mean. This build does
// not decode them, and an image that sets the flag has to say so rather than
// quietly produce wrong bytes.
TEST(Cramfs, ExtBlockPointersAreDeclaredUnsupported) {
    std::vector<Ent> root{reg("a", "hello")};
    const Bytes img = Writer(true).build(root, "ext", 0x3 | 0x800);

    std::unique_ptr<FilesystemReader> reader;
    std::shared_ptr<const Source> keep;
    Status st = Status::success();
    const WalkResult r = walk_image(img, reader, keep, st);
    ASSERT_TRUE(st);
    EXPECT_TRUE(has_code(r.diagnostics, "cramfs-unsupported-flags"));
    EXPECT_NE(reader->info().attrs.at("flags").find("ext_block_pointers"), std::string::npos);
}
