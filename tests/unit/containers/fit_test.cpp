// fit_test.cpp — the FIT container reader.
//
// The trees are built here byte by byte rather than by shelling out to
// mkimage, so the test is the same on every host and pins the exact layout
// the reader claims to read: both payload encodings (inline `data`, and
// external `data-position` / `data-offset`), a payload that is not there, and
// the two shapes that must be refused (a plain device tree, and bytes that
// are not an FDT at all). Parity with `dumpimage -T flat_dt -p N` is covered
// by the corpus harness.
#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Fdt.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"

using namespace omnitrace;
using namespace omnitrace::container;

namespace {

using Bytes = std::vector<std::uint8_t>;

std::unique_ptr<ContainerReader> make_fit() {
    return ContainerRegistry::instance().create("fit");
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

void append(Bytes& out, const Bytes& more) {
    out.insert(out.end(), more.begin(), more.end());
}

void push_be32(Bytes& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>(v >> (24 - 8 * i)));
}

void pad4(Bytes& out) {
    while ((out.size() & 3U) != 0) out.push_back(0);
}

Bytes text(const std::string& s) {
    Bytes b(s.begin(), s.end());
    b.push_back(0);
    return b;
}

// A flattened device tree, assembled token by token. Only what the reader
// reads is built: the memory reservation block is the single terminating
// entry every real producer writes.
class Fdt {
   public:
    void begin_node(const std::string& name) {
        push_be32(struct_, fdt::kBeginNode);
        append(struct_, text(name));
        pad4(struct_);
    }
    void end_node() { push_be32(struct_, fdt::kEndNode); }
    void prop(const std::string& name, const Bytes& value) {
        push_be32(struct_, fdt::kProp);
        push_be32(struct_, static_cast<std::uint32_t>(value.size()));
        push_be32(struct_, string_off(name));
        append(struct_, value);
        pad4(struct_);
    }
    void prop_str(const std::string& name, const std::string& value) { prop(name, text(value)); }
    void prop_u32(const std::string& name, std::uint32_t value) {
        Bytes v;
        push_be32(v, value);
        prop(name, v);
    }

    /// The finished blob. `struct_off()` says where the structure block
    /// landed, which is what an inline `data` property's offset is relative to.
    Bytes finish() {
        Bytes body = struct_;
        push_be32(body, fdt::kEnd);
        Bytes out(40, 0);
        // The reservation block is 8-aligned and ends with a zero entry.
        const std::uint32_t rsv_off = 40;
        out.resize(rsv_off + 16, 0);
        const auto struct_off = static_cast<std::uint32_t>(out.size());
        append(out, body);
        const auto strings_off = static_cast<std::uint32_t>(out.size());
        append(out, strings_);
        const auto total = static_cast<std::uint32_t>(out.size());

        Bytes head;
        push_be32(head, fdt::kMagic);
        push_be32(head, total);
        push_be32(head, struct_off);
        push_be32(head, strings_off);
        push_be32(head, rsv_off);
        push_be32(head, 17);
        push_be32(head, 16);
        push_be32(head, 0);
        push_be32(head, static_cast<std::uint32_t>(strings_.size()));
        push_be32(head, static_cast<std::uint32_t>(body.size()));
        std::copy(head.begin(), head.end(), out.begin());
        return out;
    }

   private:
    std::uint32_t string_off(const std::string& name) {
        const auto it = offsets_.find(name);
        if (it != offsets_.end()) return it->second;
        const auto off = static_cast<std::uint32_t>(strings_.size());
        append(strings_, text(name));
        offsets_[name] = off;
        return off;
    }

    Bytes struct_, strings_;
    std::map<std::string, std::uint32_t> offsets_;
};

struct Walked {
    fs::WalkResult r;
    Status st = Status::success();
};

Walked walk_it(ContainerReader& reader) {
    Walked w;
    const Limits lim;
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

Bytes filled(std::size_t n, std::uint8_t v) {
    return Bytes(n, v);
}

}  // namespace

TEST(FitContainer, InlineImagesBecomeEntriesWithTheirMetadata) {
    Fdt t;
    t.begin_node("");
    t.prop_str("description", "test fit");
    t.begin_node("images");
    t.begin_node("kernel");
    t.prop_str("description", "test kernel");
    t.prop_str("type", "kernel");
    t.prop_str("os", "linux");
    t.prop_str("arch", "arm64");
    t.prop_str("compression", "none");
    t.prop_u32("load", 0x80000);
    t.prop_u32("entry", 0x80000);
    t.prop("data", filled(1000, 0xAA));
    t.end_node();
    t.begin_node("ramdisk");
    t.prop_str("type", "ramdisk");
    t.prop_str("compression", "gzip");
    t.prop("data", filled(7, 0xBB));
    t.end_node();
    t.end_node();  // images
    t.begin_node("configurations");
    t.prop_str("default", "conf");
    t.begin_node("conf");
    t.prop_str("kernel", "kernel");
    t.end_node();
    t.end_node();
    t.end_node();  // root
    const Bytes img = t.finish();

    std::shared_ptr<const Source> keep;
    auto reader = make_fit();
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 2u);
    EXPECT_EQ(w.r.files, 2u);

    const EntryResult* kernel = entry_named(w.r, "kernel");
    ASSERT_NE(kernel, nullptr);
    EXPECT_EQ(kernel->meta.size, 1000u);
    EXPECT_EQ(kernel->digests.bytes, 1000u);
    EXPECT_EQ(kernel->meta.extra.at("type"), "kernel");
    EXPECT_EQ(kernel->meta.extra.at("os"), "linux");
    EXPECT_EQ(kernel->meta.extra.at("arch"), "arm64");
    EXPECT_EQ(kernel->meta.extra.at("description"), "test kernel");
    EXPECT_EQ(kernel->meta.extra.at("load"), "0x80000");
    EXPECT_EQ(kernel->meta.extra.at("entry"), "0x80000");
    EXPECT_EQ(kernel->meta.extra.at("storage"), "inline");

    const EntryResult* rd = entry_named(w.r, "ramdisk");
    ASSERT_NE(rd, nullptr);
    EXPECT_EQ(rd->meta.size, 7u);
    // Emitted as stored: the reader does not unpack what `compression` names,
    // the nested scan does.
    EXPECT_EQ(rd->meta.extra.at("compression"), "gzip");

    const ContainerInfo info = reader->info();
    EXPECT_EQ(info.format, "fit");
    EXPECT_EQ(info.size, img.size());  // inline: totalsize is the whole thing
    EXPECT_EQ(info.attrs.at("image_count"), "2");
    EXPECT_EQ(info.attrs.at("description"), "test fit");
    EXPECT_EQ(info.attrs.at("default_configuration"), "conf");
    EXPECT_EQ(info.attrs.at("version"), "17");
}

TEST(FitContainer, ExternalDataOffsetIsRelativeToTheAlignedTreeEnd) {
    Fdt t;
    t.begin_node("");
    t.begin_node("images");
    t.begin_node("kernel");
    t.prop_u32("data-size", 16);
    t.prop_u32("data-offset", 0);
    t.end_node();
    t.begin_node("fdt");
    t.prop_u32("data-size", 4);
    t.prop_u32("data-offset", 16);
    t.end_node();
    t.end_node();
    t.end_node();
    Bytes img = t.finish();
    // data-offset is relative to the 4-aligned end of the tree, and the
    // strings block does not generally land on a boundary -- mkimage -E pads
    // to 4 before writing the payloads, so this one does too. Asserting the
    // padding is needed is what makes the alignment part of the test.
    ASSERT_NE(img.size() % 4, 0u);
    const std::uint64_t ext_base = (img.size() + 3) & ~std::uint64_t{3};
    img.resize(ext_base, 0);
    append(img, filled(16, 0x11));
    append(img, filled(4, 0x22));

    std::shared_ptr<const Source> keep;
    auto reader = make_fit();
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 2u);
    const EntryResult* kernel = entry_named(w.r, "kernel");
    ASSERT_NE(kernel, nullptr);
    EXPECT_EQ(kernel->meta.size, 16u);
    EXPECT_EQ(kernel->meta.extra.at("storage"), "external");
    EXPECT_EQ(entry_named(w.r, "fdt")->meta.size, 4u);
    // The container runs past totalsize, out to the last payload.
    EXPECT_EQ(reader->info().size, img.size());
}

TEST(FitContainer, DataPositionIsAbsoluteFromTheFitStart) {
    Fdt t;
    t.begin_node("");
    t.begin_node("images");
    t.begin_node("blob");
    t.prop_u32("data-size", 8);
    t.prop_u32("data-position", 0);  // patched below, once the size is known
    t.end_node();
    t.end_node();
    t.end_node();
    Bytes img = t.finish();
    const std::uint32_t at = static_cast<std::uint32_t>(img.size()) + 32;
    // Rebuild with the real position now that the tree's length is known.
    Fdt t2;
    t2.begin_node("");
    t2.begin_node("images");
    t2.begin_node("blob");
    t2.prop_u32("data-size", 8);
    t2.prop_u32("data-position", at);
    t2.end_node();
    t2.end_node();
    t2.end_node();
    img = t2.finish();
    ASSERT_EQ(img.size() + 32, at);
    append(img, filled(32, 0));  // a gap the position skips over
    append(img, filled(8, 0x55));

    std::shared_ptr<const Source> keep;
    auto reader = make_fit();
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    ASSERT_EQ(w.r.entries, 1u);
    const EntryResult* blob = entry_named(w.r, "blob");
    ASSERT_NE(blob, nullptr);
    EXPECT_EQ(blob->digests.bytes, 8u);
    EXPECT_EQ(reader->info().size, img.size());
}

TEST(FitContainer, AnExternalPayloadOutsideTheSpanIsReportedNotInvented) {
    Fdt t;
    t.begin_node("");
    t.begin_node("images");
    t.begin_node("here");
    t.prop("data", filled(4, 0x01));
    t.end_node();
    t.begin_node("gone");
    t.prop_u32("data-size", 4096);
    t.prop_u32("data-offset", 0);
    t.end_node();
    t.end_node();
    t.end_node();
    const Bytes img = t.finish();  // no payload bytes appended at all

    std::shared_ptr<const Source> keep;
    auto reader = make_fit();
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    // The image that is there is still recovered; the one that is not is a
    // diagnostic, never a zero-filled entry.
    EXPECT_EQ(w.r.entries, 1u);
    EXPECT_NE(entry_named(w.r, "here"), nullptr);
    EXPECT_EQ(entry_named(w.r, "gone"), nullptr);
    EXPECT_TRUE(has_code(w.r.diagnostics, "fit-data-missing"));
    EXPECT_TRUE(w.r.truncated);
}

TEST(FitContainer, ImageNamesAreOneHostSafeComponentAndStayDistinct) {
    Fdt t;
    t.begin_node("");
    t.begin_node("images");
    t.begin_node("a/b");
    t.prop("data", filled(2, 0x01));
    t.end_node();
    t.begin_node("a:b");  // collapses to the same component
    t.prop("data", filled(3, 0x02));
    t.end_node();
    t.end_node();
    t.end_node();
    const Bytes img = t.finish();

    std::shared_ptr<const Source> keep;
    auto reader = make_fit();
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    ASSERT_EQ(w.r.entries, 2u);
    // A node name is evidence and must not steer where the Sink writes, and
    // the second must not overwrite the first.
    const EntryResult* first = entry_named(w.r, "a_b");
    const EntryResult* second = entry_named(w.r, "a_b_2");
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(first->meta.size, 2u);
    EXPECT_EQ(second->meta.size, 3u);
}

TEST(FitContainer, ImagesWithNoSubnodesSaysSoRatherThanFailing) {
    Fdt t;
    t.begin_node("");
    t.begin_node("images");
    t.end_node();
    t.end_node();
    const Bytes img = t.finish();

    std::shared_ptr<const Source> keep;
    auto reader = make_fit();
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    const Walked w = walk_it(*reader);
    ASSERT_TRUE(w.st);
    EXPECT_EQ(w.r.entries, 0u);
    EXPECT_TRUE(has_code(w.r.diagnostics, "fit-no-images"));
}

TEST(FitContainer, OpenRefusesAPlainDeviceTree) {
    Fdt t;
    t.begin_node("");
    t.prop_str("model", "some board");
    t.begin_node("memory@0");
    t.prop_u32("reg", 0);
    t.end_node();
    t.end_node();
    const Bytes img = t.finish();

    std::shared_ptr<const Source> keep;
    auto reader = make_fit();
    // A DTB is a structure to report, not a container to walk: without
    // /images there is nothing to extract.
    EXPECT_FALSE(reader->open(span_of(img, keep)));
}

TEST(FitContainer, OpenRejectsWhatIsNotAnFdt) {
    std::shared_ptr<const Source> keep;
    auto reader = make_fit();
    const Bytes junk(256, 0x5A);
    EXPECT_FALSE(reader->open(span_of(junk, keep)));

    // The right magic with an impossible header is refused too: totalsize 0
    // and version 0 describe no tree that could be walked.
    Bytes bad;
    push_be32(bad, fdt::kMagic);
    bad.resize(64, 0);
    EXPECT_FALSE(reader->open(span_of(bad, keep)));
}
