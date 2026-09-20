// stream_test.cpp — the gzip and xz container readers: one "payload" entry,
// the stream's real extent reported back, and hostile input degraded into
// diagnostics rather than a crash or an unbounded allocation.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <zlib.h>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Source.h"
#include "omnitrace/core/Span.h"

using namespace omnitrace;
using namespace omnitrace::container;

namespace {

using Bytes = std::vector<std::uint8_t>;

// A real gzip member, built with zlib so the test never hand-rolls the format.
Bytes gzip_of(const Bytes& raw) {
    z_stream zs{};
    EXPECT_EQ(deflateInit2(&zs, Z_BEST_SPEED, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY), Z_OK);
    Bytes out(deflateBound(&zs, static_cast<uLong>(raw.size())) + 64);
    zs.next_in = const_cast<Bytef*>(raw.data());
    zs.avail_in = static_cast<uInt>(raw.size());
    zs.next_out = out.data();
    zs.avail_out = static_cast<uInt>(out.size());
    EXPECT_EQ(deflate(&zs, Z_FINISH), Z_STREAM_END);
    out.resize(zs.total_out);
    deflateEnd(&zs);
    return out;
}

Bytes text(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

Span span_of(const Bytes& b, std::shared_ptr<const Source>& keep) {
    keep = std::make_shared<MemorySource>(b, "t");
    return Span::whole(keep);
}

// Walks a reader into a ListingSink and returns what it produced.
struct Walked {
    Status status = Status::success();
    fs::WalkResult result;
    std::vector<Bytes> data;
};

std::unique_ptr<ContainerReader> make(const std::string& format) {
    return ContainerRegistry::instance().create(format);
}

}  // namespace

TEST(StreamContainer, RegistryHasTheStreamFormats) {
    const auto formats = ContainerRegistry::instance().formats();
    EXPECT_NE(std::find(formats.begin(), formats.end(), "gzip"), formats.end());
    EXPECT_NE(std::find(formats.begin(), formats.end(), "xz"), formats.end());
    EXPECT_EQ(make("no-such-format"), nullptr);
}

TEST(StreamContainer, GzipEmitsOnePayloadAndItsExtent) {
    const Bytes raw = text(std::string(5000, 'A') + "tail");
    Bytes img = gzip_of(raw);
    const std::uint64_t stream_len = img.size();
    // Trailing bytes after the member: the reader must stop at the stream end,
    // which is the whole point of reporting an extent.
    img.insert(img.end(), 4096, 0xEE);

    std::shared_ptr<const Source> keep;
    auto reader = make("gzip");
    ASSERT_NE(reader, nullptr);
    ASSERT_TRUE(reader->open(span_of(img, keep)));

    ListingSink sink(true, Limits{});
    fs::WalkResult r;
    ASSERT_TRUE(reader->walk(sink, fs::WalkOptions{}, r));

    EXPECT_EQ(r.entries, 1u);
    EXPECT_EQ(r.files, 1u);
    ASSERT_EQ(r.entries_out.size(), 1u);
    EXPECT_EQ(r.entries_out[0].meta.path, "payload");
    EXPECT_EQ(r.entries_out[0].meta.kind, EntryKind::Regular);
    EXPECT_EQ(r.entries_out[0].meta.size, raw.size());
    EXPECT_FALSE(r.entries_out[0].truncated);

    const ContainerInfo info = reader->info();
    EXPECT_EQ(info.format, "gzip");
    EXPECT_EQ(info.compression, "gzip");
    EXPECT_EQ(info.size, stream_len);  // the trailing 0xEE bytes are not claimed
    EXPECT_EQ(info.attrs.at("stream_bytes"), std::to_string(stream_len));
    EXPECT_EQ(info.attrs.at("payload_bytes"), std::to_string(raw.size()));
}

TEST(StreamContainer, ConcatenatedGzipMembersAreOnePayload) {
    const Bytes a = gzip_of(text("first-"));
    const Bytes b = gzip_of(text("second"));
    Bytes img = a;
    img.insert(img.end(), b.begin(), b.end());

    std::shared_ptr<const Source> keep;
    auto reader = make("gzip");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    ListingSink sink(true, Limits{});
    fs::WalkResult r;
    ASSERT_TRUE(reader->walk(sink, fs::WalkOptions{}, r));
    ASSERT_EQ(r.entries_out.size(), 1u);
    EXPECT_EQ(r.entries_out[0].meta.size, 12u);  // "first-second"
    EXPECT_EQ(reader->info().size, img.size());
}

TEST(StreamContainer, PayloadOverTheCapIsCutAndMarked) {
    const Bytes raw(200000, 'z');
    const Bytes img = gzip_of(raw);
    std::shared_ptr<const Source> keep;
    auto reader = make("gzip");
    ASSERT_TRUE(reader->open(span_of(img, keep)));

    Limits lim;
    lim.max_file_bytes = 1024;
    ListingSink sink(true, lim);
    fs::WalkOptions opts;
    opts.limits = lim;
    fs::WalkResult r;
    // A capped payload is still evidence: the walk succeeds and emits what it
    // decoded, marked truncated.
    ASSERT_TRUE(reader->walk(sink, opts, r));
    EXPECT_TRUE(r.truncated);
    ASSERT_EQ(r.entries_out.size(), 1u);
    EXPECT_TRUE(r.entries_out[0].truncated);
    EXPECT_LE(r.entries_out[0].meta.size, 1024u);
    bool saw = false;
    for (const Diagnostic& d : r.diagnostics)
        saw = saw || d.code == "container-limit-file-bytes";
    EXPECT_TRUE(saw);
}

TEST(StreamContainer, CorruptStreamFailsWithADiagnosticAndNoPayload) {
    Bytes img = gzip_of(text(std::string(2000, 'q')));
    std::fill(img.begin() + 12, img.end() - 8, 0x5A);  // wreck the deflate data
    std::shared_ptr<const Source> keep;
    auto reader = make("gzip");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    ListingSink sink(true, Limits{});
    fs::WalkResult r;
    EXPECT_FALSE(reader->walk(sink, fs::WalkOptions{}, r));
    EXPECT_TRUE(r.entries_out.empty());
    bool saw = false;
    for (const Diagnostic& d : r.diagnostics)
        saw = saw || (d.code == "container-decompress-failed" && d.severity == Severity::Error);
    EXPECT_TRUE(saw);
}

TEST(StreamContainer, OpenRejectsWhatIsNotItsFormat) {
    std::shared_ptr<const Source> keep;
    const Bytes junk(64, 0x00);
    EXPECT_FALSE(make("gzip")->open(span_of(junk, keep)));
    EXPECT_FALSE(make("xz")->open(span_of(junk, keep)));

    const Bytes empty;
    std::shared_ptr<const Source> keep2;
    const Status st = make("gzip")->open(span_of(empty, keep2));
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("container-empty"), std::string::npos);

    // A gzip stream is not an xz one and vice versa.
    const Bytes gz = gzip_of(text("hello"));
    std::shared_ptr<const Source> keep3;
    EXPECT_FALSE(make("xz")->open(span_of(gz, keep3)));
}

TEST(StreamContainer, WalkBeforeOpenFails) {
    auto reader = make("gzip");
    ListingSink sink(true, Limits{});
    fs::WalkResult r;
    const Status st = reader->walk(sink, fs::WalkOptions{}, r);
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("container-not-open"), std::string::npos);
}

TEST(StreamContainer, NoExtractStillListsThePayload) {
    const Bytes raw = text(std::string(3000, 'k'));
    const Bytes img = gzip_of(raw);
    std::shared_ptr<const Source> keep;
    auto reader = make("gzip");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    ListingSink sink(false, Limits{});
    fs::WalkOptions opts;
    opts.extract_data = false;
    fs::WalkResult r;
    ASSERT_TRUE(reader->walk(sink, opts, r));
    ASSERT_EQ(r.entries_out.size(), 1u);
    EXPECT_EQ(r.entries_out[0].meta.path, "payload");
    EXPECT_FALSE(r.entries_out[0].written);
    EXPECT_EQ(reader->info().size, img.size());
}

// A stream whose header promises far more than the input holds must fail
// rather than allocate; the cap in the decoder is what bounds it.
TEST(StreamContainer, TruncatedStreamIsRefusedNotAllocated) {
    Bytes img = gzip_of(text(std::string(100000, 'w')));
    img.resize(img.size() / 2);
    std::shared_ptr<const Source> keep;
    auto reader = make("gzip");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    ListingSink sink(true, Limits{});
    fs::WalkResult r;
    EXPECT_FALSE(reader->walk(sink, fs::WalkOptions{}, r));
    EXPECT_TRUE(r.entries_out.empty());
}
