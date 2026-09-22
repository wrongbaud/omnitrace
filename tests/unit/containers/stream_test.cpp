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
    for (const Diagnostic& d : r.diagnostics) saw = saw || d.code == "container-limit-file-bytes";
    EXPECT_TRUE(saw);
    // The trailer was never reached, so there is nothing to claim about it.
    EXPECT_EQ(r.entries_out[0].meta.extra.at("checksum"), "unchecked");
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

// A stream the data runs out underneath is not a failed walk. What decoded
// before the end is real evidence and is emitted, marked truncated and
// `unchecked`, the same place a payload cut short by the cap lands.
//
// This test used to assert the opposite -- that such a stream yields nothing.
// The concern it was written for was allocation, not evidence: a header
// promising far more than the input holds must not be believed. That concern
// is unchanged and is still the decoder's cap, asserted below; discarding what
// decoded was never what bounded it. The router-wrt image is what changed the
// answer: a truncated gzip there holds 2837007 bytes of tar with the router's
// OpenSSL libraries in it.
TEST(StreamContainer, TruncatedStreamEmitsWhatDecodedAndStaysBounded) {
    const Bytes raw = text(std::string(100000, 'w'));
    Bytes img = gzip_of(raw);
    img.resize(img.size() / 2);

    std::shared_ptr<const Source> keep;
    auto reader = make("gzip");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    ListingSink sink(true, Limits{});
    fs::WalkResult r;
    ASSERT_TRUE(reader->walk(sink, fs::WalkOptions{}, r));

    ASSERT_EQ(r.entries_out.size(), 1u);
    const EntryResult& e = r.entries_out[0];
    EXPECT_GT(e.meta.size, 0u) << "the bytes that did decode are the point";
    EXPECT_LT(e.meta.size, raw.size()) << "and the payload is incomplete, not whole";
    EXPECT_TRUE(e.truncated);
    EXPECT_TRUE(r.truncated);
    // Never checked against anything: the trailer the check lives in was not
    // in the data. "unchecked" and not "mismatch" -- incomplete, not damaged.
    EXPECT_EQ(e.meta.extra.at("checksum"), "unchecked");
    bool saw = false;
    for (const Diagnostic& d : r.diagnostics)
        saw = saw || (d.code == "container-stream-truncated" && d.severity == Severity::Warning);
    EXPECT_TRUE(saw);

    // The original intent, still held: a header claiming 100000 bytes does not
    // get to allocate them. The cap bounds the payload.
    Limits lim;
    lim.max_file_bytes = 4096;
    auto capped = make("gzip");
    ASSERT_TRUE(capped->open(span_of(img, keep)));
    ListingSink sink2(true, lim);
    fs::WalkOptions opts;
    opts.limits = lim;
    fs::WalkResult r2;
    ASSERT_TRUE(capped->walk(sink2, opts, r2));
    ASSERT_EQ(r2.entries_out.size(), 1u);
    EXPECT_LE(r2.entries_out[0].meta.size, 4096u);
}

// The guard the rule rests on, stated as its own test: a stream that broke
// mid-data with input still to spare yields nothing, however much garbage it
// managed to decode first. Across the corpus every one of the 195 hits the
// validator cannot measure is this case -- 181 of them accidental gzip headers
// in the QNX image's speech data -- and one in the router-wrt image produces 3774806
// bytes before it breaks, so "it decoded a lot" is not evidence of anything.
TEST(StreamContainer, CorruptStreamWithInputToSpareYieldsNothing) {
    // Wreck the deflate data outright, the way the existing corrupt-stream
    // test does, and leave plenty of input behind it. Flipping a single byte
    // is not enough: deflate rides over it and only the CRC notices, which is
    // a different case with a different answer.
    Bytes img = gzip_of(text(std::string(100000, 'w')));
    std::fill(img.begin() + 12, img.end() - 8, 0x5A);
    img.insert(img.end(), 4096, 0x5A);

    std::shared_ptr<const Source> keep;
    auto reader = make("gzip");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    ListingSink sink(true, Limits{});
    fs::WalkResult r;
    EXPECT_FALSE(reader->walk(sink, fs::WalkOptions{}, r));
    EXPECT_TRUE(r.entries_out.empty());
}

// A stream that decoded whole and then failed its own checksum is the one
// failure that still yields evidence: the payload is complete, and it is
// emitted with the mismatch recorded on the entry rather than thrown away.
TEST(StreamContainer, GzipWithABadCrcStillEmitsThePayloadAndSaysSo) {
    const Bytes raw = text(std::string(9000, 'z') + "end");
    Bytes img = gzip_of(raw);
    img[img.size() - 8] ^= 0xFF;  // the CRC-32, not the deflate data

    std::shared_ptr<const Source> keep;
    auto reader = make("gzip");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    ListingSink sink(true, Limits{});
    fs::WalkResult r;
    ASSERT_TRUE(reader->walk(sink, fs::WalkOptions{}, r));

    ASSERT_EQ(r.entries_out.size(), 1u);
    EXPECT_EQ(r.entries_out[0].meta.size, raw.size());  // every byte recovered
    EXPECT_EQ(r.entries_out[0].meta.extra.at("checksum"), "mismatch");
    bool saw = false;
    for (const Diagnostic& d : r.diagnostics)
        saw = saw || (d.code == "container-checksum-mismatch" && d.severity == Severity::Error);
    EXPECT_TRUE(saw);

    const ContainerInfo info = reader->info();
    EXPECT_EQ(info.attrs.at("checksum_kind"), "crc32");
    // zlib stops on the CRC and never reads the ISIZE behind it; the reader
    // must still claim the whole member or the image keeps a four-byte hole.
    EXPECT_EQ(info.size, img.size());
}

// The good case says so too, so "checksum" is a verdict and not just an alarm.
TEST(StreamContainer, AnIntactStreamRecordsThatItsCheckPassed) {
    const Bytes img = gzip_of(text(std::string(4096, 'c')));
    std::shared_ptr<const Source> keep;
    auto reader = make("gzip");
    ASSERT_TRUE(reader->open(span_of(img, keep)));
    ListingSink sink(true, Limits{});
    fs::WalkResult r;
    ASSERT_TRUE(reader->walk(sink, fs::WalkOptions{}, r));
    ASSERT_EQ(r.entries_out.size(), 1u);
    EXPECT_EQ(r.entries_out[0].meta.extra.at("checksum"), "ok");
    EXPECT_EQ(reader->info().attrs.at("checksum_kind"), "crc32");
}
