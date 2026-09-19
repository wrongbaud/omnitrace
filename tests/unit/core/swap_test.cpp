// swap_test.cpp — SwappedSource (unaligned reads against a reference swap of
// the whole buffer) and detect_word_swap (synthetic swapped firmware, raw
// firmware, random bytes, and the corpus images when present).
#include "omnitrace/core/Swap.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace omnitrace {
namespace {

using Bytes = std::vector<std::uint8_t>;

// Reference: reverse every complete w-byte word; leave a partial tail alone.
Bytes reference_swap(Bytes b, std::size_t w) {
    const std::size_t whole = b.size() - b.size() % w;
    for (std::size_t i = 0; i < whole; i += w)
        std::reverse(b.begin() + static_cast<std::ptrdiff_t>(i),
                     b.begin() + static_cast<std::ptrdiff_t>(i + w));
    return b;
}

Bytes random_bytes(std::size_t n, std::uint64_t seed) {
    std::mt19937_64 rng(seed);
    Bytes b(n);
    for (auto& x : b) x = static_cast<std::uint8_t>(rng());
    return b;
}

std::shared_ptr<const Source> mem(Bytes b, const char* label = "img") {
    return std::make_shared<MemorySource>(std::move(b), label);
}

Bytes read_all(const Source& s, std::uint64_t off, std::size_t n) {
    Bytes out(n);
    out.resize(s.read(off, out));
    return out;
}

void put(Bytes& b, std::size_t off, const char* s) {
    std::memcpy(b.data() + off, s, std::strlen(s));
}
void put_u32le(Bytes& b, std::size_t off, std::uint32_t v) {
    for (std::size_t i = 0; i < 4; ++i)
        b[off + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF);
}

// A 256 KiB firmware-like image: ARM vector table (branches + NOPs), an ELF
// header, and version/banner strings. Everything else is 0xFF (erased flash).
Bytes synthetic_firmware() {
    Bytes b(256u << 10, 0xFF);
    for (std::size_t i = 0; i < 8; ++i)
        put_u32le(b, i * 4, 0xEA000000u | static_cast<std::uint32_t>(0x10 + i));
    for (std::size_t i = 8; i < 16; ++i) put_u32le(b, i * 4, 0xE1A00000u);
    put(b, 0x1000,
        "\x7f"
        "ELF");
    b[0x1004] = 1;  // ELFCLASS32
    b[0x1005] = 1;  // little-endian
    b[0x1006] = 1;  // EV_CURRENT
    put(b, 0x2000, "U-Boot 2020.10 (Sep 19 2026 - 09:00:00 +0000)");
    put(b, 0x2100, "Linux version 5.10.0 (gcc version 10.2.0)");
    put(b, 0x2200, "Preload1 Image test complete");
    put(b, 0x2300, "Copyright (C) 2026 Example Vendor. All Rights Reserved.");
    put(b, 0x2400, "Booting from SPI NOR: partition table at 0x40000");
    return b;
}

const char* corpus_path(const char* rel) {
    static std::string p;
    p = std::string(OMNITRACE_SOURCE_DIR) + "/corpus/" + rel;
    return p.c_str();
}

// ------------------------------------------------------------- SwappedSource

TEST(SwappedSource, IdAndSizeAndNoMap) {
    const auto parent = mem(Bytes(16, 0), "p");
    const SwappedSource s32(parent, SwapKind::Swap32);
    const SwappedSource s16(parent, SwapKind::Swap16);
    const SwappedSource none(parent, SwapKind::None);
    EXPECT_EQ(s32.id(), "mem:p|swap32");
    EXPECT_EQ(s16.id(), "mem:p|swap16");
    EXPECT_EQ(none.id(), "mem:p");
    EXPECT_EQ(s32.size(), 16u);
    EXPECT_EQ(s32.kind(), SwapKind::Swap32);
    EXPECT_EQ(s32.parent().get(), parent.get());
    EXPECT_TRUE(s32.map(0, 16).empty());
    EXPECT_TRUE(s32.map(0, 4).empty());
}

TEST(SwappedSource, NullParentAndEmpty) {
    const SwappedSource s(nullptr, SwapKind::Swap32);
    EXPECT_EQ(s.size(), 0u);
    EXPECT_EQ(s.id(), "|swap32");
    std::uint8_t buf[8];
    EXPECT_EQ(s.read(0, buf), 0u);
    const SwappedSource e(mem({}, "e"), SwapKind::Swap16);
    EXPECT_EQ(e.read(0, buf), 0u);
    EXPECT_EQ(e.read(0, std::span<std::uint8_t>{}), 0u);
}

TEST(SwappedSource, WholeBufferMatchesReference) {
    const Bytes original = random_bytes(4096, 1);
    for (const auto [kind, w] : {std::pair{SwapKind::Swap16, std::size_t{2}},
                                 std::pair{SwapKind::Swap32, std::size_t{4}}}) {
        const SwappedSource s(mem(original), kind);
        EXPECT_EQ(read_all(s, 0, original.size()), reference_swap(original, w));
    }
}

TEST(SwappedSource, UnalignedReadsMatchReferenceProperty) {
    for (const std::size_t size : {std::size_t{4096}, std::size_t{4097}, std::size_t{4099}}) {
        const Bytes original = random_bytes(size, size);
        for (const auto [kind, w] : {std::pair{SwapKind::Swap16, std::size_t{2}},
                                     std::pair{SwapKind::Swap32, std::size_t{4}}}) {
            const Bytes ref = reference_swap(original, w);
            const SwappedSource s(mem(original), kind);
            std::mt19937_64 rng(size * w);
            for (int i = 0; i < 2000; ++i) {
                const std::size_t off = static_cast<std::size_t>(rng() % (size + 8));
                const std::size_t len = static_cast<std::size_t>(rng() % 1200);
                const Bytes got = read_all(s, off, len);
                const std::size_t expect_len = off >= size ? 0 : std::min(len, size - off);
                ASSERT_EQ(got.size(), expect_len) << "off=" << off << " len=" << len;
                ASSERT_TRUE(std::equal(got.begin(), got.end(),
                                       ref.begin() + static_cast<std::ptrdiff_t>(off)))
                    << "off=" << off << " len=" << len << " w=" << w;
            }
        }
    }
}

TEST(SwappedSource, TrailingPartialWordPassesThrough) {
    Bytes b = {1, 2, 3, 4, 5, 6, 7};
    const SwappedSource s(mem(b), SwapKind::Swap32);
    EXPECT_EQ(read_all(s, 0, 7), (Bytes{4, 3, 2, 1, 5, 6, 7}));
    EXPECT_EQ(read_all(s, 4, 10), (Bytes{5, 6, 7}));
    EXPECT_EQ(read_all(s, 6, 1), (Bytes{7}));
    const SwappedSource s16(mem(b), SwapKind::Swap16);
    EXPECT_EQ(read_all(s16, 0, 7), (Bytes{2, 1, 4, 3, 6, 5, 7}));
}

TEST(SwappedSource, LargeReadUsesHeapPath) {
    const Bytes original = random_bytes(3u << 20, 7);
    const SwappedSource s(mem(original), SwapKind::Swap32);
    const Bytes ref = reference_swap(original, 4);
    const Bytes got = read_all(s, 1, (2u << 20) + 3);
    ASSERT_EQ(got.size(), (2u << 20) + 3);
    EXPECT_TRUE(std::equal(got.begin(), got.end(), ref.begin() + 1));
}

TEST(SwappedSource, SpanOverSwappedViewReadsIntegers) {
    Bytes b(8, 0);
    put_u32le(b, 0, 0x11223344);  // bytes 44 33 22 11 -> swapped: 11 22 33 44
    const Span sp = Span::whole(std::make_shared<SwappedSource>(mem(b), SwapKind::Swap32));
    EXPECT_EQ(sp.source_id(), "mem:img|swap32");
    EXPECT_EQ(sp.at<std::uint32_t>(0, Endian::Big), 0x11223344u);
    EXPECT_EQ(sp.at<std::uint32_t>(0, Endian::Little), 0x44332211u);
    EXPECT_FALSE(sp.view(0, 4).has_value());  // no zero-copy mapping
    EXPECT_TRUE(sp.bytes(0, 4).has_value());
}

// ---------------------------------------------------------- detect_word_swap

TEST(DetectWordSwap, NamesAndEmpty) {
    EXPECT_STREQ(swap_kind_name(SwapKind::None), "none");
    EXPECT_STREQ(swap_kind_name(SwapKind::Swap16), "swap16");
    EXPECT_STREQ(swap_kind_name(SwapKind::Swap32), "swap32");
    const SwapDetection d = detect_word_swap(Span{});
    EXPECT_EQ(d.kind, SwapKind::None);
    EXPECT_EQ(d.confidence, 0);
    EXPECT_FALSE(d.evidence.empty());
}

TEST(DetectWordSwap, SyntheticStoredSwap32) {
    const Bytes fw = synthetic_firmware();
    const SwapDetection d = detect_word_swap(Span::whole(mem(reference_swap(fw, 4))));
    EXPECT_EQ(d.kind, SwapKind::Swap32) << d.evidence;
    EXPECT_GE(d.confidence, 60) << d.evidence;
    EXPECT_NE(d.evidence.find("swap32"), std::string::npos);
    EXPECT_NE(d.evidence.find("magics"), std::string::npos);
    EXPECT_NE(d.evidence.find("ASCII runs"), std::string::npos);
}

TEST(DetectWordSwap, SyntheticStoredSwap16) {
    const Bytes fw = synthetic_firmware();
    const SwapDetection d = detect_word_swap(Span::whole(mem(reference_swap(fw, 2))));
    EXPECT_EQ(d.kind, SwapKind::Swap16) << d.evidence;
    EXPECT_GE(d.confidence, 60) << d.evidence;
}

TEST(DetectWordSwap, SyntheticRawIsNone) {
    const SwapDetection d = detect_word_swap(Span::whole(mem(synthetic_firmware())));
    EXPECT_EQ(d.kind, SwapKind::None) << d.evidence;
    EXPECT_EQ(d.confidence, 0);
    EXPECT_NE(d.evidence.find("unambiguous known magics"), std::string::npos) << d.evidence;
}

TEST(DetectWordSwap, StringsOnlyWithoutMagicsIsNoneInRaw) {
    // Text alone never vetoes and never claims on its own unless the swapped
    // view reads clearly better; a raw text image must stay raw.
    Bytes b(64u << 10, 0);
    put(b, 0x100, "hostname=router\nwifi_ssid=Example Network\npassword=hunter2\n");
    put(b, 0x200, "Boot Reason: Power On Reset\nUptime Counter: 0\n");
    const SwapDetection d = detect_word_swap(Span::whole(mem(b)));
    EXPECT_EQ(d.kind, SwapKind::None) << d.evidence;
}

TEST(DetectWordSwap, RandomBytesIsNone) {
    for (const std::uint64_t seed : {11u, 12u, 13u}) {
        const SwapDetection d = detect_word_swap(Span::whole(mem(random_bytes(1u << 20, seed))));
        EXPECT_EQ(d.kind, SwapKind::None) << d.evidence;
        EXPECT_EQ(d.confidence, 0);
    }
}

TEST(DetectWordSwap, ErasedFlashIsNone) {
    const SwapDetection d = detect_word_swap(Span::whole(mem(Bytes(1u << 20, 0xFF))));
    EXPECT_EQ(d.kind, SwapKind::None) << d.evidence;
}

TEST(DetectWordSwap, BudgetBoundsWorkAndStaysDeterministic) {
    const Bytes fw = reference_swap(synthetic_firmware(), 4);
    Bytes big;
    for (int i = 0; i < 8; ++i) big.insert(big.end(), fw.begin(), fw.end());  // 2 MiB
    const auto src = mem(big);
    const SwapDetection full = detect_word_swap(Span::whole(src));
    const SwapDetection small = detect_word_swap(Span::whole(src), 256u << 10);
    EXPECT_EQ(full.kind, SwapKind::Swap32) << full.evidence;
    EXPECT_EQ(small.kind, SwapKind::Swap32) << small.evidence;
    EXPECT_NE(small.evidence.find("262144 sampled bytes"), std::string::npos) << small.evidence;
    EXPECT_NE(full.evidence.find("2097152 sampled bytes"), std::string::npos) << full.evidence;
    EXPECT_EQ(detect_word_swap(Span::whole(src)).evidence, full.evidence);
}

// ------------------------------------------------------------------- corpus

TEST(DetectWordSwap, CorpusMx25l165dIsSwap32) {
    const char* path = corpus_path("auto-ivi-example/flash/MX25L165D.bin");
    if (!std::filesystem::exists(path)) GTEST_SKIP() << "corpus image missing: " << path;
    std::shared_ptr<MappedFile> file;
    ASSERT_TRUE(MappedFile::open(path, file));
    const SwapDetection d = detect_word_swap(Span::whole(file));
    EXPECT_EQ(d.kind, SwapKind::Swap32) << d.evidence;
    EXPECT_GE(d.confidence, 85) << d.evidence;

    const auto view = std::make_shared<SwappedSource>(file, SwapKind::Swap32);
    const Bytes all = read_all(*view, 0, static_cast<std::size_t>(view->size()));
    ASSERT_EQ(all.size(), file->size());
    const std::string text(all.begin(), all.end());
    // The task brief read this as "[Preload1 Image test"; the corrected bytes
    // say "[Preloader 1st Image empty]" (raw: "erP[daol1 reI tsegampme").
    EXPECT_NE(text.find("[Preloader 1st Image empty]"), std::string::npos);
    EXPECT_NE(text.find("SNOR_ROM"), std::string::npos);
    const Bytes raw = read_all(*file, 0, static_cast<std::size_t>(file->size()));
    const std::string raw_text(raw.begin(), raw.end());
    EXPECT_EQ(raw_text.find("Preloader"), std::string::npos);
    EXPECT_NE(raw_text.find("erP[daol"), std::string::npos);
}

TEST(DetectWordSwap, CorpusRouterIsNone) {
    const char* path = corpus_path("router-example/flash/router.bin");
    if (!std::filesystem::exists(path)) GTEST_SKIP() << "corpus image missing: " << path;
    std::shared_ptr<MappedFile> file;
    ASSERT_TRUE(MappedFile::open(path, file));
    const SwapDetection d = detect_word_swap(Span::whole(file));
    EXPECT_EQ(d.kind, SwapKind::None) << d.evidence;
    EXPECT_EQ(d.confidence, 0);
}

}  // namespace
}  // namespace omnitrace
