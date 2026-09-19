// text_test.cpp — UTF-8 sanitizing (Unicode Table 3-7 vectors), UTF-16LE
// decoding of fixed-width fields, and host-safe filename components.
#include "omnitrace/core/Text.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace omnitrace {
namespace {

std::string bytes(std::initializer_list<int> v) {
    std::string s;
    for (const int b : v) s.push_back(static_cast<char>(b));
    return s;
}

std::vector<std::uint8_t> u8(std::initializer_list<int> v) {
    std::vector<std::uint8_t> out;
    for (const int b : v) out.push_back(static_cast<std::uint8_t>(b));
    return out;
}

TEST(Text, ValidSequencesPassThrough) {
    const std::string ascii = "plain ASCII 0123 !@#";
    const std::string two = bytes({0xC2, 0xB5});               // U+00B5 MICRO SIGN
    const std::string three = bytes({0xE2, 0x82, 0xAC});       // U+20AC EURO SIGN
    const std::string four = bytes({0xF0, 0x9F, 0x98, 0x80});  // U+1F600
    const std::string max = bytes({0xF4, 0x8F, 0xBF, 0xBF});   // U+10FFFF
    const std::string e0 = bytes({0xE0, 0xA0, 0x80});          // U+0800, smallest 3-byte
    const std::string ed = bytes({0xED, 0x9F, 0xBF});          // U+D7FF, just below surrogates
    const std::string ee = bytes({0xEE, 0x80, 0x80});          // U+E000, just above surrogates
    const std::string f0 = bytes({0xF0, 0x90, 0x80, 0x80});    // U+10000, smallest 4-byte
    for (const std::string& s : {ascii, two, three, four, max, e0, ed, ee, f0}) {
        EXPECT_EQ(sanitize_utf8(s), s);
        EXPECT_TRUE(is_clean_utf8(s));
    }
    const std::string mixed = "a" + two + "b" + three + "c" + four + "\t\n\r";
    EXPECT_EQ(sanitize_utf8(mixed), mixed);
    EXPECT_TRUE(is_clean_utf8(mixed));
    EXPECT_EQ(sanitize_utf8(""), "");
    EXPECT_TRUE(is_clean_utf8(""));
}

TEST(Text, RejectsOverlongForms) {
    EXPECT_EQ(sanitize_utf8(bytes({0xC0, 0x80})), "\\xc0\\x80");             // overlong NUL
    EXPECT_EQ(sanitize_utf8(bytes({0xC1, 0xBF})), "\\xc1\\xbf");             // overlong U+007F
    EXPECT_EQ(sanitize_utf8(bytes({0xE0, 0x80, 0x80})), "\\xe0\\x80\\x80");  // overlong 3-byte
    EXPECT_EQ(sanitize_utf8(bytes({0xE0, 0x9F, 0xBF})), "\\xe0\\x9f\\xbf");  // overlong U+07FF
    EXPECT_EQ(sanitize_utf8(bytes({0xF0, 0x80, 0x80, 0x80})), "\\xf0\\x80\\x80\\x80");
    EXPECT_EQ(sanitize_utf8(bytes({0xF0, 0x8F, 0xBF, 0xBF})), "\\xf0\\x8f\\xbf\\xbf");
    EXPECT_FALSE(is_clean_utf8(bytes({0xC0, 0x80})));
}

TEST(Text, RejectsSurrogates) {
    EXPECT_EQ(sanitize_utf8(bytes({0xED, 0xA0, 0x80})), "\\xed\\xa0\\x80");  // U+D800
    EXPECT_EQ(sanitize_utf8(bytes({0xED, 0xBF, 0xBF})), "\\xed\\xbf\\xbf");  // U+DFFF
    EXPECT_FALSE(is_clean_utf8(bytes({0xED, 0xA0, 0x80})));
}

TEST(Text, RejectsAboveMaxCodePoint) {
    EXPECT_EQ(sanitize_utf8(bytes({0xF4, 0x90, 0x80, 0x80})), "\\xf4\\x90\\x80\\x80");  // U+110000
    EXPECT_EQ(sanitize_utf8(bytes({0xF5, 0x80, 0x80, 0x80})), "\\xf5\\x80\\x80\\x80");
    EXPECT_EQ(sanitize_utf8(bytes({0xF8, 0x88, 0x80, 0x80, 0x80})), "\\xf8\\x88\\x80\\x80\\x80");
    EXPECT_EQ(sanitize_utf8(bytes({0xFE})), "\\xfe");
    EXPECT_EQ(sanitize_utf8(bytes({0xFF})), "\\xff");
}

TEST(Text, RejectsTruncatedSequences) {
    EXPECT_EQ(sanitize_utf8(bytes({0xE2, 0x82})), "\\xe2\\x82");
    EXPECT_EQ(sanitize_utf8(bytes({0xE2, 0x82, 'A'})), "\\xe2\\x82A");
    EXPECT_EQ(sanitize_utf8(bytes({0xC2})), "\\xc2");
    EXPECT_EQ(sanitize_utf8(bytes({0xF0, 0x9F, 0x98})), "\\xf0\\x9f\\x98");
    EXPECT_EQ(sanitize_utf8("ok" + bytes({0xF0, 0x9F})), "ok\\xf0\\x9f");
    // A valid sequence right after a truncated one is kept intact.
    EXPECT_EQ(sanitize_utf8(bytes({0xE2, 0xC2, 0xB5})), "\\xe2" + bytes({0xC2, 0xB5}));
}

TEST(Text, RejectsLoneContinuationAndRawLatin1) {
    EXPECT_EQ(sanitize_utf8(bytes({0x80})), "\\x80");
    EXPECT_EQ(sanitize_utf8(bytes({0xBF})), "\\xbf");
    // The byte that crashed the JSON emitter on the QNX corpus image.
    EXPECT_EQ(sanitize_utf8(bytes({'n', 'a', 'm', 'e', 0xB5})), "name\\xb5");
    EXPECT_EQ(sanitize_utf8(bytes({0xB5, 0xB5})), "\\xb5\\xb5");
    EXPECT_FALSE(is_clean_utf8(bytes({0xB5})));
}

TEST(Text, ControlCharacters) {
    EXPECT_EQ(sanitize_utf8(std::string("a\0b", 3)), "a\\x00b");
    EXPECT_EQ(sanitize_utf8("\x01\x1f"), "\\x01\\x1f");
    EXPECT_EQ(sanitize_utf8("\x1b[0m"), "\\x1b[0m");
    // \t \n \r are kept; DEL and C1 controls are not C0 and pass through.
    EXPECT_EQ(sanitize_utf8("a\tb\nc\r"), "a\tb\nc\r");
    EXPECT_EQ(sanitize_utf8("\x7f"), "\x7f");
    EXPECT_EQ(sanitize_utf8(bytes({0xC2, 0x85})), bytes({0xC2, 0x85}));
    EXPECT_FALSE(is_clean_utf8(std::string("\0", 1)));
    EXPECT_FALSE(is_clean_utf8("\x1b"));
    EXPECT_TRUE(is_clean_utf8("a\tb\nc\r"));
}

TEST(Text, Idempotent) {
    const std::string hostile =
        bytes({0xB5, 0xC0, 0x80, 0xED, 0xA0, 0x80, 0xE2, 0x82, 0x00, 0x01, 0xFF}) + "tail" +
        bytes({0xE2, 0x82, 0xAC});
    const std::string once = sanitize_utf8(hostile);
    EXPECT_TRUE(is_clean_utf8(once));
    EXPECT_EQ(sanitize_utf8(once), once);
    EXPECT_EQ(sanitize_utf8(sanitize_utf8(once)), once);
    EXPECT_NE(once.find("\\xb5"), std::string::npos);
    EXPECT_NE(once.find("\\x00"), std::string::npos);
}

TEST(Text, SpanOverloadMatchesStringView) {
    const std::vector<std::uint8_t> v = u8({'a', 0xB5, 0xE2, 0x82, 0xAC, 0x00});
    const std::string s(reinterpret_cast<const char*>(v.data()), v.size());
    EXPECT_EQ(sanitize_utf8(std::span<const std::uint8_t>(v)), sanitize_utf8(s));
    EXPECT_EQ(sanitize_utf8(std::span<const std::uint8_t>(v)),
              "a\\xb5" + bytes({0xE2, 0x82, 0xAC}) + "\\x00");
    EXPECT_EQ(sanitize_utf8(std::span<const std::uint8_t>()), "");
}

TEST(Text, Utf16leBasic) {
    // "EFI" then NUL padding, as a GPT partition name field.
    const auto v = u8({'E', 0, 'F', 0, 'I', 0, 0, 0, 'X', 0});
    EXPECT_EQ(utf16le_to_utf8(v), "EFI");
    EXPECT_EQ(utf16le_to_utf8(std::span<const std::uint8_t>()), "");
    EXPECT_EQ(utf16le_to_utf8(u8({0, 0})), "");
    // BMP code points: U+00B5 and U+20AC.
    EXPECT_EQ(utf16le_to_utf8(u8({0xB5, 0x00, 0xAC, 0x20})), bytes({0xC2, 0xB5, 0xE2, 0x82, 0xAC}));
}

TEST(Text, Utf16leSurrogatePairAndEmbeddedNul) {
    // U+1F600 is D83D DE00 in UTF-16.
    const auto pair = u8({'a', 0, 0x3D, 0xD8, 0x00, 0xDE, 'b', 0});
    EXPECT_EQ(utf16le_to_utf8(pair), "a" + bytes({0xF0, 0x9F, 0x98, 0x80}) + "b");
    // An embedded NUL terminates the field; whatever follows is padding/garbage.
    const auto nul = u8({'a', 0, 0, 0, 'z', 0, 0x3D, 0xD8});
    EXPECT_EQ(utf16le_to_utf8(nul), "a");
    // A lone high surrogate, a lone low surrogate, and a high surrogate followed
    // by a non-surrogate are shown as raw bytes rather than dropped.
    EXPECT_EQ(utf16le_to_utf8(u8({0x3D, 0xD8})), "\\x3d\\xd8");
    EXPECT_EQ(utf16le_to_utf8(u8({0x00, 0xDE})), "\\x00\\xde");
    EXPECT_EQ(utf16le_to_utf8(u8({0x3D, 0xD8, 'b', 0})), "\\x3d\\xd8b");
    // An odd trailing byte is escaped, and control code units are sanitized.
    EXPECT_EQ(utf16le_to_utf8(u8({'a', 0, 0xB5})), "a\\xb5");
    EXPECT_EQ(utf16le_to_utf8(u8({0x01, 0, 'a', 0})), "\\x01a");
    for (const auto& v : {pair, nul}) EXPECT_TRUE(is_clean_utf8(utf16le_to_utf8(v)));
}

TEST(Text, SafeFilenameComponent) {
    EXPECT_EQ(safe_filename_component("../etc:passwd"), "_etc_passwd");
    EXPECT_EQ(safe_filename_component(".."), "unnamed");
    EXPECT_EQ(safe_filename_component("."), "unnamed");
    EXPECT_EQ(safe_filename_component(""), "unnamed");
    EXPECT_EQ(safe_filename_component("///"), "_");
    EXPECT_EQ(safe_filename_component("a/b\\c:d*e?f\"g<h>i|j"), "a_b_c_d_e_f_g_h_i_j");
    EXPECT_EQ(safe_filename_component("a///b"), "a_b");
    EXPECT_EQ(safe_filename_component("a___b"), "a_b");
    EXPECT_EQ(safe_filename_component(".hidden"), "hidden");
    EXPECT_EQ(safe_filename_component("trailing. . "), "trailing");
    EXPECT_EQ(safe_filename_component("rootfs.squashfs"), "rootfs.squashfs");
    EXPECT_EQ(safe_filename_component("with space"), "with space");
    EXPECT_EQ(safe_filename_component(std::string("nul\0byte", 8)), "nul_x00byte");
    EXPECT_EQ(safe_filename_component("\x01\x02"), "_x01_x02");
    EXPECT_EQ(safe_filename_component(bytes({0xB5})), "_xb5");
    // Multi-byte characters survive intact.
    const std::string utf = bytes({0xE3, 0x83, 0x95, 0xE3, 0x82, 0xA1});  // ファ
    EXPECT_EQ(safe_filename_component(utf), utf);
}

TEST(Text, SafeFilenameComponentWindowsReserved) {
    EXPECT_EQ(safe_filename_component("CON"), "CON_");
    EXPECT_EQ(safe_filename_component("con"), "con_");
    EXPECT_EQ(safe_filename_component("Con.txt"), "Con.txt_");
    EXPECT_EQ(safe_filename_component("NUL"), "NUL_");
    EXPECT_EQ(safe_filename_component("COM1"), "COM1_");
    EXPECT_EQ(safe_filename_component("LPT9.log"), "LPT9.log_");
    EXPECT_EQ(safe_filename_component("COM0"), "COM0");
    EXPECT_EQ(safe_filename_component("CONSOLE"), "CONSOLE");
    EXPECT_EQ(safe_filename_component("config"), "config");
    // Appending must not exceed max_len.
    EXPECT_EQ(safe_filename_component("CON", 3), "CO_");
    EXPECT_EQ(safe_filename_component("PRN", 4), "PRN_");
}

TEST(Text, SafeFilenameComponentTrimsAtUtf8Boundary) {
    // 198 ASCII bytes then a 3-byte character straddling the 200-byte cut.
    const std::string name = std::string(198, 'a') + bytes({0xE2, 0x82, 0xAC}) + "tail";
    const std::string cut = safe_filename_component(name, 200);
    EXPECT_EQ(cut, std::string(198, 'a'));
    EXPECT_TRUE(is_clean_utf8(cut));
    // A cut that lands exactly after the character keeps it.
    EXPECT_EQ(safe_filename_component(name, 201),
              std::string(198, 'a') + bytes({0xE2, 0x82, 0xAC}));
    // Default limit is 64 bytes.
    EXPECT_EQ(safe_filename_component(std::string(100, 'b')).size(), 64u);
    // A cut that exposes a trailing dot still strips it.
    EXPECT_EQ(safe_filename_component("abc.def", 4), "abc");
    EXPECT_EQ(safe_filename_component("abc", 0), "unnamed");
}

}  // namespace
}  // namespace omnitrace
