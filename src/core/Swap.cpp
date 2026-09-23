// Swap.cpp — SwappedSource and detect_word_swap. See Swap.h for the contract
// and docs/formats/word-swap.md for the heuristic and its thresholds.
//
// SwappedSource::read pulls the aligned words that cover [off, off+len) from
// the parent, reverses the bytes of every complete word, and copies the
// requested window out. Word alignment is absolute (parent offset 0), so a
// read never depends on where it starts. A trailing partial word (the parent's
// size is not a multiple of the word size) is passed through unchanged; the
// caller that installs the view reports that on the Image node.
//
// detect_word_swap samples the Span in 64 KiB windows, builds the swap16 and
// swap32 renderings of each window, and scores every view by (a) hits of a
// fixed table of well-known magics and ARM code words (the structure score)
// and (b) printable-ASCII runs (the text score). A word swap permutes bytes
// within a word, so a printable string stays printable and the run counts of
// the three views are nearly equal: text can only break ties. The decision
// is made on the structure score when any view has one, on the text score
// otherwise. A swap is chosen only when the raw view has no unambiguous magic
// hit and the deciding score is at least kMarginRatio times the raw view's.
#include "omnitrace/core/Swap.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <utility>
#include <vector>

namespace omnitrace {

namespace {

std::uint64_t word_bytes(SwapKind k) {
    switch (k) {
        case SwapKind::Swap16:
            return 2;
        case SwapKind::Swap32:
            return 4;
        case SwapKind::None:
            return 1;
    }
    return 1;
}

// Reverse the bytes of every complete `w`-byte word in [p, p+n); a trailing
// partial word is left as is.
void swap_words(std::uint8_t* p, std::size_t n, std::size_t w) {
    if (w < 2) return;
    const std::size_t whole = n - n % w;
    for (std::size_t i = 0; i < whole; i += w) std::reverse(p + i, p + i + w);
}

std::string dec(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(v));
    return buf;
}

// ---------------------------------------------------------------- detection

constexpr std::size_t kWindowBytes = 64u << 10;  // sampling window; not a limit

// Scoring weights. A strong magic is a full format identifier (>= 4 bytes,
// chance rate <= 2^-32 per position); a weak one is short or has wildcards.
constexpr std::uint64_t kStrongWeight = 8;
constexpr std::uint64_t kWeakWeight = 1;
// Decision thresholds (documented in docs/formats/word-swap.md).
constexpr std::uint64_t kMarginRatio = 2;  // swapped score must be >= 2x raw
constexpr std::uint64_t kMinScore = 8;     // and at least one strong hit's worth

// A byte pattern that identifies a format. `veto`: a hit in the raw view
// proves the raw view is right (it is not the swap image of another entry).
// Magics whose 16- or 32-bit swap is itself a listed magic (SquashFS
// hsqs/sqsh, JFFS2 LE/BE) are not vetoes: they cannot tell the views apart.
struct BytePattern {
    const char* name;
    std::vector<std::uint8_t> bytes;
    bool strong;
    bool veto;
};

// A 32-bit little-endian word pattern checked at 4-byte alignment only.
struct WordPattern {
    const char* name;
    std::uint32_t value;
    std::uint32_t mask;
    bool strong;
};

const std::vector<BytePattern>& byte_patterns() {
    static const std::vector<BytePattern> t = {
        {"elf", {0x7f, 'E', 'L', 'F'}, true, true},
        {"uimage", {0x27, 0x05, 0x19, 0x56}, true, true},
        {"squashfs-le", {'h', 's', 'q', 's'}, true, false},
        {"squashfs-be", {'s', 'q', 's', 'h'}, true, false},
        {"jffs2-le-dirent", {0x85, 0x19, 0x01, 0xe0}, true, false},
        {"jffs2-le-inode", {0x85, 0x19, 0x02, 0xe0}, true, false},
        {"jffs2-le-cleanmarker", {0x85, 0x19, 0x03, 0x20}, true, false},
        {"jffs2-be-dirent", {0x19, 0x85, 0xe0, 0x01}, true, false},
        {"jffs2-be-inode", {0x19, 0x85, 0xe0, 0x02}, true, false},
        {"jffs2-be-cleanmarker", {0x19, 0x85, 0x20, 0x03}, true, false},
        {"ubi", {'U', 'B', 'I', '#'}, true, true},
        {"ubifs", {0x31, 0x18, 0x10, 0x06}, true, true},
        {"gzip", {0x1f, 0x8b, 0x08}, false, false},
        // bzip2's "BZh" is three bytes and level-dependent; the 48-bit block
        // magic behind it (pi, in BCD) is not, and the first block's copy is
        // byte-aligned at offset 4. Without it a bare .bz2 of compressed
        // noise scores as text in a swapped view and the whole file is lost.
        {"bzip2-block", {0x31, 0x41, 0x59, 0x26, 0x53, 0x59}, true, true},
        {"7z", {0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, true, true},
        {"zip", {'P', 'K', 0x03, 0x04}, true, true},
        {"cpio-newc", {'0', '7', '0', '7', '0', '1'}, true, true},
        // "!<arch>\n" is eight bytes at offset 0. A static library is mostly
        // ELF members, whose own magic is four bytes and cannot score, so
        // without this a .a of compressed-looking object code is analysed
        // word-swapped and the whole archive is lost.
        {"ar", {'!', '<', 'a', 'r', 'c', 'h', '>', '\n'}, true, true},
        {"xz", {0xfd, '7', 'z', 'X', 'Z', 0x00}, true, true},
        {"zstd", {0x28, 0xb5, 0x2f, 0xfd}, true, true},
        {"lz4-frame", {0x04, 0x22, 0x4d, 0x18}, true, true},
        {"lzop", {0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a}, true, true},
        {"dtb", {0xd0, 0x0d, 0xfe, 0xed}, true, true},
        // Neither cramfs entry vetoes: one is the other's swap32 image, so a
        // hit proves only that this is cramfs, not which view is right. Listing
        // just the LE one as a veto made every big-endian cramfs image score 0
        // in the raw view and 8 in swap32, so it was "corrected" into garbage.
        {"cramfs-le", {0x45, 0x3d, 0xcd, 0x28}, true, false},
        {"cramfs-be", {0x28, 0xcd, 0x3d, 0x45}, true, false},
        {"romfs", {'-', 'r', 'o', 'm', '1', 'f', 's', '-'}, true, true},
        // FAT's type strings are eight bytes and sit at 54 or 82, well inside
        // the first window. They are not at offset 0 and the format has no
        // magic that is, so this is the only thing a FAT boot sector offers a
        // scorer -- and it offers it in whichever view is the right one, since
        // a word swap turns "FAT32   " into "T3FA  2 ".
        {"fat32", {'F', 'A', 'T', '3', '2', ' ', ' ', ' '}, true, true},
        {"fat16", {'F', 'A', 'T', '1', '6', ' ', ' ', ' '}, true, true},
        {"fat12", {'F', 'A', 'T', '1', '2', ' ', ' ', ' '}, true, true},
        {"android-boot", {'A', 'N', 'D', 'R', 'O', 'I', 'D', '!'}, true, true},
        {"android-vendor-boot", {'V', 'N', 'D', 'R', 'B', 'O', 'O', 'T'}, true, true},
        {"android-sparse", {0x3a, 0xff, 0x26, 0xed}, true, true},
        // The super's own magic sits 4096 bytes in, past a reserved area, so a
        // window has to reach it -- but the logical partitions it holds are
        // ext4, whose 2-byte magic cannot score, so this is the only thing
        // that speaks for a super image in the raw view. "Dgal" and "alDg" are
        // nothing, so it vetoes.
        {"android-super", {'g', 'D', 'l', 'a'}, true, true},
        {"cpio-crc", {'0', '7', '0', '7', '0', '2'}, true, true},
        {"cpio-odc", {'0', '7', '0', '7', '0', '7'}, true, true},
        {"dm-verity", {'v', 'e', 'r', 'i', 't', 'y', 0x00, 0x00}, true, true},
        {"gpt", {'E', 'F', 'I', ' ', 'P', 'A', 'R', 'T'}, true, true},
        {"luks", {'L', 'U', 'K', 'S', 0xba, 0xbe}, true, true},
        {"qnx-ifs", {0xeb, 0x7e, 0xff, 0x00}, true, true},
        {"tar-ustar", {'u', 's', 't', 'a', 'r'}, true, true},
        {"yaffs2", {0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff}, true, true},
        // QNX6 writes its superblock magic in the host's byte order, so the
        // two spellings are each other's swap32 image and neither can say
        // which view is right -- the same shape as SquashFS below.
        {"qnx6-be", {0x68, 0x19, 0x11, 0x22}, true, false},
        {"qnx6-le", {0x22, 0x11, 0x19, 0x68}, true, false},
        // The DD-WRT/Broadcom SquashFS spellings complete that family: `shsq`
        // is `hsqs` under swap16 and `qshs` under swap32, and so on round.
        {"squashfs-vendor-shsq", {'s', 'h', 's', 'q'}, true, false},
        {"squashfs-vendor-qshs", {'q', 's', 'h', 's'}, true, false},
        {"u-boot", {'U', '-', 'B', 'o', 'o', 't'}, true, true},
        {"linux-version",
         {'L', 'i', 'n', 'u', 'x', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n'},
         true,
         true},
        {"pem", {'-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N'}, true, true},
    };
    return t;
}

// Copies the table out for `swap_magics()`. The internal form is an
// implementation detail; the exported one is what a test can assert on.
std::vector<SwapMagic> export_patterns() {
    std::vector<SwapMagic> out;
    out.reserve(byte_patterns().size());
    for (const BytePattern& p : byte_patterns())
        out.push_back(SwapMagic{p.name, p.bytes, p.strong, p.veto});
    return out;
}

const std::vector<WordPattern>& word_patterns() {
    static const std::vector<WordPattern> t = {
        // ARM32: 0xEA00xxxx unconditional forward branch (vector tables,
        // literal-pool jumps); 1/65536 chance per word, so weak.
        {"arm-branch", 0xEA000000u, 0xFFFF0000u, false},
        // ARM32: mov r0, r0 — the canonical NOP / padding word.
        {"arm-nop", 0xE1A00000u, 0xFFFFFFFFu, true},
    };
    return t;
}

// First-byte dispatch so a 64 MiB budget costs one table lookup per byte.
struct Dispatch {
    std::array<std::vector<std::size_t>, 256> by_first{};
    std::size_t max_len = 0;
    Dispatch() {
        const auto& pats = byte_patterns();
        for (std::size_t i = 0; i < pats.size(); ++i) {
            by_first[pats[i].bytes[0]].push_back(i);
            max_len = std::max(max_len, pats[i].bytes.size());
        }
    }
};

const Dispatch& dispatch() {
    static const Dispatch d;
    return d;
}

struct ViewScore {
    std::uint64_t strong = 0;  // strong byte-pattern hits + strong word hits
    std::uint64_t weak = 0;    // weak byte-pattern hits + weak word hits
    std::uint64_t veto = 0;    // raw-view-proving hits (subset of strong)
    std::uint64_t runs = 0;    // printable runs of >= 6 chars
    std::uint64_t shape = 0;   // uppercase-then-lowercase pairs inside runs
    // Magics and code words: asymmetric between views, so this decides.
    std::uint64_t structure() const { return kStrongWeight * strong + kWeakWeight * weak; }
    // Runs are nearly symmetric between views; `shape` is not (a real word is
    // capitalised at its front, a reversed one at its back).
    std::uint64_t text() const { return runs + shape; }
};

bool printable(std::uint8_t c) {
    return (c >= 0x20 && c <= 0x7e) || c == '\t' || c == '\n' || c == '\r';
}
bool upper(std::uint8_t c) {
    return c >= 'A' && c <= 'Z';
}
bool lower(std::uint8_t c) {
    return c >= 'a' && c <= 'z';
}

void score_buffer(const std::uint8_t* p, std::size_t n, ViewScore& s) {
    const Dispatch& d = dispatch();
    const auto& pats = byte_patterns();
    for (std::size_t i = 0; i < n; ++i) {
        for (const std::size_t pi : d.by_first[p[i]]) {
            const BytePattern& pat = pats[pi];
            if (pat.bytes.size() > n - i) continue;
            if (std::memcmp(p + i, pat.bytes.data(), pat.bytes.size()) != 0) continue;
            if (pat.strong)
                ++s.strong;
            else
                ++s.weak;
            if (pat.veto) ++s.veto;
        }
    }
    for (std::size_t i = 0; i + 4 <= n; i += 4) {
        const std::uint32_t w = static_cast<std::uint32_t>(p[i]) |
                                (static_cast<std::uint32_t>(p[i + 1]) << 8) |
                                (static_cast<std::uint32_t>(p[i + 2]) << 16) |
                                (static_cast<std::uint32_t>(p[i + 3]) << 24);
        for (const WordPattern& wp : word_patterns()) {
            if ((w & wp.mask) != wp.value) continue;
            if (wp.strong)
                ++s.strong;
            else
                ++s.weak;
        }
    }
    std::size_t run = 0;
    std::uint64_t shape = 0;
    auto close = [&] {
        if (run >= 6) {
            ++s.runs;
            s.shape += shape;
        }
        run = 0;
        shape = 0;
    };
    for (std::size_t i = 0; i < n; ++i) {
        if (!printable(p[i])) {
            close();
            continue;
        }
        if (run > 0 && upper(p[i - 1]) && lower(p[i])) ++shape;
        ++run;
    }
    close();
}

// Window start offsets: every window when the budget covers the span,
// otherwise `count` windows spread evenly and aligned to the window size.
std::vector<std::uint64_t> window_starts(std::uint64_t size, std::uint64_t budget) {
    std::vector<std::uint64_t> out;
    if (size == 0) return out;
    const std::uint64_t total = (size + kWindowBytes - 1) / kWindowBytes;
    const std::uint64_t allowed = std::max<std::uint64_t>(1, budget / kWindowBytes);
    if (total <= allowed) {
        for (std::uint64_t i = 0; i < total; ++i) out.push_back(i * kWindowBytes);
        return out;
    }
    const std::uint64_t last = size - kWindowBytes;  // size > allowed * window >= window
    for (std::uint64_t i = 0; i < allowed; ++i) {
        // i * last cannot overflow for any real image (last < 2^44, i < 2^20).
        const std::uint64_t off = allowed == 1 ? 0 : (i * last) / (allowed - 1);
        out.push_back(off - off % kWindowBytes);
    }
    return out;
}

std::string ratio_text(std::uint64_t num, std::uint64_t den) {
    const std::uint64_t d = den == 0 ? 1 : den;
    const std::uint64_t tenths = (num * 10) / d;
    return dec(tenths / 10) + "." + dec(tenths % 10);
}

std::string view_text(const char* name, const ViewScore& v) {
    return std::string(name) + " " + dec(v.structure()) + "/" + dec(v.text()) + " (" +
           dec(v.strong) + " magics, " + dec(v.weak) + " code words, " + dec(v.runs) +
           " ASCII runs)";
}

std::uint8_t confidence_for(std::uint64_t best, std::uint64_t raw) {
    const std::uint64_t r = raw == 0 ? 1 : raw;
    std::uint8_t by_ratio = 60;
    if (best >= 8 * r)
        by_ratio = 99;
    else if (best >= 4 * r)
        by_ratio = 85;
    std::uint8_t by_volume = 60;
    if (best >= 128)
        by_volume = 99;
    else if (best >= 32)
        by_volume = 85;
    return std::min(by_ratio, by_volume);
}

}  // namespace

// ------------------------------------------------------------------- public

const char* swap_kind_name(SwapKind k) {
    switch (k) {
        case SwapKind::None:
            return "none";
        case SwapKind::Swap16:
            return "swap16";
        case SwapKind::Swap32:
            return "swap32";
    }
    return "none";
}

SwappedSource::SwappedSource(std::shared_ptr<const Source> parent, SwapKind kind)
    : parent_(std::move(parent)), kind_(kind) {}

std::uint64_t SwappedSource::size() const {
    return parent_ ? parent_->size() : 0;
}

std::string SwappedSource::id() const {
    const std::string base = parent_ ? parent_->id() : std::string{};
    if (kind_ == SwapKind::None) return base;
    return base + "|" + swap_kind_name(kind_);
}

std::size_t SwappedSource::read(std::uint64_t off, std::span<std::uint8_t> out) const {
    if (!parent_ || out.empty()) return 0;
    const std::uint64_t total = parent_->size();
    if (off >= total) return 0;
    const std::size_t n =
        static_cast<std::size_t>(std::min<std::uint64_t>(out.size(), total - off));
    if (kind_ == SwapKind::None) return parent_->read(off, out.subspan(0, n));

    const std::uint64_t w = word_bytes(kind_);
    const std::uint64_t start = off - off % w;
    const std::uint64_t want_end = off + n;  // <= total, no overflow
    const std::uint64_t end = std::min(total, want_end + (w - want_end % w) % w);
    const std::size_t span_len = static_cast<std::size_t>(end - start);

    // Small reads (Span::at<T>, header probes) use a stack buffer.
    std::uint8_t small[512];
    std::vector<std::uint8_t> big;
    std::uint8_t* buf = small;
    if (span_len > sizeof small) {
        big.resize(span_len);
        buf = big.data();
    }
    const std::size_t got = parent_->read(start, std::span<std::uint8_t>(buf, span_len));
    const std::size_t lead = static_cast<std::size_t>(off - start);
    if (got <= lead) return 0;
    swap_words(buf, got, static_cast<std::size_t>(w));
    const std::size_t avail = std::min(n, got - lead);
    std::memcpy(out.data(), buf + lead, avail);
    return avail;
}

std::span<const std::uint8_t> SwappedSource::map(std::uint64_t, std::size_t) const {
    return {};
}

std::vector<SwapMagic> swap_magics() {
    return export_patterns();
}

SwapDetection detect_word_swap(const Span& span, std::uint64_t budget) {
    SwapDetection out;
    if (span.empty()) {
        out.evidence = "empty span";
        return out;
    }
    ViewScore raw, s16, s32;
    std::vector<std::uint8_t> buf(kWindowBytes), b16(kWindowBytes), b32(kWindowBytes);
    std::uint64_t sampled = 0;
    for (const std::uint64_t start : window_starts(span.size(), budget)) {
        const std::size_t got = span.read(start, std::span<std::uint8_t>(buf.data(), buf.size()));
        if (got == 0) continue;
        sampled += got;
        std::memcpy(b16.data(), buf.data(), got);
        std::memcpy(b32.data(), buf.data(), got);
        swap_words(b16.data(), got, 2);
        swap_words(b32.data(), got, 4);
        score_buffer(buf.data(), got, raw);
        score_buffer(b16.data(), got, s16);
        score_buffer(b32.data(), got, s32);
    }

    const std::string detail = view_text("raw", raw) + ", " + view_text("swap16", s16) + ", " +
                               view_text("swap32", s32) + " [structure/text] in " + dec(sampled) +
                               " sampled bytes";
    if (raw.veto > 0) {
        out.evidence = "raw view has " + dec(raw.veto) + " unambiguous known magics; " + detail;
        return out;
    }
    // Decide on structure when any view has some, on text otherwise.
    const bool by_structure = raw.structure() + s16.structure() + s32.structure() > 0;
    const char* basis = by_structure ? "structure" : "text";
    auto pick = [&](const ViewScore& v) { return by_structure ? v.structure() : v.text(); };
    const std::uint64_t r = pick(raw);
    const std::uint64_t v16 = pick(s16);
    const std::uint64_t v32 = pick(s32);
    SwapKind kind = SwapKind::None;
    std::uint64_t best = 0;
    if (v32 > v16 || (v32 == v16 && v32 > 0 && s32.text() > s16.text())) {
        kind = SwapKind::Swap32;
        best = v32;
    } else if (v16 > v32 || (v32 == v16 && v16 > 0 && s16.text() > s32.text())) {
        kind = SwapKind::Swap16;
        best = v16;
    }
    if (kind == SwapKind::None) {
        out.evidence = std::string("swap16 and swap32 ") + basis + " scores are alike; " + detail;
        return out;
    }
    if (best < kMinScore || best < kMarginRatio * r) {
        out.evidence = std::string(swap_kind_name(kind)) + " " + basis +
                       " score does not beat raw by " + dec(kMarginRatio) + "x; " + detail;
        return out;
    }
    out.kind = kind;
    out.confidence = confidence_for(best, r);
    out.evidence = std::string(swap_kind_name(kind)) + " " + basis + " score " + dec(best) +
                   " is " + ratio_text(best, r) + "x the raw view's " + dec(r) + ": " + detail;
    return out;
}

}  // namespace omnitrace
