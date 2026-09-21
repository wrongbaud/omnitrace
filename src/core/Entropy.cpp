// Entropy.cpp — Shannon entropy and byte-distribution profiling. See the header
// for what these numbers can and cannot support.
#include "omnitrace/core/Entropy.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <vector>

namespace omnitrace::entropy {

namespace {

// Classification thresholds, in bits per byte over the whole sample. They are
// named rather than inline so the numbers are arguable in one place, and every
// one of them is a convention, not a law: the point of the class is to tell an
// examiner where to look first, and `Profile` keeps the raw measurements for
// anyone who disagrees with where the lines fall.
constexpr double kSparseMax = 1.5;  // below this, one value dominates
constexpr double kPackedMin = 7.2;  // above this, nothing recognisable is left
// A printable fraction this high means text even at entropy a binary would
// reach: base64, PEM and JSON all score 5-6 bits and are still text.
constexpr double kTextPrintable = 0.85;
// Reduced chi-square band that counts as uniform. Truly uniform bytes give
// chi2/df ~= 1.0 with a standard deviation of sqrt(2/df) ~= 0.09, so this is
// roughly +/- 4 sigma at the low end and deliberately wider at the high end:
// a compressor's output drifts upward, and calling it `Packed` when it is
// really cipher text is the safer error of the two.
constexpr double kUniformLow = 0.65;
constexpr double kUniformHigh = 1.45;

bool is_printable(std::uint8_t b) {
    return (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r';
}

// Window starts spread evenly over `size`, at most `budget` bytes in total.
// Same shape as core/Swap.cpp's sampler: every window when the span fits in
// the budget, otherwise an even spread so each region of a huge span is
// represented. Deterministic, which keeps a manifest reproducible.
std::vector<std::uint64_t> window_starts(std::uint64_t size, std::size_t window,
                                         std::uint64_t budget) {
    std::vector<std::uint64_t> out;
    if (size == 0 || window == 0) return out;
    const std::uint64_t w = window;
    const std::uint64_t total = (size + w - 1) / w;
    const std::uint64_t allowed = std::max<std::uint64_t>(1, budget / w);
    if (total <= allowed) {
        for (std::uint64_t i = 0; i < total; ++i) out.push_back(i * w);
        return out;
    }
    const std::uint64_t last = size > w ? size - w : 0;
    for (std::uint64_t i = 0; i < allowed; ++i) {
        const std::uint64_t off = allowed == 1 ? 0 : (i * last) / (allowed - 1);
        out.push_back(off - off % w);
    }
    return out;
}

// Running state over however many windows the sampler visited.
struct Accumulator {
    std::array<std::uint64_t, 256> hist{};
    std::uint64_t sampled = 0;
    std::uint64_t windows = 0;
    std::uint64_t printable = 0;
    double sum = 0.0, lo = 8.0, hi = 0.0;
    bool have_fill = false;
    bool uniform = true;
    std::uint8_t fill = 0;

    void add(std::span<const std::uint8_t> win) {
        if (win.empty()) return;
        std::array<std::uint64_t, 256> local{};
        for (const std::uint8_t b : win) {
            ++local[b];
            ++hist[b];
            if (is_printable(b)) ++printable;
        }
        if (uniform) {
            if (!have_fill) {
                fill = win[0];
                have_fill = true;
            }
            for (const std::uint8_t b : win)
                if (b != fill) {
                    uniform = false;
                    break;
                }
        }
        // Entropy of this window, from its own histogram.
        const double n = static_cast<double>(win.size());
        double bits = 0.0;
        for (const std::uint64_t c : local) {
            if (c == 0) continue;
            const double p = static_cast<double>(c) / n;
            bits -= p * std::log2(p);
        }
        sum += bits;
        lo = std::min(lo, bits);
        hi = std::max(hi, bits);
        sampled += win.size();
        ++windows;
    }
};

Profile finish(const Accumulator& a, std::uint64_t min_bytes) {
    Profile p;
    p.sampled = a.sampled;
    p.windows = a.windows;
    if (a.windows == 0) return p;  // Unknown
    p.mean = a.sum / static_cast<double>(a.windows);
    p.min = a.lo;
    p.max = a.hi;
    p.printable = static_cast<double>(a.printable) / static_cast<double>(a.sampled);
    p.uniform_fill = a.uniform;
    p.fill_byte = a.fill;

    // Reduced chi-square of the whole sample against a uniform distribution.
    // Over the pooled histogram rather than per window, because 4096 bytes in
    // 256 bins is too thin a table for the statistic to mean much on its own.
    const double expected = static_cast<double>(a.sampled) / 256.0;
    if (expected > 0.0) {
        double chi = 0.0;
        for (const std::uint64_t c : a.hist) {
            const double d = static_cast<double>(c) - expected;
            chi += d * d / expected;
        }
        p.chi_square = chi / 255.0;
    }

    if (a.sampled < min_bytes) return p;  // measured, but not enough to classify

    if (p.uniform_fill)
        p.klass = Class::Erased;
    else if (p.mean < kSparseMax)
        p.klass = Class::Sparse;
    else if (p.printable >= kTextPrintable)
        p.klass = Class::Text;
    else if (p.mean < kPackedMin)
        p.klass = Class::Binary;
    else
        p.klass = (p.chi_square >= kUniformLow && p.chi_square <= kUniformHigh) ? Class::Random
                                                                                : Class::Packed;
    return p;
}

}  // namespace

double shannon(std::span<const std::uint8_t> data) {
    if (data.empty()) return 0.0;
    std::array<std::uint64_t, 256> hist{};
    for (const std::uint8_t b : data) ++hist[b];
    const double n = static_cast<double>(data.size());
    double bits = 0.0;
    for (const std::uint64_t c : hist) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / n;
        bits -= p * std::log2(p);
    }
    return bits;
}

const char* class_name(Class c) {
    switch (c) {
        case Class::Unknown:
            return "unknown";
        case Class::Erased:
            return "erased";
        case Class::Sparse:
            return "sparse";
        case Class::Text:
            return "text";
        case Class::Binary:
            return "binary";
        case Class::Packed:
            return "packed";
        case Class::Random:
            return "random";
    }
    return "unknown";
}

const char* class_meaning(Class c) {
    switch (c) {
        case Class::Unknown:
            return "too few bytes to profile";
        case Class::Erased:
            return "one byte value throughout: erased flash or fill, holding no data";
        case Class::Sparse:
            return "nearly one value: padding, a sparse table or a mostly-blank area";
        case Class::Text:
            return "mostly printable: configuration, logs, scripts or PEM";
        case Class::Binary:
            return "structured non-text: code, metadata or mixed data";
        case Class::Packed:
            return "high entropy but measurably non-uniform: compressed data";
        case Class::Random:
            return "high entropy and uniform: compressed or encrypted, which these "
                   "numbers cannot tell apart";
    }
    return "";
}

Profile profile(std::span<const std::uint8_t> data, const Options& opts) {
    Accumulator a;
    const std::size_t w = opts.window == 0 ? data.size() : opts.window;
    for (std::size_t off = 0; off < data.size() && a.sampled < opts.budget; off += w)
        a.add(data.subspan(off, std::min(w, data.size() - off)));
    return finish(a, opts.min_bytes);
}

Profile profile(const Span& span, std::uint64_t at, std::uint64_t len, const Options& opts) {
    if (len == 0 || opts.window == 0) return {};
    // Clamp to what the span actually holds, so a caller's stale length cannot
    // make the sampler spread windows over bytes that are not there.
    const std::uint64_t avail = span.size() > at ? span.size() - at : 0;
    const std::uint64_t n = std::min(len, avail);
    if (n == 0) return {};

    Accumulator a;
    std::vector<std::uint8_t> buf(opts.window);
    for (const std::uint64_t start : window_starts(n, opts.window, opts.budget)) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(opts.window, n - start));
        const std::size_t got = span.read(at + start, std::span<std::uint8_t>(buf.data(), want));
        if (got == 0) break;  // short read: profile what was there
        a.add(std::span<const std::uint8_t>(buf.data(), got));
    }
    return finish(a, opts.min_bytes);
}

}  // namespace omnitrace::entropy
