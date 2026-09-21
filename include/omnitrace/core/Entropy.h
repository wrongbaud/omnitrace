// Entropy.h — what a run of bytes looks like statistically, when nothing
// identifies it.
/// @file Entropy.h
/// @brief Shannon entropy and byte-distribution profiling of a span.
///
/// A region no signature matched is the least informative thing an analysis
/// can report, and an image is often mostly regions. Entropy is what turns
/// "unidentified" into something an examiner can act on: erased flash, a
/// padding run, a config partition, a compressed blob, or bytes that look
/// like cipher output.
///
/// **What this cannot do.** Entropy does not prove encryption. A well
/// compressed payload and an AES-encrypted one both sit at ~8 bits per byte,
/// and no statistic here separates them reliably — a good compressor's output
/// is meant to look random. The chi-square test distinguishes *uniform* from
/// *nearly uniform*, which is the sharpest line available, and that is why
/// `Class::Random` says "uniform" rather than "encrypted". Everything here
/// reports a measurement and a hedged class; the word "encrypted" is never
/// asserted from these numbers alone.
///
/// Reads are bounded and sampled, so profiling a 15 GiB region costs the same
/// as profiling a 16 MiB one. Thread-safety: pure functions, no shared state.
#pragma once
#include <cstdint>
#include <span>

#include "omnitrace/core/Span.h"

/// @namespace omnitrace::entropy
/// @brief Byte-distribution profiling (`shannon`, `profile`).
namespace omnitrace::entropy {

/// Shannon entropy of `data` in bits per byte, 0.0 (one value repeated) to
/// 8.0 (all 256 values equally likely). Empty input is 0.0.
double shannon(std::span<const std::uint8_t> data);

/// What a run of bytes looks like. Ordered by entropy, low to high, so a
/// caller can compare with `<`.
enum class Class : std::uint8_t {
    Unknown,  ///< Too few bytes read to say anything.
    Erased,   ///< One byte value throughout: erased NOR flash (0xFF), zero fill.
    Sparse,   ///< Nearly one value: padding, a sparse table, a mostly-blank area.
    Text,     ///< Mostly printable: config, logs, scripts, certificates in PEM form.
    Binary,   ///< Structured non-text: code, filesystem metadata, mixed data.
    Packed,   ///< High but measurably non-uniform: compressed data.
    Random,   ///< ~8 bits and uniform: encrypted, or a strong compressor's output.
};

/// "unknown", "erased", "sparse", "text", "binary", "packed" or "random".
const char* class_name(Class c);

/// One line an examiner can read: what the class means and what it does not.
const char* class_meaning(Class c);

/// Measurements over the sampled bytes of a span.
struct Profile {
    Class klass = Class::Unknown;
    double mean = 0.0;  ///< Mean Shannon entropy across windows, bits per byte.
    double min = 0.0;   ///< Lowest window, which finds a run of padding inside a busy region.
    double max = 0.0;   ///< Highest window.
    /// Chi-square of the sampled byte histogram against a uniform
    /// distribution, divided by its 255 degrees of freedom. Uniform random
    /// data sits near 1.0; structured data is far above it. This is the one
    /// number that separates `Random` from `Packed`, and it is a statement
    /// about uniformity, never about a cipher.
    double chi_square = 0.0;
    double printable = 0.0;      ///< Fraction of sampled bytes that are printable ASCII or space.
    std::uint64_t sampled = 0;   ///< Bytes actually read.
    std::uint64_t windows = 0;   ///< Windows scored.
    bool uniform_fill = false;   ///< Every sampled byte was `fill_byte`.
    std::uint8_t fill_byte = 0;  ///< Meaningful only when `uniform_fill`.
};

/// How much to read and in what size pieces.
struct Options {
    /// Bytes per window. Entropy is a property of a window, not of a byte:
    /// too small and every window looks random, too large and a short
    /// compressed run is averaged away. 4 KiB is a flash page and reads as
    /// text, code or packed the way an examiner would call it.
    std::size_t window = 4096;
    /// Ceiling on bytes read. A larger span is sampled in evenly spread
    /// windows, exactly as `detect_word_swap` samples an image, so a 15 GiB
    /// region costs one pass over 8 MiB.
    std::uint64_t budget = 8U << 20;
    /// Spans shorter than this get `Class::Unknown`: a handful of bytes has
    /// no meaningful distribution, and reporting one invites over-reading.
    std::uint64_t min_bytes = 256;
};

/// Profile `len` bytes of `span` starting at `at`. A short read stops the
/// sampling and the profile describes what was read (`sampled` says how much).
Profile profile(const Span& span, std::uint64_t at, std::uint64_t len, const Options& opts = {});

/// Profile a buffer already in memory.
Profile profile(std::span<const std::uint8_t> data, const Options& opts = {});

}  // namespace omnitrace::entropy
