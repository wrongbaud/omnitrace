// Endian.h — byte-order helpers. All on-disk integers go through these.
/// @file Endian.h
/// @brief Byte-order enum and the two integer decoders every on-disk field
/// passes through (`Span::at<T>` calls `load_int`).
///
/// Everything here is header-only, constexpr-friendly and has no state, so it
/// is safe from any thread.
#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace omnitrace {

/// Byte order of an on-disk integer.
enum class Endian : std::uint8_t { Little, Big };

/// "little" or "big"; the string written to manifest.yaml.
inline const char* endian_name(Endian e) {
    return e == Endian::Little ? "little" : "big";
}

/// Reverse the bytes of an integral value (identity for 1-byte types).
template <class T>
inline T byteswap_int(T v) {
    static_assert(std::is_integral_v<T>);
    if constexpr (sizeof(T) == 1) {
        return v;
    } else {
        std::array<std::uint8_t, sizeof(T)> b{};
        std::memcpy(b.data(), &v, sizeof(T));
        for (std::size_t i = 0; i < sizeof(T) / 2; ++i) std::swap(b[i], b[sizeof(T) - 1 - i]);
        std::memcpy(&v, b.data(), sizeof(T));
        return v;
    }
}

// Decode an integer of type T from raw bytes (caller guarantees sizeof(T) bytes).
/// Decode a `T` stored in byte order `e` from raw bytes.
///
/// Precondition: `p` points at least `sizeof(T)` readable bytes; this function
/// does no bounds check. Parsers reach it through `Span::at<T>`, which does.
template <class T>
inline T load_int(const std::uint8_t* p, Endian e) {
    static_assert(std::is_integral_v<T>);
    T v{};
    std::memcpy(&v, p, sizeof(T));
    const bool native_little = std::endian::native == std::endian::little;
    const bool want_little = e == Endian::Little;
    return native_little == want_little ? v : byteswap_int(v);
}

}  // namespace omnitrace
