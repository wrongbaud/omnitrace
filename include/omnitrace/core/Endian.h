// Endian.h — byte-order helpers. All on-disk integers go through these.
#pragma once
#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace omnitrace {

enum class Endian : std::uint8_t { Little, Big };

inline const char* endian_name(Endian e) { return e == Endian::Little ? "little" : "big"; }

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
