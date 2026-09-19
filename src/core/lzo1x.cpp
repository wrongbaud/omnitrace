// lzo1x.cpp — see lzo1x.h. Written from the LZO1X bitstream description.
#include "lzo1x.h"

#include <cstring>
#include <limits>

namespace omnitrace::compress::lzo {

const char* lzo1x_status_code(Lzo1xStatus s) {
    switch (s) {
        case Lzo1xStatus::Ok:
            return "ok";
        case Lzo1xStatus::InputOverrun:
            return "lzo1x-input-overrun";
        case Lzo1xStatus::OutputOverrun:
            return "decompress-cap";
        case Lzo1xStatus::LookbehindOverrun:
            return "lzo1x-lookbehind-overrun";
        case Lzo1xStatus::EofNotFound:
            return "lzo1x-eof-not-found";
        case Lzo1xStatus::Corrupt:
            return "lzo1x-corrupt";
    }
    return "lzo1x-corrupt";
}

namespace {

// Output cursor over a growable vector with a hard cap. Growth is geometric
// but never past the cap, so a hostile stream cannot make us over-allocate.
struct OutBuf {
    std::vector<std::uint8_t>& v;
    std::uint64_t cap;
    std::size_t pos = 0;

    bool ensure(std::uint64_t need) {
        if (need > cap) return false;
        if (need > v.size()) {
            std::uint64_t grow = static_cast<std::uint64_t>(v.size()) * 2;
            if (grow < need) grow = need;
            if (grow < 256) grow = 256;
            if (grow > cap) grow = cap;
            v.resize(static_cast<std::size_t>(grow));
        }
        return true;
    }
};

// Count-of-255 extension: a run of zero bytes (each worth 255) followed by one
// non-zero byte. Returns false on input overrun or an absurd count.
bool read_extension(std::span<const std::uint8_t> in, std::size_t& ip, std::uint64_t& count) {
    // A zero run longer than this cannot represent a length we could ever emit.
    constexpr std::uint64_t kMaxZeroRun = std::numeric_limits<std::uint64_t>::max() / 255 - 2;
    std::uint64_t zeros = 0;
    for (;;) {
        if (ip >= in.size()) return false;
        const std::uint8_t b = in[ip++];
        if (b != 0) {
            count += zeros * 255 + b;
            return true;
        }
        if (++zeros > kMaxZeroRun) return false;
    }
}

}  // namespace

Lzo1xStatus lzo1x_decompress_safe(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                                  std::uint64_t max_out, std::size_t* consumed) {
    out.clear();
    if (consumed) *consumed = 0;
    OutBuf ob{out, max_out};
    std::size_t ip = 0;
    const std::size_t in_len = in.size();

    // `state` is the number of literals copied by the previous instruction
    // (0..3, or 4 meaning "four or more"); it changes the meaning of opcodes
    // 0..15. `lit` is the literal count the current instruction asks us to copy
    // before decoding the next opcode.
    unsigned state = 0;
    std::uint64_t lit = 0;

    auto finish = [&](Lzo1xStatus s) {
        out.resize(ob.pos);
        return s;
    };

    if (in_len == 0) return finish(Lzo1xStatus::InputOverrun);

    // First byte: 18..255 is a literal run of (byte - 17) bytes.
    if (in[0] > 17) {
        lit = static_cast<std::uint64_t>(in[0]) - 17;
        ip = 1;
        state = lit < 4 ? static_cast<unsigned>(lit) : 4u;
    }

    for (;;) {
        if (lit != 0) {
            if (!ob.ensure(ob.pos + lit)) return finish(Lzo1xStatus::OutputOverrun);
            if (in_len - ip < lit) return finish(Lzo1xStatus::InputOverrun);
            std::memcpy(out.data() + ob.pos, in.data() + ip, static_cast<std::size_t>(lit));
            ob.pos += static_cast<std::size_t>(lit);
            ip += static_cast<std::size_t>(lit);
            lit = 0;
        }

        if (ip >= in_len) return finish(Lzo1xStatus::EofNotFound);
        const std::uint8_t t = in[ip++];
        std::uint64_t mlen = 0;
        std::uint64_t dist = 0;

        if (t < 16) {
            if (state == 0) {
                // Long literal run: 3 + (L ?: 15 + extension).
                std::uint64_t n = t;
                if (n == 0) {
                    n = 15;
                    if (!read_extension(in, ip, n)) return finish(Lzo1xStatus::InputOverrun);
                }
                lit = n + 3;
                state = 4;
                continue;
            }
            // Short match; the trailing byte H supplies the high distance bits.
            if (ip >= in_len) return finish(Lzo1xStatus::InputOverrun);
            const std::uint64_t h = in[ip++];
            if (state < 4) {
                mlen = 2;
                dist = (h << 2) + (t >> 2) + 1;
            } else {
                mlen = 3;
                dist = (h << 2) + (t >> 2) + 2049;
            }
            lit = t & 3;
        } else if (t < 32) {
            // 0001HLLL: long-distance match; distance 16384 + (H << 14) + D.
            mlen = t & 7;
            if (mlen == 0) {
                mlen = 7;
                if (!read_extension(in, ip, mlen)) return finish(Lzo1xStatus::InputOverrun);
            }
            mlen += 2;
            if (in_len - ip < 2) return finish(Lzo1xStatus::InputOverrun);
            const std::uint64_t le16 =
                static_cast<std::uint64_t>(in[ip]) | (static_cast<std::uint64_t>(in[ip + 1]) << 8);
            ip += 2;
            const std::uint64_t h = (t & 8) ? 1u : 0u;
            const std::uint64_t d = le16 >> 2;
            if (h == 0 && d == 0) {
                // End-of-stream marker (canonically 11 00 00).
                if (consumed) *consumed = ip;
                return finish(Lzo1xStatus::Ok);
            }
            dist = 16384 + (h << 14) + d;
            lit = le16 & 3;
        } else if (t < 64) {
            // 001LLLLL: match within 16 KiB; distance D + 1.
            mlen = t & 31;
            if (mlen == 0) {
                mlen = 31;
                if (!read_extension(in, ip, mlen)) return finish(Lzo1xStatus::InputOverrun);
            }
            mlen += 2;
            if (in_len - ip < 2) return finish(Lzo1xStatus::InputOverrun);
            const std::uint64_t le16 =
                static_cast<std::uint64_t>(in[ip]) | (static_cast<std::uint64_t>(in[ip + 1]) << 8);
            ip += 2;
            dist = (le16 >> 2) + 1;
            lit = le16 & 3;
        } else {
            // 01LDDDSS: 3..4 bytes, 1LLDDDSS: 5..8 bytes; distance (H << 3) + D + 1.
            if (ip >= in_len) return finish(Lzo1xStatus::InputOverrun);
            const std::uint64_t h = in[ip++];
            mlen = (t < 128) ? 3u + ((t >> 5) & 1u) : 5u + ((t >> 5) & 3u);
            dist = (h << 3) + ((t >> 2) & 7u) + 1;
            lit = t & 3;
        }

        // Copy the match. Overlap (dist < mlen) is the normal run-length case,
        // so copy forward one byte at a time whenever the ranges overlap.
        if (dist > ob.pos) return finish(Lzo1xStatus::LookbehindOverrun);
        if (!ob.ensure(ob.pos + mlen)) return finish(Lzo1xStatus::OutputOverrun);
        std::uint8_t* dst = out.data() + ob.pos;
        const std::uint8_t* src = dst - dist;
        const std::size_t n = static_cast<std::size_t>(mlen);
        if (dist >= mlen) {
            std::memcpy(dst, src, n);
        } else {
            for (std::size_t i = 0; i < n; ++i) dst[i] = src[i];
        }
        ob.pos += n;
        state = static_cast<unsigned>(lit);
    }
}

}  // namespace omnitrace::compress::lzo
