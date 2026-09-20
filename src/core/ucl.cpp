// ucl.cpp — UCL NRV2B decompressor. See ucl.h.
#include "ucl.h"

#include <cstddef>

namespace omnitrace::compress::ucl {

namespace {

// The offset code that terminates a stream: (code - 3) * 256 + 0xff wraps to
// 0xffffffff in 32-bit arithmetic. Any larger code is not a valid offset.
constexpr std::uint64_t kEndCode = 0x1000002;
// Matches beyond this distance carry one extra byte of length.
constexpr std::uint64_t kLongDistance = 0xd00;

// Bits come from one byte at a time, most significant first. The buffer holds
// the byte shifted left by one with a 1 bit below it; when the low seven bits
// are zero the sentinel has reached bit 7 and the buffer is empty.
class BitReader {
   public:
    explicit BitReader(std::span<const std::uint8_t> in) : in_(in) {}

    unsigned bit() {
        if ((bb_ & 0x7fu) != 0) {
            bb_ <<= 1;
        } else {
            if (pos_ >= in_.size()) {
                overrun_ = true;
                return 0;
            }
            bb_ = static_cast<std::uint32_t>(in_[pos_++]) * 2u + 1u;
        }
        return (bb_ >> 8) & 1u;
    }
    bool byte(std::uint8_t& out) {
        if (pos_ >= in_.size()) {
            overrun_ = true;
            return false;
        }
        out = in_[pos_++];
        return true;
    }
    bool overrun() const { return overrun_; }
    std::size_t pos() const { return pos_; }

   private:
    std::span<const std::uint8_t> in_;
    std::size_t pos_ = 0;
    std::uint32_t bb_ = 0;
    bool overrun_ = false;
};

}  // namespace

const char* nrv2b_status_code(Nrv2bStatus s) {
    switch (s) {
        case Nrv2bStatus::Ok:
            return "ok";
        case Nrv2bStatus::InputOverrun:
            return "ucl-input-overrun";
        case Nrv2bStatus::OutputOverrun:
            return "decompress-cap";
        case Nrv2bStatus::LookbehindOverrun:
            return "ucl-lookbehind-overrun";
        case Nrv2bStatus::Corrupt:
            return "ucl-corrupt";
    }
    return "ucl-corrupt";
}

Nrv2bStatus nrv2b_decompress(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                             std::uint64_t max_out, std::size_t* consumed) {
    out.clear();
    if (consumed != nullptr) *consumed = 0;
    BitReader br(in);
    std::uint64_t last_off = 1;

    for (;;) {
        // Literals: a 1 bit introduces one stored byte.
        for (;;) {
            const unsigned b = br.bit();
            if (br.overrun()) return Nrv2bStatus::InputOverrun;
            if (b == 0) break;
            std::uint8_t lit = 0;
            if (!br.byte(lit)) return Nrv2bStatus::InputOverrun;
            if (out.size() >= max_out) return Nrv2bStatus::OutputOverrun;
            out.push_back(lit);
        }

        // Offset: prefix code, one data bit then one stop bit per step.
        std::uint64_t code = 1;
        for (;;) {
            code = code * 2 + br.bit();
            const unsigned stop = br.bit();
            if (br.overrun()) return Nrv2bStatus::InputOverrun;
            if (stop != 0) break;
            if (code > kEndCode) return Nrv2bStatus::Corrupt;
        }
        std::uint64_t off = 0;
        if (code == 2) {
            off = last_off;
        } else {
            if (code < 3 || code > kEndCode) return Nrv2bStatus::Corrupt;
            std::uint8_t low = 0;
            if (!br.byte(low)) return Nrv2bStatus::InputOverrun;
            const std::uint64_t raw = (code - 3) * 256 + low;
            if (raw == 0xffffffffu) break;  // end marker
            off = raw + 1;
            last_off = off;
        }

        // Length: two bits, or a prefix code when both are zero.
        std::uint64_t len = br.bit();
        len = len * 2 + br.bit();
        if (br.overrun()) return Nrv2bStatus::InputOverrun;
        if (len == 0) {
            len = 1;
            for (;;) {
                len = len * 2 + br.bit();
                const unsigned stop = br.bit();
                if (br.overrun()) return Nrv2bStatus::InputOverrun;
                if (stop != 0) break;
                if (len > max_out) return Nrv2bStatus::OutputOverrun;
                // NRV2B lengths are 32-bit; a wider code is no stream, and
                // refusing it here keeps the accumulator from wrapping.
                if (len > 0xFFFFFFFFull) return Nrv2bStatus::Corrupt;
            }
            len += 2;
        }
        if (off > kLongDistance) len += 1;
        len += 1;  // the stream stores one less than the copy length

        if (off == 0 || off > out.size()) return Nrv2bStatus::LookbehindOverrun;
        if (len > max_out - out.size()) return Nrv2bStatus::OutputOverrun;
        std::size_t src = out.size() - static_cast<std::size_t>(off);
        for (std::uint64_t i = 0; i < len; ++i) {
            const std::uint8_t b = out[src++];  // copied first: push_back may reallocate
            out.push_back(b);                   // ranges may overlap (run-length style)
        }
    }

    if (consumed != nullptr) *consumed = br.pos();
    return Nrv2bStatus::Ok;
}

}  // namespace omnitrace::compress::ucl
