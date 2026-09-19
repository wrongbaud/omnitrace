// rtime.cpp — see rtime.h.
#include "rtime.h"

#include <array>
#include <cstring>

namespace omnitrace::compress::rtime {

const char* rtime_status_code(RtimeStatus s) {
    switch (s) {
        case RtimeStatus::Ok:
            return "ok";
        case RtimeStatus::InputOverrun:
            return "rtime-input-overrun";
        case RtimeStatus::OutputOverrun:
            return "decompress-cap";
    }
    return "rtime-corrupt";
}

RtimeStatus rtime_decompress(std::span<const std::uint8_t> in, std::vector<std::uint8_t>& out,
                             std::uint64_t max_out) {
    out.clear();
    // Each pair yields 1 + repeat (<= 256) bytes; growth is geometric and
    // capped at max_out so a hostile stream cannot force a huge allocation.
    std::array<std::size_t, 256> positions{};
    std::size_t pos = 0;
    std::size_t ip = 0;
    const std::size_t in_len = in.size();

    auto ensure = [&](std::uint64_t need) {
        if (need > max_out) return false;
        if (need > out.size()) {
            std::uint64_t grow = static_cast<std::uint64_t>(out.size()) * 2;
            if (grow < need) grow = need;
            if (grow < 256) grow = 256;
            if (grow > max_out) grow = max_out;
            out.resize(static_cast<std::size_t>(grow));
        }
        return true;
    };
    auto finish = [&](RtimeStatus s) {
        out.resize(pos);
        return s;
    };

    while (ip < in_len) {
        if (in_len - ip < 2) return finish(RtimeStatus::InputOverrun);
        const std::uint8_t value = in[ip];
        const std::size_t repeat = in[ip + 1];
        ip += 2;
        if (!ensure(static_cast<std::uint64_t>(pos) + 1 + repeat))
            return finish(RtimeStatus::OutputOverrun);
        out[pos++] = value;
        const std::size_t back = positions[value];  // always <= pos - 1 < pos
        positions[value] = pos;
        std::uint8_t* dst = out.data() + pos;
        const std::uint8_t* src = out.data() + back;
        if (back + repeat <= pos) {
            std::memcpy(dst, src, repeat);
        } else {
            for (std::size_t i = 0; i < repeat; ++i) dst[i] = src[i];
        }
        pos += repeat;
    }
    return finish(RtimeStatus::Ok);
}

}  // namespace omnitrace::compress::rtime
