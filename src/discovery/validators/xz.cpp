// xz.cpp — .xz stream header validator.
//
// 0 FD 37 7A 58 5A 00, 6 stream flags (byte 0 must be 0; byte 1 low nibble =
// check type 0/1/4/10, high nibble 0), 8 CRC32 (zlib) of the two flag bytes.
// The flags CRC covers two bytes, so it only guards the Structural tier: it
// never lifts a stream to Verified (that needs a decode probe), and a
// mismatch drops the hit to Magic. Compressed streams inside a validated
// filesystem are then absorbed by it during conflict resolution.
// Reference: The .xz File Format specification §2.1.1
#include <array>

#include "../crc32.h"
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

std::optional<Finding> validate_xz(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    std::array<std::uint8_t, 2> flags{};
    if (span.read(start + 6, std::span<std::uint8_t>(flags.data(), flags.size())) != flags.size()) {
        diag(f, Severity::Warning, "xz-truncated-header",
             "fewer than 12 bytes available for the stream header");
        return f;
    }
    const auto stored = span.at<std::uint32_t>(start + 8, Endian::Little);
    const std::uint8_t check = static_cast<std::uint8_t>(flags[1] & 0x0F);
    const char* check_name = check == 0    ? "none"
                             : check == 1  ? "crc32"
                             : check == 4  ? "crc64"
                             : check == 10 ? "sha256"
                                           : nullptr;
    if (flags[0] != 0 || (flags[1] & 0xF0) != 0 || check_name == nullptr) {
        diag(f, Severity::Warning, "xz-bad-stream-flags",
             "stream flags " + hex_bytes(flags) + " are not valid");
        return f;
    }
    f.attrs["check"] = check_name;
    if (stored &&
        crc32_zlib(std::span<const std::uint8_t>(flags.data(), flags.size())) != *stored) {
        diag(f, Severity::Warning, "xz-header-crc-mismatch", "stream flags CRC32 does not match");
        return f;
    }
    f.confidence = Confidence::Structural;
    if (const std::uint64_t n = compressed_stream_length(f, span, start, compress::Codec::Xz, sig);
        n != 0) {
        f.size = n;
        f.confidence = Confidence::Consistent;
    }
    f.evidence = "stream header CRC ok, check " + std::string(check_name);
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("xz", validate_xz);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(xz)
