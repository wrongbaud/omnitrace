// zip.cpp — ZIP archive validator: finds the end of the archive, which no
// single header states.
//
// A zip is local file headers and their data, then the central directory, then
// the end-of-central-directory record:
//
//   50 4b 03 04  local file header   30 bytes + name + extra, then the data
//   50 4b 07 08  data descriptor     only when flag bit 3 defers the sizes
//   50 4b 01 02  central directory    46 bytes + name + extra + comment
//   50 4b 06 06  zip64 EOCD           56 bytes
//   50 4b 06 07  zip64 EOCD locator   20 bytes
//   50 4b 05 06  EOCD                 22 bytes + comment
//
// The signature matches the local file header, so the walk runs forward: local
// headers until the central directory, the directory entries until the EOCD,
// and the archive ends after the EOCD's comment. Everything but the sizes is
// fixed-width, so the walk is a hop per member and reads no file data.
//
// The one hard case is flag bit 3, which streaming writers set: the sizes are
// zero in the local header and follow the data in a descriptor. There the walk
// searches forward for a descriptor whose compressed size equals the distance
// it sits at, which is a precise check rather than a guess.
//
// Reference: PKWARE APPNOTE.TXT 6.3.10, sections 4.3.6 to 4.3.16.
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint32_t kLocal = 0x04034B50U;
constexpr std::uint32_t kCentral = 0x02014B50U;
constexpr std::uint32_t kEocd = 0x06054B50U;
constexpr std::uint32_t kEocd64 = 0x06064B50U;
constexpr std::uint32_t kEocd64Locator = 0x07064B50U;
constexpr std::uint32_t kDataDescriptor = 0x08074B50U;

constexpr std::uint64_t kLocalHeader = 30;
constexpr std::uint64_t kCentralHeader = 46;
constexpr std::uint64_t kEocdSize = 22;
constexpr std::uint64_t kEocd64Size = 56;
constexpr std::uint64_t kLocatorSize = 20;
constexpr std::uint32_t kFlagDeferredSizes = 0x0008;
constexpr std::uint32_t kZip64Marker = 0xFFFFFFFFU;

std::optional<std::uint32_t> u32(const Span& s, std::uint64_t off) {
    return s.at<std::uint32_t>(off, Endian::Little);
}
std::optional<std::uint16_t> u16(const Span& s, std::uint64_t off) {
    return s.at<std::uint16_t>(off, Endian::Little);
}

// The compressed size from a local header's zip64 extra field (0x0001). The
// field lists uncompressed then compressed size, and carries only the ones
// whose 32-bit slot held the all-ones marker, so the caller says whether the
// uncompressed one is there.
std::optional<std::uint64_t> zip64_sizes(const Span& span, std::uint64_t extra_at,
                                         std::uint64_t extra_len, bool usize_present) {
    const std::uint64_t end = sat_add(extra_at, extra_len);
    for (std::uint64_t x = extra_at; x + 4 <= end;) {
        const auto id = u16(span, x);
        const auto len = u16(span, x + 2);
        if (!id || !len) return std::nullopt;
        if (*id == 0x0001) {
            const std::uint64_t at = x + 4 + (usize_present ? 8 : 0);
            return span.at<std::uint64_t>(at, Endian::Little);
        }
        x += 4ULL + *len;
    }
    return std::nullopt;
}

// The next central-directory header at or after `from`, within `limit`.
//
// A zip is not always members-then-directory: Android inserts an "APK Signing
// Block" between the two (it is how v2 and v3 signatures are carried, and the
// format reserves the space precisely so readers that go via the EOCD do not
// care). Anything else that pads the gap has the same shape. A candidate is
// accepted only if it really is a directory entry whose own name and extra
// lengths land on another entry or on an end record, so a "PK\x01\x02" inside
// compressed data is not mistaken for one.
std::optional<std::uint64_t> find_central_directory(const Span& span, std::uint64_t from,
                                                    std::uint64_t limit) {
    // Chunked, like find_descriptor: a Span accessor per byte over a 16 MiB
    // window is a virtual call per byte.
    constexpr std::size_t kChunk = 1U << 16;
    const std::uint64_t end = std::min(sat_add(from, limit), span.size());
    std::vector<std::uint8_t> buf;
    std::vector<std::uint64_t> candidates;
    for (std::uint64_t base = from; base + 4 <= end;) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(kChunk, end - base));
        buf.resize(want);
        const std::size_t got = span.read(base, std::span<std::uint8_t>(buf.data(), want));
        if (got < 4) break;
        for (std::size_t i = 0; i + 4 <= got; ++i) {
            if (buf[i] == 0x50 && buf[i + 1] == 0x4B && buf[i + 2] == 0x01 && buf[i + 3] == 0x02)
                candidates.push_back(base + i);
        }
        if (got < want) break;
        base += got - 3;
    }
    for (const std::uint64_t p : candidates) {
        if (p + kCentralHeader > end) break;
        const auto namelen = u16(span, p + 28);
        const auto extralen = u16(span, p + 30);
        const auto commentlen = u16(span, p + 32);
        if (!namelen || !extralen || !commentlen) continue;
        const std::uint64_t next = sat_add(p, kCentralHeader + *namelen + *extralen + *commentlen);
        const auto after = u32(span, next);
        if (after && (*after == kCentral || *after == kEocd || *after == kEocd64)) return p;
    }
    return std::nullopt;
}

// Is this local file header plausible enough to walk?
//
// The screen is what keeps the cost of a false positive down. "PK\x03\x04"
// is four bytes, an eMMC image holds hundreds of them inside compressed data,
// and the deferred-sizes branch below searches forward for a data descriptor.
// Without this check that search ran on garbage and took a scan of the QNX
// corpus from 12 seconds to nearly three minutes.
//
// Both fields are narrow in the spec: the version needed to extract is a
// version times ten, so 63 covers every version ever defined, and the
// compression method is one of a short list.
bool plausible_local_header(const Span& span, std::uint64_t pos) {
    const auto version = u16(span, pos + 4);
    const auto method = u16(span, pos + 8);
    if (!version || !method) return false;
    if (*version > 63) return false;
    switch (*method) {
        case 0:   // stored
        case 1:   // shrunk
        case 6:   // imploded
        case 8:   // deflate
        case 9:   // deflate64
        case 12:  // bzip2
        case 14:  // lzma
        case 93:  // zstd
        case 95:  // xz
        case 96:  // jpeg
        case 97:  // wavpack
        case 98:  // ppmd
        case 99:  // AE-x encryption
            return true;
        default:
            return false;
    }
}

// Where the data descriptor after `data_at` sits, found by requiring its
// compressed-size field to equal the distance from the data start. Searching
// for the signature alone would match compressed bytes; this does not.
//
// Read in chunks: a Span accessor per byte over a 64 MiB window is a virtual
// call per byte, which is the difference between a search that is bounded and
// one that is merely finite.
std::optional<std::uint64_t> find_descriptor(const Span& span, std::uint64_t data_at,
                                             std::uint64_t limit) {
    constexpr std::size_t kChunk = 1U << 16;
    const std::uint64_t end = std::min(sat_add(data_at, limit), span.size());
    std::vector<std::uint8_t> buf;
    for (std::uint64_t base = data_at; base + 16 <= end;) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(kChunk, end - base));
        buf.resize(want);
        const std::size_t got = span.read(base, std::span<std::uint8_t>(buf.data(), want));
        if (got < 16) break;
        for (std::size_t i = 0; i + 16 <= got; ++i) {
            if (buf[i] != 0x50 || buf[i + 1] != 0x4B || buf[i + 2] != 0x07 || buf[i + 3] != 0x08)
                continue;
            const std::uint64_t p = base + i;
            const std::uint32_t csize = static_cast<std::uint32_t>(buf[i + 8]) |
                                        (static_cast<std::uint32_t>(buf[i + 9]) << 8) |
                                        (static_cast<std::uint32_t>(buf[i + 10]) << 16) |
                                        (static_cast<std::uint32_t>(buf[i + 11]) << 24);
            if (csize == p - data_at) return p;
        }
        // Overlap so a record straddling the chunk edge is still seen.
        base += got - 15;
    }
    return std::nullopt;
}

std::optional<Finding> validate_zip(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Little;

    const std::uint64_t cap = extra_u64(sig, "max_entries").value_or(200000);
    const std::uint64_t search = extra_u64(sig, "max_descriptor_search").value_or(64ULL << 20);
    // The gap before the directory is a signing block or similar padding, not
    // member data, so it is bounded much more tightly than a member is.
    const std::uint64_t gap_search = extra_u64(sig, "max_gap_search").value_or(16ULL << 20);

    // Pass 1: the local headers, up to the central directory.
    std::uint64_t pos = start;
    std::uint64_t locals = 0;
    bool reached_central = false;
    bool deferred = false;
    for (;;) {
        const auto s = u32(span, pos);
        if (!s) break;
        if (*s == kCentral) {
            reached_central = true;
            break;
        }
        if (*s == kLocal && !plausible_local_header(span, pos)) {
            diag(f, Severity::Info, "zip-no-central-directory",
                 "the header at " + hex(span.absolute(pos)) +
                     " has no usable version or compression method; the archive has no extent and "
                     "claims no bytes");
            f.attrs["extent"] = "unknown";
            f.attrs["entries"] = dec(locals);
            return f;
        }
        if (*s != kLocal) {
            // Not a member and not the directory: something sits between them.
            //
            // Only worth looking when at least one member was walked. A stray
            // "PK\x03\x04" in compressed data stops on its very first header,
            // and searching megabytes forward from each of the hundreds of
            // those in an eMMC image costs more than the whole rest of the
            // analysis: it took the QNX corpus from 2m18 to 6m37.
            if (locals == 0) break;
            if (const auto cd = find_central_directory(span, pos, gap_search)) {
                f.attrs["gap_before_directory"] = dec(*cd - pos);
                pos = *cd;
                reached_central = true;
            }
            break;
        }
        if (locals > cap) {
            diag(f, Severity::Warning, "zip-limit-entries",
                 "more than " + dec(cap) + " members before the central directory");
            break;
        }
        const auto flags = u16(span, pos + 6);
        const auto csize = u32(span, pos + 18);
        const auto namelen = u16(span, pos + 26);
        const auto extralen = u16(span, pos + 28);
        if (!flags || !csize || !namelen || !extralen) break;
        const std::uint64_t data_at = sat_add(pos, kLocalHeader + *namelen + *extralen);
        std::uint64_t next = 0;
        if ((*flags & kFlagDeferredSizes) != 0 && *csize == 0) {
            deferred = true;
            const auto desc = find_descriptor(span, data_at, search);
            if (!desc) {
                diag(f, Severity::Info, "zip-deferred-sizes",
                     "member " + dec(locals) +
                         " defers its sizes to a data descriptor that was not found; the archive "
                         "has no extent and claims no bytes");
                f.attrs["extent"] = "unknown";
                f.attrs["entries"] = dec(locals);
                return f;
            }
            next = sat_add(*desc, 16);  // signature + crc + both sizes
        } else {
            std::uint64_t real_csize = *csize;
            if (*csize == kZip64Marker) {
                // zip64 puts the real sizes in the 0x0001 extra field, as
                // uncompressed then compressed, each present only when its
                // 32-bit field held the marker.
                const auto usize_field = u32(span, pos + 22);
                const auto z = zip64_sizes(span, pos + kLocalHeader + *namelen, *extralen,
                                           usize_field && *usize_field == kZip64Marker);
                if (!z) {
                    diag(f, Severity::Info, "zip-deferred-sizes",
                         "member " + dec(locals) +
                             " claims zip64 sizes but has no readable zip64 extra field");
                    f.attrs["extent"] = "unknown";
                    f.attrs["entries"] = dec(locals);
                    return f;
                }
                real_csize = *z;
                f.attrs["zip64"] = "true";
            }
            next = sat_add(data_at, real_csize);
        }
        if (next <= pos || next >= span.size()) {
            diag(f, Severity::Warning, "zip-truncated",
                 "member " + dec(locals) + " runs past the available data");
            f.attrs["extent"] = "unknown";
            f.attrs["entries"] = dec(locals);
            return f;
        }
        ++locals;
        pos = next;
    }
    if (!reached_central) {
        diag(f, Severity::Info, "zip-no-central-directory",
             "no central directory was reached, so the archive has no extent and claims no bytes");
        f.attrs["extent"] = "unknown";
        f.attrs["entries"] = dec(locals);
        return f;
    }
    f.confidence = Confidence::Structural;
    const std::uint64_t cd_at = pos;

    // Pass 2: the central directory entries, up to the EOCD.
    std::uint64_t entries = 0;
    bool reached_eocd = false;
    for (;;) {
        const auto s = u32(span, pos);
        if (!s) break;
        if (*s == kEocd || *s == kEocd64) {
            reached_eocd = true;
            break;
        }
        if (*s != kCentral || entries > cap) break;
        const auto namelen = u16(span, pos + 28);
        const auto extralen = u16(span, pos + 30);
        const auto commentlen = u16(span, pos + 32);
        if (!namelen || !extralen || !commentlen) break;
        const std::uint64_t next =
            sat_add(pos, kCentralHeader + *namelen + *extralen + *commentlen);
        if (next <= pos || next > span.size()) break;
        ++entries;
        pos = next;
    }
    if (!reached_eocd) {
        diag(f, Severity::Warning, "zip-no-eocd",
             "the central directory does not end in an end-of-central-directory record");
        f.attrs["extent"] = "unknown";
        f.attrs["entries"] = dec(entries);
        return f;
    }

    // Pass 3: the trailer. A zip64 archive puts its own EOCD and a locator
    // before the 22-byte one, and every one of them is fixed-width.
    std::uint64_t end = pos;
    if (const auto s = u32(span, end); s && *s == kEocd64) {
        f.attrs["zip64"] = "true";
        end = sat_add(end, kEocd64Size);
        if (const auto loc = u32(span, end); loc && *loc == kEocd64Locator)
            end = sat_add(end, kLocatorSize);
    }
    const auto eocd_sig = u32(span, end);
    if (!eocd_sig || *eocd_sig != kEocd) {
        diag(f, Severity::Warning, "zip-no-eocd",
             "the record after the central directory is not an end-of-central-directory record");
        f.attrs["extent"] = "unknown";
        f.attrs["entries"] = dec(entries);
        return f;
    }
    const auto cd_offset = u32(span, end + 16);
    const auto commentlen = u16(span, end + 20);
    if (!commentlen) {
        diag(f, Severity::Warning, "zip-truncated", "the EOCD record is cut short");
        f.attrs["extent"] = "unknown";
        return f;
    }
    // The EOCD's own view of where the directory starts must agree with where
    // the walk found it. That is what separates a real archive from a run of
    // bytes that happened to parse.
    if (cd_offset && *cd_offset != kZip64Marker && start + *cd_offset != cd_at) {
        diag(f, Severity::Warning, "zip-cd-offset-mismatch",
             "the EOCD points the central directory at " + hex(span.absolute(start + *cd_offset)) +
                 " but it was walked to " + hex(span.absolute(cd_at)));
    } else {
        f.confidence = Confidence::Consistent;
    }

    end = sat_add(end, kEocdSize + *commentlen);
    f.attrs["entries"] = dec(entries);
    f.attrs["local_headers"] = dec(locals);
    if (deferred) f.attrs["deferred_sizes"] = "true";
    bool truncated = false;
    f.size = clamp_size(span, start, end - start, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "zip-truncated", "the archive ends past the available data");
    }
    f.evidence = dec(entries) + " member(s), central directory at " +
                 hex(span.absolute(cd_at)) + ", " + dec(end - start) + " bytes";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("zip", validate_zip);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(zip)
