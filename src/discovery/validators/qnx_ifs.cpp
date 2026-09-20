// qnx_ifs.cpp — QNX IFS (mkifs image filesystem) validator.
//
// An IFS starts with the 256-byte startup header (sys/startup.h): 0 signature
// u32 0x00ff7eeb, 4 version u16 (1), 6 flags1 u8 (0x01 virtual, 0x02
// big-endian, 0x1c compression: 0x04 zlib, 0x08 lzo, 0x0c ucl), 7 flags2 u8,
// 8 header_size u16 (256), 10 machine u16 (ELF e_machine), 12 startup_vaddr,
// 16 paddr_bias, 20 image_paddr, 24 ram_paddr, 28 ram_size, 32 startup_size,
// 36 stored_size, 40 imagefs_paddr, 44 imagefs_size, 48 preboot_size u16,
// 50 zero0 u16, 52 zero[3] u32, 64 info[48] u32. The startup code follows and
// the last 4 bytes of the startup_size region are a checksum making the
// little-endian u32 sum of the region zero. At start + startup_size sits the
// image filesystem: uncompressed, its 88-byte header ("imagefs", flags,
// image_size, hdr_dir_size, dir_offset, boot_ino[4], script_ino, chain_paddr,
// spare[10], mountflags, mountpoint) whose image_size bytes again sum to zero;
// compressed, a sequence of blocks each prefixed by a 2-byte big-endian
// length, a zero length ending the sequence, padding to 4 and a checksum
// that zeroes the sum of stored_size - startup_size bytes (zlib images hold
// one gzip stream instead). Fields are in target byte order (flags1 0x02).
// Format knowledge: the QNX SDP startup_header and mkifs documentation and
// the sys/startup.h, sys/image.h headers, read for understanding; nothing
// copied. Reader: src/filesystems/qnxifs/, docs/formats/qnx-ifs.md.
#include <array>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kStartupHeaderSize = 256;
constexpr std::uint64_t kImageHeaderSize = 88;
constexpr std::uint64_t kDirentAttrSize = 24;
constexpr std::uint32_t kInoFlagMask = 0xe0000000u;  // processed/runonce/bootstrap ELF bits
constexpr std::uint32_t kIfMt = 0170000, kIfReg = 0100000;
constexpr std::uint64_t kDefaultMaxDirEntries = 1000000;  // TOML: max_dir_entries
constexpr std::uint64_t kDefaultMaxBlocks = 1u << 20;     // TOML: max_blocks

const char* machine_name(std::uint16_t m) {
    switch (m) {
        case 3:
            return "x86";
        case 8:
            return "mips";
        case 20:
            return "ppc";
        case 40:
            return "arm";
        case 42:
            return "sh";
        case 62:
            return "x86_64";
        case 183:
            return "aarch64";
        case 243:
            return "riscv";
        default:
            return nullptr;
    }
}

const char* codec_name(unsigned c) {
    switch (c) {
        case 0:
            return "none";
        case 1:
            return "zlib";
        case 2:
            return "lzo";
        case 3:
            return "ucl";
        case 4:
            return "lz4";
        default:
            return nullptr;
    }
}

// Little-endian u32 sum over [off, off+len) of the span; false when short.
bool sum_words(const Span& span, std::uint64_t off, std::uint64_t len, Endian e,
               std::uint32_t& sum) {
    sum = 0;
    std::array<std::uint8_t, 4096> buf{};
    for (std::uint64_t done = 0; done + 4 <= len;) {
        const std::uint64_t want = std::min<std::uint64_t>(buf.size(), (len - done) & ~3ull);
        if (span.read(off + done,
                      std::span<std::uint8_t>(buf.data(), static_cast<std::size_t>(want))) != want)
            return false;
        for (std::uint64_t i = 0; i < want; i += 4)
            sum += load_int<std::uint32_t>(buf.data() + i, e);
        done += want;
    }
    return true;
}

std::optional<Finding> validate_qnx_ifs(const Span& span, std::uint64_t start,
                                        const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    const auto flags1 = span.u8(start + 6);
    const auto zero2 = span.at<std::uint32_t>(start + 60, Endian::Little);
    if (!flags1 || !zero2) {
        diag(f, Severity::Warning, "qnx-ifs-truncated-header",
             "fewer than 64 bytes available for the startup header");
        return f;
    }
    const Endian e = (*flags1 & 0x02) != 0 ? Endian::Big : Endian::Little;
    f.endian = e;
    const std::uint16_t version = span.at<std::uint16_t>(start + 4, e).value_or(0);
    const std::uint8_t flags2 = span.u8(start + 7).value_or(0);
    const std::uint16_t header_size = span.at<std::uint16_t>(start + 8, e).value_or(0);
    const std::uint16_t machine = span.at<std::uint16_t>(start + 10, e).value_or(0);
    const std::uint32_t startup_vaddr = span.at<std::uint32_t>(start + 12, e).value_or(0);
    const std::uint32_t paddr_bias = span.at<std::uint32_t>(start + 16, e).value_or(0);
    const std::uint32_t image_paddr = span.at<std::uint32_t>(start + 20, e).value_or(0);
    const std::uint32_t ram_paddr = span.at<std::uint32_t>(start + 24, e).value_or(0);
    const std::uint32_t ram_size = span.at<std::uint32_t>(start + 28, e).value_or(0);
    const std::uint32_t startup_size = span.at<std::uint32_t>(start + 32, e).value_or(0);
    const std::uint32_t stored_size = span.at<std::uint32_t>(start + 36, e).value_or(0);
    const std::uint32_t imagefs_size = span.at<std::uint32_t>(start + 44, e).value_or(0);
    const std::uint16_t preboot_size = span.at<std::uint16_t>(start + 48, e).value_or(0);
    const std::uint16_t zero0 = span.at<std::uint16_t>(start + 50, e).value_or(0);
    const std::uint32_t zero1 = span.at<std::uint32_t>(start + 52, e).value_or(0);
    const std::uint32_t zero1b = span.at<std::uint32_t>(start + 56, e).value_or(0);

    // A 4-byte magic inside compressed or random data is common (the
    // corpus has two in one 2 MiB splash partition); the fixed fields are
    // the discriminator, so a mismatch is noise, not a corrupt header.
    if (version != 1 || header_size != kStartupHeaderSize || zero0 != 0 || zero1 != 0 ||
        zero1b != 0 || *zero2 != 0)
        return std::nullopt;

    f.attrs["version"] = dec(version);
    f.attrs["flags1"] = hex(*flags1);
    f.attrs["flags2"] = hex(flags2);
    f.attrs["startup_vaddr"] = hex(startup_vaddr);
    f.attrs["paddr_bias"] = hex(paddr_bias);
    f.attrs["image_paddr"] = hex(image_paddr);
    f.attrs["ram_paddr"] = hex(ram_paddr);
    f.attrs["ram_size"] = dec(ram_size);
    f.attrs["startup_size"] = dec(startup_size);
    f.attrs["stored_size"] = dec(stored_size);
    f.attrs["imagefs_size"] = dec(imagefs_size);
    if (preboot_size != 0) f.attrs["preboot_size"] = dec(preboot_size);
    const char* mname = machine_name(machine);
    f.attrs["machine"] = mname != nullptr ? mname : "unknown(" + hex(machine) + ")";
    const unsigned codec = (*flags1 & 0x1c) >> 2;
    const char* cname = codec_name(codec);
    f.attrs["compressed"] = cname != nullptr ? cname : "unknown(" + dec(codec) + ")";

    if (startup_size < kStartupHeaderSize || (startup_size & 3) != 0 ||
        (stored_size != 0 && startup_size > stored_size)) {
        diag(f, Severity::Warning, "qnx-ifs-bad-startup-size",
             "startup_size " + dec(startup_size) + " and stored_size " + dec(stored_size) +
                 " are not a header plus startup code inside the stored image");
        return f;
    }
    if (mname == nullptr)
        diag(f, Severity::Warning, "qnx-ifs-unknown-machine",
             "machine " + hex(machine) + " is not an ELF machine QNX Neutrino runs on");
    if (cname == nullptr) {
        diag(f, Severity::Warning, "qnx-ifs-unsupported-compression",
             "flags1 compression code " + dec(codec) + " is not zlib, lzo, ucl or lz4");
        bool truncated = false;
        f.size = clamp_size(span, start, stored_size, truncated);
        return f;
    }
    if (startup_size > remaining(span, start)) {
        diag(f, Severity::Warning, "qnx-ifs-truncated",
             "startup_size " + dec(startup_size) + " extends past the available data");
        f.size = remaining(span, start);
        return f;
    }
    f.confidence = Confidence::Structural;

    // Startup checksum: the region sums to zero. Vendors patch the header
    // after mkifs (flags2, the info array), so a mismatch is reported and
    // does not change the tier.
    std::uint32_t sum = 0;
    if (sum_words(span, start, startup_size, e, sum) && sum == 0) {
        f.attrs["startup_checksum"] = "ok";
    } else {
        f.attrs["startup_checksum"] = "mismatch";
        diag(f, Severity::Warning, "qnx-ifs-startup-checksum-bad",
             "startup header and code sum to " + hex_fixed(sum, 8) + ", not zero" +
                 (sum == static_cast<std::uint32_t>(flags2) << 24
                      ? " (the residual is flags2 alone: set after mkifs)"
                      : ""));
    }

    const std::uint64_t ipos = start + startup_size;
    if (codec == 0) {
        static constexpr std::uint8_t kSig[] = {'i', 'm', 'a', 'g', 'e', 'f', 's'};
        const auto image_size = span.at<std::uint32_t>(ipos + 8, e);
        if (!span.matches_at(ipos, kSig) || !image_size) {
            diag(f, Severity::Warning, "qnx-ifs-no-image-header",
                 "no \"imagefs\" header at startup_size (" + hex(startup_size) + ")");
            bool truncated = false;
            f.size = clamp_size(span, start, stored_size, truncated);
            return f;
        }
        const std::uint8_t iflags = span.u8(ipos + 7).value_or(0);
        const Endian ie = (iflags & 0x01) != 0 ? Endian::Big : Endian::Little;
        const std::uint32_t isize = span.at<std::uint32_t>(ipos + 8, ie).value_or(0);
        const std::uint32_t hdr_dir_size = span.at<std::uint32_t>(ipos + 12, ie).value_or(0);
        const std::uint32_t dir_offset = span.at<std::uint32_t>(ipos + 16, ie).value_or(0);
        const std::uint32_t script_ino = span.at<std::uint32_t>(ipos + 36, ie).value_or(0);
        f.attrs["image_flags"] = hex(iflags);
        f.attrs["image_size"] = dec(isize);
        f.attrs["hdr_dir_size"] = dec(hdr_dir_size);
        f.attrs["dir_offset"] = dec(dir_offset);
        std::string boots;
        for (std::uint64_t i = 0; i < 4; ++i) {
            const std::uint32_t b = span.at<std::uint32_t>(ipos + 20 + 4 * i, ie).value_or(0);
            if (b != 0) boots += (boots.empty() ? "" : ",") + dec(b & ~kInoFlagMask);
        }
        if (!boots.empty()) f.attrs["boot_ino"] = boots;
        f.attrs["script"] = script_ino != 0 ? "true" : "false";
        if (dir_offset >= kImageHeaderSize) {
            const auto mp = span.cstring(ipos + kImageHeaderSize,
                                         static_cast<std::size_t>(dir_offset - kImageHeaderSize));
            if (mp && !mp->empty()) f.attrs["mountpoint"] = list_safe(*mp);
        }
        const std::uint64_t claimed = sat_add(startup_size, isize);
        bool truncated = false;
        f.size = clamp_size(span, start, std::max<std::uint64_t>(claimed, stored_size), truncated);
        if (dir_offset < kImageHeaderSize || dir_offset > hdr_dir_size || hdr_dir_size > isize ||
            isize < kImageHeaderSize + 4) {
            diag(f, Severity::Warning, "qnx-ifs-bad-image-header",
                 "dir_offset " + dec(dir_offset) + ", hdr_dir_size " + dec(hdr_dir_size) +
                     " and image_size " + dec(isize) + " are not nested");
            return f;
        }
        if (truncated) {
            diag(f, Severity::Warning, "qnx-ifs-truncated",
                 "image_size " + dec(isize) + " at " + hex(startup_size) +
                     " extends past the available data");
            return f;
        }
        if (stored_size != 0 && claimed > stored_size)
            diag(f, Severity::Info, "qnx-ifs-stored-size-mismatch",
                 "startup_size + image_size (" + dec(claimed) + ") exceeds stored_size " +
                     dec(stored_size));
        // Count directory entries by their size chain.
        const std::uint64_t max_entries =
            extra_u64(sig, "max_dir_entries").value_or(kDefaultMaxDirEntries);
        std::uint64_t entries = 0, files = 0;
        bool dir_ok = true;
        for (std::uint64_t pos = dir_offset; pos + kDirentAttrSize <= hdr_dir_size;) {
            const std::uint16_t esize = span.at<std::uint16_t>(ipos + pos, ie).value_or(0);
            if (esize == 0) break;
            if (esize < kDirentAttrSize || pos + esize > hdr_dir_size) {
                dir_ok = false;
                break;
            }
            const std::uint32_t mode = span.at<std::uint32_t>(ipos + pos + 8, ie).value_or(0);
            if ((mode & kIfMt) == kIfReg) files++;
            entries++;
            if (entries >= max_entries) break;
            pos += esize;
        }
        f.attrs["entries"] = dec(entries);
        f.attrs["files"] = dec(files);
        if (!dir_ok) {
            diag(f, Severity::Warning, "qnx-ifs-dirent-corrupt",
                 "directory entry chain breaks after " + dec(entries) + " entries");
            return f;
        }
        f.confidence = Confidence::Consistent;
        std::uint32_t isum = 0;
        if (sum_words(span, ipos, isize, ie, isum) && isum == 0) {
            f.attrs["image_checksum"] = "ok";
            f.confidence = Confidence::Verified;
        } else {
            f.attrs["image_checksum"] = "mismatch";
            diag(f, Severity::Warning, "qnx-ifs-image-checksum-bad",
                 "image filesystem sums to " + hex_fixed(isum, 8) + ", not zero");
        }
        f.evidence = "qnx-ifs " + f.attrs["machine"] + ", uncompressed, " + dec(entries) +
                     " entries, image checksum " + f.attrs["image_checksum"];
        return f;
    }

    // Compressed: the area after the startup code. zlib is one gzip stream;
    // lzo, ucl and lz4 are length-prefixed blocks ended by a zero length.
    const std::uint64_t comp_start = ipos;
    std::uint64_t comp_end = 0;
    bool has_trailer = false;  // a checksum word ends the stored area
    if (codec == 1) {
        static constexpr std::uint8_t kGzip[] = {0x1f, 0x8b};
        if (!span.matches_at(comp_start, kGzip)) {
            diag(f, Severity::Warning, "qnx-ifs-bad-compressed-block",
                 "no gzip stream at startup_size (" + hex(startup_size) + ")");
            f.confidence = Confidence::Magic;
            bool truncated = false;
            f.size = clamp_size(span, start, stored_size, truncated);
            return f;
        }
        bool truncated = false;
        f.size = clamp_size(span, start, stored_size, truncated);
        if (truncated)
            diag(f, Severity::Warning, "qnx-ifs-truncated",
                 "stored_size " + dec(stored_size) + " extends past the available data");
        comp_end = start + f.size;
        has_trailer = !truncated;
    } else {
        const std::uint64_t max_blocks = extra_u64(sig, "max_blocks").value_or(kDefaultMaxBlocks);
        const std::uint16_t first = span.at<std::uint16_t>(comp_start, Endian::Big).value_or(0);
        if (first == 0 || comp_start + 2 + first > span.size()) {
            diag(f, Severity::Warning, "qnx-ifs-bad-compressed-block",
                 "first compressed block length " + dec(first) + " at " + hex(startup_size) +
                     " is zero or runs past the data");
            f.confidence = Confidence::Magic;
            bool truncated = false;
            f.size = clamp_size(span, start, stored_size, truncated);
            return f;
        }
        std::uint64_t blocks = 0, comp_bytes = 0, pos = comp_start;
        bool terminated = false, ok = true;
        while (blocks < max_blocks) {
            const auto len = span.at<std::uint16_t>(pos, Endian::Big);
            if (!len) {
                ok = false;
                break;
            }
            pos += 2;
            if (*len == 0) {
                terminated = true;
                break;
            }
            if (*len > span.size() - pos) {
                ok = false;
                break;
            }
            pos += *len;
            comp_bytes += *len;
            blocks++;
        }
        f.attrs["blocks"] = dec(blocks);
        f.attrs["compressed_bytes"] = dec(comp_bytes);
        if (!terminated) {
            diag(f, Severity::Warning, ok ? "qnx-ifs-limit-blocks" : "qnx-ifs-truncated",
                 ok ? "more than " + dec(max_blocks) + " compressed blocks; walk stopped"
                    : "compressed block chain runs past the available data after " + dec(blocks) +
                          " blocks");
            f.size = ok ? pos - start : remaining(span, start);
            return f;
        }
        // The stored image ends the chain with padding to 4 and a checksum
        // word; accept stored_size when it says so, else claim the chain.
        const std::uint64_t chain_end = pos;
        const std::uint64_t padded = sat_add((chain_end - start + 3) & ~3ull, 4);
        if (stored_size >= chain_end - start && stored_size <= padded &&
            stored_size <= remaining(span, start))
            comp_end = start + stored_size;
        else
            comp_end = chain_end;
        has_trailer = comp_end >= chain_end + 4;
        f.size = comp_end - start;
        if (stored_size != 0 && comp_end != start + stored_size)
            diag(f, Severity::Info, "qnx-ifs-stored-size-mismatch",
                 "compressed block chain ends at " + dec(chain_end - start) +
                     " bytes but stored_size is " + dec(stored_size));
    }
    f.attrs["stored_checksum"] = "unverified";
    if (has_trailer && comp_end == start + stored_size) {
        std::uint32_t csum = 0;
        if (sum_words(span, comp_start, comp_end - comp_start, e, csum) && csum == 0) {
            f.attrs["stored_checksum"] = "ok";
            f.confidence = Confidence::Verified;
        } else {
            f.attrs["stored_checksum"] = "mismatch";
            diag(f, Severity::Warning, "qnx-ifs-stored-checksum-bad",
                 "compressed area sums to " + hex_fixed(csum, 8) + ", not zero");
        }
    }
    f.evidence = "qnx-ifs " + f.attrs["machine"] + ", " + cname + "-compressed, " + dec(f.size) +
                 " bytes stored, checksum " + f.attrs["stored_checksum"];
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("qnx-ifs", validate_qnx_ifs);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(qnx_ifs)
