// QnxIfsReader.cpp — QNX IFS reader. See QnxIfsReader.h and
// docs/formats/qnx-ifs.md.
//
// Format knowledge: the QNX SDP documentation of the startup header, the
// image header and mkifs, and the sys/startup.h / sys/image.h headers, read
// for understanding; nothing copied. Every byte of evidence is read through
// Span; every cap is a Limits field.
//
// Pipeline:
//   open()  parse the startup header (target byte order from flags1), verify
//           its checksum, locate the image filesystem after the startup code;
//           when flags1 selects a compressor, walk the length-prefixed block
//           chain and decompress it into a bounded in-memory image; parse the
//           image header, verify its checksum, count the directory entries
//   walk()  the directory in stored order: files streamed one chunk at a
//           time from the (possibly decompressed) image, directories,
//           symlinks and devices with the attributes mkifs recorded
#include "QnxIfsReader.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "../../core/ucl.h"
#include "omnitrace/core/Compression.h"
#include "omnitrace/core/Endian.h"
#include "omnitrace/core/Source.h"

namespace omnitrace::fs {

namespace detail {
void omnitrace_fs_anchor_qnxifs() {}
}  // namespace detail

namespace {

// ------------------------------------------------------------------ constants
// Format constants from sys/startup.h and sys/image.h; not tunable limits.
constexpr std::uint64_t kStartupHeaderSize = 256;
constexpr std::uint64_t kImageHeaderSize = 88;
constexpr std::uint64_t kDirentAttrSize = 24;
constexpr std::uint8_t kFlags1BigEndian = 0x02;
constexpr std::uint8_t kFlags1CompressMask = 0x1c;
constexpr std::uint8_t kImageFlagsBigEndian = 0x01;
constexpr std::uint32_t kInoProcessedElf = 0x80000000u;
constexpr std::uint32_t kInoRunonceElf = 0x40000000u;
constexpr std::uint32_t kInoBootstrapExe = 0x20000000u;
constexpr std::uint32_t kInoFlagMask = kInoProcessedElf | kInoRunonceElf | kInoBootstrapExe;

constexpr std::uint32_t kIfMt = 0170000, kIfSock = 0140000, kIfLnk = 0120000, kIfReg = 0100000,
                        kIfBlk = 0060000, kIfNam = 0050000, kIfDir = 0040000, kIfChr = 0020000,
                        kIfFifo = 0010000;

enum Codec : unsigned {
    kCodecNone = 0,
    kCodecZlib = 1,
    kCodecLzo = 2,
    kCodecUcl = 3,
    kCodecLz4 = 4
};

// Streaming chunk. A performance knob, not an input guard.
constexpr std::size_t kChunk = 64 * 1024;

// Diagnostic codes. Tests and downstream agents key on these strings.
constexpr const char* kCodeStartupChecksumBad = "qnx-ifs-startup-checksum-bad";
constexpr const char* kCodeImageChecksumBad = "qnx-ifs-image-checksum-bad";
constexpr const char* kCodeDecompressFailed = "qnx-ifs-decompress-failed";
constexpr const char* kCodeDecompressCap = "qnx-ifs-decompress-cap";
constexpr const char* kCodeDirentCorrupt = "qnx-ifs-dirent-corrupt";
constexpr const char* kCodeEntrySkipped = "qnx-ifs-entry-skipped";
constexpr const char* kCodeFileOutOfRange = "qnx-ifs-file-out-of-range";
constexpr const char* kCodeImageTruncated = "qnx-ifs-image-truncated";
constexpr const char* kCodeLimitNodes = "qnx-ifs-limit-nodes";
constexpr const char* kCodeLimitBlocks = "qnx-ifs-limit-blocks";
constexpr const char* kCodeLimitFiles = "qnx-ifs-limit-files";
constexpr const char* kCodeLimitFileBytes = "qnx-ifs-limit-file-bytes";
constexpr const char* kCodeSinkError = "qnx-ifs-sink-error";

std::string dec(std::uint64_t v) {
    return std::to_string(v);
}
std::string hex(std::uint64_t v) {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    do {
        s.insert(s.begin(), digits[v & 0xf]);
        v >>= 4;
    } while (v);
    return "0x" + s;
}
std::string hex8(std::uint32_t v) {
    static const char digits[] = "0123456789abcdef";
    std::string s(8, '0');
    for (int i = 7; i >= 0; --i) {
        s[static_cast<std::size_t>(i)] = digits[v & 0xf];
        v >>= 4;
    }
    return "0x" + s;
}
std::uint64_t sat_mul(std::uint64_t a, std::uint64_t b) {
    if (a == 0 || b == 0) return 0;
    return a > UINT64_MAX / b ? UINT64_MAX : a * b;
}

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
        case kCodecNone:
            return "none";
        case kCodecZlib:
            return "zlib";
        case kCodecLzo:
            return "lzo";
        case kCodecUcl:
            return "ucl";
        case kCodecLz4:
            return "lz4";
        default:
            return nullptr;
    }
}

EntryKind kind_from_mode(std::uint32_t mode) {
    switch (mode & kIfMt) {
        case kIfReg:
            return EntryKind::Regular;
        case kIfDir:
            return EntryKind::Directory;
        case kIfLnk:
            return EntryKind::Symlink;
        case kIfChr:
            return EntryKind::CharDevice;
        case kIfBlk:
            return EntryKind::BlockDevice;
        case kIfFifo:
            return EntryKind::Fifo;
        case kIfSock:
            return EntryKind::Socket;
        case kIfNam:
        default:
            return EntryKind::Unknown;
    }
}

// u32 sum over [off, off+len) of the span in byte order `e`; false when short.
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

// NUL-terminated string inside [off, off+max) of the span; nullopt when no
// NUL exists inside the window or the window is outside the span.
std::optional<std::string> nul_string(const Span& span, std::uint64_t off, std::uint64_t max) {
    if (off > span.size() || max > span.size() - off) return std::nullopt;
    const auto raw = span.bytes(off, static_cast<std::size_t>(max));
    if (!raw) return std::nullopt;
    const auto nul = std::find(raw->begin(), raw->end(), std::uint8_t{0});
    if (nul == raw->end()) return std::nullopt;
    return std::string(raw->begin(), nul);
}

}  // namespace

// ------------------------------------------------------------------ Impl

struct QnxIfsReader::Impl {
    Span span;
    bool opened = false;

    // Startup header.
    Endian se = Endian::Little;
    std::uint16_t version = 0, machine = 0, preboot_size = 0;
    std::uint8_t flags1 = 0, flags2 = 0;
    std::uint32_t startup_vaddr = 0, paddr_bias = 0, image_paddr = 0, ram_paddr = 0, ram_size = 0,
                  startup_size = 0, stored_size = 0, imagefs_paddr = 0, imagefs_size = 0;
    unsigned codec = kCodecNone;
    bool startup_checksum_ok = false;
    std::uint32_t startup_sum = 0;
    std::vector<Diagnostic> startup_diags;  // kept across a re-decompression

    // Compressed area (codec != none); the chain is walked by decompress().
    std::uint64_t comp_start = 0, comp_end = 0, comp_bytes = 0, blocks = 0;
    bool chain_terminated = true, chain_capped = false;
    Limits decomp_limits;  // the caps the current decompression used
    bool decomp_capped = false, decomp_failed = false;
    std::uint64_t decompressed_bytes = 0;
    std::vector<Diagnostic> decomp_diags;

    // The image filesystem, from its "imagefs" header.
    Span image;
    bool image_ok = false;
    Endian ie = Endian::Little;
    std::uint8_t image_flags = 0;
    std::uint32_t image_size = 0, hdr_dir_size = 0, dir_offset = 0, script_ino = 0, chain_paddr = 0,
                  mountflags = 0;
    std::array<std::uint32_t, 4> boot_ino{};
    std::string mountpoint;
    bool image_checksum_ok = false, image_truncated = false;
    std::uint32_t image_sum = 0;
    std::uint64_t dir_end = 0;  // end of the dirent area inside `image`

    // Directory census from open().
    std::uint64_t entries = 0, files = 0, dirs = 0, symlinks = 0, devices = 0, skipped = 0;
    std::uint32_t root_mode = 0, root_mtime = 0;
    bool root_seen = false;

    std::vector<Diagnostic> open_diags;

    Status parse_startup();
    void decompress(const Limits& L);
    Status parse_image();
    void census();

    // walk
    struct Walk {
        Sink* sink = nullptr;
        const WalkOptions* opts = nullptr;
        WalkResult* out = nullptr;
        bool stop = false;
        std::vector<std::uint8_t> chunk;
    };
    void walk_dir(Walk& w);
    bool check_limits(const std::string& path, Walk& w);
    void emit_regular(FileMeta meta, std::uint64_t off, std::uint64_t size, Walk& w);
    void emit_other(const FileMeta& meta, Walk& w, std::vector<Diagnostic> diags);
    static void count_entry(WalkResult& out, const FileMeta& m);
    static void diag(WalkResult& out, Severity s, const char* code, std::string msg) {
        out.diagnostics.push_back({s, code, std::move(msg)});
    }
};

// ------------------------------------------------------------------ open

Status QnxIfsReader::Impl::parse_startup() {
    static constexpr std::uint8_t kSigLe[] = {0xeb, 0x7e, 0xff, 0x00};
    static constexpr std::uint8_t kSigBe[] = {0x00, 0xff, 0x7e, 0xeb};
    if (!span.matches_at(0, kSigLe) && !span.matches_at(0, kSigBe))
        return Status::fail("qnx-ifs-bad-header: no startup header signature at offset 0");
    const auto f1 = span.u8(6);
    const auto last = span.at<std::uint32_t>(kStartupHeaderSize - 4, Endian::Little);
    if (!f1 || !last)
        return Status::fail("qnx-ifs-bad-header: fewer than 256 bytes for the startup header");
    flags1 = *f1;
    se = (flags1 & kFlags1BigEndian) != 0 ? Endian::Big : Endian::Little;
    version = span.at<std::uint16_t>(4, se).value_or(0);
    flags2 = span.u8(7).value_or(0);
    const std::uint16_t header_size = span.at<std::uint16_t>(8, se).value_or(0);
    machine = span.at<std::uint16_t>(10, se).value_or(0);
    startup_vaddr = span.at<std::uint32_t>(12, se).value_or(0);
    paddr_bias = span.at<std::uint32_t>(16, se).value_or(0);
    image_paddr = span.at<std::uint32_t>(20, se).value_or(0);
    ram_paddr = span.at<std::uint32_t>(24, se).value_or(0);
    ram_size = span.at<std::uint32_t>(28, se).value_or(0);
    startup_size = span.at<std::uint32_t>(32, se).value_or(0);
    stored_size = span.at<std::uint32_t>(36, se).value_or(0);
    imagefs_paddr = span.at<std::uint32_t>(40, se).value_or(0);
    imagefs_size = span.at<std::uint32_t>(44, se).value_or(0);
    preboot_size = span.at<std::uint16_t>(48, se).value_or(0);
    if (version != 1)
        return Status::fail("qnx-ifs-bad-header: startup header version " + dec(version) +
                            " is not 1");
    if (header_size != kStartupHeaderSize)
        return Status::fail("qnx-ifs-bad-header: header_size " + dec(header_size) + " is not 256");
    if (startup_size < kStartupHeaderSize || (startup_size & 3) != 0)
        return Status::fail("qnx-ifs-bad-header: startup_size " + dec(startup_size) +
                            " cannot hold the header");
    if (startup_size > span.size())
        return Status::fail("qnx-ifs-bad-header: startup_size " + dec(startup_size) +
                            " extends past the " + dec(span.size()) + " available bytes");
    codec = (flags1 & kFlags1CompressMask) >> 2;
    if (codec_name(codec) == nullptr)
        return Status::fail("qnx-ifs-unsupported-compression: flags1 compression code " +
                            dec(codec) + " is not zlib, lzo, ucl or lz4");
    startup_checksum_ok = sum_words(span, 0, startup_size, se, startup_sum) && startup_sum == 0;
    if (!startup_checksum_ok)
        startup_diags.push_back({Severity::Warning, kCodeStartupChecksumBad,
                                 "startup header and code sum to " + hex8(startup_sum) +
                                     ", not zero" +
                                     (startup_sum == static_cast<std::uint32_t>(flags2) << 24
                                          ? " (the residual is flags2 alone: set after mkifs)"
                                          : "")});
    comp_start = startup_size;
    if (codec == kCodecNone) image = span.sub(startup_size);
    return Status::success();
}

// Decompress the block chain into an in-memory image. Bounded by
// max_file_bytes and by max_decompress_ratio times the compressed bytes; a
// tripped cap or a bad block keeps the prefix decoded so far. The chain
// itself (zlib: one stream up to stored_size; lzo, ucl, lz4: length-prefixed
// blocks ended by a zero length) is walked here so that every block counts
// against max_nodes_per_fs: a chain of millions of 1-byte blocks ends with
// the budget, not with the end of the data.
void QnxIfsReader::Impl::decompress(const Limits& L) {
    decomp_limits = L;
    decomp_capped = decomp_failed = false;
    decomp_diags.clear();
    comp_end = comp_start;
    comp_bytes = blocks = 0;
    chain_terminated = true;
    chain_capped = false;
    if (codec == kCodecZlib) {
        comp_end = std::min<std::uint64_t>(span.size(),
                                           std::max<std::uint64_t>(stored_size, startup_size));
        comp_bytes = comp_end - comp_start;
        blocks = 1;
    } else {
        std::uint64_t pos = comp_start;
        chain_terminated = false;
        for (;;) {
            if (blocks >= L.max_nodes_per_fs) {
                chain_capped = true;
                break;
            }
            const auto len = span.at<std::uint16_t>(pos, Endian::Big);
            if (!len) break;
            pos += 2;
            if (*len == 0) {
                chain_terminated = true;
                break;
            }
            if (*len > span.size() - pos) break;
            pos += *len;
            comp_bytes += *len;
            blocks++;
        }
        comp_end = std::min<std::uint64_t>(pos, span.size());
    }
    std::vector<std::uint8_t> buf;
    const std::uint64_t cap =
        std::min<std::uint64_t>(L.max_file_bytes, sat_mul(comp_bytes, L.max_decompress_ratio));
    std::vector<std::uint8_t> block;
    std::vector<std::uint8_t> raw;
    auto fail = [&](std::uint64_t idx, std::uint64_t at, const std::string& why) {
        decomp_failed = true;
        decomp_diags.push_back({Severity::Warning, kCodeDecompressFailed,
                                "compressed block " + dec(idx) + " at " + hex(at) + " (" +
                                    std::string(codec_name(codec)) + "): " + why +
                                    "; the image is cut there"});
    };
    auto capped = [&](std::uint64_t idx) {
        decomp_capped = true;
        decomp_diags.push_back({Severity::Warning, kCodeDecompressCap,
                                "decompressed image reached the cap of " + dec(cap) +
                                    " bytes (max_file_bytes, or max_decompress_ratio x " +
                                    dec(comp_bytes) + " compressed bytes) in block " + dec(idx) +
                                    "; the image is cut there"});
    };
    if (codec == kCodecZlib) {
        const auto v = span.view(comp_start, static_cast<std::size_t>(comp_bytes));
        std::span<const std::uint8_t> in;
        if (v) {
            in = *v;
        } else if (auto b = span.bytes(comp_start, static_cast<std::size_t>(comp_bytes))) {
            raw = std::move(*b);
            in = raw;
        }
        const Status st = compress::decompress(compress::Codec::Zlib, in, buf, cap);
        if (!st) {
            if (st.error.rfind("decompress-cap", 0) == 0)
                capped(0);
            else
                fail(0, comp_start, st.error);
        }
    } else {
        std::uint64_t pos = comp_start;
        for (std::uint64_t idx = 0; idx < blocks; ++idx) {
            const std::uint16_t len = span.at<std::uint16_t>(pos, Endian::Big).value_or(0);
            const std::uint64_t at = pos + 2;
            pos = at + len;
            const auto v = span.view(at, len);
            std::span<const std::uint8_t> in;
            if (v) {
                in = *v;
            } else if (auto b = span.bytes(at, len)) {
                raw = std::move(*b);
                in = raw;
            } else {
                fail(idx, at, "block runs past the data");
                break;
            }
            const std::uint64_t room = cap - buf.size();
            bool hit_cap = false;
            std::string why;
            if (codec == kCodecUcl) {
                const compress::ucl::Nrv2bStatus rc =
                    compress::ucl::nrv2b_decompress(in, block, room);
                if (rc == compress::ucl::Nrv2bStatus::OutputOverrun)
                    hit_cap = true;
                else if (rc != compress::ucl::Nrv2bStatus::Ok)
                    why = compress::ucl::nrv2b_status_code(rc);
            } else {
                const Status st = compress::decompress(
                    codec == kCodecLzo ? compress::Codec::Lzo1x : compress::Codec::Lz4, in, block,
                    room);
                if (!st) {
                    if (st.error.rfind("decompress-cap", 0) == 0)
                        hit_cap = true;
                    else
                        why = st.error;
                }
            }
            buf.insert(buf.end(), block.begin(), block.end());
            if (hit_cap) {
                capped(idx);
                break;
            }
            if (!why.empty()) {
                fail(idx, at, why);
                break;
            }
        }
        if (chain_capped && !decomp_failed && !decomp_capped) {
            decomp_capped = true;
            decomp_diags.push_back({Severity::Warning, kCodeLimitBlocks,
                                    "max_nodes_per_fs (" + dec(L.max_nodes_per_fs) +
                                        ") compressed blocks decoded; the rest of the chain was "
                                        "not read"});
        } else if (!chain_terminated && !decomp_failed && !decomp_capped) {
            decomp_diags.push_back({Severity::Warning, kCodeImageTruncated,
                                    "compressed block chain has no terminator inside the data; " +
                                        dec(blocks) + " blocks decoded"});
        }
    }
    decompressed_bytes = buf.size();
    image = Span::whole(std::make_shared<MemorySource>(std::move(buf), "qnx-ifs-decompressed"));
}

Status QnxIfsReader::Impl::parse_image() {
    static constexpr std::uint8_t kSig[] = {'i', 'm', 'a', 'g', 'e', 'f', 's'};
    image_ok = false;
    const auto last = image.at<std::uint32_t>(kImageHeaderSize - 4, Endian::Little);
    if (!image.matches_at(0, kSig) || !last)
        return Status::fail("qnx-ifs-no-image-header: no \"imagefs\" header at startup_size (" +
                            hex(startup_size) + ")" +
                            (codec != kCodecNone ? " after decompression" : ""));
    image_flags = image.u8(7).value_or(0);
    ie = (image_flags & kImageFlagsBigEndian) != 0 ? Endian::Big : Endian::Little;
    image_size = image.at<std::uint32_t>(8, ie).value_or(0);
    hdr_dir_size = image.at<std::uint32_t>(12, ie).value_or(0);
    dir_offset = image.at<std::uint32_t>(16, ie).value_or(0);
    for (std::size_t i = 0; i < 4; ++i)
        boot_ino[i] = image.at<std::uint32_t>(20 + 4 * i, ie).value_or(0);
    script_ino = image.at<std::uint32_t>(36, ie).value_or(0);
    chain_paddr = image.at<std::uint32_t>(40, ie).value_or(0);
    mountflags = image.at<std::uint32_t>(84, ie).value_or(0);
    if (dir_offset > kImageHeaderSize)
        mountpoint = nul_string(image, kImageHeaderSize, dir_offset - kImageHeaderSize)
                         .value_or(std::string());
    if (dir_offset < kImageHeaderSize || dir_offset > hdr_dir_size)
        return Status::fail("qnx-ifs-bad-image-header: dir_offset " + dec(dir_offset) +
                            " and hdr_dir_size " + dec(hdr_dir_size) + " are not nested");
    image_truncated = false;
    dir_end = hdr_dir_size;
    if (hdr_dir_size > image.size()) {
        image_truncated = true;
        dir_end = image.size();
        open_diags.push_back({Severity::Warning, kCodeImageTruncated,
                              "hdr_dir_size " + dec(hdr_dir_size) + " extends past the " +
                                  dec(image.size()) + " bytes of image data; directory cut"});
    } else if (image_size > image.size()) {
        image_truncated = true;
        open_diags.push_back({Severity::Warning, kCodeImageTruncated,
                              "image_size " + dec(image_size) + " extends past the " +
                                  dec(image.size()) + " bytes of image data"});
    } else if (hdr_dir_size > image_size) {
        open_diags.push_back(
            {Severity::Warning, kCodeImageTruncated,
             "hdr_dir_size " + dec(hdr_dir_size) + " exceeds image_size " + dec(image_size)});
    }
    image_checksum_ok = !image_truncated && image_size >= kImageHeaderSize + 4 &&
                        sum_words(image, 0, image_size, ie, image_sum) && image_sum == 0;
    if (!image_checksum_ok)
        open_diags.push_back({Severity::Warning, kCodeImageChecksumBad,
                              image_truncated
                                  ? std::string("image checksum not verifiable: image truncated")
                                  : "image filesystem sums to " + hex8(image_sum) + ", not zero"});
    image_ok = true;
    return Status::success();
}

// Count entries by kind without touching the Sink (for info()).
void QnxIfsReader::Impl::census() {
    entries = files = dirs = symlinks = devices = skipped = 0;
    root_seen = false;
    const Limits defaults;
    for (std::uint64_t pos = dir_offset;
         pos + kDirentAttrSize <= dir_end && entries + skipped < defaults.max_nodes_per_fs;) {
        const std::uint16_t esize = image.at<std::uint16_t>(pos, ie).value_or(0);
        if (esize == 0 || esize < kDirentAttrSize || pos + esize > dir_end) break;
        const std::uint32_t ino = image.at<std::uint32_t>(pos + 4, ie).value_or(0);
        const std::uint32_t mode = image.at<std::uint32_t>(pos + 8, ie).value_or(0);
        if (ino == 0) {
            skipped++;
        } else {
            switch (kind_from_mode(mode)) {
                case EntryKind::Regular:
                    files++;
                    break;
                case EntryKind::Directory: {
                    const auto path =
                        nul_string(image, pos + kDirentAttrSize, esize - kDirentAttrSize);
                    if (path && path->empty() && !root_seen) {
                        root_seen = true;
                        root_mode = mode;
                        root_mtime = image.at<std::uint32_t>(pos + 20, ie).value_or(0);
                        entries--;  // the root names nothing: not an emitted entry
                    } else {
                        dirs++;
                    }
                    break;
                }
                case EntryKind::Symlink:
                    symlinks++;
                    break;
                default:
                    devices++;
                    break;
            }
            entries++;
        }
        pos += esize;
    }
}

// ------------------------------------------------------------------ emission

void QnxIfsReader::Impl::count_entry(WalkResult& out, const FileMeta& m) {
    out.entries++;
    switch (m.kind) {
        case EntryKind::Regular:
            out.files++;
            break;
        case EntryKind::Directory:
            out.dirs++;
            break;
        case EntryKind::Symlink:
            out.symlinks++;
            break;
        default:
            out.others++;
            break;
    }
}

bool QnxIfsReader::Impl::check_limits(const std::string& path, Walk& w) {
    const Limits& L = w.opts->limits;
    if (w.out->entries >= L.max_files) {
        diag(*w.out, Severity::Warning, kCodeLimitFiles,
             "max_files (" + dec(L.max_files) + ") reached at '" + path + "'; walk stopped");
        w.out->truncated = true;
        w.stop = true;
        return false;
    }
    return true;
}

void QnxIfsReader::Impl::emit_regular(FileMeta meta, std::uint64_t off, std::uint64_t size,
                                      Walk& w) {
    const Limits& L = w.opts->limits;
    std::vector<Diagnostic> diags;
    bool truncated = false;
    std::uint64_t avail = size;
    if (off > image.size() || size > image.size() - off) {
        avail = off > image.size() ? 0 : image.size() - off;
        truncated = true;
        diags.push_back({Severity::Warning, kCodeFileOutOfRange,
                         "data at " + hex(off) + " + " + dec(size) + " runs past the " +
                             dec(image.size()) + " bytes of image data; " + dec(avail) +
                             " bytes recovered"});
    }
    if (avail > L.max_file_bytes) {
        avail = L.max_file_bytes;
        truncated = true;
        diags.push_back({Severity::Warning, kCodeLimitFileBytes,
                         "max_file_bytes (" + dec(L.max_file_bytes) + ") reached; " + dec(size) +
                             " bytes claimed"});
    }
    meta.extra["data_offset"] = hex(off);
    Status s = w.sink->begin_file(meta);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        return;
    }
    if (w.opts->extract_data) {
        for (std::uint64_t done = 0; done < avail;) {
            const std::size_t n =
                static_cast<std::size_t>(std::min<std::uint64_t>(kChunk, avail - done));
            std::span<const std::uint8_t> piece;
            if (const auto v = image.view(off + done, n)) {
                piece = *v;
            } else if (auto b = image.bytes(off + done, n)) {
                w.chunk = std::move(*b);
                piece = w.chunk;
            } else {
                truncated = true;
                diags.push_back({Severity::Warning, kCodeFileOutOfRange,
                                 "read of " + dec(n) + " bytes at " + hex(off + done) + " failed"});
                break;
            }
            if (Status ws = w.sink->write(piece); !ws) {
                truncated = true;
                break;
            }
            done += n;
        }
    }
    EntryResult r;
    s = w.sink->end_file(r);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        if (r.meta.path.empty()) return;
    }
    if (truncated) r.truncated = true;
    if (r.truncated) w.out->truncated = true;
    for (Diagnostic& d : diags) r.diagnostics.push_back(std::move(d));
    w.out->bytes += r.digests.bytes;
    count_entry(*w.out, r.meta);
    w.out->entries_out.push_back(std::move(r));
}

void QnxIfsReader::Impl::emit_other(const FileMeta& meta, Walk& w, std::vector<Diagnostic> diags) {
    EntryResult r;
    const Status s = w.sink->entry(meta, r);
    if (!s) {
        diag(*w.out, Severity::Warning, kCodeSinkError, "'" + meta.path + "': " + s.error);
        return;
    }
    for (Diagnostic& d : diags) r.diagnostics.push_back(std::move(d));
    count_entry(*w.out, r.meta);
    w.out->entries_out.push_back(std::move(r));
}

// ------------------------------------------------------------------ walk

void QnxIfsReader::Impl::walk_dir(Walk& w) {
    const Limits& L = w.opts->limits;
    std::uint64_t nodes = 0;
    for (std::uint64_t pos = dir_offset; pos + kDirentAttrSize <= dir_end && !w.stop;) {
        if (nodes >= L.max_nodes_per_fs) {
            diag(*w.out, Severity::Warning, kCodeLimitNodes,
                 "max_nodes_per_fs (" + dec(L.max_nodes_per_fs) +
                     ") directory entries parsed; the rest of the directory was not read");
            w.out->truncated = true;
            break;
        }
        nodes++;
        const std::uint16_t esize = image.at<std::uint16_t>(pos, ie).value_or(0);
        if (esize == 0) break;  // end of directory
        if (esize < kDirentAttrSize || pos + esize > dir_end) {
            diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
                 "directory entry at " + hex(pos) + " has size " + dec(esize) +
                     ", which is below 24 or runs past the directory end (" + hex(dir_end) +
                     "); the rest of the directory was not read");
            w.out->truncated = true;
            break;
        }
        const std::uint64_t entry_end = pos + esize;
        const std::uint16_t extattr = image.at<std::uint16_t>(pos + 2, ie).value_or(0);
        const std::uint32_t ino = image.at<std::uint32_t>(pos + 4, ie).value_or(0);
        const std::uint32_t mode = image.at<std::uint32_t>(pos + 8, ie).value_or(0);
        const std::uint32_t gid = image.at<std::uint32_t>(pos + 12, ie).value_or(0);
        const std::uint32_t uid = image.at<std::uint32_t>(pos + 16, ie).value_or(0);
        const std::uint32_t mtime = image.at<std::uint32_t>(pos + 20, ie).value_or(0);
        const std::uint64_t entry_pos = pos;
        pos = entry_end;

        if (ino == 0) {
            diag(*w.out, Severity::Info, kCodeEntrySkipped,
                 "directory entry at " + hex(entry_pos) + " has inode 0 (mkifs: skip entry)");
            continue;
        }
        FileMeta m;
        m.kind = kind_from_mode(mode);
        m.mode = mode & 07777u;
        m.uid = uid;
        m.gid = gid;
        m.mtime = static_cast<std::int64_t>(mtime);
        m.inode = ino & ~kInoFlagMask;
        m.nlink = 1;
        if ((ino & kInoProcessedElf) != 0) m.extra["processed_elf"] = "true";
        if ((ino & kInoRunonceElf) != 0) m.extra["runonce_elf"] = "true";
        if ((ino & kInoBootstrapExe) != 0) m.extra["bootstrap"] = "true";
        if (script_ino != 0 && (ino & ~kInoFlagMask) == (script_ino & ~kInoFlagMask))
            m.extra["script"] = "true";
        for (const std::uint32_t b : boot_ino)
            if (b != 0 && (b & ~kInoFlagMask) == (ino & ~kInoFlagMask)) m.extra["boot"] = "true";
        if (extattr != 0) m.extra["extattr_offset"] = dec(extattr);

        std::uint64_t body = entry_pos + kDirentAttrSize;  // where the path starts
        std::uint64_t data_off = 0, data_size = 0;
        std::uint16_t sym_offset = 0, sym_size = 0;
        switch (m.kind) {
            case EntryKind::Regular:
                data_off = image.at<std::uint32_t>(body, ie).value_or(0);
                data_size = image.at<std::uint32_t>(body + 4, ie).value_or(0);
                body += 8;
                break;
            case EntryKind::Directory:
                break;
            case EntryKind::Symlink:
                sym_offset = image.at<std::uint16_t>(body, ie).value_or(0);
                sym_size = image.at<std::uint16_t>(body + 2, ie).value_or(0);
                body += 4;
                break;
            case EntryKind::Unknown:
                if ((mode & kIfMt) != kIfNam) {
                    diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
                         "directory entry at " + hex(entry_pos) + " (inode " + dec(m.inode) +
                             ") has mode " + hex(mode) + " with no known type; skipped");
                    continue;
                }
                [[fallthrough]];
            default: {  // devices, fifos, sockets, named specials
                const std::uint32_t dev = image.at<std::uint32_t>(body, ie).value_or(0);
                const std::uint32_t rdev = image.at<std::uint32_t>(body + 4, ie).value_or(0);
                body += 8;
                m.extra["dev"] = hex(dev);
                m.extra["rdev"] = hex(rdev);
                // QNX Neutrino major()/minor(): 6 bits of major above 10 bits of minor.
                m.rdev_major = (rdev >> 10) & 0x3fu;
                m.rdev_minor = rdev & 0x3ffu;
                break;
            }
        }
        if (body > entry_end) {
            diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
                 "directory entry at " + hex(entry_pos) + " (inode " + dec(m.inode) +
                     ") is too short for its type; skipped");
            continue;
        }
        const auto path = nul_string(image, body, entry_end - body);
        if (!path) {
            diag(*w.out, Severity::Warning, kCodeDirentCorrupt,
                 "directory entry at " + hex(entry_pos) + " (inode " + dec(m.inode) +
                     ") has no NUL-terminated path; skipped");
            continue;
        }
        m.path = *path;
        if (m.kind == EntryKind::Directory && m.path.empty()) {
            // The root directory entry: it names nothing the Sink can place.
            continue;
        }
        if (!check_limits(m.path, w)) break;
        if (m.kind == EntryKind::Regular) {
            m.size = data_size;
            emit_regular(std::move(m), data_off, data_size, w);
            continue;
        }
        std::vector<Diagnostic> diags;
        if (m.kind == EntryKind::Symlink) {
            const auto target =
                nul_string(image, body + sym_offset,
                           std::min<std::uint64_t>(
                               entry_end > body + sym_offset ? entry_end - body - sym_offset : 0,
                               static_cast<std::uint64_t>(sym_size) + 1));
            if (!target || body + sym_offset + sym_size > entry_end) {
                diags.push_back({Severity::Warning, kCodeDirentCorrupt,
                                 "symlink target (sym_offset " + dec(sym_offset) + ", sym_size " +
                                     dec(sym_size) + ") is not inside the entry; target lost"});
            } else {
                m.link_target = *target;
            }
            m.size = m.link_target.size();
        }
        emit_other(m, w, std::move(diags));
    }
}

// ------------------------------------------------------------------ public API

QnxIfsReader::QnxIfsReader() : impl_(std::make_unique<Impl>()) {}
QnxIfsReader::~QnxIfsReader() = default;

std::string QnxIfsReader::format() const {
    return "qnx-ifs";
}

Status QnxIfsReader::open(const Span& span) {
    Impl& im = *impl_;
    im = Impl{};
    im.span = span;
    if (Status s = im.parse_startup(); !s) return s;
    if (im.codec != kCodecNone) im.decompress(Limits{});
    if (Status s = im.parse_image(); !s) return s;
    im.census();
    im.opened = true;
    return Status::success();
}

FilesystemInfo QnxIfsReader::info() const {
    const Impl& im = *impl_;
    FilesystemInfo fi;
    fi.format = "qnx-ifs";
    if (!im.opened) return fi;
    fi.endian = im.ie;
    fi.size = std::max<std::uint64_t>(
        im.stored_size, im.codec == kCodecNone ? im.startup_size + im.image_size : im.comp_end);
    fi.compression = im.codec == kCodecNone ? "" : codec_name(im.codec);
    fi.label = im.mountpoint;
    fi.attrs["endian"] = endian_name(im.ie);
    fi.attrs["version"] = dec(im.version);
    const char* mname = machine_name(im.machine);
    fi.attrs["machine"] = mname != nullptr ? mname : "unknown(" + hex(im.machine) + ")";
    fi.attrs["flags1"] = hex(im.flags1);
    fi.attrs["flags2"] = hex(im.flags2);
    fi.attrs["startup_vaddr"] = hex(im.startup_vaddr);
    fi.attrs["paddr_bias"] = hex(im.paddr_bias);
    fi.attrs["image_paddr"] = hex(im.image_paddr);
    fi.attrs["ram_paddr"] = hex(im.ram_paddr);
    fi.attrs["ram_size"] = dec(im.ram_size);
    fi.attrs["startup_size"] = dec(im.startup_size);
    fi.attrs["stored_size"] = dec(im.stored_size);
    fi.attrs["imagefs_size"] = dec(im.imagefs_size);
    if (im.preboot_size != 0) fi.attrs["preboot_size"] = dec(im.preboot_size);
    fi.attrs["startup_checksum"] = im.startup_checksum_ok ? "ok" : "mismatch";
    fi.attrs["compressed"] = codec_name(im.codec);
    if (im.codec != kCodecNone) {
        fi.attrs["blocks"] = dec(im.blocks);
        fi.attrs["compressed_bytes"] = dec(im.comp_bytes);
        fi.attrs["decompressed_bytes"] = dec(im.decompressed_bytes);
        if (im.decomp_capped) fi.attrs["decompress_capped"] = "true";
        if (im.decomp_failed) fi.attrs["decompress_failed"] = "true";
    }
    fi.attrs["image_flags"] = hex(im.image_flags);
    fi.attrs["image_size"] = dec(im.image_size);
    fi.attrs["hdr_dir_size"] = dec(im.hdr_dir_size);
    fi.attrs["dir_offset"] = dec(im.dir_offset);
    fi.attrs["image_checksum"] = im.image_checksum_ok ? "ok" : "mismatch";
    std::string boots;
    for (const std::uint32_t b : im.boot_ino)
        if (b != 0) boots += (boots.empty() ? "" : ",") + dec(b & ~kInoFlagMask);
    if (!boots.empty()) fi.attrs["boot_ino"] = boots;
    if (im.script_ino != 0) fi.attrs["script_ino"] = dec(im.script_ino & ~kInoFlagMask);
    if (im.chain_paddr != 0) fi.attrs["chain_paddr"] = hex(im.chain_paddr);
    fi.attrs["mountflags"] = hex(im.mountflags);
    if (!im.mountpoint.empty()) fi.attrs["mountpoint"] = im.mountpoint;
    fi.attrs["entries"] = dec(im.entries);
    fi.attrs["files"] = dec(im.files);
    fi.attrs["dirs"] = dec(im.dirs);
    fi.attrs["symlinks"] = dec(im.symlinks);
    fi.attrs["devices"] = dec(im.devices);
    if (im.skipped != 0) fi.attrs["skipped_entries"] = dec(im.skipped);
    if (im.root_seen) {
        fi.attrs["root_mode"] = hex(im.root_mode & 07777u);
        fi.attrs["root_mtime"] = dec(im.root_mtime);
    }
    return fi;
}

Status QnxIfsReader::walk(Sink& sink, const WalkOptions& opts, WalkResult& out) {
    Impl& im = *impl_;
    if (!im.opened) return Status::fail("qnx-ifs-not-open: walk before a successful open");
    out = WalkResult{};
    // open() decompressed with the default caps; honour the caller's when a
    // cap tripped or the caller's are tighter.
    if (im.codec != kCodecNone &&
        (opts.limits.max_file_bytes != im.decomp_limits.max_file_bytes ||
         opts.limits.max_decompress_ratio != im.decomp_limits.max_decompress_ratio ||
         opts.limits.max_nodes_per_fs != im.decomp_limits.max_nodes_per_fs)) {
        im.open_diags.clear();  // the image-header diagnostics; parse_image writes them again
        im.decompress(opts.limits);
        if (Status s = im.parse_image(); !s) return s;
        im.census();
    }
    for (const Diagnostic& d : im.startup_diags) out.diagnostics.push_back(d);
    for (const Diagnostic& d : im.decomp_diags) out.diagnostics.push_back(d);
    for (const Diagnostic& d : im.open_diags) out.diagnostics.push_back(d);
    if (im.decomp_capped || im.decomp_failed || im.image_truncated) out.truncated = true;
    Impl::Walk w;
    w.sink = &sink;
    w.opts = &opts;
    w.out = &out;
    im.walk_dir(w);
    return Status::success();
}

OMNITRACE_REGISTER_FILESYSTEM("qnx-ifs", QnxIfsReader);

}  // namespace omnitrace::fs
