// SevenZip.cpp — the 7z archive structure. See the header.
//
// Reference: the 7-Zip source's `DOC/7zFormat.txt`, read for understanding;
// nothing copied. Checked against 7-Zip 26.03 output with LZMA2, LZMA1,
// Copy and BCJ chains, with the header both compressed and not.
#include "omnitrace/core/SevenZip.h"

#include <algorithm>
#include <map>
#include <span>
#include <utility>

#include <zlib.h>

#include "omnitrace/core/Compression.h"
#include "omnitrace/core/Endian.h"

namespace omnitrace::sevenzip {

namespace {

// Property ids (`7zFormat.txt`).
constexpr std::uint64_t kEnd = 0x00, kHeader = 0x01, kArchiveProperties = 0x02,
                        kAdditionalStreams = 0x03, kMainStreams = 0x04, kFilesInfo = 0x05,
                        kPackInfo = 0x06, kUnpackInfo = 0x07, kSubStreamsInfo = 0x08,
                        kSize = 0x09, kCrc = 0x0A, kFolder = 0x0B, kCodersUnpackSize = 0x0C,
                        kNumUnpackStream = 0x0D, kEmptyStream = 0x0E, kEmptyFile = 0x0F,
                        kAnti = 0x10, kName = 0x11, kMTime = 0x14, kWinAttributes = 0x15,
                        kEncodedHeader = 0x17, kDummy = 0x19;

// Bounds. A header is attacker-controlled and its numbers are variable
// length, so every count that drives an allocation needs one.
constexpr std::uint64_t kMaxFolders = 1u << 20;
constexpr std::uint64_t kMaxCoders = 64;
constexpr std::uint64_t kMaxPackStreams = 1u << 22;
constexpr std::uint64_t kMaxFiles = 1u << 22;
constexpr std::uint64_t kMaxHeaderBytes = 256ull << 20;
constexpr std::uint64_t kMaxNameBytes = 64ull << 20;
// FILETIME is 100 ns ticks since 1601-01-01; this is the gap to the epoch.
constexpr std::uint64_t kFiletimeEpochGap = 11644473600ull;
constexpr std::uint32_t kAttrUnixExtension = 0x8000u;
constexpr std::uint32_t kAttrDirectory = 0x10u;

/// A cursor over the header bytes with the format's variable-length numbers.
/// Every read is bounds-checked and sets `bad` rather than throwing, so a
/// truncated header stops the parse instead of reading past the buffer.
class Reader {
   public:
    explicit Reader(const std::vector<std::uint8_t>& b) : b_(b) {}

    bool bad = false;

    std::uint8_t u8() {
        if (p_ >= b_.size()) {
            bad = true;
            return 0;
        }
        return b_[p_++];
    }
    std::uint32_t u32() {
        if (p_ + 4 > b_.size()) {
            bad = true;
            return 0;
        }
        const auto v = load_int<std::uint32_t>(b_.data() + p_, Endian::Little);
        p_ += 4;
        return v;
    }
    std::uint64_t u64() {
        if (p_ + 8 > b_.size()) {
            bad = true;
            return 0;
        }
        const auto v = load_int<std::uint64_t>(b_.data() + p_, Endian::Little);
        p_ += 8;
        return v;
    }
    /// The format's NUMBER: a first byte whose high bits say how many more
    /// follow, and the rest of the value in those.
    std::uint64_t num() {
        const std::uint8_t first = u8();
        if (bad) return 0;
        std::uint64_t value = 0;
        std::uint8_t mask = 0x80;
        for (unsigned i = 0; i < 8; ++i) {
            if ((first & mask) == 0)
                return value | (static_cast<std::uint64_t>(first & (mask - 1)) << (8 * i));
            const std::uint8_t byte = u8();
            if (bad) return 0;
            value |= static_cast<std::uint64_t>(byte) << (8 * i);
            mask = static_cast<std::uint8_t>(mask >> 1);
        }
        return value;
    }
    /// `n` bits, most significant first.
    std::vector<bool> bits(std::uint64_t n) {
        std::vector<bool> out;
        if (n > kMaxFiles) {
            bad = true;
            return out;
        }
        out.reserve(static_cast<std::size_t>(n));
        std::uint8_t byte = 0, mask = 0;
        for (std::uint64_t i = 0; i < n; ++i) {
            if (mask == 0) {
                byte = u8();
                mask = 0x80;
            }
            out.push_back((byte & mask) != 0);
            mask = static_cast<std::uint8_t>(mask >> 1);
        }
        return out;
    }
    /// A bit vector preceded by an "all are defined" byte.
    std::vector<bool> defined_vector(std::uint64_t n) {
        if (u8() != 0) return std::vector<bool>(static_cast<std::size_t>(std::min(n, kMaxFiles)),
                                                true);
        return bits(n);
    }
    void skip(std::uint64_t n) {
        if (n > b_.size() - std::min<std::uint64_t>(p_, b_.size())) {
            bad = true;
            p_ = b_.size();
            return;
        }
        p_ += static_cast<std::size_t>(n);
    }
    std::size_t pos() const { return p_; }
    void seek(std::size_t p) {
        if (p > b_.size()) {
            bad = true;
            return;
        }
        p_ = p;
    }
    std::size_t size() const { return b_.size(); }
    const std::uint8_t* at(std::size_t p) const { return b_.data() + p; }

   private:
    const std::vector<std::uint8_t>& b_;
    std::size_t p_ = 0;
};

std::uint32_t crc32_of(std::span<const std::uint8_t> d) {
    return static_cast<std::uint32_t>(::crc32(0UL, d.data(), static_cast<uInt>(d.size())));
}

// UTF-16LE to UTF-8. Surrogate pairs are joined; a lone one is kept as the
// replacement character rather than dropped, because a name is evidence.
std::string utf16le_to_utf8(const std::uint8_t* p, std::size_t bytes) {
    std::string out;
    auto emit = [&](std::uint32_t cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    };
    for (std::size_t i = 0; i + 1 < bytes; i += 2) {
        std::uint32_t u = static_cast<std::uint32_t>(p[i]) | (static_cast<std::uint32_t>(p[i + 1]) << 8);
        if (u >= 0xD800 && u < 0xDC00 && i + 3 < bytes) {
            const std::uint32_t lo =
                static_cast<std::uint32_t>(p[i + 2]) | (static_cast<std::uint32_t>(p[i + 3]) << 8);
            if (lo >= 0xDC00 && lo < 0xE000) {
                emit(0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00));
                i += 2;
                continue;
            }
        }
        if (u >= 0xD800 && u < 0xE000) u = 0xFFFD;
        emit(u);
    }
    return out;
}

bool read_folder(Reader& r, Folder& f) {
    const std::uint64_t n = r.num();
    if (r.bad || n == 0 || n > kMaxCoders) return false;
    for (std::uint64_t i = 0; i < n; ++i) {
        Coder c;
        const std::uint8_t flags = r.u8();
        const std::uint64_t id_size = flags & 0x0Fu;
        if (r.bad || id_size == 0 || id_size > 15) return false;
        for (std::uint64_t k = 0; k < id_size; ++k) c.id.push_back(r.u8());
        if ((flags & 0x10u) != 0) {
            c.num_in = r.num();
            c.num_out = r.num();
            if (c.num_in == 0 || c.num_in > kMaxCoders || c.num_out == 0 ||
                c.num_out > kMaxCoders)
                return false;
        }
        if ((flags & 0x20u) != 0) {
            const std::uint64_t ps = r.num();
            if (r.bad || ps > 1024) return false;
            for (std::uint64_t k = 0; k < ps; ++k) c.props.push_back(r.u8());
        }
        if (r.bad) return false;
        f.coders.push_back(std::move(c));
    }
    const std::uint64_t in_total = f.total_in(), out_total = f.total_out();
    if (out_total == 0) return false;
    for (std::uint64_t i = 0; i + 1 < out_total; ++i) {
        const std::uint64_t a = r.num(), b = r.num();
        if (r.bad || a >= in_total || b >= out_total) return false;
        f.binds.emplace_back(a, b);
    }
    const std::uint64_t packed = in_total - f.binds.size();
    if (packed == 0 || packed > in_total) return false;
    if (packed == 1) {
        // The one in-stream nothing is bound to.
        for (std::uint64_t i = 0; i < in_total; ++i) {
            const bool bound = std::any_of(f.binds.begin(), f.binds.end(),
                                           [&](const auto& b) { return b.first == i; });
            if (!bound) {
                f.packed.push_back(i);
                break;
            }
        }
        if (f.packed.empty()) return false;
    } else {
        for (std::uint64_t i = 0; i < packed; ++i) {
            const std::uint64_t idx = r.num();
            if (r.bad || idx >= in_total) return false;
            f.packed.push_back(idx);
        }
    }
    return !r.bad;
}

bool read_streams_info(Reader& r, StreamsInfo& si) {
    std::uint64_t id = r.num();
    if (r.bad) return false;

    if (id == kPackInfo) {
        si.pack_pos = r.num();
        const std::uint64_t n = r.num();
        if (r.bad || n > kMaxPackStreams) return false;
        for (;;) {
            const std::uint64_t t = r.num();
            if (r.bad) return false;
            if (t == kEnd) break;
            if (t == kSize) {
                for (std::uint64_t i = 0; i < n; ++i) si.pack_sizes.push_back(r.num());
            } else if (t == kCrc) {
                const std::vector<bool> d = r.defined_vector(n);
                for (std::uint64_t i = 0; i < n; ++i) {
                    if (i < d.size() && d[i]) r.u32();
                }
            } else {
                return false;  // an id no released 7-Zip writes here
            }
            if (r.bad) return false;
        }
        id = r.num();
    }

    std::uint64_t num_folders = 0;
    if (id == kUnpackInfo) {
        if (r.num() != kFolder) return false;
        num_folders = r.num();
        if (r.bad || num_folders > kMaxFolders) return false;
        if (r.u8() != 0) return false;  // folders held in another stream
        si.folders.resize(static_cast<std::size_t>(num_folders));
        for (Folder& f : si.folders) {
            if (!read_folder(r, f)) return false;
        }
        if (r.num() != kCodersUnpackSize) return false;
        for (Folder& f : si.folders) {
            for (std::uint64_t i = 0; i < f.total_out(); ++i) f.out_sizes.push_back(r.num());
            if (r.bad) return false;
        }
        for (;;) {
            const std::uint64_t t = r.num();
            if (r.bad) return false;
            if (t == kEnd) break;
            if (t == kCrc) {
                const std::vector<bool> d = r.defined_vector(num_folders);
                for (std::size_t i = 0; i < si.folders.size(); ++i) {
                    if (i < d.size() && d[i]) {
                        si.folders[i].crc = r.u32();
                        si.folders[i].has_crc = true;
                    }
                }
            } else {
                return false;
            }
            if (r.bad) return false;
        }
        // Which packed stream each folder starts at.
        std::uint64_t pack = 0;
        for (Folder& f : si.folders) {
            f.first_pack_index = pack;
            pack += f.packed.size();
        }
        id = r.num();
    }

    si.substreams_per_folder.assign(si.folders.size(), 1);
    if (id == kSubStreamsInfo) {
        std::uint64_t t = r.num();
        if (t == kNumUnpackStream) {
            for (std::size_t i = 0; i < si.folders.size(); ++i)
                si.substreams_per_folder[i] = r.num();
            if (r.bad) return false;
            t = r.num();
        }
        std::uint64_t total_substreams = 0;
        for (const std::uint64_t n : si.substreams_per_folder) {
            if (n > kMaxFiles) return false;
            total_substreams += n;
        }
        if (total_substreams > kMaxFiles) return false;

        // Every substream but the last of each folder has its size written;
        // the last one takes what is left of the folder's output.
        for (std::size_t i = 0; i < si.folders.size(); ++i) {
            const std::uint64_t n = si.substreams_per_folder[i];
            if (n == 0) continue;
            std::uint64_t sum = 0;
            if (t == kSize) {
                for (std::uint64_t k = 0; k + 1 < n; ++k) {
                    const std::uint64_t v = r.num();
                    si.substream_sizes.push_back(v);
                    sum += v;
                }
            } else if (n != 1) {
                return false;  // several substreams and no sizes for them
            }
            const std::uint64_t whole = si.folders[i].unpacked_size();
            if (sum > whole) return false;
            si.substream_sizes.push_back(whole - sum);
        }
        if (r.bad) return false;
        if (t == kSize) t = r.num();

        // A folder holding exactly one substream already has its CRC.
        std::uint64_t unknown = 0;
        for (std::size_t i = 0; i < si.folders.size(); ++i) {
            if (si.substreams_per_folder[i] == 1 && si.folders[i].has_crc) continue;
            unknown += si.substreams_per_folder[i];
        }
        si.substream_crcs.assign(static_cast<std::size_t>(total_substreams), 0);
        si.substream_crc_defined.assign(static_cast<std::size_t>(total_substreams), false);
        while (t != kEnd) {
            if (r.bad) return false;
            if (t == kCrc) {
                const std::vector<bool> d = r.defined_vector(unknown);
                std::size_t next = 0, slot = 0;
                for (std::size_t i = 0; i < si.folders.size(); ++i) {
                    const std::uint64_t n = si.substreams_per_folder[i];
                    if (n == 1 && si.folders[i].has_crc) {
                        if (slot < si.substream_crcs.size()) {
                            si.substream_crcs[slot] = si.folders[i].crc;
                            si.substream_crc_defined[slot] = true;
                        }
                        ++slot;
                        continue;
                    }
                    for (std::uint64_t k = 0; k < n; ++k, ++next, ++slot) {
                        if (next < d.size() && d[next] && slot < si.substream_crcs.size()) {
                            si.substream_crcs[slot] = r.u32();
                            si.substream_crc_defined[slot] = true;
                        }
                    }
                }
            } else {
                return false;
            }
            t = r.num();
        }
        id = r.num();  // the StreamsInfo kEnd
    } else {
        for (const Folder& f : si.folders) si.substream_sizes.push_back(f.unpacked_size());
        si.substream_crcs.assign(si.folders.size(), 0);
        si.substream_crc_defined.assign(si.folders.size(), false);
        for (std::size_t i = 0; i < si.folders.size(); ++i) {
            si.substream_crcs[i] = si.folders[i].crc;
            si.substream_crc_defined[i] = si.folders[i].has_crc;
        }
    }
    return !r.bad && id == kEnd;
}

bool read_files_info(Reader& r, std::vector<FileEntry>& files) {
    const std::uint64_t n = r.num();
    if (r.bad || n > kMaxFiles) return false;
    files.assign(static_cast<std::size_t>(n), FileEntry{});
    std::vector<bool> empty_stream(static_cast<std::size_t>(n), false), empty_file;

    for (;;) {
        const std::uint64_t type = r.num();
        if (r.bad) return false;
        if (type == kEnd) break;
        const std::uint64_t size = r.num();
        if (r.bad || size > r.size()) return false;
        const std::size_t end = r.pos() + static_cast<std::size_t>(size);
        if (end > r.size()) return false;

        if (type == kEmptyStream) {
            empty_stream = r.bits(n);
        } else if (type == kEmptyFile) {
            const std::uint64_t k =
                static_cast<std::uint64_t>(std::count(empty_stream.begin(), empty_stream.end(), true));
            empty_file = r.bits(k);
        } else if (type == kName) {
            if (r.u8() != 0) return false;  // names held in another stream
            if (size > kMaxNameBytes) return false;
            const std::size_t from = r.pos();
            std::size_t start = from;
            std::size_t idx = 0;
            for (std::size_t i = from; i + 1 < end; i += 2) {
                if (r.at(i)[0] == 0 && r.at(i)[1] == 0) {
                    if (idx < files.size())
                        files[idx].name = utf16le_to_utf8(r.at(start), i - start);
                    ++idx;
                    start = i + 2;
                }
            }
        } else if (type == kMTime) {
            const std::vector<bool> d = r.defined_vector(n);
            if (r.u8() != 0) return false;
            for (std::size_t i = 0; i < files.size(); ++i) {
                if (i >= d.size() || !d[i]) continue;
                const std::uint64_t ft = r.u64();
                // FILETIME before the Unix epoch would go negative; such a
                // stamp is not one to report.
                if (ft / 10000000ull > kFiletimeEpochGap) {
                    files[i].mtime = ft / 10000000ull - kFiletimeEpochGap;
                    files[i].has_mtime = true;
                }
            }
        } else if (type == kWinAttributes) {
            const std::vector<bool> d = r.defined_vector(n);
            if (r.u8() != 0) return false;
            for (std::size_t i = 0; i < files.size(); ++i) {
                if (i >= d.size() || !d[i]) continue;
                files[i].attributes = r.u32();
                files[i].has_attributes = true;
            }
        }
        // Anything else (kAnti, kDummy, times other than mtime, unknown ids)
        // is skipped by its declared size, which is what the size is for.
        if (r.bad) return false;
        r.seek(end);
    }

    std::size_t empty_index = 0;
    for (std::size_t i = 0; i < files.size(); ++i) {
        const bool empty = i < empty_stream.size() && empty_stream[i];
        files[i].has_stream = !empty;
        if (!empty) continue;
        // An entry with no stream is a directory unless the empty-file vector
        // says otherwise; without that vector they are all directories.
        const bool is_file = empty_index < empty_file.size() && empty_file[empty_index];
        files[i].is_dir = !is_file;
        ++empty_index;
    }
    for (FileEntry& f : files) {
        if (f.has_attributes && (f.attributes & kAttrDirectory) != 0) f.is_dir = true;
    }
    return true;
}

// The whole header, once any compression has been undone.
bool parse_header_body(Reader& r, Archive& out) {
    std::uint64_t id = r.num();
    if (r.bad || id != kHeader) return false;
    id = r.num();
    if (id == kArchiveProperties) {
        for (;;) {
            const std::uint64_t t = r.num();
            if (r.bad) return false;
            if (t == kEnd) break;
            r.skip(r.num());
        }
        id = r.num();
    }
    if (id == kAdditionalStreams) {
        StreamsInfo ignored;
        if (!read_streams_info(r, ignored)) return false;
        id = r.num();
    }
    if (id == kMainStreams) {
        if (!read_streams_info(r, out.streams)) return false;
        id = r.num();
    }
    if (id == kFilesInfo) {
        if (!read_files_info(r, out.files)) return false;
        id = r.num();
    }
    return !r.bad;
}

}  // namespace

std::string Coder::name() const {
    static const std::map<std::vector<std::uint8_t>, const char*> kNames = {
        {{0x00}, "copy"},
        {{0x03}, "delta"},
        {{0x21}, "lzma2"},
        {{0x0A}, "bcj-arm64"},
        {{0x0B}, "bcj-riscv"},
        {{0x03, 0x01, 0x01}, "lzma"},
        {{0x03, 0x03, 0x01, 0x03}, "bcj-x86"},
        {{0x03, 0x03, 0x01, 0x1B}, "bcj2"},
        {{0x03, 0x03, 0x02, 0x05}, "bcj-ppc"},
        {{0x03, 0x03, 0x03, 0x01}, "bcj-ia64"},
        {{0x03, 0x03, 0x05, 0x01}, "bcj-arm"},
        {{0x03, 0x03, 0x07, 0x01}, "bcj-armt"},
        {{0x03, 0x03, 0x08, 0x05}, "bcj-sparc"},
        {{0x03, 0x04, 0x01}, "ppmd"},
        {{0x04, 0x01, 0x08}, "deflate"},
        {{0x04, 0x01, 0x09}, "deflate64"},
        {{0x04, 0x02, 0x02}, "bzip2"},
        {{0x06, 0xF1, 0x07, 0x01}, "aes256-sha256"},
    };
    const auto it = kNames.find(id);
    if (it != kNames.end()) return it->second;
    std::string hex;
    static const char* kHex = "0123456789abcdef";
    for (const std::uint8_t b : id) {
        hex.push_back(kHex[b >> 4]);
        hex.push_back(kHex[b & 0x0F]);
    }
    return hex.empty() ? "unknown" : hex;
}

std::uint64_t Folder::total_in() const {
    std::uint64_t n = 0;
    for (const Coder& c : coders) n += c.num_in;
    return n;
}

std::uint64_t Folder::total_out() const {
    std::uint64_t n = 0;
    for (const Coder& c : coders) n += c.num_out;
    return n;
}

std::uint64_t Folder::final_out_index() const {
    const std::uint64_t n = total_out();
    for (std::uint64_t i = 0; i < n; ++i) {
        const bool bound =
            std::any_of(binds.begin(), binds.end(), [&](const auto& b) { return b.second == i; });
        if (!bound) return i;
    }
    return n;
}

std::uint64_t Folder::unpacked_size() const {
    const std::uint64_t i = final_out_index();
    return i < out_sizes.size() ? out_sizes[i] : 0;
}

std::uint32_t FileEntry::unix_mode() const {
    // p7zip puts the Unix mode in the top half and sets a flag in the bottom.
    if (!has_attributes || (attributes & kAttrUnixExtension) == 0) return 0;
    return attributes >> 16;
}

namespace {

// The coders that are not copy, in coder order. Copy is the identity, so it
// never affects what a chain can do.
std::vector<std::string> working_coders(const Folder& f) {
    std::vector<std::string> out;
    for (const Coder& c : f.coders) {
        const std::string n = c.name();
        if (n != "copy") out.push_back(n);
    }
    return out;
}

bool is_lzma_filter(const std::string& n) {
    return n == "lzma" || n == "lzma2" || n == "delta" || n.rfind("bcj", 0) == 0;
}

}  // namespace

bool folder_decodable(const Folder& f, std::string* unsupported_coder) {
    for (const Coder& c : f.coders) {
        // A coder taking more than one input is a graph this does not wire up
        // (BCJ2 is the only one 7-Zip writes).
        if (c.num_in != 1 || c.num_out != 1) {
            if (unsupported_coder != nullptr) *unsupported_coder = c.name() + " (multi-stream)";
            return false;
        }
    }
    const std::vector<std::string> work = working_coders(f);
    if (work.empty()) return true;  // a stored folder

    // zlib and libbz2 are here, but they cannot be chained with liblzma's
    // filters, so those two coders work only on their own.
    if (work.size() == 1 && (work[0] == "deflate" || work[0] == "bzip2")) return true;

    for (const std::string& n : work) {
        if (!is_lzma_filter(n)) {
            if (unsupported_coder != nullptr) *unsupported_coder = n;
            return false;
        }
    }
    // liblzma will not run a chain that is only byte filters: a raw chain has
    // to end in a compressor. 7-Zip makes such a folder for an executable in
    // a -m0=Copy archive (Copy paired with BCJ).
    const bool has_compressor =
        std::any_of(work.begin(), work.end(),
                    [](const std::string& n) { return n == "lzma" || n == "lzma2"; });
    if (!has_compressor) {
        if (unsupported_coder != nullptr) *unsupported_coder = "a byte filter with no compressor";
        return false;
    }
    return true;
}

bool folder_is_filtered_store(const Folder& f, std::string* filter) {
    bool any_filter = false;
    for (const Coder& c : f.coders) {
        const std::string n = c.name();
        if (n == "copy") continue;
        if (n.rfind("bcj", 0) == 0 || n == "delta") {
            any_filter = true;
            if (filter != nullptr && filter->empty()) *filter = n;
            continue;
        }
        return false;  // a compressor or something unknown: not a stored folder
    }
    return any_filter;
}

Status decode_folder(const Span& span, const Folder& f, std::uint64_t pack_at,
                     const std::vector<std::uint64_t>& pack_sizes,
                     std::vector<std::uint8_t>& out) {
    out.clear();
    std::string bad;
    if (!folder_decodable(f, &bad))
        return Status::fail("7z-unsupported-coder: " + bad + " is not one this build decodes");
    if (f.packed.size() != 1)
        return Status::fail("7z-unsupported-coder: a folder with " +
                            std::to_string(f.packed.size()) + " packed streams is not one this "
                            "build wires up");
    if (f.first_pack_index >= pack_sizes.size())
        return Status::fail("7z-bad-header: the folder's packed stream is not in the pack list");

    // Walk the coders from the packed stream outwards; that is the order they
    // decode in. liblzma wants the reverse, which is the order they were
    // applied when the archive was made.
    std::vector<const Coder*> decode_order;
    std::vector<std::uint64_t> in_base(f.coders.size(), 0), out_base(f.coders.size(), 0);
    {
        std::uint64_t in = 0, o = 0;
        for (std::size_t i = 0; i < f.coders.size(); ++i) {
            in_base[i] = in;
            out_base[i] = o;
            in += f.coders[i].num_in;
            o += f.coders[i].num_out;
        }
    }
    auto coder_of_in = [&](std::uint64_t idx) -> std::size_t {
        for (std::size_t i = 0; i < f.coders.size(); ++i) {
            if (idx >= in_base[i] && idx < in_base[i] + f.coders[i].num_in) return i;
        }
        return f.coders.size();
    };
    std::size_t current = coder_of_in(f.packed[0]);
    for (std::size_t step = 0; step <= f.coders.size(); ++step) {
        if (current >= f.coders.size())
            return Status::fail("7z-bad-header: the folder's coder graph does not connect");
        decode_order.push_back(&f.coders[current]);
        // Whatever takes this coder's output next.
        const std::uint64_t my_out = out_base[current];
        std::size_t next = f.coders.size();
        for (const auto& [in_idx, out_idx] : f.binds) {
            if (out_idx == my_out) {
                next = coder_of_in(in_idx);
                break;
            }
        }
        if (next == f.coders.size()) break;
        current = next;
    }
    if (decode_order.size() != f.coders.size())
        return Status::fail("7z-bad-header: the folder's coder graph is not a single chain");

    const std::uint64_t packed_size = pack_sizes[static_cast<std::size_t>(f.first_pack_index)];
    const auto raw = span.bytes(pack_at, static_cast<std::size_t>(packed_size));
    if (!raw) return Status::fail("7z-truncated: the folder's packed bytes are not in the archive");
    const std::uint64_t want = f.unpacked_size();

    // Deflate and bzip2 come from zlib and libbz2 rather than liblzma, so
    // they only work when nothing has to be chained with them.
    {
        const std::vector<std::string> work = working_coders(f);
        if (work.size() == 1 && (work[0] == "deflate" || work[0] == "bzip2")) {
            return compress::decompress_exact(
                work[0] == "deflate" ? compress::Codec::Deflate : compress::Codec::Bzip2,
                std::span<const std::uint8_t>(raw->data(), raw->size()), out,
                static_cast<std::size_t>(want));
        }
    }

    std::vector<compress::RawFilter> chain;
    for (auto it = decode_order.rbegin(); it != decode_order.rend(); ++it) {
        const std::string n = (*it)->name();
        // Copy is the identity. liblzma has no filter for it, and a folder
        // may pair one with a BCJ filter (7-Zip does that for executables in
        // a -m0=Copy archive), so it is dropped rather than mapped.
        if (n == "copy") continue;
        compress::RawFilter rf;
        rf.props = (*it)->props;
        if (n == "lzma") {
            // 7z writes raw LZMA1 with the size in the header and usually no
            // end marker, which the extended filter is made for.
            rf.id = compress::kFilterLzma1Ext;
        } else if (n == "lzma2") {
            rf.id = compress::kFilterLzma2;
        } else if (n == "delta") {
            rf.id = compress::kFilterDelta;
        } else if (n == "bcj-x86") {
            rf.id = compress::kFilterX86;
        } else if (n == "bcj-arm") {
            rf.id = compress::kFilterArm;
        } else if (n == "bcj-armt") {
            rf.id = compress::kFilterArmThumb;
        } else if (n == "bcj-ppc") {
            rf.id = compress::kFilterPowerPc;
        } else if (n == "bcj-ia64") {
            rf.id = compress::kFilterIa64;
        } else if (n == "bcj-sparc") {
            rf.id = compress::kFilterSparc;
        } else if (n == "bcj-arm64") {
            rf.id = compress::kFilterArm64;
        } else if (n == "bcj-riscv") {
            rf.id = compress::kFilterRiscV;
        } else {
            return Status::fail("7z-unsupported-coder: " + n);
        }
        chain.push_back(std::move(rf));
    }
    if (chain.empty()) {  // nothing but copy coders: the folder is stored
        if (raw->size() != want)
            return Status::fail("7z-bad-header: a stored folder's packed and unpacked sizes differ");
        out = *raw;
        return Status::success();
    }
    return compress::decompress_raw(std::span<const compress::RawFilter>(chain.data(), chain.size()),
                                    std::span<const std::uint8_t>(raw->data(), raw->size()), out,
                                    static_cast<std::size_t>(want));
}

Status read_archive(const Span& span, std::uint64_t at, Archive& out) {
    out = Archive{};
    std::array<std::uint8_t, kSignatureHeaderSize> sig{};
    if (span.read(at, std::span<std::uint8_t>(sig.data(), sig.size())) != sig.size())
        return Status::fail("7z-truncated: fewer than 32 bytes for the signature header");
    if (!std::equal(kMagic.begin(), kMagic.end(), sig.begin()))
        return Status::fail("7z-bad-magic: no 7z signature at this offset");
    out.version_major = sig[6];
    out.version_minor = sig[7];
    const std::uint32_t start_crc = load_int<std::uint32_t>(sig.data() + 8, Endian::Little);
    out.start_header_crc_ok =
        crc32_of(std::span<const std::uint8_t>(sig.data() + 12, 20)) == start_crc;
    out.next_header_offset = load_int<std::uint64_t>(sig.data() + 12, Endian::Little);
    out.next_header_size = load_int<std::uint64_t>(sig.data() + 20, Endian::Little);
    // The start header is NextHeaderOffset(8) + NextHeaderSize(8) + CRC(4),
    // so the header's own CRC sits at 12 + 16.
    const std::uint32_t header_crc = load_int<std::uint32_t>(sig.data() + 28, Endian::Little);
    if (!out.start_header_crc_ok)
        return Status::fail("7z-bad-start-header: the 20-byte start header does not match its CRC");
    if (out.next_header_size > kMaxHeaderBytes)
        return Status::fail("7z-bad-start-header: the header claims " +
                            std::to_string(out.next_header_size) + " bytes");

    const std::uint64_t header_at = at + kSignatureHeaderSize + out.next_header_offset;
    if (header_at < at || header_at - at > span.size() ||
        out.next_header_size > span.size() - (header_at - at))
        return Status::fail("7z-truncated: the header is not inside the available data");
    out.size = kSignatureHeaderSize + out.next_header_offset + out.next_header_size;

    if (out.next_header_size == 0) return Status::success();  // an empty archive
    const auto header = span.bytes(header_at, static_cast<std::size_t>(out.next_header_size));
    if (!header) return Status::fail("7z-truncated: the header could not be read");
    out.header_crc_ok =
        crc32_of(std::span<const std::uint8_t>(header->data(), header->size())) == header_crc;
    if (!out.header_crc_ok)
        return Status::fail("7z-header-crc-mismatch: the header does not match its CRC");

    // An encoded header is a StreamsInfo describing one folder whose output
    // is the real header, so it has to be decoded before anything can be read.
    Reader probe(*header);
    if (probe.num() == kEncodedHeader) {
        out.header_was_encoded = true;
        StreamsInfo si;
        Reader r(*header);
        r.num();
        if (!read_streams_info(r, si) || si.folders.size() != 1)
            return Status::fail("7z-bad-header: the encoded header is not one folder");
        std::string bad;
        if (!folder_decodable(si.folders[0], &bad))
            return Status::fail("7z-header-undecodable: the header is compressed with " + bad);
        std::vector<std::uint8_t> plain;
        const std::uint64_t pack_at = at + kSignatureHeaderSize + si.pack_pos;
        if (const Status st = decode_folder(span, si.folders[0], pack_at, si.pack_sizes, plain);
            !st)
            return Status::fail("7z-header-undecodable: " + st.error);
        Reader hr(plain);
        if (!parse_header_body(hr, out))
            return Status::fail("7z-bad-header: the decoded header did not parse");
        return Status::success();
    }

    Reader r(*header);
    if (!parse_header_body(r, out)) return Status::fail("7z-bad-header: the header did not parse");
    return Status::success();
}

}  // namespace omnitrace::sevenzip
