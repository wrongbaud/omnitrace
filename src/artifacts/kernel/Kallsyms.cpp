// Kallsyms.cpp — decoding the symbol table a Linux kernel carries inside
// itself. See the header for why it is read back to front.
//
// The structures, in the order the kernel lays them out:
//
//   kallsyms_num_syms    one word: how many symbols follow
//   kallsyms_names       num_syms entries of (length byte, that many token
//                        indices); the first decoded character is the nm type
//   kallsyms_markers     one word per 256 symbols: the offset of that block
//                        inside `names`, starting at 0
//   kallsyms_token_table 256 NUL-terminated strings, the compression alphabet
//   kallsyms_token_index 256 u16: the offset of each token in that table
//
// Nothing here has a magic number, so each structure is found by a property
// only it has and then confirmed by the next one lining up exactly.
#include "Kallsyms.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace omnitrace::artifacts::kernel {

namespace {

constexpr std::size_t kTokens = 256;
constexpr std::size_t kIndexBytes = kTokens * 2;
// A token table is a few hundred bytes: 256 short fragments of symbol names.
constexpr std::uint16_t kMinTableBytes = 256;
constexpr std::uint16_t kMaxTableBytes = 4096;
constexpr std::size_t kMinSyms = 500;
// How far back from the markers a `num_syms` word may sit. The names blob for
// 400k symbols is a few megabytes; beyond this it is not this kernel's.
constexpr std::size_t kMaxNamesBytes = 8u << 20;
constexpr std::size_t kScoreSample = 500;

std::uint16_t rd16(const std::uint8_t* p, bool be) {
    return be ? static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[0]) << 8) | p[1])
              : static_cast<std::uint16_t>((static_cast<std::uint16_t>(p[1]) << 8) | p[0]);
}
std::uint64_t rdword(const std::uint8_t* p, bool be, unsigned w) {
    std::uint64_t v = 0;
    for (unsigned i = 0; i < w; ++i)
        v |= static_cast<std::uint64_t>(p[be ? w - 1 - i : i]) << (8 * i);
    return v;
}

bool is_symbol_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' ||
           c == '.' || c == '$';
}
// The nm letters the kernel emits, plus the ones it uses for absolute and
// unknown. A name whose first character is not one of these is not a symbol.
bool is_type_char(unsigned char c) {
    return std::strchr("AaBbCcDdGgIiNnPpRrSsTtUuVvWw?-", static_cast<char>(c)) != nullptr &&
           c != '\0';
}

/// Where the token table can start: for every token i > 0 the byte
/// immediately before it is the NUL that ended token i-1. 255 constraints
/// narrow the window to a handful of positions.
///
/// It is a *shortlist*, not an answer. A table whose tokens happen to share a
/// length -- every one a single character, say -- satisfies the constraint
/// shifted by that length as well, so the right base is whichever one goes on
/// to decode into symbols. Taking the first and giving up is how a table gets
/// missed.
std::vector<std::size_t> token_base_candidates(std::span<const std::uint8_t> d,
                                               std::size_t index_at,
                                               const std::uint16_t (&idx)[kTokens]) {
    std::vector<std::size_t> out;
    const std::size_t lo = index_at > kMaxTableBytes ? index_at - kMaxTableBytes : 0;
    for (std::size_t base = lo; base + kMinTableBytes <= index_at; ++base) {
        bool ok = true;
        for (std::size_t i = 1; i < kTokens; ++i) {
            const std::size_t at = base + idx[i];
            if (at == 0 || at - 1 >= index_at || d[at - 1] != 0) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;
        if (base + idx[kTokens - 1] >= index_at) continue;
        out.push_back(base);
        if (out.size() >= 8) break;
    }
    return out;
}

}  // namespace

Kallsyms parse(std::span<const std::uint8_t> image, std::size_t max_symbols) {
    Kallsyms result;
    if (image.size() < kIndexBytes + kMinTableBytes) return result;

    for (const bool be : {false, true}) {
        for (std::size_t at = 0; at + kIndexBytes <= image.size(); at += 2) {
            // index[0] is always 0 and index[1] is token 0's length plus its
            // NUL, which is 1..9 in every real table. Two byte tests reject
            // almost every position before anything is unpacked.
            if (image[at] != 0 || image[at + 1] != 0) continue;
            const std::uint16_t first = rd16(image.data() + at + 2, be);
            if (first < 1 || first > 9) continue;

            std::uint16_t idx[kTokens];
            bool monotonic = true;
            for (std::size_t i = 0; i < kTokens; ++i) {
                idx[i] = rd16(image.data() + at + i * 2, be);
                if (i != 0 && idx[i] < idx[i - 1]) {
                    monotonic = false;
                    break;
                }
            }
            if (!monotonic) continue;
            if (idx[kTokens - 1] < kMinTableBytes || idx[kTokens - 1] > kMaxTableBytes) continue;

            for (const std::size_t table_at : token_base_candidates(image, at, idx)) {
                // The table is now known; read the 256 tokens out of it.
                std::string tokens[kTokens];
                bool tokens_ok = true;
                for (std::size_t i = 0; i < kTokens; ++i) {
                    const std::size_t p = table_at + idx[i];
                    std::size_t e = p;
                    while (e < at && image[e] != 0) ++e;
                    if (e >= at) {
                        tokens_ok = false;
                        break;
                    }
                    tokens[i].assign(reinterpret_cast<const char*>(image.data() + p), e - p);
                }
                if (!tokens_ok) continue;

                for (const unsigned word : {4u, 8u}) {
                    // markers: one word per 256 symbols, increasing, first is 0.
                    //
                    // The gap before the token table is not one word of
                    // alignment. The camera's 3.10 kernel leaves eight
                    // zero bytes there, and a walk that starts inside them
                    // reads a zero, calls it the end of the array and reports
                    // a single marker -- which is how that image decoded to
                    // nothing while its token table sat in plain sight.
                    for (std::size_t pad = 0; pad < 32; ++pad) {
                        if (pad > table_at) break;
                        const std::size_t m_end = table_at - pad;
                        if (m_end % word != 0 || m_end < word * 2) continue;
                        std::size_t p = m_end - word;
                        std::uint64_t prev = 0;
                        bool first_word = true, chain = true;
                        std::size_t markers = 0;
                        while (true) {
                            const std::uint64_t v = rdword(image.data() + p, be, word);
                            if (!first_word && v >= prev) {
                                chain = false;
                                break;
                            }
                            prev = v;
                            first_word = false;
                            ++markers;
                            if (v == 0) break;
                            if (p < word || markers > max_symbols / 256 + 2) {
                                chain = false;
                                break;
                            }
                            p -= word;
                        }
                        if (!chain || markers < 2) continue;
                        const std::size_t m_start = p;
                        const std::uint64_t last_marker =
                            rdword(image.data() + m_end - word, be, word);

                        // num_syms sits immediately before the names blob. A
                        // candidate is confirmed by decoding only the final block
                        // of <=256 symbols and landing exactly on the markers.
                        const std::size_t floor_at =
                            m_start > kMaxNamesBytes ? m_start - kMaxNamesBytes : 0;
                        for (std::size_t ns = m_start - word; ns + word > floor_at; ns -= word) {
                            const std::uint64_t num = rdword(image.data() + ns, be, word);
                            if (num < kMinSyms || num > max_symbols) {
                                if (ns < word) break;
                                continue;
                            }
                            if ((num + 255) / 256 != markers) {
                                if (ns < word) break;
                                continue;
                            }
                            const std::size_t names_at = ns + word;
                            if (last_marker >= m_start - names_at) {
                                if (ns < word) break;
                                continue;
                            }
                            std::size_t q = names_at + static_cast<std::size_t>(last_marker);
                            const std::uint64_t want = num - 256 * (markers - 1);
                            std::uint64_t seen = 0;
                            bool walked = true;
                            while (seen < want) {
                                if (q >= m_start) {
                                    walked = false;
                                    break;
                                }
                                const std::size_t len = image[q];
                                ++q;
                                if (q + len > m_start) {
                                    walked = false;
                                    break;
                                }
                                q += len;
                                ++seen;
                            }
                            // `names` is padded up to the alignment `markers`
                            // needs, so the walk lands within one word of it
                            // rather than exactly on it. Counting `want` entries
                            // first is also what stops a pad byte being read as a
                            // zero-length symbol.
                            if (!walked || q > m_start || m_start - q >= word) {
                                if (ns < word) break;
                                continue;
                            }

                            // Everything lines up. Decode, then judge the result:
                            // a kernel image is megabytes of data and arithmetic
                            // alone will eventually agree with itself.
                            std::vector<Symbol> syms;
                            syms.reserve(static_cast<std::size_t>(num));
                            q = names_at;
                            for (std::uint64_t i = 0; i < num; ++i) {
                                const std::size_t len = image[q];
                                ++q;
                                std::string s;
                                for (std::size_t k = 0; k < len; ++k) s += tokens[image[q + k]];
                                q += len;
                                Symbol sym;
                                if (!s.empty()) {
                                    sym.type = s[0];
                                    sym.name = s.substr(1);
                                }
                                syms.push_back(std::move(sym));
                            }
                            std::size_t good = 0;
                            const std::size_t sample = std::min(kScoreSample, syms.size());
                            for (std::size_t i = 0; i < sample; ++i) {
                                const Symbol& sy = syms[i];
                                if (sy.name.empty()) continue;
                                if (!is_type_char(static_cast<unsigned char>(sy.type))) continue;
                                if (std::all_of(sy.name.begin(), sy.name.end(), [](char c) {
                                        return is_symbol_char(static_cast<unsigned char>(c));
                                    }))
                                    ++good;
                            }
                            if (sample == 0 || good * 10 < sample * 9) {
                                if (ns < word) break;
                                continue;
                            }
                            result.found = true;
                            result.big_endian = be;
                            result.word_size = word;
                            result.token_table = table_at;
                            result.num_syms_at = ns;
                            result.symbols = std::move(syms);
                            return result;
                        }
                    }
                }
            }
        }
    }
    return result;
}

}  // namespace omnitrace::artifacts::kernel
