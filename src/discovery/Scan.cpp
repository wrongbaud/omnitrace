// Scan.cpp — multi-pattern magic search over a Span plus deterministic
// conflict resolution.
//
// Search: every signature's first two magic bytes index a 64 Ki-entry table;
// the inner loop is one load + one table probe per byte and only falls into
// the candidate list (sorted by signature index) on a probe hit, so a 4 GB
// image scans in a few seconds. The Span is walked in chunks (zero-copy via
// Span::view when the Source maps, otherwise Span::read into a buffer) with
// an overlap of max_magic_len - 1 so no hit straddling a chunk edge is lost.
//
// Hits become Findings by calling the signature's validator (if any). A hit of
// signature S that lands inside the range of an already-accepted finding of S
// at Consistent or better is not re-validated: formats made of repeated nodes
// (JFFS2, UBI, tar) would otherwise cost O(n^2) and produce one finding per
// node. See docs/formats/signatures.md.
//
// Conflict resolution treats partition tables specially: a table finding is
// only ever absorbed by another partition table (a protective MBR under its
// GPT), never by a filesystem or container that happens to start at the same
// offset or to claim the bytes around it. A table's own extent is small (one
// sector to a few KiB) so the normal rule still suppresses stray magics that
// land inside its entry array. See docs/formats/partition-tables.md.
#include <algorithm>
#include <cstring>
#include <sstream>

#include "omnitrace/discovery/Signature.h"

namespace omnitrace::discovery {

namespace {

// Bytes read per chunk. A buffer size, not an evidence limit: hits are found
// regardless of where chunk edges fall.
constexpr std::size_t kChunkBytes = 16u << 20;

struct Candidate {
    std::uint16_t key;
    std::uint32_t sig;
};

struct Compiled {
    std::vector<std::uint8_t> probe;    // 65536 flags indexed by first two magic bytes
    std::vector<Candidate> candidates;  // sorted by (key, sig)
    std::size_t max_len = 0;
};

Compiled compile(const SignatureSet& sigs) {
    Compiled c;
    c.probe.assign(65536, 0);
    for (std::size_t i = 0; i < sigs.signatures.size(); ++i) {
        const auto& m = sigs.signatures[i].magic;
        if (m.size() < 2) continue;  // load_toml rejects these; defensive for hand-built sets
        const std::uint16_t key = static_cast<std::uint16_t>((m[0] << 8) | m[1]);
        c.probe[key] = 1;
        c.candidates.push_back({key, static_cast<std::uint32_t>(i)});
        c.max_len = std::max(c.max_len, m.size());
    }
    std::sort(c.candidates.begin(), c.candidates.end(), [](const Candidate& a, const Candidate& b) {
        return a.key != b.key ? a.key < b.key : a.sig < b.sig;
    });
    return c;
}

std::string hex_u64(std::uint64_t v) {
    std::ostringstream os;
    os << "0x" << std::hex << v;
    return os.str();
}

std::string magic_text(const std::vector<std::uint8_t>& m) {
    std::string out;
    bool printable = true;
    for (const std::uint8_t b : m) printable = printable && b >= 0x20 && b < 0x7F && b != '"';
    if (printable) {
        out.push_back('"');
        out.append(m.begin(), m.end());
        out.push_back('"');
        return out;
    }
    static const char* digits = "0123456789abcdef";
    for (const std::uint8_t b : m) {
        if (!out.empty()) out.push_back(' ');
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0xF]);
    }
    return out;
}

std::uint64_t end_of(const Finding& f) {
    return f.size > UINT64_MAX - f.offset ? UINT64_MAX : f.offset + f.size;
}

struct Range {
    std::uint64_t offset = 0;
    std::uint64_t end = 0;
};

// attrs["also_covers"] = "offset:length;offset:length;..." (decimal, Span
// relative). Anything unparsable is ignored: a malformed hint only costs a
// duplicate finding, never a crash.
std::vector<Range> parse_ranges(const std::string& text) {
    std::vector<Range> out;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t item_end = text.find(';', pos);
        if (item_end == std::string::npos) item_end = text.size();
        const std::string item = text.substr(pos, item_end - pos);
        pos = item_end + 1;
        const std::size_t colon = item.find(':');
        if (colon == std::string::npos) continue;
        std::uint64_t v[2] = {0, 0};
        bool ok = colon > 0 && colon + 1 < item.size();
        for (int k = 0; k < 2 && ok; ++k) {
            const std::string field = k == 0 ? item.substr(0, colon) : item.substr(colon + 1);
            for (const char ch : field) {
                if (ch < '0' || ch > '9' || v[k] > (UINT64_MAX - 9) / 10) {
                    ok = false;
                    break;
                }
                v[k] = v[k] * 10 + static_cast<std::uint64_t>(ch - '0');
            }
        }
        if (!ok || v[1] == 0) continue;
        out.push_back({v[0], v[1] > UINT64_MAX - v[0] ? UINT64_MAX : v[0] + v[1]});
    }
    return out;
}

// Total order used for output and for resolution.
bool before(const Finding& a, const Finding& b) {
    if (a.offset != b.offset) return a.offset < b.offset;
    if (a.confidence != b.confidence) return a.confidence > b.confidence;
    if (a.size != b.size) return a.size > b.size;
    if (a.signature != b.signature) return a.signature < b.signature;
    return a.format < b.format;
}

bool is_partition_table(const Finding& f) {
    return f.category == "partition-table";
}

// A raw compressed stream (gzip, xz, lz4 frame, zstd). These validators cap at
// Structural by design: a deflate header carries nothing to cross-check.
bool is_compressed_stream(const Finding& f) {
    return f.category == "compressed";
}

// May `owner` take `f` into its also_matched? A partition table is only ever
// absorbed by another partition table; anything else follows the normal rule.
bool may_absorb(const Finding& owner, const Finding& f) {
    return !is_partition_table(f) || is_partition_table(owner);
}

// Confidence part of the containment rule: strictly higher, or equal when `f`
// is a compressed stream inside something that is not one.
//
// A SquashFS or JFFS2 is built out of gzip/xz/lz4/zstd blocks, so its range is
// full of compressed-stream hits that are noise, not finds. Normally the
// filesystem outranks them and absorbs them. When it is truncated it drops to
// Structural, the same tier those validators cap at, and the strict rule
// releases every one of them: a SquashFS cut short by an extraction limit
// turned into 131 spurious top-level containers. Equal-confidence nesting is
// still kept for everything else (an ext4 inside an MBR partition stays
// visible), and a compressed stream still outranks nothing: it is only ever
// the absorbed side here.
bool outranks(const Finding& owner, const Finding& f) {
    if (owner.confidence > f.confidence) return true;
    return owner.confidence == f.confidence && is_compressed_stream(f) &&
           !is_compressed_stream(owner);
}

std::vector<Finding> resolve(std::vector<Finding> in) {
    std::sort(in.begin(), in.end(), before);
    std::vector<Finding> kept;
    kept.reserve(in.size());
    // Indices into `kept` of sized findings that may still contain later ones,
    // innermost last. Zero-size findings never contain anything.
    std::vector<std::size_t> open;
    for (Finding& f : in) {
        const std::uint64_t f_end = end_of(f);
        while (!open.empty() && end_of(kept[open.back()]) <= f.offset) open.pop_back();
        std::optional<std::size_t> owner;
        // Exact same-offset duplicate: the first eligible in sort order (higher
        // confidence, then larger, then name) is among the kept findings at
        // this offset, which are contiguous at the back of `kept`.
        for (std::size_t j = kept.size(); j-- > 0 && kept[j].offset == f.offset;) {
            if (may_absorb(kept[j], f)) {
                owner = j;
                break;
            }
        }
        if (!owner) {
            for (auto it = open.rbegin(); it != open.rend(); ++it) {
                const Finding& k = kept[*it];
                if (outranks(k, f) && f.offset >= k.offset && f_end <= end_of(k) &&
                    may_absorb(k, f)) {
                    owner = *it;
                    break;
                }
            }
        }
        if (owner) {
            f.also_matched.clear();
            kept[*owner].also_matched.push_back(std::move(f));
            continue;
        }
        kept.push_back(std::move(f));
        if (kept.back().size > 0) open.push_back(kept.size() - 1);
    }
    return kept;
}

}  // namespace

std::vector<Finding> scan(const Span& span, const SignatureSet& sigs, const ScanOptions& opts) {
    std::vector<Finding> out;
    const Compiled comp = compile(sigs);
    if (comp.candidates.empty() || span.empty()) return out;

    // Resolve validators once.
    std::vector<const Validator*> validators(sigs.signatures.size(), nullptr);
    std::vector<std::uint8_t> validator_missing(sigs.signatures.size(), 0);
    if (opts.validate) {
        for (std::size_t i = 0; i < sigs.signatures.size(); ++i) {
            const std::string& name = sigs.signatures[i].validator;
            if (name.empty()) continue;
            validators[i] = ValidatorRegistry::instance().find(name);
            if (validators[i] == nullptr) validator_missing[i] = 1;
        }
    }
    // Per signature: end of the last accepted finding at >= Consistent, plus
    // any member ranges a validator declared through attrs["also_covers"]
    // (the EBRs of an MBR chain: each is a 0x55AA sector that would otherwise
    // be reported as a table of its own). Hits arrive in offset order, so
    // ranges are dropped once passed.
    std::vector<std::uint64_t> covered_until(sigs.signatures.size(), 0);
    std::vector<std::vector<Range>> also_covered(sigs.signatures.size());
    bool hit_limit = false;

    auto on_hit = [&](std::uint64_t hit, std::uint32_t si) {
        const Signature& sig = sigs.signatures[si];
        if (sig.magic_offset > hit) return;  // structure would start before the Span
        const std::uint64_t start = hit - sig.magic_offset;
        if (sig.alignment > 1 && (start % sig.alignment) != 0) return;
        if (start < covered_until[si]) return;
        if (!also_covered[si].empty()) {
            auto& ranges = also_covered[si];
            ranges.erase(std::remove_if(ranges.begin(), ranges.end(),
                                        [&](const Range& r) { return r.end <= start; }),
                         ranges.end());
            for (const Range& r : ranges)
                if (start >= r.offset && start < r.end) return;
        }

        std::optional<Finding> f;
        if (validators[si] != nullptr) {
            f = (*validators[si])(span, start, sig);
            if (!f) return;  // validator rejected
        } else {
            f.emplace();
            f->offset = start;
            f->confidence = Confidence::Magic;
            if (validator_missing[si] != 0) {
                f->diagnostics.push_back(
                    {Severity::Warning, "validator-missing",
                     "signature '" + sig.name + "' names validator '" + sig.validator +
                         "' which is not registered; reporting the magic match only"});
            }
        }
        f->signature = sig.name;
        if (f->format.empty()) f->format = sig.format;
        if (f->category.empty()) f->category = sig.category;
        if (sig.endian) f->endian = *sig.endian;
        std::string ev = "magic " + magic_text(sig.magic) + " at " + hex_u64(hit);
        if (sig.magic_offset != 0) ev += " (structure at " + hex_u64(start) + ")";
        f->evidence = f->evidence.empty() ? ev : ev + "; " + f->evidence;
        if (f->confidence >= Confidence::Consistent && f->size > 0 && f->offset == start)
            covered_until[si] = end_of(*f);
        if (const auto it = f->attrs.find("also_covers"); it != f->attrs.end())
            for (const Range& r : parse_ranges(it->second))
                if (r.offset > start) also_covered[si].push_back(r);
        out.push_back(std::move(*f));
        if (out.size() >= opts.max_hits) hit_limit = true;
    };

    const std::uint64_t total = span.size();
    const std::size_t overlap = comp.max_len - 1;
    std::vector<std::uint8_t> buffer;
    std::uint64_t pos = 0;
    while (pos < total && !hit_limit) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(kChunkBytes, total - pos));
        const bool last_chunk = pos + want >= total;
        const std::uint8_t* p = nullptr;
        std::size_t n = 0;
        if (auto v = span.view(pos, want)) {
            p = v->data();
            n = v->size();
        } else {
            buffer.resize(want);
            n = span.read(pos, std::span<std::uint8_t>(buffer.data(), want));
            p = buffer.data();
            if (n == 0) break;  // unreadable source: stop rather than spin
        }
        // Starts fully served by this chunk: any pattern (<= max_len) fits.
        const std::size_t limit = last_chunk ? n : (n > overlap ? n - overlap : 0);
        for (std::size_t s = 0; s + 1 < n && s < limit && !hit_limit; ++s) {
            const std::uint16_t key = static_cast<std::uint16_t>((p[s] << 8) | p[s + 1]);
            if (comp.probe[key] == 0) continue;
            auto it =
                std::lower_bound(comp.candidates.begin(), comp.candidates.end(), Candidate{key, 0},
                                 [](const Candidate& a, const Candidate& b) {
                                     return a.key != b.key ? a.key < b.key : a.sig < b.sig;
                                 });
            for (; it != comp.candidates.end() && it->key == key; ++it) {
                const auto& m = sigs.signatures[it->sig].magic;
                if (m.size() > n - s) continue;
                if (std::memcmp(p + s, m.data(), m.size()) != 0) continue;
                on_hit(pos + s, it->sig);
            }
        }
        if (last_chunk || n < want) break;
        pos += n - overlap;
    }

    if (hit_limit && !out.empty()) {
        std::ostringstream os;
        os << "stopped after " << opts.max_hits
           << " hits (ScanOptions::max_hits); the rest of the Span was not scanned";
        out.back().diagnostics.push_back({Severity::Warning, "scan-hit-limit", os.str()});
    }
    if (opts.resolve_conflicts) return resolve(std::move(out));
    std::sort(out.begin(), out.end(), before);
    return out;
}

}  // namespace omnitrace::discovery
