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

// Total order used for output and for resolution.
bool before(const Finding& a, const Finding& b) {
    if (a.offset != b.offset) return a.offset < b.offset;
    if (a.confidence != b.confidence) return a.confidence > b.confidence;
    if (a.size != b.size) return a.size > b.size;
    if (a.signature != b.signature) return a.signature < b.signature;
    return a.format < b.format;
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
        // Exact same-offset duplicate: the first in sort order (higher
        // confidence, then larger, then name) already sits at kept.back().
        if (!kept.empty() && kept.back().offset == f.offset) {
            owner = kept.size() - 1;
        } else {
            for (auto it = open.rbegin(); it != open.rend(); ++it) {
                const Finding& k = kept[*it];
                if (k.confidence > f.confidence && f.offset >= k.offset && f_end <= end_of(k)) {
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
    // Per signature: end of the last accepted finding at >= Consistent.
    std::vector<std::uint64_t> covered_until(sigs.signatures.size(), 0);
    bool hit_limit = false;

    auto on_hit = [&](std::uint64_t hit, std::uint32_t si) {
        const Signature& sig = sigs.signatures[si];
        if (sig.magic_offset > hit) return;  // structure would start before the Span
        const std::uint64_t start = hit - sig.magic_offset;
        if (sig.alignment > 1 && (start % sig.alignment) != 0) return;
        if (start < covered_until[si]) return;

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
