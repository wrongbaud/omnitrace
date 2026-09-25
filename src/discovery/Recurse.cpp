// Recurse.cpp — the analysis driver. See Recurse.h for the contract.
//
// Node insertion order is: partition tables and their entries first (they are
// the map every other finding is placed on), then every other finding and gap
// in byte order, so the same image always yields the same ids and the same
// manifest.yaml. Every offset arithmetic saturates; every reader or host
// failure becomes a Diagnostic on the node it belongs to and a Coverage row,
// never an exception or a skipped finding.
#include "omnitrace/discovery/Recurse.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <system_error>

#include "omnitrace/core/Entropy.h"
#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Span.h"
#include "omnitrace/core/Swap.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::discovery {

// The budget is a policy about evidence; the disk is a fact about the machine.
// Nothing connected the two, so the ratio default -- which exists so a large
// image is not truncated by a number chosen for a 2 MiB SPI part -- asked for
// 467 GiB of extraction from a 116 GiB UFS LUN onto a filesystem with 330 GB
// free. Filling the disk is worse than truncating: the run dies partway, the
// case is unusable, and so is the machine until someone clears space.
std::uint64_t disk_headroom(std::uint64_t available) {
    constexpr std::uint64_t kMinReserve = 256ull << 20;
    const std::uint64_t reserve = std::max(kMinReserve, available / 20);
    return available > reserve ? available - reserve : 0;
}

namespace {

// Bytes free on the filesystem that holds `dir`, or nullopt when it cannot be
// asked -- a path that does not exist yet, a Source with no filesystem behind
// it, a platform that refuses. Unknown means unguarded: a guard that fired on
// a failed query would refuse to run where it cannot measure.
std::optional<std::uint64_t> available_bytes(const std::filesystem::path& dir) {
    std::error_code ec;
    std::filesystem::path probe = dir;
    while (!probe.empty() && !std::filesystem::exists(probe, ec)) {
        const std::filesystem::path up = probe.parent_path();
        if (up == probe) break;
        probe = up;
    }
    if (probe.empty()) return std::nullopt;
    const std::filesystem::space_info info = std::filesystem::space(probe, ec);
    if (ec || info.available == static_cast<std::uintmax_t>(-1)) return std::nullopt;
    return static_cast<std::uint64_t>(info.available);
}

// ------------------------------------------------------------------ helpers

std::string dec(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%llu", static_cast<unsigned long long>(v));
    return buf;
}

std::string hex(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

// "0x" + at least eight hex digits: the carved-file prefix for nested finds.
std::string hex08(std::uint64_t v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%08llx", static_cast<unsigned long long>(v));
    return buf;
}

std::uint64_t sat_add(std::uint64_t a, std::uint64_t b) {
    return b > UINT64_MAX - a ? UINT64_MAX : a + b;
}

// Last path component, whatever the separator; the whole string if none.
std::string basename_of(const std::string& path) {
    const std::size_t cut = path.find_last_of("/\\");
    if (cut == std::string::npos) return path;
    return path.substr(cut + 1);
}

// Strict unsigned decimal parse: the whole string, no sign, no overflow.
std::optional<std::uint64_t> parse_u64(const std::string& s) {
    if (s.empty() || s.size() > 20) return std::nullopt;
    std::uint64_t v = 0;
    for (const char ch : s) {
        if (ch < '0' || ch > '9') return std::nullopt;
        const std::uint64_t d = static_cast<std::uint64_t>(ch - '0');
        if (v > (UINT64_MAX - d) / 10) return std::nullopt;
        v = v * 10 + d;
    }
    return v;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (;;) {
        const std::size_t cut = s.find(sep, start);
        if (cut == std::string::npos) {
            out.push_back(s.substr(start));
            return out;
        }
        out.push_back(s.substr(start, cut - start));
        start = cut + 1;
    }
}

std::string attr_or(const std::map<std::string, std::string>& attrs, const char* key,
                    const std::string& fallback) {
    const auto it = attrs.find(key);
    return it == attrs.end() ? fallback : it->second;
}

bool has_diag(const std::vector<Diagnostic>& ds, const char* code) {
    for (const Diagnostic& d : ds)
        if (d.code == code) return true;
    return false;
}

// --------------------------------------------------------------- structures

// A byte range [offset, end) that is accounted for and therefore not a gap.
struct Claim {
    std::uint64_t offset = 0;
    std::uint64_t end = 0;
};

// A structural node that may contain later findings (for parent lookup).
struct Extent {
    std::string id;
    std::uint64_t offset = 0;
    std::uint64_t end = 0;
};

// One partition entry parsed from a partition-table finding's attrs.
struct PartSpec {
    std::string index;        // "p1"
    std::uint64_t start = 0;  // relative to LBA 0 of the disk the table describes
    std::uint64_t size = 0;
    std::map<std::string, std::string> attrs;
};

// One partition entry node of the span being analysed.
struct PartInfo {
    std::string id;
    std::string index;
    std::uint64_t start = 0, end = 0;  // span-relative; end == start when unusable
    bool protective = false;           // MBR 0xEE covering a GPT: not a real partition
};

// Mutable state for one analyze() call. Readers never see it.
struct Ctx {
    const AnalyzeOptions& opts;
    Manifest& out;
    Listings& listings;
    std::string image_id;
    std::uint64_t files_used = 0;  // run-wide Limits accounting across every walk
    std::uint64_t bytes_used = 0;
    std::map<std::string, std::size_t> coverage_index;  // format -> row in out.coverage
    std::vector<Extent> extents;                        // structural nodes, insertion order
};

// One row per format. "partial" outranks "supported" so a failed walk is never
// hidden behind an earlier success of the same format.
void set_coverage(Ctx& c, const std::string& format, const std::string& status,
                  const std::string& detail) {
    const auto it = c.coverage_index.find(format);
    if (it == c.coverage_index.end()) {
        c.coverage_index.emplace(format, c.out.coverage.size());
        c.out.coverage.push_back({format, status, detail});
        return;
    }
    Coverage& row = c.out.coverage[it->second];
    if (row.status == "partial" && status == "supported") return;
    if (row.status == status && row.detail == detail) return;
    row.status = status;
    if (!detail.empty()) row.detail = detail;
}

// The "carve" row accumulates: every skipped or failed carve is listed.
void carve_partial(Ctx& c, const std::string& detail) {
    const auto it = c.coverage_index.find("carve");
    if (it == c.coverage_index.end()) {
        set_coverage(c, "carve", "partial", detail);
        return;
    }
    Coverage& row = c.out.coverage[it->second];
    if (row.status != "partial") {
        row.status = "partial";
        row.detail = detail;
    } else if (!row.detail.empty()) {
        row.detail += "; " + detail;
    } else {
        row.detail = detail;
    }
}

// Innermost structural node whose range contains `offset`; `fallback`
// otherwise. Ties go to the most recently added node (the most nested one).
std::string parent_for(const Ctx& c, std::uint64_t offset, const std::string& fallback) {
    std::string best = fallback;
    std::uint64_t best_len = UINT64_MAX;
    for (const Extent& e : c.extents) {
        if (offset < e.offset || offset >= e.end) continue;
        const std::uint64_t len = e.end - e.offset;
        if (len <= best_len) {
            best_len = len;
            best = e.id;
        }
    }
    return best;
}

NodeKind kind_for(const Finding& f) {
    if (f.category == "partition-table") return NodeKind::Partition;
    if (f.category == "filesystem") return NodeKind::Filesystem;
    if (f.category == "container" || f.category == "compressed" || f.format == "uimage")
        return NodeKind::Container;
    return NodeKind::Region;  // kernel, bootloader, crypto, other: identified bytes, nothing to
                              // open
}

std::string name_for(const Finding& f) {
    for (const char* key : {"label", "volume_name", "name"}) {
        const auto it = f.attrs.find(key);
        if (it != f.attrs.end() && !it->second.empty()) return sanitize_utf8(it->second);
    }
    return f.format;
}

Node node_from_finding(const Finding& f, const Span& span, const std::string& parent_id,
                       NodeKind kind) {
    Node n;
    n.kind = kind;
    n.parent_id = parent_id;
    n.name = name_for(f);
    n.format = f.format;
    n.location = {span.source_id(), span.absolute(f.offset), f.size};
    n.confidence = static_cast<std::uint8_t>(f.confidence);
    n.evidence = f.evidence;
    n.endian = f.endian;
    n.attrs = f.attrs;
    n.attrs["signature"] = f.signature;
    n.attrs["category"] = f.category;
    n.diagnostics = f.diagnostics;
    for (const Finding& alt : f.also_matched) {
        n.diagnostics.push_back({Severity::Info, "also-matched",
                                 alt.format + " (" + alt.signature + ") also matched at " +
                                     hex(span.absolute(alt.offset)) + " with confidence " +
                                     dec(static_cast<std::uint8_t>(alt.confidence))});
    }
    return n;
}

// A finding of unknown size (0) has no extent: it claims no bytes and parents
// nothing, so a magic-only zip does not swallow every find after it (auto-emmc:
// the squashfs and ext4 were nested under a size-0 zip -> xz chain).
std::uint64_t end_of(const Finding& f, const Span& span) {
    if (f.size == 0) return std::min(f.offset, span.size());
    return std::min(sat_add(f.offset, f.size), span.size());
}

std::vector<Finding> run_scanner(const Ctx& c, const Span& span) {
    if (c.opts.scanner) return c.opts.scanner(span);
    return scan(span, SignatureSet::builtin(), c.opts.scan);
}

// -------------------------------------------------------- partition tables

// attrs["partitions"] is "p1:start:size:type[:...];p2:..." (see validators/mbr.cpp
// and validators/gpt.cpp). Anything unparsable is reported and skipped.
std::vector<PartSpec> parse_partitions(const Finding& f, std::vector<Diagnostic>& diags) {
    std::vector<PartSpec> out;
    const auto it = f.attrs.find("partitions");
    if (it == f.attrs.end() || it->second.empty()) return out;
    for (const std::string& item : split(it->second, ';')) {
        const std::vector<std::string> fields = split(item, ':');
        const auto start = fields.size() > 1 ? parse_u64(fields[1]) : std::nullopt;
        const auto size = fields.size() > 2 ? parse_u64(fields[2]) : std::nullopt;
        if (fields.size() < 4 || !start || !size) {
            diags.push_back({Severity::Warning, "partition-entry-unparsable",
                             "cannot parse partition entry '" + sanitize_utf8(item) + "'"});
            continue;
        }
        PartSpec p;
        p.index = fields[0];
        p.start = *start;
        p.size = *size;
        p.attrs["type"] = fields[3];
        if (f.format == "gpt")
            p.attrs["type_guid"] = fields[3];
        else
            p.attrs["type_byte"] = fields[3];
        // Positional fields first (a GPT label is evidence bytes and may
        // itself contain '='), then only the keys and flags the validators
        // emit: anything else would let a partition name inject attrs such as
        // protective=true, role=table or carved_path=... into the node.
        for (std::size_t i = 4; i < fields.size(); ++i) {
            const std::string& fld = fields[i];
            if (f.format == "gpt" && i == 4) {
                p.attrs["unique_guid"] = fld;
                continue;
            }
            if (f.format == "gpt" && i == 5) {
                if (!fld.empty()) p.attrs["label"] = sanitize_utf8(fld);
                continue;
            }
            const std::size_t eq = fld.find('=');
            if (eq != std::string::npos) {
                if (fld.substr(0, eq) == "attrs") p.attrs["gpt_attributes"] = fld.substr(eq + 1);
                continue;
            }
            if (fld == "boot" || fld == "logical") p.attrs[fld] = "true";  // mbr flags
        }
        out.push_back(std::move(p));
    }
    return out;
}

// Bytes the table's own metadata occupies (the header sectors, not the
// partitions it describes). The rest of the extent is claimed by the entries.
std::uint64_t table_metadata_bytes(const Finding& f) {
    std::uint64_t claim = 512;
    if (f.format == "gpt") {
        const std::uint64_t sector =
            parse_u64(attr_or(f.attrs, "sector_size", "512")).value_or(512);
        const std::uint64_t count = parse_u64(attr_or(f.attrs, "entry_count", "0")).value_or(0);
        const std::uint64_t esize = parse_u64(attr_or(f.attrs, "entry_size", "0")).value_or(0);
        std::uint64_t array =
            (esize != 0 && count > UINT64_MAX / esize) ? UINT64_MAX : count * esize;
        if (sector != 0 && array % sector != 0) array = sat_add(array, sector - array % sector);
        claim = sat_add(sector == 0 ? 1024 : 2 * sector, array);
    }
    if (f.size != 0 && claim > f.size) claim = f.size;
    return claim;
}

// "mbr-primary" | "gpt-primary" | "gpt-backup", from the validator's attrs
// (contract) or, for an older validator, from its backup marker.
std::string table_role(const Finding& f) {
    const std::string t = attr_or(f.attrs, "table", "");
    if (!t.empty()) return t;
    if (f.format == "gpt" && attr_or(f.attrs, "backup", "") == "true") return "gpt-backup";
    return f.format + "-primary";
}

// Span-relative offset of LBA 0 of the disk a table describes.
std::uint64_t disk_base(const Finding& f, const std::string& role) {
    if (const auto v = parse_u64(attr_or(f.attrs, "disk_offset", ""))) return *v;
    return role == "gpt-backup" ? 0 : f.offset;
}

// A used table in this span, after GPT primary/backup folding.
struct TableUse {
    std::size_t finding = 0;
    std::optional<std::size_t> folded_backup;  // gpt-backup absorbed into this primary
    std::string role;
};

// Fold GPT backups into their primaries (same disk_guid); a backup with no
// primary is used on its own. Every other table is used as is.
std::vector<TableUse> choose_tables(const std::vector<Finding>& findings) {
    std::vector<TableUse> use;
    std::set<std::size_t> folded;
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const Finding& f = findings[i];
        if (f.category != "partition-table" || f.format != "gpt") continue;
        if (table_role(f) != "gpt-primary") continue;
        const std::string guid = attr_or(f.attrs, "disk_guid", "");
        if (guid.empty()) continue;
        for (std::size_t j = 0; j < findings.size(); ++j) {
            const Finding& b = findings[j];
            if (j == i || b.category != "partition-table" || b.format != "gpt") continue;
            if (table_role(b) != "gpt-backup" || attr_or(b.attrs, "disk_guid", "") != guid)
                continue;
            if (folded.insert(j).second) {
                use.push_back({i, j, "gpt-primary"});
                break;
            }
        }
    }
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const Finding& f = findings[i];
        if (f.category != "partition-table" || folded.count(i)) continue;
        bool already = false;
        for (const TableUse& u : use) already = already || u.finding == i;
        if (!already) use.push_back({i, std::nullopt, table_role(f)});
    }
    std::sort(use.begin(), use.end(), [&](const TableUse& a, const TableUse& b) {
        return findings[a.finding].offset < findings[b.finding].offset;
    });
    return use;
}

// ------------------------------------------------------------- filesystems

// analyze_span and process_filesystem are mutually recursive: walking a
// filesystem extracts files, and an extracted file may itself be an image
// (the QNX6 "storage" partition of the corpus keeps SquashFS update images
// that way). The findings overload lets a caller that has already scanned the
// Span hand the result over instead of scanning it twice.
void analyze_span(Ctx& c, const Span& span, const std::string& parent_id, std::size_t depth);
void analyze_span(Ctx& c, const Span& span, const std::string& parent_id, std::size_t depth,
                  std::vector<Finding> findings);

struct WalkOutcome {
    fs::WalkResult result;
    std::uint64_t files = 0, bytes = 0;
    Status status = Status::success();
    std::string sink_error;
};

// A reader's walk, type-erased: FilesystemReader and ContainerReader have the
// same walk signature but no common base, and this file must not care which.
using WalkFn = std::function<Status(Sink&, const fs::WalkOptions&, fs::WalkResult&)>;

// Open the right Sink for this run and run `do_walk` into it. `group` is the
// case-directory subdirectory the tree lands in ("filesystems" or
// "containers"); `node_id` names the directory inside it.
WalkOutcome walk_into_sink(Ctx& c, const WalkFn& do_walk, const char* group,
                           const std::string& node_id, const Limits& limits) {
    WalkOutcome w;
    fs::WalkOptions wopts;
    wopts.extract_data = c.opts.extract;
    wopts.history = c.opts.history;
    wopts.limits = limits;

    if (c.opts.extract) {
        const std::filesystem::path root =
            std::filesystem::path(c.opts.out_dir) / group / node_id / "files";
        std::error_code ec;
        std::filesystem::create_directories(root.parent_path(), ec);
        if (ec) {
            w.sink_error = "cannot create '" + root.parent_path().string() + "': " + ec.message();
            return w;
        }
        DiskSink::Options dopts;
        dopts.hash = true;
        dopts.write_versions = c.opts.history;
        dopts.limits = limits;
        // Beside the tree it mirrors, named for what it holds.
        if (c.opts.tar_filesystems) dopts.tar_path = (root.parent_path() / "files.tar").string();
        std::unique_ptr<DiskSink> sink;
        if (Status st = DiskSink::open(root.string(), dopts, sink); !st) {
            w.sink_error = st.error;
            return w;
        }
        w.status = do_walk(*sink, wopts, w.result);
        w.files = sink->files_emitted();
        w.bytes = sink->bytes_emitted();
        return w;
    }

    ListingSink sink(false, limits);
    w.status = do_walk(sink, wopts, w.result);
    if (w.result.entries_out.empty() && !sink.entries().empty())
        w.result.entries_out = sink.entries();
    w.files = sink.files_emitted();
    w.bytes = sink.bytes_emitted();
    return w;
}

// An extracted file to re-scan, and the File node it becomes the content of.
struct Descend {
    std::string node_id;
    std::string host_path;
};

std::vector<Descend> add_file_nodes(Ctx& c, const std::string& fs_id, const Node& fs_node,
                                    const std::vector<EntryResult>& entries) {
    std::vector<Descend> nested;
    for (const EntryResult& r : entries) {
        Node fn;
        fn.kind = NodeKind::File;
        fn.parent_id = fs_id;
        fn.name = basename_of(r.meta.path);
        if (fn.name.empty()) fn.name = r.meta.path;
        fn.location =
            fs_node
                .location;  // Phase 0: the filesystem's span; per-file extents are a reader feature
        fn.confidence = fs_node.confidence;
        fn.evidence = "walked by " + fs_node.format + " reader";
        fn.endian = fs_node.endian;
        fn.file = r.meta;
        fn.digests = r.digests;
        fn.diagnostics = r.diagnostics;
        if (r.truncated) fn.attrs["truncated"] = "true";
        if (!r.written && c.opts.extract && r.meta.kind == EntryKind::Regular &&
            r.host_path.empty())
            fn.attrs["written"] = "false";
        const std::string id = c.out.add_node(std::move(fn)).id;
        // Only a regular file whose bytes actually reached the host can be
        // re-scanned: there is nothing to map otherwise. With --no-extract
        // host_path is always empty, so nothing is descended into.
        if (r.written && !r.host_path.empty() && r.meta.kind == EntryKind::Regular &&
            r.meta.size != 0)
            nested.push_back({id, r.host_path});
    }
    return nested;
}

// Re-scan one extracted file and, when it holds something worth opening, run
// the whole pass over it with the File node as the parent.
//
// "Worth opening" is a Filesystem or a Partition table found at Structural or
// better. Both halves matter, measured on the QNX corpus (14.7 GiB, 163k
// extracted files):
//
//   * Kind. A Region find (an ELF, a DTB, a certificate) is identified bytes
//     with nothing to open, and every rootfs is full of them. A Container
//     counts only when open_container actually yields a reader for it: with
//     no reader the node would carry an "analyze-no-reader" warning and
//     recover nothing, which is how 909 gzip entries in a rootfs turn into
//     909 useless nodes.
//   * Tier. Confidence::Magic means the magic matched and nothing was
//     validated. The magic-only signatures (zip, tar, cpio, 7z) hit constantly
//     inside compressed and binary data: descending on them produced 3988 zip
//     and 1994 tar nodes, every one a false positive, against 32 real nested
//     filesystems. Requiring Structural also drops the romfs hits the validator
//     itself calls "magic string inside other data".
//   * Extent, for filesystems and partition tables. The find must claim at
//     least min_region_bytes, the floor the pass already applies to
//     unidentified space. A high tier is not by itself a size: the JFFS2
//     validator CRC-checks nodes and reaches Verified on a single valid
//     12-byte node, so the `mtd` binary in the router rootfs holds a "verified
//     jffs2 filesystem" of 12 bytes. Nothing can be recovered out of an image
//     smaller than a gap worth reporting. A compressed stream is exempt: its
//     extent is unknown until the reader decodes it, which is the whole point
//     of opening it.
void descend_into_file(Ctx& c, const Descend& d, std::size_t depth) {
    std::shared_ptr<MappedFile> file;
    if (Status st = MappedFile::open(d.host_path, file); !st) {
        if (Node* n = c.out.find(d.node_id))
            n->diagnostics.push_back(
                {Severity::Warning, "analyze-nested-open-failed",
                 "the extracted file could not be re-read for nested analysis: " + st.error});
        return;
    }
    if (file->size() == 0) return;
    const Span whole = Span::whole(file);

    std::vector<Finding> findings = run_scanner(c, whole);
    bool worth_opening = false;
    for (const Finding& f : findings) {
        if (f.confidence < Confidence::Structural) continue;
        const NodeKind k = kind_for(f);
        if (k == NodeKind::Filesystem || k == NodeKind::Partition)
            worth_opening = worth_opening || f.size >= c.opts.min_region_bytes;
        else if (k == NodeKind::Container)
            worth_opening =
                worth_opening || (c.opts.open_container && c.opts.open_container(f.format));
    }
    if (!worth_opening) return;

    if (Node* n = c.out.find(d.node_id)) n->attrs["nested_image"] = "true";
    // Extents are Span-relative, so the image's must not be visible while a
    // different Source is analysed; everything else in Ctx (the run-wide
    // budgets, the coverage index) is deliberately shared.
    std::vector<Extent> outer;
    outer.swap(c.extents);
    analyze_span(c, whole, d.node_id, depth + 1, std::move(findings));
    c.extents.swap(outer);
}

// Re-scan every file a walk wrote, after the owning node is complete so the
// manifest is consistent while a deeper level is being built. The depth cap is
// checked once here rather than per file: a rootfs has thousands of them and
// one diagnostic per level is what the examiner needs.
void descend_all(Ctx& c, const std::vector<Descend>& nested, const std::string& owner_id,
                 std::size_t depth) {
    if (nested.empty()) return;
    if (depth + 1 > c.opts.limits.max_depth) {
        c.out.diagnostics.push_back(
            {Severity::Warning, "analyze-limit-depth",
             "nesting deeper than max_depth (" + dec(c.opts.limits.max_depth) + ") under " +
                 owner_id + "; " + dec(nested.size()) + " extracted file(s) were not re-scanned"});
        return;
    }
    for (const Descend& d : nested) descend_into_file(c, d, depth);
}

// Open + walk one filesystem finding whose node is already in the graph, then
// re-scan every file it extracted (`depth` is the level `span` sits at).
void process_filesystem(Ctx& c, const Span& span, const Finding& f, const std::string& fs_id,
                        std::size_t depth) {
    std::vector<Diagnostic> diags;
    std::vector<Descend> nested;
    std::map<std::string, std::string> attrs;
    std::optional<std::uint64_t> new_length;

    std::unique_ptr<fs::FilesystemReader> reader =
        c.opts.open_reader ? c.opts.open_reader(f.format) : nullptr;
    if (!reader) {
        set_coverage(c, f.format, "unsupported", "no reader registered");
        diags.push_back({Severity::Warning, "analyze-no-reader",
                         "no " + f.format + " reader registered; not walked"});
    } else {
        const Span fs_span = f.size != 0 ? span.sub(f.offset, f.size) : span.sub(f.offset);
        if (Status st = reader->open(fs_span); !st) {
            set_coverage(c, f.format, "partial",
                         "open failed at " + hex(span.absolute(f.offset)) + ": " + st.error);
            diags.push_back({Severity::Error, "analyze-open-failed",
                             f.format + " reader rejected the structure: " + st.error});
        } else {
            const fs::FilesystemInfo info = reader->info();
            if (!info.label.empty()) attrs["label"] = sanitize_utf8(info.label);
            if (info.block_size != 0) attrs["block_size"] = dec(info.block_size);
            if (!info.compression.empty()) attrs["compression"] = info.compression;
            for (const auto& [k, v] : info.attrs) attrs.emplace(k, v);
            if (f.size == 0 && info.size != 0)
                new_length = std::min<std::uint64_t>(info.size, fs_span.size());

            Limits limits = c.opts.limits;
            limits.max_files =
                c.files_used >= limits.max_files ? 0 : limits.max_files - c.files_used;
            limits.max_bytes =
                c.bytes_used >= limits.max_bytes ? 0 : limits.max_bytes - c.bytes_used;
            if (limits.max_files == 0) {
                set_coverage(c, f.format, "partial",
                             "run-wide max_files reached before this filesystem");
                diags.push_back({Severity::Warning, "analyze-limit-files",
                                 "run-wide max_files reached; filesystem not walked"});
                attrs["truncated"] = "true";
            } else {
                const WalkFn do_walk = [&reader](Sink& sink, const fs::WalkOptions& wo,
                                                 fs::WalkResult& wr) {
                    return reader->walk(sink, wo, wr);
                };
                WalkOutcome w = walk_into_sink(c, do_walk, "filesystems", fs_id, limits);
                if (!w.sink_error.empty()) {
                    set_coverage(c, f.format, "partial", w.sink_error);
                    diags.push_back({Severity::Error, "analyze-sink-failed", w.sink_error});
                } else {
                    c.files_used = sat_add(c.files_used, w.files);
                    c.bytes_used = sat_add(c.bytes_used, w.bytes);
                    const fs::WalkResult& r = w.result;
                    attrs["entries"] = dec(r.entries);
                    attrs["files"] = dec(r.files);
                    attrs["dirs"] = dec(r.dirs);
                    attrs["symlinks"] = dec(r.symlinks);
                    attrs["others"] = dec(r.others);
                    attrs["bytes"] = dec(r.bytes);
                    if (c.opts.history) {
                        attrs["superseded"] = dec(r.superseded);
                        attrs["deleted"] = dec(r.deleted);
                    }
                    if (r.truncated) attrs["truncated"] = "true";
                    for (const Diagnostic& d : r.diagnostics) diags.push_back(d);
                    if (!w.status) {
                        set_coverage(c, f.format, "partial",
                                     "walk failed at " + hex(span.absolute(f.offset)) + ": " +
                                         w.status.error);
                        diags.push_back({Severity::Error, "analyze-walk-failed", w.status.error});
                    } else if (r.truncated) {
                        set_coverage(c, f.format, "partial",
                                     "a limit stopped the walk at " + hex(span.absolute(f.offset)));
                    } else {
                        set_coverage(c, f.format, "supported", "");
                    }
                    const Node fs_copy = *c.out.find(fs_id);  // add_node may reallocate
                    nested = add_file_nodes(c, fs_id, fs_copy, r.entries_out);
                    c.listings.emplace_back(fs_id, r.entries_out);
                }
            }
        }
    }

    if (Node* fs_node = c.out.find(fs_id)) {
        for (const auto& [k, v] : attrs) fs_node->attrs[k] = v;
        if (new_length) fs_node->location.length = *new_length;
        for (Diagnostic& d : diags) fs_node->diagnostics.push_back(std::move(d));
    }

    descend_all(c, nested, fs_id, depth);
}

// Open + walk one container finding whose node is already in the graph. Same
// shape as process_filesystem: the two differ only in the reader interface and
// in the facts info() carries.
void process_container(Ctx& c, const Span& span, const Finding& f, const std::string& id,
                       std::size_t depth) {
    std::vector<Diagnostic> diags;
    std::map<std::string, std::string> attrs;
    std::optional<std::uint64_t> new_length;
    std::vector<Descend> nested;

    std::unique_ptr<container::ContainerReader> reader =
        c.opts.open_container ? c.opts.open_container(f.format) : nullptr;
    if (!reader) {
        // Rule 7: a container we recognise but do not open is a Coverage row
        // and a Diagnostic, never a silent node.
        set_coverage(c, f.format, "unsupported", "no container reader registered");
        diags.push_back({Severity::Warning, "analyze-no-reader",
                         "no " + f.format + " container reader registered; payload not opened"});
    } else if (attr_or(f.attrs, "extent", "") == "unknown" ||
               (f.category == "compressed" && f.size == 0)) {
        // Two ways of knowing the reader has nothing to do.
        //
        // The validator walked this structure and could not find its end: a
        // deflate stream that does not decode, a tar with no end-of-archive
        // block, a cpio with no trailer, a boot header with an impossible
        // version. It says so with `extent: unknown`. The reader would repeat
        // exactly that work and fail the same way, because the validator's
        // probe *is* the reader's parse.
        //
        // Or a compressed-stream validator rejected the header before it got
        // as far as probing -- a gzip whose OS byte is not a defined value,
        // an xz whose flags CRC is wrong. Those leave the finding at Magic
        // with no extent and no marker, and they are the common case: a
        // speech-data blob in the corpus holds thousands of byte runs that
        // start 1f 8b 08. No extent on a compressed finding means no stream,
        // whichever way the validator reached that conclusion.
        //
        // Trying anyway is not free. On the QNX corpus 91 "ustar" strings sit
        // inside binary data; opening each one produced an empty walk and
        // dragged the whole format's coverage row to "partial" while real
        // archives elsewhere read fine. The node keeps the validator's note
        // ("tar-no-end-marker" and friends), which says what happened, and
        // coverage stays silent because nothing was attempted.
        //
        // Formats whose validator does not size at all (zip, 7z: magic only)
        // never set the attr, so a reader for them still gets its chance.
    } else {
        // A compressed stream is always opened on the rest of the parent, even
        // when the validator measured it: its decoder is what finds the end,
        // and it is the same decode the validator's probe ran. Clamping to the
        // measured size can only disagree with it, and on the QNX corpus 17
        // streams did -- a member whose measured length was an underestimate
        // got a short window and failed with "decompress-corrupt" after the
        // validator had read it fine. Everything else is given exactly the
        // extent its validator claimed.
        const Span c_span = (f.size != 0 && f.category != "compressed") ? span.sub(f.offset, f.size)
                                                                        : span.sub(f.offset);
        if (Status st = reader->open(c_span); !st) {
            set_coverage(c, f.format, "partial",
                         "open failed at " + hex(span.absolute(f.offset)) + ": " + st.error);
            diags.push_back({Severity::Error, "analyze-open-failed",
                             f.format + " container reader rejected the structure: " + st.error});
        } else {
            Limits limits = c.opts.limits;
            limits.max_files =
                c.files_used >= limits.max_files ? 0 : limits.max_files - c.files_used;
            limits.max_bytes =
                c.bytes_used >= limits.max_bytes ? 0 : limits.max_bytes - c.bytes_used;
            if (limits.max_files == 0) {
                set_coverage(c, f.format, "partial",
                             "run-wide max_files reached before this container");
                diags.push_back({Severity::Warning, "analyze-limit-files",
                                 "run-wide max_files reached; container not opened"});
                attrs["truncated"] = "true";
            } else {
                const WalkFn do_walk = [&reader](Sink& sink, const fs::WalkOptions& wo,
                                                 fs::WalkResult& wr) {
                    return reader->walk(sink, wo, wr);
                };
                WalkOutcome w = walk_into_sink(c, do_walk, "containers", id, limits);
                if (!w.sink_error.empty()) {
                    set_coverage(c, f.format, "partial", w.sink_error);
                    diags.push_back({Severity::Error, "analyze-sink-failed", w.sink_error});
                } else {
                    c.files_used = sat_add(c.files_used, w.files);
                    c.bytes_used = sat_add(c.bytes_used, w.bytes);
                    // info() is read after the walk: a stream reader only knows
                    // where the stream ended once it has decoded it, and that
                    // extent is what the validator could not supply.
                    const container::ContainerInfo info = reader->info();
                    if (!info.compression.empty()) attrs["compression"] = info.compression;
                    for (const auto& [k, v] : info.attrs) attrs.emplace(k, v);
                    if (f.size == 0 && info.size != 0)
                        new_length = std::min<std::uint64_t>(info.size, c_span.size());

                    const fs::WalkResult& r = w.result;
                    attrs["entries"] = dec(r.entries);
                    attrs["files"] = dec(r.files);
                    attrs["bytes"] = dec(r.bytes);
                    if (r.truncated) attrs["truncated"] = "true";
                    for (const Diagnostic& d : r.diagnostics) diags.push_back(d);
                    if (!w.status) {
                        set_coverage(c, f.format, "partial",
                                     "walk failed at " + hex(span.absolute(f.offset)) + ": " +
                                         w.status.error);
                        diags.push_back({Severity::Error, "analyze-walk-failed", w.status.error});
                    } else if (r.truncated) {
                        set_coverage(c, f.format, "partial",
                                     "a limit stopped the walk at " + hex(span.absolute(f.offset)));
                    } else {
                        set_coverage(c, f.format, "supported", "");
                    }
                    const Node copy = *c.out.find(id);  // add_node may reallocate
                    nested = add_file_nodes(c, id, copy, r.entries_out);
                    c.listings.emplace_back(id, r.entries_out);
                }
            }
        }
    }

    if (Node* n = c.out.find(id)) {
        for (const auto& [k, v] : attrs) n->attrs[k] = v;
        if (new_length) n->location.length = *new_length;
        for (Diagnostic& d : diags) n->diagnostics.push_back(std::move(d));
    }
    descend_all(c, nested, id, depth);
}

// ------------------------------------------------------------------ regions

// "0xff" / "0x00" when every byte of [off, off+len) is that value; empty otherwise.
std::string uniform_fill(const Span& span, std::uint64_t off, std::uint64_t len) {
    if (len == 0) return {};
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(std::min<std::uint64_t>(len, 1u << 20)));
    std::optional<std::uint8_t> fill;
    std::uint64_t done = 0;
    while (done < len) {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(buf.size(), len - done));
        const std::size_t got = span.read(off + done, std::span<std::uint8_t>(buf.data(), want));
        if (got == 0) return {};
        if (!fill) fill = buf[0];
        for (std::size_t i = 0; i < got; ++i)
            if (buf[i] != *fill) return {};
        done += got;
    }
    return *fill == 0xFF ? "0xff" : *fill == 0x00 ? "0x00" : hex(*fill);
}

// A number with three decimals, for the entropy attrs. std::to_string gives
// six and they are all noise at this precision.
std::string bits_text(double v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.3f", v);
    return buf;
}

Node gap_node(const Span& span, std::uint64_t off, std::uint64_t len,
              const std::string& parent_id) {
    Node n;
    n.kind = NodeKind::Region;
    n.parent_id = parent_id;
    n.name = "unidentified";
    n.location = {span.source_id(), span.absolute(off), len};
    n.confidence = 0;
    n.evidence = "no signature matched";
    n.diagnostics.push_back(
        {Severity::Info, "region-unidentified", "no signature matched in " + dec(len) + " bytes"});

    // "Unidentified" on its own tells an examiner nothing, and an image is
    // mostly regions. What the bytes look like statistically is the difference
    // between erased flash they can ignore and a payload they cannot read.
    //
    // uniform_fill first: it reads the whole region, but bails on the first
    // byte that differs, so it is cheap for everything that is not fill -- and
    // when it does hold it is an exact claim about every byte, which a sampled
    // profile could not make.
    const std::string fill = uniform_fill(span, off, len);
    if (!fill.empty()) {
        n.attrs["fill"] = fill;
        n.attrs["entropy"] = "0.000";
        n.attrs["entropy_class"] = entropy::class_name(entropy::Class::Erased);
        return n;
    }
    const entropy::Profile e = entropy::profile(span, off, len);
    if (e.klass == entropy::Class::Unknown) return n;  // too few bytes to say
    n.attrs["entropy"] = bits_text(e.mean);
    n.attrs["entropy_class"] = entropy::class_name(e.klass);
    n.attrs["entropy_chi2"] = bits_text(e.chi_square);
    // Only the two high-entropy classes get a diagnostic. Text and binary
    // regions are ordinary and saying so on every one of them would be noise.
    if (e.klass == entropy::Class::Random || e.klass == entropy::Class::Packed) {
        n.diagnostics.push_back(
            {Severity::Info, "region-high-entropy",
             dec(len) + " bytes at " + bits_text(e.mean) + " bits/byte (" +
                 entropy::class_name(e.klass) + "): " + entropy::class_meaning(e.klass) +
                 ". No signature matched, so it is either a format this build does not know, a "
                 "headerless compressed stream, or ciphertext"});
    }
    return n;
}

// Bytes a structure starting at offset 0 must present for any builtin
// signature to match there: the farthest magic end. A partition whose first
// that-many bytes are one repeated value cannot hold a finding at its start.
std::uint64_t leading_magic_reach() {
    static const std::uint64_t reach = [] {
        std::uint64_t r = 1;
        for (const Signature& s : SignatureSet::builtin().signatures)
            r = std::max(r, sat_add(s.magic_offset, s.magic.size()));
        return r;
    }();
    return reach;
}

// ---------------------------------------------------------------- the pass

// Something to turn into a node, keyed by offset so nodes appear in byte order.
struct Item {
    std::uint64_t offset = 0;
    bool is_gap = false;
    std::size_t finding = 0;  // index into findings when !is_gap
    std::uint64_t gap_len = 0;
    std::string gap_parent;  // partition id, or empty for the span's parent
};

// [off, off+len) minus every range in `claims`, in order. Used to report a gap
// against the extents as they stand after the readers ran.
std::vector<Claim> subtract_claims(std::uint64_t off, std::uint64_t len,
                                   std::vector<Claim> claims) {
    std::vector<Claim> out;
    const std::uint64_t end = sat_add(off, len);
    std::sort(claims.begin(), claims.end(),
              [](const Claim& a, const Claim& b) { return a.offset < b.offset; });
    std::uint64_t cursor = off;
    for (const Claim& cl : claims) {
        if (cl.end <= cursor || cl.offset >= end) continue;
        if (cl.offset > cursor) out.push_back({cursor, std::min(cl.offset, end)});
        cursor = std::max(cursor, cl.end);
        if (cursor >= end) break;
    }
    if (cursor < end) out.push_back({cursor, end});
    return out;
}

// Gaps between merged claims, reported to `items` under `parent`.
void note_gaps(const Ctx& c, std::vector<Claim> claims, std::uint64_t from, std::uint64_t to,
               const std::string& parent, std::vector<Item>& items) {
    std::sort(claims.begin(), claims.end(), [](const Claim& a, const Claim& b) {
        return a.offset != b.offset ? a.offset < b.offset : a.end > b.end;
    });
    std::uint64_t cursor = from;
    auto gap = [&](std::uint64_t a, std::uint64_t b) {
        if (b > a && b - a >= c.opts.min_region_bytes) items.push_back({a, true, 0, b - a, parent});
    };
    for (const Claim& cl : claims) {
        if (cl.offset > cursor) gap(cursor, cl.offset);
        cursor = std::max(cursor, cl.end);
    }
    gap(cursor, to);
}

// Analyze one Span whose bytes belong to `parent_id`, with `findings` already
// scanned from it. `descend_into_file` calls this for an extracted file that
// is itself an image; Container payloads will use it too.
void analyze_span(Ctx& c, const Span& span, const std::string& parent_id, std::size_t depth,
                  std::vector<Finding> findings) {
    if (depth > c.opts.limits.max_depth) {
        c.out.diagnostics.push_back({Severity::Warning, "analyze-limit-depth",
                                     "nesting deeper than max_depth (" +
                                         dec(c.opts.limits.max_depth) + ") under " + parent_id});
        return;
    }
    bool any_gpt = false;
    for (const Finding& f : findings)
        any_gpt = any_gpt || (f.category == "partition-table" && f.format == "gpt");

    // Pass 1: partition tables become nodes first; they are the map.
    std::vector<Claim> top_claims;
    std::vector<PartInfo> parts;
    for (const TableUse& use : choose_tables(findings)) {
        const Finding& f = findings[use.finding];
        // A table that starts inside an entry of a table already used at this
        // level (an MBR sector stored as file data in a GPT partition, a disk
        // image inside a filesystem) describes some other disk: keep it as a
        // table node with no entries instead of a second partition map.
        std::string enclosing;
        for (const PartInfo& p : parts)
            if (!p.protective && f.offset >= p.start && f.offset < p.end) enclosing = p.index;
        if (!enclosing.empty()) {
            Node n =
                node_from_finding(f, span, parent_for(c, f.offset, parent_id), NodeKind::Partition);
            n.name = f.format + " partition table";
            n.attrs["role"] = "table";
            n.attrs["table"] = use.role;
            n.attrs["nested"] = "true";
            n.diagnostics.push_back({Severity::Info, "partition-table-nested",
                                     f.format + " table at " + hex(span.absolute(f.offset)) +
                                         " lies inside partition " + enclosing +
                                         "; its entries describe another disk and were not "
                                         "expanded"});
            c.out.add_node(std::move(n));
            continue;
        }
        std::vector<Diagnostic> part_diags;
        const std::vector<PartSpec> specs = parse_partitions(f, part_diags);
        top_claims.push_back(
            {f.offset, std::min(sat_add(f.offset, table_metadata_bytes(f)), span.size())});

        Node n =
            node_from_finding(f, span, parent_for(c, f.offset, parent_id), NodeKind::Partition);
        n.name = f.format + " partition table";
        n.attrs["role"] = "table";
        n.attrs["table"] = use.role;
        for (Diagnostic& d : part_diags) n.diagnostics.push_back(std::move(d));
        if (use.folded_backup) {
            const Finding& b = findings[*use.folded_backup];
            const std::uint64_t sector =
                parse_u64(attr_or(b.attrs, "sector_size", "512")).value_or(512);
            const std::string lba = attr_or(b.attrs, "my_lba", "");
            n.attrs["backup_lba"] = !lba.empty() ? lba : dec(b.offset / (sector ? sector : 512));
            n.attrs["backup_offset"] = hex(span.absolute(b.offset));
            if (!has_diag(b.diagnostics, "gpt-header-crc-mismatch")) {
                n.attrs["backup_header"] = "ok";
            } else {
                n.attrs["backup_header"] = "crc-mismatch";
                n.diagnostics.push_back({Severity::Warning, "gpt-backup-crc-mismatch",
                                         "backup GPT header at " + hex(span.absolute(b.offset)) +
                                             " has a CRC mismatch"});
            }
            top_claims.push_back({b.offset, end_of(b, span)});
        }
        if (use.role == "gpt-backup") {
            // Only the backup survived: the primary at LBA 1 is gone, or it
            // describes another disk (attrs primary=mismatch). Say so on the
            // image, where an examiner looks first, and in Coverage (rule 7:
            // a recovered table is never a silent success).
            Node* img = c.out.find(c.image_id);
            bool copied = false;
            for (const Diagnostic& d : f.diagnostics) {
                if (d.code != "gpt-primary-missing") continue;
                if (img) img->diagnostics.push_back(d);
                copied = true;
            }
            const bool stale = attr_or(f.attrs, "primary", "") == "mismatch";
            if (!copied) {
                const Diagnostic d{
                    Severity::Warning, stale ? "gpt-backup-mismatch" : "gpt-primary-missing",
                    std::string(stale ? "the primary GPT header describes a different disk or "
                                        "entry array; a second partition map was recovered "
                                        "from the backup header at "
                                      : "no primary GPT header; partitions recovered from the "
                                        "backup header at ") +
                        hex(span.absolute(f.offset))};
                n.diagnostics.push_back(d);
                if (img) img->diagnostics.push_back(d);
            }
            set_coverage(c, "gpt", "partial",
                         std::string(stale ? "stale backup header expanded at "
                                           : "primary header missing; partitions recovered from "
                                             "the backup header at ") +
                             hex(span.absolute(f.offset)));
        }
        const std::string table_id = c.out.add_node(std::move(n)).id;
        const std::uint64_t base = disk_base(f, use.role);

        for (const PartSpec& p : specs) {
            Node pn;
            pn.kind = NodeKind::Partition;
            pn.parent_id = table_id;
            pn.name = attr_or(p.attrs, "label", p.index);
            pn.format = f.format;
            const std::uint64_t start = sat_add(base, p.start);
            std::uint64_t length = p.size;
            pn.confidence = static_cast<std::uint8_t>(f.confidence);
            pn.evidence = f.format + " entry " + p.index;
            pn.attrs = p.attrs;
            pn.attrs["index"] = p.index;
            pn.attrs["table"] = use.role;
            PartInfo info;
            info.index = p.index;
            info.protective = f.format == "mbr" && any_gpt && p.attrs.count("type") &&
                              p.attrs.at("type") == "0xee";
            if (info.protective) {
                pn.attrs["protective"] = "true";
                pn.diagnostics.push_back({Severity::Info, "partition-protective",
                                          "protective MBR entry covering the GPT; the GPT "
                                          "entries are the partitions"});
            }
            if (start >= span.size()) {
                pn.location = {span.source_id(), span.absolute(std::min(start, span.size())), 0};
                pn.diagnostics.push_back({Severity::Warning, "partition-outside-image",
                                          "entry starts at " + hex(span.absolute(start)) +
                                              ", past the end of the data"});
                pn.confidence = static_cast<std::uint8_t>(Confidence::Magic);
                info.id = c.out.add_node(std::move(pn)).id;
                info.start = info.end = start;
                parts.push_back(std::move(info));
                continue;
            }
            if (length > span.size() - start) {
                pn.attrs["claimed_size"] = dec(length);
                length = span.size() - start;
                pn.diagnostics.push_back({Severity::Warning, "partition-truncated",
                                          "entry extends past the end of the data; clamped to " +
                                              dec(length) + " bytes"});
            }
            pn.location = {span.source_id(), span.absolute(start), length};
            info.id = c.out.add_node(std::move(pn)).id;
            info.start = start;
            info.end = info.protective ? start : start + length;
            if (!info.protective && length > 0) {
                c.extents.push_back({info.id, start, start + length});
                top_claims.push_back({start, start + length});
            }
            parts.push_back(std::move(info));
        }
    }

    // Pass 2: a partition with nothing at its first byte is scanned on its
    // own Span (a finding at offset 0 of the partition is kept).
    std::vector<Finding> rescanned;
    for (const PartInfo& p : parts) {
        if (p.protective || p.end <= p.start) continue;
        bool found = false;
        for (const Finding& f : findings) found = found || f.offset == p.start;
        if (found) continue;
        const std::uint64_t reach = std::min(leading_magic_reach(), p.end - p.start);
        if (!uniform_fill(span, p.start, reach).empty()) continue;  // erased/zero: nothing there
        for (Finding f : run_scanner(c, span.sub(p.start, p.end - p.start))) {
            if (f.offset != 0 || f.category == "partition-table") continue;
            f.offset = p.start;
            for (Finding& alt : f.also_matched) alt.offset = sat_add(alt.offset, p.start);
            f.diagnostics.push_back({Severity::Info, "partition-rescan",
                                     "found by scanning partition " + p.index +
                                         " on its own; the whole-image scan missed it"});
            rescanned.push_back(std::move(f));
        }
    }
    for (Finding& f : rescanned) findings.push_back(std::move(f));
    std::stable_sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.size > b.size;
    });

    // Pass 3: claims and gaps, at the top level and inside every partition.
    std::vector<Item> items;
    std::vector<std::vector<Claim>> part_claims(parts.size());
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const Finding& f = findings[i];
        if (f.category == "partition-table") continue;
        items.push_back({f.offset, false, i, 0, {}});
        if (f.size == 0) continue;  // unknown extent: claims nothing, splits no gap
        const std::uint64_t f_end = end_of(f, span);
        bool inside = false;
        for (std::size_t p = 0; p < parts.size(); ++p) {
            if (parts[p].protective || f.offset < parts[p].start || f.offset >= parts[p].end)
                continue;
            part_claims[p].push_back({f.offset, std::min(f_end, parts[p].end)});
            inside = true;
        }
        if (!inside) top_claims.push_back({f.offset, f_end});
    }
    note_gaps(c, top_claims, 0, span.size(), {}, items);
    for (std::size_t p = 0; p < parts.size(); ++p) {
        if (parts[p].protective || parts[p].end <= parts[p].start) continue;
        note_gaps(c, part_claims[p], parts[p].start, parts[p].end, parts[p].id, items);
    }
    std::stable_sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        return a.is_gap < b.is_gap;  // a finding at the same offset comes first
    });

    // Pass 4: nodes, in byte order.
    //
    // `resolved` holds each finding's extent as it stands *after* its reader
    // ran, which is not what pass 3 saw. A compressed stream has no extent
    // until the reader decodes it (the validator cannot know where a deflate
    // stream ends), so pass 3 treated its bytes as unclaimed and planned a gap
    // over them. Findings sort before gaps at the same offset, so by the time a
    // gap item comes up the container that owns those bytes has its real
    // length, and the gap is reported against that instead of over it.
    std::vector<Claim> resolved;
    for (const Item& it : items) {
        if (it.is_gap) {
            const std::string parent = it.gap_parent.empty() ? parent_id : it.gap_parent;
            for (const Claim& part : subtract_claims(it.offset, it.gap_len, resolved)) {
                const std::uint64_t len = part.end - part.offset;
                if (len >= c.opts.min_region_bytes)
                    c.out.add_node(gap_node(span, part.offset, len, parent));
            }
            continue;
        }
        const Finding& f = findings[it.finding];
        const std::uint64_t f_end = end_of(f, span);
        const std::string parent = parent_for(c, f.offset, parent_id);
        const NodeKind kind = kind_for(f);
        Node n = node_from_finding(f, span, parent, kind);
        const std::string id = c.out.add_node(std::move(n)).id;
        if (kind == NodeKind::Filesystem || kind == NodeKind::Container)
            c.extents.push_back({id, f.offset, f_end});
        if (kind == NodeKind::Filesystem) process_filesystem(c, span, f, id, depth);
        if (kind == NodeKind::Container) process_container(c, span, f, id, depth);
        // The reader may have given the node the extent the validator could
        // not (see `resolved` above).
        if (const Node* n = c.out.find(id); n != nullptr && n->location.length != 0) {
            const std::uint64_t end = std::min(sat_add(f.offset, n->location.length), span.size());
            if (end > f.offset) resolved.push_back({f.offset, end});
        }
    }
}

void analyze_span(Ctx& c, const Span& span, const std::string& parent_id, std::size_t depth) {
    analyze_span(c, span, parent_id, depth, run_scanner(c, span));
}

// ------------------------------------------------------------------ carving

constexpr std::size_t kCarveChunk = 8u << 20;  // I/O buffer, not a limit

// Stream the whole of `src` to `path`, hashing as it goes. Empty string on
// success, otherwise the reason (the partial file is removed). Reads in
// bounded chunks, so writing out a 15 GiB view costs one 8 MiB buffer.
std::string stream_span_to_file(const Span& src, const std::filesystem::path& path,
                                Digests& digests, bool& short_read) {
    short_read = false;
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return "cannot open '" + path.string() + "' for writing";
    Hasher h;
    std::vector<std::uint8_t> buf(
        static_cast<std::size_t>(std::min<std::uint64_t>(kCarveChunk, src.size())));
    std::uint64_t done = 0;
    while (done < src.size()) {
        const std::size_t got = src.read(done, std::span<std::uint8_t>(buf.data(), buf.size()));
        if (got == 0) {
            short_read = true;
            break;
        }
        f.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(got));
        if (!f) {
            f.close();
            std::error_code ec;
            std::filesystem::remove(path, ec);
            return "short write to '" + path.string() + "'";
        }
        h.update(std::span<const std::uint8_t>(buf.data(), got));
        done += got;
    }
    f.close();
    digests = h.finish();
    return {};
}

// Stream [node.location] of `whole` to `path`.
std::string carve_bytes(const Span& whole, const Node& n, const std::filesystem::path& path,
                        Digests& digests, bool& short_read) {
    return stream_span_to_file(whole.sub(n.location.offset, n.location.length), path, digests,
                               short_read);
}

// The same, for a find whose offsets are into an extracted file rather than
// into the evidence: a region inside a decompressed payload has its own
// `location.source`, and the image Span cannot reach it.
//
// The open is cached because one payload can hold hundreds of them -- the
// dongle dongle's xz payload is 222 shared objects, and opening a 23 MB file
// once per object would be 222 maps of the same bytes.
std::string carve_bytes_from(std::shared_ptr<MappedFile>& cached, std::string& cached_path,
                             const Node& n, const std::filesystem::path& path, Digests& digests,
                             bool& short_read) {
    // `source_id` is the path for an extracted file (a word-swapped view is
    // the only one that carries a "|..." suffix, and those are never here).
    if (cached_path != n.location.source_id || !cached) {
        std::shared_ptr<MappedFile> f;
        if (Status st = MappedFile::open(n.location.source_id, f); !st) return st.error;
        cached = std::move(f);
        cached_path = n.location.source_id;
    }
    return stream_span_to_file(Span::whole(cached).sub(n.location.offset, n.location.length), path,
                               digests, short_read);
}

// The corrected view's file name: the evidence's stem, the transform that was
// undone, and .bin -- the same "-swap32" tag carved files already carry
// (carved_file_name below).
std::string corrected_view_name(const std::string& evidence_path, const std::string& transform) {
    std::string stem =
        safe_filename_component(std::filesystem::path(basename_of(evidence_path)).stem().string());
    if (stem.empty()) stem = "image";
    return stem + "-" + transform + ".bin";
}

// Write the view the analysis runs on, when that view is not the evidence.
//
// A word-swapped image is analysed through a SwappedSource, so every offset in
// the manifest, and every byte of every carved file, belongs to a rendering
// that exists only in memory. Recording that the image was corrected and then
// writing nothing leaves the examiner unable to act on any of it: they cannot
// re-run binwalk, loop-mount a partition or hand the image to a vendor tool
// without reproducing the swap themselves. Returns the case-relative path, or
// "" when nothing was written.
std::string write_corrected_view(const AnalyzeOptions& opts, const Span& view,
                                 const std::string& evidence_path, const std::string& transform,
                                 Node& n) {
    if (!opts.write_corrected_view || opts.out_dir.empty()) return {};
    if (view.size() > opts.max_carve_bytes) {
        n.attrs["corrected_skipped"] = "max-carve-bytes";
        n.diagnostics.push_back({Severity::Warning, "image-corrected-view-limit",
                                 "the " + transform + " view is " + dec(view.size()) +
                                     " bytes, over --max-carve-bytes (" +
                                     dec(opts.max_carve_bytes) +
                                     "); it was not written, so nothing on disk holds the bytes "
                                     "the offsets in this manifest refer to"});
        return {};
    }
    const std::filesystem::path dir = std::filesystem::path(opts.out_dir) / "flash";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        n.diagnostics.push_back({Severity::Error, "image-corrected-view-failed",
                                 "cannot create '" + dir.string() + "': " + ec.message()});
        return {};
    }
    const std::string name = corrected_view_name(evidence_path, transform);
    Digests d;
    bool short_read = false;
    const std::string why = stream_span_to_file(view, dir / name, d, short_read);
    if (!why.empty()) {
        n.diagnostics.push_back({Severity::Error, "image-corrected-view-failed", why});
        return {};
    }
    const std::string rel = "flash/" + name;
    n.attrs["corrected_path"] = rel;
    n.attrs["corrected_sha256"] = d.sha256;
    // The id every offset in this manifest is relative to. A later pass that
    // re-opens the file above gets a *different* Source id -- the path it was
    // written to -- so without this recorded there is nothing to match the
    // regions against. rules::sweep skipped every region on a word-swapped
    // image for exactly that reason, and said only "0 regions scanned".
    n.attrs["corrected_source_id"] = view.source_id();
    if (short_read)
        n.diagnostics.push_back({Severity::Warning, "image-corrected-view-short",
                                 "the evidence stopped returning bytes before its size while the " +
                                     transform + " view was written; " + rel + " is short"});
    n.diagnostics.push_back(
        {Severity::Info, "image-corrected-view",
         "the analysis ran on the " + transform + " view of the image, written to " + rel +
             " (sha256 " + d.sha256 +
             "); every offset in this manifest that is relative to the image is an offset into "
             "that file, not into the evidence"});
    return rel;
}

// The GPT label / index name of a partition entry node, or the offset-format
// name of a nested find, made safe for every host and unique in `used`.
std::string carved_file_name(const Node& n, bool is_entry, std::set<std::string>& used,
                             const std::string& owner_id) {
    std::string stem;
    if (!owner_id.empty()) {
        // A find inside an extracted file: its offset is into that file, so
        // two payloads both hold something at 0x7908. Naming the owning node
        // keeps them apart and says which file to look in.
        stem = owner_id + "-" + hex08(n.location.offset) + "-" + n.format;
    } else if (is_entry) {
        stem = attr_or(n.attrs, "index", "p");
        std::string label = attr_or(n.attrs, "label", "");
        for (char& ch : label)
            if (ch == ' ' || ch == '\t') ch = '_';
        if (!label.empty()) stem += "-" + label;
    } else {
        stem = hex08(n.location.offset) + "-" + n.format;
    }
    // Bytes carved from a word-swapped view are the corrected bytes; say so
    // in the name (source id "<image>|swap16" or "<image>|swap32").
    const std::size_t bar = n.location.source_id.find_last_of('|');
    if (bar != std::string::npos) {
        const std::string tag = n.location.source_id.substr(bar + 1);
        if (tag == "swap16" || tag == "swap32") stem += "-" + tag;
    }
    stem = safe_filename_component(stem);
    std::string name = stem + ".bin";
    for (std::uint64_t k = 2; !used.insert(name).second; ++k) name = stem + "~" + dec(k) + ".bin";
    return name;
}

// Post-pass over the finished graph: carve partition entries and nested finds
// into <out_dir>/partitions/, then write mount.sh.
void carve_all(Ctx& c, const Span& whole) {
    if (c.opts.carve == Carve::None || c.opts.out_dir.empty()) return;
    const std::filesystem::path dir = std::filesystem::path(c.opts.out_dir) / "partitions";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        const std::string why = "cannot create '" + dir.string() + "': " + ec.message();
        carve_partial(c, why);
        c.out.diagnostics.push_back({Severity::Error, "carve-dir-failed", why});
        return;
    }

    std::set<std::string> used;
    std::shared_ptr<MappedFile> sub_source;  // the extracted file a sub-range is carved from
    std::string sub_source_path;
    std::vector<std::string> ids;
    for (const Node& n : c.out.nodes()) ids.push_back(n.id);
    bool any_ok = false;
    for (const std::string& id : ids) {
        Node* n = c.out.find(id);
        if (!n) continue;
        bool is_entry = false;
        bool sub_file = false;
        if (n->kind == NodeKind::Partition) {
            if (attr_or(n->attrs, "role", "") == "table") continue;
            if (attr_or(n->attrs, "protective", "") == "true") continue;
            if (has_diag(n->diagnostics, "partition-outside-image")) continue;
            is_entry = true;
        } else {
            if (c.opts.carve != Carve::All) continue;
            if (n->kind != NodeKind::Filesystem && n->kind != NodeKind::Container &&
                n->kind != NodeKind::Region)
                continue;
            if (n->format.empty()) continue;  // an unidentified gap, not a find
            const Node* parent = c.out.find(n->parent_id);
            if (!parent) continue;
            if (parent->kind == NodeKind::Partition) {
                if (parent->location.offset == n->location.offset) {
                    // The partition file is this filesystem's carve.
                    const std::string in = attr_or(parent->attrs, "carved_path", "");
                    if (!in.empty()) n->attrs["carved_in"] = in;
                    continue;
                }
            } else if (parent->kind == NodeKind::File) {
                // A find inside an *extracted file* is reachable through that
                // file only when it is the whole of it. A strict sub-range is
                // not: the dongle dongle's xz payload is one 23 MB file
                // holding 222 complete ARM shared objects, and until they were
                // carved they had no digests at all -- located, sized and
                // typed, but impossible to match against a known-file set or
                // cite in a report. `docs/formats/elf.md` has the reasoning.
                //
                // "The whole of it" has to be measured against the file's own
                // size. A File node's `location` is a position in the
                // *enclosing* structure -- for a file inside a filesystem its
                // `length` is the filesystem's -- so comparing against that
                // made every whole-file find look like a sub-range and carved
                // a byte-identical second copy of 52 tarballs and 52 gzips out
                // of one router image.
                const std::uint64_t file_size =
                    parent->file ? parent->file->size : parent->digests.bytes;
                if (n->location.offset == 0 && file_size != 0 && n->location.length >= file_size) {
                    continue;
                }
                sub_file = true;
            } else if (parent->kind != NodeKind::Image) {
                continue;  // inside a filesystem/container: reachable through its extraction
            }
        }
        if (n->location.length == 0) {
            n->diagnostics.push_back(
                {Severity::Info, "carve-unknown-size", "extent unknown; not carved"});
            continue;
        }
        const std::string name =
            carved_file_name(*n, is_entry, used, sub_file ? n->parent_id : std::string{});
        if (n->location.length > c.opts.max_carve_bytes) {
            const std::string why = name + " skipped: " + dec(n->location.length) +
                                    " exceeds --max-carve-bytes (" + dec(c.opts.max_carve_bytes) +
                                    ")";
            carve_partial(c, why);
            n->diagnostics.push_back({Severity::Warning, "carve-limit-bytes", why});
            n->attrs["carve_skipped"] = "max-carve-bytes";
            continue;
        }
        // Carving has no run-wide byte budget -- `max_carve_bytes` is per
        // file -- so the disk is the only thing bounding it. 47 partitions of
        // a UFS LUN come to 116 GiB and every one of them is under the 4 GiB
        // per-file default. The query is re-run per node rather than once,
        // because each carve is what changes the answer.
        if (const std::optional<std::uint64_t> now = available_bytes(dir)) {
            if (n->location.length > disk_headroom(*now)) {
                const std::string why = name + " skipped: " + dec(n->location.length) +
                                        " bytes with only " + dec(*now) +
                                        " free on the output "
                                        "filesystem";
                carve_partial(c, why);
                n->diagnostics.push_back({Severity::Warning, "carve-limit-disk", why});
                n->attrs["carve_skipped"] = "disk-space";
                continue;
            }
        }
        Digests d;
        bool short_read = false;
        const std::string err =
            sub_file ? carve_bytes_from(sub_source, sub_source_path, *n, dir / name, d, short_read)
                     : carve_bytes(whole, *n, dir / name, d, short_read);
        if (!err.empty()) {
            carve_partial(c, name + ": " + err);
            n->diagnostics.push_back({Severity::Error, "carve-write-failed", err});
            continue;
        }
        n->digests = d;
        n->attrs["carved_path"] = "partitions/" + name;
        if (short_read) {
            const std::string why =
                name + " short: " + dec(d.bytes) + " of " + dec(n->location.length) + " bytes";
            carve_partial(c, why);
            n->diagnostics.push_back({Severity::Warning, "carve-short-read", why});
            n->attrs["truncated"] = "true";
        } else {
            any_ok = true;
        }
    }
    if (any_ok) set_coverage(c, "carve", "supported", "");

    const std::filesystem::path script = dir / "mount.sh";
    std::ofstream f(script, std::ios::binary | std::ios::trunc);
    const std::string text = mount_script_text(c.out);
    if (f) f.write(text.data(), static_cast<std::streamsize>(text.size()));
    if (!f) {
        const std::string why = "cannot write '" + script.string() + "'";
        carve_partial(c, why);
        c.out.diagnostics.push_back({Severity::Error, "carve-mount-script-failed", why});
        return;
    }
    f.close();
    std::filesystem::permissions(script,
                                 std::filesystem::perms::owner_exec |
                                     std::filesystem::perms::group_exec |
                                     std::filesystem::perms::others_exec,
                                 std::filesystem::perm_options::add, ec);  // best effort
}

}  // namespace

// ------------------------------------------------------------------- public

const char* carve_name(Carve c) {
    switch (c) {
        case Carve::None:
            return "none";
        case Carve::Table:
            return "table";
        case Carve::All:
            return "all";
    }
    return "all";
}

std::string mount_type_for(const std::string& format) {
    if (format == "ext2" || format == "ext3" || format == "ext4" || format == "ext") return "ext4";
    if (format == "squashfs") return "squashfs";
    if (format == "qnx6") return "qnx6";
    if (format == "fat" || format == "fat12" || format == "fat16" || format == "fat32")
        return "vfat";
    if (format == "exfat") return "exfat";
    if (format == "ntfs") return "ntfs3";
    if (format == "cramfs") return "cramfs";
    if (format == "romfs") return "romfs";
    return {};
}

std::string mount_script_text(const Manifest& m) {
    // (file name, filesystem format) for every carved file that holds a
    // filesystem at its first byte.
    std::vector<std::pair<std::string, std::string>> mountable, mtd;
    for (const Node& n : m.nodes()) {
        const std::string path = attr_or(n.attrs, "carved_path", "");
        if (path.empty()) continue;
        std::string format;
        if (n.kind == NodeKind::Filesystem) {
            format = n.format;
        } else if (n.kind == NodeKind::Partition) {
            for (const Node* ch : m.children_of(n.id))
                if (ch->kind == NodeKind::Filesystem && ch->location.offset == n.location.offset) {
                    format = ch->format;
                    break;
                }
        }
        if (format.empty()) continue;
        const std::string file = basename_of(path);
        const std::string type = mount_type_for(format);
        if (!type.empty())
            mountable.emplace_back(file, type);
        else if (format == "jffs2" || format == "ubifs" || format == "yaffs2")
            mtd.emplace_back(file, format);
    }
    auto quoted = [](const std::string& s) {
        std::string q = "\"";
        for (const char ch : s) {
            if (ch == '"' || ch == '\\' || ch == '$' || ch == '`') q.push_back('\\');
            q.push_back(ch);
        }
        return q + "\"";
    };
    std::string names, types;
    for (const auto& [file, type] : mountable) {
        if (!names.empty()) {
            names += ' ';
            types += ' ';
        }
        names += quoted(file);
        types += quoted(type);
    }

    std::string s;
    s += "#!/bin/bash\n";
    s += "# Generated by omnitrace from the examiner's mount template. Mounts every\n";
    s += "# carved partition in this directory that holds a loop-mountable filesystem.\n";
    s += "# Directory to directly mount partitions\n";
    s += "MOUNT_DIR=\"mounts\"\n";
    s += "# Directory to place tarballs of mounted filesystems\n";
    s += "FSDIR=\"filesystems\"\n";
    s += "# Carved files that hold a filesystem, in image order\n";
    s += "PARTITION_NAMES=(" + names + ")\n";
    s += "# The mount -t type for each entry above\n";
    s += "PARTITION_TYPES=(" + types + ")\n";
    if (!mtd.empty()) {
        s += "#\n";
        s += "# Flash filesystems below cannot be loop-mounted; attach them to an MTD\n";
        s += "# device first (sizes in KiB; erase size must match the image):\n";
        s += "#   jffs2:  modprobe mtdram total_size=<KiB> erase_size=<KiB>\n";
        s += "#           modprobe mtdblock; dd if=<file> of=/dev/mtdblock0\n";
        s += "#           mount -t jffs2 /dev/mtdblock0 <dir>\n";
        s += "#   ubifs:  modprobe nandsim ...; ubiformat /dev/mtd0 -f <file>\n";
        s += "#           ubiattach -m 0; mount -t ubifs ubi0:<volume> <dir>\n";
        s += "#   yaffs2: modprobe nandsim ...; nandwrite -o /dev/mtd0 <file>\n";
        s += "#           mount -t yaffs2 /dev/mtdblock0 <dir>\n";
        for (const auto& [file, format] : mtd) s += "#   " + file + ": " + format + "\n";
    }
    s += "\n";
    s += "help()\n{\n";
    s += "\techo \"Generic Mount Script\"\n";
    s += "\techo \"  This script will attempt to mount the partitions in this folder\"\n";
    s += "\techo \"  Arguments: -m -u -h -t\"\n";
    s += "\techo \"  Example: ./mount.sh -m\"\n";
    s += "\techo \"  The example above will attempt to mount the partitions locally\"\n";
    s += "\techo \"  Example: ./mount.sh -u\"\n";
    s += "\techo \"  The example above will attempt to unmount the partitions locally\"\n";
    s += "\techo \"  Example: ./mount.sh -t\"\n";
    s += "\techo \"  The example above will attempt to generate tarballs for mounted "
         "filesystems\"\n";
    s += "}\n\n";
    s += "check_mount_dir()\n{\n";
    s += "\techo \"Checking for mount directory\"\n";
    s += "\tif test -d \"$MOUNT_DIR\"; then\n";
    s += "\t\techo \"Mount directory exists, attempting to mount partitions\"\n";
    s += "\telse\n";
    s += "\t\techo \"Creating mount directory: $MOUNT_DIR\"\n";
    s += "\t\tmkdir \"$MOUNT_DIR\"\n";
    s += "\tfi\n";
    s += "}\n\n";
    s += "check_partition_folders()\n{\n";
    s += "    for part in \"${!PARTITION_NAMES[@]}\"\n    do\n";
    s += "        if test -d \"$MOUNT_DIR/${PARTITION_NAMES[$part]}\"; then\n";
    s += "            echo \"Mount directory exists for partition: ${PARTITION_NAMES[$part]}\"\n";
    s += "        else\n";
    s += "            echo \"Creating mount directory for partition: "
         "${PARTITION_NAMES[$part]}\"\n";
    s += "            mkdir \"$MOUNT_DIR/${PARTITION_NAMES[$part]}\"\n";
    s += "        fi\n";
    s += "    done\n";
    s += "}\n\n";
    s += "mount_partitions()\n{\n";
    s += "    for part in \"${!PARTITION_NAMES[@]}\"\n    do\n";
    s += "        echo \"Attempting to mount ${PARTITION_NAMES[$part]} fstype: "
         "${PARTITION_TYPES[$part]} at: $MOUNT_DIR/${PARTITION_NAMES[$part]}\"\n";
    s += "        sudo mount -t \"${PARTITION_TYPES[$part]}\" -o loop,ro "
         "\"${PARTITION_NAMES[$part]}\" \"$MOUNT_DIR/${PARTITION_NAMES[$part]}\"\n";
    s += "    done\n";
    s += "}\n\n";
    s += "generate_fs_tarballs()\n{\n";
    s += "    if test -d \"$FSDIR\"; then\n";
    s += "            echo \"Filesystem directory exists, attempting to create filesystem "
         "tarballs\"\n";
    s += "    else\n";
    s += "            echo \"Creating filesystem directory: $FSDIR\"\n";
    s += "            mkdir \"$FSDIR\"\n";
    s += "    fi\n";
    s += "    for part in \"${!PARTITION_NAMES[@]}\"\n    do\n";
    s += "        sudo tar cvf \"$FSDIR/${PARTITION_NAMES[$part]}.tar\" "
         "\"$MOUNT_DIR/${PARTITION_NAMES[$part]}\"\n";
    s += "    done\n";
    s += "    echo \"Tar operations complete, filesystems can be found in $FSDIR\"\n";
    s += "}\n\n";
    s += "unmount_partitions()\n{\n";
    s += "    for part in \"${!PARTITION_NAMES[@]}\"\n    do\n";
    s += "        sudo umount \"$MOUNT_DIR/${PARTITION_NAMES[$part]}\"\n";
    s += "    done\n";
    s += "}\n\n";
    s += "while getopts 'muht' opt; do\n";
    s += "    case \"$opt\" in\n";
    s += "        m)\n";
    s += "            echo \"Attempting to mount partitions\"\n";
    s += "            check_mount_dir\n";
    s += "            check_partition_folders\n";
    s += "            mount_partitions\n";
    s += "            echo \"Mount Results:\"\n";
    s += "            mount | grep \"$MOUNT_DIR\"\n";
    s += "            ;;\n";
    s += "        u)\n";
    s += "            echo \"Unmounting!\"\n";
    s += "            unmount_partitions\n";
    s += "            ;;\n";
    s += "        t)\n";
    s += "            echo \"Attempting to create tarballs of mounted filesystems\"\n";
    s += "            generate_fs_tarballs\n";
    s += "            ;;\n";
    s += "        h)\n";
    s += "            help\n";
    s += "            ;;\n";
    s += "    esac\n";
    s += "done\n";
    s += "if [ $OPTIND -eq 1 ]; then help ; fi\n";
    return s;
}

// `Limits::max_bytes` is a floor that suits a small compressed image, and
// `max_bytes_ratio` scales it with the evidence so a 16 GiB eMMC dump is not
// truncated by a number chosen for a 2 MiB SPI part. Saturating, because
// image_size * ratio overflows on a hostile Source size.
std::uint64_t extraction_budget(const Limits& lim, std::uint64_t image_size) {
    if (lim.max_bytes_ratio == 0) return lim.max_bytes;  // set exactly; do not raise
    const std::uint64_t scaled =
        image_size > std::numeric_limits<std::uint64_t>::max() / lim.max_bytes_ratio
            ? std::numeric_limits<std::uint64_t>::max()
            : image_size * lim.max_bytes_ratio;
    return std::max(lim.max_bytes, scaled);
}

// The same rule for one entry (`core/Limits.h`). A *stored* entry cannot be
// larger than the image that holds it, so the image size is the tightest cap
// that never cuts legitimate content -- and a cut here is not a partial
// recovery when the entry is itself a filesystem image, because the tables
// that name its contents live at its end.
std::uint64_t entry_budget(const Limits& lim, std::uint64_t image_size) {
    if (lim.max_file_bytes_ratio == 0) return lim.max_file_bytes;  // set exactly; do not raise
    const std::uint64_t scaled =
        image_size > std::numeric_limits<std::uint64_t>::max() / lim.max_file_bytes_ratio
            ? std::numeric_limits<std::uint64_t>::max()
            : image_size * lim.max_file_bytes_ratio;
    return std::max(lim.max_file_bytes, scaled);
}

Status analyze(const std::shared_ptr<const Source>& image, const std::string& evidence_path,
               const AnalyzeOptions& opts, Manifest& out, Listings& listings) {
    if (!image) return Status::fail("analyze-no-image: image source is null");
    if (opts.extract && opts.out_dir.empty())
        return Status::fail("analyze-no-out-dir: extraction needs out_dir");

    // Size the extraction budgets -- the run's and one entry's -- to the
    // evidence before any walk reads it. `scaled` is a local the Ctx below
    // borrows, so it has to outlive the run.
    AnalyzeOptions scaled = opts;
    scaled.limits.max_bytes = extraction_budget(opts.limits, image->size());
    scaled.limits.max_file_bytes = entry_budget(opts.limits, image->size());

    // ...then to the disk, which is the harder limit of the two. Reported
    // before anything is written, because an examiner choosing a budget wants
    // to hear it now and not from a half-finished case.
    std::optional<std::uint64_t> free_bytes;
    if (opts.extract && !opts.out_dir.empty()) {
        free_bytes = available_bytes(opts.out_dir);
        if (free_bytes) {
            const std::uint64_t room = disk_headroom(*free_bytes);
            if (scaled.limits.max_bytes > room) {
                out.diagnostics.push_back(
                    {Severity::Warning, "analyze-limit-disk",
                     "the extraction budget of " + dec(scaled.limits.max_bytes) +
                         " bytes is more than the output filesystem can take (" + dec(*free_bytes) +
                         " bytes free), so it was cut to " + dec(room) +
                         "; extraction will stop there with sink-limit-bytes rather than fill "
                         "the disk. Free space, choose another --out, or lower --max-bytes to "
                         "a figure you mean"});
                scaled.limits.max_bytes = room;
            }
        }
    }

    const Digests digests = hash_span(Span::whole(image));

    Evidence ev;
    ev.id = "e" + dec(out.evidence.size() + 1);
    ev.path = evidence_path;
    ev.size = image->size();
    ev.digests = digests;
    out.evidence.push_back(ev);

    Node img;
    img.kind = NodeKind::Image;
    img.name = sanitize_utf8(basename_of(evidence_path));
    if (img.name.empty()) img.name = image->id();
    img.format = "raw";
    img.location = {image->id(), 0, image->size()};
    img.confidence = static_cast<std::uint8_t>(Confidence::Verified);
    img.evidence = "examiner supplied";
    img.digests = digests;
    img.attrs["evidence"] = ev.id;
    if (image->size() == 0)
        img.diagnostics.push_back(
            {Severity::Warning, "analyze-empty-image", "the image has no bytes"});
    const std::string image_id = out.add_node(std::move(img)).id;

    // EXTENSION POINT: word-swap detection. A caller-supplied image_view hook
    // wins; otherwise detect_word_swap (core/Swap.h) decides whether the
    // dumper reversed the bytes of every 16- or 32-bit word, and the whole
    // analysis (scan, partitions, walks, carves) runs on the corrected view.
    // Nodes found there carry "<image-id>|swap32" in location.source; the
    // Image node itself keeps the evidence's own id and records the decision.
    std::shared_ptr<const Source> view = image;
    // Names the correction when the analysis is not running on the evidence
    // itself; that is also the condition for writing the view out below.
    std::string transform;
    if (opts.image_view) {
        if (Node* n = out.find(image_id)) {
            std::shared_ptr<const Source> chosen = opts.image_view(image, *n);
            if (chosen && chosen != image) {
                view = std::move(chosen);
                // A caller-supplied hook records its own attrs and diagnostics;
                // all this knows is that the bytes are no longer the evidence's.
                transform = "corrected";
            }
        }
    } else if (Node* n = out.find(image_id)) {
        const SwapDetection d = detect_word_swap(Span::whole(image));
        if (d.kind != SwapKind::None) {
            const std::string kind = swap_kind_name(d.kind);
            n->attrs["word_swap"] = kind;
            n->attrs["word_swap_confidence"] = dec(d.confidence);
            n->diagnostics.push_back({Severity::Warning, "image-word-swapped", d.evidence});
            const std::uint64_t word = d.kind == SwapKind::Swap16 ? 2 : 4;
            if (image->size() % word != 0)
                n->diagnostics.push_back({Severity::Info, "image-word-swap-tail",
                                          "image size " + dec(image->size()) +
                                              " is not a multiple of " + dec(word) + "; the last " +
                                              dec(image->size() % word) +
                                              " byte(s) are passed through unswapped"});
            bool have_row = false;
            for (Coverage& row : out.coverage) {
                if (row.format != "word-swap") continue;
                row.status = "supported";
                row.detail = kind + " applied";
                have_row = true;
            }
            if (!have_row) out.coverage.push_back({"word-swap", "supported", kind + " applied"});
            view = std::make_shared<SwappedSource>(image, d.kind);
            transform = kind;
        }
    }
    const Span whole = Span::whole(view);

    // The corrected view is the only copy of the bytes the rest of this
    // manifest describes, so it is written before anything is found in it.
    if (!transform.empty()) {
        if (Node* n = out.find(image_id)) {
            const std::string rel =
                write_corrected_view(scaled, whole, evidence_path, transform, *n);
            if (!rel.empty())
                for (Coverage& row : out.coverage)
                    if (row.format == "word-swap") row.detail += "; view written to " + rel;
        }
    }

    Ctx ctx{scaled, out, listings, image_id, 0, 0, {}, {}};
    for (std::size_t i = 0; i < out.coverage.size(); ++i)
        ctx.coverage_index.emplace(out.coverage[i].format, i);
    analyze_span(ctx, whole, image_id, 0);
    carve_all(ctx, whole);
    return Status::success();
}

}  // namespace omnitrace::discovery
