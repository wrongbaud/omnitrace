// Recurse.cpp — the analysis driver. See Recurse.h for the contract.
//
// Node insertion order is the offset order of the things found, so the same
// image always yields the same ids and the same manifest.yaml. Every offset
// arithmetic saturates; every reader failure becomes a Diagnostic on the node
// it belongs to and a Coverage row, never an exception or a skipped finding.
#include "omnitrace/discovery/Recurse.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <system_error>

#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::discovery {

namespace {

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
    std::uint64_t start = 0;  // relative to the table finding
    std::uint64_t size = 0;
    std::map<std::string, std::string> attrs;
};

// Mutable state for one analyze() call. Readers never see it.
struct Ctx {
    const AnalyzeOptions& opts;
    Manifest& out;
    Listings& listings;
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

// Innermost structural node whose range contains [offset, end); `fallback`
// otherwise. Ties go to the most recently added node (the most nested one).
std::string parent_for(const Ctx& c, std::uint64_t offset, std::uint64_t end,
                       const std::string& fallback) {
    std::string best = fallback;
    std::uint64_t best_len = UINT64_MAX;
    for (const Extent& e : c.extents) {
        if (offset < e.offset || end > e.end) continue;
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
        if (it != f.attrs.end() && !it->second.empty()) return it->second;
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
                             "cannot parse partition entry '" + item + "'"});
            continue;
        }
        PartSpec p;
        p.index = fields[0];
        p.start = *start;
        p.size = *size;
        p.attrs["type"] = fields[3];
        for (std::size_t i = 4; i < fields.size(); ++i) {
            const std::string& fld = fields[i];
            const std::size_t eq = fld.find('=');
            if (eq != std::string::npos) {
                p.attrs[fld.substr(0, eq)] = fld.substr(eq + 1);
            } else if (f.format == "gpt" && i == 4) {
                p.attrs["unique_guid"] = fld;
            } else if (f.format == "gpt" && i == 5) {
                p.attrs["name"] = fld;
            } else if (!fld.empty()) {
                p.attrs[fld] = "true";  // mbr flags: boot, logical
            }
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

// ------------------------------------------------------------- filesystems

struct WalkOutcome {
    fs::WalkResult result;
    std::uint64_t files = 0, bytes = 0;
    Status status = Status::success();
    std::string sink_error;
};

// Open the right Sink for this run and walk `reader` into it.
WalkOutcome walk_into_sink(Ctx& c, fs::FilesystemReader& reader, const std::string& fs_id,
                           const Limits& limits) {
    WalkOutcome w;
    fs::WalkOptions wopts;
    wopts.extract_data = c.opts.extract;
    wopts.history = c.opts.history;
    wopts.limits = limits;

    if (c.opts.extract) {
        const std::filesystem::path root =
            std::filesystem::path(c.opts.out_dir) / "filesystems" / fs_id / "files";
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
        std::unique_ptr<DiskSink> sink;
        if (Status st = DiskSink::open(root.string(), dopts, sink); !st) {
            w.sink_error = st.error;
            return w;
        }
        w.status = reader.walk(*sink, wopts, w.result);
        w.files = sink->files_emitted();
        w.bytes = sink->bytes_emitted();
        return w;
    }

    ListingSink sink(false, limits);
    w.status = reader.walk(sink, wopts, w.result);
    if (w.result.entries_out.empty() && !sink.entries().empty())
        w.result.entries_out = sink.entries();
    w.files = sink.files_emitted();
    w.bytes = sink.bytes_emitted();
    return w;
}

void add_file_nodes(Ctx& c, const std::string& fs_id, const Node& fs_node,
                    const std::vector<EntryResult>& entries) {
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
        c.out.add_node(std::move(fn));
    }
}

// Open + walk one filesystem finding whose node is already in the graph.
void process_filesystem(Ctx& c, const Span& span, const Finding& f, const std::string& fs_id) {
    std::vector<Diagnostic> diags;
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
            if (!info.label.empty()) attrs["label"] = info.label;
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
                WalkOutcome w = walk_into_sink(c, *reader, fs_id, limits);
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
                    add_file_nodes(c, fs_id, fs_copy, r.entries_out);
                    c.listings.emplace_back(fs_id, r.entries_out);
                }
            }
        }
    }

    Node* fs_node = c.out.find(fs_id);
    if (!fs_node) return;
    for (const auto& [k, v] : attrs) fs_node->attrs[k] = v;
    if (new_length) fs_node->location.length = *new_length;
    for (Diagnostic& d : diags) fs_node->diagnostics.push_back(std::move(d));
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

Node gap_node(const Span& span, std::uint64_t off, std::uint64_t len,
              const std::string& parent_id) {
    Node n;
    n.kind = NodeKind::Region;
    n.parent_id = parent_id;
    n.name = "unidentified";
    n.location = {span.source_id(), span.absolute(off), len};
    n.confidence = 0;
    n.evidence = "no signature matched";
    const std::string fill = uniform_fill(span, off, len);
    if (!fill.empty()) n.attrs["fill"] = fill;
    n.diagnostics.push_back(
        {Severity::Info, "region-unidentified", "no signature matched in " + dec(len) + " bytes"});
    return n;
}

// ---------------------------------------------------------------- the pass

// Something to turn into a node, keyed by offset so nodes appear in byte order.
struct Item {
    std::uint64_t offset = 0;
    bool is_gap = false;
    std::size_t finding = 0;  // index into findings when !is_gap
    std::uint64_t gap_len = 0;
};

// Analyze one Span whose bytes belong to `parent_id`. Phase 1a will call this
// again for Container payloads and extracted files, with depth + 1.
void analyze_span(Ctx& c, const Span& span, const std::string& parent_id, std::size_t depth) {
    if (depth > c.opts.limits.max_depth) {
        c.out.diagnostics.push_back({Severity::Warning, "analyze-limit-depth",
                                     "nesting deeper than max_depth (" +
                                         dec(c.opts.limits.max_depth) + ") under " + parent_id});
        return;
    }
    const std::vector<Finding> findings = scan(span, SignatureSet::builtin(), c.opts.scan);

    // Pass 1: parse partition tables and build the claim map.
    std::vector<std::vector<PartSpec>> parts(findings.size());
    std::vector<std::vector<Diagnostic>> part_diags(findings.size());
    std::vector<Claim> claims;
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const Finding& f = findings[i];
        if (f.category == "partition-table") {
            parts[i] = parse_partitions(f, part_diags[i]);
            claims.push_back(
                {f.offset, std::min(sat_add(f.offset, table_metadata_bytes(f)), span.size())});
            for (const PartSpec& p : parts[i]) {
                const std::uint64_t start = sat_add(f.offset, p.start);
                if (start >= span.size()) continue;
                claims.push_back({start, std::min(sat_add(start, p.size), span.size())});
            }
        } else {
            const std::uint64_t end =
                f.size == 0 ? span.size() : std::min(sat_add(f.offset, f.size), span.size());
            claims.push_back({f.offset, end});
        }
    }
    std::sort(claims.begin(), claims.end(), [](const Claim& a, const Claim& b) {
        return a.offset != b.offset ? a.offset < b.offset : a.end > b.end;
    });

    // Pass 2: gaps between merged claims.
    std::vector<Item> items;
    for (std::size_t i = 0; i < findings.size(); ++i)
        items.push_back({findings[i].offset, false, i, 0});
    std::uint64_t cursor = 0;
    auto note_gap = [&](std::uint64_t from, std::uint64_t to) {
        if (to > from && to - from >= c.opts.min_region_bytes)
            items.push_back({from, true, 0, to - from});
    };
    for (const Claim& cl : claims) {
        if (cl.offset > cursor) note_gap(cursor, cl.offset);
        cursor = std::max(cursor, cl.end);
    }
    note_gap(cursor, span.size());
    std::stable_sort(items.begin(), items.end(), [](const Item& a, const Item& b) {
        if (a.offset != b.offset) return a.offset < b.offset;
        return a.is_gap < b.is_gap;  // a finding at the same offset comes first
    });

    // Pass 3: nodes, in byte order.
    for (const Item& it : items) {
        if (it.is_gap) {
            const std::string parent = parent_for(c, it.offset, it.offset + it.gap_len, parent_id);
            c.out.add_node(gap_node(span, it.offset, it.gap_len, parent));
            continue;
        }
        const Finding& f = findings[it.finding];
        const std::uint64_t f_end =
            f.size == 0 ? span.size() : std::min(sat_add(f.offset, f.size), span.size());
        const std::string parent = parent_for(c, f.offset, f_end, parent_id);
        const NodeKind kind = kind_for(f);
        Node n = node_from_finding(f, span, parent, kind);

        if (kind == NodeKind::Partition) {
            n.name = f.format + " partition table";
            n.attrs["role"] = "table";
            for (Diagnostic& d : part_diags[it.finding]) n.diagnostics.push_back(std::move(d));
            const std::string table_id = c.out.add_node(std::move(n)).id;
            for (const PartSpec& p : parts[it.finding]) {
                Node pn;
                pn.kind = NodeKind::Partition;
                pn.parent_id = table_id;
                pn.name = attr_or(p.attrs, "name", p.index);
                pn.format = f.format;
                const std::uint64_t start = sat_add(f.offset, p.start);
                std::uint64_t length = p.size;
                pn.confidence = static_cast<std::uint8_t>(f.confidence);
                pn.evidence = f.format + " entry " + p.index;
                pn.attrs = p.attrs;
                pn.attrs["index"] = p.index;
                if (start >= span.size()) {
                    pn.location = {span.source_id(), span.absolute(std::min(start, span.size())),
                                   0};
                    pn.diagnostics.push_back({Severity::Warning, "partition-outside-image",
                                              "entry starts at " + hex(span.absolute(start)) +
                                                  ", past the end of the data"});
                    pn.confidence = static_cast<std::uint8_t>(Confidence::Magic);
                    c.out.add_node(std::move(pn));
                    continue;
                }
                if (length > span.size() - start) {
                    pn.attrs["claimed_size"] = dec(length);
                    length = span.size() - start;
                    pn.diagnostics.push_back(
                        {Severity::Warning, "partition-truncated",
                         "entry extends past the end of the data; clamped to " + dec(length) +
                             " bytes"});
                }
                pn.location = {span.source_id(), span.absolute(start), length};
                const std::string pid = c.out.add_node(std::move(pn)).id;
                c.extents.push_back({pid, start, start + length});
            }
            continue;
        }

        if (kind == NodeKind::Container) {
            // Rule 7: a container we recognise but do not open (Phase 1a) is a
            // Coverage row and a Diagnostic, never a silent node.
            set_coverage(c, f.format, "unsupported", "no container reader registered");
            n.diagnostics.push_back(
                {Severity::Warning, "analyze-no-reader",
                 "no " + f.format + " container reader registered; payload not opened"});
        }
        const std::string id = c.out.add_node(std::move(n)).id;
        if (kind == NodeKind::Filesystem || kind == NodeKind::Container)
            c.extents.push_back({id, f.offset, f_end});
        if (kind == NodeKind::Filesystem) process_filesystem(c, span, f, id);
        // Phase 1a: kind == Container -> open a ContainerReader, walk its payload
        // into a Sink, then analyze_span(c, payload_span, id, depth + 1).
    }
}

}  // namespace

Status analyze(const std::shared_ptr<const Source>& image, const std::string& evidence_path,
               const AnalyzeOptions& opts, Manifest& out, Listings& listings) {
    if (!image) return Status::fail("analyze-no-image: image source is null");
    if (opts.extract && opts.out_dir.empty())
        return Status::fail("analyze-no-out-dir: extraction needs out_dir");

    const Span whole = Span::whole(image);
    const Digests digests = hash_span(whole);

    Evidence ev;
    ev.id = "e" + dec(out.evidence.size() + 1);
    ev.path = evidence_path;
    ev.size = image->size();
    ev.digests = digests;
    out.evidence.push_back(ev);

    Node img;
    img.kind = NodeKind::Image;
    img.name = basename_of(evidence_path);
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

    Ctx ctx{opts, out, listings, 0, 0, {}, {}};
    for (std::size_t i = 0; i < out.coverage.size(); ++i)
        ctx.coverage_index.emplace(out.coverage[i].format, i);
    analyze_span(ctx, whole, image_id, 0);
    return Status::success();
}

}  // namespace omnitrace::discovery
