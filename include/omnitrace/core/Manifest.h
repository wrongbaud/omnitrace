// Manifest.h — the whole case as data. Serialized to manifest.yaml (output/).
/// @file Manifest.h
/// @brief `Manifest`, the in-memory form of INFO.yaml / manifest.yaml, plus
/// `Evidence` and `RunInfo`.
///
/// `discovery::analyze` fills it, `output::manifest_to_yaml` writes it and
/// `output::manifest_from_yaml` reads it back; the CLI refuses to exit 0
/// unless the round trip is byte-identical.
#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "omnitrace/core/Node.h"

namespace omnitrace {

/// One evidence file the examiner supplied.
struct Evidence {
    std::string id;           ///< "e1", "e2", ...
    std::string path;         ///< As given by the examiner.
    std::uint64_t size = 0;   ///< Bytes.
    Digests digests;          ///< MD5/SHA-1/SHA-256 of the whole file.
    std::string acquired_at;  ///< ISO-8601, examiner supplied or the file's mtime.
    std::string note;         ///< Free text.
};

/// Who produced this manifest and when. Set by the CLI, not by `analyze()`.
struct RunInfo {
    std::string tool = "omnitrace";       ///< Producer name.
    std::string version;                  ///< OMNITRACE_VERSION.
    std::string git_sha;                  ///< If known.
    std::string started_at, finished_at;  ///< ISO-8601 from `Clock`.
    std::string host_os;                  ///< Free text.
    std::vector<std::string> argv;        ///< The command line.
};

/// The whole case as data: run info, evidence, the node graph, coverage,
/// tools and run-level diagnostics.
///
/// Not thread-safe; one analysis builds one Manifest. Determinism: ids depend
/// only on insertion order, so the same sequence of `add_node` calls yields
/// the same ids and the same YAML.
class Manifest {
   public:
    /// Schema tag written as the first YAML key and checked on read.
    static constexpr const char* kSchema = "omnitrace/1";

    RunInfo run;                          ///< Left to the caller by `analyze()`.
    std::vector<Evidence> evidence;       ///< One row per input file.
    std::vector<Coverage> coverage;       ///< One row per format met.
    std::vector<ToolRecord> tools;        ///< External tools run (none today).
    std::vector<Diagnostic> diagnostics;  ///< Run-level caveats, e.g. "analyze-limit-depth".

    // Graph. Nodes are stored in insertion order; ids are assigned here.
    /// Append `n` to the graph. Assigns `n.id` ("n%06zu", 1-based), clears and
    /// then ignores any pre-set `child_ids`, and appends the id to the parent's
    /// `child_ids`. A `parent_id` that is not in the graph is kept as given and
    /// the node gets a "manifest-parent-missing" warning.
    /// @return a reference into the node vector, valid only until the next `add_node`.
    Node& add_node(Node n);  // sets n.id, links into parent's child_ids
    /// The node with that id, or `nullptr`.
    const Node* find(const std::string& id) const;
    /// Mutable overload of `find`.
    Node* find(const std::string& id);
    /// Every node in insertion order (the order `nodes:` is written in).
    const std::vector<Node>& nodes() const { return nodes_; }
    /// Direct children of `id` in insertion order; empty when `id` is unknown.
    std::vector<const Node*> children_of(const std::string& id) const;
    /// Number of nodes of kind `k`.
    std::size_t count(NodeKind k) const;

   private:
    std::vector<Node> nodes_;
    std::map<std::string, std::size_t> index_;
};

}  // namespace omnitrace
