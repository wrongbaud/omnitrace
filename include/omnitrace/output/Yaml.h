// Yaml.h — manifest and listing serialization. Deterministic: same Manifest ->
// byte-identical text (keys in fixed order, no timestamps except those stored).
/// @file Yaml.h
/// @brief INFO.yaml / manifest.yaml and listing.yaml serialization, the
/// reverse parse, and the JSON Schema for the manifest.
///
/// Conventions (src/output/Yaml.cpp): keys in a fixed order; offsets, sizes
/// and counters as decimal integers with a quoted `offset_hex` twin; unix
/// timestamps with an ISO-8601 twin; `deleted` / `superseded` written only
/// when true and `version` only when > 0; strings that would read as another
/// YAML type are double-quoted; every string is `sanitize_utf8`'d.
#pragma once
#include <string>
#include <vector>

#include "omnitrace/core/Manifest.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Status.h"

namespace omnitrace::output {

/// The whole Manifest as YAML (schema `omnitrace/1`): `schema`, `run`,
/// `evidence`, `nodes`, `coverage`, `tools`, `diagnostics`, in that order.
std::string manifest_to_yaml(const Manifest& m);
/// Parse `text` back into `out`. Fails (never throws) with "manifest: ..."
/// for a YAML error, a document that is not a map, a `schema` other than
/// `Manifest::kSchema`, or a missing/mistyped field; `out` is untouched on
/// failure. `manifest_to_yaml(out)` reproduces `text` byte for byte, which the
/// CLI checks before exiting 0.
Status manifest_from_yaml(const std::string& text, Manifest& out);

// Per-filesystem listing.yaml: one document with `filesystem:` header and `entries:`.
/// Per-filesystem listing.yaml: `filesystem: <node id>` then `entries:`, one
/// map per `EntryResult` (metadata, digests, host_path, written, truncated,
/// diagnostics; absent when empty or false).
std::string listing_to_yaml(const std::string& fs_node_id, const std::vector<EntryResult>& entries);

// JSON Schema (draft 2020-12) for manifest.yaml, also written to docs/schema/manifest.schema.json.
/// JSON Schema (draft 2020-12) for manifest.yaml. The checked-in copy is
/// docs/schema/manifest.schema.json; a unit test keeps the two identical.
std::string manifest_json_schema();

}  // namespace omnitrace::output
