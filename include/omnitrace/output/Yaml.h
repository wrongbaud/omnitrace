// Yaml.h — manifest and listing serialization. Deterministic: same Manifest ->
// byte-identical text (keys in fixed order, no timestamps except those stored).
#pragma once
#include <string>
#include <vector>

#include "omnitrace/core/Manifest.h"
#include "omnitrace/core/Sink.h"
#include "omnitrace/core/Status.h"

namespace omnitrace::output {

std::string manifest_to_yaml(const Manifest& m);
Status manifest_from_yaml(const std::string& text, Manifest& out);

// Per-filesystem listing.yaml: one document with `filesystem:` header and `entries:`.
std::string listing_to_yaml(const std::string& fs_node_id, const std::vector<EntryResult>& entries);

// JSON Schema (draft 2020-12) for manifest.yaml, also written to docs/schema/manifest.schema.json.
std::string manifest_json_schema();

}  // namespace omnitrace::output
