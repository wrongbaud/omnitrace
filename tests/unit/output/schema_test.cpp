// schema_test.cpp — manifest_json_schema() is identical to the file in
// docs/schema/, is valid JSON Schema shaped, and describes exactly what
// manifest_to_yaml emits (checked with a small structural validator: object
// keys, required keys, array items, scalar types, enums, consts, patterns
// and integer ranges, following $ref into $defs).
#include <gtest/gtest.h>
#include <yaml-cpp/yaml.h>

#include <fstream>
#include <nlohmann/json.hpp>
#include <regex>
#include <sstream>
#include <string>

#include "fixture.h"
#include "omnitrace/output/Yaml.h"

#ifndef OMNITRACE_SOURCE_DIR
#define OMNITRACE_SOURCE_DIR "."
#endif

namespace omnitrace::output {
namespace {

using json = nlohmann::ordered_json;

std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

struct Validator {
    const json& root;
    std::vector<std::string> errors;

    const json& resolve(const json& schema) {
        if (schema.contains("$ref")) {
            const std::string ref = schema["$ref"].get<std::string>();
            const std::string prefix = "#/$defs/";
            if (ref.rfind(prefix, 0) == 0) return root["$defs"][ref.substr(prefix.size())];
            errors.push_back("unresolvable $ref " + ref);
        }
        return schema;
    }

    bool is_integer_text(const std::string& s) {
        static const std::regex re("^-?[0-9]+$");
        return std::regex_match(s, re);
    }

    void check(const YAML::Node& node, const json& raw, const std::string& path) {
        const json& schema = resolve(raw);
        if (schema.contains("const")) {
            const json& c = schema["const"];
            if (!node.IsScalar()) {
                errors.push_back(path + ": const expects a scalar");
            } else if (c.is_string() && node.Scalar() != c.get<std::string>()) {
                errors.push_back(path + ": const mismatch '" + node.Scalar() + "'");
            } else if (c.is_boolean() && node.Scalar() != (c.get<bool>() ? "true" : "false")) {
                errors.push_back(path + ": const bool mismatch '" + node.Scalar() + "'");
            }
            return;
        }
        const std::string type = schema.value("type", "");
        if (type == "object") {
            if (!node.IsMap()) {
                errors.push_back(path + ": expected map");
                return;
            }
            const json props = schema.value("properties", json::object());
            for (const auto& kv : node) {
                const std::string key = kv.first.Scalar();
                if (props.contains(key)) {
                    check(kv.second, props[key], path + "." + key);
                } else if (schema.contains("additionalProperties") &&
                           schema["additionalProperties"].is_object()) {
                    check(kv.second, schema["additionalProperties"], path + "." + key);
                } else {
                    errors.push_back(path + ": key '" + key + "' not in schema");
                }
            }
            for (const auto& req : schema.value("required", json::array())) {
                if (!node[req.get<std::string>()].IsDefined()) {
                    errors.push_back(path + ": required key '" + req.get<std::string>() +
                                     "' missing");
                }
            }
            // Emission order must be the schema's property order.
            std::vector<std::string> emitted, expected;
            for (const auto& kv : node) {
                if (props.contains(kv.first.Scalar())) emitted.push_back(kv.first.Scalar());
            }
            for (const auto& p : props.items()) {
                if (node[p.key()].IsDefined()) expected.push_back(p.key());
            }
            if (!props.empty() && emitted != expected)
                errors.push_back(path + ": key order differs from schema");
        } else if (type == "array") {
            if (!node.IsSequence()) {
                errors.push_back(path + ": expected sequence");
                return;
            }
            std::size_t i = 0;
            for (const YAML::Node& item : node)
                check(item, schema["items"], path + "[" + std::to_string(i++) + "]");
        } else if (type == "integer") {
            if (!node.IsScalar() || !is_integer_text(node.Scalar())) {
                errors.push_back(path + ": expected integer");
                return;
            }
            // Range: compare as long double after parse; exact enough for the
            // bounds the schema uses.
            const long double v = std::stold(node.Scalar());
            if (schema.contains("minimum") && v < schema["minimum"].get<long double>())
                errors.push_back(path + ": below minimum");
            if (schema.contains("maximum") && v > schema["maximum"].get<long double>())
                errors.push_back(path + ": above maximum");
        } else if (type == "number") {
            if (!node.IsScalar()) errors.push_back(path + ": expected number");
        } else if (type == "string") {
            if (!node.IsScalar()) {
                errors.push_back(path + ": expected string");
                return;
            }
            if (schema.contains("enum")) {
                bool ok = false;
                for (const auto& e : schema["enum"])
                    ok = ok || e.get<std::string>() == node.Scalar();
                if (!ok) errors.push_back(path + ": '" + node.Scalar() + "' not in enum");
            }
            if (schema.contains("pattern")) {
                const std::regex re(schema["pattern"].get<std::string>());
                if (!std::regex_search(node.Scalar(), re))
                    errors.push_back(path + ": pattern mismatch '" + node.Scalar() + "'");
            }
        } else {
            errors.push_back(path + ": schema has no usable type");
        }
    }
};

TEST(Schema, MatchesCheckedInFile) {
    const std::string path =
        std::string(OMNITRACE_SOURCE_DIR) + "/docs/schema/manifest.schema.json";
    const std::string file = read_file(path);
    ASSERT_FALSE(file.empty()) << "missing " << path;
    EXPECT_EQ(manifest_json_schema(), file)
        << "regenerate docs/schema/manifest.schema.json from manifest_json_schema()";
}

TEST(Schema, IsWellFormedDraft2020) {
    const json s = json::parse(manifest_json_schema());
    EXPECT_EQ(s["$schema"], "https://json-schema.org/draft/2020-12/schema");
    EXPECT_EQ(s["type"], "object");
    EXPECT_EQ(s["properties"]["schema"]["const"], "omnitrace/1");
    EXPECT_FALSE(s["additionalProperties"].get<bool>());
    for (const char* def : {"run", "digests", "evidence", "diagnostic", "location", "file", "node",
                            "coverage", "tool"}) {
        EXPECT_TRUE(s["$defs"].contains(def)) << def;
        EXPECT_FALSE(s["$defs"][def]["additionalProperties"].get<bool>()) << def;
    }
}

TEST(Schema, DescribesExactlyWhatIsEmitted) {
    const json schema = json::parse(manifest_json_schema());
    const YAML::Node doc = YAML::Load(manifest_to_yaml(test::full_manifest()));
    Validator v{schema, {}};
    v.check(doc, schema, "$");
    for (const std::string& e : v.errors) ADD_FAILURE() << e;
}

TEST(Schema, ValidatorRejectsDrift) {
    // Sanity check the checker itself: an unknown key and a bad enum must be caught.
    const json schema = json::parse(manifest_json_schema());
    YAML::Node doc = YAML::Load(manifest_to_yaml(test::full_manifest()));
    doc["nodes"][0]["bogus"] = 1;
    doc["nodes"][1]["kind"] = "blob";
    Validator v{schema, {}};
    v.check(doc, schema, "$");
    EXPECT_EQ(v.errors.size(), 2u);
}

}  // namespace
}  // namespace omnitrace::output
