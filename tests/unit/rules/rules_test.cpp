// rules_test.cpp — pack parsing, rule compilation, matching and the caps.
//
// The built-in packs are part of the product, so they are tested as data:
// every one must parse, compile, and match the thing it says it matches
// without matching the thing next to it. The hand-built packs below cover the
// cases a built-in one should never contain — a bad pattern, a hostile
// quantifier, a rule that finds something on every byte.
#include "omnitrace/rules/Rule.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace omnitrace;
using namespace omnitrace::rules;

namespace {

std::span<const std::uint8_t> bytes_of(const std::string& s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

Engine engine_for(const std::string& yaml) {
    RulePack p;
    const Status st = RulePack::parse(yaml, "test", p);
    EXPECT_TRUE(st) << st.error;
    Engine e;
    const Status b = Engine::build({p}, e);
    EXPECT_TRUE(b) << b.error;
    return e;
}

std::vector<Hit> scan(const Engine& e, const std::string& text, bool in_files = true) {
    std::vector<Hit> hits;
    e.scan_bytes(bytes_of(text), in_files, ScanLimits{}, hits);
    return hits;
}

std::vector<std::string> ids(const std::vector<Hit>& hits) {
    std::vector<std::string> out;
    for (const Hit& h : hits) out.push_back(h.rule);
    return out;
}

bool has_id(const std::vector<std::string>& v, const std::string& id) {
    return std::find(v.begin(), v.end(), id) != v.end();
}

bool has(const std::vector<Hit>& hits, const std::string& id) {
    return std::find_if(hits.begin(), hits.end(), [&](const Hit& h) { return h.rule == id; }) !=
           hits.end();
}

}  // namespace

// ------------------------------------------------------------ pack parsing

TEST(Rules, ParsesAMinimalPack) {
    RulePack p;
    const Status st = RulePack::parse(R"(
pack: demo
version: 3
rules:
  - id: hello
    kind: literal
    pattern: hello
    category: greeting
    severity: high
    description: says hello
)",
                                      "inline", p);
    ASSERT_TRUE(st) << st.error;
    EXPECT_EQ(p.name, "demo");
    EXPECT_EQ(p.version, 3u);
    ASSERT_EQ(p.rules.size(), 1u);
    EXPECT_EQ(p.rules[0].id, "hello");
    EXPECT_EQ(p.rules[0].pack, "demo");
    EXPECT_EQ(p.rules[0].kind, Kind::Literal);
    EXPECT_EQ(p.rules[0].severity, Severity::High);
    EXPECT_EQ(p.rules[0].category, "greeting");
    // Both scopes by default: a rule with no `scope` looks everywhere.
    EXPECT_TRUE(p.rules[0].in_files);
    EXPECT_TRUE(p.rules[0].in_regions);
}

TEST(Rules, RejectsAPackItCannotActOn) {
    const auto fails = [](const char* yaml, const char* code) {
        RulePack p;
        const Status st = RulePack::parse(yaml, "inline", p);
        EXPECT_FALSE(st) << yaml;
        EXPECT_NE(st.error.find(code), std::string::npos) << st.error;
    };
    fails("not: a: valid: yaml: [", "rules-bad-yaml");
    fails("version: 1\nrules: []\n", "rules-no-name");
    fails("pack: p\n", "rules-no-rules");
    fails("pack: p\nrules: []\n", "rules-no-rules");
    fails("pack: p\nrules:\n  - kind: literal\n    pattern: x\n", "rules-no-id");
    fails("pack: p\nrules:\n  - id: a\n    kind: literal\n", "rules-no-pattern");
    fails("pack: p\nrules:\n  - id: a\n    kind: sorcery\n    pattern: x\n", "rules-bad-kind");
    fails("pack: p\nrules:\n  - id: a\n    pattern: x\n    severity: urgent\n",
          "rules-bad-severity");
    fails("pack: p\nrules:\n  - id: a\n    pattern: x\n    validate: astrology\n",
          "rules-bad-validate");
    fails("pack: p\nrules:\n  - id: a\n    pattern: x\n    scope: [elsewhere]\n",
          "rules-bad-scope");
    // A duplicate id would make a hit ambiguous about which rule found it.
    fails("pack: p\nrules:\n  - id: a\n    pattern: x\n  - id: a\n    pattern: y\n",
          "rules-duplicate-id");
}

// A pattern that does not compile is refused at build time, naming the rule,
// rather than being dropped and leaving an examiner thinking it ran.
TEST(Rules, ABadPatternFailsTheBuildAndNamesTheRule) {
    RulePack p;
    ASSERT_TRUE(RulePack::parse("pack: p\nrules:\n  - id: broken\n    pattern: '([unclosed'\n",
                                "inline", p));
    Engine e;
    const Status st = Engine::build({p}, e);
    EXPECT_FALSE(st);
    EXPECT_NE(st.error.find("rules-bad-pattern"), std::string::npos) << st.error;
    EXPECT_NE(st.error.find("broken"), std::string::npos) << st.error;
}

TEST(Rules, HexPatternsMatchBytesAndAcceptWildcards) {
    const Engine e = engine_for(R"(
pack: hex
rules:
  - id: exact
    kind: hex
    pattern: "deadbeef"
  - id: wild
    kind: hex
    pattern: "ca ?? ca ??"
)");
    std::string data("\x11\xde\xad\xbe\xef\x22\xca\xfe\xca\xfe\x33", 11);
    const std::vector<Hit> hits = scan(e, data);
    EXPECT_TRUE(has(hits, "exact"));
    EXPECT_TRUE(has(hits, "wild"));
    for (const Hit& h : hits)
        if (h.rule == "exact") EXPECT_EQ(h.offset, 1u);

    RulePack p;
    ASSERT_TRUE(RulePack::parse("pack: p\nrules:\n  - id: odd\n    kind: hex\n    pattern: abc\n",
                                "inline", p));
    Engine bad;
    EXPECT_FALSE(Engine::build({p}, bad)) << "an odd number of hex digits is not a byte pattern";
}

// Evidence is bytes, not text. A rule has to be able to match inside data that
// is not valid UTF-8, which is most of a flash dump.
TEST(Rules, MatchesInsideBinaryDataAndQuotesItSafely) {
    const Engine e = engine_for(
        "pack: p\nrules:\n  - id: key\n    kind: literal\n"
        "    pattern: SECRET\n");
    std::string data(
        "\x00\xff\xfe"
        "SECRET"
        "\x80\x81",
        11);
    const std::vector<Hit> hits = scan(e, data);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0].offset, 3u);
    EXPECT_EQ(hits[0].match, "SECRET");
    // The context carries the surrounding bytes in a form a YAML file can hold.
    EXPECT_NE(hits[0].context.find("\\x00"), std::string::npos) << hits[0].context;
    EXPECT_NE(hits[0].context.find("SECRET"), std::string::npos);
}

TEST(Rules, ScopeDecidesWhereARuleRuns) {
    const Engine e = engine_for(R"(
pack: p
rules:
  - id: files-only
    kind: literal
    pattern: TOKEN
    scope: [files]
  - id: regions-only
    kind: literal
    pattern: TOKEN
    scope: [regions]
)");
    EXPECT_EQ(ids(scan(e, "a TOKEN here", true)), (std::vector<std::string>{"files-only"}));
    EXPECT_EQ(ids(scan(e, "a TOKEN here", false)), (std::vector<std::string>{"regions-only"}));
}

TEST(Rules, GlobPathsMatchPathsNotContents) {
    const Engine e = engine_for(R"(
pack: p
rules:
  - id: shadow
    kind: glob-path
    pattern: '**/etc/shadow'
    severity: critical
  - id: conf-here
    kind: glob-path
    pattern: 'etc/*.conf'
)");
    const auto paths = [&](const char* p) {
        std::vector<Hit> h;
        e.scan_path(p, h);
        return ids(h);
    };
    EXPECT_EQ(paths("etc/shadow"), (std::vector<std::string>{"shadow"}));
    EXPECT_EQ(paths("usr/local/etc/shadow"), (std::vector<std::string>{"shadow"}));
    EXPECT_TRUE(paths("etc/shadow.bak").empty());
    EXPECT_EQ(paths("etc/a.conf"), (std::vector<std::string>{"conf-here"}));
    // A single star does not cross a separator.
    EXPECT_TRUE(paths("etc/sub/a.conf").empty());
    // Contents are never consulted by a path rule.
    EXPECT_TRUE(scan(e, "etc/shadow").empty());
}

// ------------------------------------------------------------ post-filters

TEST(Rules, ValidateFiltersDropMatchesThatFailTheirCheckDigit) {
    const Engine e = engine_for(R"(
pack: p
rules:
  - id: vin
    kind: regex
    pattern: '\b[A-HJ-NPR-Z0-9]{17}\b'
    validate: vin-checksum
)");
    // A real VIN and the same one with the check digit changed.
    const std::vector<Hit> good = scan(e, "vin 1HGCM82633A004352 end");
    EXPECT_EQ(good.size(), 1u) << "a VIN with a valid check digit is a hit";
    const std::vector<Hit> bad = scan(e, "vin 1HGCM82633A004353 end");
    EXPECT_TRUE(bad.empty()) << "a 17-character token that fails the check digit is not a VIN";

    // The check digit is one in eleven, so a placeholder can pass it by
    // chance. This one sits in ICU's data tables and in iconv, and turned up
    // ten times on a real head unit before the shape test was added.
    EXPECT_TRUE(scan(e, " X1X2X3X4X6X7X8X9X ").empty())
        << "a token that is more than half one character is a placeholder, not a vehicle";
}

TEST(Rules, PhoneNumbersAreNotFloatFormats) {
    Engine e;
    ASSERT_TRUE(Engine::build(RulePack::builtin(), e));
    // `e+631065600` is a float in file(1)'s magic database, not a number.
    EXPECT_FALSE(has(scan(e, "  %e+631065600\t"), "phone-e164"));
    EXPECT_TRUE(has(scan(e, " call +14155552671 now"), "phone-e164"));
}

TEST(Rules, MacFilterDropsPlaceholders) {
    const Engine e = engine_for(R"(
pack: p
rules:
  - id: mac
    kind: regex
    pattern: '(?i)(?:[^0-9a-f:]|^)((?:[0-9a-f]{2}:){5}[0-9a-f]{2})(?:[^0-9a-f:]|$)'
    validate: mac-not-broadcast
)");
    EXPECT_EQ(scan(e, " 00:1a:2b:3c:4d:5e ").size(), 1u);
    EXPECT_TRUE(scan(e, " ff:ff:ff:ff:ff:ff ").empty()) << "broadcast is not a device";
    EXPECT_TRUE(scan(e, " 00:00:00:00:00:00 ").empty()) << "all-zero is a placeholder";
}

// ------------------------------------------------------------------- caps

// A pack is user input. One rule that matches everywhere must not be able to
// fill a manifest with a million hits.
TEST(Rules, HitsPerRuleAreCapped) {
    const Engine e = engine_for("pack: p\nrules:\n  - id: a\n    kind: literal\n    pattern: a\n");
    const std::string many(5000, 'a');
    std::vector<Hit> hits;
    ScanLimits lim;
    lim.max_hits_per_rule_per_item = 10;
    e.scan_bytes(bytes_of(many), true, lim, hits);
    EXPECT_EQ(hits.size(), 10u);
}

TEST(Rules, ReadingIsCappedPerItem) {
    const Engine e = engine_for(
        "pack: p\nrules:\n  - id: late\n    kind: literal\n"
        "    pattern: NEEDLE\n");
    std::string data(4096, '.');
    data += "NEEDLE";
    ScanLimits lim;
    lim.max_bytes_per_item = 1024;
    std::vector<Hit> hits;
    e.scan_bytes(bytes_of(data), true, lim, hits);
    EXPECT_TRUE(hits.empty()) << "the needle is past the cap, so it is not reached";
    lim.max_bytes_per_item = 1u << 20;
    e.scan_bytes(bytes_of(data), true, lim, hits);
    EXPECT_EQ(hits.size(), 1u);
}

// The whole reason for RE2: a pattern that would make a backtracking engine
// run for the rest of the case has to finish in ordinary time.
TEST(Rules, APathologicalPatternStillTerminates) {
    const Engine e = engine_for(
        "pack: p\nrules:\n  - id: evil\n    kind: regex\n"
        "    pattern: '(a+)+$'\n");
    const std::string subject(2000, 'a');  // no trailing char, the classic blowup
    std::vector<Hit> hits;
    e.scan_bytes(bytes_of(subject + "b"), true, ScanLimits{}, hits);
    SUCCEED() << "returned at all, which std::regex would not have";
}

TEST(Rules, HitOrderIsDeterministic) {
    const Engine e = engine_for(R"(
pack: p
rules:
  - id: zeta
    kind: literal
    pattern: X
  - id: alpha
    kind: literal
    pattern: X
)");
    const std::vector<Hit> a = scan(e, "..X..X..");
    const std::vector<Hit> b = scan(e, "..X..X..");
    ASSERT_EQ(a.size(), 4u);
    EXPECT_EQ(ids(a), ids(b));
    // Ordered by offset, then rule id, so a manifest does not churn.
    EXPECT_EQ(ids(a), (std::vector<std::string>{"alpha", "zeta", "alpha", "zeta"}));
    EXPECT_LE(a[0].offset, a[2].offset);
}

// ------------------------------------------------------------- the packs

TEST(Rules, EveryBuiltinPackParsesAndCompiles) {
    const std::vector<RulePack>& packs = RulePack::builtin();
    ASSERT_FALSE(packs.empty()) << "rules/*.yaml did not get embedded";
    std::size_t total = 0;
    for (const RulePack& p : packs) {
        EXPECT_FALSE(p.name.empty());
        EXPECT_FALSE(p.rules.empty()) << p.name;
        total += p.rules.size();
        for (const Rule& r : p.rules) {
            EXPECT_FALSE(r.id.empty());
            EXPECT_FALSE(r.category.empty()) << p.name << "/" << r.id;
            EXPECT_FALSE(r.description.empty())
                << p.name << "/" << r.id << ": a rule an examiner sees needs to say what it is";
        }
    }
    EXPECT_GE(total, 20u);
    Engine e;
    const Status st = Engine::build(packs, e);
    ASSERT_TRUE(st) << st.error;
    EXPECT_GT(e.content_rules(), 0u);
    EXPECT_GT(e.path_rules(), 0u);
}

// The built-in rules against the text they exist for, and against the text
// next to it that they must leave alone.
TEST(Rules, BuiltinRulesFindWhatTheyClaimTo) {
    Engine e;
    ASSERT_TRUE(Engine::build(RulePack::builtin(), e));

    const std::string sample =
        "ifconfig eth0 hw ether 00:1a:2b:3c:4d:5e\n"
        "nameserver 192.168.1.254\n"
        "ssid=\"HomeNet\"\npsk=\"correct horse battery staple\"\n"
        "root:$6$abcdefgh$0123456789abcdefghijklmnopqrstuvwxyzABCDEF:19000:0:99999:7:::\n"
        "contact admin@example.com or https://updates.vendor.example/fw\n"
        "VIN 1HGCM82633A004352\n"
        "AKIAIOSFODNN7EXAMPLE\n";
    const std::vector<Hit> hits = scan(e, sample);
    for (const char* id : {"mac-colon", "ipv4", "wifi-ssid", "wifi-psk", "shadow-hash", "email",
                           "url", "vin", "aws-access-key"})
        EXPECT_TRUE(has(hits, id)) << id << " did not fire on text written for it";

    // And the things that look similar but are not.
    const std::vector<Hit> quiet = scan(e,
                                        "version 1.2.3.4.5 build 999.999.999.999\n"
                                        "sha 00:11:22:33:44:55:66:77\n");
    EXPECT_FALSE(has(quiet, "ipv4")) << "a version string is not an address";
    EXPECT_FALSE(has(quiet, "mac-colon")) << "eight hex pairs are not a MAC";
}

TEST(Rules, BuiltinPathRulesFindTheUsualFiles) {
    Engine e;
    ASSERT_TRUE(Engine::build(RulePack::builtin(), e));
    const auto hit_ids = [&](const char* p) {
        std::vector<Hit> h;
        e.scan_path(p, h);
        return ids(h);
    };
    EXPECT_TRUE(has_id(hit_ids("etc/shadow"), "shadow-file"));
    EXPECT_TRUE(has_id(hit_ids("etc/passwd"), "passwd-file"));
    EXPECT_TRUE(has_id(hit_ids("etc/wpa_supplicant/wpa_supplicant.conf"), "wpa-supplicant-conf"));
    EXPECT_TRUE(has_id(hit_ids("root/.ssh/authorized_keys"), "ssh-authorized-keys"));
    EXPECT_TRUE(hit_ids("usr/bin/busybox").empty());
}
