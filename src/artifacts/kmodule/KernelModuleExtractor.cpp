// KernelModuleExtractor.cpp — what a Linux kernel module says about itself.
//
// A module is an ELF relocatable object with a `.modinfo` section holding
// NUL-separated `key=value` records. That section is the whole point of this
// extractor: it is where a driver states what hardware it is for, who wrote
// it, what licence it ships under and which kernel it was built against.
//
// The Linux analyzer already counts modules and names them
// (`docs/ANALYZERS.md`), which answers "how many drivers and what are they
// called". It cannot answer "what is this driver *for*" without opening every
// one of them, and an analyzer that read two hundred files to describe a
// platform would be doing an extractor's job. So it corroborates a version and
// stops; this parses the section properly, from the raw bytes, one record per
// module.
#include <algorithm>
#include <map>
#include <string>
#include <vector>

#include "omnitrace/artifacts/Artifact.h"
#include "omnitrace/core/Elf.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::artifacts {

namespace {

constexpr const char* kCodeStaleModule = "kmodule-vermagic-path-mismatch";
constexpr const char* kCodeProprietary = "kmodule-proprietary-license";

// Keys worth a column. `alias` and `parm` repeat and are counted rather than
// listed: a wireless driver carries hundreds of aliases and a table of them is
// not a report.
constexpr std::string_view kSuffix = ".ko";

bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

/// `.modinfo` is NUL-separated `key=value`. Repeats are normal (`alias` and
/// `parm` especially), so the first wins for single-valued keys and the rest
/// are counted.
struct ModInfo {
    std::map<std::string, std::string> single;
    std::map<std::string, unsigned> repeats;
};

ModInfo parse_modinfo(std::span<const std::uint8_t> sec) {
    ModInfo mi;
    std::size_t i = 0;
    while (i < sec.size()) {
        std::size_t end = i;
        while (end < sec.size() && sec[end] != 0) ++end;
        const std::string_view rec(reinterpret_cast<const char*>(sec.data() + i), end - i);
        i = end + 1;
        if (rec.empty()) continue;
        const std::size_t eq = rec.find('=');
        if (eq == std::string_view::npos) continue;
        const std::string key(rec.substr(0, eq));
        std::string value = sanitize_utf8(rec.substr(eq + 1));
        if (value.size() > 300) value.resize(300);
        ++mi.repeats[key];
        if (mi.single.find(key) == mi.single.end()) mi.single.emplace(key, std::move(value));
    }
    return mi;
}

/// "4.14.63" out of "lib/modules/4.14.63/kernel/net/foo.ko"; empty when the
/// path is not under a release directory.
std::string release_from_path(const std::string& path) {
    static constexpr std::string_view kRoot = "lib/modules/";
    const std::size_t at = path.find(kRoot);
    if (at == std::string::npos) return {};
    const std::size_t from = at + kRoot.size();
    const std::size_t slash = path.find('/', from);
    if (slash == std::string::npos) return {};
    return path.substr(from, slash - from);
}

/// The leading digits-and-dots of a vermagic string.
std::string leading_version(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size() && ((s[i] >= '0' && s[i] <= '9') || s[i] == '.')) ++i;
    return std::string(s.substr(0, i));
}

class KernelModuleExtractor final : public Extractor {
   public:
    std::string name() const override { return "kmodule"; }

    bool applies(std::string_view path, std::span<const std::uint8_t> head) const override {
        // A path test first, because it is free and names all but the odd
        // case. `.ko.gz`/`.ko.xz`/`.ko.zst` are modules too but are not ELF
        // until something decompresses them; the nested analysis does that and
        // the payload arrives here on its own, so they are deliberately not
        // matched by name (docs/ARTIFACTS.md, known gaps).
        if (ends_with(path, kSuffix)) return true;
        // An ELF under lib/modules that is not called .ko is still a module on
        // some vendor builds.
        if (head.size() >= 4 && head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' &&
            head[3] == 'F')
            return path.find("lib/modules/") != std::string_view::npos;
        return false;
    }

    void extract(const FileRef& file, Yield& out) const override {
        const auto header = elf::parse_header(file.bytes);
        if (!header) return;  // named .ko but not an ELF: not this extractor's file
        const std::span<const std::uint8_t> sec = elf::section(file.bytes, *header, ".modinfo");
        if (sec.empty()) return;  // an ELF with no .modinfo is not a module
        const ModInfo mi = parse_modinfo(sec);
        if (mi.single.empty()) return;

        Artifact a;
        a.kind = "kernel-module";
        a.node = file.node;
        a.path = file.path;

        // `name=` is not always written; the file name is the fallback and is
        // what modprobe would use anyway.
        std::string mod = value(mi, "name");
        if (mod.empty()) {
            mod = file.path.substr(file.path.rfind('/') + 1);
            const std::size_t dot = mod.find(".ko");
            if (dot != std::string::npos) mod.resize(dot);
        }
        a.fields["module"] = mod;
        // A module is the same module in another case when it drives the same
        // hardware, which is its name -- not its path, which carries the
        // kernel release, and not its bytes, which change on every rebuild.
        a.identity = mod;
        for (const auto& [key, field] : {std::pair{"description", "description"},
                                         {"license", "license"},
                                         {"author", "author"},
                                         {"depends", "depends"},
                                         {"vermagic", "vermagic"},
                                         {"firmware", "firmware"},
                                         {"srcversion", "srcversion"}}) {
            const std::string v = value(mi, key);
            if (!v.empty()) a.fields[field] = v;
        }
        a.fields["arch"] = elf::machine_name(header->machine);
        // Aliases are how the kernel matches a module to hardware, so the
        // count is a rough measure of how much this driver claims to drive.
        if (const auto it = mi.repeats.find("alias"); it != mi.repeats.end())
            a.fields["aliases"] = std::to_string(it->second);
        if (const auto it = mi.repeats.find("parm"); it != mi.repeats.end())
            a.fields["parameters"] = std::to_string(it->second);

        // A licence that is not GPL-compatible means the source was never
        // published, which is worth an examiner's attention on a device whose
        // firmware is supposed to be.
        const std::string lic = value(mi, "license");
        if (!lic.empty() && lic.find("GPL") == std::string::npos &&
            lic.find("BSD") == std::string::npos && lic.find("MIT") == std::string::npos &&
            lic.find("Dual") == std::string::npos) {
            a.severity = Severity::Info;
            out.diagnostics.push_back({Severity::Info, kCodeProprietary,
                                       "'" + file.path + "' is licensed '" + lic +
                                           "': a binary-only driver, so its source is not public"});
        }

        // The same disagreement the analyzer reports, said once per module
        // here rather than once per filesystem: this names *which* module is
        // the odd one out, which is what an examiner needs to act on it.
        const std::string vm = value(mi, "vermagic");
        const std::string on_disk = release_from_path(file.path);
        if (!vm.empty() && !on_disk.empty()) {
            const std::string built = leading_version(vm);
            if (!built.empty() && built != on_disk) {
                a.severity = Severity::Warning;
                out.diagnostics.push_back({Severity::Warning, kCodeStaleModule,
                                           "'" + file.path + "' was built for kernel " + built +
                                               " but is installed under " + on_disk +
                                               "; it cannot load there"});
            }
        }
        out.artifacts.push_back(std::move(a));
    }

   private:
    static std::string value(const ModInfo& mi, std::string_view key) {
        const auto it = mi.single.find(std::string(key));
        return it == mi.single.end() ? std::string{} : it->second;
    }
};

}  // namespace

OMNITRACE_REGISTER_EXTRACTOR("kmodule", KernelModuleExtractor);

}  // namespace omnitrace::artifacts

namespace omnitrace::artifacts::detail {
void omnitrace_extractor_anchor_kmodule() {}
}  // namespace omnitrace::artifacts::detail
