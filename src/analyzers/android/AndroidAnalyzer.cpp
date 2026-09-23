// AndroidAnalyzer.cpp — the Android platform model.
//
// **This analyzer has never seen a real Android tree.** Every marker and key
// below comes from the documented Android layout and AOSP property names, not
// from evidence: the one Android image this project has access to is the automotive Android unit
// unit's `la_super`, which was on a drive that was disconnected before this
// was written, and no corpus image contains Android (`ro.build.fingerprint`,
// `ro.build.version.release` and `ro.product.manufacturer` all score zero
// across every one of them).
//
// That matters because of what happened to the QNX model, which *was* aimed at
// evidence: the corpus corrected six things the fixtures could not, including
// a Tree bug that silently disabled its strongest marker and a "marker" that
// turned out to be a filesystem artefact. Treat the tiers and the fact keys
// here as a first draft to be checked against `la_super`, not as something
// that has been shown to work. docs/ANALYZERS.md says the same.
//
// Android is Linux, so `rank()` is what makes this win a tree the Linux model
// also matches; see Analyzer::rank.
//
// One thing worth stating because it shapes everything else: an Android device
// is several partitions, not one filesystem. `system`, `vendor`, `product`,
// `system_ext`, `data` and the boot ramdisk each arrive separately, and each
// says something different. The analyzer reports which role a tree looks like
// rather than pretending every Android tree is the same thing.
#include <algorithm>

#include "../Common.h"
#include "omnitrace/analyzers/Platform.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::analyzers {

namespace {

using common::add;

constexpr const char* kCodeDebuggable = "platform-android-debuggable";
constexpr const char* kCodeInsecure = "platform-android-insecure";
constexpr const char* kCodeUnverified = "platform-android-unverified-boot";

// build.prop moved when Android went system-as-root: a mounted system is
// /system/build.prop, but a `system` partition extracted as an image has it at
// its own root. Both are checked because omnitrace hands over whichever the
// reader produced.
const std::vector<std::string>& prop_paths() {
    static const std::vector<std::string> p = {
        "build.prop",     "system/build.prop",     "vendor/build.prop",    "product/build.prop",
        "etc/build.prop", "system_ext/build.prop", "system/etc/build.prop"};
    return p;
}

// Which partition of a device this tree looks like. Saying "android" about a
// `vendor` image and a `data` image alike loses the distinction an examiner
// cares about most: user data is not firmware.
std::string partition_role(const Tree& t) {
    if (t.has_file("system/packages.xml") || t.has_dir("data/data") ||
        t.has_file("system/users/userlist.xml") || t.has_dir("misc/wifi"))
        return "data";
    if (t.has_file("init.rc") || t.has_file("init") || t.has_dir("first_stage_ramdisk"))
        return "ramdisk";
    if (t.has_file("vendor/build.prop") || t.has_dir("lib/hw") || t.has_dir("firmware") ||
        t.has_dir("vendor/firmware"))
        return "vendor";
    if (t.has_file("product/build.prop")) return "product";
    if (t.has_file("system_ext/build.prop")) return "system_ext";
    if (t.has_file("build.prop") || t.has_file("system/build.prop")) return "system";
    return {};
}

class AndroidAnalyzer final : public Analyzer {
   public:
    Platform platform() const override { return Platform::Android; }
    // Android is Linux and must be reported as Android: the Linux model
    // matches an Android tree too, and counting markers cannot settle it.
    unsigned rank() const override { return 2; }

    unsigned detect(const Tree& t) const override {
        // Strong: things only Android has. The same discipline the QNX model
        // needed -- one weak marker must not claim a tree.
        unsigned strong = 0;
        if (!t.first_of(prop_paths()).empty()) ++strong;
        for (const char* p : {"bin/app_process", "bin/app_process32", "bin/app_process64",
                              "system/bin/app_process64", "framework/framework.jar",
                              "system/framework/framework.jar"})
            if (t.has_file(p)) ++strong;
        for (const char* p : {"etc/permissions", "system/etc/permissions", "priv-app",
                              "system/priv-app", "apex", "system/apex"})
            if (t.has_dir(p)) ++strong;
        if (t.has_file("system/packages.xml") || t.has_file("system/users/userlist.xml")) ++strong;
        if (strong == 0) return 0;

        unsigned support = 0;
        for (const char* p : {"app", "system/app", "framework", "system/framework", "etc/init",
                              "system/etc/init", "lib/hw", "vendor/lib/hw", "odm", "data/data",
                              "misc/wifi", "etc/selinux", "system/etc/selinux"})
            if (t.has_dir(p)) ++support;
        for (const char* p : {"bin/toybox", "system/bin/toybox", "bin/toolbox", "init.rc",
                              "etc/selinux/plat_sepolicy.cil"})
            if (t.has_file(p)) ++support;
        return strong * 2 + support;
    }

    void describe(const Tree& t, Report& r) const override {
        const std::string role = partition_role(t);
        if (!role.empty())
            add(r, "android.partition", role, role == "data" ? "data" : "build.prop");
        describe_props(t, r);
        describe_users(t, r);
    }

   private:
    // build.prop is KEY=VALUE, the same shape as os-release. The property
    // names are AOSP's and stable across versions; what a given device
    // actually populates is not, which is why nothing here is required.
    static void describe_props(const Tree& t, Report& r) {
        for (const std::string& path : prop_paths()) {
            if (!t.has_file(path)) continue;
            const auto text = t.read(path, 1U << 20);
            if (!text) continue;
            const auto kv = common::parse_env(*text);
            for (const auto& [from, to] : {std::pair{"ro.build.fingerprint", "os.fingerprint"},
                                           {"ro.build.version.release", "os.version"},
                                           {"ro.build.version.sdk", "os.sdk"},
                                           {"ro.build.version.security_patch", "os.security_patch"},
                                           {"ro.build.id", "build.id"},
                                           {"ro.build.date", "build.date"},
                                           {"ro.build.type", "build.type"},
                                           {"ro.build.tags", "build.tags"},
                                           {"ro.build.flavor", "build.flavor"},
                                           {"ro.product.model", "device.model"},
                                           {"ro.product.manufacturer", "device.manufacturer"},
                                           {"ro.product.brand", "device.brand"},
                                           {"ro.product.device", "device.codename"},
                                           {"ro.product.name", "device.product"},
                                           {"ro.product.cpu.abi", "device.abi"},
                                           {"ro.board.platform", "device.soc"}}) {
                const auto it = kv.find(from);
                if (it != kv.end()) add(r, to, it->second, path);
            }
            // A composed name so the report reads as something, even on a
            // device that populates only half of these.
            const auto brand = kv.find("ro.product.brand");
            const auto model = kv.find("ro.product.model");
            const auto rel = kv.find("ro.build.version.release");
            if (model != kv.end()) {
                std::string pretty =
                    brand != kv.end() ? brand->second + " " + model->second : model->second;
                if (rel != kv.end()) pretty += " (Android " + rel->second + ")";
                add(r, "os.pretty_name", pretty, path);
            }

            // How locked down the device is. These three are the ones that
            // decide whether an examiner can simply ask the device.
            describe_security(kv, path, r);
        }
    }

    static void describe_security(const std::map<std::string, std::string>& kv,
                                  const std::string& path, Report& r) {
        const auto dbg = kv.find("ro.debuggable");
        if (dbg != kv.end()) {
            add(r, "security.debuggable", dbg->second, path);
            if (dbg->second == "1")
                r.diagnostics.push_back(
                    {Severity::Warning, kCodeDebuggable,
                     "ro.debuggable=1: this is an engineering build, adb runs as root and any "
                     "app can be debugged"});
        }
        const auto sec = kv.find("ro.secure");
        if (sec != kv.end()) {
            add(r, "security.secure", sec->second, path);
            if (sec->second == "0")
                r.diagnostics.push_back({Severity::Warning, kCodeInsecure,
                                         "ro.secure=0: adbd does not drop privileges on this "
                                         "build"});
        }
        const auto vbs = kv.find("ro.boot.verifiedbootstate");
        if (vbs != kv.end()) {
            add(r, "security.verified_boot", vbs->second, path);
            // green is the only state that means the bootloader is locked and
            // the image is the vendor's; orange means unlocked.
            if (vbs->second != "green")
                r.diagnostics.push_back(
                    {Severity::Warning, kCodeUnverified,
                     "ro.boot.verifiedbootstate=" + vbs->second +
                         ": the boot chain was not fully verified, so the image on this device "
                         "may not be the vendor's"});
        }
        for (const auto& [from, to] : {std::pair{"ro.build.selinux", "security.selinux"},
                                       {"ro.boot.flash.locked", "security.bootloader_locked"},
                                       {"ro.oem_unlock_supported", "security.oem_unlock"}}) {
            const auto it = kv.find(from);
            if (it != kv.end()) add(r, to, it->second, path);
        }
    }

    // An Android system partition has no passwd file; accounts are AIDs
    // compiled in. What a *data* partition has is the user list, which is what
    // "how many people used this device" means on Android.
    static void describe_users(const Tree& t, Report& r) {
        const std::string users = t.first_of({"system/users/userlist.xml"});
        if (!users.empty()) add(r, "users.list", "present", users);
        const std::vector<std::string> dirs = t.list_dir("system/users");
        unsigned profiles = 0;
        for (const std::string& n : dirs)
            if (!n.empty() && std::all_of(n.begin(), n.end(), [](char c) {
                    return std::isdigit(static_cast<unsigned char>(c)) != 0;
                }))
                ++profiles;
        if (profiles != 0) add(r, "users.count", std::to_string(profiles), "system/users");
        if (t.has_file("system/packages.xml"))
            add(r, "apps.packages_xml", "present", "system/packages.xml");
        const std::vector<std::string> apps = t.list_dir("data");
        if (!apps.empty()) add(r, "apps.data_dirs", std::to_string(apps.size()), "data");
    }
};

}  // namespace

OMNITRACE_REGISTER_ANALYZER(Platform::Android, AndroidAnalyzer);

}  // namespace omnitrace::analyzers

namespace omnitrace::analyzers::detail {
void omnitrace_analyzer_anchor_android() {}
}  // namespace omnitrace::analyzers::detail
