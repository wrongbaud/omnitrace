// QnxAnalyzer.cpp — the QNX Neutrino platform model.
//
// QNX outranks Linux deliberately. A QNX root has `etc/passwd`, `etc/group`,
// `etc/shadow`, `proc/` and `usr/lib`, so the Linux analyzer scores five
// markers on one and would happily call it Linux -- measured on the automotive Android unit's
// IFS images, which is what `Analyzer::rank` exists for. Counting markers
// cannot settle it; being the more specific answer can.
//
// The markers below are things a QNX system has and a Linux one does not, and
// they come from two real IFS images on that unit: a 49-entry boot IFS and a
// 726-entry system one. The most reliable family is the resource managers --
// QNX names its drivers `devb-*` (block), `devc-*` (character) and `io-*`
// (stacks), and no Linux system has a `devb-umass` or an `io-pkt`.
#include <algorithm>
#include <optional>

#include "../Common.h"
#include "omnitrace/analyzers/Platform.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::analyzers {

namespace {

using common::add;
using common::for_each_line;

constexpr const char* kCodeInsecureService = "platform-qnx-insecure-service";
constexpr const char* kCodeNoSecpol = "platform-qnx-no-security-policy";
constexpr const char* kCodeNoShadow = "platform-shadow-absent";

// QNX names its resource managers by role: devb- block drivers, devc-
// character drivers, io- stacks (io-pkt, io-usb-otg, io-hid, io-audio). A
// directory holding several is QNX and nothing else.
unsigned resource_managers(const Tree& t, const char* dir) {
    unsigned n = 0;
    for (const std::string& name : t.list_dir(dir)) {
        if (name.rfind("devb-", 0) == 0 || name.rfind("devc-", 0) == 0 || name.rfind("io-", 0) == 0)
            ++n;
    }
    return n;
}

class QnxAnalyzer final : public Analyzer {
   public:
    Platform platform() const override { return Platform::Qnx; }
    // Above Linux: see the file comment. A QNX tree matches both, and this is
    // the more precise answer.
    unsigned rank() const override { return 2; }

    unsigned detect(const Tree& t) const override {
        // `.boot` is deliberately not a marker. Every QNX6 *filesystem* has an
        // empty `.boot` directory at its root -- it is where the boot file
        // lives -- so it says the partition is QNX6, which discovery already
        // reports as the format, and says nothing about whether a *system* is
        // on it. Using it claimed five pure data partitions in the QNX corpus
        // image (`deviceInfo/DID/keymgr-store`, `bt/dbus/IPC/mdnsd`) as QNX
        // systems, each on that one marker and with no facts to show for it.
        unsigned strong = 0;
        // The IFS is mounted at /proc/boot, and only a system has one.
        if (t.has_dir("proc/boot")) ++strong;
        if (t.has_dir("etc/system/config")) ++strong;
        if (t.has_file("usr/sbin/qconn") || t.has_file("bin/qconn")) ++strong;
        if (t.has_file("etc/secpolgenerate.cfg") || t.has_file("lib64/libsecpol.so")) ++strong;
        // QNX names its resource managers by role: devb- block drivers, devc-
        // character drivers, io- stacks. Several together are QNX and nothing
        // else, wherever they live.
        unsigned rm = 0;
        for (const char* dir : {"sbin", "bin", "proc/boot", "usr/sbin"})
            rm += resource_managers(t, dir);
        if (rm >= 2) ++strong;

        // Nothing only QNX has: say nothing. A tree that merely sits on a QNX
        // device is not a QNX system, and reporting it as one buries the
        // images that are.
        if (strong == 0) return 0;

        unsigned support = 0;
        for (const char* p : {"bin/ksh", "bin/slogger2", "bin/secpol", "bin/secpolgenerate",
                              "bin/on", "sbin/chkqnx6fs", "sbin/mkqnx6fs", "etc/nopasswd",
                              "etc/inetd.conf", "lib64/libslog2.so.1", "lib/libslog2.so.1"})
            if (t.has_file(p)) ++support;
        for (const char* p : {"proc/boot", "etc/system", "etc/system/config"})
            if (t.has_dir(p)) ++support;
        return strong * 2 + support + std::min(rm, 8U);
    }

    void describe(const Tree& t, Report& r) const override {
        describe_build(t, r);
        describe_users(t, r);
        describe_services(t, r);
        describe_security(t, r);
    }

   private:
    // QNX itself carries no os-release. What a shipped unit does carry is the
    // integrator's build manifest, and on the automotive Android unit that is the single most
    // identifying file on the system: product, build id, timestamp, and
    // whether secure boot was on.
    static void describe_build(const Tree& t, Report& r) {
        const std::string path = t.first_of({"Buildinfo.txt", "etc/Buildinfo.txt", "build.txt"});
        if (path.empty()) return;
        const auto text = t.read(path, 64 * 1024);
        if (!text) return;
        const auto kv = common::parse_env(*text);
        for (const auto& [from, to] : {std::pair{"BUILD_ID", "build.id"},
                                       {"BUILD_TIMESTAMP", "build.timestamp"},
                                       {"TARGET_PRODUCT", "build.product"},
                                       {"TARGET_BUILD_VARIANT", "build.variant"},
                                       {"SECURE_BOOT", "build.secure_boot"},
                                       {"QC_PRODUCT", "build.soc"},
                                       {"QC_DISTRIBUTION", "build.soc_distribution"},
                                       {"MANIFESTS_REVISION", "build.manifest_revision"}}) {
            const auto it = kv.find(from);
            if (it != kv.end()) add(r, to, it->second, path);
        }
        // Integrator keys are vendor-specific and there is no point guessing
        // at their names; anything dotted under a vendor prefix is passed
        // through so an automotive Android unit or another vendor build number is not silently dropped.
        for (const auto& [k, v] : kv) {
            if (k.find('.') == std::string::npos) continue;
            // Only the vendor's own key is flattened; the dots in the
            // "build.vendor." prefix are the report's own structure.
            std::string leaf = k;
            std::replace(leaf.begin(), leaf.end(), '.', '_');
            add(r, "build.vendor." + leaf, v, path);
        }
    }

    static void describe_users(const Tree& t, Report& r) {
        // On an IFS the accounts live in the boot image, not in /etc: the automotive QNX unit
        // unit in the QNX corpus has proc/boot/passwd and proc/boot/group and
        // an empty /etc, so looking only at etc/passwd reported nothing at all
        // about a 945-entry system.
        const std::string pw = t.first_of({"etc/passwd", "proc/boot/passwd"});
        const std::string sh = t.first_of({"etc/shadow", "proc/boot/shadow"});
        if (pw.empty() && sh.empty()) return;
        const auto passwd = pw.empty() ? std::nullopt : t.read(pw, 4U << 20);
        if (passwd) {
            unsigned accounts = 0, uid0 = 0;
            for_each_line(*passwd, [&](std::string_view line) {
                if (line.front() == '#') return;
                const auto f = common::split_colons(line);
                if (f.size() < 3) return;
                ++accounts;
                if (f[2] == "0") {
                    ++uid0;
                    add(r, "user.uid0", std::string(f[0]), pw);
                }
            });
            add(r, "users.count", std::to_string(accounts), pw);
            if (uid0 > 1) add(r, "users.uid0_count", std::to_string(uid0), pw);
        }
        if (!pw.empty()) {
            const auto tally = common::describe_password_file(t, r, pw, /*is_shadow=*/false);
            // Counts come from shadow when there is one; see add_password_counts.
            if (sh.empty()) common::add_password_counts(r, tally, pw);
            // `x` with no shadow file anywhere in the image means the secrets
            // are in a file this extraction does not have, which is worth
            // saying once rather than once per account.
            if (sh.empty() && tally.by_kind.count("in-shadow") != 0)
                r.diagnostics.push_back(
                    {Severity::Info, kCodeNoShadow,
                     std::to_string(tally.by_kind.at("in-shadow")) + " account(s) in " + pw +
                         " defer to a shadow file, and no shadow file is present in this image"});
        }
        if (!sh.empty()) {
            const auto tally = common::describe_password_file(t, r, sh, /*is_shadow=*/true);
            common::add_password_counts(r, tally, sh);
        }
        // QNX ships a second passwd-shaped file for accounts that need no
        // password, and it is exactly as load-bearing as it sounds: on the automotive Android unit
        // unit it holds `root::0:0:Superuser`. describe_password_file reports
        // every empty field it finds, so the diagnostics come out naming this
        // file rather than etc/passwd.
        if (t.has_file("etc/nopasswd"))
            common::describe_password_file(t, r, "etc/nopasswd", /*is_shadow=*/false);
    }

    // What the system offers on the network, and as whom. inetd.conf lines are
    // `service socket proto wait user program args`, and the user field is the
    // half that matters.
    static void describe_services(const Tree& t, Report& r) {
        const std::string inetd_path = t.first_of({"etc/inetd.conf", "proc/boot/inetd.conf"});
        const auto inetd = inetd_path.empty() ? std::nullopt : t.read(inetd_path, 256 * 1024);
        if (inetd) {
            std::string enabled;
            for_each_line(*inetd, [&](std::string_view line) {
                if (line.front() == '#') return;
                std::vector<std::string> words;
                std::size_t pos = 0;
                while (pos < line.size()) {
                    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) ++pos;
                    const std::size_t start = pos;
                    while (pos < line.size() && line[pos] != ' ' && line[pos] != '\t') ++pos;
                    if (pos > start) words.emplace_back(line.substr(start, pos - start));
                }
                if (words.size() < 6) return;
                const std::string& service = words[0];
                const std::string& user = words[4];
                if (!enabled.empty()) enabled += ",";
                enabled += service;
                add(r, "service." + service, user, inetd_path);
                // telnet, rsh and ftp carry credentials in clear text. Enabled
                // and running as root, they are the way into the unit.
                if (service == "telnet" || service == "shell" || service == "login" ||
                    service == "ftp" || service == "exec")
                    r.diagnostics.push_back(
                        {Severity::Warning, kCodeInsecureService,
                         inetd_path + " enables '" + service + "' as " + user +
                             "; it carries credentials in clear text and accepts them over the "
                             "network"});
            });
            add(r, "services.inetd", enabled, inetd_path);
        }
        if (t.has_file("etc/ftpusers")) add(r, "service.ftpusers", "present", "etc/ftpusers");
        for (const char* p : {"usr/sbin/sshd", "bin/sshd"})
            if (t.has_file(p)) add(r, "service.sshd", p, p);
        if (t.has_file("usr/sbin/qconn") || t.has_file("bin/qconn"))
            r.diagnostics.push_back({Severity::Warning, kCodeInsecureService,
                                     "qconn is present: the QNX remote debug agent gives "
                                     "unauthenticated control of the target when it is running"});
    }

    // QNX 7 can confine every process with a security policy. Whether one is
    // present, and whether the build claims secure boot, are the two questions
    // worth answering about how locked down a unit is.
    static void describe_security(const Tree& t, Report& r) {
        unsigned policies = 0;
        for (const std::string& name : t.list_dir("proc/boot"))
            if (name.rfind("secpol", 0) == 0) ++policies;
        const bool tooling = t.has_file("bin/secpol") || t.has_file("etc/secpolgenerate.cfg") ||
                             t.has_file("lib64/libsecpol.so");
        if (policies != 0) add(r, "security.secpol_files", std::to_string(policies), "proc/boot");
        if (tooling) add(r, "security.secpol", "present", "etc/secpolgenerate.cfg");
        if (policies == 0 && !tooling)
            r.diagnostics.push_back(
                {Severity::Info, kCodeNoSecpol,
                 "no QNX security policy files or tooling found, so processes are not confined "
                 "by one on this image"});
        if (t.has_dir("var/chroot") || t.has_dir("chroot"))
            add(r, "security.chroot", "present", "var/chroot");
    }
};

}  // namespace

OMNITRACE_REGISTER_ANALYZER(Platform::Qnx, QnxAnalyzer);

}  // namespace omnitrace::analyzers

namespace omnitrace::analyzers::detail {
void omnitrace_analyzer_anchor_qnx() {}
}  // namespace omnitrace::analyzers::detail
