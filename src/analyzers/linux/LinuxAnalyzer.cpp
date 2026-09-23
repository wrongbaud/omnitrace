// LinuxAnalyzer.cpp — the Linux platform model.
//
// Detection is a count of markers that a Linux root filesystem has and almost
// nothing else does. It is deliberately not "does /etc exist": a QNX IFS has
// /etc too, and so does half of everything. The markers below are the ones
// that survived being aimed at the corpus -- OpenWrt on three different
// routers, which is what embedded Linux overwhelmingly is.
//
// What it reports is what the system says about *itself*, each fact naming the
// file it was read from so an examiner can open that file and disagree. It
// parses nothing it does not have to: os-release and the OpenWrt release files
// are KEY=VALUE, passwd and shadow are colon-separated, and that is the whole
// of it. Anything richer belongs in an artifact extractor.
#include <algorithm>

#include "../Common.h"
#include "omnitrace/analyzers/Platform.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::analyzers {

namespace {

using common::add;
using common::for_each_line;
using common::parse_env;

constexpr const char* kCodeNoRelease = "platform-linux-no-release";
constexpr const char* kCodeShadowUnreadable = "platform-shadow-unreadable";

class LinuxAnalyzer final : public Analyzer {
   public:
    Platform platform() const override { return Platform::Linux; }
    unsigned rank() const override { return 1; }

    unsigned detect(const Tree& t) const override {
        // At least one thing that is a Linux *system*, not merely a directory
        // a Linux system also has. The QNX model needed this rule and so does
        // this one: `proc/` and `usr/lib` alone describe half the partitions
        // on a device, and claiming a tree on one of them buries the images
        // that really are systems.
        unsigned strong = 0;
        for (const char* p : {"etc/passwd", "etc/inittab", "etc/fstab", "etc/shadow", "bin/busybox",
                              "sbin/init", "bin/sh"})
            if (t.has_file(p)) ++strong;
        for (const char* p : {"etc/init.d", "etc/rc.d", "etc/systemd/system"})
            if (t.has_dir(p)) ++strong;
        if (!t.first_of({"etc/os-release", "usr/lib/os-release", "etc/openwrt_release",
                         "etc/lsb-release"})
                 .empty())
            strong += 2;
        if (strong == 0) return 0;

        unsigned support = 0;
        for (const char* p : {"etc/group", "etc/hostname", "etc/resolv.conf", "usr/bin/env",
                              "lib/ld.so.1", "etc/hosts"})
            if (t.has_file(p)) ++support;
        for (const char* p : {"proc", "sys", "usr/lib", "var/log", "etc/network", "usr/bin"})
            if (t.has_dir(p)) ++support;
        return strong * 2 + support;
    }

    void describe(const Tree& t, Report& r) const override {
        describe_os(t, r);
        describe_users(t, r);
        describe_network(t, r);
        describe_services(t, r);
    }

   private:
    // What the distribution calls itself. os-release is the standard and is
    // usually a symlink into /usr/lib; OpenWrt also writes its own file, and
    // on the IP cameras that is the *only* one there is.
    static void describe_os(const Tree& t, Report& r) {
        const std::string rel =
            t.first_of({"etc/os-release", "usr/lib/os-release", "etc/lsb-release"});
        if (!rel.empty()) {
            if (const auto text = t.read(rel, 64 * 1024)) {
                const auto kv = parse_env(*text);
                for (const auto& [from, to] : {std::pair{"PRETTY_NAME", "os.pretty_name"},
                                               {"NAME", "os.name"},
                                               {"ID", "os.id"},
                                               {"VERSION", "os.version"},
                                               {"VERSION_ID", "os.version_id"},
                                               {"BUILD_ID", "os.build_id"},
                                               {"DISTRIB_DESCRIPTION", "os.pretty_name"},
                                               {"DISTRIB_ID", "os.name"},
                                               {"DISTRIB_RELEASE", "os.version"}}) {
                    const auto it = kv.find(from);
                    if (it != kv.end()) add(r, to, it->second, rel);
                }
            }
        }
        // OpenWrt's own release file carries the target and architecture,
        // which os-release does not, and names the exact build.
        const std::string owrt = t.first_of({"etc/openwrt_release"});
        if (!owrt.empty()) {
            if (const auto text = t.read(owrt, 64 * 1024)) {
                const auto kv = parse_env(*text);
                for (const auto& [from, to] : {std::pair{"DISTRIB_DESCRIPTION", "os.pretty_name"},
                                               {"DISTRIB_ID", "os.name"},
                                               {"DISTRIB_RELEASE", "os.version"},
                                               {"DISTRIB_REVISION", "os.build_id"},
                                               {"DISTRIB_TARGET", "os.target"},
                                               {"DISTRIB_ARCH", "os.arch"}}) {
                    const auto it = kv.find(from);
                    if (it != kv.end()) add(r, to, it->second, owrt);
                }
            }
        }
        if (rel.empty() && owrt.empty())
            r.diagnostics.push_back(
                {Severity::Info, kCodeNoRelease,
                 "no os-release, lsb-release or openwrt_release: the system does not say what "
                 "distribution it is, so the version has to come from a banner or a binary"});

        if (const auto host = t.read("etc/hostname", 256))
            add(r, "os.hostname", sanitize_utf8(*host).substr(0, 128), "etc/hostname");
        // The banner is where OpenWrt prints its version at login, and on a
        // vendor build it is often the only place the vendor's own name shows.
        // The banner is where OpenWrt prints its version at login, and on a
        // vendor build it is often the only place the vendor's own name shows.
        // It is also mostly ASCII art, so the line worth keeping is one that
        // carries a version: letters and digits together. "W I R E L E S S
        // F R E E D O M" is the trap -- it is almost all letters and says
        // nothing.
        if (const auto banner = t.read("etc/banner", 8 * 1024)) {
            std::string best;
            for_each_line(*banner, [&](std::string_view line) {
                if (!best.empty()) return;
                const bool has_alpha = std::any_of(line.begin(), line.end(), [](char c) {
                    return std::isalpha(static_cast<unsigned char>(c)) != 0;
                });
                const bool has_digit = std::any_of(line.begin(), line.end(), [](char c) {
                    return std::isdigit(static_cast<unsigned char>(c)) != 0;
                });
                if (has_alpha && has_digit) best = std::string(line);
            });
            // Trim the decoration a banner line is usually wrapped in.
            while (!best.empty() && (best.front() == ' ' || best.front() == '-')) best.erase(0, 1);
            while (!best.empty() && (best.back() == ' ' || best.back() == '-')) best.pop_back();
            add(r, "os.banner", best.substr(0, 200), "etc/banner");
        }
    }

    // Accounts, and whether they could be logged into. The hash itself is
    // never reported: an examiner wants to know a hash exists and how weak it
    // is, and a report that quoted it would be a credential store.
    static void describe_users(const Tree& t, Report& r) {
        const auto passwd = t.read("etc/passwd", 4U << 20);
        if (!passwd) return;
        const bool have_shadow = t.has_file("etc/shadow");
        unsigned accounts = 0, uid0 = 0;
        for_each_line(*passwd, [&](std::string_view line) {
            if (line.front() == '#') return;
            const auto f = common::split_colons(line);
            if (f.size() < 7) return;
            ++accounts;
            if (f[2] == "0") {
                ++uid0;
                add(r, "user.uid0", std::string(f[0]), "etc/passwd");
            }
        });
        add(r, "users.count", std::to_string(accounts), "etc/passwd");
        if (uid0 > 1) add(r, "users.uid0_count", std::to_string(uid0), "etc/passwd");

        const auto pw = common::describe_password_file(t, r, "etc/passwd", /*is_shadow=*/false);
        // Counts come from shadow when there is one; see add_password_counts.
        if (!have_shadow) {
            common::add_password_counts(r, pw, "etc/passwd");
            return;
        }
        if (!t.read("etc/shadow", 1)) {
            r.diagnostics.push_back({Severity::Warning, kCodeShadowUnreadable,
                                     "etc/shadow is listed but its bytes could not be read back, "
                                     "so account password state is unknown"});
            return;
        }
        const auto sh = common::describe_password_file(t, r, "etc/shadow", /*is_shadow=*/true);
        common::add_password_counts(r, sh, "etc/shadow");
    }

    static void describe_network(const Tree& t, Report& r) {
        // OpenWrt keeps its configuration in UCI files rather than the
        // Debian-style ones, and an embedded case is far more likely to have
        // the former.
        for (const auto& [path, key] : {std::pair{"etc/config/network", "network.uci"},
                                        {"etc/config/wireless", "network.wireless_uci"},
                                        {"etc/network/interfaces", "network.interfaces"}})
            if (t.has_file(path)) add(r, key, "present", path);
        if (const auto resolv = t.read("etc/resolv.conf", 8 * 1024)) {
            std::string servers;
            for_each_line(*resolv, [&](std::string_view line) {
                if (line.rfind("nameserver", 0) != 0) return;
                std::string_view v = line.substr(10);
                while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
                if (v.empty()) return;
                if (!servers.empty()) servers += ",";
                servers.append(v);
            });
            add(r, "network.nameservers", servers, "etc/resolv.conf");
        }
    }

    static void describe_services(const Tree& t, Report& r) {
        // What starts at boot is the shape of the system: an init.d listing is
        // a service inventory an examiner can read at a glance.
        for (const char* dir : {"etc/init.d", "etc/rc.d", "etc/systemd/system"}) {
            const std::vector<std::string> names = t.list_dir(dir);
            if (names.empty()) continue;
            add(r, "init.dir", dir, dir);
            add(r, "init.count", std::to_string(names.size()), dir);
            std::string joined;
            for (const std::string& n : names) {
                if (joined.size() > 400) {
                    joined += ",...";
                    break;
                }
                if (!joined.empty()) joined += ",";
                joined += n;
            }
            add(r, "init.services", joined, dir);
            break;
        }
        if (t.has_file("bin/busybox")) add(r, "userland.busybox", "present", "bin/busybox");
        for (const char* p : {"usr/sbin/dropbear", "sbin/dropbear", "usr/sbin/sshd"})
            if (t.has_file(p)) add(r, "service.ssh", p, p);
        for (const char* p : {"usr/sbin/telnetd", "sbin/telnetd"})
            if (t.has_file(p)) add(r, "service.telnet", p, p);
    }
};

}  // namespace

OMNITRACE_REGISTER_ANALYZER(Platform::Linux, LinuxAnalyzer);

}  // namespace omnitrace::analyzers

namespace omnitrace::analyzers::detail {
void omnitrace_analyzer_anchor_linux() {}
}  // namespace omnitrace::analyzers::detail
