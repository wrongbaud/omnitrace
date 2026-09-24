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
#include <cctype>
#include <map>
#include <set>

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
constexpr const char* kCodeKernelMismatch = "platform-linux-kernel-mismatch";
constexpr const char* kCodeKernelMulti = "platform-linux-multiple-kernels";

// Modules are ELF, and their `.modinfo` section is NUL-separated `key=value`.
// Reading that section properly means parsing section headers; the analyzer
// wants one field out of one module to corroborate a version it already has,
// so it looks the key up in the bytes instead. A wrong answer here is an
// unrecognised vermagic, never a wrong kernel version: the version comes from
// the directory name and this only agrees or disagrees with it. `artifacts`
// parses the real section out of the raw bytes (docs/ARTIFACTS.md).
//
// `Tree::read` hands back text that has been through `sanitize_utf8`, so the
// NUL between records arrives as the four characters `\x00` rather than a
// byte. That is what separates a record here, and it is also what makes the
// boundary check exact -- `depends=` must not match inside `pre_depends=`.
constexpr std::string_view kNulEscape = "\\x00";

std::string modinfo_value(const std::string& text, std::string_view key) {
    const std::string needle = std::string(key) + "=";
    std::size_t at = text.find(needle);
    while (at != std::string::npos) {
        const bool at_record_start =
            at == 0 || (at >= kNulEscape.size() &&
                        text.compare(at - kNulEscape.size(), kNulEscape.size(), kNulEscape) == 0);
        if (at_record_start) {
            const std::size_t from = at + needle.size();
            std::size_t end = text.find(kNulEscape, from);
            if (end == std::string::npos) end = text.size();
            std::string v = text.substr(from, std::min<std::size_t>(end - from, 200));
            while (!v.empty() && (v.back() == ' ' || v.back() == '\n')) v.pop_back();
            return v;
        }
        at = text.find(needle, at + 1);
    }
    return {};
}

// "4.14.63" out of "lib/modules/4.14.63/kernel/net/foo.ko", and out of a
// vermagic string like "5.4.55 SMP mod_unload ARMv7 p2v8".
std::string leading_version(std::string_view s) {
    std::size_t i = 0;
    while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])) != 0 || s[i] == '.'))
        ++i;
    return std::string(s.substr(0, i));
}

constexpr std::string_view kModulesRoot = "lib/modules";

// A module file, compressed or not. Every layout in the corpus uses one of
// these four.
bool is_module(std::string_view path) {
    for (const char* ext : {".ko", ".ko.gz", ".ko.xz", ".ko.zst"}) {
        const std::string_view e(ext);
        if (path.size() > e.size() && path.compare(path.size() - e.size(), e.size(), e) == 0)
            return true;
    }
    return false;
}

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
        describe_kernel(t, r);
        describe_users(t, r);
        describe_network(t, r);
        describe_services(t, r);
    }

   private:
    // The kernel a system was built to run, and the drivers it carries.
    //
    // `lib/modules/<release>/` is the answer for both: the directory name *is*
    // `uname -r`, and everything under it is the module set. That beats every
    // other source available inside a root filesystem -- the "Linux version"
    // banner lives in the kernel image, which is a different node entirely
    // (`docs/ANALYZERS.md`), and os-release says nothing about the kernel.
    //
    // A module's `vermagic` is then a second, independent witness. Agreement
    // is worth nothing to report and disagreement is worth a lot: modules
    // built against a different kernel than the one installed will not load,
    // and on a device that is usually a vendor having shipped a mismatched
    // update.
    static void describe_kernel(const Tree& t, Report& r) {
        // Both sources for the release name, because either one alone has a
        // hole. `list_dir` sees only directories the listing records, and an
        // archive built without directory members has none; the paths of the
        // modules themselves always name the release, but a release directory
        // holding no modules has no paths. The union has neither hole.
        std::set<std::string> found;
        for (const std::string& d : t.list_dir("lib/modules")) found.insert(d);
        for (const std::string& f : t.files_under("lib/modules")) {
            const std::string_view rest(f.c_str() + kModulesRoot.size() + 1);
            const std::size_t slash = rest.find('/');
            if (slash != std::string_view::npos) found.emplace(rest.substr(0, slash));
        }
        const std::vector<std::string> releases(found.begin(), found.end());
        std::string release;
        if (releases.size() == 1) {
            release = releases.front();
        } else if (releases.size() > 1) {
            // More than one is normal on a system that kept an old kernel, and
            // it means "which one is running" is not a question this can
            // answer from the filesystem alone.
            std::string all;
            for (const std::string& v : releases) {
                if (!all.empty()) all += ",";
                all += v;
            }
            add(r, "kernel.versions", all.substr(0, 200), "lib/modules");
            r.diagnostics.push_back({Severity::Info, kCodeKernelMulti,
                                     "lib/modules holds " + std::to_string(releases.size()) +
                                         " kernel release(s) (" + all.substr(0, 120) +
                                         "); which one boots is not recorded in the filesystem"});
            release = releases.back();  // the newest by sort order, reported as one of several
        }
        if (release.empty()) return;

        const std::string root = std::string(kModulesRoot) + "/" + release;
        add(r, "kernel.version", release, root);

        const std::vector<std::string> under = t.files_under(root);
        std::vector<std::string> modules;
        std::map<std::string, unsigned> by_subsystem;
        for (const std::string& p : under) {
            if (!is_module(p)) continue;
            modules.push_back(p);
            // `kernel/drivers/net/wireless/foo.ko` -> `drivers/net/wireless`.
            // A flat layout (OpenWrt installs every module in one directory)
            // has no such path and is not guessed at from the module name.
            const std::size_t k = p.find("/kernel/");
            if (k == std::string::npos) continue;
            const std::size_t from = k + 8;
            const std::size_t slash = p.rfind('/');
            if (slash != std::string::npos && slash > from)
                ++by_subsystem[p.substr(from, slash - from)];
        }
        add(r, "kernel.modules.count", std::to_string(modules.size()), root);
        describe_builtin(t, r, root);
        if (modules.empty()) return;

        if (!by_subsystem.empty()) {
            std::vector<std::pair<std::string, unsigned>> sorted(by_subsystem.begin(),
                                                                 by_subsystem.end());
            std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
                return a.second != b.second ? a.second > b.second : a.first < b.first;
            });
            std::string joined;
            for (const auto& [dir, n] : sorted) {
                if (joined.size() > 400) {
                    joined += ",...";
                    break;
                }
                if (!joined.empty()) joined += ",";
                joined += dir + "=" + std::to_string(n);
            }
            add(r, "kernel.modules.subsystems", joined, root);
        }

        // The names themselves, which is what "what drivers are present"
        // actually asks. Capped like every other list here; the full
        // inventory, with each module's own description, is what the
        // `kmodule` extractor produces (docs/ARTIFACTS.md).
        std::string names;
        for (const std::string& p : modules) {
            std::string base = p.substr(p.rfind('/') + 1);
            const std::size_t dot = base.find(".ko");
            if (dot != std::string::npos) base.resize(dot);
            if (names.size() > 600) {
                names += ",...";
                break;
            }
            if (!names.empty()) names += ",";
            names += base;
        }
        add(r, "kernel.modules.names", names, root);

        // One module's vermagic, read to corroborate the release above. The
        // first module that has one is enough: they are all built together.
        for (const std::string& p : modules) {
            const auto bytes = t.read(p, 512 * 1024);
            if (!bytes) continue;
            const std::string vm = modinfo_value(*bytes, "vermagic");
            if (vm.empty()) continue;
            add(r, "kernel.vermagic", vm, p);
            const std::string claimed = leading_version(vm);
            if (!claimed.empty() && claimed != release)
                r.diagnostics.push_back(
                    {Severity::Warning, kCodeKernelMismatch,
                     "'" + p + "' was built for kernel " + claimed + " but is installed under " +
                         release + "; modules that disagree with their kernel do not load"});
            break;
        }

        // What the system loads at boot, which is a much shorter and more
        // telling list than what it ships: OpenWrt writes one file per module
        // in etc/modules.d, Debian-style systems one line per module.
        std::string autoload;
        std::string autoload_src;
        for (const std::string& f : t.list_dir("etc/modules.d")) {
            if (const auto text = t.read("etc/modules.d/" + f, 16 * 1024)) {
                for_each_line(*text, [&](std::string_view line) {
                    if (line.empty() || line.front() == '#') return;
                    if (autoload.size() > 400) return;
                    if (!autoload.empty()) autoload += ",";
                    autoload.append(line);
                });
                autoload_src = "etc/modules.d";
            }
        }
        if (autoload.empty()) {
            for (const char* f : {"etc/modules", "etc/modules.conf"}) {
                const auto text = t.read(f, 64 * 1024);
                if (!text) continue;
                for_each_line(*text, [&](std::string_view line) {
                    if (line.empty() || line.front() == '#') return;
                    if (autoload.size() > 400) return;
                    if (!autoload.empty()) autoload += ",";
                    autoload.append(line);
                });
                autoload_src = f;
                break;
            }
        }
        if (!autoload.empty())
            add(r, "kernel.modules.autoload", autoload.substr(0, 420), autoload_src);
    }

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

    // Drivers compiled into the kernel rather than built as modules.
    // They have no .ko and no .modinfo, so this list is the only place they
    // are named -- and a system with no loadable modules at all is usually one
    // that built everything in, not one with no drivers, which is why this is
    // read before the module set is found to be empty.
    //
    // Kernels before 2.6.29 do not write the file and OpenWrt strips it, so not
    // finding one says nothing either way and is not a diagnostic.
    static void describe_builtin(const Tree& t, Report& r, const std::string& root) {
        if (const auto builtin = t.read(root + "/modules.builtin", 1u << 20)) {
            unsigned count = 0;
            std::map<std::string, unsigned> by_dir;
            std::string names;
            for_each_line(*builtin, [&](std::string_view line) {
                while (!line.empty() && (line.back() == '\r' || line.back() == ' '))
                    line.remove_suffix(1);
                if (line.empty() || line.front() == '#') return;
                ++count;
                const std::size_t slash = line.rfind('/');
                std::string base(slash == std::string_view::npos ? line : line.substr(slash + 1));
                const std::size_t dot = base.find(".ko");
                if (dot != std::string::npos) base.resize(dot);
                if (names.size() <= 600) {
                    if (!names.empty()) names += ",";
                    names += base;
                } else if (names.size() < 605) {
                    names += ",...";
                }
                // `kernel/drivers/usb/foo.ko` -> `drivers/usb`.
                if (line.rfind("kernel/", 0) == 0 && slash != std::string_view::npos && slash > 7)
                    ++by_dir[std::string(line.substr(7, slash - 7))];
            });
            const std::string src = root + "/modules.builtin";
            add(r, "kernel.builtin.count", std::to_string(count), src);
            if (!names.empty()) add(r, "kernel.builtin.names", names, src);
            if (!by_dir.empty()) {
                std::vector<std::pair<std::string, unsigned>> sorted(by_dir.begin(), by_dir.end());
                std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) {
                    return a.second != b.second ? a.second > b.second : a.first < b.first;
                });
                std::string joined;
                for (const auto& [dir, n] : sorted) {
                    if (joined.size() > 400) {
                        joined += ",...";
                        break;
                    }
                    if (!joined.empty()) joined += ",";
                    joined += dir + "=" + std::to_string(n);
                }
                add(r, "kernel.builtin.subsystems", joined, src);
            }
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
