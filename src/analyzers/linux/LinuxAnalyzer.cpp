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

#include "omnitrace/analyzers/Platform.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::analyzers {

namespace {

constexpr const char* kCodeNoRelease = "platform-linux-no-release";
constexpr const char* kCodeShadowUnreadable = "platform-shadow-unreadable";
constexpr const char* kCodeEmptyPassword = "platform-account-no-password";
constexpr const char* kCodeWeakHash = "platform-account-weak-hash";
constexpr const char* kCodeReleaseDisagrees = "platform-release-disagrees";

// KEY=VALUE, one per line, with the value optionally single- or double-quoted.
// os-release (man 5 os-release) and OpenWrt's /etc/openwrt_release are both
// this shape; so is /etc/lsb-release.
std::map<std::string, std::string> parse_env(const std::string& text) {
    std::map<std::string, std::string> out;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string_view line(text.data() + pos, eol - pos);
        pos = eol + 1;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty() || line.front() == '#') continue;
        const std::size_t eq = line.find('=');
        if (eq == std::string_view::npos) continue;
        std::string_view key = line.substr(0, eq);
        std::string_view val = line.substr(eq + 1);
        if (val.size() >= 2 && (val.front() == '"' || val.front() == '\'') &&
            val.back() == val.front()) {
            val.remove_prefix(1);
            val.remove_suffix(1);
        }
        if (key.empty() || val.empty()) continue;
        out.emplace(std::string(key), std::string(val));
    }
    return out;
}

// Two files may answer the same question. When they agree, saying so twice is
// noise; when they disagree, that is a finding and both are kept so an
// examiner can see which file said what.
void add(Report& r, std::string key, std::string value, std::string source) {
    if (value.empty()) return;
    const Fact* clash = nullptr;
    for (const Fact& f : r.facts) {
        if (f.key != key) continue;
        if (f.value == value) return;  // agreed; saying it twice is noise
        clash = &f;
    }
    if (clash != nullptr)
        r.diagnostics.push_back({Severity::Info, kCodeReleaseDisagrees,
                                 key + " differs between " + clash->source + " (" + clash->value +
                                     ") and " + source + " (" + value + "); both are reported"});
    r.facts.push_back(Fact{std::move(key), std::move(value), std::move(source)});
}

// A crypt(3) field, named. What matters forensically is whether an account
// could be logged into and how well the hash resists being cracked, not the
// hash itself -- which is why the hash is never copied into the report.
//
// The same bytes mean different things in the two files, which is why the
// caller has to say which one it is reading. In passwd, `x` means "the secret
// is in shadow" and is the normal case; in shadow it is not a crypt string at
// all, so nothing a user could type will ever hash to it and the account
// cannot be logged into. The router corpus has both: `dnsmasq:x` in shadow
// (login impossible) and `root::` (login with no password whatsoever).
std::string hash_kind(std::string_view h, bool in_shadow) {
    if (h.empty()) return "empty";  // any password, or none, is accepted
    if (h == "*" || h == "!" || h == "!!" || h == "!*") return "locked";
    if (h == "x") return in_shadow ? "invalid" : "in-shadow";
    if (h.rfind("$1$", 0) == 0) return "md5";
    if (h.rfind("$2", 0) == 0) return "bcrypt";
    if (h.rfind("$5$", 0) == 0) return "sha256";
    if (h.rfind("$6$", 0) == 0) return "sha512";
    if (h.rfind("$y$", 0) == 0 || h.rfind("$7$", 0) == 0) return "yescrypt";
    if (h.front() == '$') return "crypt-other";
    if (h.size() == 13) return "descrypt";  // the ancient one, trivially cracked
    return "unrecognised";
}

// Is this a hash someone could actually attack, as opposed to a state that
// means the account has no usable password?
bool is_real_hash(const std::string& kind) {
    return kind != "empty" && kind != "locked" && kind != "invalid" && kind != "in-shadow" &&
           kind != "unrecognised";
}

// One colon-separated line's fields.
std::vector<std::string_view> split_colons(std::string_view line) {
    std::vector<std::string_view> out;
    std::size_t pos = 0;
    for (;;) {
        const std::size_t c = line.find(':', pos);
        if (c == std::string_view::npos) {
            out.push_back(line.substr(pos));
            break;
        }
        out.push_back(line.substr(pos, c - pos));
        pos = c + 1;
    }
    return out;
}

void for_each_line(const std::string& text, const std::function<void(std::string_view)>& fn) {
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string_view line(text.data() + pos, eol - pos);
        pos = eol + 1;
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (!line.empty()) fn(line);
    }
}

class LinuxAnalyzer final : public Analyzer {
   public:
    Platform platform() const override { return Platform::Linux; }
    unsigned rank() const override { return 1; }

    unsigned detect(const Tree& t) const override {
        unsigned score = 0;
        // Each of these is something a Linux root has and a QNX IFS, a FAT
        // data partition or a firmware blob does not.
        for (const char* p : {"etc/passwd", "etc/inittab", "etc/fstab", "etc/group", "etc/hostname",
                              "etc/resolv.conf", "etc/shadow"})
            if (t.has_file(p)) ++score;
        for (const char* p : {"bin/busybox", "sbin/init", "bin/sh", "usr/bin/env", "lib/ld.so.1"})
            if (t.has_file(p)) ++score;
        for (const char* p : {"etc/init.d", "etc/rc.d", "proc", "sys", "usr/lib", "var/log"})
            if (t.has_dir(p)) ++score;
        if (!t.first_of({"etc/os-release", "usr/lib/os-release", "etc/openwrt_release",
                         "etc/lsb-release"})
                 .empty())
            score += 2;
        return score;
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
        const auto passwd = t.read("etc/passwd", 1u << 20);
        if (!passwd) return;
        const bool have_shadow = t.has_file("etc/shadow");
        unsigned accounts = 0, uid0 = 0;
        for_each_line(*passwd, [&](std::string_view line) {
            if (line.front() == '#') return;
            const auto f = split_colons(line);
            if (f.size() < 7) return;
            ++accounts;
            const std::string name(f[0]);
            if (f[2] == "0") {
                ++uid0;
                add(r, "user.uid0", name, "etc/passwd");
            }
            // The secret normally lives in shadow, and repeating "in-shadow"
            // for every account says nothing. What is worth reporting from
            // passwd is a hash sitting in the world-readable file, which
            // embedded systems still ship, and the state of every account when
            // there is no shadow file at all.
            const std::string kind = hash_kind(f[1], /*in_shadow=*/false);
            if (is_real_hash(kind))
                r.diagnostics.push_back(
                    {Severity::Warning, kCodeWeakHash,
                     "'" + name + "' has its password hash (" + kind +
                         ") in etc/passwd, which is world-readable, rather than in etc/shadow"});
            if (is_real_hash(kind) || !have_shadow)
                add(r, "user." + name + ".password", kind, "etc/passwd");
        });
        add(r, "users.count", std::to_string(accounts), "etc/passwd");
        if (uid0 > 1) add(r, "users.uid0_count", std::to_string(uid0), "etc/passwd");

        const auto shadow = t.read("etc/shadow", 1u << 20);
        if (!shadow) {
            if (have_shadow)
                r.diagnostics.push_back({Severity::Warning, kCodeShadowUnreadable,
                                         "etc/shadow is listed but its bytes could not be read "
                                         "back, so account password state is unknown"});
            return;
        }
        unsigned with_hash = 0;
        for_each_line(*shadow, [&](std::string_view line) {
            if (line.front() == '#') return;
            const auto f = split_colons(line);
            if (f.size() < 2) return;
            const std::string name(f[0]);
            const std::string kind = hash_kind(f[1], /*in_shadow=*/true);
            add(r, "user." + name + ".password", kind, "etc/shadow");
            if (is_real_hash(kind)) ++with_hash;
            // An account that accepts any password, or none, is the single
            // most actionable thing on the system, and a table row is the
            // wrong place for it. The router corpus image has exactly this:
            // `root::` -- root logs in with no password at all.
            if (kind == "empty")
                r.diagnostics.push_back(
                    {Severity::Warning, kCodeEmptyPassword,
                     "'" + name +
                         "' has an empty password field in etc/shadow: the account "
                         "authenticates with no password"});
            else if (kind == "md5" || kind == "descrypt")
                r.diagnostics.push_back(
                    {Severity::Info, kCodeWeakHash,
                     "'" + name + "' uses " + kind + ", which modern hardware cracks quickly"});
        });
        add(r, "users.with_password", std::to_string(with_hash), "etc/shadow");
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
