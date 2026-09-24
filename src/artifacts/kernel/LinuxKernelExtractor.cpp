// LinuxKernelExtractor.cpp — what a Linux kernel image says about itself.
//
// Two things, and the first is the more useful. A kernel carries its build
// banner as a plain string: "Linux version 5.4.55 (jenkins@...) (gcc version
// 8.4.0 ...) #0 SMP Fri Aug 15 02:53:20 2025". That names the kernel, the
// toolchain and the build date, and it is the *only* source for any of them
// when a system has no `lib/modules` to read a release out of -- which is the
// case for every kernel that shipped as a compressed image with its modules
// built in.
//
// The second is the symbol table. A kernel image that is not an ELF has no
// symbol table a normal reader can use, so `CONFIG_KALLSYMS` puts one inside
// the image; the kernel needs it to print names in an oops. `Kallsyms.h`
// explains how it is found. What it is worth here is what the kernel contains:
// 29,793 symbols on the router-nand image, which is a description of a system whose
// filesystem lists 174 loadable modules and says nothing about the rest.
#include <algorithm>
#include <map>
#include <string>

#include "Kallsyms.h"
#include "omnitrace/artifacts/Artifact.h"
#include "omnitrace/core/Elf.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::artifacts {

namespace {

constexpr const char* kCodeNoSymbols = "kernel-no-symbol-table";
constexpr std::string_view kBanner = "Linux version ";

bool name_is(std::string_view path, std::initializer_list<const char*> names) {
    const std::size_t slash = path.rfind('/');
    const std::string_view base = slash == std::string_view::npos ? path : path.substr(slash + 1);
    for (const char* n : names)
        if (base.rfind(n, 0) == 0) return true;
    return false;
}

/// The banner, from the first "Linux version " to the end of its line.
std::string find_banner(std::span<const std::uint8_t> d) {
    const std::string_view hay(reinterpret_cast<const char*>(d.data()), d.size());
    const std::size_t at = hay.find(kBanner);
    if (at == std::string_view::npos) return {};
    std::size_t end = at;
    // Bounded: a banner is one line and never 1 KiB.
    while (end < d.size() && end - at < 1024 && d[end] != 0 && d[end] != '\n') ++end;
    return sanitize_utf8(std::string_view(reinterpret_cast<const char*>(d.data() + at), end - at));
}

/// "5.4.55" out of "Linux version 5.4.55 (jenkins@...)", and empty when what
/// follows is not a version at all.
///
/// The check is what stops this claiming English prose. "Linux version " is a
/// plain string with no magic behind it, and it turns up in writing: the router-wrt
/// image carries "Linux version of the hub software for the Direct Connect
/// network", which produced a kernel record whose version was "of" until this
/// required a number. It is the same rule every weak magic in this project
/// follows -- something per-record has to earn the claim.
std::string version_of(const std::string& banner) {
    if (banner.size() <= kBanner.size()) return {};
    const std::size_t from = kBanner.size();
    std::size_t end = from;
    while (end < banner.size() && banner[end] != ' ') ++end;
    const std::string v = banner.substr(from, end - from);
    // A kernel release is at least `major.minor`, digits either side of a dot.
    std::size_t dot = v.find('.');
    if (dot == std::string::npos || dot == 0 || dot + 1 >= v.size()) return {};
    const auto digits = [](char c) { return c >= '0' && c <= '9'; };
    if (!digits(v[dot - 1]) || !digits(v[dot + 1])) return {};
    if (!digits(v[0])) return {};
    return v;
}

/// The "(gcc version 8.4.0 ...)" group, which names the toolchain a vendor
/// built with and is often the only dating evidence on a stripped image.
std::string compiler_of(const std::string& banner) {
    const std::size_t at = banner.find("(gcc version ");
    if (at == std::string::npos) return {};
    int depth = 0;
    for (std::size_t i = at; i < banner.size(); ++i) {
        if (banner[i] == '(') ++depth;
        if (banner[i] == ')' && --depth == 0) return banner.substr(at + 1, i - at - 1);
    }
    return {};
}

class LinuxKernelExtractor final : public Extractor {
   public:
    std::string name() const override { return "linux-kernel"; }

    bool applies(std::string_view path, std::span<const std::uint8_t> head) const override {
        // A kernel image has no magic of its own: a compressed one is
        // identified by its wrapper, and what reaches this extractor is the
        // decompressed payload. So the screen is the name -- the names a
        // kernel is built or shipped under, plus `payload`, which is what the
        // stream readers call the one file they emit (Container.h). `extract`
        // then requires the banner before it does anything expensive, so a
        // payload that is not a kernel costs one substring search.
        if (name_is(path, {"vmlinux", "vmlinuz", "zImage", "bzImage", "uImage", "Image", "kernel",
                           "payload"}))
            return true;
        // An ELF called something else is a kernel only if it says so, and
        // that is not worth reading every ELF in a case to find out.
        (void)head;
        return false;
    }

    void extract(const FileRef& file, Yield& out) const override {
        const std::string banner = find_banner(file.bytes);
        if (banner.empty()) return;  // not a kernel; the usual case for a payload
        const std::string version = version_of(banner);
        if (version.empty()) return;  // the words, but not a kernel: see version_of

        Artifact a;
        a.kind = "linux-kernel";
        a.node = file.node;
        a.path = file.path;
        a.fields["banner"] = banner.size() > 300 ? banner.substr(0, 300) : banner;
        a.fields["version"] = version;
        // One kernel per image, and the banner is what distinguishes two of
        // them: a case holding a boot image and its recovery twin has two
        // records that differ only in what they were built from.
        a.identity = banner.size() > 300 ? banner.substr(0, 300) : banner;
        const std::string cc = compiler_of(banner);
        if (!cc.empty()) a.fields["compiler"] = cc.size() > 200 ? cc.substr(0, 200) : cc;

        // An ELF kernel (a vmlinux that was never stripped) names its own
        // architecture; a raw image does not, and kallsyms does not carry it.
        if (const auto eh = elf::parse_header(file.bytes))
            a.fields["arch"] = elf::machine_name(eh->machine);

        const kernel::Kallsyms ks = kernel::parse(file.bytes);
        if (!ks.found) {
            a.fields["symbols"] = "0";
            out.diagnostics.push_back(
                {Severity::Info, kCodeNoSymbols,
                 "'" + file.path +
                     "' is a Linux kernel with no kallsyms table: it was built without "
                     "CONFIG_KALLSYMS, so the image does not name its own functions"});
            out.artifacts.push_back(std::move(a));
            return;
        }

        a.fields["symbols"] = std::to_string(ks.symbols.size());
        a.fields["word_size"] = std::to_string(ks.word_size * 8);
        a.fields["endian"] = ks.big_endian ? "big" : "little";

        // A histogram of nm types, which says what the image is made of
        // without listing thirty thousand names: `T` is exported text, `t`
        // static text, `d`/`D` data, `b`/`B` bss, `r` rodata.
        std::map<char, unsigned> by_type;
        for (const kernel::Symbol& s : ks.symbols) ++by_type[s.type];
        std::string types;
        for (const auto& [t, n] : by_type) {
            if (types.size() > 120) {
                types += ",...";
                break;
            }
            if (!types.empty()) types += ",";
            types += std::string(1, t) + "=" + std::to_string(n);
        }
        a.fields["symbol_types"] = types;

        // Where the kernel runs. An address array turns the symbol list into
        // a map of the running system: the first symbol is the base the image
        // was linked for, and the span to the last is how much of the address
        // space it occupies. Nothing in the image says where it was loaded
        // *physically*, so these are virtual addresses and are labelled as
        // such.
        if (ks.addressed && !ks.symbols.empty()) {
            const auto hex = [](std::uint64_t v) {
                static const char* kDigits = "0123456789abcdef";
                std::string h;
                for (int shift = 60; shift >= 0; shift -= 4) {
                    const unsigned nib = static_cast<unsigned>((v >> shift) & 0xF);
                    if (h.empty() && nib == 0 && shift != 0) continue;
                    h += kDigits[nib];
                }
                return "0x" + h;
            };
            std::uint64_t lo = ks.symbols.front().address;
            std::uint64_t hi = lo;
            for (const kernel::Symbol& sy : ks.symbols) {
                lo = std::min(lo, sy.address);
                hi = std::max(hi, sy.address);
            }
            a.fields["address_mode"] = kernel::address_mode_name(ks.mode);
            a.fields["load_address"] = hex(lo);
            a.fields["address_span"] = hex(hi - lo);
            if (ks.relative_base != 0) a.fields["relative_base"] = hex(ks.relative_base);
            // `_text` or `_stext` is where the kernel's own code begins, and
            // is the number an examiner needs to line a disassembly up.
            for (const char* want : {"_text", "_stext", "stext"}) {
                const auto it =
                    std::find_if(ks.symbols.begin(), ks.symbols.end(),
                                 [&](const kernel::Symbol& sy) { return sy.name == want; });
                if (it != ks.symbols.end()) {
                    a.fields["text_start"] = hex(it->address);
                    break;
                }
            }
        }

        // The table itself, written out rather than summarised.
        //
        // Thirty thousand names do not belong in a record or a report table,
        // and counting them is not the same as having them: a symbol list is
        // what an examiner loads into a disassembler, greps for a driver, or
        // diffs against another unit's kernel. It goes into the case
        // directory in `nm` order and `nm` format, so the tools that already
        // read that format can read this.
        a.fields["symbols_file"] = emit_table(file, ks, out);

        // Whether this kernel can load modules at all is a property of the
        // image, and it decides whether an empty lib/modules means "drivers
        // are built in" or "the modules are missing".
        const bool loadable =
            has(ks, "module_layout") || has(ks, "load_module") || has(ks, "do_init_module");
        a.fields["loadable_modules"] = loadable ? "yes" : "no";

        out.artifacts.push_back(std::move(a));
    }

   private:
    /// `symbols/<node>-<file>.txt`, in `nm` format: address, type, name.
    ///
    /// `nm` prints spaces where an address is unknown and so does this, which
    /// keeps the columns aligned whether or not the address array was read.
    /// The width follows the kernel's own word size.
    static std::string emit_table(const FileRef& file, const kernel::Kallsyms& ks, Yield& out) {
        const unsigned digits = ks.word_size == 8 ? 16u : 8u;
        std::string text;
        // ~30 bytes a line; one allocation instead of thirty thousand.
        text.reserve(ks.symbols.size() * 32);
        for (const kernel::Symbol& sy : ks.symbols) {
            if (ks.addressed) {
                static const char* kHex = "0123456789abcdef";
                for (unsigned i = digits; i-- > 0;) text += kHex[(sy.address >> (i * 4)) & 0xF];
            } else {
                text.append(digits, ' ');
            }
            text += ' ';
            text += sy.type;
            text += ' ';
            text += sanitize_utf8(sy.name);
            text += '\n';
        }

        // One file per kernel image, named for the node and the entry it came
        // from: a case routinely holds several (a boot image and its
        // recovery twin), and one `symbols.txt` would keep only the last.
        std::string stem = file.path;
        for (char& c : stem)
            if (c == '/' || c == '\\' || c == ':') c = '-';
        if (stem.size() > 80) stem.resize(80);
        ExtractedFile ef;
        ef.path = "symbols/" + file.node + "-" + stem + ".txt";
        ef.content = std::move(text);
        const std::string where = ef.path;
        out.files.push_back(std::move(ef));
        return where;
    }

    static bool has(const kernel::Kallsyms& ks, std::string_view name) {
        return std::any_of(ks.symbols.begin(), ks.symbols.end(),
                           [&](const kernel::Symbol& s) { return s.name == name; });
    }
};

}  // namespace

OMNITRACE_REGISTER_EXTRACTOR("linux-kernel", LinuxKernelExtractor);

}  // namespace omnitrace::artifacts

namespace omnitrace::artifacts::detail {
void omnitrace_extractor_anchor_linux_kernel() {}
}  // namespace omnitrace::artifacts::detail
