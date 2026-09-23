// ar.cpp — ar archive validator (static libraries, .deb, .ipk).
//
// `!<arch>\n` and then nothing but 60-byte member headers, each followed by
// its data padded to an even offset. There is no central directory, no
// trailer, and no length anywhere in the file: the only way to know where an
// archive ends is to walk it.
//
// Member header (all fields ASCII, space padded, and *not* NUL terminated):
//    0  name  16    28  uid   6    40  mode 8    58  "`\n"  2
//   16  mtime 12    34  gid   6    48  size 10
//
// The two-byte terminator at 58 is what makes a walk trustworthy: it is the
// only per-member check the format has, and it is what lets a truncated
// archive claim exactly the members that verified rather than the whole span
// behind the magic. That is the same rule tar and GPT follow -- when a magic
// is too weak to trust, something per-record has to earn the extent.
//
// Names come in three dialects and the validator does not care about any of
// them; the reader does (`docs/formats/ar.md`).
#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kMagicLen = 8;
constexpr std::uint64_t kHeaderLen = 60;

// A decimal or octal ASCII field, space padded. Returns nullopt when it holds
// anything else, which is how a random 60 bytes behind the magic is caught.
std::optional<std::uint64_t> ascii_num(const std::vector<std::uint8_t>& h, std::size_t off,
                                       std::size_t len, unsigned base) {
    std::uint64_t v = 0;
    bool any = false;
    for (std::size_t i = 0; i < len; ++i) {
        const std::uint8_t c = h[off + i];
        if (c == ' ') {
            // Trailing padding only: a space inside the digits is corruption.
            for (std::size_t j = i; j < len; ++j)
                if (h[off + j] != ' ') return std::nullopt;
            break;
        }
        if (c < '0' || c > '9') return std::nullopt;
        const unsigned d = static_cast<unsigned>(c - '0');
        if (d >= base) return std::nullopt;
        if (v > (0xFFFFFFFFFFFFFFFFULL - d) / base) {
            return std::nullopt;  // an overflowing field is not a size
        }
        v = (v * base) + d;
        any = true;
    }
    if (!any) return std::uint64_t{0};  // an all-blank field means zero
    return v;
}

std::optional<Finding> validate_ar(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Little;  // every field is ASCII; there is no byte order

    const std::uint64_t cap = extra_u64(sig, "max_members").value_or(200000);
    const std::uint64_t avail = remaining(span, start);
    std::uint64_t off = kMagicLen;
    std::uint64_t members = 0, accounted = kMagicLen;
    std::uint64_t data_bytes = 0;
    bool has_symbol_table = false, has_string_table = false, bsd_names = false;
    bool ran_out = false, bad = false;
    std::string why;

    while (members < cap) {
        if (off + kHeaderLen > avail) {
            // Out of data. Either the archive ended exactly here (the normal
            // case) or it was cut short mid-header.
            ran_out = off != avail;
            break;
        }
        auto raw = span.bytes(start + off, kHeaderLen);
        if (!raw) {
            ran_out = true;
            break;
        }
        const std::vector<std::uint8_t>& h = *raw;
        if (h[58] != 0x60 || h[59] != 0x0A) {
            bad = true;
            why = "member " + dec(members) + " at " + hex(off) + " has no '`\\n' terminator";
            break;
        }
        const auto size = ascii_num(h, 48, 10, 10);
        if (!size) {
            bad = true;
            why = "member " + dec(members) + " at " + hex(off) +
                  " has a size field that is not a "
                  "decimal number";
            break;
        }
        // Every other numeric field is checked too: they are what separates a
        // real header from sixty bytes that happen to end in "`\n".
        if (!ascii_num(h, 16, 12, 10) || !ascii_num(h, 28, 6, 10) || !ascii_num(h, 34, 6, 10) ||
            !ascii_num(h, 40, 8, 8)) {
            bad = true;
            why = "member " + dec(members) + " at " + hex(off) +
                  " has a non-numeric mtime, uid, gid or mode";
            break;
        }
        const std::string name(reinterpret_cast<const char*>(h.data()), 16);
        if (name.rfind("//", 0) == 0)
            has_string_table = true;
        else if (name.rfind("/ ", 0) == 0 || name.rfind("__.SYMDEF", 0) == 0)
            has_symbol_table = true;
        else if (name.rfind("#1/", 0) == 0)
            bsd_names = true;

        const std::uint64_t padded = *size + (*size & 1u);
        if (padded < *size || off + kHeaderLen > avail - std::min(avail, padded)) {
            // The member claims more than the span holds: truncated, not bad.
            ran_out = true;
            break;
        }
        if (off + kHeaderLen + padded > avail) {
            ran_out = true;
            break;
        }
        off += kHeaderLen + padded;
        accounted = off;
        data_bytes += *size;
        ++members;
    }

    if (members == 0) {
        // Nothing verified. The magic alone is eight bytes of ASCII that can
        // appear in text, so this is reported but never sized.
        diag(f, Severity::Warning, "ar-no-members",
             bad ? why : std::string("no member header follows the magic"));
        return f;
    }

    f.attrs["members"] = dec(members);
    f.attrs["data_bytes"] = dec(data_bytes);
    if (has_symbol_table) f.attrs["symbol_table"] = "true";
    if (has_string_table) f.attrs["string_table"] = "true";
    if (bsd_names) f.attrs["bsd_long_names"] = "true";

    if (members >= cap) {
        diag(f, Severity::Info, "ar-limit-members",
             "stopped after " + dec(cap) + " members; the archive may be longer");
    } else if (ran_out) {
        // Data ran out inside a member: the archive really is cut short.
        diag(f, Severity::Warning, "ar-truncated",
             "the archive is cut short after " + dec(members) + " member(s)");
    }
    // `bad` is deliberately not a warning once a member has verified. The
    // format has no trailer, so bytes that stop looking like a member header
    // are simply where the archive ends -- the normal case for one embedded in
    // a larger image. Warning there would put a diagnostic on every static
    // library in a root filesystem.

    f.size = accounted;
    // Verified needs "a CRC or checksum verified, or a decode probe succeeded"
    // (docs/ARCHITECTURE.md). ar has no checksum, but walking it is the decode
    // probe: every 60-byte header carries a two-byte terminator, and each one
    // has to land exactly where the previous member's size said it would. Two
    // members chained that way is a claim about the bytes between them rather
    // than a guess about the magic.
    //
    // The tier matters beyond the report. Absorbing nested findings needs
    // *strictly higher* confidence than what is absorbed (`outranks` in
    // Scan.cpp), and a static library is hundreds of ELF members that each
    // match the elf signature at Consistent. At Consistent the scan reported
    // all 298 of one libgcc.a as separate top-level regions, on top of the 298
    // files the reader already extracts. Nothing is lost by absorbing them:
    // the reader emits every member and the nested analysis identifies each.
    if (ran_out || members >= cap) {
        f.confidence = Confidence::Structural;
    } else {
        f.confidence = members >= 2 ? Confidence::Verified : Confidence::Consistent;
    }
    f.evidence = dec(members) + " member(s), " + dec(data_bytes) + " bytes of member data" +
                 (has_symbol_table ? ", symbol table" : "") +
                 (has_string_table ? ", long-name table" : "");
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("ar", validate_ar);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(ar)
