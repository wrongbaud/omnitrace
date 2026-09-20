// sevenzip.cpp — 7z archive validator.
//
// The structure is parsed by omnitrace::sevenzip
// (include/omnitrace/core/SevenZip.h), which container::SevenZipReader shares.
//
// Sizing is exact and cheap: the 32-byte signature header carries the offset
// and length of the header at the far end of the archive, and both are
// covered by CRCs, so one 32-byte read gives a verified extent. Reading the
// header itself costs a decode of one small folder, which is what puts the
// entry count and the coders on the finding.
#include "anchors.h"
#include "common.h"
#include "omnitrace/core/SevenZip.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

std::optional<Finding> validate_7z(const Span& span, std::uint64_t start, const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    sevenzip::Archive a;
    const Status st = sevenzip::read_archive(span, start, a);

    // A six-byte magic whose start header does not check out is a
    // coincidence, not a damaged archive.
    if (!a.start_header_crc_ok) return std::nullopt;

    Finding f = make_finding(sig, start, Confidence::Structural);
    f.endian = Endian::Little;
    f.attrs["version"] = dec(a.version_major) + "." + dec(a.version_minor);
    f.attrs["header_offset"] = hex(sevenzip::kSignatureHeaderSize + a.next_header_offset);
    f.attrs["header_size"] = dec(a.next_header_size);
    f.attrs["header_encoded"] = a.header_was_encoded ? "true" : "false";
    // The start header is CRC-covered and carries the archive's whole extent,
    // so the size is known even when the header will not parse.
    bool truncated = false;
    f.size = clamp_size(span, start, a.size, truncated);
    if (truncated)
        diag(f, Severity::Warning, "7z-truncated",
             "the header ends at " + hex(a.size) + ", past the available data");

    if (!st) {
        const std::string code = st.error.substr(0, st.error.find(':'));
        diag(f, Severity::Warning, code.empty() ? "7z-bad-header" : code, st.error);
        f.evidence = "7z signature header verified, " + st.error;
        return f;
    }
    f.confidence = Confidence::Consistent;

    std::uint64_t files = 0, dirs = 0, bytes = 0;
    for (const sevenzip::FileEntry& e : a.files) {
        if (e.is_dir) {
            ++dirs;
        } else {
            ++files;
        }
    }
    for (const std::uint64_t s : a.streams.substream_sizes) bytes += s;

    // Which coders the archive uses decides whether a reader can do anything
    // with it, so it goes on the finding rather than waiting for the walk.
    std::vector<std::string> coders;
    std::uint64_t undecodable = 0;
    for (const sevenzip::Folder& fo : a.streams.folders) {
        for (const sevenzip::Coder& c : fo.coders) {
            const std::string n = c.name();
            if (std::find(coders.begin(), coders.end(), n) == coders.end()) coders.push_back(n);
        }
        if (!sevenzip::folder_decodable(fo)) ++undecodable;
    }
    std::sort(coders.begin(), coders.end());
    std::string list;
    for (const std::string& c : coders) {
        if (!list.empty()) list.push_back(',');
        list += c;
    }
    f.attrs["coders"] = list;
    f.attrs["folders"] = dec(a.streams.folders.size());
    f.attrs["entries"] = dec(a.files.size());
    f.attrs["files"] = dec(files);
    f.attrs["directories"] = dec(dirs);
    f.attrs["unpacked_bytes"] = dec(bytes);
    if (undecodable != 0) {
        f.attrs["undecodable_folders"] = dec(undecodable);
        diag(f, Severity::Info, "7z-unsupported-coder",
             dec(undecodable) + " of " + dec(a.streams.folders.size()) +
                 " folder(s) use a coder this build does not decode (" + list +
                 "); their files are listed but not extracted");
    }
    f.evidence = "7z " + dec(a.version_major) + "." + dec(a.version_minor) +
                 ", start header and header CRCs ok, " + dec(a.files.size()) + " entr(ies), " +
                 dec(a.streams.folders.size()) + " folder(s) [" + list + "], " + dec(bytes) +
                 " byte(s) unpacked";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("7z", validate_7z);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(sevenzip)
