// ArReader.h — ar archives: static libraries, .deb, .ipk. See the .cpp.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// An ar archive: `!<arch>\n` and then nothing but 60-byte member headers,
/// each followed by its data padded to an even offset. No directory, no
/// trailer, no nesting — a flat list, which is why a static library full of
/// object files is one archive and not a tree.
///
/// Names arrive in three dialects and all three are resolved here, because a
/// member called `/108` is not a file name:
///
/// * **GNU short** — `name.o/`, the slash marking where the name ends so a
///   trailing space can be part of it.
/// * **GNU long** — `/108`, an offset into the `//` member, which is one
///   string table for every name too long for the 16-byte field.
/// * **BSD long** — `#1/13`, where the first 13 bytes of the *data* are the
///   name and the recorded size covers them.
///
/// The symbol table (`/` or `__.SYMDEF`) and the string table (`//`) are
/// archive metadata rather than members, and are not emitted as files; their
/// presence is recorded in `attrs` so nothing disappears silently.
class ArReader final : public ContainerReader {
   public:
    std::string format() const override { return "ar"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    /// One member header, located but not yet read.
    struct Member {
        std::uint64_t header_at = 0;
        std::uint64_t data_at = 0;
        std::uint64_t size = 0;  ///< Data bytes, the BSD name prefix removed.
        std::uint64_t next = 0;
        std::string name;
        std::uint64_t mtime = 0;
        std::uint32_t uid = 0, gid = 0, mode = 0;
        bool is_table = false;  ///< Symbol or string table: metadata, not a file.
        bool ok = false;
    };

    Member read_member(std::uint64_t pos) const;
    void load_string_table();
    /// `/108` -> the name at offset 108 of the `//` member.
    std::string long_name(std::uint64_t offset) const;

    Span span_;
    bool opened_ = false;
    std::vector<std::uint8_t> strings_;  ///< The `//` member, verbatim.
    std::uint64_t members_ = 0, total_ = 0, data_bytes_ = 0;
    bool has_symbol_table_ = false, has_string_table_ = false, bsd_names_ = false;
};

namespace detail {
void omnitrace_container_anchor_ar();
}

}  // namespace omnitrace::container
