// Kallsyms.h — the symbol table a Linux kernel carries inside itself.
#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace omnitrace::artifacts::kernel {

/// One decoded symbol. `type` is the nm letter the kernel stores ahead of the
/// name: `T`/`t` text, `D`/`d` data, `B`/`b` bss, `r` rodata, and so on.
/// `address` is where the symbol lives in the kernel's own address space, and
/// is 0 when the table's address array could not be read (`Kallsyms::addressed`
/// says which). It is a *virtual* address: nothing in the image says where it
/// was loaded physically.
struct Symbol {
    char type = '?';
    std::uint64_t address = 0;
    std::string name;
};

/// How a table stores its addresses. The kernel has changed this twice and
/// every form is still in the field.
enum class AddressMode : std::uint8_t {
    None,      ///< Not decoded.
    Absolute,  ///< `kallsyms_addresses`: one word per symbol, the address itself.
    Relative,  ///< `kallsyms_offsets`: a u32 per symbol, added to `relative_base`.
    /// `--absolute-percpu`: a *positive* offset is an absolute address and a
    /// negative one is `relative_base - 1 - offset`.
    RelativePercpu,
};
/// "absolute" | "relative" | "relative-percpu" | "none".
const char* address_mode_name(AddressMode m);

/// What a decode found.
struct Kallsyms {
    bool found = false;
    bool big_endian = false;
    unsigned word_size = 0;         ///< 4 or 8, as the kernel was built.
    std::uint64_t token_table = 0;  ///< Offsets into the image, for the record.
    std::uint64_t num_syms_at = 0;
    /// Addresses were decoded and every `Symbol::address` is real. False means
    /// the names are still good and the addresses are all 0: the two halves of
    /// the table are found separately and one can fail without the other.
    bool addressed = false;
    AddressMode mode = AddressMode::None;
    std::uint64_t relative_base = 0;  ///< Meaningful for the relative modes.
    std::vector<Symbol> symbols;
};

/// Find and decode the kallsyms table in a raw kernel image.
///
/// A kernel that is not an ELF has no symbol table a normal reader can use;
/// `CONFIG_KALLSYMS` puts one inside the image instead, because the kernel
/// needs to print symbol names in an oops. The layout, in order, is
/// `kallsyms_names` (compressed), `kallsyms_markers`, `kallsyms_token_table`,
/// `kallsyms_token_index` -- none of which has a magic number.
///
/// It is found from the back, because only the last structure is
/// self-describing: `token_index` is 256 `u16` where entry *i* is the byte
/// offset of token *i* inside the table that precedes it, so the table's
/// position can be *solved* rather than guessed. Everything earlier is then
/// pinned by a decode that has to land exactly where the next structure
/// begins, and the result is accepted only when the names it produces look
/// like symbols. Three independent checks, because a kernel image is several
/// megabytes of data that will coincidentally satisfy any one of them.
///
/// `max_symbols` bounds the work on hostile input. Returns `found = false`
/// rather than failing: most files are not kernels.
Kallsyms parse(std::span<const std::uint8_t> image, std::size_t max_symbols = 400000);

}  // namespace omnitrace::artifacts::kernel
