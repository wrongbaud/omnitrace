// Kallsyms.h — the symbol table a Linux kernel carries inside itself.
#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace omnitrace::artifacts::kernel {

/// One decoded symbol. `type` is the nm letter the kernel stores ahead of the
/// name: `T`/`t` text, `D`/`d` data, `B`/`b` bss, `r` rodata, and so on.
struct Symbol {
    char type = '?';
    std::string name;
};

/// What a decode found.
struct Kallsyms {
    bool found = false;
    bool big_endian = false;
    unsigned word_size = 0;         ///< 4 or 8, as the kernel was built.
    std::uint64_t token_table = 0;  ///< Offsets into the image, for the record.
    std::uint64_t num_syms_at = 0;
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
