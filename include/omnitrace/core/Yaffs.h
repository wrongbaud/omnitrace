// Yaffs.h — the YAFFS2 chunk grid, shared by the validator and the reader.
/// @file Yaffs.h
/// @brief Geometry detection, packed tags and object headers for YAFFS2.
///
/// A YAFFS2 image has no superblock and no magic. It is a flat grid of
/// chunks, each a NAND page followed by its spare (out-of-band) area:
///
///     [ page: 2048 ][ spare: 64 ]  [ page ][ spare ] ...
///
/// The spare holds `struct yaffs_packed_tags2`: sixteen bytes of tags
/// (`seq_number`, `obj_id`, `chunk_id`, `n_bytes`, little-endian) and a
/// twelve-byte `yaffs_ecc_other` computed over exactly those sixteen. Where
/// in the spare the tags start depends on the flash's spare layout -- 0 for
/// yaffs's own, 2 for Linux MTD's -- and neither the page size, the spare
/// size nor that offset is recorded anywhere in the image.
///
/// So the grid has to be found by trying candidates, and the tag checksum is
/// what makes that safe: read the tags out of alignment and the ECC says so
/// at once. `detect_geometry` does exactly that.
///
/// It is in core because two layers read the same bytes: the `yaffs2`
/// validator decides whether a region is an image and how big it is, and
/// `fs::Yaffs2Reader` walks the chunks into files. Everything here is pure
/// and reads through the Span, so it is safe from any thread.
#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "omnitrace/core/Span.h"

/// @namespace omnitrace::yaffs
/// @brief YAFFS2 chunk grid parsing.
namespace omnitrace::yaffs {

/// Bytes of packed tags in the spare: sixteen of tags, twelve of ECC.
inline constexpr std::uint64_t kTagsSize = 16;
/// @copydoc kTagsSize
inline constexpr std::uint64_t kPackedTagsSize = 28;
/// Bytes of `yaffs_obj_hdr` at the start of an object header's page.
inline constexpr std::uint64_t kObjHeaderSize = 512;

/// `enum yaffs_obj_type`.
enum class ObjType : std::uint8_t {
    Unknown = 0,
    File = 1,
    Symlink = 2,
    Directory = 3,
    Hardlink = 4,
    Special = 5,
};

/// Object ids YAFFS2 reserves. Everything a user created is above these.
inline constexpr std::uint32_t kRootId = 1;
/// @copydoc kRootId
inline constexpr std::uint32_t kLostNFoundId = 2;
/// The parent an object is given when it is unlinked but still open.
inline constexpr std::uint32_t kUnlinkedId = 3;
/// The parent an object is given when it is deleted.
inline constexpr std::uint32_t kDeletedId = 4;

/// Flags YAFFS2 packs into `chunk_id` and `obj_id` of a header chunk's tags
/// when it also carries the object's summary (`yaffs_packedtags2.c`).
inline constexpr std::uint32_t kExtraHeaderInfoFlag = 0x80000000u;
/// @copydoc kExtraHeaderInfoFlag
inline constexpr std::uint32_t kExtraShrinkFlag = 0x40000000u;
/// @copydoc kExtraHeaderInfoFlag
inline constexpr std::uint32_t kExtraShadowsFlag = 0x20000000u;
/// @copydoc kExtraHeaderInfoFlag
inline constexpr std::uint32_t kAllExtraFlags = 0xF0000000u;
/// @copydoc kExtraHeaderInfoFlag
inline constexpr unsigned kExtraObjectTypeShift = 28;

/// Where a chunk's page and spare sit, and where in the spare the tags are.
struct Geometry {
    std::uint32_t page = 0;          ///< Bytes of NAND page (the data area).
    std::uint32_t spare = 0;         ///< Bytes of spare (out-of-band) area.
    std::uint32_t tags_offset = 0;   ///< Tags position inside the spare: 0 or 2.

    /// Bytes from one chunk's first byte to the next one's.
    std::uint64_t chunk_size() const { return static_cast<std::uint64_t>(page) + spare; }
    /// True when this describes a usable grid.
    bool valid() const {
        return page != 0 && spare >= tags_offset + kPackedTagsSize;
    }
    /// "yaffs" or "linux-mtd".
    const char* layout_name() const { return tags_offset == 0 ? "yaffs" : "linux-mtd"; }
};

/// One chunk's tags, decoded.
struct Tags {
    std::uint32_t seq = 0;       ///< Block sequence number; higher is newer.
    std::uint32_t obj_id = 0;    ///< Which object this chunk belongs to.
    std::uint32_t chunk_id = 0;  ///< 0 = object header, else data block `chunk_id - 1`.
    std::uint32_t n_bytes = 0;   ///< Valid bytes of the page (data chunks).
    bool is_header = false;      ///< `chunk_id` names a header, either form.
    bool erased = false;         ///< The tags are all 0xFF: the chunk was never written.
    bool ecc_ok = false;         ///< The tags match their own checksum.
    // Set when the header chunk also carried the object's summary.
    bool extra = false;              ///< The tags carry the summary below.
    std::uint32_t parent_id = 0;     ///< Parent object, from the summary.
    ObjType type = ObjType::Unknown; ///< Object type, from the summary.
    bool is_shrink = false;          ///< Shrink header (a truncation), from the summary.
};

/// One `yaffs_obj_hdr`, decoded from a header chunk's page.
struct ObjHeader {
    ObjType type = ObjType::Unknown;
    std::uint32_t parent_id = 0;
    std::string name;       ///< Raw bytes from the header; sanitize before output.
    std::uint32_t mode = 0;
    std::uint32_t uid = 0, gid = 0;
    std::uint32_t atime = 0, mtime = 0, ctime = 0;
    std::uint64_t size = 0;      ///< Files only; 0 for everything else.
    std::int32_t equiv_id = -1;  ///< Hard links: the object they are a link to.
    std::string alias;           ///< Symlinks: the target, raw.
    std::uint32_t rdev = 0;      ///< Special files: the device number.
    std::int32_t shadows_obj = -1;
    bool is_shrink = false;
};

/// The three-part checksum YAFFS2 puts over a chunk's tags
/// (`yaffs_ecc_calc_other`).
struct Ecc {
    std::uint8_t col_parity = 0;              ///< Six bits, as stored.
    std::uint32_t line_parity = 0;
    std::uint32_t line_parity_prime = 0;
    friend bool operator==(const Ecc& a, const Ecc& b) {
        return a.col_parity == b.col_parity && a.line_parity == b.line_parity &&
               a.line_parity_prime == b.line_parity_prime;
    }
};

/// The checksum `data` should carry. Note the column parity is shifted right
/// by two and masked to six bits before it is stored, which is what
/// `yaffs_ecc_calc_other` does and what an implementation that skips it gets
/// wrong.
Ecc ecc_of(std::span<const std::uint8_t> data);

/// Decode the tags of the chunk whose first byte is `at`. False when the
/// chunk does not fit in `span`; `Tags::erased` and `Tags::ecc_ok` say what
/// was found when it does.
bool read_tags(const Span& span, const Geometry& geo, std::uint64_t at, Tags& out);

/// Decode the object header in the page of the chunk at `at`. False when the
/// page does not fit or the type is not one YAFFS2 defines.
bool read_header(const Span& span, const Geometry& geo, std::uint64_t at, ObjHeader& out);

/// Find the grid that the chunk starting at `at` belongs to, by trying every
/// geometry YAFFS2 is used with and keeping the one whose tags verify over
/// `probe_chunks` chunks. False when none does.
///
/// `at` must be the first byte of a chunk. With `require_header` the chunk
/// must also carry an object header, which is what the signature's magic
/// matches and what lets the validator start from a hit in the middle of an
/// image; a reader handed the image's first chunk cannot assume that, and
/// passes false.
bool detect_geometry(const Span& span, std::uint64_t at, std::uint64_t probe_chunks,
                     Geometry& out, bool require_header = true);

}  // namespace omnitrace::yaffs
