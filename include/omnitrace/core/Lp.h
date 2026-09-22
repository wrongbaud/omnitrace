// Lp.h — Android logical-partition ("super") metadata, shared by the
// android-super validator and its container reader.
/// @file Lp.h
/// @brief Parser for the metadata an Android dynamic-partitions `super` image
/// carries: geometry, metadata header, and the partition/extent/group/device
/// tables.
///
/// A `super` partition holds several logical partitions (`system`, `vendor`,
/// `product`, `system_ext`, and their `_a`/`_b` slots) whose sizes are decided
/// at flash time rather than at build time. The map lives in a fixed area at
/// the front:
///
/// | offset | bytes | what |
/// |---|---|---|
/// | 0 | 4096 | reserved (a partition table may live here) |
/// | 4096 | 4096 | geometry (magic `gDla`) |
/// | 8192 | 4096 | backup geometry |
/// | 12288 | `metadata_max_size` | metadata slot 0 (magic `0PLA`) |
/// | ... | | `metadata_slot_count` slots, then the same again as backups |
///
/// The metadata header names four tables by offset from the end of the
/// header: partitions (36-byte name, attributes, first extent, extent count,
/// group), extents (sector count, target type, target sector, source device),
/// groups and block devices. A partition is the concatenation of its extents;
/// a `linear` extent is bytes at `target_data * 512` of the source device and
/// a `zero` extent is that many zero bytes, which is how a sparse logical
/// partition is described without storing the holes.
///
/// It lives in core because two layers read the same bytes: the
/// `android-super` validator decides what the structure is and how far it
/// runs, and `container::SuperReader` assembles the logical partitions out of
/// it. Neither owns the parse.
///
/// Everything here is pure: it reads through the Span and holds no state
/// beyond the returned Metadata, so it is safe from any thread. Nothing is
/// trusted -- every table offset, count and extent is range-checked against
/// the Span and against the caps below, because a super image is evidence and
/// a scan meets accidental magics.
///
/// Reference: AOSP `system/core/fs_mgr/liblp` (`metadata_format.h`), read for
/// the layout only.
#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "omnitrace/core/Span.h"

/// @namespace omnitrace::lp
/// @brief Android logical-partition (super) metadata parsing.
namespace omnitrace::lp {

/// Geometry magic, little-endian at `kGeometryOffset` ("gDla").
inline constexpr std::uint32_t kGeometryMagic = 0x616C4467u;
/// Metadata header magic, little-endian at the start of a slot ("0PLA").
inline constexpr std::uint32_t kHeaderMagic = 0x414C5030u;

/// Bytes reserved before the geometry, which may hold a partition table.
inline constexpr std::uint64_t kReservedBytes = 4096;
/// The geometry sits here, and its backup copy in the 4096 bytes after it.
inline constexpr std::uint64_t kGeometryOffset = kReservedBytes;
/// Bytes each geometry copy occupies.
inline constexpr std::uint64_t kGeometrySize = 4096;
/// First metadata slot: past the reserved area and both geometry copies.
inline constexpr std::uint64_t kMetadataOffset = kReservedBytes + (kGeometrySize * 2);
/// Every extent and target offset is in units of this.
inline constexpr std::uint64_t kSectorSize = 512;

/// Smallest header that can name its four tables.
inline constexpr std::uint64_t kMinHeaderSize = 80;

/// Caps. Past any of these the structure is treated as hostile rather than
/// walked: the tables are attacker-controlled and a magic can land anywhere.
inline constexpr std::uint32_t kMaxSlots = 32;
/// @copydoc kMaxSlots
inline constexpr std::uint32_t kMaxPartitions = 4096;
/// @copydoc kMaxSlots
inline constexpr std::uint32_t kMaxExtents = 65536;
/// @copydoc kMaxSlots
inline constexpr std::uint64_t kMaxMetadataSize = 1u << 20;

/// What a `linear` extent points at, versus one that is only zeros.
enum class Target : std::uint8_t {
    Linear = 0,  ///< Bytes at `target_data * 512` of `target_source`.
    Zero = 1,    ///< `num_sectors * 512` zero bytes, stored nowhere.
};

/// The geometry block: how big the metadata area is and how it is laid out.
struct Geometry {
    std::uint32_t struct_size = 0;
    std::uint32_t metadata_max_size = 0;  ///< Bytes one slot occupies.
    std::uint32_t metadata_slot_count = 0;
    std::uint32_t logical_block_size = 0;
};

/// One logical partition's row.
struct Partition {
    std::string name;  ///< Up to 36 bytes, NUL-padded, sanitised on read.
    std::uint32_t attributes = 0;
    std::uint32_t first_extent = 0;
    std::uint32_t num_extents = 0;
    std::uint32_t group_index = 0;
};

/// One extent of one partition.
struct Extent {
    std::uint64_t num_sectors = 0;
    Target target = Target::Linear;
    std::uint64_t target_data = 0;    ///< Sector offset within the source device.
    std::uint32_t target_source = 0;  ///< Index into the block-device table.
};

/// One block device the extents may name.
struct BlockDevice {
    std::string name;                    ///< Partition name of the device ("super").
    std::uint64_t first_sector = 0;      ///< Where the logical space starts on it.
    std::uint64_t size = 0;              ///< Device size in bytes.
    std::uint32_t alignment = 0;         ///< Alignment in bytes.
    std::uint32_t alignment_offset = 0;  ///< Offset the alignment is measured from.
};

/// A parsed metadata slot, plus the geometry that located it.
struct Metadata {
    Geometry geometry;
    std::uint16_t major_version = 0, minor_version = 0;
    std::uint32_t header_size = 0;
    std::uint64_t slot_offset = 0;  ///< Span offset the slot was read from.
    std::vector<Partition> partitions;
    std::vector<Extent> extents;
    std::vector<BlockDevice> block_devices;
    std::uint32_t group_count = 0;
    std::uint64_t tables_size = 0;  ///< Bytes of table the header checksums.

    /// Bytes `p` comes to, summing its extents. 0 when its extents are out of
    /// range, which `partition_extents` reports as failure.
    std::uint64_t partition_size(const Partition& p) const;
    /// `p`'s extents, or nullopt when its range does not fit the table.
    std::optional<std::vector<Extent>> partition_extents(const Partition& p) const;
    /// Bytes the whole super image occupies, from the block-device table; 0
    /// when the table does not say.
    std::uint64_t device_size() const;
};

/// Read the geometry at `base + kGeometryOffset`, checking its magic. nullopt
/// when the magic is absent, a field is unreadable, or a size is impossible.
std::optional<Geometry> read_geometry(const Span& span, std::uint64_t base);

/// Read the metadata slot at `base + kMetadataOffset` (slot 0) for `geom`.
/// nullopt when the magic is absent or any table runs outside the slot, the
/// Span or the caps above.
std::optional<Metadata> read_metadata(const Span& span, std::uint64_t base, const Geometry& geom);

/// Geometry then slot 0, the usual pairing.
std::optional<Metadata> read(const Span& span, std::uint64_t base);

/// Which of the three SHA-256 checksums the structure carries actually match.
///
/// liblp stores one over the geometry, one over the metadata header, and one
/// over the tables -- the last being the partition map itself. They are the
/// difference between "these bytes are shaped like a super" and "these bytes
/// are a super": the geometry magic is four bytes and a scan finds it in
/// unrelated data, but a matching SHA-256 over the map does not happen by
/// accident. `tables` is the one a caller should insist on before trusting a
/// partition list.
struct Checksums {
    bool geometry = false;
    bool header = false;
    bool tables = false;
};

/// Recompute and compare all three. Anything unreadable counts as a mismatch,
/// never as a pass.
Checksums verify(const Span& span, std::uint64_t base, const Metadata& m);

}  // namespace omnitrace::lp
