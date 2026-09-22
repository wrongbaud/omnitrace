// Lp.cpp — Android logical-partition (super) metadata. See Lp.h.
//
// Every read goes through the Span and is checked. The tables are a map an
// attacker controls: a partition may claim extents that are not in the extent
// table, an extent may claim more sectors than the device holds, and a table
// descriptor may point anywhere. None of that is allowed to become an
// out-of-range read or an overflowed size, so offsets saturate and every
// range is tested against both the slot and the Span.
#include "omnitrace/core/Lp.h"

#include <algorithm>
#include <limits>

#include "omnitrace/core/Hash.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::lp {

namespace {

constexpr Endian kLE = Endian::Little;

std::uint64_t sat_add(std::uint64_t a, std::uint64_t b) {
    return a > std::numeric_limits<std::uint64_t>::max() - b
               ? std::numeric_limits<std::uint64_t>::max()
               : a + b;
}
std::uint64_t sat_mul(std::uint64_t a, std::uint64_t b) {
    if (a == 0 || b == 0) return 0;
    return a > std::numeric_limits<std::uint64_t>::max() / b
               ? std::numeric_limits<std::uint64_t>::max()
               : a * b;
}

// A NUL-padded fixed-width name field, sanitised. Names reach the manifest and
// become path components, so they are never trusted as bytes.
std::string name_field(const Span& span, std::uint64_t off, std::size_t width) {
    const auto raw = span.bytes(off, width);
    if (!raw) return {};
    std::size_t n = 0;
    while (n < raw->size() && (*raw)[n] != 0) ++n;
    return sanitize_utf8(std::span<const std::uint8_t>(raw->data(), n));
}

// One {offset, num_entries, entry_size} table descriptor.
struct TableDesc {
    std::uint32_t offset = 0, num_entries = 0, entry_size = 0;
};

std::optional<TableDesc> read_desc(const Span& span, std::uint64_t off) {
    const auto a = span.at<std::uint32_t>(off, kLE);
    const auto b = span.at<std::uint32_t>(off + 4, kLE);
    const auto c = span.at<std::uint32_t>(off + 8, kLE);
    if (!a || !b || !c) return std::nullopt;
    return TableDesc{*a, *b, *c};
}

// Where `desc`'s rows start, given the byte after the header. nullopt when the
// table does not fit inside the slot or inside the Span, or when a row is
// smaller than the fields this build reads out of it.
std::optional<std::uint64_t> table_base(const Span& span, std::uint64_t tables_base,
                                        const TableDesc& desc, std::uint64_t slot_end,
                                        std::uint32_t min_entry_size, std::uint32_t max_entries) {
    if (desc.num_entries > max_entries) return std::nullopt;
    if (desc.num_entries != 0 && desc.entry_size < min_entry_size) return std::nullopt;
    const std::uint64_t base = sat_add(tables_base, desc.offset);
    const std::uint64_t len = sat_mul(desc.num_entries, desc.entry_size);
    const std::uint64_t end = sat_add(base, len);
    if (end > slot_end || end > span.size()) return std::nullopt;
    return base;
}

}  // namespace

std::optional<std::vector<Extent>> Metadata::partition_extents(const Partition& p) const {
    const std::uint64_t end = sat_add(p.first_extent, p.num_extents);
    if (end > extents.size()) return std::nullopt;
    return std::vector<Extent>(extents.begin() + static_cast<std::ptrdiff_t>(p.first_extent),
                               extents.begin() + static_cast<std::ptrdiff_t>(end));
}

std::uint64_t Metadata::partition_size(const Partition& p) const {
    const auto own = partition_extents(p);
    if (!own) return 0;
    std::uint64_t total = 0;
    for (const Extent& e : *own) total = sat_add(total, sat_mul(e.num_sectors, kSectorSize));
    return total;
}

std::uint64_t Metadata::device_size() const {
    std::uint64_t biggest = 0;
    for (const BlockDevice& d : block_devices) biggest = std::max(biggest, d.size);
    return biggest;
}

std::optional<Geometry> read_geometry(const Span& span, std::uint64_t base) {
    const std::uint64_t off = sat_add(base, kGeometryOffset);
    const auto magic = span.at<std::uint32_t>(off, kLE);
    if (!magic || *magic != kGeometryMagic) return std::nullopt;

    Geometry g;
    const auto struct_size = span.at<std::uint32_t>(off + 4, kLE);
    // magic(4) struct_size(4) checksum[32] -> the three sizes start at 40 and
    // the struct is 52 bytes.
    const auto max_size = span.at<std::uint32_t>(off + 40, kLE);
    const auto slots = span.at<std::uint32_t>(off + 44, kLE);
    const auto block = span.at<std::uint32_t>(off + 48, kLE);
    if (!struct_size || !max_size || !slots || !block) return std::nullopt;
    g.struct_size = *struct_size;
    g.metadata_max_size = *max_size;
    g.metadata_slot_count = *slots;
    g.logical_block_size = *block;

    // What a real geometry looks like: it describes itself, it leaves room for
    // a header, it has at least one slot, and its block size is a power of two
    // that a block device could have.
    if (g.struct_size < 52 || g.struct_size > kGeometrySize) return std::nullopt;
    if (g.metadata_max_size < kMinHeaderSize || g.metadata_max_size > kMaxMetadataSize)
        return std::nullopt;
    if (g.metadata_slot_count == 0 || g.metadata_slot_count > kMaxSlots) return std::nullopt;
    if (g.logical_block_size < 512 || (g.logical_block_size & (g.logical_block_size - 1)) != 0)
        return std::nullopt;
    return g;
}

std::optional<Metadata> read_metadata(const Span& span, std::uint64_t base, const Geometry& geom) {
    const std::uint64_t slot = sat_add(base, kMetadataOffset);
    const auto magic = span.at<std::uint32_t>(slot, kLE);
    if (!magic || *magic != kHeaderMagic) return std::nullopt;

    Metadata m;
    m.geometry = geom;
    m.slot_offset = slot;
    const auto major = span.at<std::uint16_t>(slot + 4, kLE);
    const auto minor = span.at<std::uint16_t>(slot + 6, kLE);
    const auto header_size = span.at<std::uint32_t>(slot + 8, kLE);
    if (!major || !minor || !header_size) return std::nullopt;
    m.major_version = *major;
    m.minor_version = *minor;
    m.header_size = *header_size;
    if (m.header_size < kMinHeaderSize || m.header_size > geom.metadata_max_size)
        return std::nullopt;

    // 12 bytes of header, a 32-byte header checksum, tables_size, a 32-byte
    // tables checksum, then the four descriptors.
    const auto tables_size = span.at<std::uint32_t>(slot + 44, kLE);
    if (!tables_size) return std::nullopt;
    m.tables_size = *tables_size;

    const std::uint64_t desc0 = sat_add(slot, 80);
    const auto partitions = read_desc(span, desc0);
    const auto extents = read_desc(span, desc0 + 12);
    const auto groups = read_desc(span, desc0 + 24);
    const auto devices = read_desc(span, desc0 + 36);
    if (!partitions || !extents || !groups || !devices) return std::nullopt;

    const std::uint64_t tables_base = sat_add(slot, m.header_size);
    const std::uint64_t slot_end = sat_add(slot, geom.metadata_max_size);

    const auto p_base = table_base(span, tables_base, *partitions, slot_end, 52, kMaxPartitions);
    const auto e_base = table_base(span, tables_base, *extents, slot_end, 24, kMaxExtents);
    // Row sizes liblp defines: partition 52, extent 24, group 44 (name[36] +
    // u64), block device 60 (u64 + 2 x u32 + u64 + name[36]). A row may be
    // larger in a newer version and is then read by field offset, but one
    // smaller cannot hold what is read out of it.
    const auto d_base = table_base(span, tables_base, *devices, slot_end, 60, kMaxSlots);
    if (!p_base || !e_base || !d_base) return std::nullopt;
    if (!table_base(span, tables_base, *groups, slot_end, 44, kMaxPartitions)) return std::nullopt;
    m.group_count = groups->num_entries;

    m.partitions.reserve(partitions->num_entries);
    for (std::uint32_t i = 0; i < partitions->num_entries; ++i) {
        const std::uint64_t row = sat_add(*p_base, sat_mul(i, partitions->entry_size));
        Partition p;
        p.name = name_field(span, row, 36);
        const auto attrs = span.at<std::uint32_t>(row + 36, kLE);
        const auto first = span.at<std::uint32_t>(row + 40, kLE);
        const auto count = span.at<std::uint32_t>(row + 44, kLE);
        const auto group = span.at<std::uint32_t>(row + 48, kLE);
        if (!attrs || !first || !count || !group) return std::nullopt;
        p.attributes = *attrs;
        p.first_extent = *first;
        p.num_extents = *count;
        p.group_index = *group;
        m.partitions.push_back(std::move(p));
    }

    m.extents.reserve(extents->num_entries);
    for (std::uint32_t i = 0; i < extents->num_entries; ++i) {
        const std::uint64_t row = sat_add(*e_base, sat_mul(i, extents->entry_size));
        Extent e;
        const auto sectors = span.at<std::uint64_t>(row, kLE);
        const auto type = span.at<std::uint32_t>(row + 8, kLE);
        const auto data = span.at<std::uint64_t>(row + 12, kLE);
        const auto source = span.at<std::uint32_t>(row + 20, kLE);
        if (!sectors || !type || !data || !source) return std::nullopt;
        e.num_sectors = *sectors;
        // An unknown target type is not a reason to reject the map -- a newer
        // liblp may add one -- but it is not Linear either, and the reader
        // must not read bytes for it. Anything but 0 is treated as Zero.
        e.target = *type == 0 ? Target::Linear : Target::Zero;
        e.target_data = *data;
        e.target_source = *source;
        m.extents.push_back(e);
    }

    m.block_devices.reserve(devices->num_entries);
    for (std::uint32_t i = 0; i < devices->num_entries; ++i) {
        const std::uint64_t row = sat_add(*d_base, sat_mul(i, devices->entry_size));
        BlockDevice d;
        const auto first = span.at<std::uint64_t>(row, kLE);
        const auto align = span.at<std::uint32_t>(row + 8, kLE);
        const auto align_off = span.at<std::uint32_t>(row + 12, kLE);
        const auto size = span.at<std::uint64_t>(row + 16, kLE);
        if (!first || !align || !align_off || !size) return std::nullopt;
        d.first_sector = *first;
        d.alignment = *align;
        d.alignment_offset = *align_off;
        d.size = *size;
        d.name = name_field(span, row + 24, 36);
        m.block_devices.push_back(std::move(d));
    }

    // A partition naming extents that are not there is a broken map, not a
    // partition of unknown size: reject it here so no caller has to.
    for (const Partition& p : m.partitions)
        if (!m.partition_extents(p)) return std::nullopt;
    return m;
}

namespace {

// SHA-256 of `len` bytes at `off`, with `[zero_at, zero_at + 32)` taken as
// zeros -- liblp computes each checksum over the structure that holds it.
bool sha256_matches(const Span& span, std::uint64_t off, std::uint64_t len,
                    std::optional<std::uint64_t> zero_at) {
    if (len == 0 || len > kMaxMetadataSize) return false;
    const auto stored_at = zero_at ? *zero_at : off;
    const auto stored = span.bytes(stored_at, 32);
    auto buf = span.bytes(off, static_cast<std::size_t>(len));
    if (!buf || !stored) return false;
    if (zero_at) {
        const std::uint64_t rel = *zero_at - off;
        if (rel + 32 > buf->size()) return false;
        std::fill_n(buf->begin() + static_cast<std::ptrdiff_t>(rel), 32, std::uint8_t{0});
    }
    const Digests d = Hasher::of(std::span<const std::uint8_t>(buf->data(), buf->size()));
    static const char* kHex = "0123456789abcdef";
    std::string want;
    want.reserve(64);
    for (const std::uint8_t b : *stored) {
        want.push_back(kHex[b >> 4]);
        want.push_back(kHex[b & 0x0F]);
    }
    return !d.sha256.empty() && d.sha256 == want;
}

}  // namespace

Checksums verify(const Span& span, std::uint64_t base, const Metadata& m) {
    Checksums c;
    const std::uint64_t geom = sat_add(base, kGeometryOffset);
    // The geometry's own checksum covers the 52-byte struct with its 32-byte
    // checksum field (at +8) zeroed.
    c.geometry = sha256_matches(span, geom, 52, geom + 8);
    // The header's covers header_size bytes with its checksum (at +12) zeroed.
    c.header = sha256_matches(span, m.slot_offset, m.header_size, m.slot_offset + 12);
    // The tables' covers tables_size bytes starting after the header, and is
    // stored at +48 with nothing zeroed.
    const auto stored = span.bytes(m.slot_offset + 48, 32);
    if (stored && m.tables_size != 0) {
        const std::uint64_t tables = sat_add(m.slot_offset, m.header_size);
        const auto buf = span.bytes(tables, static_cast<std::size_t>(std::min<std::uint64_t>(
                                                m.tables_size, kMaxMetadataSize)));
        if (buf && m.tables_size <= kMaxMetadataSize) {
            const Digests d = Hasher::of(std::span<const std::uint8_t>(buf->data(), buf->size()));
            static const char* kHex = "0123456789abcdef";
            std::string want;
            want.reserve(64);
            for (const std::uint8_t b : *stored) {
                want.push_back(kHex[b >> 4]);
                want.push_back(kHex[b & 0x0F]);
            }
            c.tables = !d.sha256.empty() && d.sha256 == want;
        }
    }
    return c;
}

std::optional<Metadata> read(const Span& span, std::uint64_t base) {
    const auto geom = read_geometry(span, base);
    if (!geom) return std::nullopt;
    return read_metadata(span, base, *geom);
}

}  // namespace omnitrace::lp
