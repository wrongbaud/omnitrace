// UbiReader.h — UBI volume reassembly. See the .cpp for the layout.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// A UBI image: physical erase blocks (PEBs), each carrying one logical erase
/// block (LEB) of one volume. This reader puts the LEBs back in order and
/// emits one entry per volume -- the image a `ubiattach` would expose, which
/// is what a UBIFS or SquashFS reader can then be pointed at.
///
/// The PEB order on the medium says nothing about the LEB order: a volume's
/// blocks are scattered by wear levelling, and the same LEB can appear twice
/// when an update was interrupted. The later copy (higher `sqnum`) wins;
/// with `WalkOptions::history` the earlier ones are emitted too.
class UbiReader final : public ContainerReader {
   public:
    std::string format() const override { return "ubi"; }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

    /// The internal volume holding the volume table. Its LEBs are parsed for
    /// volume names but never emitted as a volume of their own.
    static constexpr std::uint32_t kLayoutVolumeId = 0x7FFFEFFFu;
    /// Volume ids at or above this are UBI's own, not a user's.
    static constexpr std::uint32_t kInternalVolumeStart = 0x7FFFEFFFu;

   private:
    /// One PEB that carries a LEB, as its VID header describes it.
    struct Leb {
        std::uint64_t peb = 0;        ///< PEB index in the image.
        std::uint64_t data_off = 0;   ///< Span-relative first byte of the LEB's data.
        std::uint64_t sqnum = 0;      ///< Global sequence number; higher is newer.
        std::uint32_t data_size = 0;  ///< Bytes used (static volumes only).
        std::uint32_t data_pad = 0;   ///< Bytes of the LEB the volume does not use.
        std::uint32_t used_ebs = 0;   ///< LEBs the volume uses (static volumes only).
        bool is_static = false;
        bool copy_flag = false;
    };

    /// Everything known about one volume after the PEB scan.
    struct Volume {
        std::uint32_t id = 0;
        std::string name;                   ///< From the volume table, else empty.
        bool is_static = false;
        std::map<std::uint32_t, Leb> lebs;  ///< lnum -> the newest copy.
        std::vector<std::pair<std::uint32_t, Leb>> superseded;  ///< Older copies, oldest first.
    };

    std::uint64_t derive_peb_size() const;
    void scan_pebs();
    void read_volume_table();
    std::uint64_t usable_leb_bytes(const Leb& leb) const;

    Span span_;
    bool opened_ = false;
    std::uint32_t vid_hdr_offset_ = 0, data_offset_ = 0, image_seq_ = 0;
    std::uint64_t peb_size_ = 0, peb_count_ = 0;
    std::uint64_t erased_pebs_ = 0, skipped_pebs_ = 0, unmapped_pebs_ = 0;
    std::uint64_t bogus_lnums_ = 0;
    std::map<std::uint32_t, Volume> volumes_;
    /// Volume-table records that passed their CRC, by volume id. Read in
    /// open() so info() can name the volumes; `vtbl_problem_` says what was
    /// wrong when the table did not parse, and walk() reports it.
    std::map<std::uint32_t, std::string> vtbl_names_;
    std::string vtbl_problem_;
};

}  // namespace omnitrace::container
