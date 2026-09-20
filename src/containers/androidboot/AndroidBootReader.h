// AndroidBootReader.h — Android boot.img and vendor_boot.img.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/containers/Container.h"
#include "omnitrace/core/Span.h"

namespace omnitrace::container {

/// The Android boot image wrapper: a header followed by page-aligned
/// sections, each emitted under its own name (`kernel`, `ramdisk`, `second`,
/// `recovery_dtbo`, `dtb`, `boot_signature`; `vendor_ramdisk`,
/// `vendor_ramdisk_table`, `bootconfig` for a vendor boot image).
///
/// Header versions 0-4 of `ANDROID!` and 3-4 of `VNDRBOOT` are handled; they
/// differ enough in layout that the section table is built per version.
/// Sections are emitted as stored: a ramdisk is normally a gzipped cpio, and
/// the analysis pass re-scans what this writes, so the stream and archive
/// readers reach it one level down.
class AndroidBootReader : public ContainerReader {
   public:
    /// `vendor` selects the `VNDRBOOT` layout and the `android-vendor-boot`
    /// format id; the registry constructs one of each.
    explicit AndroidBootReader(bool vendor) : vendor_(vendor) {}

    std::string format() const override {
        return vendor_ ? "android-vendor-boot" : "android-boot";
    }
    Status open(const Span& span) override;
    ContainerInfo info() const override;
    Status walk(Sink& sink, const WalkOptions& opts, WalkResult& out) override;

   private:
    /// One page-aligned section of the image.
    struct Section {
        const char* name;
        std::uint64_t size;
    };

    bool vendor_ = false;
    Span span_;
    bool opened_ = false;
    std::uint32_t version_ = 0;
    std::uint32_t page_ = 0;
    std::uint64_t header_pages_ = 1;  // pages the header occupies before the first section
    std::uint64_t total_ = 0;
    std::string name_;
    std::vector<Section> sections_;
};

}  // namespace omnitrace::container
