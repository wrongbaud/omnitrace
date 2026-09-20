// SevenZip.h — the 7z archive structure, shared by the validator and the reader.
/// @file SevenZip.h
/// @brief Signature header, streams info and files info for `.7z` archives.
///
/// A 7z archive is a 32-byte signature header, then the packed data, then a
/// header at the very end describing all of it:
///
///     [ 32-byte signature header ][ packed streams ][ header ]
///                                                   ^ NextHeaderOffset
///
/// The header is usually itself compressed (an "encoded header"), so reading
/// an archive means decoding one folder before the real header can be parsed
/// at all. `read_archive` does that.
///
/// Its shape is unlike the other archive formats here. Files do not own their
/// bytes: the archive holds **folders**, each a small graph of coders
/// (LZMA2, BCJ, Copy, ...) that turns one or more packed streams into one
/// output stream, and that output is then cut into **substreams**, one per
/// file. So a file's data is a range of a folder's output, and a folder has
/// to be decoded whole to get at any of it -- which is why solid archives
/// compress so well and why extracting one file is not cheap.
///
/// It is in core because two layers read the same bytes: the `7z` validator
/// decides what a region is and how long it is, and
/// `container::SevenZipReader` decodes the folders. Everything here reads
/// through the Span and holds no global state.
///
/// Reference: the 7-Zip source's `DOC/7zFormat.txt`, read for understanding;
/// nothing copied.
#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "omnitrace/core/Span.h"
#include "omnitrace/core/Status.h"

/// @namespace omnitrace::sevenzip
/// @brief 7z archive structure parsing.
namespace omnitrace::sevenzip {

/// The six bytes a 7z archive starts with.
inline constexpr std::array<std::uint8_t, 6> kMagic{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
/// Bytes of signature header, after which the packed streams begin.
inline constexpr std::uint64_t kSignatureHeaderSize = 32;

/// One coder of a folder: what it is, how many streams it takes and gives,
/// and the properties the archive stored for it.
struct Coder {
    std::vector<std::uint8_t> id;     ///< The codec id, as stored.
    std::uint64_t num_in = 1;
    std::uint64_t num_out = 1;
    std::vector<std::uint8_t> props;
    /// "copy", "lzma", "lzma2", "bcj-x86", "aes256-sha256", ... or the id as hex.
    std::string name() const;
};

/// One folder: a coder graph turning packed streams into one output stream.
struct Folder {
    std::vector<Coder> coders;
    /// Bind pairs, each wiring a coder's input to another coder's output.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> binds;
    /// The in-stream indices that come straight from packed streams.
    std::vector<std::uint64_t> packed;
    /// Unpacked size of every out-stream, in coder order.
    std::vector<std::uint64_t> out_sizes;
    std::uint64_t first_pack_index = 0;  ///< Its first packed stream's index.
    bool has_crc = false;
    std::uint32_t crc = 0;

    std::uint64_t total_in() const;
    std::uint64_t total_out() const;
    /// The out-stream nothing is bound to: the folder's result. `total_out()`
    /// when the folder is malformed and there is no such stream.
    std::uint64_t final_out_index() const;
    /// How many bytes decoding the whole folder yields.
    std::uint64_t unpacked_size() const;
};

/// Everything about where the data is and how it is packed.
struct StreamsInfo {
    std::uint64_t pack_pos = 0;  ///< First packed stream, relative to the signature header's end.
    std::vector<std::uint64_t> pack_sizes;
    std::vector<Folder> folders;
    std::vector<std::uint64_t> substreams_per_folder;
    std::vector<std::uint64_t> substream_sizes;
    std::vector<std::uint32_t> substream_crcs;
    std::vector<bool> substream_crc_defined;
};

/// One entry of the archive's file list.
struct FileEntry {
    std::string name;          ///< UTF-8, converted from the stored UTF-16LE; raw.
    bool has_stream = true;    ///< False for directories and empty files.
    bool is_dir = false;
    std::uint64_t mtime = 0;   ///< Unix seconds; 0 when not recorded.
    bool has_mtime = false;
    std::uint32_t attributes = 0;
    bool has_attributes = false;
    /// The Unix mode p7zip stores in the high half of `attributes`, or 0.
    std::uint32_t unix_mode() const;
};

/// A parsed archive.
struct Archive {
    std::uint8_t version_major = 0, version_minor = 0;
    std::uint64_t next_header_offset = 0, next_header_size = 0;
    bool start_header_crc_ok = false;  ///< The 20-byte start header matched its CRC.
    bool header_crc_ok = false;        ///< The header matched its CRC.
    bool header_was_encoded = false;   ///< The header itself was compressed.
    StreamsInfo streams;
    std::vector<FileEntry> files;
    /// Bytes from the archive's first to one past its last, which is the end
    /// of the header.
    std::uint64_t size = 0;
};

/// Read the archive whose magic is at `at`.
///
/// Fails with a stable code: `7z-bad-magic`, `7z-truncated`,
/// `7z-bad-start-header`, `7z-header-crc-mismatch`, `7z-bad-header`, or
/// `7z-header-undecodable` when the header is compressed with something this
/// build cannot decode. `Archive::size` is set as soon as the start header
/// verifies, so a caller can size an archive it cannot fully parse.
Status read_archive(const Span& span, std::uint64_t at, Archive& out);

/// True when every coder of `f` is one `decompress_raw` can handle, so the
/// folder can be decoded. BCJ2, AES, PPMd and the deflate/bzip2 coders are
/// not, and say so through `unsupported_coder`.
bool folder_decodable(const Folder& f, std::string* unsupported_coder = nullptr);

/// True when `f` stores its data and then only runs byte filters over it, so
/// the packed bytes are the content with a reversible transform applied.
/// liblzma cannot run a byte filter without a compressor under it, so such a
/// folder is not decodable -- but its bytes are all there, which is worth
/// more to an examiner than nothing. `filter` names the transform.
bool folder_is_filtered_store(const Folder& f, std::string* filter = nullptr);

/// Decode the whole of `f` from the packed bytes at `pack_at`.
///
/// Fails with `7z-unsupported-coder` when a coder is not one this build has,
/// and with the usual decompression codes otherwise.
Status decode_folder(const Span& span, const Folder& f, std::uint64_t pack_at,
                     const std::vector<std::uint64_t>& pack_sizes,
                     std::vector<std::uint8_t>& out);

}  // namespace omnitrace::sevenzip
