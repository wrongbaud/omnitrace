// verity.cpp — dm-verity hash-device superblock validator.
//
// 512-byte superblock, all little-endian (Linux drivers/md/dm-verity-target.c
// `struct verity_sb`, cryptsetup lib/verity/verity.c):
//    0 signature[8]  "verity\0\0"     8 version u32 (1)     12 hash_type u32 (0/1)
//   16 uuid[16]                      32 algorithm[32]      64 data_block_size u32
//   68 hash_block_size u32           72 data_blocks u64    80 salt_size u16
//   82 pad[6]                        88 salt[256]         344 pad[168]
// The superblock occupies the first hash block; the hash tree follows, one
// level per fan-out step (hash_block_size / digest_size children per block)
// down to the leaf level over the data blocks. Its size follows from the
// superblock, so the finding covers superblock + tree; forward-error-
// correction data (if any) is device-specific and not claimed.
#include <array>

#include "anchors.h"
#include "common.h"

namespace omnitrace::discovery {
namespace {

using namespace validators;

constexpr std::uint64_t kMinBlock = 512, kMaxBlock = 64u * 1024u;

std::string lower(std::string s) {
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

std::uint32_t digest_size(const std::string& algo) {
    if (algo == "sha256") return 32;
    if (algo == "sha1") return 20;
    if (algo == "sha512") return 64;
    return 0;
}

std::optional<Finding> validate_verity(const Span& span, std::uint64_t start,
                                       const Signature& sig) {
    if (start >= span.size()) return std::nullopt;
    std::array<std::uint8_t, 512> raw{};
    Finding f = make_finding(sig, start, Confidence::Magic);
    f.endian = Endian::Little;
    if (span.read(start, std::span<std::uint8_t>(raw.data(), raw.size())) != raw.size()) {
        diag(f, Severity::Warning, "verity-truncated-header",
             "fewer than 512 bytes available for the superblock");
        return f;
    }
    auto u32 = [&](std::size_t o) {
        return load_int<std::uint32_t>(raw.data() + o, Endian::Little);
    };
    const std::uint32_t version = u32(8);
    const std::uint32_t hash_type = u32(12);
    const std::uint32_t data_block_size = u32(64);
    const std::uint32_t hash_block_size = u32(68);
    const std::uint64_t data_blocks = load_int<std::uint64_t>(raw.data() + 72, Endian::Little);
    const std::uint16_t salt_size = load_int<std::uint16_t>(raw.data() + 80, Endian::Little);
    std::string algorithm;
    for (std::size_t i = 32; i < 64 && raw[i] != 0; ++i)
        algorithm.push_back(static_cast<char>(raw[i]));
    const std::string algo = lower(list_safe(algorithm));

    if (version != 1) {
        diag(f, Severity::Warning, "verity-unsupported-version",
             "superblock version " + dec(version) + " is not 1");
        return f;
    }
    if (hash_type > 1) {
        diag(f, Severity::Warning, "verity-bad-hash-type",
             "hash_type " + dec(hash_type) + " is neither 0 (Chrome OS) nor 1 (normal)");
        return f;
    }
    if (!is_pow2(data_block_size) || data_block_size < kMinBlock || data_block_size > kMaxBlock ||
        !is_pow2(hash_block_size) || hash_block_size < kMinBlock || hash_block_size > kMaxBlock) {
        diag(f, Severity::Warning, "verity-bad-block-size",
             "block sizes " + dec(data_block_size) + "/" + dec(hash_block_size) +
                 " are not powers of two in 512..65536");
        return f;
    }
    const std::uint32_t ds = digest_size(algo);
    if (ds == 0) {
        diag(f, Severity::Warning, "verity-bad-algorithm",
             "algorithm \"" + algo + "\" is not sha256, sha1 or sha512");
        return f;
    }
    if (salt_size > 256) {
        diag(f, Severity::Warning, "verity-bad-salt-size",
             "salt_size " + dec(salt_size) + " exceeds the 256-byte field");
        return f;
    }
    f.confidence = Confidence::Structural;
    f.attrs["version"] = dec(version);
    f.attrs["hash_type"] = dec(hash_type);
    f.attrs["uuid"] = uuid_raw(std::span<const std::uint8_t>(raw.data() + 16, 16));
    f.attrs["algorithm"] = algo;
    f.attrs["data_block_size"] = dec(data_block_size);
    f.attrs["hash_block_size"] = dec(hash_block_size);
    f.attrs["data_blocks"] = dec(data_blocks);
    f.attrs["data_bytes"] = dec(sat_mul(data_blocks, data_block_size));
    f.attrs["salt"] = hex_bytes(std::span<const std::uint8_t>(raw.data() + 88, salt_size));

    // Hash tree size: levels of ceil(n / per_block) blocks until one root block.
    const std::uint64_t per_block = hash_block_size / ds;
    std::uint64_t tree_blocks = 0;
    if (per_block >= 2 && data_blocks > 0) {
        std::uint64_t n = data_blocks;
        // ceil without the n + per_block - 1 wrap a hostile data_blocks near
        // UINT64_MAX would cause; the sums saturate so clamp_size sees a
        // huge claim, never a wrapped small one.
        while (n > 1) {
            n = n / per_block + (n % per_block != 0 ? 1 : 0);
            tree_blocks = sat_add(tree_blocks, n);
        }
    }
    f.attrs["hash_tree_blocks"] = dec(tree_blocks);
    const std::uint64_t claimed = sat_mul(sat_add(1, tree_blocks), hash_block_size);
    bool truncated = false;
    f.size = clamp_size(span, start, claimed, truncated);
    if (truncated) {
        diag(f, Severity::Warning, "verity-truncated",
             "superblock plus hash tree (" + dec(claimed) +
                 " bytes) extends past the available data");
    } else if (data_blocks > 0) {
        f.confidence = Confidence::Consistent;
    }
    f.evidence = algo + " over " + dec(data_blocks) + " data blocks of " + dec(data_block_size) +
                 ", hash tree " + dec(tree_blocks) + " block(s)";
    return f;
}

}  // namespace

OMNITRACE_REGISTER_VALIDATOR("verity", validate_verity);

}  // namespace omnitrace::discovery

OMNITRACE_VALIDATOR_ANCHOR(verity)
