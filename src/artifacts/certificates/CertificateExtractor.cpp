// CertificateExtractor.cpp — PEM certificates, private keys and DH parameters.
//
// The rules packs already *find* a "-----BEGIN CERTIFICATE-----" block. What
// they cannot do is say what it contains, and that is the whole value here: a
// certificate that expired in 2019, one issued to CN=router.local by itself,
// or -- the finding that matters most -- a private key sitting in the same
// file as the certificate it belongs to. The router in the corpus has exactly
// that in etc/lighttpd/server.pem.
//
// Two rules shape the output.
//
// **A private key's bytes are never copied anywhere.** The record says a key
// is present, what kind it is and how long, and names the file. A report that
// quoted key material would be a key store, which is the same argument the
// analyzers make about password hashes.
//
// **A CA trust store is summarised, not enumerated.** etc/ssl/certs on the
// corpus router holds 253 certificates that came with the firmware and say
// nothing about the device. Emitting 253 records buries the one certificate
// that does. Files under a trust-store path contribute a count and their
// expiry tally; everything else gets a record of its own.
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <memory>

#include "omnitrace/artifacts/Artifact.h"
#include "omnitrace/core/Text.h"

namespace omnitrace::artifacts {

namespace {

constexpr const char* kCodeUnparsable = "artifact-certificate-unparsable";
constexpr const char* kCodePrivateKey = "artifact-private-key-present";
constexpr const char* kCodeExpired = "artifact-certificate-expired";
constexpr const char* kCodeWeakKey = "artifact-weak-key";

// The paths a distribution's CA bundle lives at. A certificate here shipped
// with the firmware; one anywhere else was put there for this device.
bool is_trust_store(std::string_view path) {
    for (const char* dir : {"etc/ssl/certs/", "usr/share/ca-certificates/", "etc/ca-certificates/",
                            "etc/pki/tls/certs/", "system/etc/security/cacerts/"}) {
        if (path.find(dir) != std::string_view::npos) return true;
    }
    return false;
}

struct BioDeleter {
    void operator()(BIO* b) const { BIO_free(b); }
};
struct X509Deleter {
    void operator()(X509* x) const { X509_free(x); }
};
struct PkeyDeleter {
    void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); }
};

// An X509_NAME as one line, sanitised. OpenSSL's oneline form is stable enough
// to compare between runs, which matters for a byte-identical manifest.
std::string name_line(X509_NAME* n) {
    if (n == nullptr) return {};
    const std::unique_ptr<BIO, BioDeleter> bio(BIO_new(BIO_s_mem()));
    if (!bio) return {};
    X509_NAME_print_ex(bio.get(), n, 0, XN_FLAG_RFC2253);
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0 || data == nullptr) return {};
    return sanitize_utf8(std::string(data, static_cast<std::size_t>(len))).substr(0, 300);
}

// An ASN1_TIME as ISO-8601. Reported verbatim and never compared against the
// wall clock: whether a certificate is expired *now* depends on when "now" is,
// and the library does not read a clock outside core/Clock. Expiry is judged
// against the certificate's own notBefore/notAfter pair only.
std::string time_iso(const ASN1_TIME* t) {
    if (t == nullptr) return {};
    const std::unique_ptr<BIO, BioDeleter> bio(BIO_new(BIO_s_mem()));
    if (!bio) return {};
    if (ASN1_TIME_print(bio.get(), t) == 0) return {};
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    if (len <= 0 || data == nullptr) return {};
    return sanitize_utf8(std::string(data, static_cast<std::size_t>(len)));
}

std::string key_description(EVP_PKEY* k, unsigned& bits_out) {
    bits_out = 0;
    if (k == nullptr) return "unknown";
    bits_out = static_cast<unsigned>(EVP_PKEY_get_bits(k));
    const int id = EVP_PKEY_get_base_id(k);
    switch (id) {
        case EVP_PKEY_RSA:
            return "rsa";
        case EVP_PKEY_EC:
            return "ec";
        case EVP_PKEY_ED25519:
            return "ed25519";
        case EVP_PKEY_ED448:
            return "ed448";
        case EVP_PKEY_DSA:
            return "dsa";
        case EVP_PKEY_DH:
            return "dh";
        default:
            break;
    }
    return "other";
}

// An RSA or DSA key below this is not a defensible length today, and a DH
// parameter set below it is the same problem. Reported, never judged beyond
// saying so.
constexpr unsigned kWeakBits = 2048;

class CertificateExtractor final : public Extractor {
   public:
    std::string name() const override { return "certificates"; }

    bool applies(std::string_view path, std::span<const std::uint8_t> head) const override {
        // PEM is text and begins with a header line; a file that does not
        // start with one is not worth reading whole. DER certificates are
        // deliberately not handled yet -- see the known gaps in the docs.
        static constexpr std::string_view kBegin = "-----BEGIN ";
        const std::string_view text(reinterpret_cast<const char*>(head.data()), head.size());
        if (text.find(kBegin) != std::string_view::npos) return true;
        // A .crt or .pem whose first bytes are not a PEM header is still worth
        // a look: some ship with a comment block or a bag of attributes first.
        for (const char* ext : {".pem", ".crt", ".cer", ".key"})
            if (path.size() > 4 && path.compare(path.size() - 4, 4, ext + 0) == 0) return true;
        return false;
    }

    void extract(const FileRef& file, Yield& out) const override {
        const std::unique_ptr<BIO, BioDeleter> bio(
            BIO_new_mem_buf(file.bytes.data(), static_cast<int>(file.bytes.size())));
        if (!bio) return;

        const bool bundle = is_trust_store(file.path);
        unsigned certs = 0, expired_pairs = 0, keys = 0;
        std::string first_subject;
        bool anything = false;

        // PEM_read_bio_X509 walks the file one block at a time, so a bundle of
        // 150 certificates in one file is read in one pass.
        for (;;) {
            X509* raw = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
            if (raw == nullptr) break;
            const std::unique_ptr<X509, X509Deleter> cert(raw);
            anything = true;
            ++certs;
            Artifact a = describe(file, cert.get(), expired_pairs);
            if (first_subject.empty()) first_subject = a.fields["subject"];
            if (bundle) {
                ++out.summarised;
            } else {
                if (a.severity == Severity::Warning)
                    out.diagnostics.push_back({Severity::Warning, kCodeExpired,
                                               "'" + file.path + "': " + a.fields["subject"] +
                                                   " is not valid after " + a.fields["not_after"]});
                out.artifacts.push_back(std::move(a));
            }
        }

        // Private keys and DH parameters live in the same files and are the
        // reason this extractor exists. Rewind: the certificate pass consumed
        // the BIO.
        keys = scan_keys(file, out);
        anything = anything || keys != 0;

        if (bundle && certs != 0) {
            Artifact a;
            a.kind = "certificate-bundle";
            a.node = file.node;
            // Keyed on the directory, not the file. A trust store is 127
            // files on the corpus router, and a record per file is 127 rows
            // that each say "one CA certificate, from the bundle". collect()
            // merges records that share a (kind, node, path), so the store
            // comes out as one row with the real count.
            const std::size_t slash = file.path.rfind('/');
            a.path = slash == std::string::npos ? file.path : file.path.substr(0, slash);
            a.severity = Severity::Info;
            a.fields["certificates"] = std::to_string(certs);
            a.fields["expired_by_own_dates"] = std::to_string(expired_pairs);
            a.fields["first_subject"] = first_subject;
            a.fields["note"] = "a trust store that shipped with the firmware; counted, not listed";
            out.artifacts.push_back(std::move(a));
        }

        if (!anything)
            out.diagnostics.push_back(
                {Severity::Info, kCodeUnparsable,
                 "'" + file.path +
                     "' looks like PEM but holds no certificate, key or parameters this build "
                     "can read"});
        ERR_clear_error();  // a failed PEM read leaves the queue dirty
    }

   private:
    /// Lowercase hex SHA-256 of the certificate's DER encoding -- the same
    /// number `openssl x509 -fingerprint -sha256` prints, without the colons.
    static std::string sha256_fingerprint(X509* cert) {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        if (X509_digest(cert, EVP_sha256(), md, &len) != 1 || len == 0) return {};
        static const char* kHex = "0123456789abcdef";
        std::string out;
        out.reserve(static_cast<std::size_t>(len) * 2);
        for (unsigned int i = 0; i < len; ++i) {
            out += kHex[md[i] >> 4];
            out += kHex[md[i] & 0x0F];
        }
        return out;
    }

    static Artifact describe(const FileRef& file, X509* cert, unsigned& expired_pairs) {
        Artifact a;
        a.kind = "certificate";
        a.node = file.node;
        a.path = file.path;
        // SHA-256 over the DER: the fingerprint an examiner compares by hand,
        // and what says a certificate in another case is *this* certificate.
        // The subject is not an identity -- a vendor reissues under the same
        // CN -- and neither is the path.
        a.identity = sha256_fingerprint(cert);
        if (!a.identity.empty()) a.fields["fingerprint"] = a.identity;
        a.fields["subject"] = name_line(X509_get_subject_name(cert));
        a.fields["issuer"] = name_line(X509_get_issuer_name(cert));
        a.fields["not_before"] = time_iso(X509_get0_notBefore(cert));
        a.fields["not_after"] = time_iso(X509_get0_notAfter(cert));
        a.fields["self_signed"] =
            X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0 ? "true"
                                                                                        : "false";
        unsigned bits = 0;
        a.fields["key_type"] = key_description(X509_get0_pubkey(cert), bits);
        if (bits != 0) a.fields["key_bits"] = std::to_string(bits);
        const int sig = X509_get_signature_nid(cert);
        if (const char* sn = OBJ_nid2sn(sig); sn != nullptr) a.fields["signature"] = sn;
        a.fields["ca"] = X509_check_ca(cert) != 0 ? "true" : "false";

        // Subject alternative names are what a certificate is really *for*.
        if (auto* alts = static_cast<GENERAL_NAMES*>(
                X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr))) {
            std::string joined;
            for (int i = 0; i < sk_GENERAL_NAME_num(alts) && joined.size() < 400; ++i) {
                const GENERAL_NAME* gn = sk_GENERAL_NAME_value(alts, i);
                if (gn == nullptr || gn->type != GEN_DNS) continue;
                const ASN1_IA5STRING* s = gn->d.dNSName;
                if (s == nullptr || s->data == nullptr) continue;
                if (!joined.empty()) joined += ",";
                joined += sanitize_utf8(std::string(reinterpret_cast<const char*>(s->data),
                                                    static_cast<std::size_t>(s->length)));
            }
            GENERAL_NAMES_free(alts);
            if (!joined.empty()) a.fields["dns_names"] = joined;
        }

        // notBefore after notAfter is a certificate that was never valid at
        // all, which needs no clock to say.
        if (ASN1_TIME_compare(X509_get0_notAfter(cert), X509_get0_notBefore(cert)) < 0) {
            ++expired_pairs;
            a.severity = Severity::Warning;
        }
        return a;
    }

    // A second pass for keys and parameters: the certificate pass consumed the
    // BIO, and rewinding a memory BIO is cheaper than re-reading the file.
    static unsigned scan_keys(const FileRef& file, Yield& out) {
        const std::unique_ptr<BIO, BioDeleter> bio(
            BIO_new_mem_buf(file.bytes.data(), static_cast<int>(file.bytes.size())));
        if (!bio) return 0;
        unsigned found = 0;
        for (;;) {
            EVP_PKEY* raw = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
            if (raw == nullptr) break;
            const std::unique_ptr<EVP_PKEY, PkeyDeleter> key(raw);
            ++found;
            unsigned bits = 0;
            const std::string kind = key_description(key.get(), bits);

            Artifact a;
            a.kind = "private-key";
            a.node = file.node;
            a.path = file.path;
            a.severity = Severity::Warning;
            a.fields["key_type"] = kind;
            if (bits != 0) a.fields["key_bits"] = std::to_string(bits);
            // The key itself is never copied here. What matters is that one is
            // on the device and what it protects, not its value.
            a.fields["note"] = "key material is deliberately not recorded; read the file itself";
            out.artifacts.push_back(std::move(a));

            out.diagnostics.push_back(
                {Severity::Warning, kCodePrivateKey,
                 "'" + file.path + "' holds an unencrypted " + kind +
                     " private key; whatever it authenticates can be impersonated"});
            if ((kind == "rsa" || kind == "dsa" || kind == "dh") && bits != 0 && bits < kWeakBits)
                out.diagnostics.push_back({Severity::Info, kCodeWeakKey,
                                           "'" + file.path + "': the " + kind + " key is " +
                                               std::to_string(bits) + " bits"});
        }
        ERR_clear_error();
        return found;
    }
};

}  // namespace

OMNITRACE_REGISTER_EXTRACTOR("certificates", CertificateExtractor);

}  // namespace omnitrace::artifacts

namespace omnitrace::artifacts::detail {
void omnitrace_extractor_anchor_certificates() {}
}  // namespace omnitrace::artifacts::detail
