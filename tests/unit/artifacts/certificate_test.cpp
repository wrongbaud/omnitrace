// certificate_test.cpp — the certificate extractor.
//
// The PEM below is a real self-signed certificate and its key, generated once
// with `openssl req -x509 -newkey rsa:2048 -nodes` and pasted in, so the test
// is hermetic and the same on every host. It is a throwaway for `test.invalid`
// and authenticates nothing.
//
// Hostile inputs get as much attention as the good one: an extractor runs over
// every file in a case, and OpenSSL is being handed attacker-controlled bytes.
#include <gtest/gtest.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include "omnitrace/artifacts/Artifact.h"

using namespace omnitrace;
using namespace omnitrace::artifacts;
namespace stdfs = std::filesystem;

namespace {

const char* kCert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDgTCCAmmgAwIBAgIUG8+pz0U4DsZusAzeMfm14RyyNCQwDQYJKoZIhvcNAQEL\n"
    "BQAwPTELMAkGA1UEBhMCR0IxFzAVBgNVBAoMDk9tbmlUcmFjZSBUZXN0MRUwEwYD\n"
    "VQQDDAx0ZXN0LmludmFsaWQwHhcNMjYwOTIzMTMxODA5WhcNMzYwOTIwMTMxODA5\n"
    "WjA9MQswCQYDVQQGEwJHQjEXMBUGA1UECgwOT21uaVRyYWNlIFRlc3QxFTATBgNV\n"
    "BAMMDHRlc3QuaW52YWxpZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
    "AKeomaG7mdIvbzvo+kXQCnDvLjk0OHrueX16b1B5Fuugff9TTSxjuo612t530m7O\n"
    "w4IqH0t6kifX72aNgMHrQieZ8CeU7OgbifLFOnfCzWKOxbtGJX4pXPf9nhB/bmq/\n"
    "ISjb2nFid+PTNcbRi+5f86JywaC65qDho2vFQ5GA7Hbm1rNzcmyMPHGrGR8QF9eO\n"
    "2yXA4JXTmYlQPsvOke/jAkwG5Hp1/8sGl19asY5Tiwkw9wQ/43PtTW/x1LcfdNDN\n"
    "oMkLgZlelrKq7oNfOyc1dLs1pcDE0lsNXONHmPJaoksLbLVeMmi6JhTyNSsKk6zH\n"
    "gYC/duMPF+rc8SIme/tfo20CAwEAAaN5MHcwHQYDVR0OBBYEFCmuYWDnMsWJ39Sw\n"
    "6VMrBXQDtzecMB8GA1UdIwQYMBaAFCmuYWDnMsWJ39Sw6VMrBXQDtzecMA8GA1Ud\n"
    "EwEB/wQFMAMBAf8wJAYDVR0RBB0wG4IMdGVzdC5pbnZhbGlkggthbHQuaW52YWxp\n"
    "ZDANBgkqhkiG9w0BAQsFAAOCAQEAAm8OFFrTCvn8dnskAY7ZRpsIjQmGtcOSnSb4\n"
    "3N7GNZMuV+J3Q1xDJ96sGNQxCHNA70bzh9YCC2xRrKjFLOsmT/uGARzr3d3ZeTXj\n"
    "fdTrOoUajz+QPS6B/AXKRRykf4aTdhiofXK9bjAzOaFqjYuCmr6UQsN2A/NJc4X1\n"
    "QXQCzUAMwPd8VW9k6MK3tvi5lGoAKHhHwT3cqNV0uZC5ALWT3K5SRVSABVfDBA6F\n"
    "nBkScL7DPaDAj9H4VLq+EqcwX5oeLYq0L94+OecoprVPQ6KjzIa/IpaTkXYM/bRi\n"
    "2J7nxu4xKp2GBNKsB6OtXKjmfSvAY8Ut3InwViW/Cv/kNSlzXQ==\n"
    "-----END CERTIFICATE-----\n";

const char* kSmallKey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMTWIeLAN80UHWfy\n"
    "iB31Ch0KNvVw5LOoY0QQTJe56+0qFmAd8NLKev0VZjdbTFEcpRnuYV+1eR9A0zIk\n"
    "3drmMiZ1A/w6MP3m+ARcJVjq9TjqLZC/5cRhzIDrSE16xRyblYYnDcLl0A6J9iKR\n"
    "OT74IZNXVX+Z5Gbmx88QQ+AbbTB1AgMBAAECgYEAv4FegpBlOf/CBGoxCIRpjItt\n"
    "oSpvOGQx//yjqFLZOWtjTayTq2IYerchNeZ7v8bQ0wPcdRPIfiHB2N2Jg/nG+28R\n"
    "esXhOtpBViW+dWhoa2BxsTaJdbtAYo2BLO01Vx2Do6FSkQZLHfWVdIgPbp0vpAcm\n"
    "HHEIwKNb9sfozNnArgECQQD/gwEvOKj10bU/s/z9usXodiDVB13CEsw1wmne7bWN\n"
    "CExnPaWCDlkJBOPEg4HN2Fo4uhpTi3ccq2PZaz7OHS7BAkEAxTZsjCmXkVxVEq0S\n"
    "kgaeCxVGh9eAjKuKwOT1/t9kFyP9WlKfa/qLGF0iUdZOKnpL+HLUlINobf+AsdNB\n"
    "S3WitQJBAML23HWCv3Hq1WlJVpbo6FBrqrvCRilrHIU81nnzWh/GID56zIqDli6K\n"
    "m518VxSRrK4yWxo6heXLZYImEiNGI0ECQAcMKNjha58wM4IVWUKKpf8zZW/ZTai5\n"
    "QJ4gEIJpLUR+bsFZjoTnUS0vtthB1k1CTZC1Wc9s2sCDju/L4tt1erkCQAIfVIv7\n"
    "nFEoEWxdSo98lm3wDUMTXgFgEkRBMgdWceOw8WY2NiDOvq4++AsIYzbQqjr/U1Pu\n"
    "fK74k9aXcT2b8Fo=\n"
    "-----END PRIVATE KEY-----\n";

const char* kKey =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEuwIBADANBgkqhkiG9w0BAQEFAASCBKUwggShAgEAAoIBAQCnqJmhu5nSL287\n"
    "6PpF0Apw7y45NDh67nl9em9QeRbroH3/U00sY7qOtdred9JuzsOCKh9LepIn1+9m\n"
    "jYDB60InmfAnlOzoG4nyxTp3ws1ijsW7RiV+KVz3/Z4Qf25qvyEo29pxYnfj0zXG\n"
    "0YvuX/OicsGguuag4aNrxUORgOx25tazc3JsjDxxqxkfEBfXjtslwOCV05mJUD7L\n"
    "zpHv4wJMBuR6df/LBpdfWrGOU4sJMPcEP+Nz7U1v8dS3H3TQzaDJC4GZXpayqu6D\n"
    "XzsnNXS7NaXAxNJbDVzjR5jyWqJLC2y1XjJouiYU8jUrCpOsx4GAv3bjDxfq3PEi\n"
    "Jnv7X6NtAgMBAAECgf8XtSYEUk+hNeC3/mz/C9JuJcqWsph9MAhkT4VuDuSVOelj\n"
    "/jBR42HkZdLAb2RSRuqRsJZV4sv7PMDQv5gPBwIgl3DEjn2+VIz5+oNKBag4esSu\n"
    "UDz9AHXxzoS+nUZmODpE8zgjnS9W1LosYw7M2ZFmzaAtTXO1spjPpHu2SrfyGBE8\n"
    "fuauO8Nxmcn1yCCiSPeilgDJmYF0fpRqiMOrk28MOccx7pouyjvSnTr2kN2CEpYl\n"
    "c9gMldUzDx+G0XMTNyxwCdFwEuyX8bl5FoA6K+1kjiRK/phGCbPMmZN+3wnpCm2w\n"
    "OVr373NOecZCfOvDJ5TER2H9xhfidRTsDq1hw8ECgYEA1tYnN/flZlLB1fx+gBr/\n"
    "uMl48c8v31KjlcJ5pu8TiGZbqPTsKLbtgT+iq71slFOHO7cYTXocEmkQ1FykBPlY\n"
    "s1sqH7k+rhHIQ+Gh2uO+SFBxw5U76xWvQgysd9BJhPk6+G9HtEtz/5gq1aA8ycEF\n"
    "Uypc5gemb8FDo9IuGU88MJECgYEAx8hX/GQkZ0Eb8ssV7HzTA88syjCyoF5GlHQE\n"
    "b+wEfI741vR+i04kSPOI+T8/3iRsPrQglUG+Q577Ad5u4FTgEz21JIT0VQ640LKf\n"
    "2+nZFgoBKfY9Ukf3BsZTK8XMRndwtdX7T345SYzcBBC6H9dsTgKDdBLgR5KcXm4a\n"
    "Vaptcx0CgYBTvSuSRD0VckJ9ryp7sopks5tB3blSOfrrX99dMykQ7JzjsXvvrsXK\n"
    "sEwu1ungsuIuY4LEiEky3+Mgc2+3RJ3PY0R7ExCcdu/xjZwyHr1HoJuHWb7+NfiX\n"
    "LSt4lCZj/2V9+pofa52uTdi8ZfXryiHSNdv6CZdVTiaYT0+Kq/jREQKBgGyww6Wt\n"
    "udxvIMxzzsatloQBB8YsvlHfWJjVkcBucHZvtlQECoCxj64cyM2Jqq6ptDZc+0kY\n"
    "znGtobP/luT3aD0vmkh3CRLpgoUQWUZksFV8NevlarFEM9H8vi0XXK6NtsVG2IYE\n"
    "DxjDyMNxckF2ixbZ6TiSOHDYA7igQDWRFiDFAoGBAIR2lGyzX8AyqmCHr8E4tObS\n"
    "/+1jJdimFn+2lrTjUHBWBpv6v0mNxBdtaK4ZOPeVmG9uRlBEWaLiDyIQ+w4aumo0\n"
    "N6Q4FEkImNzsagX6UjPRNMaCy9s7btpuuiQsH2Q+aMNGFvsqUma1MRheLWscMhh2\n"
    "K/rAKIx9uMKKKaRy79ck\n"
    "-----END PRIVATE KEY-----\n";

class TempDir {
   public:
    TempDir() {
        stdfs::path base;
        if (const char* env = std::getenv("OMNITRACE_TEST_TMPDIR"))
            base = env;
        else
            base = stdfs::temp_directory_path();
        static int counter = 0;
        std::random_device rd;
        path_ = base / ("omnitrace-cert-" + std::to_string(rd()) + "-" + std::to_string(counter++));
        stdfs::remove_all(path_);
        stdfs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        stdfs::remove_all(path_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    const stdfs::path& path() const { return path_; }

   private:
    stdfs::path path_;
};

// One filesystem of files with contents on disk, as a Sink would leave them.
class Fs {
   public:
    explicit Fs(const stdfs::path& root) : root_(root) {}
    Fs& file(const std::string& path, const std::string& content) {
        EntryResult e;
        e.meta.path = path;
        e.meta.kind = EntryKind::Regular;
        e.meta.size = content.size();
        const stdfs::path host = root_ / path;
        stdfs::create_directories(host.parent_path());
        std::ofstream f(host, std::ios::binary);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        e.host_path = host.string();
        e.written = true;
        entries_.push_back(std::move(e));
        return *this;
    }
    FilesystemEntries entries() const { return {{"n000001", entries_}}; }

   private:
    stdfs::path root_;
    std::vector<EntryResult> entries_;
};

const Artifact* of_kind(const Collection& c, const std::string& kind) {
    for (const Artifact& a : c.artifacts)
        if (a.kind == kind) return &a;
    return nullptr;
}
bool has_code(const std::vector<Diagnostic>& ds, const std::string& code) {
    for (const Diagnostic& d : ds)
        if (d.code == code) return true;
    return false;
}
std::size_t count_kind(const Collection& c, const std::string& kind) {
    std::size_t n = 0;
    for (const Artifact& a : c.artifacts)
        if (a.kind == kind) ++n;
    return n;
}

}  // namespace

TEST(CertificateExtractor, ParsesWhatARuleCanOnlyFind) {
    // The whole reason this layer exists: a search pack can say a certificate
    // is present, and only a parser can say what it is for.
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("etc/lighttpd/server.pem", kCert);
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));

    const Artifact* cert = of_kind(c, "certificate");
    ASSERT_NE(cert, nullptr);
    EXPECT_EQ(cert->path, "etc/lighttpd/server.pem");
    EXPECT_NE(cert->fields.at("subject").find("CN=test.invalid"), std::string::npos);
    EXPECT_EQ(cert->fields.at("self_signed"), "true");
    EXPECT_EQ(cert->fields.at("key_type"), "rsa");
    EXPECT_EQ(cert->fields.at("key_bits"), "2048");
    EXPECT_FALSE(cert->fields.at("not_before").empty());
    EXPECT_FALSE(cert->fields.at("not_after").empty());
    // What a certificate is actually for.
    ASSERT_NE(cert->fields.count("dns_names"), 0u);
    EXPECT_NE(cert->fields.at("dns_names").find("test.invalid"), std::string::npos);
}

TEST(CertificateExtractor, APrivateKeyIsAWarningAndIsNeverCopied) {
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("etc/lighttpd/server.pem", std::string(kCert) + kKey);
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));

    const Artifact* key = of_kind(c, "private-key");
    ASSERT_NE(key, nullptr) << "a key beside its certificate is the finding that matters";
    EXPECT_EQ(key->severity, Severity::Warning);
    EXPECT_EQ(key->fields.at("key_type"), "rsa");
    EXPECT_EQ(key->fields.at("key_bits"), "2048");
    EXPECT_TRUE(has_code(c.diagnostics, "artifact-private-key-present"));

    // No key material anywhere in the output. A report that quoted it would be
    // a key store.
    const std::string yaml = to_yaml(c);
    EXPECT_EQ(yaml.find("PRIVATE KEY"), std::string::npos);
    EXPECT_EQ(yaml.find("MII"), std::string::npos) << "no base64 body either";
    for (const auto& [k, v] : key->fields) EXPECT_LT(v.size(), 120u) << k;
}

TEST(CertificateExtractor, ATrustStoreIsCountedNotEnumerated) {
    // The corpus router ships 127 files of CA certificates. A record each is
    // 127 rows that say the same thing and bury the one certificate the device
    // actually uses.
    const TempDir tmp;
    Fs fs(tmp.path());
    for (int i = 0; i < 12; ++i) fs.file("etc/ssl/certs/ca-" + std::to_string(i) + ".crt", kCert);
    fs.file("etc/lighttpd/server.pem", kCert);
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));

    EXPECT_EQ(count_kind(c, "certificate"), 1u) << "only the device's own";
    ASSERT_EQ(count_kind(c, "certificate-bundle"), 1u) << "one row for the store, not one per file";
    const Artifact* bundle = of_kind(c, "certificate-bundle");
    ASSERT_NE(bundle, nullptr);
    EXPECT_EQ(bundle->path, "etc/ssl/certs") << "keyed on the directory";
    EXPECT_EQ(bundle->fields.at("certificates"), "12") << "the counts merge";
    EXPECT_EQ(c.summarised, 12u);
}

TEST(CertificateExtractor, HostileInputIsRefusedWithoutTakingTheRunDown) {
    const TempDir tmp;
    Fs fs(tmp.path());
    // A PEM header and nothing behind it.
    fs.file("a.pem", "-----BEGIN CERTIFICATE-----\n");
    // A header, a body that is not base64, and a footer.
    fs.file("b.pem",
            "-----BEGIN CERTIFICATE-----\n!!!!not base64!!!!\n-----END CERTIFICATE-----\n");
    // Truncated in the middle of a real certificate.
    fs.file("c.pem", std::string(kCert).substr(0, 200));
    // A .crt that is binary rubbish.
    std::string junk;
    for (int i = 0; i < 4096; ++i) junk.push_back(static_cast<char>((i * 37 + 11) & 0xFF));
    fs.file("d.crt", junk);
    // A header claiming to be a key, with a certificate's body.
    fs.file("e.pem", "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n");

    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c)) << "one bad file is not a reason to fail the run";
    EXPECT_TRUE(c.artifacts.empty()) << "nothing was parsed, so nothing is claimed";
    // Each file said why rather than failing silently.
    EXPECT_TRUE(has_code(c.diagnostics, "artifact-certificate-unparsable"));
}

TEST(CertificateExtractor, AWeakKeyIsCalledOut) {
    // The IP camera in the corpus keeps a 1024-bit RSA key in
    // etc/vendor_mgmt/priv-key.pem.
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("weak.pem", kSmallKey);
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    const Artifact* key = of_kind(c, "private-key");
    ASSERT_NE(key, nullptr);
    EXPECT_EQ(key->fields.at("key_bits"), "1024");
    EXPECT_TRUE(has_code(c.diagnostics, "artifact-weak-key"));
}

TEST(CertificateExtractor, FilesNoExtractorClaimsAreNotRead) {
    // `applies` is the cheap screen: it runs for every file in a case, so a
    // tree of ordinary files must cost a head read and nothing more.
    const TempDir tmp;
    Fs fs(tmp.path());
    fs.file("bin/busybox", std::string(4096, '\x7f'));
    fs.file("etc/passwd", "root:x:0:0::/root:/bin/sh\n");
    fs.file("var/log/messages", "Jan  1 00:00:00 box kernel: hello\n");
    Collection c;
    ASSERT_TRUE(collect(fs.entries(), {}, c));
    EXPECT_EQ(c.files_examined, 0u);
    EXPECT_TRUE(c.artifacts.empty());
    EXPECT_TRUE(c.diagnostics.empty());
}
