// fixture.h — a fully populated Manifest shared by the output tests.
#pragma once
#include <string>
#include <vector>

#include "omnitrace/core/Manifest.h"
#include "omnitrace/core/Sink.h"

namespace omnitrace::output::test {

inline Digests sample_digests(char fill) {
    Digests d;
    d.md5 = std::string(32, fill);
    d.sha1 = std::string(40, fill);
    d.sha256 = std::string(64, fill);
    d.bytes = 4096;
    return d;
}

inline FileMeta full_file_meta() {
    FileMeta f;
    f.path = "etc/config/network.conf";
    f.kind = EntryKind::Regular;
    f.mode = 0100644;
    f.uid = 1000;
    f.gid = 100;
    f.size = 4096;
    f.mtime = 1700000000;
    f.ctime = 1700000001;
    f.atime = 1700000002;
    f.crtime = 1699999999;
    f.mtime_nsec = 123456789;
    f.ctime_nsec = 1;
    f.atime_nsec = 999999999;
    f.inode = 42;
    f.nlink = 2;
    f.link_target = "";
    f.rdev_major = 0;
    f.rdev_minor = 0;
    f.deleted = true;
    f.superseded = true;
    f.version = 7;
    f.extra["compression"] = "zlib";
    f.extra["xattrs"] = "security.selinux";
    return f;
}

// image -> partition -> filesystem -> {file (full meta), file (symlink), file (device)}
//       -> container -> region
//       -> artifact
inline Manifest full_manifest() {
    Manifest m;
    m.run.tool = "omnitrace";
    m.run.version = "0.1.0";
    m.run.git_sha = "0123abcd";
    m.run.started_at = "2026-01-02T03:04:05Z";
    m.run.finished_at = "2026-01-02T03:04:09Z";
    m.run.host_os = "linux";
    m.run.argv = {"omnitrace", "analyze", "--out", "case dir", "evidence|weird.bin"};

    Evidence ev;
    ev.id = "e1";
    ev.path = "/cases/router/spi-flash.bin";
    ev.size = 16u << 20;
    ev.digests = sample_digests('a');
    ev.acquired_at = "2025-12-31T23:59:59Z";
    ev.note = "SPI dump via flashrom";
    m.evidence.push_back(ev);

    Node img;
    img.kind = NodeKind::Image;
    img.name = "spi-flash.bin";
    img.format = "raw";
    img.location = {"e1", 0, 16u << 20};
    img.confidence = 99;
    img.evidence = "examiner supplied";
    img.digests = sample_digests('a');
    m.add_node(img);  // n000001

    Node part;
    part.kind = NodeKind::Partition;
    part.parent_id = "n000001";
    part.name = "rootfs";
    part.format = "mtd";
    part.location = {"e1", 0x100000, 0x400000};
    part.confidence = 85;
    part.evidence = "uboot mtdparts";
    part.attrs["index"] = "2";
    part.attrs["label"] = "rootfs";
    m.add_node(part);  // n000002

    Node fs;
    fs.kind = NodeKind::Filesystem;
    fs.parent_id = "n000002";
    fs.name = "squashfs";
    fs.format = "squashfs";
    fs.location = {"e1", 0x100000, 0x3f0000};
    fs.confidence = 60;
    fs.evidence = "superblock parsed";
    fs.endian = Endian::Big;
    fs.attrs["compression"] = "xz";
    fs.attrs["version"] = "4.0";
    fs.diagnostics.push_back({Severity::Warning, "squashfs-limit-entries", "entry limit reached"});
    fs.diagnostics.push_back({Severity::Info, "squashfs-note", "note: contains | pipe"});
    m.add_node(fs);  // n000003

    Node file;
    file.kind = NodeKind::File;
    file.parent_id = "n000003";
    file.name = "network.conf";
    file.location = {"e1", 0x123456, 4096};
    file.confidence = 99;
    file.file = full_file_meta();
    file.digests = sample_digests('b');
    m.add_node(file);  // n000004

    Node link;
    link.kind = NodeKind::File;
    link.parent_id = "n000003";
    link.name = "sh";
    link.file = FileMeta{};
    link.file->path = "bin/sh";
    link.file->kind = EntryKind::Symlink;
    link.file->mode = 0777;
    link.file->size = 7;
    link.file->link_target = "busybox";
    link.file->mtime = 1700000006;
    m.add_node(link);  // n000005

    Node dev;
    dev.kind = NodeKind::File;
    dev.parent_id = "n000003";
    dev.name = "console";
    dev.file = FileMeta{};
    dev.file->path = "dev/console";
    dev.file->kind = EntryKind::CharDevice;
    dev.file->mode = 0600;
    dev.file->rdev_major = 5;
    dev.file->rdev_minor = 1;
    m.add_node(dev);  // n000006

    Node cont;
    cont.kind = NodeKind::Container;
    cont.parent_id = "n000001";
    cont.name = "kernel";
    cont.format = "uimage";
    cont.location = {"e1", 0x40000, 0xc0000};
    cont.confidence = 25;
    cont.evidence = "magic only";
    m.add_node(cont);  // n000007

    Node region;
    region.kind = NodeKind::Region;
    region.parent_id = "n000007";
    region.name = "trailing";
    region.location = {"e1", 0xf0000, 0x10000};
    region.confidence = 0;
    region.diagnostics.push_back({Severity::Error, "region-unidentified", "no signature matched"});
    m.add_node(region);  // n000008

    Node art;
    art.kind = NodeKind::Artifact;
    art.parent_id = "n000004";
    art.name = "mac-address";
    art.format = "";
    art.location = {"e1", 0x123500, 17};
    art.confidence = 60;
    art.evidence = "regex";
    art.attrs["value"] = "00:11:22:33:44:55";
    m.add_node(art);  // n000009

    m.coverage.push_back({"squashfs", "supported", ""});
    m.coverage.push_back({"ubifs", "tool-missing", "no ubireader"});

    ToolRecord t;
    t.name = "sasquatch";
    t.version = "4.5";
    t.argv = {"-d", "out", "img"};
    t.exit_code = -1;
    t.seconds = 0.1;
    m.tools.push_back(t);

    m.diagnostics.push_back({Severity::Info, "run-note", "everything fine"});
    return m;
}

inline std::vector<EntryResult> sample_entries() {
    std::vector<EntryResult> out;
    EntryResult a;
    a.meta = full_file_meta();
    a.digests = sample_digests('c');
    a.host_path = "case/filesystems/n000003/files/etc/config/network.conf";
    a.written = true;
    out.push_back(a);

    EntryResult b;
    b.meta.path = "weird|name\nwith newline";
    b.meta.kind = EntryKind::Directory;
    b.meta.mode = 0755;
    b.meta.uid = 0;
    b.meta.gid = 0;
    b.truncated = true;
    b.diagnostics.push_back({Severity::Warning, "sink-limit-bytes", "stopped early"});
    out.push_back(b);

    EntryResult c;
    c.meta.path = "bin/sh";
    c.meta.kind = EntryKind::Symlink;
    c.meta.mode = 0777;
    c.meta.link_target = "busybox";
    c.meta.mtime = 1700000006;
    out.push_back(c);
    return out;
}

}  // namespace omnitrace::output::test
