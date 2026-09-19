# Competitive Landscape: Embedded / Firmware Forensic Analysis

Surveyed 2026-09-19 via web search plus GitHub API checks (language, license, last push, latest release). Dates marked "(API)" come from the GitHub API; vendor claims are from marketing pages and flagged where unverified.

## 1. Firmware extraction tools (the "unpack" layer)

**binwalk v3** — https://github.com/ReFirmLabs/binwalk — MIT, Rust. Complete rewrite; v3.1.0 (2024-10-31) is still the latest release (API), repo pushed 2026-08-11. Signature scan + recursive extraction, adds LUKS/NTFS/APFS/Btrfs, fewer false positives, Windows support. Kali ships it as `binwalk3` alongside the Python 2.4.x line. No hashing, no deleted-file recovery, no reports; still shells out to external extractors for several filesystems. Gap: extraction only, no forensic layer, release cadence has stalled.

**unblob** — https://github.com/onekey-sec/unblob — MIT, Python (with Rust helper). Actively maintained by ONEKEY; release 26.6.4 (2026-06-04), last push 2026-09-16. 83 handlers as of March 2026 (MSI, D-Link encimg/DEAFBEAD/FPKG, QNAP PC1, QNX deflate/UCL, UFS1/2, SquashFS variants). Best-in-class format coverage and a Python library API; JSON reports of chunks/offsets. Depends on ONEKEY's forks of sasquatch (C, GPL-2.0, v4.5.1-6, 2026-01-27), jefferson (v0.4.7, 2026-01-13), ubi_reader (0.8.16, 2026-09-04), all actively maintained (API). Gap: no hashing/chain of custody, no deleted-file recovery, no artifact search, no report generation; Linux/macOS oriented, Windows not first-class.

**moria + mithril** — https://github.com/nmatt0/moria and https://github.com/nmatt0/mithril — MIT, C++20, by Matt Brown (Brown Fine Security). Published 2026-09-08; v0.2.1 for both (2026-09-13, API), pushed 2026-09-19. Moria is a single static C++ binary that identifies and extracts SquashFS, JFFS2, UBI/UBIFS, YAFFS2, cramfs, romfs, EROFS, ext2/3/4, F2FS, FAT/exFAT, NTFS, HFS+, XFS, btrfs and containers (uImage, gzip, etc.) in-process with no external extractors, recursing automatically and rebuilding UBI volume-by-volume; JSON output with offsets and confidence. Mithril does offline secrets, SBOM (CycloneDX/SPDX), CVE (OSV/NVD/KEV/EPSS mirror), license, boot-chain and weak-key analysis. Open issues show QNX IFS (#20) and MBR/GPT region mapping (#21) in progress. Gap: explicitly no hashing, no deleted-file recovery, no reports, no PII/log/network artifact search; no web UI. Closest architectural neighbour to OmniTrace v2 (single C++ binary, JSON for agents) and the most likely candidate to vendor or link as an extraction core. Windows support unverified. No Coventry University connection found.

**FACT** — https://github.com/fkie-cad/FACT_core — GPL-3.0, Python, Fraunhofer FKIE. v4.4.1 (2026-09-14), pushed 2026-09-18. Web UI + REST/GraphQL, extraction via its own extractor container, plugin analyses (crypto material, software components, CVE lookup, strings, file type, hashes, firmware-version comparison). Ubuntu/Debian only with Docker/MongoDB/Redis. Gap: security-research orientation, heavy Linux-only server deployment, no deleted-file recovery, no forensic reporting or PII/connection-history artifacts. GPL-3 blocks code reuse in an Apache-2.0 project.

**EMBA** — https://github.com/e-m-b-a/emba — GPL-3.0, Bash. v2.0.3 (2026-07-21), pushed 2026-09-18; MCP server released Feb 2026. Full pipeline: extraction (wraps unblob/binwalk), static analysis, SBOM, CVE, system emulation (successor to Firmadyne/FirmAE, both unmaintained), HTML web report. Linux only, huge dependency footprint. Gap: vulnerability-focused, not evidence-focused; no hashing/chain-of-custody, no deleted files.

**OFRAK** — https://github.com/redballoonsecurity/ofrak — Python, source-available (OFRAK Community License, not OSI; Pro/Enterprise for commercial). GitHub tag ofrak-v3.2.0 (2023-08-10) but PyPI 3.3.0 (2025-10-03); pushed 2026-08-21. Unpack/modify/repack with resource tree, GUI, JFFS2/ext/SquashFS/UBI unpackers, Ghidra/Binary Ninja/angr backends. Gap: RE/modification platform, license blocks commercial embedding, no forensic features.

**Firmware Analysis Toolkit (attify)** — https://github.com/attify/firmware-analysis-toolkit — Rewritten in Rust (pushed 2026-09-08) under FSL-1.1-ALv2 (source-available). Now a "firmware security research platform": blob classification, filesystem inventory, ELF taint tracing, edge-AI artifact detection, QEMU emulation. Gap: security research, not open source, no forensic layer.

**firmwalker** — original craigz28/firmwalker returns HTTP 404 as of 2026-09-19 (reason unverified). Forks such as zhibx/firmwalker_pro (pushed 2026-08-08) persist. Bash grep-script over an extracted rootfs for passwd/shadow, keys, certs, URLs, emails, IPs. Gap: trivial, unmaintained, unstructured. Its pattern list is a useful seed for YAML artifact rules.

**fwanalyzer (Cruise)** — https://github.com/cruise-automation/fwanalyzer — Apache-2.0, Go; last push 2023-10-08, dormant. Rule-driven checks (file presence, permissions, hashes, strings) over ext/FAT/SquashFS/UBIFS/cpio images; JSON report. Gap: dead, security QA not forensics. Its TOML rule model is a good reference for the YAML rule format.

**Legacy:** firmware-mod-kit (C/shell, code.google export, no releases), yaffshiv (Python, last push 2024-08-30), Firmware_Slap (2020, abandoned), Firmadyne (2024, unmaintained; ~1 % emulation success on 2024 test set vs EMBA ~77 %).

## 2. General digital-forensics suites (the "evidence" layer)

**The Sleuth Kit / Autopsy** — https://github.com/sleuthkit — C (TSK), Java (Autopsy). TSK 4.15.0 (2026-04-15), Autopsy 4.23.1 (2026-05-07). Filesystems: NTFS, FAT/exFAT, HFS+, APFS, ext2/3/4, UFS, ISO9660, YAFFS2 (with deleted-chunk reconstruction). Full forensic model: hashing, hash sets, deleted/unallocated recovery (tsk_recover), timelines, keyword search, reports. No SquashFS, UBIFS, JFFS2, cramfs, QNX6, F2FS, EROFS. Gap: cannot open most embedded images without pre-extraction; Autopsy is a Windows-centric Java desktop app. Complementary: libtsk is the natural dependency for ext4/FAT/YAFFS2 deleted-file recovery and the reference abstraction model.

**UBIFT** — https://github.com/matthias-deu/ubift — MIT, Python (DFRWS EU 2024). TSK-style layered UBI/UBIFS parser with `--deleted` recovery via journal/index and an Autopsy ingest module. Last push 2024-02-18, dormant. The only known open-source UBIFS deleted-file recovery; port candidate.

**qnxmount (NFI)** — https://github.com/NetherlandsForensicInstitute/qnxmount — Apache-2.0, Python/Kaitai/FUSE. QNX6/ETFS/EFS with vehicle-forensics quirks (>4K blocks). Last push 2025-05-15; Linux only.

**qnxprobe (Brignoni)** — https://github.com/abrignoni/qnxprobe — MIT, Python stdlib only, v1.29 (2026-09-13), pushed 2026-09-18. Reads QNX6/QNX4/ETFS/EFS/IFS, ext2-4, F2FS, FAT32/exFAT, NTFS, HFS+, APFS from raw/E01 images by on-disk structure, extracts to zip with a provenance manifest (volumes.json), deleted-file recovery for NTFS/FAT/exFAT/F2FS, cross-platform binaries, feeds LEAPP. Very new and moving fast; closest open-source thing to "infotainment forensics".

**LEAPP family (iLEAPP/ALEAPP/VLEAPP)** — https://github.com/abrignoni/VLEAPP — MIT, Python. VLEAPP v2026.4.0 (2026-09-13) parses vehicle/infotainment logical extractions (a range of vehicle makes) into HTML/TSV/timeline. Gap: artifact parsers only, expects already-extracted filesystems; no imaging/partition/extraction. Useful as an artifact catalogue.

**plaso/log2timeline** — https://github.com/log2timeline/plaso — Apache-2.0, Python, release 20260720. Super-timeline from files/images via dfVFS (ext, FAT, NTFS, APFS); no SquashFS/UBIFS/JFFS2. Complementary for timelines of extracted rootfs.

**bulk_extractor** — https://github.com/simsong/bulk_extractor — C++, v2.2.0 (2026-08-18). Filesystem-agnostic scanning for emails, URLs, credit cards, phone numbers, JSON, EXIF, etc. with histograms; also carves. Directly relevant as a proven C++ scanner architecture for PII on raw dumps. No MAC-address or log-format scanners by default.

**PhotoRec/TestDisk** (C, GPL-2.0, v7.2 stable, pushed 2026-08-19), **scalpel** (dormant since 2024), **foremost** (legacy): signature carvers usable on raw flash after ECC/OOB stripping; no flash-filesystem awareness.

## 3. Commercial forensics suites

- **Cellebrite (UFED/Inseyets/Physical Analyzer):** chip-off and eMMC dumps handled as mobile "physical" images; 5-day chip-off course. Spring 2026 release emphasises Corellium virtual automotive/infotainment environments rather than infotainment dump parsing. No embedded-Linux flash FS support advertised.
- **Magnet AXIOM / AXIOM Cyber:** ingests JTAG/chip-off images, imports Berla iVe exports (.ivo) since 5.5; markets "IoT" broadly. No SquashFS/UBIFS/JFFS2 parsing found.
- **Berla iVe:** the de-facto commercial infotainment/telematics tool (Gen 5 kit; v4.15 adds 2020-2026 Subaru/Toyota). Closed, hardware-kit based, vehicle-model driven; no generic firmware analysis.
- **MSAB XRY/XAMN:** chip-off/JTAG for phones (NIST-tested); has an "embedded system forensics" glossary page but no product features for flash filesystems.
- **Oxygen Forensic Detective:** v17.2; drones (DJI/Parrot/Autel), Alexa/Google Home, some vehicle infotainment imports. Windows only.
- **GMDSOFT MD-NEXT/MD-DRONE:** chip-off (MD-READER), JTAG, IoT/Smart TV/drone extraction; Korean LE market.
- **Belkasoft X, X-Ways, Exterro FTK, Paraben E3:** disk-centric; Belkasoft/Paraben claim "drone/car/IoT" at the artifact-import level. None list embedded flash filesystems.

All are Windows, closed, and priced per seat; none do recursive firmware-container unpacking. Feature claims are from marketing pages and were not verified hands-on.

## 4. Commercial firmware-security platforms (not forensics)

ONEKEY (unblob upstream; Düsseldorf), Finite State (acquired MergeBase 2024), BugProve (on-prem/air-gapped option), NetRise (agreement to be acquired by Accenture, June 2026), Binarly, Eclypsium (Series C, March 2026), Microsoft Defender for IoT firmware analysis (ex-ReFirm Centrifuge / Binwalk Enterprise). All are SBOM/CVE/vulnerability products for product-security teams, not evidence tools: no hashing/chain of custody, deleted data, PII, or court reports. "Cyberus" could not be identified as a firmware-analysis vendor (Cyberus Technology is a hypervisor company).

## 5. Comparison table

| Tool | License / Lang | Extract & recurse | Flash FS (Sq/UBI/JFFS2/YAFFS/QNX6) | Hashing / CoC | Deleted recovery | Artifact search | Reports | Cross-platform | Status |
|---|---|---|---|---|---|---|---|---|---|
| binwalk 3 | MIT / Rust | Yes | Sq, UBI, JFFS2, YAFFS (ext.) / no QNX6 | No | No | No | No | L/M/W | v3.1.0 2024, stalled |
| unblob | MIT / Py+Rust | Yes (83 fmts) | Sq, UBI, JFFS2, YAFFS, QNX bits | No | No | No | JSON | L/M | 26.6.4, very active |
| moria/mithril | MIT / C++ | Yes | Sq, UBI, JFFS2, YAFFS, EROFS, F2FS; QNX IFS WIP | No | No | secrets only | JSON | L/M (W unverified) | v0.2.1 Sep 2026 |
| FACT | GPL-3 / Py | Yes | via unpackers | file hashes | No | crypto/strings | web | Linux server | v4.4.1 Sep 2026 |
| EMBA | GPL-3 / Bash | Yes (wraps) | via unblob/binwalk | No | No | creds/CVE | HTML | Linux | v2.0.3 Jul 2026 |
| OFRAK | source-avail / Py | Yes | Sq, JFFS2, UBI, ext | No | No | No | GUI | L/M/W | 3.3.0 Oct 2025 |
| TSK/Autopsy | IPL-CPL / C+Java | No | YAFFS2, ext4 only | Yes | Yes | keyword/regex | Yes | W/L/M | 4.15/4.23 2026 |
| UBIFT | MIT / Py | No | UBIFS | No | Yes (UBIFS) | No | Autopsy | L | dormant 2024 |
| qnxprobe | MIT / Py | partitions | QNX6/4/ETFS/EFS/IFS, F2FS | self-test | NTFS/FAT/F2FS | No | manifest | W/M/L | v1.29 Sep 2026 |
| VLEAPP | MIT / Py | No | n/a | No | No | vehicle artifacts | HTML/TSV | W/M/L | 2026.4.0 |
| bulk_extractor | C++ | No | n/a | No | carve | PII (email/URL/CC) | histograms | W/M/L | 2.2.0 Aug 2026 |
| plaso | Apache / Py | No | ext/FAT/NTFS | No | No | timeline | Yes | W/M/L | 20260720 |
| Berla iVe / AXIOM / Cellebrite / Oxygen | commercial | limited | none | Yes | some | Yes | Yes | Windows | active |

## 6. Synthesis

**Direct competitors (partial overlap, none complete).** No tool does the full pipeline. Nearest are moria+mithril (same language and single-binary/JSON philosophy, but no forensic layer and only two weeks old), FACT (web UI + hashing + plugins, but Linux-server, GPL, security-focused) and qnxprobe (forensic provenance + infotainment filesystems, but Python and no recursive container unpacking or artifact rules). Commercial suites own the reporting/court side but cannot open SquashFS/UBIFS/JFFS2/QNX6 images natively; Berla owns infotainment but is closed and vehicle-model bound.

**Adjacent / wrappable / portable.**
- unblob: call as an optional subprocess plugin for the long tail of vendor container formats; consume its JSON.
- moria: evaluate linking or vendoring as a C++ extraction core to reach unblob/binwalk parity quickly (MIT, C++20).
- libtsk: ext4/FAT/YAFFS2 deleted recovery and the abstraction-layer model.
- UBIFT: port its UBIFS journal/deleted-inode logic to C++.
- qnxmount / qnxprobe / dumpifs: QNX6/ETFS/EFS/IFS parsing references.
- bulk_extractor: C++ scanner design for PII/MAC/URL over raw dumps.
- fwanalyzer / firmwalker: seed rule sets for YAML artifact definitions.
- VLEAPP / ALEAPP: artifact parser catalogue for Linux/Android/vehicle targets.
- plaso: timeline export target.

**White space for an open-source, cross-platform C++ suite.**
1. No open-source tool combines recursive firmware extraction with a forensic chain of custody (image hashing, per-file hashes, extraction provenance manifest) and examiner reports.
2. Deleted-file recovery for flash filesystems is essentially absent: only UBIFT (dormant, UBIFS) and TSK (YAFFS2/ext4). JFFS2 obsolete-node recovery, UBIFS journal replay, YAFFS2 chunk history and F2FS/ext4 on eMMC in one engine does not exist.
3. No tool handles raw NAND dumps (OOB/ECC stripping, bad-block handling) as a first-class input before filesystem parsing.
4. Artifact hunting for evidence rather than vulnerabilities (MAC/IMEI/serials, Wi-Fi/Bluetooth pairing history, connection logs, PII, certificates, users) with user-supplied YAML/glob rules and markdown/YAML output for downstream agents does not exist for embedded images.
5. Cross-platform single binary with a web UI: FACT/EMBA are Linux-server only, Autopsy is Java/Windows-first, commercial tools are Windows-only.
6. OS-aware analyzers (Linux, Android, QNX, RTOS) that map extracted filesystems into evidence categories, bridging "unblob output directory" and "Autopsy case".

**Caveats.** Vendor feature claims for Cellebrite/Magnet/MSAB/Oxygen embedded support are from marketing pages; moria's Windows support and the reason for firmwalker's 404 could not be verified; OFRAK's GitHub tags lag its PyPI releases.
