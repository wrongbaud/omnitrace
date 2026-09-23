# Search rules

Discovery answers *what is this?* Rules answer *is the thing an examiner came
looking for in here?* — a MAC address, a private key, a VIN, a password file —
across every extracted file and every region no signature claimed.

The set is deliberately the examiner's to extend. A pack is a YAML file, the
built-in ones are compiled into the binary, and `--rules <file>` adds more.

## The rtos pack: why this is a pack and not an analyzer

The platform analyzers take a `Tree` — a path namespace. An RTOS or bare-metal
image has no filesystem, so there is nothing for an analyzer to look at, and
`rules::sweep` already searches every region no signature claimed. That is
exactly where this firmware lives, so the RTOS work is a search pack.

**Every rule is anchored on a version or a copyright, never on the bare product
name.** The corpus contains the trap that makes this necessary: a U-Boot
image-type table listing `FreeRTOS`, `VxWorks`, `RTEMS` and every other OS it
can boot. That table is not evidence that any of them is present, and a pack
matching bare names would report an RTOS on an ordinary Linux camera.

Two things the corpus corrected in the first draft:

* **`bad magic` had to go.** It is an ordinary error string in busybox,
  openssl and libcrypto, and fired nine times on a router with no bootloader
  in it at all.
* **`\W` as a word separator matches NUL**, so `image\x00\x00\x00invalid`
  matched across two unrelated entries of a string table. The separator is
  printable punctuation and space only — boot code writes `[CRC Check Fail]`,
  not `CRC\0Check\0Fail`.

`gcc-banner` and `arm-eabi-toolchain` are `scope: [regions]`. Every ELF in a
filesystem carries the GCC banner in `.comment`, so in a walked tree they fire
once per binary — 307 times on one corpus image — and say nothing the file
itself does not. In an unidentified blob the banner is often the only thing
that says anything at all.

## A pack

```yaml
pack: automotive-basics
version: 1
description: >
  What this pack is for. Free text.

rules:
  - id: vin
    category: pii
    kind: regex
    pattern: '\b[A-HJ-NPR-Z0-9]{17}\b'
    validate: vin-checksum
    severity: high
    scope: [files, regions]
    description: Vehicle identification number, confirmed by its check digit
```

| key | meaning |
|---|---|
| `pack` | required; names the pack and appears on every hit |
| `version` | integer, default 1 |
| `id` | required; unique within the pack |
| `kind` | `regex` (default), `literal`, `hex` or `glob-path` |
| `pattern` | required; interpreted per `kind` |
| `category` | free text, default `other`: network, users, credentials, certs, pii, ... |
| `severity` | `info`, `low`, `medium` (default), `high`, `critical` |
| `validate` | optional post-filter: `vin-checksum`, `luhn`, `mac-not-broadcast` |
| `scope` | `[files]`, `[regions]` or both (the default) |
| `description` | what a hit means; shown to the examiner |

A pack with a rule this build cannot act on is **refused whole**, naming the
rule: a bad pattern, an unknown `validate:` filter or a duplicate id fails the
load rather than being skipped. Silently dropping one line of an examiner's
intent is worse than not running.

## Kinds

* **`regex`** — an RE2 expression. Byte-oriented: RE2 runs in Latin-1 so a
  pattern can match inside data that is not valid UTF-8, which is most of a
  flash dump.
* **`literal`** — exact bytes, quoted before compiling. No escaping to get
  wrong.
* **`hex`** — hex byte pairs, whitespace ignored, `??` matching any byte:
  `"ca ?? ca ??"`.
* **`glob-path`** — matched against the entry's path, never its contents.
  `*` and `?` stay inside one path segment; `**` crosses them, and `**/`
  also matches zero directories, so `**/etc/shadow` finds it at the root.

## Why RE2 and not `std::regex`

A pack is untrusted input in exactly the way an image is. A pattern with
nested quantifiers — `(a+)+$` is the classic — makes a backtracking engine run
for longer than the case will last. RE2 is linear in the subject whatever the
pattern, which is the same bargain every reader in this codebase makes with
its own input. It costs a dependency (and Abseil behind it); the alternative
costs an examiner's afternoon to a pack they wrote themselves.

## Caps

`ScanLimits` bounds both ends, because a pack and an image are both
adversarial:

| cap | default | why |
|---|---|---|
| `max_bytes_per_item` | 64 MiB | a single file cannot dominate a run |
| `max_hits_per_rule_per_item` | 64 | one chatty rule cannot bury the rest |
| `max_hits_total` | 100000 | whole-run ceiling |
| `context_bytes` | 40 | quoted either side of a match |

Matched bytes and their context are quoted with non-printables as `\xNN`, so a
hit is safe to put in a YAML file and readable without a hex editor.

Hits come back ordered by offset then rule id, so a manifest is byte-identical
run to run.

## Built-in packs

| pack | what it looks for |
|---|---|
| `network` | MAC addresses, IPv4, URLs, SSIDs and PSKs, and the config files that hold them (`wpa_supplicant`, `hostapd`, `interfaces`, `resolv.conf`, `hosts`, DHCP leases) |
| `credentials` | `shadow`/`passwd`, crypt(3) hashes, PEM private keys and certificates, SSH and Dropbear host keys, AWS/Google/Slack tokens, JWTs, password assignments |
| `pii` | emails, VINs (check digit), IMEIs (Luhn), payment cards (Luhn), E.164 phone numbers, GPS coordinates |

### Tuning them against real evidence

The first draft of these packs was run over the router corpus image's
extracted JFFS2 tree (3,111 files, 82 MiB) and three rules were obviously
wrong:

| rule | before | after | why |
|---|---|---|---|
| `password-assignment` | 581 | 13 | matched every `password = obj.newPassword` in the web UI's JavaScript; now the assignment has to be the whole line, which is what a config file looks like and source code is not |
| `wifi-ssid` | 76 | 8 | `ssid\s*=` also matched `ssid ==` in JavaScript comparisons |
| `imei` | 3 | 0 | fifteen zeros pass the Luhn check (they sum to zero); a run of one repeated digit is a filler field, not an identifier |

That pass is the point of having a corpus. A rule that fires 581 times on one
router is not a finding, it is noise that hides the eight that matter.

A second pass over an automotive Android unit VCUNH head-unit extraction found three more, and they
are a different kind — not too-loose patterns, but matches that satisfy every
check the rule makes and are still wrong:

| rule | what it matched | why it is not that |
|---|---|---|
| `vin` | `X1X2X3X4X6X7X8X9X` in ICU's data tables and in iconv | it **passes the check digit** — that is one chance in eleven, so a placeholder gets there eventually. A VIN is a manufacturer prefix, a descriptor and a serial; no real one is more than half the same character, where this is 9 `X` out of 17 |
| `phone-e164` | `e+631065600` in file(1)'s magic database | a float format. The pattern excluded a preceding digit but not a preceding letter |
| `shadow-hash` | `$1$2$3$4$5$6$7$8$9$` in samba's case-mapping tables | the character class admitted `$` into the hash body, so a run of `$n` looked like `$id$salt$hash` |

The VIN one is worth dwelling on. A check digit is a *filter*, not a proof:
it removes ten in eleven of the things that are shaped like a VIN, which is
exactly why the rule uses it — and it still lets a synthetic string through.
Validation narrows a rule; it does not make it true.
