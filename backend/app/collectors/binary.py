"""Binary collector — SPEC.md §7.2, build step 11.

Source says what someone wrote; a linked binary says what is deployed and
callable right now, including code nobody has the source for any more. Three
kinds of evidence come out of an ELF, and they are not equally strong:

* **``DT_NEEDED``** — the shared libraries the loader will resolve. This is the
  observation the advisor's feasibility check (§11) reads: ``libcrypto.so.1.1``
  is OpenSSL 1.1, and a soname carries the major release only. That precision
  is recorded as observed, because ``libcrypto.so.3`` cannot tell 3.3 from 3.5
  and the boundary the advisor needs is exactly there. ``confidence: high``.
* **``.dynsym``** — the functions the binary imports. ``MD5_Init`` in the dynamic
  symbol table proves the binary can call it. ``confidence: high``.
* **``.rodata``** — string constants. ``TLS_RSA_WITH_3DES_EDE_CBC_SHA`` in a data
  section might be a log label, a lookup key or dead data. ``confidence:
  medium``, and this collector is where a scanner has to resist claiming more
  than it knows. The one string that is worth more is ``OPENSSL_VERSION_TEXT``,
  because it carries the minor release the soname lacks; the advisor pairs it
  with the soname from the same binary.

Non-ELF files are skipped silently after a four-byte sniff, so this collector
can be pointed at the whole approved tree. A file that claims to be an ELF and
is not parses as far as it goes and then costs itself, not the scan.

Symbol names are resolved to an algorithm spelling through a table kept here,
not through the alias table: ``EVP_sha1`` is an OpenSSL function name, not an
algorithm name, and the alias table should not have to know OpenSSL's API.
Strings in ``.rodata`` *are* matched against the alias table, because a string
that spells an algorithm the way a config file would is the same observation
arriving by another route.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from app.collectors.base import Collector, RawFinding, ScanContext
from app.core.normalizer import AliasIndex, get_alias_index
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer

logger = logging.getLogger(__name__)

__all__ = [
    "BinaryCollector",
    "ELF_MAGIC",
    "KNOWN_LIBRARIES",
    "OBS_LIBRARY_VERSION",
    "OBS_LINKED_LIBRARY",
    "OBS_RODATA_STRING",
    "OBS_SYMBOL",
    "SYMBOL_TABLE",
    "SymbolRule",
    "is_elf",
    "library_from_soname",
]

ELF_MAGIC = b"\x7fELF"

#: Observation names. The first two are the contract the advisor (§11) reads —
#: ``app/core/advisor.py`` defines the same strings as its input vocabulary.
OBS_LINKED_LIBRARY = "linked_library"
OBS_LIBRARY_VERSION = "library_version_string"
OBS_SYMBOL = "dynamic_symbol"
OBS_RODATA_STRING = "rodata_string"

#: ``.rodata`` larger than this is read up to the cap. A string past 16 MB into
#: a data section is not where a cipher-suite name lives.
MAX_RODATA_BYTES = 16 * 1024 * 1024

#: A printable run worth calling a string. Four characters is the shortest
#: algorithm name in the alias table that is not also an English word.
_STRING_RUN = re.compile(rb"[\x20-\x7e]{4,}")

#: IANA-style cipher-suite names. Recorded even when the alias table has no
#: entry for them: an observation the pack cannot classify is still an
#: observation, and it resolves to ``unknown`` honestly (§10).
_CIPHER_SUITE = re.compile(r"^(?:TLS|SSL)_[A-Z0-9]+_WITH_[A-Z0-9_]+$")

#: Soname → library. The version is whatever follows ``.so.`` — ``1.1`` for
#: OpenSSL 1.1.x, ``3`` for 3.x, ``1.0.0`` for the old ABI — recorded verbatim so
#: nothing rounds it. A bare ``libcrypto.so`` has no version at all.
KNOWN_LIBRARIES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^lib(?:crypto|ssl)\.so(?:\.(?P<version>[\d.]+))?$"), "openssl"),
    (re.compile(r"^libgnutls\.so(?:\.(?P<version>[\d.]+))?$"), "gnutls"),
    (re.compile(r"^libgcrypt\.so(?:\.(?P<version>[\d.]+))?$"), "libgcrypt"),
    (re.compile(r"^libmbed(?:tls|crypto|x509)\.so(?:\.(?P<version>[\d.]+))?$"), "mbedtls"),
    (re.compile(r"^libnss3\.so(?:\.(?P<version>[\d.]+))?$"), "nss"),
    (re.compile(r"^libsodium\.so(?:\.(?P<version>[\d.]+))?$"), "libsodium"),
    (re.compile(r"^libwolfssl\.so(?:\.(?P<version>[\d.]+))?$"), "wolfssl"),
    (re.compile(r"^libnettle\.so(?:\.(?P<version>[\d.]+))?$"), "nettle"),
)

#: Version banners libraries compile into their own binaries and into anything
#: that prints them. The precise release the soname cannot carry.
_VERSION_BANNERS: tuple[tuple[re.Pattern[bytes], str], ...] = (
    (re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})"), "openssl"),
    (re.compile(rb"GnuTLS (\d+\.\d+\.\d+)"), "gnutls"),
    (re.compile(rb"mbed ?TLS (\d+\.\d+\.\d+)", re.IGNORECASE), "mbedtls"),
)


@dataclass(frozen=True, slots=True)
class SymbolRule:
    """A dynamic-symbol name pattern and the algorithm it proves callable."""

    pattern: re.Pattern[str]
    algorithm: str
    primitive: Primitive = Primitive.UNKNOWN
    mode: str | None = None
    key_size: int | None = None


def _rule(
    pattern: str,
    algorithm: str,
    primitive: Primitive = Primitive.UNKNOWN,
    mode: str | None = None,
    key_size: int | None = None,
) -> SymbolRule:
    return SymbolRule(re.compile(pattern), algorithm, primitive, mode, key_size)


#: OpenSSL's libcrypto API, the one the demo links and the one most C code on a
#: Linux box links. First match wins, so the specific spellings come first.
#: ``EVP_PKEY_*`` is deliberately absent: it is generic over every key type and
#: proves nothing about which one.
SYMBOL_TABLE: tuple[SymbolRule, ...] = (
    # hashes
    _rule(r"^(MD5|MD5_Init|MD5_Update|MD5_Final|EVP_md5)$", "MD5", Primitive.HASH),
    _rule(r"^(MD4|MD4_Init|MD4_Update|MD4_Final|EVP_md4)$", "MD4", Primitive.HASH),
    _rule(r"^(MD2|MD2_Init|EVP_md2)$", "MD2", Primitive.HASH),
    _rule(r"^(SHA1|SHA1_Init|SHA1_Update|SHA1_Final|EVP_sha1)$", "SHA-1", Primitive.HASH),
    _rule(r"^(SHA224|SHA224_Init|EVP_sha224)$", "SHA-224", Primitive.HASH),
    _rule(r"^(SHA256|SHA256_Init|SHA256_Update|SHA256_Final|EVP_sha256)$", "SHA-256", Primitive.HASH),
    _rule(r"^(SHA384|SHA384_Init|EVP_sha384)$", "SHA-384", Primitive.HASH),
    _rule(r"^(SHA512|SHA512_Init|SHA512_Update|SHA512_Final|EVP_sha512)$", "SHA-512", Primitive.HASH),
    # symmetric ciphers, with the mode the function name fixes
    _rule(r"^(DES_ecb_encrypt|DES_ecb3_encrypt|EVP_des_ecb)$", "DES", Primitive.CIPHER, "ECB"),
    _rule(r"^(DES_ncbc_encrypt|DES_cbc_encrypt|EVP_des_cbc)$", "DES", Primitive.CIPHER, "CBC"),
    _rule(r"^(DES_ede3_ecb_encrypt|EVP_des_ede3_ecb|EVP_des_ede3)$", "3DES", Primitive.CIPHER, "ECB"),
    _rule(r"^(DES_ede3_cbc_encrypt|EVP_des_ede3_cbc|EVP_des_ede_cbc)$", "3DES", Primitive.CIPHER, "CBC"),
    _rule(r"^DES_(set_key.*|key_sched|set_odd_parity|is_weak_key)$", "DES", Primitive.CIPHER),
    _rule(r"^(RC4|RC4_set_key|EVP_rc4)$", "RC4", Primitive.CIPHER),
    _rule(r"^(RC2_.*|EVP_rc2_.*)$", "RC2", Primitive.CIPHER),
    _rule(r"^(BF_.*|EVP_bf_.*)$", "Blowfish", Primitive.CIPHER),
    _rule(r"^(AES_ecb_encrypt|EVP_aes_128_ecb)$", "AES", Primitive.CIPHER, "ECB", 128),
    _rule(r"^EVP_aes_192_ecb$", "AES", Primitive.CIPHER, "ECB", 192),
    _rule(r"^EVP_aes_256_ecb$", "AES", Primitive.CIPHER, "ECB", 256),
    _rule(r"^(AES_cbc_encrypt|EVP_aes_128_cbc)$", "AES", Primitive.CIPHER, "CBC", 128),
    _rule(r"^EVP_aes_192_cbc$", "AES", Primitive.CIPHER, "CBC", 192),
    _rule(r"^EVP_aes_256_cbc$", "AES", Primitive.CIPHER, "CBC", 256),
    _rule(r"^EVP_aes_128_gcm$", "AES", Primitive.CIPHER, "GCM", 128),
    _rule(r"^EVP_aes_192_gcm$", "AES", Primitive.CIPHER, "GCM", 192),
    _rule(r"^EVP_aes_256_gcm$", "AES", Primitive.CIPHER, "GCM", 256),
    _rule(r"^EVP_aes_128_ctr$", "AES", Primitive.CIPHER, "CTR", 128),
    _rule(r"^EVP_aes_256_ctr$", "AES", Primitive.CIPHER, "CTR", 256),
    _rule(r"^(AES_set_(en|de)crypt_key|AES_encrypt|AES_decrypt)$", "AES", Primitive.CIPHER),
    _rule(r"^EVP_chacha20(_poly1305)?$", "ChaCha20", Primitive.CIPHER),
    # asymmetric — the primitive only where the function name fixes it
    _rule(r"^(RSA_sign|RSA_verify|RSA_sign_ASN1_OCTET_STRING|RSA_verify_ASN1_OCTET_STRING)$", "RSA", Primitive.SIGNATURE),
    _rule(r"^(RSA_public_encrypt|RSA_private_decrypt)$", "RSA", Primitive.KEY_EXCHANGE),
    _rule(r"^(RSA_generate_key|RSA_generate_key_ex|RSA_new|RSA_private_encrypt|RSA_public_decrypt|RSA_size|RSA_bits)$", "RSA"),
    _rule(r"^(DSA_do_sign|DSA_sign|DSA_do_verify|DSA_verify)$", "DSA", Primitive.SIGNATURE),
    _rule(r"^(DSA_generate_key|DSA_generate_parameters.*|DSA_new)$", "DSA"),
    _rule(r"^(ECDSA_do_sign.*|ECDSA_sign.*|ECDSA_do_verify|ECDSA_verify)$", "ECDSA", Primitive.SIGNATURE),
    _rule(r"^ECDH_compute_key$", "ECDH", Primitive.KEY_EXCHANGE),
    _rule(r"^(DH_generate_key|DH_compute_key|DH_generate_parameters.*)$", "DH", Primitive.KEY_EXCHANGE),
    _rule(r"^(ED25519_sign|ED25519_verify)$", "Ed25519", Primitive.SIGNATURE),
    _rule(r"^X25519$", "X25519", Primitive.KEY_EXCHANGE),
)


def is_elf(path: Path) -> bool:
    """The four-byte sniff. Anything else is skipped without a word."""
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == ELF_MAGIC
    except OSError:
        return False


def library_from_soname(soname: str) -> tuple[str, str | None] | None:
    """``libcrypto.so.1.1`` → ``("openssl", "1.1")``; an unknown soname → ``None``."""
    for pattern, library in KNOWN_LIBRARIES:
        match = pattern.match(soname)
        if match:
            return library, match.group("version")
    return None


class BinaryCollector(Collector):
    """§7.2. ``source_layer: artifact`` — what is linked, not what was intended."""

    name: ClassVar[CollectorName] = CollectorName.BINARY

    def collect(self, ctx: ScanContext) -> list[RawFinding]:
        aliases = get_alias_index()
        findings: list[RawFinding] = []
        for relative, absolute in ctx.iter_files():
            ctx.check_budget(f"reading {relative}")
            if not is_elf(absolute):
                continue
            try:
                findings.extend(_collect_elf(relative, absolute, aliases))
            except (ELFError, ValueError, OSError) as exc:
                # A file that says ELF and is not. Its own findings are the cost;
                # the rest of the tree is not (§7's survivability rule, one file
                # down from the runner's).
                logger.warning("binary: %s is not a readable ELF: %s", relative, exc)
        return findings


# --------------------------------------------------------------------------- #
# One ELF
# --------------------------------------------------------------------------- #


def _collect_elf(relative: str, absolute: Path, aliases: AliasIndex) -> list[RawFinding]:
    findings: list[RawFinding] = []
    with open(absolute, "rb") as handle:
        elf = ELFFile(handle)
        findings.extend(_dependency_findings(relative, elf))
        findings.extend(_symbol_findings(relative, elf))
        rodata = elf.get_section_by_name(".rodata")
        if rodata is not None and rodata["sh_type"] != "SHT_NOBITS":
            data = rodata.data()[:MAX_RODATA_BYTES]
            findings.extend(_version_findings(relative, data))
            findings.extend(_string_findings(relative, data, aliases))
    return findings


def _dependency_findings(relative: str, elf: ELFFile) -> list[RawFinding]:
    """One finding per crypto library in ``DT_NEEDED``. Every other library is not crypto."""
    findings: list[RawFinding] = []
    seen: set[str] = set()
    for section in elf.iter_sections():
        if not isinstance(section, DynamicSection):
            continue
        for tag in section.iter_tags():
            if tag.entry.d_tag != "DT_NEEDED":
                continue
            soname = str(tag.needed)
            if soname in seen:
                continue
            seen.add(soname)
            resolved = library_from_soname(soname)
            if resolved is None:
                continue
            library, version = resolved
            evidence: dict[str, Any] = {
                "file": relative,
                "observation": OBS_LINKED_LIBRARY,
                "section": ".dynamic",
                "soname": soname,
                "library": library,
                "version": version,
                # The advisor reads this to know it is looking at a major
                # release, not a precise one.
                "version_precision": "soname",
            }
            findings.append(
                RawFinding(
                    collector=CollectorName.BINARY,
                    algorithm_name=soname,
                    source_layer=SourceLayer.ARTIFACT,
                    confidence=Confidence.HIGH,
                    evidence_location=relative,
                    evidence_raw=evidence,
                )
            )
    return findings


def _symbol_findings(relative: str, elf: ELFFile) -> list[RawFinding]:
    """One finding per algorithm the dynamic symbols prove callable.

    ``MD5_Init``, ``MD5_Update`` and ``MD5_Final`` are one capability, not three
    findings; the symbols that produced the row are all listed in its evidence.
    """
    dynsym = elf.get_section_by_name(".dynsym")
    if not isinstance(dynsym, SymbolTableSection):
        return []

    grouped: dict[tuple[str, Primitive, str | None, int | None], list[str]] = {}
    for symbol in dynsym.iter_symbols():
        name = symbol.name
        if not name:
            continue
        rule = _symbol_rule(name)
        if rule is None:
            continue
        key = (rule.algorithm, rule.primitive, rule.mode, rule.key_size)
        symbols = grouped.setdefault(key, [])
        if name not in symbols:
            symbols.append(name)

    findings: list[RawFinding] = []
    for (algorithm, primitive, mode, key_size), symbols in grouped.items():
        findings.append(
            RawFinding(
                collector=CollectorName.BINARY,
                algorithm_name=algorithm,
                source_layer=SourceLayer.ARTIFACT,
                confidence=Confidence.HIGH,
                primitive=primitive,
                mode=mode,
                key_size=key_size,
                evidence_location=relative,
                evidence_raw={
                    "file": relative,
                    "observation": OBS_SYMBOL,
                    "section": ".dynsym",
                    "symbols": sorted(symbols),
                },
            )
        )
    return findings


def _symbol_rule(name: str) -> SymbolRule | None:
    for rule in SYMBOL_TABLE:
        if rule.pattern.match(name):
            return rule
    return None


def _version_findings(relative: str, rodata: bytes) -> list[RawFinding]:
    """Library version banners — the precise release a soname cannot carry."""
    findings: list[RawFinding] = []
    for pattern, library in _VERSION_BANNERS:
        seen: set[str] = set()
        for match in pattern.finditer(rodata):
            version = match.group(1).decode("ascii", "replace")
            if version in seen:
                continue
            seen.add(version)
            # The banner itself, bounded: `OpenSSL 1.1.1f  31 Mar 2020`.
            end = rodata.find(b"\0", match.start())
            banner = rodata[match.start() : end if 0 < end - match.start() <= 64 else match.end()]
            findings.append(
                RawFinding(
                    collector=CollectorName.BINARY,
                    algorithm_name=match.group(0).split(b" ")[0].decode("ascii", "replace"),
                    source_layer=SourceLayer.ARTIFACT,
                    # A string, so §7.2's medium — but it is the string the
                    # library itself embeds, which is why the advisor trusts it
                    # over the soname from the same file.
                    confidence=Confidence.MEDIUM,
                    evidence_location=relative,
                    evidence_raw={
                        "file": relative,
                        "observation": OBS_LIBRARY_VERSION,
                        "section": ".rodata",
                        "library": library,
                        "version": version,
                        "text": banner.decode("ascii", "replace"),
                    },
                )
            )
    return findings


def _string_findings(relative: str, rodata: bytes, aliases: AliasIndex) -> list[RawFinding]:
    """Strings that spell an algorithm or a cipher suite. Medium, always."""
    findings: list[RawFinding] = []
    seen: set[str] = set()
    for run in _STRING_RUN.finditer(rodata):
        text = run.group(0).decode("ascii")
        if text in seen:
            continue
        for candidate in _candidate_strings(text):
            if candidate in seen:
                continue
            if _CIPHER_SUITE.match(candidate) or aliases.by_spelling(candidate) is not None:
                seen.add(candidate)
                findings.append(
                    RawFinding(
                        collector=CollectorName.BINARY,
                        algorithm_name=candidate,
                        source_layer=SourceLayer.ARTIFACT,
                        confidence=Confidence.MEDIUM,
                        evidence_location=relative,
                        evidence_raw={
                            "file": relative,
                            "observation": OBS_RODATA_STRING,
                            "section": ".rodata",
                            "string": candidate,
                            "offset": run.start(),
                        },
                    )
                )
        seen.add(text)
    return findings


def _candidate_strings(text: str) -> Iterable[str]:
    """The whole run, then each whitespace-separated token of it.

    ``.rodata`` packs adjacent literals without separators only when they are
    NUL-terminated separately, so a run is usually one literal — but a format
    string like ``suite    : %s`` should not hide a name, and a version banner
    should not be mistaken for one.
    """
    stripped = text.strip()
    if stripped:
        yield stripped
    for token in stripped.split():
        if len(token) >= 4 and token != stripped:
            yield token
