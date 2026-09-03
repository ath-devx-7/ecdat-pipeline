"""Certificate collector — SPEC.md §7.3.

Reads X.509 certificates out of the approved tree and records what each one
declares: public key algorithm and size, signature algorithm OID, validity
window, issuer, subject, SANs, self-signed flag.

**The hard rule (SPEC.md §1) shapes the whole file.** Private key material is
never parsed and never read past the header that identifies it. That is not a
check bolted onto the end — it is why this collector streams files line by line
instead of slurping them: a PEM bundle holding a certificate followed by its key
must yield the certificate *and stop at the key's BEGIN line*, with the key's
bytes never entering the process. There is no code path in this module that
calls a private key loader, and .p12/.pfx containers are treated as key material
outright even though §7.3 lists them as certificate extensions — a certificate
reachable only through a key container is not worth breaking the rule for.

Verdicts are not this collector's business. "RSA-1024 is broken" is a policy
lookup (§10) against a cited standard; here it is simply an RSA key of 1024
bits, observed at a location.
"""

from __future__ import annotations

import logging
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dh,
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)

from app.collectors.base import Collector, RawFinding, ScanContext
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer

logger = logging.getLogger(__name__)

__all__ = ["CertificateCollector"]

#: §7.3's candidate list. Presence here means "look at it", not "parse it" — the
#: key containers below are on both lists and lose the argument.
CERTIFICATE_EXTENSIONS = frozenset({".pem", ".crt", ".cer", ".der", ".p12", ".pfx"})

#: PKCS#12 bundles carry a private key. Metadata only, never opened.
KEY_CONTAINER_EXTENSIONS = frozenset({".p12", ".pfx"})

PEM_CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----"
PEM_CERTIFICATE_END = "-----END CERTIFICATE-----"

#: BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY, BEGIN ENCRYPTED PRIVATE KEY —
#: every spelling openssl emits.
PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")

#: A certificate expiring inside this window is worth surfacing before it bites.
EXPIRY_WARNING_DAYS = 90

#: Read budgets. A declared candidate earns a larger one than a file we are only
#: sniffing on the off-chance it embeds a PEM block.
MAX_CANDIDATE_BYTES = 4 * 1024 * 1024
MAX_SNIFF_BYTES = 1024 * 1024

#: Bounds a single readline so a newline-free binary blob cannot be pulled into
#: memory whole.
MAX_LINE_BYTES = 8192

#: Observation names for findings that are not algorithm uses. The policy engine
#: turns these into ``hygiene`` verdicts once the pack carries a cited rule for
#: them (§10); until then they resolve to ``unknown``, which is the honest answer.
OBS_PRIVATE_KEY_FILE = "private-key-file"
OBS_PRIVATE_KEY_WORLD_READABLE = "private-key-world-readable"
OBS_CERTIFICATE_EXPIRED = "certificate-expired"
OBS_CERTIFICATE_EXPIRING = "certificate-expiring"
OBS_CERTIFICATE_SELF_SIGNED = "certificate-self-signed"

#: Path segments that make a self-signed certificate unremarkable (§7.3 asks for
#: self-signed "in a non-dev path"). Deliberately short. "demo" and "sample" are
#: absent: a directory called demo in a customer tree is as likely to hold a
#: genuinely deployed certificate as a throwaway one, and suppressing a real
#: finding is worse than reporting a dull one.
DEV_PATH_SEGMENTS = frozenset(
    {"test", "tests", "testdata", "fixture", "fixtures", "dev", "development"}
)


class CertificateCollector(Collector):
    """§7.3. ``source_layer: artifact`` — what is installed, not what was intended."""

    name: ClassVar[CollectorName] = CollectorName.CERTS

    def collect(self, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for relative, absolute in ctx.iter_files():
            ctx.check_budget(f"reading {relative}")
            findings.extend(self._collect_one(relative, absolute))
        return findings

    # ------------------------------------------------------------------ file

    def _collect_one(self, relative: str, absolute: Path) -> list[RawFinding]:
        suffix = absolute.suffix.lower()

        if suffix in KEY_CONTAINER_EXTENSIONS:
            # Never opened. A .p12 is on §7.3's extension list and contains a
            # private key, and §1 has no convenience exception.
            return _key_material_findings(
                relative, absolute, container=f"PKCS#12 ({suffix})"
            )

        declared_candidate = suffix in CERTIFICATE_EXTENSIONS
        limit = MAX_CANDIDATE_BYTES if declared_candidate else MAX_SNIFF_BYTES
        try:
            size = absolute.stat().st_size
        except OSError as exc:
            logger.debug("certs: cannot stat %s: %s", relative, exc)
            return []
        if size > limit and not declared_candidate:
            # Sniffing a large non-candidate for an embedded PEM block is not
            # worth the read; a declared candidate is still attempted, truncated.
            return []

        try:
            blocks, key_header, truncated = _scan_pem_stream(absolute, limit)
        except OSError as exc:
            logger.debug("certs: cannot read %s: %s", relative, exc)
            return []

        findings: list[RawFinding] = []
        for block in blocks:
            findings.extend(
                _certificate_findings(
                    relative,
                    block.pem,
                    line=block.line,
                    encoding="pem",
                    loader=x509.load_pem_x509_certificate,
                )
            )

        if key_header is not None:
            # Anything after this point in the file was never read.
            findings.extend(
                _key_material_findings(
                    relative,
                    absolute,
                    container=key_header,
                    certificates_before_key=len(blocks),
                )
            )
            return findings

        if not blocks and declared_candidate and not truncated:
            findings.extend(_der_findings(relative, absolute, size))
        return findings


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #


class _PemBlock:
    __slots__ = ("line", "pem")

    def __init__(self, line: int, pem: bytes) -> None:
        self.line = line
        self.pem = pem


def _scan_pem_stream(path: Path, max_bytes: int) -> tuple[list[_PemBlock], str | None, bool]:
    """Stream ``path``, collecting PEM certificate blocks, stopping at a key header.

    Returns the blocks found, the private key header line if one was reached, and
    whether the read was cut short by ``max_bytes``.

    The loop stops the instant a ``BEGIN ... PRIVATE KEY`` line appears, which is
    what makes "never read private key bytes" true of a mixed file rather than
    only of a file that is nothing but a key. ``overlap`` carries the tail of the
    previous read so a header split across two bounded reads is still caught.
    """
    blocks: list[_PemBlock] = []
    key_header: str | None = None
    truncated = False
    consumed = 0
    overlap = ""
    open_block: list[str] | None = None
    open_line = 0

    with path.open("rb") as handle:
        number = 0
        while True:
            raw = handle.readline(MAX_LINE_BYTES)
            if not raw:
                break
            number += 1
            consumed += len(raw)
            # latin-1 never raises, and every marker looked for here is ASCII.
            line = raw.decode("latin-1").strip()

            match = PRIVATE_KEY_BEGIN.search(overlap + line)
            if match is not None:
                key_header = match.group(0)
                break
            overlap = line[-64:]

            if line == PEM_CERTIFICATE_BEGIN:
                open_block = [line]
                open_line = number
            elif open_block is not None:
                open_block.append(line)
                if line == PEM_CERTIFICATE_END:
                    pem = ("\n".join(open_block) + "\n").encode("ascii", "ignore")
                    blocks.append(_PemBlock(open_line, pem))
                    open_block = None

            if consumed >= max_bytes:
                truncated = True
                break

    return blocks, key_header, truncated


def _der_findings(relative: str, absolute: Path, size: int) -> list[RawFinding]:
    """A binary candidate with no PEM markers. Only a *certificate* loader is tried.

    If the DER turns out to be something else it stays unparsed: this module has
    no key loader to fall back to, which is the point.
    """
    if size > MAX_CANDIDATE_BYTES:
        return []
    try:
        data = absolute.read_bytes()
    except OSError as exc:
        logger.debug("certs: cannot read %s: %s", relative, exc)
        return []
    return _certificate_findings(
        relative, data, line=None, encoding="der", loader=x509.load_der_x509_certificate
    )


# --------------------------------------------------------------------------- #
# Certificate to findings
# --------------------------------------------------------------------------- #


def _certificate_findings(
    relative: str, data: bytes, *, line: int | None, encoding: str, loader
) -> list[RawFinding]:
    try:
        certificate = loader(data)
    except Exception as exc:  # noqa: BLE001 - any malformed input, same answer
        logger.debug(
            "certs: %s holds an unparseable %s certificate: %s", relative, encoding, exc
        )
        return []

    location = relative if line is None else f"{relative}:{line}"
    identity = _certificate_identity(certificate, relative, encoding)

    findings = [
        _public_key_finding(certificate, location, identity),
        _signature_finding(certificate, location, identity),
    ]
    findings.extend(_validity_findings(certificate, location, identity))
    findings.extend(_self_signed_findings(certificate, relative, location, identity))
    return findings


def _certificate_identity(
    certificate: x509.Certificate, relative: str, encoding: str
) -> dict[str, Any]:
    """The shared evidence block. Every finding from one certificate carries it."""
    return {
        "file": relative,
        "encoding": encoding,
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": format(certificate.serial_number, "x"),
        "not_valid_before": certificate.not_valid_before_utc.isoformat(),
        "not_valid_after": certificate.not_valid_after_utc.isoformat(),
        "self_signed": certificate.issuer == certificate.subject,
        "subject_alternative_names": _subject_alternative_names(certificate),
    }


def _subject_alternative_names(certificate: x509.Certificate) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        return []
    names = list(extension.value.get_values_for_type(x509.DNSName))
    names.extend(
        str(address) for address in extension.value.get_values_for_type(x509.IPAddress)
    )
    return names


def _public_key_finding(
    certificate: x509.Certificate, location: str, identity: dict[str, Any]
) -> RawFinding:
    """The subject public key.

    ``primitive`` is ``signature``: a certificate exists to bind an identity to a
    key, and that is an authentication use. The awkward case is RSA in a TLS 1.2
    ``TLS_RSA_*`` handshake, where the same key does key transport — but an
    artefact on disk cannot say which, and only the live handshake (§7.5,
    ``source_layer: live``) can. Guessing key exchange here would push the finding
    into a Mosca wave it may not belong in (§12).
    """
    name, key_size, curve = _public_key_shape(certificate.public_key())
    return RawFinding(
        collector=CollectorName.CERTS,
        algorithm_name=name,
        source_layer=SourceLayer.ARTIFACT,
        confidence=Confidence.HIGH,
        primitive=Primitive.SIGNATURE,
        key_size=key_size,
        evidence_location=location,
        evidence_raw={
            **identity,
            "observation": "certificate_public_key",
            "public_key_algorithm": name,
            "public_key_size_bits": key_size,
            "curve": curve,
        },
    )


def _public_key_shape(public_key: Any) -> tuple[str, int | None, str | None]:
    """Algorithm name, size in bits and curve name — as the key type reports them."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, None
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size, None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve
        return "ECDSA", curve.key_size, curve.name
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448, "ed448"
    if isinstance(public_key, x25519.X25519PublicKey):
        return "X25519", 256, "x25519"
    if isinstance(public_key, x448.X448PublicKey):
        return "X448", 448, "x448"
    if isinstance(public_key, dh.DHPublicKey):
        return "DH", public_key.key_size, None
    return type(public_key).__name__, getattr(public_key, "key_size", None), None


def _signature_finding(
    certificate: x509.Certificate, location: str, identity: dict[str, Any]
) -> RawFinding:
    """The signature over the certificate. The one place an OID is observed directly."""
    oid = certificate.signature_algorithm_oid
    friendly = _oid_name(oid)
    try:
        hash_algorithm = certificate.signature_hash_algorithm
        hash_name = hash_algorithm.name if hash_algorithm is not None else None
    except Exception:  # noqa: BLE001 - unsupported hash, the OID is still the finding
        hash_name = None
    return RawFinding(
        collector=CollectorName.CERTS,
        algorithm_name=friendly or oid.dotted_string,
        algorithm_oid=oid.dotted_string,
        source_layer=SourceLayer.ARTIFACT,
        confidence=Confidence.HIGH,
        primitive=Primitive.SIGNATURE,
        evidence_location=location,
        evidence_raw={
            **identity,
            "observation": "certificate_signature_algorithm",
            "signature_algorithm_oid": oid.dotted_string,
            "signature_algorithm_name": friendly,
            "signature_hash": hash_name,
        },
    )


def _oid_name(oid: x509.ObjectIdentifier) -> str | None:
    """The registered short name for an OID, or None when it has none.

    ``ObjectIdentifier._name`` is the library's own lookup and answers the
    literal string ``"Unknown OID"`` for anything unregistered, which is a name
    no dashboard should ever display — hence the guard. The dotted string is the
    identity that matters either way; this is only the human label.
    """
    name = getattr(oid, "_name", None)
    return None if name in (None, "Unknown OID") else name


def _validity_findings(
    certificate: x509.Certificate, location: str, identity: dict[str, Any]
) -> list[RawFinding]:
    remaining = certificate.not_valid_after_utc - datetime.now(timezone.utc)

    if remaining <= timedelta(0):
        name, observation = OBS_CERTIFICATE_EXPIRED, "certificate_expired"
    elif remaining <= timedelta(days=EXPIRY_WARNING_DAYS):
        name, observation = OBS_CERTIFICATE_EXPIRING, "certificate_expiring"
    else:
        return []

    return [
        RawFinding(
            collector=CollectorName.CERTS,
            algorithm_name=name,
            source_layer=SourceLayer.ARTIFACT,
            confidence=Confidence.HIGH,
            evidence_location=location,
            evidence_raw={
                **identity,
                "observation": observation,
                "days_remaining": remaining.days,
                "warning_window_days": EXPIRY_WARNING_DAYS,
            },
        )
    ]


def _self_signed_findings(
    certificate: x509.Certificate,
    relative: str,
    location: str,
    identity: dict[str, Any],
) -> list[RawFinding]:
    """§7.3: self-signed *in a non-dev path*. One under ``tests/`` is furniture."""
    if certificate.issuer != certificate.subject or _is_dev_path(relative):
        return []
    return [
        RawFinding(
            collector=CollectorName.CERTS,
            algorithm_name=OBS_CERTIFICATE_SELF_SIGNED,
            source_layer=SourceLayer.ARTIFACT,
            confidence=Confidence.HIGH,
            evidence_location=location,
            evidence_raw={**identity, "observation": "certificate_self_signed"},
        )
    ]


def _is_dev_path(relative: str) -> bool:
    return any(part.lower() in DEV_PATH_SEGMENTS for part in relative.split("/"))


# --------------------------------------------------------------------------- #
# Key material — metadata only
# --------------------------------------------------------------------------- #


def _key_material_findings(
    relative: str,
    absolute: Path,
    *,
    container: str,
    certificates_before_key: int | None = None,
) -> list[RawFinding]:
    """Path, size and POSIX permissions. Nothing else, ever (§1, §7.3).

    ``algorithm_name`` is a fixed marker rather than anything read out of the
    file: even the family implied by a ``BEGIN RSA PRIVATE KEY`` header is more
    than §7.3 asks us to record, so the header line is kept as evidence and never
    promoted into an algorithm identity.
    """
    size, mode, world_readable = _key_file_metadata(absolute)
    evidence: dict[str, Any] = {
        "file": relative,
        "observation": "private_key_material",
        "container": container,
        "size_bytes": size,
        "posix_mode": mode,
        # NTFS carries no POSIX mode. Reporting an absent observation as a value
        # is how a tool starts lying, so it is reported as unavailable instead.
        "permissions_available": mode is not None,
        "world_readable": world_readable,
        "parsed": False,
    }
    if certificates_before_key is not None:
        evidence["certificates_read_before_key"] = certificates_before_key

    findings = [
        RawFinding(
            collector=CollectorName.CERTS,
            algorithm_name=OBS_PRIVATE_KEY_FILE,
            source_layer=SourceLayer.ARTIFACT,
            confidence=Confidence.HIGH,
            evidence_location=relative,
            evidence_raw=evidence,
        )
    ]
    if world_readable:
        findings.append(
            RawFinding(
                collector=CollectorName.CERTS,
                algorithm_name=OBS_PRIVATE_KEY_WORLD_READABLE,
                source_layer=SourceLayer.ARTIFACT,
                confidence=Confidence.HIGH,
                evidence_location=relative,
                evidence_raw={**evidence, "observation": "private_key_world_readable"},
            )
        )
    return findings


def _key_file_metadata(absolute: Path) -> tuple[int | None, str | None, bool | None]:
    """``(size, octal mode, world_readable)``. Mode is None where POSIX modes are fiction."""
    try:
        info = absolute.stat()
    except OSError:
        return None, None, None
    if os.name == "nt":
        return info.st_size, None, None
    mode = stat.S_IMODE(info.st_mode)
    return info.st_size, format(mode, "04o"), bool(mode & stat.S_IROTH)
