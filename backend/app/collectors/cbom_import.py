"""CBOM import — SPEC.md §7.6, build step 12.

The door through which another tool's inventory enters. CBOMkit, a commercial
scanner, a hand-written manifest: anything that speaks CycloneDX 1.6 becomes
findings here, and from then on it is treated exactly like everything the
native collectors produced — normalized, classified, scored, advised. §18 is the
reason this exists: the import path is what makes CBOMkit an input rather than a
competitor.

Four decisions shape the module.

**The upload is kept, byte for byte, and never read again.** ``provenance_blobs``
holds the document exactly as it arrived so a disputed finding can be traced to
precisely what the source tool said — which needs the bytes, not a
re-serialisation of them. The column is JSONB, and JSONB does not preserve key
order or whitespace, so the text is stored *as a string inside* the JSON rather
than as parsed JSON: a JSON string round-trips its characters exactly, and a
parsed object would not. Nothing in the system parses the blob a second time;
findings are produced from the one parse done at upload.

**A third party's observation is not our observation.** Every imported finding
is ``source_layer: source`` unless the document says otherwise through an
``ecdat:source_layer`` property, and ``confidence: medium`` unless it carries
``ecdat:confidence``. The consequence that matters is §9's: the alignment check
compares ``live`` against ``config``, so a CBOM that reports "TLS 1.0 accepted
on 8443" is recorded and classified but never mistaken for a handshake this tool
performed.

**``pke`` is resolved by what the key does, not by its name.** CycloneDX files
RSA under ``pke`` whether it signs or transports keys, and only
``cryptoFunctions`` says which. Sign and verify mean a signature; encrypt,
decrypt and encapsulation mean key exchange; both, or neither, is ``unknown`` —
because the wave (§12) and the target (§11) both turn on this one field, and a
guess here is a wrong roadmap entry.

**Key material in the document stays in the document.** A
``related-crypto-material`` entry may carry a ``value``. It is never copied into
a finding, whatever its type: a finding records that a key exists, its size and
its algorithm, and stops. §1's rule does not have a "but it was already in a
JSON file" exception.

Only CycloneDX 1.6 is accepted, and the document has to validate against the
1.6 schema before anything is read from it. A document that does not validate
is refused rather than read as far as it goes: an inventory that half-parsed is
an inventory with holes nobody can see.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from cyclonedx.model import crypto as cdx
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from sqlalchemy.orm import Session

from app.collectors.base import RawFinding
from app.core.normalizer import normalize
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer
from app.models.finding import Finding, ProvenanceBlob
from app.models.scan import Scan

logger = logging.getLogger(__name__)

__all__ = [
    "CbomImportError",
    "ImportResult",
    "OBS_PRIVATE_KEY_FILE",
    "PROPERTY_CONFIDENCE",
    "PROPERTY_SOURCE_LAYER",
    "SUPPORTED_SPEC_VERSION",
    "findings_from_bom",
    "import_cbom",
    "parse_cbom",
    "primitive_of",
]

SUPPORTED_SPEC_VERSION = "1.6"

#: Component properties a producer (including our own exporter) may set to
#: override §7.6's defaults. Anything else in ``properties`` is evidence.
PROPERTY_CONFIDENCE = "ecdat:confidence"
PROPERTY_SOURCE_LAYER = "ecdat:source_layer"

#: The same marker the certificate collector emits for a key file (§7.3), so
#: one key reported by two routes counts as one kind of thing.
OBS_PRIVATE_KEY_FILE = "private-key-file"

#: CycloneDX primitives → ECDAT's. ``pke`` is absent on purpose — see
#: :func:`primitive_of`.
_PRIMITIVES: Mapping[cdx.CryptoPrimitive, Primitive] = {
    cdx.CryptoPrimitive.HASH: Primitive.HASH,
    cdx.CryptoPrimitive.MAC: Primitive.HASH,
    cdx.CryptoPrimitive.XOF: Primitive.HASH,
    cdx.CryptoPrimitive.BLOCK_CIPHER: Primitive.CIPHER,
    cdx.CryptoPrimitive.STREAM_CIPHER: Primitive.CIPHER,
    cdx.CryptoPrimitive.AE: Primitive.CIPHER,
    cdx.CryptoPrimitive.KEY_WRAP: Primitive.CIPHER,
    cdx.CryptoPrimitive.SIGNATURE: Primitive.SIGNATURE,
    cdx.CryptoPrimitive.KEY_AGREE: Primitive.KEY_EXCHANGE,
    cdx.CryptoPrimitive.KEM: Primitive.KEY_EXCHANGE,
}

_SIGNING_FUNCTIONS = frozenset({cdx.CryptoFunction.SIGN, cdx.CryptoFunction.VERIFY})
_CONFIDENTIALITY_FUNCTIONS = frozenset(
    {
        cdx.CryptoFunction.ENCRYPT,
        cdx.CryptoFunction.DECRYPT,
        cdx.CryptoFunction.ENCAPSULATE,
        cdx.CryptoFunction.DECAPSULATE,
        cdx.CryptoFunction.KEYDERIVE,
    }
)


class CbomImportError(ValueError):
    """The upload is not a CycloneDX 1.6 document this importer can read. Shown verbatim."""


@dataclass(frozen=True, slots=True)
class ImportResult:
    blob: ProvenanceBlob
    findings: list[Finding]
    component_count: int
    tool: str | None
    #: bom-refs that produced no finding, and why — reported, never silent
    skipped: tuple[str, ...] = field(default=())


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def parse_cbom(raw: bytes) -> tuple[Bom, dict[str, Any]]:
    """Decode, validate against the 1.6 schema, and build the model. Raises on any failure."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CbomImportError("The upload is not UTF-8 text.") from exc
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise CbomImportError(f"The upload is not JSON: {exc.msg} at line {exc.lineno}.") from exc
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise CbomImportError(
            'The upload is not a CycloneDX document: "bomFormat": "CycloneDX" is missing.'
        )
    spec_version = str(document.get("specVersion") or "")
    if spec_version != SUPPORTED_SPEC_VERSION:
        raise CbomImportError(
            f"CycloneDX specVersion {spec_version or '(missing)'} is not supported; "
            f"only {SUPPORTED_SPEC_VERSION} is accepted (§7.6)."
        )
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(text)
    if error is not None:
        raise CbomImportError(
            f"The upload does not validate against the CycloneDX {SUPPORTED_SPEC_VERSION} "
            f"schema: {str(error)[:300]}"
        )
    try:
        bom = Bom.from_json(document)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001 - the library raises several kinds
        raise CbomImportError(f"The document could not be read as a CycloneDX BOM: {exc}") from exc
    return bom, document


def _tool_name(bom: Bom) -> str | None:
    tools = bom.metadata.tools
    for component in tools.components:
        return f"{component.name} {component.version}".strip() if component.version else component.name
    for tool in tools.tools:
        return f"{tool.name} {tool.version}".strip() if tool.version else tool.name
    return None


# --------------------------------------------------------------------------- #
# Mapping
# --------------------------------------------------------------------------- #


def primitive_of(properties: cdx.AlgorithmProperties | None) -> Primitive:
    """§7.6's awkward case, made explicit. See the module docstring."""
    if properties is None or properties.primitive is None:
        return Primitive.UNKNOWN
    mapped = _PRIMITIVES.get(properties.primitive)
    if mapped is not None:
        return mapped
    if properties.primitive is not cdx.CryptoPrimitive.PKE:
        return Primitive.UNKNOWN
    functions = set(properties.crypto_functions or ())
    signs = bool(functions & _SIGNING_FUNCTIONS)
    conceals = bool(functions & _CONFIDENTIALITY_FUNCTIONS)
    if signs and not conceals:
        return Primitive.SIGNATURE
    if conceals and not signs:
        return Primitive.KEY_EXCHANGE
    return Primitive.UNKNOWN


def _key_size(properties: cdx.AlgorithmProperties | None) -> int | None:
    if properties is None or not properties.parameter_set_identifier:
        return None
    text = str(properties.parameter_set_identifier).strip()
    return int(text) if text.isdigit() else None


def _mode(properties: cdx.AlgorithmProperties | None) -> str | None:
    if properties is None or properties.mode is None:
        return None
    if properties.mode in (cdx.CryptoMode.OTHER, cdx.CryptoMode.UNKNOWN):
        return None
    return properties.mode.value.upper()


def _property(component: Component, name: str) -> str | None:
    for item in component.properties:
        if item.name == name and item.value:
            return str(item.value).strip()
    return None


def _confidence(component: Component) -> Confidence | None:
    value = _property(component, PROPERTY_CONFIDENCE)
    if value is None:
        return None
    try:
        return Confidence(value.lower())
    except ValueError:
        logger.warning("cbom: %s declares confidence %r, which is not one of ours; using the default", component.bom_ref, value)
        return None


def _source_layer(component: Component) -> SourceLayer | None:
    value = _property(component, PROPERTY_SOURCE_LAYER)
    if value is None:
        return None
    try:
        return SourceLayer(value.lower())
    except ValueError:
        logger.warning("cbom: %s declares source_layer %r, which is not one of ours; using the default", component.bom_ref, value)
        return None


def _occurrences(component: Component) -> list[dict[str, Any]]:
    if component.evidence is None:
        return []
    found = []
    for occurrence in component.evidence.occurrences:
        found.append(
            {
                "location": occurrence.location,
                "line": occurrence.line,
                "symbol": occurrence.symbol,
            }
        )
    return found


def _location(occurrence: Mapping[str, Any] | None, fallback: str) -> str:
    if occurrence is None or not occurrence.get("location"):
        return fallback
    if occurrence.get("line"):
        return f"{occurrence['location']}:{occurrence['line']}"
    return str(occurrence["location"])


class _Mapper:
    """One document → raw findings. Holds the bom-ref index and the skip list."""

    def __init__(self, bom: Bom, provenance_id: str | None, tool: str | None) -> None:
        #: every component, nested ones included, in document order
        self.components: list[Component] = list(_walk(bom.components))
        self.by_ref: dict[str, Component] = {}
        for component in self.components:
            if component.bom_ref and component.bom_ref.value:
                self.by_ref[str(component.bom_ref.value)] = component
        self.provenance_id = provenance_id
        self.tool = tool
        self.skipped: list[str] = []
        #: bom-refs already emitted through a certificate's references
        self.consumed: set[str] = set()

    # ---------------------------------------------------------------- shared

    def _evidence(self, component: Component, observation: str, occurrence=None, **extra) -> dict[str, Any]:
        crypto = component.crypto_properties
        return {
            "observation": observation,
            "bom_ref": str(component.bom_ref.value) if component.bom_ref else None,
            "component_name": component.name,
            "asset_type": crypto.asset_type.value if crypto and crypto.asset_type else None,
            "occurrence": occurrence,
            "provenance_id": self.provenance_id,
            "tool": self.tool,
            **extra,
        }

    def _finding(
        self,
        component: Component,
        *,
        algorithm_name: str,
        observation: str,
        occurrence: Mapping[str, Any] | None,
        primitive: Primitive = Primitive.UNKNOWN,
        oid: str | None = None,
        key_size: int | None = None,
        mode: str | None = None,
        protocol_version: str | None = None,
        **extra: Any,
    ) -> RawFinding:
        ref = str(component.bom_ref.value) if component.bom_ref else component.name
        return RawFinding(
            collector=CollectorName.CBOM_IMPORT,
            algorithm_name=algorithm_name,
            source_layer=_source_layer(component),
            confidence=_confidence(component),
            algorithm_oid=oid,
            primitive=primitive,
            key_size=key_size,
            mode=mode,
            protocol_version=protocol_version,
            evidence_location=_location(occurrence, ref),
            evidence_raw=self._evidence(component, observation, occurrence, **extra),
        )

    def _each_occurrence(self, component: Component) -> list[Mapping[str, Any] | None]:
        """One row per observed use (§5). A component with no occurrence is one row."""
        return list(_occurrences(component)) or [None]

    # ------------------------------------------------------------- per type

    def findings(self) -> list[RawFinding]:
        produced: list[RawFinding] = []
        for component in self.components:
            ref = str(component.bom_ref.value) if component.bom_ref else component.name
            if component.type is not ComponentType.CRYPTOGRAPHIC_ASSET or component.crypto_properties is None:
                continue
            if ref in self.consumed:
                continue
            asset_type = component.crypto_properties.asset_type
            if asset_type is cdx.CryptoAssetType.ALGORITHM:
                produced.extend(self._algorithm(component))
            elif asset_type is cdx.CryptoAssetType.PROTOCOL:
                produced.extend(self._protocol(component))
            elif asset_type is cdx.CryptoAssetType.CERTIFICATE:
                produced.extend(self._certificate(component))
            elif asset_type is cdx.CryptoAssetType.RELATED_CRYPTO_MATERIAL:
                produced.extend(self._material(component, occurrence_owner=component))
            else:
                self.skipped.append(f"{ref}: assetType {asset_type} is not handled")
        return produced

    def _algorithm(self, component: Component, *, primitive: Primitive | None = None,
                   key_size: int | None = None, observation: str = "cbom_algorithm",
                   occurrence_owner: Component | None = None, **extra: Any) -> list[RawFinding]:
        crypto = component.crypto_properties
        assert crypto is not None
        properties = crypto.algorithm_properties
        owner = occurrence_owner or component
        rows = []
        for occurrence in self._each_occurrence(owner):
            rows.append(
                self._finding(
                    component,
                    algorithm_name=component.name,
                    observation=observation,
                    occurrence=occurrence,
                    primitive=primitive if primitive is not None else primitive_of(properties),
                    oid=crypto.oid,
                    key_size=key_size if key_size is not None else _key_size(properties),
                    mode=_mode(properties),
                    cyclonedx_primitive=properties.primitive.value if properties and properties.primitive else None,
                    crypto_functions=sorted(f.value for f in (properties.crypto_functions or ())) if properties else [],
                    curve=properties.curve if properties else None,
                    parameter_set=properties.parameter_set_identifier if properties else None,
                    **extra,
                )
            )
        return rows

    def _protocol(self, component: Component) -> list[RawFinding]:
        crypto = component.crypto_properties
        assert crypto is not None
        properties = crypto.protocol_properties
        kind = properties.type.value.upper() if properties and properties.type else "protocol"
        version = properties.version if properties else None
        name = f"{kind} {version}".strip() if version else component.name
        rows: list[RawFinding] = []
        for occurrence in self._each_occurrence(component):
            rows.append(
                self._finding(
                    component,
                    algorithm_name=name,
                    observation="cbom_protocol",
                    occurrence=occurrence,
                    primitive=Primitive.PROTOCOL,
                    oid=crypto.oid,
                    protocol_version=version,
                    protocol_type=kind,
                )
            )
            for suite in (properties.cipher_suites if properties else ()):
                if not suite.name:
                    continue
                rows.append(
                    self._finding(
                        component,
                        algorithm_name=suite.name,
                        observation="cbom_protocol_cipher_suite",
                        occurrence=occurrence,
                        primitive=Primitive.CIPHER,
                        protocol_version=version,
                        protocol_type=kind,
                        suite=suite.name,
                        suite_identifiers=sorted(str(i) for i in suite.identifiers),
                        suite_algorithms=[
                            self.by_ref[str(r)].name if str(r) in self.by_ref else str(r)
                            for r in suite.algorithms
                        ],
                    )
                )
        return rows

    def _certificate(self, component: Component) -> list[RawFinding]:
        crypto = component.crypto_properties
        assert crypto is not None
        properties = crypto.certificate_properties
        ref = str(component.bom_ref.value) if component.bom_ref else component.name
        details = {
            "certificate": {
                "subject": properties.subject_name if properties else None,
                "issuer": properties.issuer_name if properties else None,
                "not_valid_before": _iso(properties.not_valid_before) if properties else None,
                "not_valid_after": _iso(properties.not_valid_after) if properties else None,
                "format": properties.certificate_format if properties else None,
            }
        }
        rows: list[RawFinding] = []

        signature = self._resolve(properties.signature_algorithm_ref if properties else None)
        if signature is not None and signature.crypto_properties is not None:
            # A certificate's signature algorithm is a signature use, whatever
            # the referenced component says its primitive is.
            rows.extend(
                self._algorithm(
                    signature,
                    primitive=Primitive.SIGNATURE,
                    observation="certificate_signature_algorithm",
                    occurrence_owner=component,
                    certificate_ref=ref,
                    **details,
                )
            )

        key_ref = properties.subject_public_key_ref if properties else None
        key_material = self._resolve(key_ref)
        if key_material is not None:
            self.consumed.add(str(key_ref))
            rows.extend(
                self._material(
                    key_material,
                    occurrence_owner=component,
                    observation="certificate_public_key",
                    primitive=Primitive.SIGNATURE,
                    certificate_ref=ref,
                    **details,
                )
            )

        if not rows:
            self.skipped.append(
                f"{ref}: certificate references no algorithm or key this document defines"
            )
        return rows

    def _material(self, component: Component, *, occurrence_owner: Component,
                  observation: str | None = None, primitive: Primitive | None = None,
                  **extra: Any) -> list[RawFinding]:
        crypto = component.crypto_properties
        assert crypto is not None
        properties = crypto.related_crypto_material_properties
        ref = str(component.bom_ref.value) if component.bom_ref else component.name
        kind = properties.type if properties else None
        size = properties.size if properties else None
        # `value` is deliberately never read. See the module docstring.
        material = {
            "material_type": kind.value if kind else None,
            "material_id": properties.id if properties else None,
            "material_state": properties.state.value if properties and properties.state else None,
            "material_format": properties.format if properties else None,
            "material_size": size,
        }

        if kind is cdx.RelatedCryptoMaterialType.PRIVATE_KEY:
            return [
                self._finding(
                    component,
                    algorithm_name=OBS_PRIVATE_KEY_FILE,
                    observation="private_key_material",
                    occurrence=next(iter(self._each_occurrence(occurrence_owner))),
                    key_size=size,
                    **material,
                    **extra,
                )
            ]

        algorithm = self._resolve(properties.algorithm_ref if properties else None)
        if algorithm is not None and algorithm.crypto_properties is not None:
            return self._algorithm(
                algorithm,
                primitive=primitive,
                key_size=size,
                observation=observation or "related_crypto_material",
                occurrence_owner=occurrence_owner,
                material_ref=ref,
                **material,
                **extra,
            )

        self.skipped.append(
            f"{ref}: related-crypto-material of type {kind.value if kind else 'unknown'} "
            "names no algorithm this document defines"
        )
        return []

    def _resolve(self, ref: Any) -> Component | None:
        if ref is None:
            return None
        return self.by_ref.get(str(ref))


def _walk(components: Iterable[Component]) -> Iterable[Component]:
    for component in components:
        yield component
        if component.components:
            yield from _walk(component.components)


def _iso(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value else None)


def findings_from_bom(
    bom: Bom, *, provenance_id: str | None = None, tool: str | None = None
) -> tuple[list[RawFinding], tuple[str, ...]]:
    """Every cryptographic asset in the BOM as raw findings, plus what was skipped and why."""
    mapper = _Mapper(bom, provenance_id, tool or _tool_name(bom))
    findings = mapper.findings()
    return findings, tuple(mapper.skipped)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def import_cbom(
    session: Session, scan: Scan, raw: bytes, *, filename: str | None = None
) -> ImportResult:
    """Store the upload as provenance, map it to findings, and write them for the scan.

    The analysis stages (§4 steps 8–10) are the caller's to run afterwards —
    ``app/runner.py``'s ``analyse`` — because they are the same stages whichever
    door the findings came through.
    """
    bom, _ = parse_cbom(raw)
    tool = _tool_name(bom)

    blob = ProvenanceBlob(
        scan_id=scan.id,
        raw_document={
            "filename": filename,
            "content_type": "application/vnd.cyclonedx+json",
            "byte_length": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "tool": tool,
            # The bytes, as a JSON string. See the module docstring for why a
            # string rather than the parsed object.
            "document": raw.decode("utf-8"),
        },
    )
    session.add(blob)
    session.flush()

    raw_findings, skipped = findings_from_bom(bom, provenance_id=str(blob.id), tool=tool)
    stored = normalize(session, scan.id, raw_findings)

    component_count = sum(
        1 for c in _walk(bom.components) if c.type is ComponentType.CRYPTOGRAPHIC_ASSET
    )
    logger.info(
        "scan %s: imported CBOM %s from %s — %d cryptographic asset(s) → %d finding(s)%s",
        scan.id,
        filename or "(unnamed)",
        tool or "an unnamed tool",
        component_count,
        len(stored),
        f"; skipped {len(skipped)}" if skipped else "",
    )
    for reason in skipped:
        logger.info("scan %s: cbom skipped %s", scan.id, reason)
    return ImportResult(
        blob=blob,
        findings=stored,
        component_count=component_count,
        tool=tool,
        skipped=skipped,
    )
