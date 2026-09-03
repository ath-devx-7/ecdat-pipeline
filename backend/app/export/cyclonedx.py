"""CycloneDX export — SPEC.md §13, build step 12.

``GET /api/scans/{id}/cbom`` builds a CycloneDX 1.6 document on demand from a
query over ``findings`` and its analysis tables. CycloneDX is the wire format at
both boundaries and is not the store: Postgres with proper columns is the store,
and this module is a view over it that is regenerated every time it is asked
for. Nothing here is persisted.

**One component per asset, one occurrence per finding.** The findings table has
one row per observed use (§5); an inventory has one entry per thing. So findings
are grouped by identity — family, OID, key size, mode, primitive — into a
component, and every finding in the group becomes an ``evidence.occurrences``
entry carrying its location, collector, layer and confidence. The verdict, wave
and recommendation ride along as ``ecdat:`` properties, which is where CycloneDX
puts data it has no field for. Nothing is invented for a field the schema wants:
a finding with no OID exports no OID.

**Not every finding is an asset.** A refused protocol version, an
"undetermined" marker, a hygiene note about a self-signed certificate — these
are observations about the scan, not cryptographic assets, and a CBOM that
listed them would misinform every tool that reads it. They are counted on the
document's metadata as ``ecdat:excluded_observations`` rather than dropped in
silence. Three non-algorithm findings *are* exported, in the shape CycloneDX
gives them: a private key file as ``related-crypto-material`` of type
``private-key`` (path and size, never bytes), a linked crypto library as a
``library`` component, and TLS cipher suites as ``cipherSuites`` on the protocol
component of the service that accepted them.

The output is validated against the 1.6 schema before it is served. A document
that fails its own schema is a bug, and serving it would hand that bug to
whatever imports it next — including this tool's own importer.
"""

from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import sqlalchemy as sa
from cyclonedx.model import Property
from cyclonedx.model import crypto as cdx
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.component_evidence import ComponentEvidence, Occurrence
from cyclonedx.output.json import JsonV1Dot6
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from sqlalchemy.orm import Session

from app.collectors.cbom_import import PROPERTY_CONFIDENCE, PROPERTY_SOURCE_LAYER
from app.core.advisor import LIBRARY_OBSERVATIONS
from app.models.analysis import Recommendation, RiskScore, VerdictRow
from app.models.enums import Confidence, Primitive
from app.models.finding import Finding
from app.models.scan import Scan

logger = logging.getLogger(__name__)

__all__ = [
    "ECDAT_VERSION",
    "MEDIA_TYPE",
    "build_cbom",
    "export_cbom",
    "validate_cbom",
]

ECDAT_VERSION = "0.12.0"
MEDIA_TYPE = "application/vnd.cyclonedx+json"

#: ECDAT primitive → CycloneDX primitive. The reverse mapping lives in the
#: importer, and the two agree so a round trip preserves the field.
_PRIMITIVES: Mapping[Primitive, cdx.CryptoPrimitive] = {
    Primitive.HASH: cdx.CryptoPrimitive.HASH,
    Primitive.CIPHER: cdx.CryptoPrimitive.BLOCK_CIPHER,
    Primitive.SIGNATURE: cdx.CryptoPrimitive.SIGNATURE,
    Primitive.KEY_EXCHANGE: cdx.CryptoPrimitive.KEY_AGREE,
    Primitive.UNKNOWN: cdx.CryptoPrimitive.UNKNOWN,
}

#: Families that are stream ciphers, so the primitive is not misreported.
_STREAM_CIPHERS = frozenset({"rc4", "chacha20", "salsa20"})
_KEMS = frozenset({"mlkem", "kyber", "hqc", "frodokem"})

_MODES: Mapping[str, cdx.CryptoMode] = {mode.value.upper(): mode for mode in cdx.CryptoMode}
_SUITE = re.compile(r"^(?:TLS|SSL)_[A-Z0-9]+_WITH_[A-Z0-9_]+$")
_PRIVATE_KEY = "private-key-file"
_CONFIDENCE_RANK = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


@dataclass
class _Analysis:
    """The analysis rows of one scan, keyed by finding."""

    verdicts: dict[UUID, VerdictRow] = field(default_factory=dict)
    scores: dict[UUID, RiskScore] = field(default_factory=dict)
    recommendations: dict[UUID, list[Recommendation]] = field(default_factory=dict)


def _load(session: Session, scan: Scan) -> tuple[list[Finding], _Analysis]:
    findings = list(
        session.scalars(
            sa.select(Finding).where(Finding.scan_id == scan.id).order_by(Finding.created_at, Finding.id)
        )
    )
    ids = sa.select(Finding.id).where(Finding.scan_id == scan.id)
    analysis = _Analysis()
    for row in session.scalars(sa.select(VerdictRow).where(VerdictRow.finding_id.in_(ids))):
        analysis.verdicts[row.finding_id] = row
    for row in session.scalars(sa.select(RiskScore).where(RiskScore.finding_id.in_(ids))):
        analysis.scores[row.finding_id] = row
    for row in session.scalars(
        sa.select(Recommendation).where(Recommendation.finding_id.in_(ids)).order_by(Recommendation.id)
    ):
        analysis.recommendations.setdefault(row.finding_id, []).append(row)
    return findings, analysis


# --------------------------------------------------------------------------- #
# Classification of findings into export shapes
# --------------------------------------------------------------------------- #


def _observation(finding: Finding) -> str | None:
    return (finding.evidence_raw or {}).get("observation")


def _resolved(finding: Finding) -> bool:
    trace = (finding.evidence_raw or {}).get("normalization") or {}
    return bool(trace.get("identity_resolved"))


def _asset(finding: Finding) -> str:
    evidence = finding.evidence_raw or {}
    host, port = evidence.get("host"), evidence.get("port")
    if host is not None and port is not None:
        return f"{host}:{port}"
    return re.sub(r":\d+$", "", finding.evidence_location or "")


def _is_suite(finding: Finding) -> bool:
    return bool(finding.algorithm_family and _SUITE.match(finding.algorithm_family))


def _is_asset(finding: Finding) -> bool:
    """An algorithm, a protocol version, a key file or a library — not a marker."""
    if _observation(finding) in LIBRARY_OBSERVATIONS or finding.algorithm_name == _PRIVATE_KEY:
        return True
    if finding.primitive is Primitive.PROTOCOL:
        return _observation(finding) != "protocol_version_not_offered"
    if _resolved(finding) or finding.algorithm_oid or _is_suite(finding):
        return True
    # Unresolved and unknown: a marker such as `certificate-self-signed`. An
    # unresolved name with an observed primitive is still an algorithm
    # somebody used, and stays.
    return finding.primitive not in (Primitive.UNKNOWN, None)


# --------------------------------------------------------------------------- #
# Building
# --------------------------------------------------------------------------- #


def _occurrence(finding: Finding, analysis: _Analysis) -> Occurrence:
    location = finding.evidence_location or "(unknown)"
    line = None
    # `path:49` splits into a path and a line; `host:8443` is one asset and does
    # not. `_asset` already knows which, from the evidence rather than the shape.
    asset = _asset(finding)
    match = re.search(r":(\d+)$", location)
    if match and asset and asset != location and location.startswith(asset):
        line = int(match.group(1))
        location = asset
    verdict = analysis.verdicts.get(finding.id)
    score = analysis.scores.get(finding.id)
    context = (
        f"collector={finding.collector.value} layer={finding.source_layer.value} "
        f"confidence={finding.confidence.value} observed_as={finding.algorithm_name}"
        + (f" verdict={verdict.verdict.value}" if verdict else "")
        + (f" wave={score.wave.value}" if score else "")
        + f" finding_id={finding.id}"
    )
    return Occurrence(location=location, line=line, additional_context=context)


def _summary_properties(prefix: str, findings: list[Finding], analysis: _Analysis) -> list[Property]:
    """What the analysis said about this group, as ``ecdat:`` properties."""
    verdicts = sorted({analysis.verdicts[f.id].verdict.value for f in findings if f.id in analysis.verdicts})
    rules = sorted({analysis.verdicts[f.id].rule_id for f in findings if f.id in analysis.verdicts and analysis.verdicts[f.id].rule_id})
    citations = sorted({analysis.verdicts[f.id].source_citation for f in findings if f.id in analysis.verdicts and analysis.verdicts[f.id].source_citation})
    waves = sorted({analysis.scores[f.id].wave.value for f in findings if f.id in analysis.scores})
    urgencies = sorted({analysis.scores[f.id].urgency_years for f in findings if f.id in analysis.scores and analysis.scores[f.id].urgency_years is not None})
    statuses = sorted({r.status.value for f in findings for r in analysis.recommendations.get(f.id, ())})
    targets = sorted({r.target for f in findings for r in analysis.recommendations.get(f.id, ()) if r.target})
    layers = sorted({f.source_layer.value for f in findings})
    collectors = sorted({f.collector.value for f in findings})
    best = max((f.confidence for f in findings), key=lambda c: _CONFIDENCE_RANK[c])

    properties = [
        Property(name=PROPERTY_CONFIDENCE, value=best.value),
        Property(name=PROPERTY_SOURCE_LAYER, value=layers[0] if len(layers) == 1 else "source"),
        Property(name="ecdat:source_layers", value=",".join(layers)),
        Property(name="ecdat:collectors", value=",".join(collectors)),
        Property(name="ecdat:finding_count", value=str(len(findings))),
    ]
    if verdicts:
        properties.append(Property(name="ecdat:verdict", value=",".join(verdicts)))
    if rules:
        properties.append(Property(name="ecdat:rule_id", value=",".join(rules)))
    if citations:
        properties.append(Property(name="ecdat:source_citation", value="; ".join(citations)))
    if waves:
        properties.append(Property(name="ecdat:wave", value=",".join(waves)))
    if urgencies:
        properties.append(Property(name="ecdat:urgency_years", value=",".join(str(u) for u in urgencies)))
    if statuses:
        properties.append(Property(name="ecdat:recommendation_status", value=",".join(statuses)))
    if targets:
        properties.append(Property(name="ecdat:recommended_target", value=",".join(targets)))
    return properties


def _cdx_primitive(finding: Finding) -> cdx.CryptoPrimitive:
    family = (finding.algorithm_family or "").lower().replace("-", "")
    if finding.primitive is Primitive.CIPHER and family in _STREAM_CIPHERS:
        return cdx.CryptoPrimitive.STREAM_CIPHER
    if finding.primitive is Primitive.KEY_EXCHANGE and family in _KEMS:
        return cdx.CryptoPrimitive.KEM
    return _PRIMITIVES.get(finding.primitive or Primitive.UNKNOWN, cdx.CryptoPrimitive.UNKNOWN)


def _algorithm_component(index: int, findings: list[Finding], analysis: _Analysis) -> Component:
    first = findings[0]
    mode = _MODES.get((first.mode or "").upper()) if first.mode else None
    properties = cdx.AlgorithmProperties(
        primitive=_cdx_primitive(first),
        parameter_set_identifier=str(first.key_size) if first.key_size else None,
        mode=mode,
    )
    return Component(
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        name=first.algorithm_family or first.algorithm_name,
        bom_ref=f"ecdat/algorithm/{index}",
        crypto_properties=cdx.CryptoProperties(
            asset_type=cdx.CryptoAssetType.ALGORITHM,
            algorithm_properties=properties,
            oid=first.algorithm_oid or None,
        ),
        evidence=ComponentEvidence(occurrences=[_occurrence(f, analysis) for f in findings]),
        properties=_summary_properties("ecdat", findings, analysis),
    )


def _protocol_component(
    index: int, asset: str, version: str | None, findings: list[Finding], suites: list[Finding], analysis: _Analysis
) -> Component:
    kind = cdx.ProtocolPropertiesType.TLS
    family = (findings[0].algorithm_family if findings else suites[0].algorithm_family) or ""
    if family.upper().startswith("SSL"):
        kind = cdx.ProtocolPropertiesType.TLS  # SSL 2.0/3.0 have no enum value of their own
    cipher_suites = []
    seen: set[str] = set()
    for suite in suites:
        name = suite.algorithm_family or suite.algorithm_name
        if name in seen:
            continue
        seen.add(name)
        cipher_suites.append(cdx.ProtocolPropertiesCipherSuite(name=name))
    label = f"{family or 'TLS'} {version}".strip() if version else f"{family or 'TLS'} (version undeclared)"
    return Component(
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        name=label,
        bom_ref=f"ecdat/protocol/{index}",
        crypto_properties=cdx.CryptoProperties(
            asset_type=cdx.CryptoAssetType.PROTOCOL,
            protocol_properties=cdx.ProtocolProperties(
                type=kind, version=version, cipher_suites=cipher_suites or None
            ),
        ),
        evidence=ComponentEvidence(occurrences=[_occurrence(f, analysis) for f in findings + suites]),
        properties=[
            Property(name="ecdat:asset", value=asset),
            *_summary_properties("ecdat", findings + suites, analysis),
        ],
    )


def _key_format(evidence: Mapping[str, Any]) -> str | None:
    """A container name from what the collector saw — never the PEM header itself.

    The certificate collector records the ``-----BEGIN ... KEY-----`` line it
    stopped at. Exporting that line would put the words "PRIVATE KEY" into a
    document people grep for leaked keys, so it is translated to the container
    it names and the header text stays behind.
    """
    for key in ("material_format", "container", "header"):
        value = evidence.get(key)
        if not value:
            continue
        text = str(value)
        upper = text.upper()
        if "PKCS#12" in upper or "PKCS12" in upper:
            return "PKCS#12"
        if upper.startswith("-----"):
            if "RSA PRIVATE" in upper:
                return "PEM (PKCS#1)"
            if "EC PRIVATE" in upper:
                return "PEM (SEC1)"
            if "PRIVATE" in upper:
                return "PEM (PKCS#8)"
            return "PEM"
        return text
    return None


def _key_component(index: int, findings: list[Finding], analysis: _Analysis) -> Component:
    first = findings[0]
    evidence = first.evidence_raw or {}
    return Component(
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        name=_PRIVATE_KEY,
        bom_ref=f"ecdat/key/{index}",
        crypto_properties=cdx.CryptoProperties(
            asset_type=cdx.CryptoAssetType.RELATED_CRYPTO_MATERIAL,
            related_crypto_material_properties=cdx.RelatedCryptoMaterialProperties(
                type=cdx.RelatedCryptoMaterialType.PRIVATE_KEY,
                size=first.key_size,
                format=_key_format(evidence),
            ),
        ),
        evidence=ComponentEvidence(occurrences=[_occurrence(f, analysis) for f in findings]),
        properties=[
            Property(name="ecdat:note", value="metadata only; key bytes are never read (SPEC.md §1)"),
            *_summary_properties("ecdat", findings, analysis),
        ],
    )


def _library_component(index: int, library: str, version: str | None, findings: list[Finding], analysis: _Analysis) -> Component:
    return Component(
        type=ComponentType.LIBRARY,
        name=library,
        version=version,
        bom_ref=f"ecdat/library/{index}",
        evidence=ComponentEvidence(occurrences=[_occurrence(f, analysis) for f in findings]),
        properties=[
            Property(name="ecdat:sonames", value=",".join(sorted({str((f.evidence_raw or {}).get("soname")) for f in findings if (f.evidence_raw or {}).get("soname")})) or "-"),
            *_summary_properties("ecdat", findings, analysis),
        ],
    )


def build_cbom(session: Session, scan: Scan) -> Bom:
    """The scan as a CycloneDX 1.6 BOM. Built from a query, every time."""
    findings, analysis = _load(session, scan)

    algorithms: dict[tuple, list[Finding]] = defaultdict(list)
    protocols: dict[tuple[str, str | None], list[Finding]] = defaultdict(list)
    suites: dict[tuple[str, str | None], list[Finding]] = defaultdict(list)
    keys: dict[str, list[Finding]] = defaultdict(list)
    libraries: dict[tuple[str, str | None], list[Finding]] = defaultdict(list)
    excluded: Counter[str] = Counter()

    for finding in findings:
        if not _is_asset(finding):
            excluded[_observation(finding) or finding.algorithm_name] += 1
            continue
        observation = _observation(finding)
        if observation in LIBRARY_OBSERVATIONS:
            evidence = finding.evidence_raw or {}
            libraries[(str(evidence.get("library") or finding.algorithm_name), evidence.get("version"))].append(finding)
        elif finding.algorithm_name == _PRIVATE_KEY:
            keys[finding.evidence_location or "(unknown)"].append(finding)
        elif finding.primitive is Primitive.PROTOCOL:
            protocols[(_asset(finding), finding.protocol_version)].append(finding)
        elif _is_suite(finding):
            suites[(_asset(finding), finding.protocol_version)].append(finding)
        else:
            key = (
                finding.algorithm_family,
                finding.algorithm_oid,
                finding.primitive.value if finding.primitive else None,
                finding.key_size,
                (finding.mode or "").upper() or None,
            )
            algorithms[key].append(finding)

    bom = Bom()
    bom.metadata.tools.components.add(
        Component(type=ComponentType.APPLICATION, name="ecdat", version=ECDAT_VERSION)
    )
    bom.metadata.component = Component(
        type=ComponentType.APPLICATION,
        name=f"ecdat-scan-{scan.id}",
        version=scan.policy_version or "unversioned",
        bom_ref=f"ecdat/scan/{scan.id}",
        properties=[
            Property(name="ecdat:scan_id", value=str(scan.id)),
            Property(name="ecdat:mode", value=scan.mode.value),
            Property(name="ecdat:source_type", value=scan.source_type.value),
            Property(name="ecdat:source_ref", value=scan.source_ref or "-"),
            Property(name="ecdat:status", value=scan.status.value),
            Property(name="ecdat:policy_version", value=scan.policy_version or "-"),
            Property(name="ecdat:data_lifetime_years", value=str(scan.data_lifetime_years) if scan.data_lifetime_years is not None else "-"),
            Property(name="ecdat:finding_count", value=str(len(findings))),
            Property(
                name="ecdat:excluded_observations",
                value="; ".join(f"{name} x{count}" for name, count in sorted(excluded.items())) or "none",
            ),
        ],
    )

    index = 0
    for key in sorted(algorithms, key=lambda k: tuple(str(part) for part in k)):
        index += 1
        bom.components.add(_algorithm_component(index, algorithms[key], analysis))
    index = 0
    for key in sorted(set(protocols) | set(suites), key=lambda k: (k[0], k[1] or "")):
        index += 1
        bom.components.add(_protocol_component(index, key[0], key[1], protocols.get(key, []), suites.get(key, []), analysis))
    for index, location in enumerate(sorted(keys), start=1):
        bom.components.add(_key_component(index, keys[location], analysis))
    for index, key in enumerate(sorted(libraries, key=lambda k: (k[0], k[1] or "")), start=1):
        bom.components.add(_library_component(index, key[0], key[1], libraries[key], analysis))

    # The scan depends on everything it found. A flat graph, but a complete one:
    # a BOM whose root has no dependencies reads as "nothing was found".
    bom.register_dependency(bom.metadata.component, list(bom.components))

    logger.info(
        "scan %s: exported CycloneDX 1.6 — %d algorithm(s), %d protocol(s), %d key file(s), "
        "%d librar(y/ies); %d observation(s) excluded",
        scan.id, len(algorithms), len(set(protocols) | set(suites)), len(keys), len(libraries), sum(excluded.values()),
    )
    return bom


def validate_cbom(text: str) -> str | None:
    """The 1.6 schema's complaint, or ``None`` when the document is valid."""
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(text)
    return None if error is None else str(error)


def export_cbom(session: Session, scan: Scan) -> str:
    """The document as JSON text, validated before it leaves."""
    text = JsonV1Dot6(build_cbom(session, scan)).output_as_string(indent=2)
    error = validate_cbom(text)
    if error is not None:
        raise RuntimeError(f"the exported CycloneDX document does not validate: {error[:300]}")
    return text
