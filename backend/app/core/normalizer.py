"""Normalizer — SPEC.md §8, build step 5.

Six collectors produce six incompatible output shapes. This module maps all of
them onto ``findings`` rows and does the two jobs §8 asks for beyond field
mapping.

**Identity resolution.** ``SHA-1``, ``sha1``, ``SHA1withRSA`` and OID
``1.3.14.3.2.26`` are one algorithm, and a dashboard that counts them as four is
worse than useless — it makes the biggest number the one with the most spellings.
The mapping lives in ``policy/algorithm_aliases.yaml``, not in this file: adding a
spelling has to be a policy-pack edit with a citation, the same as adding a
verdict, because a table of algorithm identities is exactly the kind of thing
that ages and needs to be reviewable on its own.

Two rules govern what the table may do to an observation:

* **The family collapses; the OID does not.** ``algorithm_family`` is the
  identity everything downstream counts and matches on. ``algorithm_oid`` stays
  the precise identity of the spelling that was observed, so a disputed finding
  can be traced back to the artefact rather than to a rewrite of it.
* **An observation always beats the table.** A collector that saw a primitive, a
  key size or a mode keeps it. The alias entry supplies those fields only where
  the collector had nothing, because the table knows what a *name* usually means
  and the collector knows what this *artefact* actually said.

Nothing is resolved by guessing. A name the table does not carry keeps its
observed spelling as its family and is stamped ``identity_resolved: false``, which
is what puts it in front of a human instead of quietly under a wrong heading. The
policy engine (§10) then answers ``unknown``, and §10's rule is that unknown is
never upgraded to safe.

**Source layer tagging.** Every row carries ``live``, ``artifact``, ``config`` or
``source``, ordered here by closeness to execution. A collector states its own —
all of them do — and :data:`COLLECTOR_SOURCE_LAYER` is the fallback plus the one
place the mapping is written down. The ordering is not decoration: it is the
precedence rule when two layers disagree, which is what the alignment check
(§9, step 8) is built on, so :func:`layer_rank` lives here next to the table it
comes from.

This module writes rows and stops. Verdicts, alignment notes, waves and
recommendations are all downstream, and none of them are computed here.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.collectors.base import RawFinding
from app.core.policy_loader import PolicyPack, PolicyValidationError, get_policy
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer
from app.models.finding import Finding

logger = logging.getLogger(__name__)

__all__ = [
    "AliasEntry",
    "AliasError",
    "AliasIndex",
    "COLLECTOR_CONFIDENCE",
    "COLLECTOR_SOURCE_LAYER",
    "LAYER_PRECEDENCE",
    "ResolvedIdentity",
    "build_alias_index",
    "get_alias_index",
    "identity_key",
    "layer_rank",
    "normalize",
    "reset_alias_index_cache",
    "resolve",
    "to_finding",
]


class AliasError(PolicyValidationError):
    """``algorithm_aliases.yaml`` loaded but cannot be turned into an index.

    A :class:`~app.core.policy_loader.PolicyValidationError` so that a broken
    alias table stops the process at startup, exactly as a missing citation in
    ``algorithms.yaml`` does. An identity table that silently half-loads would
    split one algorithm across two dashboard rows and never say why.
    """


#: §8's ordering: closeness to execution. `live` is observed fact, `source` is
#: intent. Step 8 resolves disagreements by taking the earlier layer.
LAYER_PRECEDENCE: tuple[SourceLayer, ...] = (
    SourceLayer.LIVE,
    SourceLayer.ARTIFACT,
    SourceLayer.CONFIG,
    SourceLayer.SOURCE,
)

#: Where each collector's output sits in that ordering (§7). Used when a raw
#: finding does not carry its own layer — every current collector does, and the
#: CBOM importer (§7.6) is the one that legitimately varies, since the layer
#: comes from the imported document when it declares one.
COLLECTOR_SOURCE_LAYER: Mapping[CollectorName, SourceLayer] = MappingProxyType(
    {
        CollectorName.NETWORK: SourceLayer.LIVE,
        CollectorName.CERTS: SourceLayer.ARTIFACT,
        CollectorName.BINARY: SourceLayer.ARTIFACT,
        CollectorName.CONFIG: SourceLayer.CONFIG,
        CollectorName.CODE: SourceLayer.SOURCE,
        CollectorName.CBOM_IMPORT: SourceLayer.SOURCE,
    }
)

#: Default confidence per §7, applied when a collector did not state one.
#: ``binary`` is the interesting case: §7.2 splits it, ``high`` for symbols and
#: dependencies, ``medium`` for ``.rodata`` strings. The default is the weaker of
#: the two, because a collector that forgot to say should not be trusted more
#: than one that did.
COLLECTOR_CONFIDENCE: Mapping[CollectorName, Confidence] = MappingProxyType(
    {
        CollectorName.NETWORK: Confidence.HIGH,
        CollectorName.CERTS: Confidence.HIGH,
        CollectorName.CONFIG: Confidence.HIGH,
        CollectorName.CODE: Confidence.HIGH,
        CollectorName.BINARY: Confidence.MEDIUM,
        CollectorName.CBOM_IMPORT: Confidence.MEDIUM,
    }
)

#: A dotted decimal OID. Used to spot a "name" that is really an OID — the
#: certificate collector falls back to the dotted string when the library has no
#: registered short name for it.
_OID_PATTERN = re.compile(r"^\d+(?:\.\d+)+$")

_ALIAS_FIELDS = frozenset(
    {
        "family",
        "oid",
        "oids",
        "primitive",
        "key_size",
        "mode",
        "protocol_version",
        "components",
        "source",
        "names",
        "note",
    }
)


def layer_rank(layer: SourceLayer) -> int:
    """Position in :data:`LAYER_PRECEDENCE`. Lower is closer to execution."""
    return LAYER_PRECEDENCE.index(layer)


def identity_key(value: str) -> str:
    """Fold a spelling to its lookup key.

    Case and separators are noise: ``SHA-1``, ``SHA1`` and ``sha1`` are the same
    name written by three different tools. Everything else is preserved, so
    ``AES128-SHA`` and ``AES256-SHA`` stay distinct.

    Public because the policy engine (§10) has to compare the families written in
    ``algorithms.yaml`` against the families written here. Two implementations of
    "are these the same name" is how the two files start disagreeing about it.
    """
    return re.sub(r"[^a-z0-9]+", "", value.lower())


# --------------------------------------------------------------------------- #
# The alias table
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class AliasEntry:
    """One entry of ``algorithm_aliases.yaml``.

    ``primitive``, ``key_size``, ``mode`` and ``protocol_version`` are defaults
    implied by the *name*. They fill gaps in an observation; they never overwrite
    one.
    """

    id: str
    family: str
    source: str
    oid: str | None = None
    primitive: Primitive | None = None
    key_size: int | None = None
    mode: str | None = None
    protocol_version: str | None = None
    #: other families this one spelling also names — `ssh-rsa` is RSA with SHA-1
    components: tuple[str, ...] = ()
    names: tuple[str, ...] = ()
    oids: tuple[str, ...] = ()
    note: str | None = None


@dataclass(frozen=True, slots=True)
class AliasIndex:
    """The table, flattened into the two lookups resolution actually needs."""

    entries: tuple[AliasEntry, ...]
    by_name: Mapping[str, AliasEntry]
    by_oid: Mapping[str, AliasEntry]

    def by_spelling(self, value: str | None) -> AliasEntry | None:
        """Resolve a name, or a dotted OID written where a name was expected."""
        if not value:
            return None
        text = value.strip()
        if _OID_PATTERN.match(text):
            return self.by_oid.get(text)
        return self.by_name.get(identity_key(text))

    def lookup(self, name: str | None, oid: str | None) -> AliasEntry | None:
        """OID first — it is an identifier, where a name is only a label."""
        if oid:
            entry = self.by_oid.get(oid.strip())
            if entry is not None:
                return entry
        return self.by_spelling(name)


def _require_text(raw: Mapping[str, Any], key: str, entry_id: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AliasError(
            f"algorithm_aliases.yaml: entry '{entry_id}' has no '{key}'. "
            "Every alias entry needs a canonical family and a citation for the "
            "mapping — an identity resolved from an uncited table is not traceable."
        )
    return value.strip()


def _string_tuple(raw: Mapping[str, Any], key: str, entry_id: str) -> tuple[str, ...]:
    value = raw.get(key) or ()
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise AliasError(f"algorithm_aliases.yaml: entry '{entry_id}': '{key}' must be a list")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise AliasError(
                f"algorithm_aliases.yaml: entry '{entry_id}': '{key}' holds a "
                f"non-string or empty value ({item!r})"
            )
        items.append(item.strip())
    return tuple(items)


def _optional_primitive(raw: Mapping[str, Any], entry_id: str) -> Primitive | None:
    value = raw.get("primitive")
    if value is None:
        return None
    try:
        return Primitive(str(value))
    except ValueError as exc:
        allowed = ", ".join(p.value for p in Primitive)
        raise AliasError(
            f"algorithm_aliases.yaml: entry '{entry_id}': primitive {value!r} is not "
            f"one of {allowed}"
        ) from exc


def _optional_int(raw: Mapping[str, Any], key: str, entry_id: str) -> int | None:
    value = raw.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise AliasError(
            f"algorithm_aliases.yaml: entry '{entry_id}': '{key}' must be an integer, "
            f"got {value!r}"
        )
    return value


def _build_entry(entry_id: str, raw: Any) -> AliasEntry:
    if not isinstance(raw, Mapping):
        raise AliasError(f"algorithm_aliases.yaml: entry '{entry_id}' is not a mapping")

    unknown = sorted(set(raw) - _ALIAS_FIELDS)
    if unknown:
        # A typo in a key is silent otherwise, and the symptom — one algorithm
        # quietly failing to collapse — surfaces as a dashboard oddity days later.
        raise AliasError(
            f"algorithm_aliases.yaml: entry '{entry_id}' has unknown field(s): "
            f"{', '.join(unknown)}"
        )

    oid = raw.get("oid")
    if oid is not None and not _OID_PATTERN.match(str(oid).strip()):
        raise AliasError(
            f"algorithm_aliases.yaml: entry '{entry_id}': oid {oid!r} is not dotted decimal"
        )
    extra_oids = _string_tuple(raw, "oids", entry_id)
    for candidate in extra_oids:
        if not _OID_PATTERN.match(candidate):
            raise AliasError(
                f"algorithm_aliases.yaml: entry '{entry_id}': oids holds {candidate!r}, "
                "which is not dotted decimal"
            )

    mode = raw.get("mode")
    protocol_version = raw.get("protocol_version")
    return AliasEntry(
        id=entry_id,
        family=_require_text(raw, "family", entry_id),
        source=_require_text(raw, "source", entry_id),
        oid=str(oid).strip() if oid is not None else None,
        primitive=_optional_primitive(raw, entry_id),
        key_size=_optional_int(raw, "key_size", entry_id),
        mode=str(mode).strip().upper() if mode is not None else None,
        protocol_version=(
            str(protocol_version).strip() if protocol_version is not None else None
        ),
        components=_string_tuple(raw, "components", entry_id),
        names=_string_tuple(raw, "names", entry_id),
        oids=extra_oids,
        note=raw.get("note"),
    )


def build_alias_index(aliases: Mapping[str, Any]) -> AliasIndex:
    """Validate the table and flatten it into name and OID lookups.

    Every failure here is a policy-pack bug rather than a scan-time problem, so
    all of them raise: a table that half-loads produces a dashboard that is
    subtly wrong, which is harder to notice than one that will not start.
    """
    if not isinstance(aliases, Mapping):
        raise AliasError("algorithm_aliases.yaml: 'aliases' must be a mapping")

    entries: list[AliasEntry] = []
    by_name: dict[str, AliasEntry] = {}
    by_oid: dict[str, AliasEntry] = {}

    for entry_id, raw in aliases.items():
        entry = _build_entry(str(entry_id), raw)
        entries.append(entry)

        for name in entry.names:
            key = identity_key(name)
            if not key:
                raise AliasError(
                    f"algorithm_aliases.yaml: entry '{entry.id}': name {name!r} folds to "
                    "an empty lookup key"
                )
            existing = by_name.get(key)
            if existing is None:
                by_name[key] = entry
            elif existing.id != entry.id:
                # Two entries claiming one spelling means resolution depends on
                # dict order, which is not a property anyone should have to know.
                raise AliasError(
                    f"algorithm_aliases.yaml: spelling {name!r} is claimed by both "
                    f"'{existing.id}' and '{entry.id}'. One spelling resolves to one "
                    "identity."
                )

        for oid in filter(None, (entry.oid, *entry.oids)):
            existing = by_oid.get(oid)
            if existing is None:
                by_oid[oid] = entry
            elif existing.id != entry.id:
                raise AliasError(
                    f"algorithm_aliases.yaml: OID {oid} is claimed by both "
                    f"'{existing.id}' and '{entry.id}'. An OID identifies one algorithm."
                )

    return AliasIndex(
        entries=tuple(entries),
        by_name=MappingProxyType(by_name),
        by_oid=MappingProxyType(by_oid),
    )


_CACHED_INDEX: AliasIndex | None = None
_CACHED_FOR_PACK: PolicyPack | None = None


def get_alias_index(policy: PolicyPack | None = None) -> AliasIndex:
    """The index for a pack, built once. Startup builds it so a bad table fails there."""
    global _CACHED_INDEX, _CACHED_FOR_PACK
    pack = policy or get_policy()
    if _CACHED_INDEX is None or _CACHED_FOR_PACK is not pack:
        _CACHED_INDEX = build_alias_index(pack.aliases)
        _CACHED_FOR_PACK = pack
    return _CACHED_INDEX


def reset_alias_index_cache() -> None:
    """Drop the cached index. For tests only — nothing in the app calls this."""
    global _CACHED_INDEX, _CACHED_FOR_PACK
    _CACHED_INDEX = None
    _CACHED_FOR_PACK = None


# --------------------------------------------------------------------------- #
# Resolution
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ResolvedIdentity:
    """What one :class:`RawFinding` becomes, before it is a database row."""

    family: str
    oid: str | None
    primitive: Primitive
    key_size: int | None
    mode: str | None
    protocol_version: str | None
    confidence: Confidence
    source_layer: SourceLayer
    entry: AliasEntry | None

    @property
    def resolved(self) -> bool:
        """False when the family is the observed spelling rather than a known one."""
        return self.entry is not None


def _canonical_protocol_version(value: str | None, index: AliasIndex) -> str | None:
    """``TLSv1`` → ``1.0``, so ``protocol_version_lt`` compares like with like.

    An unrecognised version is kept verbatim rather than parsed into a number:
    guessing at the ordering of a protocol nobody has written a rule for is how a
    tool ends up calling something safe by arithmetic accident.
    """
    if not value:
        return None
    entry = index.by_spelling(value)
    if entry is not None and entry.protocol_version:
        return entry.protocol_version
    return value.strip()


def resolve(raw: RawFinding, index: AliasIndex) -> ResolvedIdentity:
    """Collapse one observation onto a canonical identity.

    The observation wins every contested field. The table only fills gaps.
    """
    entry = index.lookup(raw.algorithm_name, raw.algorithm_oid)
    observed_name = (raw.algorithm_name or "").strip()

    primitive = raw.primitive
    if primitive is Primitive.UNKNOWN and entry is not None and entry.primitive is not None:
        primitive = entry.primitive

    mode = raw.mode or (entry.mode if entry is not None else None)
    key_size = raw.key_size
    if key_size is None and entry is not None:
        key_size = entry.key_size

    protocol_version = _canonical_protocol_version(raw.protocol_version, index)
    if protocol_version is None and entry is not None:
        protocol_version = entry.protocol_version

    collector = raw.collector
    return ResolvedIdentity(
        # An unresolved name keeps its own spelling as its identity: countable,
        # traceable, and stamped `identity_resolved: false` so the gap is visible.
        # A row with no family at all would be one nothing downstream can group,
        # filter or report, so an empty name still gets the literal "unknown".
        family=entry.family if entry is not None else (observed_name or "unknown"),
        oid=raw.algorithm_oid or (entry.oid if entry is not None else None),
        primitive=primitive,
        key_size=key_size,
        mode=mode.strip().upper() if mode else None,
        protocol_version=protocol_version,
        confidence=raw.confidence or COLLECTOR_CONFIDENCE.get(collector, Confidence.MEDIUM),
        source_layer=raw.source_layer
        or COLLECTOR_SOURCE_LAYER.get(collector, SourceLayer.ARTIFACT),
        entry=entry,
    )


def _trace(raw: RawFinding, identity: ResolvedIdentity) -> dict[str, Any]:
    """What the normalizer did, recorded on the row that it did it to.

    Kept small and always present: `alias_id` and `identity_resolved` answer "why
    is this row filed under that family", and the `observed_*` keys appear only
    when normalization changed something, so their presence is itself the signal.
    """
    entry = identity.entry
    trace: dict[str, Any] = {
        "identity_resolved": identity.resolved,
        "alias_id": entry.id if entry is not None else None,
        "observed_name": raw.algorithm_name,
    }
    if entry is not None:
        trace["alias_source"] = entry.source
        if entry.components:
            # `ssh-rsa` is RSA *with SHA-1*; the row says RSA and this says the rest.
            trace["component_families"] = list(entry.components)
    if raw.algorithm_oid and raw.algorithm_oid != identity.oid:
        trace["observed_oid"] = raw.algorithm_oid
    if raw.protocol_version and raw.protocol_version != identity.protocol_version:
        trace["observed_protocol_version"] = raw.protocol_version
    if raw.primitive is not identity.primitive:
        trace["observed_primitive"] = raw.primitive.value
    return trace


def to_finding(scan_id: UUID, raw: RawFinding, index: AliasIndex) -> Finding:
    """One observation, one row. Nothing is merged, dropped or invented."""
    identity = resolve(raw, index)
    evidence = {**dict(raw.evidence_raw), "normalization": _trace(raw, identity)}
    return Finding(
        scan_id=scan_id,
        collector=raw.collector,
        algorithm_name=raw.algorithm_name,
        algorithm_oid=identity.oid,
        algorithm_family=identity.family,
        primitive=identity.primitive,
        key_size=identity.key_size,
        mode=identity.mode,
        protocol_version=identity.protocol_version,
        evidence_location=raw.evidence_location,
        evidence_raw=evidence,
        confidence=identity.confidence,
        source_layer=identity.source_layer,
    )


def _unresolvable_finding(scan_id: UUID, raw: RawFinding, error: Exception) -> Finding:
    """A row for an observation resolution choked on.

    Dropping it would be the one outcome worse than a badly labelled finding: the
    collector saw something, and a scan that quietly loses observations cannot be
    audited. The row keeps the observed spelling and says what went wrong.
    """
    return Finding(
        scan_id=scan_id,
        collector=raw.collector,
        algorithm_name=raw.algorithm_name,
        algorithm_oid=raw.algorithm_oid,
        algorithm_family=(raw.algorithm_name or "").strip() or "unknown",
        primitive=raw.primitive,
        key_size=raw.key_size,
        mode=raw.mode,
        protocol_version=raw.protocol_version,
        evidence_location=raw.evidence_location,
        evidence_raw={
            **dict(raw.evidence_raw),
            "normalization": {
                "identity_resolved": False,
                "alias_id": None,
                "observed_name": raw.algorithm_name,
                "normalization_error": f"{type(error).__name__}: {error}",
            },
        },
        confidence=raw.confidence or Confidence.LOW,
        source_layer=raw.source_layer
        or COLLECTOR_SOURCE_LAYER.get(raw.collector, SourceLayer.ARTIFACT),
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def normalize(
    session: Session,
    scan_id: UUID,
    raw_findings: Sequence[RawFinding],
    *,
    index: AliasIndex | None = None,
    policy: PolicyPack | None = None,
) -> list[Finding]:
    """Write one ``findings`` row per raw finding and return them.

    Called by ``app/runner.py`` once every collector has finished. The row count
    equals the observation count — normalization renames things, it does not
    merge or discard them, so a number the user was shown at collection time is
    still the number in the table.
    """
    index = index or get_alias_index(policy)

    rows: list[Finding] = []
    unresolved: Counter[str] = Counter()
    for raw in raw_findings:
        try:
            row = to_finding(scan_id, raw, index)
            if row.evidence_raw["normalization"]["identity_resolved"] is False:
                unresolved[row.algorithm_family] += 1
        except Exception as exc:  # noqa: BLE001 - an observation is never dropped
            logger.exception(
                "scan %s: could not normalize %r from the %s collector; storing it "
                "unresolved",
                scan_id,
                raw.algorithm_name,
                raw.collector.value,
            )
            row = _unresolvable_finding(scan_id, raw, exc)
            unresolved[row.algorithm_family] += 1
        rows.append(row)

    session.add_all(rows)
    session.flush()

    logger.info(
        "scan %s: normalized %d observation(s) into %d finding(s); %d resolved to a "
        "known identity",
        scan_id,
        len(raw_findings),
        len(rows),
        len(rows) - sum(unresolved.values()),
    )
    if unresolved:
        # Not an error. It is the list of spellings the alias table does not
        # carry, which is the shortest description of what to add to it next.
        logger.info(
            "scan %s: unresolved identities (kept as observed): %s",
            scan_id,
            ", ".join(f"{name} x{count}" for name, count in unresolved.most_common()),
        )
    return rows
