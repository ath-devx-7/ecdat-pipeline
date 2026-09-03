"""Loads the policy pack from ``backend/policy/`` into read-only memory.

SPEC.md §6. Five YAML files, read once at application startup:

* ``version.yaml``           — version stamp and the Mosca defaults
* ``algorithms.yaml``        — the policy engine's lookup table (§10)
* ``pqc_targets.yaml``       — the advisor's rules (§11)
* ``algorithm_aliases.yaml`` — identity resolution (§8, populated in step 5)
* ``named_groups.yaml``      — TLS named-group code points (§7.5, populated in step 7)

Two invariants this module enforces:

1. **Every entry in algorithms.yaml and pqc_targets.yaml carries a ``source``
   citation.** An entry without one fails the load, naming the offending id.
   A verdict a user cannot trace to a published standard is not usable evidence.
2. **The loaded pack is read-only.** Frozen dataclasses, tuples and
   ``MappingProxyType`` all the way down, so no code path can mutate policy at
   runtime and no API endpoint writes back to these files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

import yaml

from app.config import get_settings

__all__ = [
    "AlgorithmRule",
    "PolicyError",
    "PolicyPack",
    "PolicyValidationError",
    "PolicyVersion",
    "PqcParameterSet",
    "PqcTarget",
    "get_policy",
    "load_policy",
    "reset_policy_cache",
]

VERSION_FILE = "version.yaml"
ALGORITHMS_FILE = "algorithms.yaml"
PQC_TARGETS_FILE = "pqc_targets.yaml"
ALIASES_FILE = "algorithm_aliases.yaml"
NAMED_GROUPS_FILE = "named_groups.yaml"

_REQUIRED_VERSION_KEYS = (
    "version",
    "published",
    "z_years_default",
    "y_years_default",
    "staleness_warning_days",
)


class PolicyError(RuntimeError):
    """Base for every policy-pack failure."""


class PolicyValidationError(PolicyError):
    """A policy file loaded but its contents are not usable."""


# --------------------------------------------------------------------------- #
# Freezing helpers
# --------------------------------------------------------------------------- #


def _freeze(value: Any) -> Any:
    """Recursively convert dicts to mapping proxies and lists to tuples."""
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


def _as_tuple(value: Any) -> tuple[Any, ...]:
    """Policy YAML writes a single value bare and multiple values as a list."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


_EMPTY_MAP: Mapping[str, Any] = MappingProxyType({})


# --------------------------------------------------------------------------- #
# Structures
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PolicyVersion:
    """``version.yaml``. Stamped onto every scan so a verdict stays reproducible."""

    version: str
    published: date
    z_years_default: int
    y_years_default: int
    staleness_warning_days: int

    def age_days(self, today: date | None = None) -> int:
        return ((today or date.today()) - self.published).days

    def is_stale(self, today: date | None = None) -> bool:
        """An air-gapped install cannot fetch updates — the UI must say so (§6)."""
        return self.age_days(today) > self.staleness_warning_days


@dataclass(frozen=True, slots=True)
class AlgorithmRule:
    """One entry from ``algorithms.yaml``."""

    id: str
    verdict: str
    source: str
    family: tuple[str, ...] = ()
    primitive: tuple[str, ...] = ()
    oid: str | None = None
    condition: Mapping[str, Any] = field(default=_EMPTY_MAP)


@dataclass(frozen=True, slots=True)
class PqcTarget:
    """One entry from ``pqc_targets.yaml``."""

    id: str
    source: str
    match: Mapping[str, Any] = field(default=_EMPTY_MAP)
    target: str | None = None
    hybrid: str | None = None
    requires: Mapping[str, Any] = field(default=_EMPTY_MAP)
    action_class: str | None = None
    side_effects: str | None = None
    note: str | None = None
    #: §11 ``no_path``: an entry with no ``target`` names what to do instead —
    #: isolation, tunnelling, replacement. The advisor never invents one.
    compensating_control: str | None = None


@dataclass(frozen=True, slots=True)
class PqcParameterSet:
    """One ``parameter_sets`` entry from ``pqc_targets.yaml`` (§11 step 2).

    ``replace`` maps a target name to the parameter set that applies when
    ``match`` holds for the scan — ``ML-KEM-768`` to ``ML-KEM-1024`` above a
    data-lifetime threshold. The threshold is policy because it is guidance,
    not arithmetic.
    """

    id: str
    source: str
    match: Mapping[str, Any] = field(default=_EMPTY_MAP)
    replace: Mapping[str, str] = field(default=_EMPTY_MAP)


@dataclass(frozen=True, slots=True)
class PolicyPack:
    """The whole pack, immutable. Obtain it through :func:`get_policy`."""

    version: PolicyVersion
    algorithms: tuple[AlgorithmRule, ...]
    prefer_hybrid: bool
    pqc_targets: tuple[PqcTarget, ...]
    aliases: Mapping[str, Any]
    named_groups: Mapping[str, Any]
    policy_dir: Path
    parameter_sets: tuple[PqcParameterSet, ...] = ()

    def algorithm(self, rule_id: str) -> AlgorithmRule | None:
        return next((r for r in self.algorithms if r.id == rule_id), None)

    def pqc_target(self, target_id: str) -> PqcTarget | None:
        return next((t for t in self.pqc_targets if t.id == target_id), None)


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise PolicyError(f"Policy file not found: {path}")
    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path.name}: not valid YAML — {exc}") from exc
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        raise PolicyValidationError(f"{path.name}: expected a YAML mapping at the top level")
    return loaded


def _entry_label(raw: Any, index: int) -> str:
    if isinstance(raw, Mapping) and raw.get("id"):
        return f"'{raw['id']}'"
    return f"at index {index} (which also has no 'id')"


def _require_source(raw: Mapping[str, Any], filename: str, index: int) -> str:
    """The hard rule from §6: no citation, no entry."""
    source = raw.get("source")
    if not isinstance(source, str) or not source.strip():
        raise PolicyValidationError(
            f"{filename}: entry {_entry_label(raw, index)} has no 'source' citation. "
            "Every policy entry must cite a published standard "
            "(e.g. NIST SP 800-131A Rev.2); the loader refuses entries without one."
        )
    return source.strip()


def _require_id(raw: Mapping[str, Any], filename: str, index: int) -> str:
    entry_id = raw.get("id")
    if not isinstance(entry_id, str) or not entry_id.strip():
        raise PolicyValidationError(
            f"{filename}: entry at index {index} has no 'id'. Every policy entry needs "
            "a stable id — verdicts record it as 'rule_id' for traceability."
        )
    return entry_id.strip()


def _load_version(policy_dir: Path) -> PolicyVersion:
    raw = _read_yaml(policy_dir / VERSION_FILE)
    missing = [key for key in _REQUIRED_VERSION_KEYS if raw.get(key) is None]
    if missing:
        raise PolicyValidationError(
            f"{VERSION_FILE}: missing required key(s): {', '.join(missing)}"
        )
    published = raw["published"]
    if not isinstance(published, date):
        try:
            published = date.fromisoformat(str(published))
        except ValueError as exc:
            raise PolicyValidationError(
                f"{VERSION_FILE}: 'published' must be an ISO date (YYYY-MM-DD), "
                f"got {raw['published']!r}"
            ) from exc
    return PolicyVersion(
        version=str(raw["version"]),
        published=published,
        z_years_default=int(raw["z_years_default"]),
        y_years_default=int(raw["y_years_default"]),
        staleness_warning_days=int(raw["staleness_warning_days"]),
    )


def _load_algorithms(policy_dir: Path) -> tuple[AlgorithmRule, ...]:
    raw = _read_yaml(policy_dir / ALGORITHMS_FILE)
    entries = raw.get("entries") or []
    if not isinstance(entries, list):
        raise PolicyValidationError(f"{ALGORITHMS_FILE}: 'entries' must be a list")

    rules: list[AlgorithmRule] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise PolicyValidationError(
                f"{ALGORITHMS_FILE}: entry at index {index} is not a mapping"
            )
        # Citation first: an entry without one is rejected whatever else it says.
        source = _require_source(entry, ALGORITHMS_FILE, index)
        entry_id = _require_id(entry, ALGORITHMS_FILE, index)
        if entry_id in seen:
            raise PolicyValidationError(f"{ALGORITHMS_FILE}: duplicate entry id '{entry_id}'")
        seen.add(entry_id)

        verdict = entry.get("verdict")
        if not isinstance(verdict, str) or not verdict.strip():
            raise PolicyValidationError(
                f"{ALGORITHMS_FILE}: entry '{entry_id}' has no 'verdict'"
            )

        rules.append(
            AlgorithmRule(
                id=entry_id,
                verdict=verdict.strip(),
                source=source,
                family=_as_tuple(entry.get("family")),
                primitive=_as_tuple(entry.get("primitive")),
                oid=entry.get("oid"),
                condition=_freeze(entry.get("condition") or {}),
            )
        )
    return tuple(rules)


def _load_pqc_targets(
    policy_dir: Path,
) -> tuple[bool, tuple[PqcTarget, ...], tuple[PqcParameterSet, ...]]:
    raw = _read_yaml(policy_dir / PQC_TARGETS_FILE)
    prefer_hybrid = bool(raw.get("prefer_hybrid", False))
    entries = raw.get("targets") or []
    if not isinstance(entries, list):
        raise PolicyValidationError(f"{PQC_TARGETS_FILE}: 'targets' must be a list")

    targets: list[PqcTarget] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise PolicyValidationError(
                f"{PQC_TARGETS_FILE}: entry at index {index} is not a mapping"
            )
        source = _require_source(entry, PQC_TARGETS_FILE, index)
        entry_id = _require_id(entry, PQC_TARGETS_FILE, index)
        if entry_id in seen:
            raise PolicyValidationError(f"{PQC_TARGETS_FILE}: duplicate entry id '{entry_id}'")
        seen.add(entry_id)

        targets.append(
            PqcTarget(
                id=entry_id,
                source=source,
                match=_freeze(entry.get("match") or {}),
                target=entry.get("target"),
                hybrid=entry.get("hybrid"),
                requires=_freeze(entry.get("requires") or {}),
                action_class=entry.get("action_class"),
                side_effects=entry.get("side_effects"),
                note=entry.get("note"),
                compensating_control=entry.get("compensating_control"),
            )
        )
    return prefer_hybrid, tuple(targets), _load_parameter_sets(raw)


def _load_parameter_sets(raw: Mapping[str, Any]) -> tuple[PqcParameterSet, ...]:
    """The ``parameter_sets`` block. Optional, but cited like everything else."""
    entries = raw.get("parameter_sets") or []
    if not isinstance(entries, list):
        raise PolicyValidationError(f"{PQC_TARGETS_FILE}: 'parameter_sets' must be a list")

    sets: list[PqcParameterSet] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise PolicyValidationError(
                f"{PQC_TARGETS_FILE}: parameter_sets entry at index {index} is not a mapping"
            )
        source = _require_source(entry, PQC_TARGETS_FILE, index)
        entry_id = _require_id(entry, PQC_TARGETS_FILE, index)
        if entry_id in seen:
            raise PolicyValidationError(
                f"{PQC_TARGETS_FILE}: duplicate parameter_sets id '{entry_id}'"
            )
        seen.add(entry_id)
        replace = entry.get("replace") or {}
        if not isinstance(replace, Mapping):
            raise PolicyValidationError(
                f"{PQC_TARGETS_FILE}: parameter_sets entry '{entry_id}': 'replace' must be "
                "a mapping of target name to parameter set"
            )
        sets.append(
            PqcParameterSet(
                id=entry_id,
                source=source,
                match=_freeze(entry.get("match") or {}),
                replace=_freeze({str(k): str(v) for k, v in replace.items()}),
            )
        )
    return tuple(sets)


def _load_mapping_file(policy_dir: Path, filename: str, key: str) -> Mapping[str, Any]:
    raw = _read_yaml(policy_dir / filename)
    value = raw.get(key)
    if value is None:
        value = {}
    if not isinstance(value, Mapping):
        raise PolicyValidationError(f"{filename}: '{key}' must be a mapping")
    return _freeze(value)


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #


def load_policy(policy_dir: Path | str | None = None) -> PolicyPack:
    """Read and validate the whole pack. Raises :class:`PolicyError` on any problem."""
    directory = Path(policy_dir) if policy_dir is not None else get_settings().policy_dir
    directory = directory.resolve()
    if not directory.is_dir():
        raise PolicyError(f"Policy directory not found: {directory}")

    prefer_hybrid, pqc_targets, parameter_sets = _load_pqc_targets(directory)
    return PolicyPack(
        version=_load_version(directory),
        algorithms=_load_algorithms(directory),
        prefer_hybrid=prefer_hybrid,
        pqc_targets=pqc_targets,
        aliases=_load_mapping_file(directory, ALIASES_FILE, "aliases"),
        named_groups=_load_mapping_file(directory, NAMED_GROUPS_FILE, "groups"),
        policy_dir=directory,
        parameter_sets=parameter_sets,
    )


_CACHED_POLICY: PolicyPack | None = None


def get_policy() -> PolicyPack:
    """The process-wide pack, loaded on first use (i.e. at application startup)."""
    global _CACHED_POLICY
    if _CACHED_POLICY is None:
        _CACHED_POLICY = load_policy()
    return _CACHED_POLICY


def reset_policy_cache() -> None:
    """Drop the cached pack. For tests only — nothing in the app calls this."""
    global _CACHED_POLICY
    _CACHED_POLICY = None
