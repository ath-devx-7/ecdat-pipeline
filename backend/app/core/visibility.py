"""Which verdicts are shown — one answer, used by every output.

Quantum-safe findings are recorded like any other: the policy engine needs them
to say that AES and SHA-256 are safe, and the readiness percentage needs them as
its numerator. But a report about what has to change is not improved by listing
what does not, so by default ``quantum_safe`` rows are kept in the store and left
out of the findings table, the roadmap, the CycloneDX export and the PDF.
``ECDAT_HIDE_QUANTUM_SAFE=false`` shows them again.

The filter lives here rather than in each consumer so the dashboard, the export
and the report cannot disagree about what a user is looking at.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.config import Settings, get_settings
from app.models.analysis import VerdictRow
from app.models.enums import Verdict

__all__ = ["hidden_verdicts", "is_visible", "visible_verdict_keys"]


def hidden_verdicts(settings: Settings | None = None) -> frozenset[Verdict]:
    settings = settings or get_settings()
    return frozenset({Verdict.QUANTUM_SAFE}) if settings.hide_quantum_safe else frozenset()


def is_visible(verdict: VerdictRow | Verdict | None, settings: Settings | None = None) -> bool:
    """A finding with no verdict yet is visible; a hidden verdict is not."""
    if verdict is None:
        return True
    value = verdict.verdict if isinstance(verdict, VerdictRow) else verdict
    return value not in hidden_verdicts(settings)


def visible_verdict_keys(settings: Settings | None = None) -> list[str]:
    """The verdict vocabulary a count table should carry, hidden ones removed."""
    hidden = hidden_verdicts(settings)
    return [verdict.value for verdict in Verdict if verdict not in hidden]


def visible_only(rows: Iterable, verdicts: dict, settings: Settings | None = None) -> list:
    """Filter findings by the verdict recorded for them (``verdicts`` keyed by finding id)."""
    hidden = hidden_verdicts(settings)
    if not hidden:
        return list(rows)
    kept = []
    for finding in rows:
        verdict = verdicts.get(finding.id)
        if verdict is not None and verdict.verdict in hidden:
            continue
        kept.append(finding)
    return kept
