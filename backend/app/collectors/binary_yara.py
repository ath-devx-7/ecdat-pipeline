"""YARA binary collector — a stub, on purpose (SPEC.md §7.2).

YARA is out of scope for the prototype. This module exists so the plugin
interface visibly supports a second binary collector: the class implements
:class:`Collector`, carries the ``binary`` name, and returns nothing. It is not
registered in ``app/runner.py`` — a collector that always finds nothing would
show up in every scan's collector list as a run that produced zero findings,
which reads as "checked and clean" rather than "not implemented".

Filling it in means: load a rule set from ``backend/yara_rules/``, match each
approved ELF, and map each rule hit to a :class:`RawFinding` with
``source_layer: artifact`` and a confidence set by the rule's own metadata —
a rule matching a constant table is proof of capability, a rule matching a
string is a hint, and §7.2 already draws that line.
"""

from __future__ import annotations

from typing import ClassVar

from app.collectors.base import Collector, RawFinding, ScanContext
from app.models.enums import CollectorName

__all__ = ["YaraBinaryCollector"]


class YaraBinaryCollector(Collector):
    """Implements the interface; observes nothing yet."""

    name: ClassVar[CollectorName] = CollectorName.BINARY

    def collect(self, ctx: ScanContext) -> list[RawFinding]:
        return []
