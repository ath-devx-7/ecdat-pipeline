"""Collectors — SPEC.md §7.

Six in the finished system. Two here, in build order: certificates and configs
first because they are the simplest and produce immediately visible output. The
network probe (§7.5) arrives in step 7, code and binary (§7.1, §7.2) in step 11,
CBOM import (§7.6) in step 12. The registry they plug into is in ``app/runner.py``.
"""

from app.collectors.base import Collector, CollectorTimeout, RawFinding, ScanContext
from app.collectors.certs import CertificateCollector
from app.collectors.config import ConfigCollector

__all__ = [
    "CertificateCollector",
    "Collector",
    "CollectorTimeout",
    "ConfigCollector",
    "RawFinding",
    "ScanContext",
]
