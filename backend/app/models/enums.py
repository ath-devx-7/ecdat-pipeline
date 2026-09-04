"""Enum values from SPEC.md §5. Downstream steps depend on these exact strings."""

from __future__ import annotations

import enum


class ScanMode(str, enum.Enum):
    PROBE_ONLY = "probe_only"
    FILES = "files"
    FILES_AND_PROBE = "files_and_probe"


class SourceType(str, enum.Enum):
    """Where a scan's files came from.

    ``FOLDER`` and ``UPLOAD`` both end in a directory on this host, and differ in
    who put it there: a folder is read in place at a path the user typed, an
    upload is a tree the browser copied in and that we therefore own and may
    delete. Downstream of staging the two are indistinguishable.
    """

    FOLDER = "folder"
    GITHUB = "github"
    DOCKER_IMAGE = "docker_image"
    UPLOAD = "upload"
    NONE = "none"


class ScanStatus(str, enum.Enum):
    STAGING = "staging"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"


class CollectorName(str, enum.Enum):
    CODE = "code"
    BINARY = "binary"
    CERTS = "certs"
    CONFIG = "config"
    NETWORK = "network"
    CBOM_IMPORT = "cbom_import"


class Primitive(str, enum.Enum):
    KEY_EXCHANGE = "key_exchange"
    SIGNATURE = "signature"
    HASH = "hash"
    CIPHER = "cipher"
    PROTOCOL = "protocol"
    UNKNOWN = "unknown"


class Confidence(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SourceLayer(str, enum.Enum):
    """Ordered by closeness to execution — this is the precedence rule (§8)."""

    LIVE = "live"
    ARTIFACT = "artifact"
    CONFIG = "config"
    SOURCE = "source"


class Verdict(str, enum.Enum):
    """broken_now and quantum_vulnerable are independent, not one scale (§10)."""

    BROKEN_NOW = "broken_now"
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    QUANTUM_SAFE = "quantum_safe"
    HYGIENE = "hygiene"
    UNKNOWN = "unknown"


class RecommendationStatus(str, enum.Enum):
    RECOMMENDED = "recommended"
    BLOCKED = "blocked"
    NO_PATH = "no_path"
    UNKNOWN = "unknown"


class ActionClass(str, enum.Enum):
    """Ordered cheapest-first — the advisor's third tie-break (§11)."""

    CONFIG = "config"
    LIBRARY_UPGRADE = "library_upgrade"
    CODE_CHANGE = "code_change"
    HARDWARE = "hardware"


class Wave(str, enum.Enum):
    WAVE_0 = "wave_0"
    WAVE_1 = "wave_1"
    WAVE_2 = "wave_2"
    WAVE_3 = "wave_3"
    VERIFY = "verify"
