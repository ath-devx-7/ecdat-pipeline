"""SQLAlchemy models. Importing this package registers all eight tables on ``Base``."""

from app.models.analysis import Recommendation, RiskScore, VerdictRow
from app.models.base import Base
from app.models.enums import (
    ActionClass,
    CollectorName,
    Confidence,
    Primitive,
    RecommendationStatus,
    ScanMode,
    ScanStatus,
    SourceLayer,
    SourceType,
    Verdict,
    Wave,
)
from app.models.finding import AlignmentNote, Finding, ProvenanceBlob
from app.models.scan import Scan, ScanFile

__all__ = [
    "ActionClass",
    "AlignmentNote",
    "Base",
    "CollectorName",
    "Confidence",
    "Finding",
    "Primitive",
    "ProvenanceBlob",
    "Recommendation",
    "RecommendationStatus",
    "RiskScore",
    "Scan",
    "ScanFile",
    "ScanMode",
    "ScanStatus",
    "SourceLayer",
    "SourceType",
    "Verdict",
    "VerdictRow",
    "Wave",
]
