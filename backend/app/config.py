"""Runtime settings. Environment-driven, prefix ``ECDAT_``."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ECDAT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "postgresql+psycopg://ecdat:ecdat@localhost:5432/ecdat"

    # Policy pack location. Read-only at runtime — nothing writes back here.
    policy_dir: Path = BACKEND_ROOT / "policy"

    # Synchronous-scan guards from SPEC.md §2.
    max_files_per_scan: int = 5000
    collector_timeout_seconds: int = 120
    scan_timeout_seconds: int = 600
    max_probe_targets: int = 20
    #: Per-target network timeout handed to sslyze (§7.5). Separate from the
    #: per-collector budget: one unreachable host must not spend the whole of it.
    probe_timeout_seconds: int = 10

    # Where staged sources land. `folder` sources are read in place and never copied.
    work_root: Path = Path("/tmp/ecdat")

    # Staging subprocess budgets. Cloning and `docker save` are the only two
    # outbound operations in the product, and both are user-initiated (§1).
    git_clone_timeout_seconds: int = 300
    docker_save_timeout_seconds: int = 600

    #: Directory names pruned during the surface scan. `.git` holds packed
    #: objects that are not deployed artefacts and would consume the file cap
    #: before a single source file were offered for approval.
    surface_exclude_dirs: tuple[str, ...] = (".git",)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
