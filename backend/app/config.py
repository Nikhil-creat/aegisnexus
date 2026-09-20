"""Runtime configuration, read from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

_DEFAULT_CORS = (
    r"https?://(localhost|127\.0\.0\.1)(:\d+)?"
    r"|https://[a-z0-9-]+\.github\.io"
)


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


@dataclass(frozen=True)
class Settings:
    anthropic_api_key: str = field(default_factory=lambda: _env("ANTHROPIC_API_KEY"))
    llm_model: str = field(default_factory=lambda: _env("LLM_MODEL", "claude-sonnet-5"))
    model_dir: Path = field(default_factory=lambda: Path(_env("MODEL_DIR", "models")))
    db_path: str = field(default_factory=lambda: _env("DB_PATH", "data/aegis.db"))
    auth_required: bool = field(default_factory=lambda: _env("AUTH_REQUIRED", "true").lower() != "false")
    admin_user: str = field(default_factory=lambda: _env("ADMIN_USER", "admin"))
    admin_password: str = field(default_factory=lambda: _env("ADMIN_PASSWORD"))
    rate_limit_per_min: int = field(default_factory=lambda: int(_env("RATE_LIMIT_PER_MIN", "240")))
    trust_proxy: bool = field(default_factory=lambda: _env("TRUST_PROXY", "false").lower() == "true")
    token_ttl: int = field(default_factory=lambda: int(_env("TOKEN_TTL_SECONDS", "3600")))
    cors_origin_regex: str = field(default_factory=lambda: _env("CORS_ORIGIN_REGEX", _DEFAULT_CORS))
    max_upload_bytes: int = field(default_factory=lambda: int(_env("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024))))
    max_agent_steps: int = field(default_factory=lambda: int(_env("MAX_AGENT_STEPS", "10")))


def get_settings() -> Settings:
    return Settings()
