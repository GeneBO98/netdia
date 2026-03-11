from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _truthy(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class OPNsenseConfig:
    url: str = ""
    key: str = ""
    secret: str = ""
    verify_ssl: bool = True

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.key and self.secret)


@dataclass(slots=True)
class Settings:
    data_dir: Path
    db_path: Path
    opnsense: OPNsenseConfig


def load_settings() -> Settings:
    data_dir = Path(os.environ.get("NETDIA_DATA_DIR", ".netdia")).expanduser().resolve()
    db_path = Path(os.environ.get("NETDIA_DB_PATH", data_dir / "netdia.db")).expanduser().resolve()
    return Settings(
        data_dir=data_dir,
        db_path=db_path,
        opnsense=OPNsenseConfig(
            url=os.environ.get("NETDIA_OPNSENSE_URL", "").rstrip("/"),
            key=os.environ.get("NETDIA_OPNSENSE_KEY", ""),
            secret=os.environ.get("NETDIA_OPNSENSE_SECRET", ""),
            verify_ssl=_truthy(os.environ.get("NETDIA_OPNSENSE_VERIFY_SSL"), True),
        ),
    )
