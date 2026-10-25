"""Loads a project-root .env into os.environ, if present. No external deps."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

_loaded = False


def load_env(env_path: Optional[str | Path] = None, force_reload: bool = False) -> None:
    global _loaded
    if _loaded and not force_reload and env_path is None:
        return
    _loaded = True

    target_file = (
        Path(env_path)
        if env_path
        else Path(__file__).resolve().parent.parent / ".env"
    )

    if not target_file.exists():
        return

    for line in target_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        # Strip matching surrounding single or double quotes
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        os.environ.setdefault(key, value)
