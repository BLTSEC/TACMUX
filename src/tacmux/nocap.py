"""Read-only NOCAP JSON adapter."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

from .config import Settings
from .errors import ExternalToolError, ValidationError


class NocapReader:
    def __init__(self, settings: Settings, binary: str = "cap"):
        self.settings = settings
        self.binary = binary

    def available(self) -> bool:
        return self.settings.nocap_enabled and shutil.which(self.binary) is not None

    def _run(self, args: list[str], target_relative: str) -> dict[str, Any]:
        if not self.settings.nocap_enabled:
            raise ExternalToolError("NOCAP integration is disabled in config")
        if not shutil.which(self.binary):
            raise ExternalToolError("NOCAP command 'cap' is not installed")
        env = os.environ.copy()
        env["NOCAP_WORKSPACE"] = str(self.settings.workspace)
        env["TACMUX_TARGET"] = target_relative
        result = subprocess.run(
            [self.binary, *args], text=True, capture_output=True, env=env, check=False
        )
        if result.returncode:
            raise ExternalToolError(
                (result.stderr or result.stdout or "NOCAP failed").strip()
            )
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ValidationError("NOCAP returned invalid JSON") from exc
        if not isinstance(value, dict) or "schema_version" not in value:
            raise ValidationError("NOCAP returned an unsupported JSON document")
        return value

    def timeline(self, target_relative: str) -> list[dict[str, Any]]:
        value = self._run(["timeline", "--format", "json"], target_relative)
        captures = value.get("captures")
        if not isinstance(captures, list):
            raise ValidationError("NOCAP timeline JSON has no captures list")
        return [item for item in captures if isinstance(item, dict)]
