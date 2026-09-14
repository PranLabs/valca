from __future__ import annotations
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ValcaConfig:
    disabled_rules: list[str] = field(default_factory=list)
    min_severity: str | None = None
    exclude_paths: list[str] = field(default_factory=list)
    telemetry: bool = True


#: Config filenames, in precedence order within a single directory.
#: `.vigilrc` is the pre-rename name and is read indefinitely — existing
#: projects must not break on an upgrade.
CONFIG_NAMES = (".valcarc", ".vigilrc")


def load_config(start: Path) -> ValcaConfig:
    """Walk up from start looking for a config file (TOML format).

    Searches the given path (or its parent if a file) and all ancestor
    directories until the filesystem root. Within one directory `.valcarc`
    wins over `.vigilrc`. Returns defaults if neither is found.
    """
    current = start if start.is_dir() else start.parent
    while True:
        candidate = next((current / n for n in CONFIG_NAMES if (current / n).is_file()), None)
        if candidate is not None:
            try:
                with open(candidate, "rb") as f:
                    data = tomllib.load(f)
            except Exception:
                return ValcaConfig()
            return ValcaConfig(
                disabled_rules=data.get("disabled_rules", []),
                min_severity=data.get("min_severity"),
                exclude_paths=data.get("exclude_paths", []),
                telemetry=data.get("telemetry", True),
            )
        parent = current.parent
        if parent == current:
            break
        current = parent
    return ValcaConfig()
