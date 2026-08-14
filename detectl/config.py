"""Adapter configuration loading.

Config for each platform can come from a YAML file (default
`~/.detectl/config.yml`, overridable via `--config`) and/or environment
variables. YAML string values may reference an environment variable with
`${VAR_NAME}` so secrets never have to live in the file itself:

    splunk:
      base_url: https://splunk.example.com:8089
      token: ${SPLUNK_TOKEN}
      owner: nobody
      app: search

Any field not present in the YAML file falls back to a platform-prefixed
environment variable (e.g. `SPLUNK_BASE_URL`, `SPLUNK_TOKEN`). If a field is
still missing after both, load_config raises ConfigError naming exactly
what's missing.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .exceptions import ConfigError

DEFAULT_CONFIG_PATH = Path.home() / ".detectl" / "config.yml"

_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")

# field name -> required? for each platform. Optional fields have sane
# defaults applied by the adapter constructors themselves.
REQUIRED_FIELDS: Dict[str, List[str]] = {
    "splunk": ["base_url", "token"],
    "elastic": ["kibana_base_url", "api_key"],
    "sentinel": [
        "tenant_id",
        "client_id",
        "client_secret",
        "subscription_id",
        "resource_group",
        "workspace_name",
        "workspace_id",
    ],
    "crowdstrike": ["client_id", "client_secret"],
    "qradar": ["base_url", "token"],
    "sumologic": ["access_id", "access_key"],
    "chronicle": ["project", "location", "instance", "access_token"],
}

OPTIONAL_FIELDS: Dict[str, List[str]] = {
    "splunk": ["owner", "app", "verify_ssl"],
    "elastic": ["es_base_url", "verify_ssl"],
    "sentinel": ["base_url"],
    "crowdstrike": ["base_url", "logscale_url", "logscale_token", "logscale_repository"],
    "qradar": ["version", "verify_ssl"],
    "sumologic": ["base_url"],
}


def _substitute_env(value: Any) -> Any:
    if isinstance(value, str):
        def repl(match: "re.Match[str]") -> str:
            var_name = match.group(1)
            if var_name not in os.environ:
                raise ConfigError(f"config references undefined environment variable: {var_name}")
            return os.environ[var_name]

        return _ENV_VAR_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _substitute_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_env(v) for v in value]
    return value


def _load_yaml_section(platform: str, config_path: Optional[Path]) -> Dict[str, Any]:
    path = config_path or DEFAULT_CONFIG_PATH
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    section = data.get(platform, {}) or {}
    return _substitute_env(section)


def _env_prefix(platform: str) -> str:
    return platform.upper() + "_"


def load_config(platform: str, config_path: Optional[Path] = None) -> Dict[str, Any]:
    if platform not in REQUIRED_FIELDS:
        raise ConfigError(f"unknown platform: {platform}")

    values = _load_yaml_section(platform, config_path)
    prefix = _env_prefix(platform)

    all_fields = REQUIRED_FIELDS[platform] + OPTIONAL_FIELDS.get(platform, [])
    for field_name in all_fields:
        if field_name in values:
            continue
        env_name = prefix + field_name.upper()
        if env_name in os.environ:
            values[field_name] = os.environ[env_name]

    missing = [f for f in REQUIRED_FIELDS[platform] if f not in values or values[f] in (None, "")]
    if missing:
        raise ConfigError(
            f"missing required config for platform '{platform}': {', '.join(missing)} "
            f"(set via {config_path or DEFAULT_CONFIG_PATH}, or environment variables "
            f"{', '.join(prefix + m.upper() for m in missing)})"
        )

    # normalize a couple of common string->bool/int env-var footguns
    if "verify_ssl" in values and isinstance(values["verify_ssl"], str):
        values["verify_ssl"] = values["verify_ssl"].strip().lower() not in ("0", "false", "no")

    return values
