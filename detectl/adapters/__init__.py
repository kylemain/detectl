"""Adapter registry and factory."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..config import load_config
from .base import SIEMAdapter
from .crowdstrike import CrowdStrikeAdapter
from .elastic import ElasticAdapter
from .sentinel import SentinelAdapter
from .splunk import SplunkAdapter

REGISTRY = {
    "splunk": SplunkAdapter,
    "elastic": ElasticAdapter,
    "sentinel": SentinelAdapter,
    "crowdstrike": CrowdStrikeAdapter,
}


def get_adapter(platform: str, config_path: Optional[Path] = None) -> SIEMAdapter:
    if platform not in REGISTRY:
        raise ValueError(f"unknown platform: {platform!r} (choices: {', '.join(sorted(REGISTRY))})")
    kwargs = load_config(platform, config_path)
    return REGISTRY[platform](**kwargs)
