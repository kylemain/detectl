"""Canonical, platform-agnostic data models.

Every adapter converts to/from these dataclasses at its own API boundary, so
callers (the CLI, or any other Python code) work with one consistent shape
regardless of which SIEM they're actually talking to. Each model carries a
`raw` field holding the untouched, platform-native payload for anything
callers need that isn't captured by the common fields.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

ListKind = str  # "watchlist" | "exclusion" | "allowlist" | "blocklist" | "suppression" | "kv_store"


@dataclass
class Rule:
    id: Optional[str]
    name: str
    query: str
    description: str = ""
    severity: str = "medium"
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ListObject:
    id: Optional[str]
    name: str
    kind: ListKind
    description: str = ""
    items: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    id: str
    title: str
    severity: str
    status: str
    rule_id: Optional[str] = None
    timestamp: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QueryResult:
    columns: List[str]
    rows: List[Dict[str, Any]]
    raw: Dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.rows)
