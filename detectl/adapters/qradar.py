"""IBM QRadar adapter.

Maps detectl's canonical resources onto QRadar's real REST API, which has
its own conventions worth calling out:

- Auth        -> an Authorized Service Token in the `SEC` header (not
                 `Authorization: Bearer`), plus a required `Version` header
                 pinning the API version -- omitting it silently falls back
                 to whatever QRadar's default is.
- Rules       -> the Custom Rules Engine (CRE). `/analytics/rules` only
                 exposes existing rule *metadata* (name, enabled, owner,
                 ...) -- rule *logic* is authored through the in-product
                 Rule Wizard and isn't creatable or generally editable via
                 this API. So `create_rule`/`update_rule` raise
                 UnsupportedOperationError; `set_rule_enabled` (a real,
                 documented toggle) and `delete_rule` work normally.
- Lists       -> Reference Data Sets (`/reference_data/sets`), QRadar's
                 lookup-list primitive. No native "kind" concept, so (same
                 convention as the Elastic adapter's `meta.detectl_kind`)
                 kind is stored as a `detectl_kind:{kind}` tag in the set's
                 `description` field. Items are added/removed one at a time
                 -- QRadar's bulk-load endpoint needs a namespace/domain_id
                 this adapter doesn't otherwise track, so it isn't used.
- Alerts      -> Offenses (`/siem/offenses`).
- run_query   -> the Ariel Query Language (AQL) search API. Ariel searches
                 are asynchronous: POST to start, poll GET until COMPLETED,
                 then GET the results -- same shape as the CrowdStrike
                 adapter's Falcon LogScale polling, reusing the same
                 poll_interval/max_polls knobs.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests

from ..exceptions import UnsupportedOperationError
from ..models import Alert, ListObject, QueryResult, Rule
from .base import SIEMAdapter

_KIND_TAG_PREFIX = "detectl_kind:"


def _kind_from_description(description: str) -> str:
    for part in (description or "").split():
        if part.startswith(_KIND_TAG_PREFIX):
            return part[len(_KIND_TAG_PREFIX):]
    return "watchlist"


def _description_for(kind: str, description: str = "") -> str:
    tag = f"{_KIND_TAG_PREFIX}{kind}"
    return f"{description} {tag}".strip() if description else tag


class QRadarAdapter(SIEMAdapter):
    name = "qradar"

    def __init__(
        self,
        base_url: str,
        token: str,
        version: str = "21.0",
        verify_ssl: bool = True,
        poll_interval: float = 1.0,
        max_polls: int = 30,
        session: Optional[requests.Session] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.poll_interval = poll_interval
        self.max_polls = max_polls
        self.session = session or requests.Session()
        self.session.headers.setdefault("SEC", token)
        self.session.headers.setdefault("Version", version)
        self.session.headers.setdefault("Accept", "application/json")
        self.session.verify = verify_ssl

    # -- connectivity --------------------------------------------------
    def test_connection(self) -> bool:
        self._request_json("GET", f"{self.base_url}/api/system/about")
        return True

    # -- rules (Custom Rules Engine metadata only) -------------------------
    def _rule_from_entry(self, entry: Dict[str, Any]) -> Rule:
        return Rule(
            id=str(entry.get("id")),
            name=entry.get("name", ""),
            query="",
            description="QRadar CRE rule logic isn't exposed as text via this API",
            severity="medium",
            enabled=entry.get("enabled", True),
            tags=[entry.get("type", "")] if entry.get("type") else [],
            raw=entry,
        )

    def list_rules(self, **filters: Any) -> List[Rule]:
        data = self._request_json("GET", f"{self.base_url}/api/analytics/rules")
        return [self._rule_from_entry(e) for e in data]

    def get_rule(self, rule_id: str) -> Rule:
        entry = self._request_json("GET", f"{self.base_url}/api/analytics/rules/{rule_id}")
        return self._rule_from_entry(entry)

    def create_rule(self, rule: Rule) -> Rule:
        raise UnsupportedOperationError(
            "QRadar's Custom Rules Engine has no API for creating new rule logic -- rules are "
            "authored through the in-product Rule Wizard. /analytics/rules only manages "
            "metadata (enable/disable, delete) for rules that already exist."
        )

    def update_rule(self, rule_id: str, rule: Rule) -> Rule:
        raise UnsupportedOperationError(
            "QRadar's Custom Rules Engine has no API for editing rule logic (name/query/"
            "severity) -- only enabling/disabling an existing rule is supported. Use "
            "enable_rule/disable_rule instead."
        )

    def delete_rule(self, rule_id: str) -> None:
        self._request("DELETE", f"{self.base_url}/api/analytics/rules/{rule_id}")

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> Rule:
        entry = self._request_json(
            "POST", f"{self.base_url}/api/analytics/rules/{rule_id}", json={"enabled": enabled}
        )
        return self._rule_from_entry(entry)

    # -- lists (Reference Data Sets) ---------------------------------------
    def _list_from_entry(self, entry: Dict[str, Any]) -> ListObject:
        return ListObject(
            id=entry.get("name"),
            name=entry.get("name", ""),
            kind=_kind_from_description(entry.get("description", "")),
            description=entry.get("description", ""),
            items=[str(d.get("value")) for d in entry.get("data", [])],
            raw=entry,
        )

    def list_lists(self, kind: Optional[str] = None) -> List[ListObject]:
        data = self._request_json("GET", f"{self.base_url}/api/reference_data/sets")
        results = [self._list_from_entry(e) for e in data]
        if kind:
            results = [r for r in results if r.kind == kind]
        return results

    def get_list(self, list_id: str) -> ListObject:
        entry = self._request_json("GET", f"{self.base_url}/api/reference_data/sets/{list_id}")
        return self._list_from_entry(entry)

    def create_list(self, list_obj: ListObject) -> ListObject:
        self._request(
            "POST",
            f"{self.base_url}/api/reference_data/sets",
            params={
                "name": list_obj.name,
                "element_type": "ALN",
                "timeout_type": "UNKNOWN",
                "description": _description_for(list_obj.kind, list_obj.description),
            },
        )
        if list_obj.items:
            self.add_list_items(list_obj.name, list_obj.items)
        return self.get_list(list_obj.name)

    def update_list(self, list_id: str, list_obj: ListObject) -> ListObject:
        existing = self.get_list(list_id)
        if existing.items:
            self.remove_list_items(list_id, existing.items)
        if list_obj.items:
            self.add_list_items(list_id, list_obj.items)
        return self.get_list(list_id)

    def delete_list(self, list_id: str) -> None:
        self._request("DELETE", f"{self.base_url}/api/reference_data/sets/{list_id}")

    def add_list_items(self, list_id: str, items: List[str]) -> ListObject:
        for value in items:
            self._request(
                "POST", f"{self.base_url}/api/reference_data/sets/{list_id}", params={"value": value}
            )
        return self.get_list(list_id)

    def remove_list_items(self, list_id: str, items: List[str]) -> ListObject:
        for value in items:
            self._request("DELETE", f"{self.base_url}/api/reference_data/sets/{list_id}/{value}")
        return self.get_list(list_id)

    # -- alerts (offenses) ---------------------------------------------
    def _alert_from_entry(self, entry: Dict[str, Any]) -> Alert:
        rule_ids = [str(r.get("id")) for r in entry.get("rules", []) if r.get("id") is not None]
        return Alert(
            id=str(entry.get("id")),
            title=entry.get("description", ""),
            severity=str(entry.get("severity", entry.get("magnitude", "unknown"))),
            status=entry.get("status", "OPEN"),
            rule_id=rule_ids[0] if rule_ids else None,
            timestamp=str(entry.get("start_time")) if entry.get("start_time") is not None else None,
            raw=entry,
        )

    def list_alerts(self, **filters: Any) -> List[Alert]:
        data = self._request_json(
            "GET", f"{self.base_url}/api/siem/offenses", params={"Range": f"items=0-{filters.get('limit', 100) - 1}"}
        )
        return [self._alert_from_entry(e) for e in data]

    def get_alert(self, alert_id: str) -> Alert:
        entry = self._request_json("GET", f"{self.base_url}/api/siem/offenses/{alert_id}")
        return self._alert_from_entry(entry)

    def set_alert_status(self, alert_id: str, status: str) -> Alert:
        entry = self._request_json(
            "POST", f"{self.base_url}/api/siem/offenses/{alert_id}", params={"status": status}
        )
        return self._alert_from_entry(entry)

    # -- events / raw queries (Ariel Query Language) -----------------------
    def run_query(self, query: str, limit: int = 100, **kwargs: Any) -> QueryResult:
        created = self._request_json(
            "POST", f"{self.base_url}/api/ariel/searches", params={"query_expression": query}
        )
        search_id = created["search_id"]
        status_url = f"{self.base_url}/api/ariel/searches/{search_id}"

        status = self._request_json("GET", status_url)
        polls = 0
        while status.get("status") != "COMPLETED" and polls < self.max_polls:
            if self.poll_interval > 0:
                time.sleep(self.poll_interval)
            polls += 1
            status = self._request_json("GET", status_url)

        results = self._request_json("GET", f"{status_url}/results")
        events = results.get("events", [])[:limit]
        columns = sorted({key for event in events for key in event.keys()})
        return QueryResult(columns=columns, rows=events, raw=results)
