"""Sumo Logic adapter.

Maps detectl's canonical resources onto real Sumo Logic REST APIs, which
span two distinct API families under one base URL:

- Auth        -> HTTP Basic auth using an Access ID/Access Key pair (not a
                 bearer token) -- sent as a standard `Authorization: Basic
                 <base64(id:key)>` header.
- Rules       -> the Monitors Library (`/v1/monitors`), Sumo's saved-query
                 + trigger + notification alerting primitive. Monitors live
                 in a folder tree, so `create_rule` requires a destination
                 folder id via `rule.raw["parent_id"]` (same convention as
                 the CrowdStrike adapter requiring `rule.raw["rule_group_id"]`
                 for Custom IOA rules). Updates need the monitor's current
                 `version` for optimistic concurrency, so `update_rule` and
                 `set_rule_enabled` do a read-modify-write.
- Lists       -> Cloud SIEM Match Lists (`/sec/v1/match-lists` +
                 `/sec/v1/match-list-items`), Sumo's suppression/allow/
                 block-list primitive for Cloud SIEM. Match lists have a
                 required `targetColumn` (what kind of value the list holds
                 -- IP, Domain, FileHash, ...) instead of detectl's kind
                 vocabulary, so `kind` is stored as a `detectl_kind:{kind}`
                 tag in the list's `description` field (same convention the
                 QRadar adapter uses for Reference Sets). Removing items
                 needs match-list-item IDs, not raw values, so
                 `remove_list_items` reads the current items to resolve
                 value -> id first.
- Alerts      -> Cloud SIEM Insights. This is the least-verified corner of
                 this adapter -- Sumo's public Insights REST surface isn't
                 as clearly documented as Monitors/Match Lists, so the
                 `sec/v2/insights` paths here are a best-effort match to
                 the same response-enveloping convention Match Lists uses
                 (`{"data": {...}}` / `{"data": {"objects": [...]}}`).
                 Verify against your deployment's `/docs/sec/` page before
                 relying on this in production.
- run_query   -> the Search Job API (`/v1/search/jobs`): POST to start,
                 poll GET until the job reports "DONE GATHERING RESULTS",
                 then GET `/messages` for rows -- the same
                 create/poll/fetch shape as the CrowdStrike adapter's
                 Falcon LogScale queries and the QRadar adapter's Ariel
                 searches, reusing the same poll_interval/max_polls knobs.
"""
from __future__ import annotations

import base64
import time
from typing import Any, Dict, List, Optional

import requests

from ..exceptions import NotFoundError
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


class SumoLogicAdapter(SIEMAdapter):
    name = "sumologic"

    def __init__(
        self,
        access_id: str,
        access_key: str,
        base_url: str = "https://api.sumologic.com/api",
        poll_interval: float = 1.0,
        max_polls: int = 30,
        session: Optional[requests.Session] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.poll_interval = poll_interval
        self.max_polls = max_polls
        self.session = session or requests.Session()
        token = base64.b64encode(f"{access_id}:{access_key}".encode()).decode()
        self.session.headers.setdefault("Authorization", f"Basic {token}")
        self.session.headers.setdefault("Content-Type", "application/json")

    # -- connectivity --------------------------------------------------
    def test_connection(self) -> bool:
        self._request_json("GET", f"{self.base_url}/v1/collectors", params={"limit": 1})
        return True

    # -- rules (Monitors Library) -------------------------------------
    def _rule_from_monitor(self, entry: Dict[str, Any]) -> Rule:
        queries = entry.get("queries") or []
        return Rule(
            id=entry.get("id"),
            name=entry.get("name", ""),
            query=queries[0]["query"] if queries else "",
            description=entry.get("description", ""),
            severity="medium",
            enabled=not entry.get("isDisabled", False),
            tags=list((entry.get("tags") or {}).keys()),
            raw=entry,
        )

    def list_rules(self, **filters: Any) -> List[Rule]:
        # Best-effort: Monitors Library search endpoint; assumed response
        # shape `{"items": [...]}` (search-result summaries, not full
        # monitor objects -- use get_rule for the full definition).
        data = self._request_json(
            "GET", f"{self.base_url}/v1/monitors/search", params={"query": filters.get("query", "type:Monitor")}
        )
        return [self._rule_from_monitor(e) for e in data.get("items", [])]

    def get_rule(self, rule_id: str) -> Rule:
        entry = self._request_json("GET", f"{self.base_url}/v1/monitors/{rule_id}")
        return self._rule_from_monitor(entry)

    def create_rule(self, rule: Rule) -> Rule:
        parent_id = rule.raw.get("parent_id")
        if not parent_id:
            raise ValueError(
                "Sumo Logic create_rule requires rule.raw['parent_id'] -- Monitors Library "
                "monitors always live in a folder (there's no bare, folder-less monitor)."
            )
        body = {
            "type": "MonitorsLibraryMonitor",
            "name": rule.name,
            "description": rule.description,
            "monitorType": "Logs",
            "queries": [{"rowId": "A", "query": rule.query}],
            "triggers": [
                {
                    "triggerType": "Critical",
                    "threshold": 0,
                    "thresholdType": "GreaterThanOrEqual",
                    "timeRange": "-15m",
                    "occurrenceType": "ResultCount",
                    "triggerSource": "AllResults",
                    "detectionMethod": "StaticCondition",
                }
            ],
            "notifications": [],
            "isDisabled": not rule.enabled,
            "contentType": "Monitor",
            "status": [],
            "groupNotifications": False,
            "tags": {},
        }
        entry = self._request_json(
            "POST", f"{self.base_url}/v1/monitors", params={"parentId": parent_id}, json=body
        )
        return self._rule_from_monitor(entry)

    def _update_monitor(self, rule_id: str, **patch: Any) -> Dict[str, Any]:
        current = self._request_json("GET", f"{self.base_url}/v1/monitors/{rule_id}")
        current.update(patch)
        current["id"] = ""  # cleared in the body -- the id is already in the URL
        self._request("PUT", f"{self.base_url}/v1/monitors/{rule_id}", json=current)
        return self._request_json("GET", f"{self.base_url}/v1/monitors/{rule_id}")

    def update_rule(self, rule_id: str, rule: Rule) -> Rule:
        entry = self._update_monitor(
            rule_id,
            name=rule.name,
            description=rule.description,
            queries=[{"rowId": "A", "query": rule.query}],
            isDisabled=not rule.enabled,
        )
        return self._rule_from_monitor(entry)

    def delete_rule(self, rule_id: str) -> None:
        self._request("DELETE", f"{self.base_url}/v1/monitors/{rule_id}")

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> Rule:
        entry = self._update_monitor(rule_id, isDisabled=not enabled)
        return self._rule_from_monitor(entry)

    # -- lists (Cloud SIEM Match Lists) -------------------------------------
    def _list_from_entry(self, entry: Dict[str, Any], items: Optional[List[str]] = None) -> ListObject:
        return ListObject(
            id=entry.get("id"),
            name=entry.get("name", ""),
            kind=_kind_from_description(entry.get("description", "")),
            description=entry.get("description", ""),
            items=items or [],
            raw=entry,
        )

    def _fetch_match_list_items(self, list_id: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        next_page_token = ""
        for _ in range(1000):  # hard safety cap against a runaway pagination loop
            params = {"listIds": list_id}
            if next_page_token:
                params["nextPageToken"] = next_page_token
            data = self._request_json(
                "GET", f"{self.base_url}/sec/v1/match-list-items/all", params=params
            ).get("data", {})
            items.extend(data.get("objects", []))
            next_page_token = data.get("nextPageToken", "")
            if not next_page_token:
                break
        return items

    def list_lists(self, kind: Optional[str] = None) -> List[ListObject]:
        data = self._request_json("GET", f"{self.base_url}/sec/v1/match-lists")
        results = [self._list_from_entry(e) for e in data.get("data", {}).get("objects", [])]
        if kind:
            results = [r for r in results if r.kind == kind]
        return results

    def get_list(self, list_id: str) -> ListObject:
        entry = self._request_json("GET", f"{self.base_url}/sec/v1/match-lists/{list_id}").get("data", {})
        items = [i["value"] for i in self._fetch_match_list_items(list_id)]
        return self._list_from_entry(entry, items)

    def create_list(self, list_obj: ListObject) -> ListObject:
        body = {
            "fields": {
                "name": list_obj.name,
                "description": _description_for(list_obj.kind, list_obj.description),
                "targetColumn": list_obj.raw.get("target_column", "Other"),
                "active": True,
                "defaultTtl": list_obj.raw.get("default_ttl", 86400),
            }
        }
        entry = self._request_json("POST", f"{self.base_url}/sec/v1/match-lists", json=body).get("data", {})
        if list_obj.items:
            self.add_list_items(entry["id"], list_obj.items)
        return self.get_list(entry["id"])

    def update_list(self, list_id: str, list_obj: ListObject) -> ListObject:
        # Sumo's match-lists API only allows active/defaultTtl/description to
        # change after creation -- name and targetColumn are immutable.
        self._request(
            "PUT",
            f"{self.base_url}/sec/v1/match-lists/{list_id}",
            json={
                "fields": {
                    "active": True,
                    "defaultTtl": list_obj.raw.get("default_ttl", 86400),
                    "description": _description_for(list_obj.kind, list_obj.description),
                }
            },
        )
        existing_items = [i["value"] for i in self._fetch_match_list_items(list_id)]
        if existing_items:
            self.remove_list_items(list_id, existing_items)
        if list_obj.items:
            self.add_list_items(list_id, list_obj.items)
        return self.get_list(list_id)

    def delete_list(self, list_id: str) -> None:
        self._request("DELETE", f"{self.base_url}/sec/v1/match-lists/{list_id}")

    def add_list_items(self, list_id: str, items: List[str]) -> ListObject:
        self._request(
            "POST",
            f"{self.base_url}/sec/v1/match-lists/{list_id}/items",
            json={"items": [{"value": value} for value in items]},
        )
        return self.get_list(list_id)

    def remove_list_items(self, list_id: str, items: List[str]) -> ListObject:
        to_remove = set(items)
        matching_ids = [i["id"] for i in self._fetch_match_list_items(list_id) if i.get("value") in to_remove]
        if matching_ids:
            self._request(
                "POST",
                f"{self.base_url}/sec/v1/match-list-items/bulk-delete",
                json={"ids": matching_ids},
            )
        return self.get_list(list_id)

    # -- alerts (Cloud SIEM Insights -- best-effort, see module docstring) --
    def _alert_from_entry(self, entry: Dict[str, Any]) -> Alert:
        return Alert(
            id=entry.get("id", ""),
            title=entry.get("name", entry.get("readableId", "")),
            severity=str(entry.get("severity", "unknown")),
            status=entry.get("status", "new"),
            rule_id=entry.get("ruleId"),
            timestamp=entry.get("firstSeen"),
            raw=entry,
        )

    def list_alerts(self, **filters: Any) -> List[Alert]:
        data = self._request_json(
            "GET", f"{self.base_url}/sec/v2/insights", params={"limit": filters.get("limit", 100)}
        )
        return [self._alert_from_entry(e) for e in data.get("data", {}).get("objects", [])]

    def get_alert(self, alert_id: str) -> Alert:
        entry = self._request_json("GET", f"{self.base_url}/sec/v2/insights/{alert_id}").get("data", {})
        if not entry:
            raise NotFoundError(f"insight not found: {alert_id}")
        return self._alert_from_entry(entry)

    def set_alert_status(self, alert_id: str, status: str) -> Alert:
        self._request(
            "PUT", f"{self.base_url}/sec/v2/insights/{alert_id}/status", json={"status": status}
        )
        return self.get_alert(alert_id)

    # -- events / raw queries (Search Job API) -----------------------------
    def run_query(
        self, query: str, start: Optional[str] = None, end: Optional[str] = None, limit: int = 100, **kwargs: Any
    ) -> QueryResult:
        body = {"query": query, "from": start or "-1h", "to": end or "now", "timeZone": "UTC"}
        created = self._request_json("POST", f"{self.base_url}/v1/search/jobs", json=body)
        job_id = created["id"]
        status_url = f"{self.base_url}/v1/search/jobs/{job_id}"

        status = self._request_json("GET", status_url)
        polls = 0
        while status.get("state") != "DONE GATHERING RESULTS" and polls < self.max_polls:
            if self.poll_interval > 0:
                time.sleep(self.poll_interval)
            polls += 1
            status = self._request_json("GET", status_url)

        results = self._request_json("GET", f"{status_url}/messages", params={"limit": limit, "offset": 0})
        rows = [m["map"] for m in results.get("messages", [])]
        columns = sorted({key for row in rows for key in row.keys()})
        return QueryResult(columns=columns, rows=rows, raw=results)
