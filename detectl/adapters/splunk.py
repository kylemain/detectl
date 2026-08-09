"""Splunk adapter.

Maps detectl's canonical resources onto real Splunk REST API endpoints:

- Rules       -> Saved Searches / correlation searches
                 (servicesNS/{owner}/{app}/saved/searches)
- Lists       -> KV Store collections
                 (servicesNS/{owner}/{app}/storage/collections/{config,data})
- Alerts      -> Fired alerts
                 (servicesNS/{owner}/{app}/alerts/fired_alerts)
- run_query   -> a blocking search job (search/jobs, exec_mode=blocking)
                 followed by a results fetch -- the standard pattern for
                 synchronous, script-driven Splunk searches.

Every request goes through HttpMixin._request[_json], which centralizes
auth/HTTP error translation. All endpoints are called with output_mode=json.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests

from ..exceptions import NotFoundError, UnsupportedOperationError
from ..models import Alert, ListObject, QueryResult, Rule
from .base import SIEMAdapter


class SplunkAdapter(SIEMAdapter):
    name = "splunk"

    def __init__(
        self,
        base_url: str,
        token: str,
        owner: str = "nobody",
        app: str = "search",
        verify_ssl: bool = True,
        session: Optional[requests.Session] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.owner = owner
        self.app = app
        self.session = session or requests.Session()
        self.session.headers.setdefault("Authorization", f"Splunk {token}")
        self.session.verify = verify_ssl

    # -- helpers -----------------------------------------------------
    @property
    def _ns(self) -> str:
        return f"{self.base_url}/servicesNS/{self.owner}/{self.app}"

    @staticmethod
    def _normalize_search(query: str) -> str:
        q = query.strip()
        if q.startswith("search ") or q.startswith("|") or q.startswith("search\n"):
            return q
        return f"search {q}"

    def _rule_from_entry(self, entry: Dict[str, Any]) -> Rule:
        content = entry.get("content", {})
        return Rule(
            id=entry["name"],
            name=entry["name"],
            query=content.get("search", ""),
            description=content.get("description", "") or "",
            severity=content.get("alert_severity", "medium"),
            enabled=not bool(int(content.get("disabled", 0))),
            tags=[],
            raw=entry,
        )

    # -- connectivity --------------------------------------------------
    def test_connection(self) -> bool:
        self._request_json("GET", f"{self.base_url}/services/server/info", params={"output_mode": "json"})
        return True

    # -- rules -----------------------------------------------------------
    def list_rules(self, **filters: Any) -> List[Rule]:
        data = self._request_json(
            "GET", f"{self._ns}/saved/searches", params={"output_mode": "json", "count": 0}
        )
        return [self._rule_from_entry(e) for e in data.get("entry", [])]

    def get_rule(self, rule_id: str) -> Rule:
        data = self._request_json(
            "GET", f"{self._ns}/saved/searches/{rule_id}", params={"output_mode": "json"}
        )
        return self._rule_from_entry(data["entry"][0])

    def create_rule(self, rule: Rule) -> Rule:
        payload = {
            "name": rule.name,
            "search": rule.query,
            "description": rule.description,
            "disabled": 0 if rule.enabled else 1,
        }
        self._request("POST", f"{self._ns}/saved/searches", data=payload, params={"output_mode": "json"})
        return self.get_rule(rule.name)

    def update_rule(self, rule_id: str, rule: Rule) -> Rule:
        payload = {
            "search": rule.query,
            "description": rule.description,
            "disabled": 0 if rule.enabled else 1,
        }
        self._request(
            "POST", f"{self._ns}/saved/searches/{rule_id}", data=payload, params={"output_mode": "json"}
        )
        return self.get_rule(rule_id)

    def delete_rule(self, rule_id: str) -> None:
        self._request("DELETE", f"{self._ns}/saved/searches/{rule_id}", params={"output_mode": "json"})

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> Rule:
        action = "enable" if enabled else "disable"
        self._request(
            "POST", f"{self._ns}/saved/searches/{rule_id}/{action}", params={"output_mode": "json"}
        )
        return self.get_rule(rule_id)

    # -- lists (KV Store collections) -------------------------------------
    def list_lists(self, kind: Optional[str] = None) -> List[ListObject]:
        if kind not in (None, "kv_store"):
            return []
        data = self._request_json(
            "GET",
            f"{self._ns}/storage/collections/config",
            params={"output_mode": "json", "count": 0},
        )
        return [
            ListObject(id=e["name"], name=e["name"], kind="kv_store", items=[], raw=e)
            for e in data.get("entry", [])
        ]

    def get_list(self, list_id: str) -> ListObject:
        cfg = self._request_json(
            "GET", f"{self._ns}/storage/collections/config/{list_id}", params={"output_mode": "json"}
        )
        records = self._request_json(
            "GET", f"{self._ns}/storage/collections/data/{list_id}", params={"output_mode": "json"}
        )
        items = [str(r.get("value", r)) for r in (records or [])]
        return ListObject(id=list_id, name=list_id, kind="kv_store", items=items, raw=cfg["entry"][0])

    def create_list(self, list_obj: ListObject) -> ListObject:
        self._request(
            "POST",
            f"{self._ns}/storage/collections/config",
            data={"name": list_obj.name},
            params={"output_mode": "json"},
        )
        if list_obj.items:
            self.add_list_items(list_obj.name, list_obj.items)
        return self.get_list(list_obj.name)

    def update_list(self, list_id: str, list_obj: ListObject) -> ListObject:
        # KV Store collections have no "rename"/"replace description" concept
        # via this API -- update semantics here mean "replace the item set".
        self._request(
            "DELETE", f"{self._ns}/storage/collections/data/{list_id}", params={"output_mode": "json"}
        )
        if list_obj.items:
            self.add_list_items(list_id, list_obj.items)
        return self.get_list(list_id)

    def delete_list(self, list_id: str) -> None:
        self._request(
            "DELETE", f"{self._ns}/storage/collections/config/{list_id}", params={"output_mode": "json"}
        )

    def add_list_items(self, list_id: str, items: List[str]) -> ListObject:
        for item in items:
            self._request(
                "POST",
                f"{self._ns}/storage/collections/data/{list_id}",
                json={"value": item},
                params={"output_mode": "json"},
            )
        return self.get_list(list_id)

    def remove_list_items(self, list_id: str, items: List[str]) -> ListObject:
        records = self._request_json(
            "GET", f"{self._ns}/storage/collections/data/{list_id}", params={"output_mode": "json"}
        )
        to_remove = set(items)
        for record in records or []:
            if str(record.get("value")) in to_remove and "_key" in record:
                self._request(
                    "DELETE",
                    f"{self._ns}/storage/collections/data/{list_id}/{record['_key']}",
                    params={"output_mode": "json"},
                )
        return self.get_list(list_id)

    # -- alerts (fired alerts) -------------------------------------------
    def list_alerts(self, **filters: Any) -> List[Alert]:
        data = self._request_json(
            "GET", f"{self._ns}/alerts/fired_alerts", params={"output_mode": "json", "count": 0}
        )
        alerts: List[Alert] = []
        for group in data.get("entry", []):
            group_name = group["name"]
            instances = self._request_json(
                "GET", f"{self._ns}/alerts/fired_alerts/{group_name}", params={"output_mode": "json"}
            )
            for inst in instances.get("entry", []):
                content = inst.get("content", {})
                alerts.append(
                    Alert(
                        id=f"{group_name}:{inst['name']}",
                        title=group_name,
                        severity=content.get("severity", "unknown"),
                        status="fired",
                        rule_id=group_name,
                        timestamp=content.get("trigger_time"),
                        raw=inst,
                    )
                )
        return alerts

    def get_alert(self, alert_id: str) -> Alert:
        group_name, _, instance_name = alert_id.partition(":")
        instances = self._request_json(
            "GET", f"{self._ns}/alerts/fired_alerts/{group_name}", params={"output_mode": "json"}
        )
        for inst in instances.get("entry", []):
            if inst["name"] == instance_name:
                content = inst.get("content", {})
                return Alert(
                    id=alert_id,
                    title=group_name,
                    severity=content.get("severity", "unknown"),
                    status="fired",
                    rule_id=group_name,
                    timestamp=content.get("trigger_time"),
                    raw=inst,
                )
        raise NotFoundError(f"fired alert instance not found: {alert_id}")

    def set_alert_status(self, alert_id: str, status: str) -> Alert:
        # Splunk's fired_alerts API has no ack/close/status concept the way
        # Elastic signals or Sentinel incidents do -- be honest about it.
        raise UnsupportedOperationError(
            "Splunk fired alerts have no settable status field via the REST API "
            "(no ack/close concept, unlike Elastic signals or Sentinel incidents)."
        )

    # -- events / raw queries ---------------------------------------------
    def run_query(self, query: str, start: Optional[str] = None, end: Optional[str] = None, limit: int = 100, **kwargs: Any) -> QueryResult:
        job_payload: Dict[str, Any] = {
            "search": self._normalize_search(query),
            "exec_mode": "blocking",
        }
        if start:
            job_payload["earliest_time"] = start
        if end:
            job_payload["latest_time"] = end

        created = self._request_json(
            "POST", f"{self._ns}/search/jobs", data=job_payload, params={"output_mode": "json"}
        )
        sid = created["sid"]

        results = self._request_json(
            "GET",
            f"{self._ns}/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": limit},
        )
        rows = results.get("results", [])
        columns = [f["name"] for f in results.get("fields", [])] or (list(rows[0].keys()) if rows else [])
        return QueryResult(columns=columns, rows=rows, raw=results)
