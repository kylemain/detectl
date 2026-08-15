"""Elastic (Kibana Security + Elasticsearch) adapter.

Maps detectl's canonical resources onto the real Kibana/Elasticsearch APIs:

- Rules       -> Kibana Detection Engine API (/api/detection_engine/rules)
- Lists       -> Kibana Lists API (/api/lists, /api/lists/items) -- this API
                 has no native "kind" (watchlist vs. exclusion vs. allow/
                 block vs. suppression) concept, so detectl stores the kind
                 in the list's `meta.detectl_kind` field as a convention.
- Alerts      -> Detection signals API (/api/detection_engine/signals/*)
- run_query   -> a raw Elasticsearch _search against `es_base_url`. Accepts
                 either a full Query DSL JSON body (a string, e.g. straight
                 from `sigmux convert --target elastic`) or a bare
                 query string, which gets wrapped in a query_string query.

Kibana requires the `kbn-xsrf` header on any state-changing request; that's
set once on the session in __init__ rather than repeated per call.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import requests

from ..exceptions import ConfigError, NotFoundError
from ..models import Alert, ListObject, QueryResult, Rule
from .base import SIEMAdapter

_SEVERITY_TO_RISK_SCORE = {"low": 21, "medium": 47, "high": 73, "critical": 99}


class ElasticAdapter(SIEMAdapter):
    name = "elastic"

    def __init__(
        self,
        kibana_base_url: str,
        api_key: str,
        es_base_url: Optional[str] = None,
        verify_ssl: bool = True,
        session: Optional[requests.Session] = None,
    ):
        self.kibana_base_url = kibana_base_url.rstrip("/")
        self.es_base_url = es_base_url.rstrip("/") if es_base_url else None
        self.session = session or requests.Session()
        self.session.headers.setdefault("Authorization", f"ApiKey {api_key}")
        self.session.headers.setdefault("kbn-xsrf", "detectl")
        self.session.headers.setdefault("Content-Type", "application/json")
        self.session.verify = verify_ssl

    # -- helpers -----------------------------------------------------
    def _rule_from_item(self, item: Dict[str, Any]) -> Rule:
        return Rule(
            id=item.get("id"),
            name=item.get("name", ""),
            query=item.get("query", ""),
            description=item.get("description", ""),
            severity=item.get("severity", "medium"),
            enabled=item.get("enabled", True),
            tags=item.get("tags", []),
            raw=item,
        )

    def _list_from_container(self, container: Dict[str, Any], items: Optional[List[str]] = None) -> ListObject:
        kind = (container.get("meta") or {}).get("detectl_kind", "watchlist")
        return ListObject(
            id=container.get("id"),
            name=container.get("name", container.get("id", "")),
            kind=kind,
            description=container.get("description", ""),
            items=items or [],
            raw=container,
        )

    # -- connectivity --------------------------------------------------
    def test_connection(self) -> bool:
        self._request_json("GET", f"{self.kibana_base_url}/api/status")
        return True

    # -- rules (Detection Engine API) -------------------------------------
    def list_rules(self, **filters: Any) -> List[Rule]:
        params = {"per_page": filters.get("per_page", 100), "page": filters.get("page", 1)}
        data = self._request_json("GET", f"{self.kibana_base_url}/api/detection_engine/rules/_find", params=params)
        return [self._rule_from_item(item) for item in data.get("data", [])]

    def get_rule(self, rule_id: str) -> Rule:
        item = self._request_json(
            "GET", f"{self.kibana_base_url}/api/detection_engine/rules", params={"id": rule_id}
        )
        return self._rule_from_item(item)

    def create_rule(self, rule: Rule) -> Rule:
        body = {
            "name": rule.name,
            "description": rule.description or rule.name,
            "query": rule.query,
            "language": "kuery",
            "type": "query",
            "severity": rule.severity,
            "risk_score": _SEVERITY_TO_RISK_SCORE.get(rule.severity, 47),
            "enabled": rule.enabled,
            "tags": rule.tags,
            "index": ["logs-*"],
            "from": "now-6m",
            "interval": "5m",
        }
        item = self._request_json("POST", f"{self.kibana_base_url}/api/detection_engine/rules", json=body)
        return self._rule_from_item(item)

    def update_rule(self, rule_id: str, rule: Rule) -> Rule:
        body = {
            "id": rule_id,
            "name": rule.name,
            "description": rule.description or rule.name,
            "query": rule.query,
            "language": "kuery",
            "type": "query",
            "severity": rule.severity,
            "risk_score": _SEVERITY_TO_RISK_SCORE.get(rule.severity, 47),
            "enabled": rule.enabled,
            "tags": rule.tags,
        }
        item = self._request_json("PUT", f"{self.kibana_base_url}/api/detection_engine/rules", json=body)
        return self._rule_from_item(item)

    def delete_rule(self, rule_id: str) -> None:
        self._request("DELETE", f"{self.kibana_base_url}/api/detection_engine/rules", params={"id": rule_id})

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> Rule:
        item = self._request_json(
            "PATCH",
            f"{self.kibana_base_url}/api/detection_engine/rules",
            json={"id": rule_id, "enabled": enabled},
        )
        return self._rule_from_item(item)

    # -- lists (Kibana Lists API) ------------------------------------------
    def list_lists(self, kind: Optional[str] = None) -> List[ListObject]:
        data = self._request_json(
            "GET", f"{self.kibana_base_url}/api/lists/_find", params={"per_page": 100}
        )
        results = [self._list_from_container(c) for c in data.get("data", [])]
        if kind:
            results = [r for r in results if r.kind == kind]
        return results

    def get_list(self, list_id: str) -> ListObject:
        container = self._request_json("GET", f"{self.kibana_base_url}/api/lists", params={"id": list_id})
        item_data = self._request_json(
            "GET",
            f"{self.kibana_base_url}/api/lists/items/_find",
            params={"list_id": list_id, "per_page": 9999},
        )
        items = [i["value"] for i in item_data.get("data", [])]
        return self._list_from_container(container, items)

    def create_list(self, list_obj: ListObject) -> ListObject:
        body = {
            "name": list_obj.name,
            "description": list_obj.description or list_obj.name,
            "type": "keyword",
            "meta": {"detectl_kind": list_obj.kind},
        }
        if list_obj.id:
            body["id"] = list_obj.id
        container = self._request_json("POST", f"{self.kibana_base_url}/api/lists", json=body)
        if list_obj.items:
            self.add_list_items(container["id"], list_obj.items)
        return self.get_list(container["id"])

    def update_list(self, list_id: str, list_obj: ListObject) -> ListObject:
        body = {
            "id": list_id,
            "name": list_obj.name,
            "description": list_obj.description or list_obj.name,
            "meta": {"detectl_kind": list_obj.kind},
        }
        self._request("PUT", f"{self.kibana_base_url}/api/lists", json=body)

        existing = self.get_list(list_id)
        if existing.items:
            self.remove_list_items(list_id, existing.items)
        if list_obj.items:
            self.add_list_items(list_id, list_obj.items)
        return self.get_list(list_id)

    def delete_list(self, list_id: str) -> None:
        self._request(
            "DELETE", f"{self.kibana_base_url}/api/lists", params={"id": list_id, "deleteReferences": "true"}
        )

    def add_list_items(self, list_id: str, items: List[str]) -> ListObject:
        for value in items:
            self._request(
                "POST",
                f"{self.kibana_base_url}/api/lists/items",
                json={"list_id": list_id, "value": value, "type": "keyword"},
            )
        return self.get_list(list_id)

    def remove_list_items(self, list_id: str, items: List[str]) -> ListObject:
        item_data = self._request_json(
            "GET",
            f"{self.kibana_base_url}/api/lists/items/_find",
            params={"list_id": list_id, "per_page": 9999},
        )
        to_remove = set(items)
        for entry in item_data.get("data", []):
            if entry.get("value") in to_remove:
                self._request("DELETE", f"{self.kibana_base_url}/api/lists/items", params={"id": entry["id"]})
        return self.get_list(list_id)

    # -- alerts (detection signals API) ------------------------------------
    def _alert_from_hit(self, hit: Dict[str, Any]) -> Alert:
        source = hit.get("_source", {})
        signal = source.get("signal", {})
        rule = signal.get("rule", {})
        return Alert(
            id=hit["_id"],
            title=rule.get("name", ""),
            severity=rule.get("severity", "unknown"),
            status=signal.get("status", "open"),
            rule_id=rule.get("id"),
            timestamp=source.get("@timestamp"),
            raw=hit,
        )

    def list_alerts(self, **filters: Any) -> List[Alert]:
        body = {"query": {"match_all": {}}, "size": filters.get("limit", 100)}
        data = self._request_json(
            "POST", f"{self.kibana_base_url}/api/detection_engine/signals/search", json=body
        )
        return [self._alert_from_hit(h) for h in data.get("hits", {}).get("hits", [])]

    def get_alert(self, alert_id: str) -> Alert:
        body = {"query": {"term": {"_id": alert_id}}, "size": 1}
        data = self._request_json(
            "POST", f"{self.kibana_base_url}/api/detection_engine/signals/search", json=body
        )
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            raise NotFoundError(f"signal not found: {alert_id}")
        return self._alert_from_hit(hits[0])

    def set_alert_status(self, alert_id: str, status: str) -> Alert:
        self._request(
            "POST",
            f"{self.kibana_base_url}/api/detection_engine/signals/status",
            json={"signal_ids": [alert_id], "status": status},
        )
        return self.get_alert(alert_id)

    # -- events / raw queries ---------------------------------------------
    def run_query(self, query: str, limit: int = 100, index: str = "*", **kwargs: Any) -> QueryResult:
        if not self.es_base_url:
            raise ConfigError(
                "run_query requires es_base_url to be configured for the elastic adapter "
                "(raw Query DSL search goes directly to Elasticsearch, not Kibana)"
            )
        index = kwargs.get("index", index)
        stripped = query.strip()
        if stripped.startswith("{"):
            body = json.loads(stripped)
            if "query" not in body:
                body = {"query": body}
        else:
            body = {"query": {"query_string": {"query": query}}}
        body.setdefault("size", limit)

        resp = self._request_json("POST", f"{self.es_base_url}/{index}/_search", json=body)
        hits = resp.get("hits", {}).get("hits", [])
        rows = [{"_id": h["_id"], "_index": h.get("_index"), **h.get("_source", {})} for h in hits]
        columns = list(rows[0].keys()) if rows else []
        return QueryResult(columns=columns, rows=rows, raw=resp)
