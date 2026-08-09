"""Microsoft Sentinel adapter.

Maps detectl's canonical resources onto Sentinel's real Azure Resource
Manager (ARM) surface plus the separate Log Analytics query API:

- Rules       -> Scheduled Analytics Rules
                 (Microsoft.SecurityInsights/alertRules)
- Lists       -> Watchlists
                 (Microsoft.SecurityInsights/watchlists, .../watchlistItems)
- Alerts      -> Incidents
                 (Microsoft.SecurityInsights/incidents)
- run_query   -> Log Analytics workspace query API (KQL), a completely
                 separate host/token scope from the ARM management API --
                 both are OAuth2 client-credentials tokens against the same
                 Azure AD app registration, just for different resources.

ARM resources are managed via idempotent PUT (create == update, matching
Azure's own convention), except partial updates like status/enabled toggles
which use PATCH where the API supports it.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

import requests

from ..exceptions import AuthenticationError
from ..models import Alert, ListObject, QueryResult, Rule
from .base import SIEMAdapter

_API_VERSION = "2023-11-01"
_LOGIN_BASE = "https://login.microsoftonline.com"
_LOGANALYTICS_BASE = "https://api.loganalytics.io"


class SentinelAdapter(SIEMAdapter):
    name = "sentinel"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        resource_group: str,
        workspace_name: str,
        workspace_id: str,
        base_url: str = "https://management.azure.com",
        session: Optional[requests.Session] = None,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.workspace_name = workspace_name
        self.workspace_id = workspace_id
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self._tokens: Dict[str, Dict[str, Any]] = {}

    # -- auth ------------------------------------------------------------
    def _get_token(self, scope: str) -> str:
        cached = self._tokens.get(scope)
        if cached and cached["expires_at"] > time.time() + 30:
            return cached["access_token"]

        resp = self.session.post(
            f"{_LOGIN_BASE}/{self.tenant_id}/oauth2/v2.0/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": scope,
            },
            timeout=self.timeout,
        )
        if resp.status_code >= 400:
            raise AuthenticationError(f"token exchange for scope {scope} failed: {resp.status_code} {resp.text}")
        payload = resp.json()
        self._tokens[scope] = {
            "access_token": payload["access_token"],
            "expires_at": time.time() + int(payload.get("expires_in", 3600)),
        }
        return payload["access_token"]

    def _mgmt_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token('https://management.azure.com/.default')}"}

    def _loganalytics_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self._get_token(f'{_LOGANALYTICS_BASE}/.default')}"}

    @property
    def _workspace_path(self) -> str:
        return (
            f"/subscriptions/{self.subscription_id}/resourceGroups/{self.resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{self.workspace_name}"
            f"/providers/Microsoft.SecurityInsights"
        )

    def _list_all_pages(self, url: str) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        params = {"api-version": _API_VERSION}
        headers = self._mgmt_headers()
        while url:
            data = self._request_json("GET", url, headers=headers, params=params)
            items.extend(data.get("value", []))
            url = data.get("nextLink")
            params = {}  # nextLink is already a fully-qualified URL with its own query string
        return items

    # -- connectivity --------------------------------------------------
    def test_connection(self) -> bool:
        self._get_token("https://management.azure.com/.default")
        return True

    # -- rules (analytics rules) -------------------------------------------
    def _rule_from_item(self, item: Dict[str, Any]) -> Rule:
        props = item.get("properties", {})
        return Rule(
            id=item["name"],
            name=props.get("displayName", ""),
            query=props.get("query", ""),
            description=props.get("description", ""),
            severity=props.get("severity", "Medium").lower(),
            enabled=props.get("enabled", True),
            tags=props.get("tactics", []),
            raw=item,
        )

    def list_rules(self, **filters: Any) -> List[Rule]:
        items = self._list_all_pages(f"{self.base_url}{self._workspace_path}/alertRules")
        return [self._rule_from_item(i) for i in items]

    def get_rule(self, rule_id: str) -> Rule:
        item = self._request_json(
            "GET",
            f"{self.base_url}{self._workspace_path}/alertRules/{rule_id}",
            headers=self._mgmt_headers(),
            params={"api-version": _API_VERSION},
        )
        return self._rule_from_item(item)

    def _put_rule(self, rule_id: str, rule: Rule, enabled: Optional[bool] = None) -> Rule:
        body = {
            "kind": "Scheduled",
            "properties": {
                "displayName": rule.name,
                "description": rule.description,
                "severity": rule.severity.capitalize(),
                "enabled": rule.enabled if enabled is None else enabled,
                "query": rule.query,
                "queryFrequency": "PT1H",
                "queryPeriod": "PT1H",
                "triggerOperator": "GreaterThan",
                "triggerThreshold": 0,
                "tactics": rule.tags,
            },
        }
        item = self._request_json(
            "PUT",
            f"{self.base_url}{self._workspace_path}/alertRules/{rule_id}",
            headers=self._mgmt_headers(),
            params={"api-version": _API_VERSION},
            json=body,
        )
        return self._rule_from_item(item)

    def create_rule(self, rule: Rule) -> Rule:
        rule_id = rule.id or str(uuid.uuid4())
        return self._put_rule(rule_id, rule)

    def update_rule(self, rule_id: str, rule: Rule) -> Rule:
        return self._put_rule(rule_id, rule)

    def delete_rule(self, rule_id: str) -> None:
        self._request(
            "DELETE",
            f"{self.base_url}{self._workspace_path}/alertRules/{rule_id}",
            headers=self._mgmt_headers(),
            params={"api-version": _API_VERSION},
        )

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> Rule:
        current = self.get_rule(rule_id)
        return self._put_rule(rule_id, current, enabled=enabled)

    # -- lists (watchlists) ------------------------------------------------
    def list_lists(self, kind: Optional[str] = None) -> List[ListObject]:
        if kind not in (None, "watchlist"):
            return []
        items = self._list_all_pages(f"{self.base_url}{self._workspace_path}/watchlists")
        return [
            ListObject(
                id=i["name"],
                name=i.get("properties", {}).get("displayName", i["name"]),
                kind="watchlist",
                description=i.get("properties", {}).get("description", ""),
                items=[],
                raw=i,
            )
            for i in items
        ]

    def get_list(self, list_id: str) -> ListObject:
        container = self._request_json(
            "GET",
            f"{self.base_url}{self._workspace_path}/watchlists/{list_id}",
            headers=self._mgmt_headers(),
            params={"api-version": _API_VERSION},
        )
        raw_items = self._list_all_pages(f"{self.base_url}{self._workspace_path}/watchlists/{list_id}/watchlistItems")
        items = [str((i.get("properties", {}).get("itemsKeyValue", {}) or {}).get("value", i)) for i in raw_items]
        props = container.get("properties", {})
        return ListObject(
            id=list_id,
            name=props.get("displayName", list_id),
            kind="watchlist",
            description=props.get("description", ""),
            items=items,
            raw=container,
        )

    def create_list(self, list_obj: ListObject) -> ListObject:
        list_id = list_obj.id or list_obj.name.lower().replace(" ", "-")
        body = {
            "properties": {
                "displayName": list_obj.name,
                "description": list_obj.description,
                "provider": "detectl",
                "source": "Local file",
                "itemsSearchKey": "value",
            }
        }
        self._request(
            "PUT",
            f"{self.base_url}{self._workspace_path}/watchlists/{list_id}",
            headers=self._mgmt_headers(),
            params={"api-version": _API_VERSION},
            json=body,
        )
        if list_obj.items:
            self.add_list_items(list_id, list_obj.items)
        return self.get_list(list_id)

    def update_list(self, list_id: str, list_obj: ListObject) -> ListObject:
        body = {
            "properties": {
                "displayName": list_obj.name,
                "description": list_obj.description,
                "provider": "detectl",
                "source": "Local file",
                "itemsSearchKey": "value",
            }
        }
        self._request(
            "PUT",
            f"{self.base_url}{self._workspace_path}/watchlists/{list_id}",
            headers=self._mgmt_headers(),
            params={"api-version": _API_VERSION},
            json=body,
        )
        existing = self.get_list(list_id)
        if existing.items:
            self.remove_list_items(list_id, existing.items)
        if list_obj.items:
            self.add_list_items(list_id, list_obj.items)
        return self.get_list(list_id)

    def delete_list(self, list_id: str) -> None:
        self._request(
            "DELETE",
            f"{self.base_url}{self._workspace_path}/watchlists/{list_id}",
            headers=self._mgmt_headers(),
            params={"api-version": _API_VERSION},
        )

    def add_list_items(self, list_id: str, items: List[str]) -> ListObject:
        for value in items:
            item_id = str(uuid.uuid4())
            self._request(
                "PUT",
                f"{self.base_url}{self._workspace_path}/watchlists/{list_id}/watchlistItems/{item_id}",
                headers=self._mgmt_headers(),
                params={"api-version": _API_VERSION},
                json={"properties": {"itemsKeyValue": {"value": value}}},
            )
        return self.get_list(list_id)

    def remove_list_items(self, list_id: str, items: List[str]) -> ListObject:
        raw_items = self._list_all_pages(f"{self.base_url}{self._workspace_path}/watchlists/{list_id}/watchlistItems")
        to_remove = set(items)
        for entry in raw_items:
            value = (entry.get("properties", {}).get("itemsKeyValue", {}) or {}).get("value")
            if str(value) in to_remove:
                self._request(
                    "DELETE",
                    f"{self.base_url}{self._workspace_path}/watchlists/{list_id}/watchlistItems/{entry['name']}",
                    headers=self._mgmt_headers(),
                    params={"api-version": _API_VERSION},
                )
        return self.get_list(list_id)

    # -- alerts (incidents) ------------------------------------------------
    def _alert_from_item(self, item: Dict[str, Any]) -> Alert:
        props = item.get("properties", {})
        return Alert(
            id=item["name"],
            title=props.get("title", ""),
            severity=props.get("severity", "Medium").lower(),
            status=props.get("status", "New"),
            rule_id=None,
            timestamp=props.get("createdTimeUtc"),
            raw=item,
        )

    def list_alerts(self, **filters: Any) -> List[Alert]:
        items = self._list_all_pages(f"{self.base_url}{self._workspace_path}/incidents")
        return [self._alert_from_item(i) for i in items]

    def get_alert(self, alert_id: str) -> Alert:
        item = self._request_json(
            "GET",
            f"{self.base_url}{self._workspace_path}/incidents/{alert_id}",
            headers=self._mgmt_headers(),
            params={"api-version": _API_VERSION},
        )
        return self._alert_from_item(item)

    def set_alert_status(self, alert_id: str, status: str) -> Alert:
        item = self._request_json(
            "PATCH",
            f"{self.base_url}{self._workspace_path}/incidents/{alert_id}",
            headers=self._mgmt_headers(),
            params={"api-version": _API_VERSION},
            json={"properties": {"status": status}},
        )
        return self._alert_from_item(item)

    # -- events / raw queries (Log Analytics KQL) --------------------------
    def run_query(self, query: str, limit: int = 100, **kwargs: Any) -> QueryResult:
        resp = self._request_json(
            "POST",
            f"{_LOGANALYTICS_BASE}/v1/workspaces/{self.workspace_id}/query",
            headers=self._loganalytics_headers(),
            json={"query": query},
        )
        tables = resp.get("tables", [])
        if not tables:
            return QueryResult(columns=[], rows=[], raw=resp)
        table = tables[0]
        columns = [c["name"] for c in table.get("columns", [])]
        rows = [dict(zip(columns, row)) for row in table.get("rows", [])[:limit]]
        return QueryResult(columns=columns, rows=rows, raw=resp)
