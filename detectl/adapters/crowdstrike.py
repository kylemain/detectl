"""CrowdStrike Falcon adapter.

Maps detectl's canonical resources onto the real Falcon API surface -- which
has a notably different shape than Splunk/Elastic/Sentinel, so a few
adapter-specific conventions are documented here:

- Rules   -> Custom IOA Rules, which the Falcon API always scopes to a
             parent "rule group" (there's no bare, group-less rule). Since
             detectl's interface addresses a rule by a single `rule_id`
             string, this adapter encodes both IDs as "{rule_group_id}:
             {instance_id}". A rule's condition is built from structured
             `field_values`, not a single query string like SPL/KQL, so
             `Rule.query` holds that structure JSON-encoded.
- Lists   -> IOC (indicator) management. Falcon's IOC API has no concept of
             a named list container the way Splunk KV Store or Sentinel
             watchlists do -- IOCs are just individually-tagged indicators.
             detectl groups them into named lists via a `detectl_list:
             {name}` tag convention, and infers `kind` (allowlist/blocklist/
             exclusion) from the IOC `action` field.
- Alerts  -> the Falcon Alerts API (composite IDs, POST-based entity fetch,
             action_parameters-based status updates -- all matching Falcon's
             real API design rather than a generic REST CRUD pattern).
- Events  -> Falcon has no ad-hoc query language/endpoint comparable to
             Splunk SPL, Elasticsearch DSL, or Sentinel KQL. run_query
             raises UnsupportedOperationError rather than faking one.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional

import requests

from ..exceptions import AuthenticationError, NotFoundError, UnsupportedOperationError
from ..models import Alert, ListObject, QueryResult, Rule
from .base import SIEMAdapter

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HASH_LEN_TO_TYPE = {32: "md5", 40: "sha1", 64: "sha256"}

_KIND_TO_ACTION = {
    "allowlist": "allow",
    "blocklist": "block",
    "exclusion": "no_action",
    "suppression": "no_action",
    "watchlist": "detect",
    "kv_store": "no_action",
}
_ACTION_TO_KIND = {v: k for k, v in _KIND_TO_ACTION.items() if k in ("allowlist", "blocklist", "watchlist")}


def _guess_ioc_type(value: str) -> str:
    if _IPV4_RE.match(value):
        return "ipv4"
    if re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) in _HASH_LEN_TO_TYPE:
        return _HASH_LEN_TO_TYPE[len(value)]
    return "domain"


class CrowdStrikeAdapter(SIEMAdapter):
    name = "crowdstrike"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str = "https://api.crowdstrike.com",
        session: Optional[requests.Session] = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

    # -- auth ------------------------------------------------------------
    def _headers(self) -> Dict[str, str]:
        if not self._token or self._token_expires_at <= time.time() + 30:
            resp = self.session.post(
                f"{self.base_url}/oauth2/token",
                data={"client_id": self.client_id, "client_secret": self.client_secret},
                timeout=self.timeout,
            )
            if resp.status_code >= 400:
                raise AuthenticationError(f"CrowdStrike token exchange failed: {resp.status_code} {resp.text}")
            payload = resp.json()
            self._token = payload["access_token"]
            self._token_expires_at = time.time() + int(payload.get("expires_in", 1800))
        return {"Authorization": f"Bearer {self._token}"}

    # -- connectivity --------------------------------------------------
    def test_connection(self) -> bool:
        self._headers()
        return True

    # -- rules (custom IOA rules, scoped to a rule group) -----------------
    def _rule_from_entry(self, group_id: str, entry: Dict[str, Any]) -> Rule:
        return Rule(
            id=f"{group_id}:{entry['instance_id']}",
            name=entry.get("name", ""),
            query=json.dumps(entry.get("field_values", [])),
            description=entry.get("description", ""),
            severity=entry.get("pattern_severity", "medium"),
            enabled=entry.get("enabled", True),
            tags=[],
            raw=entry,
        )

    def _get_group(self, group_id: str) -> Dict[str, Any]:
        data = self._request_json(
            "GET",
            f"{self.base_url}/ioarules/entities/rule-groups/v1",
            headers=self._headers(),
            params={"ids": group_id},
        )
        resources = data.get("resources", [])
        if not resources:
            raise NotFoundError(f"IOA rule group not found: {group_id}")
        return resources[0]

    def list_rules(self, **filters: Any) -> List[Rule]:
        group_id = filters.get("rule_group_id")
        if not group_id:
            raise ValueError(
                "CrowdStrike list_rules requires a rule_group_id filter -- Falcon custom IOA "
                "rules are always scoped to a rule group (there's no bare, group-less rule)."
            )
        group = self._get_group(group_id)
        return [self._rule_from_entry(group_id, r) for r in group.get("rules", [])]

    def get_rule(self, rule_id: str) -> Rule:
        group_id, _, instance_id = rule_id.partition(":")
        group = self._get_group(group_id)
        for entry in group.get("rules", []):
            if entry["instance_id"] == instance_id:
                return self._rule_from_entry(group_id, entry)
        raise NotFoundError(f"IOA rule not found: {rule_id}")

    def create_rule(self, rule: Rule) -> Rule:
        group_id = rule.raw.get("rule_group_id")
        if not group_id:
            raise ValueError("CrowdStrike create_rule requires rule.raw['rule_group_id']")
        try:
            field_values = json.loads(rule.query) if rule.query else []
        except json.JSONDecodeError:
            field_values = []
        body = {
            "rulegroup_id": group_id,
            "name": rule.name,
            "description": rule.description,
            "pattern_severity": rule.severity,
            "disposition_id": 20,  # "detect"
            "field_values": field_values,
            "enabled": rule.enabled,
        }
        data = self._request_json(
            "POST", f"{self.base_url}/ioarules/entities/rules/v1", headers=self._headers(), json=body
        )
        instance_id = data["resources"][0]["instance_id"]
        return self.get_rule(f"{group_id}:{instance_id}")

    def update_rule(self, rule_id: str, rule: Rule) -> Rule:
        group_id, _, instance_id = rule_id.partition(":")
        try:
            field_values = json.loads(rule.query) if rule.query else []
        except json.JSONDecodeError:
            field_values = []
        body = {
            "rulegroup_id": group_id,
            "instance_id": instance_id,
            "name": rule.name,
            "description": rule.description,
            "pattern_severity": rule.severity,
            "field_values": field_values,
            "enabled": rule.enabled,
        }
        self._request("PATCH", f"{self.base_url}/ioarules/entities/rules/v1", headers=self._headers(), json=body)
        return self.get_rule(rule_id)

    def delete_rule(self, rule_id: str) -> None:
        group_id, _, instance_id = rule_id.partition(":")
        self._request(
            "DELETE",
            f"{self.base_url}/ioarules/entities/rules/v1",
            headers=self._headers(),
            params={"ids": instance_id, "rule_group_id": group_id},
        )

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> Rule:
        current = self.get_rule(rule_id)
        current.enabled = enabled
        return self.update_rule(rule_id, current)

    # -- lists (IOCs grouped by a detectl_list:{name} tag) -----------------
    def _iocs_by_list_name(self) -> Dict[str, List[Dict[str, Any]]]:
        ids = self._request_json(
            "GET",
            f"{self.base_url}/iocs/queries/indicators/v1",
            headers=self._headers(),
            params={"filter": "tags:'detectl_list:*'", "limit": 5000},
        ).get("resources", [])
        if not ids:
            return {}
        details = self._request_json(
            "GET", f"{self.base_url}/iocs/entities/indicators/v1", headers=self._headers(), params={"ids": ids}
        ).get("resources", [])
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for ioc in details:
            for tag in ioc.get("tags", []):
                if tag.startswith("detectl_list:"):
                    grouped.setdefault(tag.split(":", 1)[1], []).append(ioc)
        return grouped

    @staticmethod
    def _derive_kind(iocs: List[Dict[str, Any]]) -> str:
        if not iocs:
            return "exclusion"
        action = iocs[0].get("action", "no_action")
        return _ACTION_TO_KIND.get(action, "exclusion")

    def list_lists(self, kind: Optional[str] = None) -> List[ListObject]:
        grouped = self._iocs_by_list_name()
        results = []
        for name, iocs in grouped.items():
            derived_kind = self._derive_kind(iocs)
            if kind and derived_kind != kind:
                continue
            results.append(
                ListObject(id=name, name=name, kind=derived_kind, items=[i["value"] for i in iocs], raw={"iocs": iocs})
            )
        return results

    def get_list(self, list_id: str) -> ListObject:
        grouped = self._iocs_by_list_name()
        iocs = grouped.get(list_id)
        if iocs is None:
            raise NotFoundError(f"IOC list not found: {list_id}")
        return ListObject(id=list_id, name=list_id, kind=self._derive_kind(iocs), items=[i["value"] for i in iocs], raw={"iocs": iocs})

    def create_list(self, list_obj: ListObject) -> ListObject:
        if list_obj.items:
            self._add_iocs(list_obj.name, list_obj.kind, list_obj.items, list_obj.description)
        return self.get_list(list_obj.name)

    def update_list(self, list_id: str, list_obj: ListObject) -> ListObject:
        existing = self.list_lists()
        current = next((l for l in existing if l.id == list_id), None)
        if current and current.items:
            self.remove_list_items(list_id, current.items)
        if list_obj.items:
            self._add_iocs(list_id, list_obj.kind, list_obj.items, list_obj.description)
        return self.get_list(list_id)

    def delete_list(self, list_id: str) -> None:
        grouped = self._iocs_by_list_name()
        iocs = grouped.get(list_id, [])
        if iocs:
            self._request(
                "DELETE",
                f"{self.base_url}/iocs/entities/indicators/v1",
                headers=self._headers(),
                params={"ids": [i["id"] for i in iocs]},
            )

    def _add_iocs(self, list_name: str, kind: str, items: List[str], description: str = "") -> None:
        action = _KIND_TO_ACTION.get(kind, "no_action")
        indicators = [
            {
                "type": _guess_ioc_type(value),
                "value": value,
                "action": action,
                "severity": "medium",
                "description": description,
                "tags": [f"detectl_list:{list_name}"],
            }
            for value in items
        ]
        self._request(
            "POST",
            f"{self.base_url}/iocs/entities/indicators/v1",
            headers=self._headers(),
            json={"indicators": indicators},
        )

    def add_list_items(self, list_id: str, items: List[str]) -> ListObject:
        existing = self.get_list(list_id)
        self._add_iocs(list_id, existing.kind, items)
        return self.get_list(list_id)

    def remove_list_items(self, list_id: str, items: List[str]) -> ListObject:
        grouped = self._iocs_by_list_name()
        iocs = grouped.get(list_id, [])
        to_remove = set(items)
        matching_ids = [i["id"] for i in iocs if i["value"] in to_remove]
        if matching_ids:
            self._request(
                "DELETE",
                f"{self.base_url}/iocs/entities/indicators/v1",
                headers=self._headers(),
                params={"ids": matching_ids},
            )
        return self.get_list(list_id)

    # -- alerts ------------------------------------------------------------
    def _alert_from_entry(self, entry: Dict[str, Any]) -> Alert:
        return Alert(
            id=entry["composite_id"],
            title=entry.get("display_name", entry.get("name", "")),
            severity=str(entry.get("severity_name", entry.get("severity", "unknown"))),
            status=entry.get("status", "new"),
            rule_id=entry.get("detect_id") or entry.get("pattern_id"),
            timestamp=entry.get("timestamp"),
            raw=entry,
        )

    def list_alerts(self, **filters: Any) -> List[Alert]:
        ids = self._request_json(
            "GET",
            f"{self.base_url}/alerts/queries/alerts/v2",
            headers=self._headers(),
            params={"limit": filters.get("limit", 100)},
        ).get("resources", [])
        if not ids:
            return []
        details = self._request_json(
            "POST",
            f"{self.base_url}/alerts/entities/alerts/v2",
            headers=self._headers(),
            json={"composite_ids": ids},
        ).get("resources", [])
        return [self._alert_from_entry(a) for a in details]

    def get_alert(self, alert_id: str) -> Alert:
        details = self._request_json(
            "POST",
            f"{self.base_url}/alerts/entities/alerts/v2",
            headers=self._headers(),
            json={"composite_ids": [alert_id]},
        ).get("resources", [])
        if not details:
            raise NotFoundError(f"alert not found: {alert_id}")
        return self._alert_from_entry(details[0])

    def set_alert_status(self, alert_id: str, status: str) -> Alert:
        self._request(
            "PATCH",
            f"{self.base_url}/alerts/entities/alerts/v2",
            headers=self._headers(),
            json={
                "composite_ids": [alert_id],
                "action_parameters": [{"name": "update_status", "value": status}],
            },
        )
        return self.get_alert(alert_id)

    # -- events / raw queries ---------------------------------------------
    def run_query(self, query: str, **kwargs: Any) -> QueryResult:
        raise UnsupportedOperationError(
            "CrowdStrike Falcon has no ad-hoc event query API comparable to Splunk SPL, "
            "Elasticsearch Query DSL, or Sentinel KQL (Falcon exposes detections/alerts/IOCs "
            "as discrete resources, not a general query surface over raw events)."
        )
