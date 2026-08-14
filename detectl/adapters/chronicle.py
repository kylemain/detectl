"""Google Security Operations (Chronicle) adapter.

Maps detectl's canonical resources onto the real Chronicle API
(`https://{location}-chronicle.googleapis.com/v1beta/...`), a standard
GCP-style resource-hierarchy REST API under
`projects/{project}/locations/{location}/instances/{instance}/...`.

- Auth        -> standard Google OAuth2, which for a service account means
                 signing a JWT with an RSA private key and exchanging it for
                 a bearer token -- real crypto, not something worth
                 reimplementing in a dependency-light, clean-room REST
                 client. This adapter instead takes an already-obtained
                 `access_token` (e.g. from `gcloud auth print-access-token`
                 against a service account, or your own token-refresh
                 cron), the same way you'd script against any Google Cloud
                 API from a lightweight client without pulling in the
                 google-auth SDK.
- Rules       -> `rules` (the YARA-L rule text lives in the `text` field --
                 this is exactly what sigmux's `chronicle` backend emits,
                 see "Pairs well with sigmux" in the README) plus a
                 *separate* nested `rules/{id}/deployment` singleton
                 resource that controls whether the rule is actually live
                 (`enabled`). A freshly-created rule isn't live until its
                 deployment is patched, so `create_rule`/`update_rule` both
                 sync the deployment's `enabled` field after writing `text`.
- Lists       -> `referenceLists`. No native "kind" concept, so (same
                 convention as the QRadar/Sumo Logic adapters) `kind` is
                 stored as a `detectl_kind:{kind}` tag in `description`.
                 Reference lists have no per-item add/remove endpoint --
                 `entries` is patched as a whole array -- and, per Google's
                 own Terraform provider source, **reference lists cannot be
                 deleted via the API at all** ("will be removed from
                 Terraform state, but will still be present on Google
                 Cloud"), so `delete_list` raises UnsupportedOperationError
                 rather than silently no-op'ing.
- Alerts      -> Detections, which only exist scoped to the rule that
                 generated them (there's no bare, rule-less detection), so
                 `list_alerts` requires a `rule_id` filter (same convention
                 as the CrowdStrike adapter requiring `rule_group_id` for
                 Custom IOA rules) and `get_alert` IDs are encoded as
                 `"{rule_id}:{detection_id}"`. This is the least-verified
                 corner of this adapter -- Chronicle's detections REST
                 surface is thinner in public docs than rules/referenceLists
                 -- and detection triage/status lives in Chronicle's
                 separate SOAR/case-management module, not a simple status
                 field here, so `set_alert_status` raises
                 UnsupportedOperationError.
- run_query   -> `instances:udmSearch`, a synchronous GET (empty body) over
                 raw UDM events -- unlike the other three new adapters in
                 this pass (Falcon LogScale, Ariel, Sumo Search Job), this
                 one isn't an async job, it just returns matches directly.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

from ..exceptions import UnsupportedOperationError
from ..models import Alert, ListObject, QueryResult, Rule
from .base import SIEMAdapter

_KIND_TAG_PREFIX = "detectl_kind:"
_RFC3339 = "%Y-%m-%dT%H:%M:%SZ"


def _kind_from_description(description: str) -> str:
    for part in (description or "").split():
        if part.startswith(_KIND_TAG_PREFIX):
            return part[len(_KIND_TAG_PREFIX):]
    return "watchlist"


def _description_for(kind: str, description: str = "") -> str:
    tag = f"{_KIND_TAG_PREFIX}{kind}"
    return f"{description} {tag}".strip() if description else tag


def _id_from_name(name: str) -> str:
    return name.rstrip("/").rsplit("/", 1)[-1]


class ChronicleAdapter(SIEMAdapter):
    name = "chronicle"

    def __init__(
        self,
        project: str,
        location: str,
        instance: str,
        access_token: str,
        session: Optional[requests.Session] = None,
    ):
        self.project = project
        self.location = location
        self.instance = instance
        self.base_url = f"https://{location}-chronicle.googleapis.com/v1beta"
        self.session = session or requests.Session()
        self.session.headers.setdefault("Authorization", f"Bearer {access_token}")
        self.session.headers.setdefault("Content-Type", "application/json")

    @property
    def _instance_path(self) -> str:
        return f"{self.base_url}/projects/{self.project}/locations/{self.location}/instances/{self.instance}"

    # -- connectivity --------------------------------------------------
    def test_connection(self) -> bool:
        self._request_json("GET", f"{self._instance_path}/rules", params={"pageSize": 1})
        return True

    # -- rules --------------------------------------------------------
    def _rule_from_entry(self, entry: Dict[str, Any], enabled: Optional[bool] = None) -> Rule:
        return Rule(
            id=_id_from_name(entry.get("name", "")),
            name=entry.get("displayName", _id_from_name(entry.get("name", ""))),
            query=entry.get("text", ""),
            description="",
            severity="medium",
            enabled=True if enabled is None else enabled,
            tags=[],
            raw=entry,
        )

    def _get_deployment(self, rule_id: str) -> Dict[str, Any]:
        return self._request_json("GET", f"{self._instance_path}/rules/{rule_id}/deployment")

    def _set_deployment_enabled(self, rule_id: str, enabled: bool) -> None:
        self._request(
            "PATCH",
            f"{self._instance_path}/rules/{rule_id}/deployment",
            params={"updateMask": "enabled"},
            json={"enabled": enabled},
        )

    def list_rules(self, **filters: Any) -> List[Rule]:
        # Single call, so `enabled` isn't reflected here (that lives on the
        # separate deployment sub-resource) -- use get_rule for that.
        data = self._request_json("GET", f"{self._instance_path}/rules")
        return [self._rule_from_entry(e) for e in data.get("rules", [])]

    def get_rule(self, rule_id: str) -> Rule:
        entry = self._request_json("GET", f"{self._instance_path}/rules/{rule_id}")
        deployment = self._get_deployment(rule_id)
        return self._rule_from_entry(entry, enabled=deployment.get("enabled", False))

    def create_rule(self, rule: Rule) -> Rule:
        entry = self._request_json("POST", f"{self._instance_path}/rules", json={"text": rule.query})
        rule_id = _id_from_name(entry["name"])
        self._set_deployment_enabled(rule_id, rule.enabled)
        return self.get_rule(rule_id)

    def update_rule(self, rule_id: str, rule: Rule) -> Rule:
        self._request(
            "PATCH",
            f"{self._instance_path}/rules/{rule_id}",
            params={"updateMask": "text"},
            json={"text": rule.query},
        )
        self._set_deployment_enabled(rule_id, rule.enabled)
        return self.get_rule(rule_id)

    def delete_rule(self, rule_id: str) -> None:
        self._request("DELETE", f"{self._instance_path}/rules/{rule_id}")

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> Rule:
        self._set_deployment_enabled(rule_id, enabled)
        return self.get_rule(rule_id)

    # -- lists (reference lists) ---------------------------------------
    def _list_from_entry(self, entry: Dict[str, Any]) -> ListObject:
        return ListObject(
            id=_id_from_name(entry.get("name", "")),
            name=_id_from_name(entry.get("name", "")),
            kind=_kind_from_description(entry.get("description", "")),
            description=entry.get("description", ""),
            items=[e.get("value", "") for e in entry.get("entries", [])],
            raw=entry,
        )

    def list_lists(self, kind: Optional[str] = None) -> List[ListObject]:
        data = self._request_json("GET", f"{self._instance_path}/referenceLists")
        results = [self._list_from_entry(e) for e in data.get("referenceLists", [])]
        if kind:
            results = [r for r in results if r.kind == kind]
        return results

    def get_list(self, list_id: str) -> ListObject:
        entry = self._request_json("GET", f"{self._instance_path}/referenceLists/{list_id}")
        return self._list_from_entry(entry)

    def create_list(self, list_obj: ListObject) -> ListObject:
        body = {
            "description": _description_for(list_obj.kind, list_obj.description),
            "entries": [{"value": v} for v in list_obj.items],
            "syntaxType": list_obj.raw.get(
                "syntax_type", "REFERENCE_LIST_SYNTAX_TYPE_PLAIN_TEXT_STRING"
            ),
        }
        entry = self._request_json(
            "POST",
            f"{self._instance_path}/referenceLists",
            params={"referenceListId": list_obj.name},
            json=body,
        )
        return self._list_from_entry(entry)

    def _patch_entries(self, list_id: str, kind: str, description: str, items: List[str]) -> None:
        self._request(
            "PATCH",
            f"{self._instance_path}/referenceLists/{list_id}",
            params={"updateMask": "description,entries"},
            json={
                "description": _description_for(kind, description),
                "entries": [{"value": v} for v in items],
            },
        )

    def update_list(self, list_id: str, list_obj: ListObject) -> ListObject:
        self._patch_entries(list_id, list_obj.kind, list_obj.description, list_obj.items)
        return self.get_list(list_id)

    def delete_list(self, list_id: str) -> None:
        raise UnsupportedOperationError(
            "Chronicle reference lists cannot be deleted via the API at all (confirmed by "
            "Google's own Terraform provider, which just drops the resource from state rather "
            "than deleting it) -- deletion has to happen in the Google SecOps console."
        )

    def add_list_items(self, list_id: str, items: List[str]) -> ListObject:
        current = self.get_list(list_id)
        merged = current.items + [v for v in items if v not in current.items]
        self._patch_entries(list_id, current.kind, current.description, merged)
        return self.get_list(list_id)

    def remove_list_items(self, list_id: str, items: List[str]) -> ListObject:
        current = self.get_list(list_id)
        to_remove = set(items)
        remaining = [v for v in current.items if v not in to_remove]
        self._patch_entries(list_id, current.kind, current.description, remaining)
        return self.get_list(list_id)

    # -- alerts (detections, always scoped to their generating rule) -------
    def _alert_from_entry(self, rule_id: str, entry: Dict[str, Any]) -> Alert:
        detection_id = _id_from_name(entry.get("name", ""))
        return Alert(
            id=f"{rule_id}:{detection_id}",
            title=entry.get("type", "Detection"),
            severity=str(entry.get("alertState", "unknown")),
            status=entry.get("alertState", "unknown"),
            rule_id=rule_id,
            timestamp=(entry.get("timeWindow") or {}).get("endTime"),
            raw=entry,
        )

    def list_alerts(self, **filters: Any) -> List[Alert]:
        rule_id = filters.get("rule_id")
        if not rule_id:
            raise ValueError(
                "Chronicle list_alerts requires a rule_id filter -- detections only exist "
                "scoped to the rule that generated them (there's no bare, rule-less detection)."
            )
        data = self._request_json(
            "GET", f"{self._instance_path}/rules/{rule_id}/detections", params={"pageSize": filters.get("limit", 100)}
        )
        return [self._alert_from_entry(rule_id, e) for e in data.get("detections", [])]

    def get_alert(self, alert_id: str) -> Alert:
        rule_id, _, detection_id = alert_id.partition(":")
        entry = self._request_json(
            "GET", f"{self._instance_path}/rules/{rule_id}/detections/{detection_id}"
        )
        return self._alert_from_entry(rule_id, entry)

    def set_alert_status(self, alert_id: str, status: str) -> Alert:
        raise UnsupportedOperationError(
            "Chronicle detections have no simple settable status field via this API -- "
            "triage/status changes happen through Chronicle's separate SOAR/case-management "
            "module, not the core detections resource."
        )

    # -- events / raw queries (synchronous UDM search) ----------------------
    def run_query(
        self, query: str, start: Optional[str] = None, end: Optional[str] = None, limit: int = 100, **kwargs: Any
    ) -> QueryResult:
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(hours=1)
        params = {
            "query": query,
            "time_range.start_time": start or start_dt.strftime(_RFC3339),
            "time_range.end_time": end or end_dt.strftime(_RFC3339),
            "limit": limit,
        }
        data = self._request_json("GET", f"{self._instance_path}:udmSearch", params=params)
        events = data.get("events", [])
        rows = [e.get("udm", {}) for e in events]
        columns = sorted({key for row in rows for key in row.keys()})
        return QueryResult(columns=columns, rows=rows, raw=data)
