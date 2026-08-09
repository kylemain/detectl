"""Abstract adapter interface every platform adapter implements, plus a
small shared HTTP helper mixin so concrete adapters don't each reimplement
error handling around `requests`.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import requests

from ..exceptions import APIError, AuthenticationError, NotFoundError
from ..models import Alert, ListObject, QueryResult, Rule


class HttpMixin:
    """Thin wrapper around a `requests.Session` with consistent error
    translation. Adapters call `self._request(...)` instead of using
    `self.session` directly, so tests can inject a fake `session` object
    (see tests/adapters/*.py) without ever hitting the network."""

    session: requests.Session
    timeout: float = 30.0

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        try:
            resp = self.session.request(method, url, **kwargs)
        except requests.RequestException as exc:  # network-level failure
            raise APIError(f"{method} {url} failed: {exc}") from exc

        if resp.status_code == 401 or resp.status_code == 403:
            raise AuthenticationError(
                f"{method} {url} -> {resp.status_code}: authentication/authorization failed"
            )
        if resp.status_code == 404:
            raise NotFoundError(f"{method} {url} -> 404 not found")
        if resp.status_code >= 400:
            raise APIError(
                f"{method} {url} -> {resp.status_code}",
                status_code=resp.status_code,
                body=resp.text,
            )
        return resp

    def _request_json(self, method: str, url: str, **kwargs) -> Any:
        resp = self._request(method, url, **kwargs)
        if not resp.content:
            return None
        return resp.json()


class SIEMAdapter(HttpMixin, ABC):
    """Common interface for every SIEM/EDR platform adapter.

    Resource categories, matching what a detection engineer actually tunes
    day to day: rules (detections), lists (watchlists / exclusion lists /
    allow-block lists / suppression lists / KV stores), alerts, and raw
    event/query access for ad-hoc investigation.

    Not every platform has a clean equivalent for every operation -- when
    that's genuinely true (e.g. CrowdStrike has no generic ad-hoc query
    language), the adapter should raise UnsupportedOperationError rather
    than faking support.
    """

    name: str

    # -- connectivity ------------------------------------------------
    @abstractmethod
    def test_connection(self) -> bool:
        """Return True if credentials/connectivity are valid, else raise."""

    # -- rules ---------------------------------------------------------
    @abstractmethod
    def list_rules(self, **filters: Any) -> List[Rule]:
        ...

    @abstractmethod
    def get_rule(self, rule_id: str) -> Rule:
        ...

    @abstractmethod
    def create_rule(self, rule: Rule) -> Rule:
        ...

    @abstractmethod
    def update_rule(self, rule_id: str, rule: Rule) -> Rule:
        ...

    @abstractmethod
    def delete_rule(self, rule_id: str) -> None:
        ...

    @abstractmethod
    def set_rule_enabled(self, rule_id: str, enabled: bool) -> Rule:
        ...

    def enable_rule(self, rule_id: str) -> Rule:
        return self.set_rule_enabled(rule_id, True)

    def disable_rule(self, rule_id: str) -> Rule:
        return self.set_rule_enabled(rule_id, False)

    # -- lists (watchlists / exclusion / allow-block / suppression / kv) --
    @abstractmethod
    def list_lists(self, kind: Optional[str] = None) -> List[ListObject]:
        ...

    @abstractmethod
    def get_list(self, list_id: str) -> ListObject:
        ...

    @abstractmethod
    def create_list(self, list_obj: ListObject) -> ListObject:
        ...

    @abstractmethod
    def update_list(self, list_id: str, list_obj: ListObject) -> ListObject:
        ...

    @abstractmethod
    def delete_list(self, list_id: str) -> None:
        ...

    @abstractmethod
    def add_list_items(self, list_id: str, items: List[str]) -> ListObject:
        ...

    @abstractmethod
    def remove_list_items(self, list_id: str, items: List[str]) -> ListObject:
        ...

    # -- alerts ----------------------------------------------------------
    @abstractmethod
    def list_alerts(self, **filters: Any) -> List[Alert]:
        ...

    @abstractmethod
    def get_alert(self, alert_id: str) -> Alert:
        ...

    @abstractmethod
    def set_alert_status(self, alert_id: str, status: str) -> Alert:
        ...

    # -- events / raw queries --------------------------------------------
    @abstractmethod
    def run_query(self, query: str, **kwargs: Any) -> QueryResult:
        """Execute a raw, platform-native query (SPL / ES DSL / KQL / ...)
        and return normalized results. Adapters with no ad-hoc query
        capability should raise UnsupportedOperationError."""

    def search_events(
        self, query: str, start: Optional[str] = None, end: Optional[str] = None, limit: int = 100
    ) -> QueryResult:
        """Convenience wrapper around run_query for time-bounded event
        search. Default implementation just forwards to run_query; adapters
        can override if their time-filtering needs special handling."""
        return self.run_query(query, start=start, end=end, limit=limit)
