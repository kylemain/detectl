"""Shared test doubles: a minimal stand-in for requests.Session so adapter
tests never touch the network. Each adapter test wires up a small
dict/callable "handler" that maps (method, path) -> canned JSON response."""
from __future__ import annotations

import json as _json
from typing import Any, Callable, Dict, Optional, Tuple


class FakeResponse:
    def __init__(self, status_code: int = 200, json_data: Any = None, text: Optional[str] = None):
        self.status_code = status_code
        self._json_data = json_data
        if text is not None:
            self.text = text
        elif json_data is not None:
            self.text = _json.dumps(json_data)
        else:
            self.text = ""
        self.content = self.text.encode("utf-8") if self.text else b""

    def json(self) -> Any:
        return self._json_data


Handler = Callable[..., Any]


class FakeSession:
    """Records every call and dispatches to `handler(method, url, **kwargs)`,
    which may return a FakeResponse or a (status_code, json_data) tuple."""

    def __init__(self, handler: Handler):
        self.handler = handler
        self.headers: Dict[str, str] = {}
        self.verify = True
        self.calls = []

    def request(self, method: str, url: str, **kwargs) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        result = self.handler(method, url, **kwargs)
        if isinstance(result, FakeResponse):
            return result
        status_code, json_data = result
        return FakeResponse(status_code=status_code, json_data=json_data)

    def post(self, url: str, **kwargs) -> FakeResponse:
        return self.request("POST", url, **kwargs)

    def get(self, url: str, **kwargs) -> FakeResponse:
        return self.request("GET", url, **kwargs)


def _lookup(routes: Dict[Tuple[str, str], Any], method: str, path: str) -> Optional[Any]:
    key = (method, path)
    if key in routes:
        return routes[key]
    # Support a trailing "*" wildcard in the path pattern for routes with a
    # dynamically-generated final path segment (e.g. a server-side uuid4).
    for (route_method, route_path), value in routes.items():
        if route_method == method and route_path.endswith("*") and path.startswith(route_path[:-1]):
            return value
    return None


def multi_route_handler(routes_by_base: Dict[str, Dict[Tuple[str, str], Any]]) -> Handler:
    """Like route_handler, but for adapters that talk to more than one host
    (e.g. Sentinel's separate login/ARM/Log Analytics endpoints)."""

    def handler(method: str, url: str, **kwargs) -> Any:
        for base_url, routes in routes_by_base.items():
            if url.startswith(base_url):
                path = url[len(base_url):]
                value = _lookup(routes, method, path)
                if value is not None:
                    return value() if callable(value) else value
        raise AssertionError(f"unhandled request: {method} {url} (kwargs={kwargs})")

    return handler


def route_handler(base_url: str, routes: Dict[Tuple[str, str], Any], default=None) -> Handler:
    """Build a handler from a {(method, path_suffix): response} dict, where
    path_suffix is the URL with base_url stripped off (query strings are
    passed separately via kwargs['params'], so they're not part of the
    path). `response` may be a FakeResponse, a (status, json) tuple, or a
    zero-arg callable returning either (for routes that need fresh state
    each call, e.g. counters). A path pattern ending in "*" matches any
    dynamically-generated final path segment."""

    def handler(method: str, url: str, **kwargs) -> Any:
        path = url[len(base_url):] if url.startswith(base_url) else url
        value = _lookup(routes, method, path)
        if value is not None:
            return value() if callable(value) else value
        if default is not None:
            return default() if callable(default) else default
        raise AssertionError(f"unhandled request: {method} {path} (kwargs={kwargs})")

    return handler
