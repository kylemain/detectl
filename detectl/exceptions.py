"""Exception hierarchy shared by every adapter."""
from __future__ import annotations

from typing import Optional


class DetectlError(Exception):
    """Base class for all detectl errors."""


class ConfigError(DetectlError):
    """Raised when adapter configuration is missing or invalid."""


class AuthenticationError(DetectlError):
    """Raised when a platform rejects credentials or a token exchange fails."""


class NotFoundError(DetectlError):
    """Raised when a requested resource (rule, list, alert, ...) doesn't exist."""


class APIError(DetectlError):
    """Raised for any non-2xx response not covered by a more specific error."""

    def __init__(self, message: str, status_code: Optional[int] = None, body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class UnsupportedOperationError(DetectlError):
    """Raised when a platform's API has no real equivalent for the requested
    operation. Adapters should raise this rather than faking support -- e.g.
    CrowdStrike's Falcon API has no ad-hoc event-search endpoint comparable
    to Splunk SPL / Elasticsearch DSL / Sentinel KQL, so
    CrowdStrikeAdapter.run_query() raises this instead of pretending."""
