"""One HTTP client shared by all connectors.

Responsibilities:
- a request timeout on every call (no request can hang the pipeline forever);
- retries with exponential backoff on network errors and on 429 / 5xx responses;
- respect of the server's Retry-After header when present;
- a minimum interval between two requests to the same API (client-side rate limiting —
  NVD allows 5 requests per 30 s without a key, 50 with a key);
- a count of requests and errors, reported in the run metadata.

Errors that retrying cannot fix (400, 401, 403, 404) are raised immediately.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests

from cybersentinel.logs import get_logger

log = get_logger("http")

RETRY_STATUSES = {429, 500, 502, 503, 504}
USER_AGENT = "CyberSentinel/0.1 (academic DataOps project; defensive vulnerability analytics)"


class SourceUnavailableError(RuntimeError):
    """The API could not be reached after all retries. The source is marked failed for this run."""


@dataclass
class HttpClient:
    name: str
    min_interval: float = 0.0
    timeout: int = 60
    max_retries: int = 5
    backoff_base: float = 2.0
    backoff_max: float = 60.0
    headers: dict[str, str] = field(default_factory=dict)
    session: Any = None  # a requests.Session, or a test double with the same .request() signature
    sleep: Any = time.sleep
    retry_statuses: frozenset[int] = frozenset(RETRY_STATUSES)
    requests_made: int = 0
    errors: int = 0
    _last_request_at: float = 0.0

    def __post_init__(self) -> None:
        if self.session is None:
            self.session = requests.Session()
        if getattr(self.session, "is_replay", False):
            self.min_interval = 0.0  # recorded responses: no remote server to protect
        self.headers = {"User-Agent": USER_AGENT, **self.headers}

    def _throttle(self) -> None:
        if self.min_interval <= 0:
            return
        wait = self._last_request_at + self.min_interval - time.monotonic()
        if wait > 0:
            self.sleep(wait)

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        last_problem = ""
        headers = {**self.headers, **kwargs.pop("headers", {})}
        for attempt in range(1, self.max_retries + 1):
            self._throttle()
            self._last_request_at = time.monotonic()
            self.requests_made += 1
            try:
                response = self.session.request(method, url, timeout=self.timeout, headers=headers, **kwargs)
            except (requests.ConnectionError, requests.Timeout) as exc:
                self.errors += 1
                last_problem = f"{type(exc).__name__}: {exc}"
                delay = min(self.backoff_base**attempt, self.backoff_max)
            else:
                if response.status_code < 400:
                    return response
                self.errors += 1
                last_problem = f"HTTP {response.status_code}"
                if response.status_code not in self.retry_statuses:
                    raise SourceUnavailableError(
                        f"{self.name}: {method} {_safe_url(url)} returned HTTP {response.status_code} "
                        f"(not retryable): {response.text[:200]}"
                    )
                retry_after = response.headers.get("Retry-After")
                backoff = min(self.backoff_base**attempt, self.backoff_max)
                # Honour Retry-After when the server sends one, but never retry faster than our backoff.
                delay = max(float(retry_after), backoff) if retry_after and retry_after.isdigit() else backoff
            if attempt < self.max_retries:
                log.warning(
                    "request failed, retrying",
                    extra={
                        "source": self.name,
                        "attempt": attempt,
                        "problem": last_problem,
                        "retry_in_s": delay,
                    },
                )
                self.sleep(delay)
        raise SourceUnavailableError(
            f"{self.name}: {method} {_safe_url(url)} failed after {self.max_retries} attempts ({last_problem})"
        )

    def get_json(self, url: str, **kwargs: Any) -> Any:
        return self.request("GET", url, **kwargs).json()

    def post_json(self, url: str, payload: Any, **kwargs: Any) -> Any:
        return self.request("POST", url, json=payload, **kwargs).json()


def _safe_url(url: str) -> str:
    return url.split("?")[0]
