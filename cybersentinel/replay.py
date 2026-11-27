"""Offline replay of recorded API responses.

`ReplaySession` has the same `.request(method, url, ...)` interface as `requests.Session`
and answers from the fixture files in tests/fixtures/api/ (trimmed REAL responses captured by
a live run — see scripts/make_fixtures.py). It is used by:
- the automated tests and the CI dbt job, which must not depend on the public APIs being up;
- `python -m cybersentinel run --replay`, a clearly-labelled offline demo mode.

It never fabricates data: a request it has no recording for gets an empty, well-formed
answer (or 404 for an unknown OSV advisory), exactly like the real API would.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests

from cybersentinel.settings import PROJECT_ROOT

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "api"


class ReplaySession:
    is_replay = True

    def __init__(self, fixtures: Path = FIXTURES, overrides: dict | None = None) -> None:
        self.fixtures = Path(fixtures)
        self.overrides = overrides or {}  # name -> body, lets tests inject edge cases
        self.calls: list[tuple[str, str, dict]] = []

    def _load(self, name: str):
        if name in self.overrides:
            return self.overrides[name]
        return json.loads((self.fixtures / name).read_text(encoding="utf-8"))

    @staticmethod
    def _response(status: int, body) -> requests.Response:
        r = requests.Response()
        r.status_code = status
        r._content = json.dumps(body).encode("utf-8")
        r.headers["Content-Type"] = "application/json"
        return r

    def request(self, method: str, url: str, params=None, json=None, **_):  # noqa: A002 - mirrors requests
        params = dict(params or {})
        self.calls.append((method, url, params))
        parsed = urlparse(url)
        params.update({k: v[0] for k, v in parse_qs(parsed.query).items()})
        host, path = parsed.netloc, parsed.path

        if "cisa.gov" in host:
            return self._response(200, self._load("cisa_kev.json"))

        if "nvd.nist.gov" in host:
            page = self._load("nvd_page.json")
            items = page["vulnerabilities"]
            if "cveId" in params:
                items = [i for i in items if i["cve"]["id"] == params["cveId"]]
            elif "hasKev" in params:
                kev = {v["cveID"] for v in self._load("cisa_kev.json")["vulnerabilities"]}
                items = [i for i in items if i["cve"]["id"] in kev]
            start = int(params.get("startIndex", 0))
            return self._response(
                200,
                {
                    **page,
                    "startIndex": start,
                    "totalResults": len(items),
                    "resultsPerPage": len(items[start:]),
                    "vulnerabilities": items[start:],
                },
            )

        if "osv.dev" in host and path.endswith("/querybatch"):
            recorded = self._load("osv_querybatch.json")
            by_pkg = {
                (q["package"]["name"], q["package"]["ecosystem"], q["version"]): r
                for q, r in zip(recorded["queries"], recorded["results"], strict=True)
            }
            results = [
                by_pkg.get((q["package"]["name"], q["package"]["ecosystem"], q["version"]), {})
                for q in (json or {}).get("queries", [])
            ]
            return self._response(200, {"results": results})

        if "osv.dev" in host and "/vulns/" in path:
            osv_id = path.rsplit("/", 1)[-1]
            details = self._load("osv_vulns.json")
            return (
                self._response(200, details[osv_id])
                if osv_id in details
                else self._response(404, {"code": 5, "message": "Bug not found."})
            )

        if "first.org" in host:
            wanted = set((params.get("cve") or "").split(","))
            data = [row for row in self._load("epss.json")["data"] if row["cve"] in wanted]
            if params.get("scope") != "time-series":
                data = [{k: v for k, v in row.items() if k != "time-series"} for row in data]
            return self._response(
                200,
                {
                    "status": "OK",
                    "status-code": 200,
                    "total": len(data),
                    "offset": 0,
                    "limit": 100,
                    "data": data,
                },
            )

        return self._response(404, {"message": f"no recording for {url}"})
