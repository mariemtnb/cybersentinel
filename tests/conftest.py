"""Shared pytest fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cybersentinel.ingestion.base import RawPayload

FIXTURES = Path(__file__).parent / "fixtures"
API = FIXTURES / "api"


def load_api(name: str):
    return json.loads((API / name).read_text(encoding="utf-8"))


@pytest.fixture
def kev_payload():
    return [RawPayload("catalog", load_api("cisa_kev.json"))]


@pytest.fixture
def nvd_payload():
    return [RawPayload("modified_0001", load_api("nvd_page.json"))]


@pytest.fixture
def epss_payload():
    return [RawPayload("batch_0001", load_api("epss.json"))]


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    """Point every data path at a temporary directory and use the fixture watchlist."""
    monkeypatch.setenv("CYBERSENTINEL_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WATCHLIST_PATH", str(FIXTURES / "watchlist.yaml"))
    monkeypatch.setenv("RAW_STORAGE", "local")
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("CYBERSENTINEL_WAREHOUSE", raising=False)
    monkeypatch.delenv("CYBERSENTINEL_PUBLISHED", raising=False)
    monkeypatch.delenv("CYBERSENTINEL_OPS_DB", raising=False)
    return tmp_path
