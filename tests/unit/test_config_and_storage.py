"""Watchlist parsing, raw-layer immutability and log secret masking."""

import logging
from datetime import UTC, datetime

import pytest

from cybersentinel.ingestion.base import RawPayload
from cybersentinel.ingestion.watchlist import WatchlistError, load_watchlist
from cybersentinel.logs import SecretMaskFilter
from cybersentinel.settings import PROJECT_ROOT
from cybersentinel.storage.raw_store import LocalWriter, RawStore


def test_project_watchlist_is_valid():
    packages = load_watchlist(PROJECT_ROOT / "config" / "watchlist.yaml")
    assert len(packages) >= 3
    assert {p.ecosystem for p in packages} >= {"PyPI", "npm"}


@pytest.mark.parametrize(
    "content",
    [
        "packages: []",
        "packages:\n  - {name: Django, ecosystem: PyPI}",
        "packages:\n  - {name: Django, ecosystem: Pip, version: '1'}",
        "packages:\n  - {name: a, ecosystem: npm, version: '1'}\n  - {name: a, ecosystem: npm, version: '1'}",
    ],
)
def test_invalid_watchlists_are_refused(tmp_path, content):
    path = tmp_path / "w.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(WatchlistError):
        load_watchlist(path)


def test_raw_snapshots_are_never_overwritten_and_can_be_replayed(tmp_path):
    store = RawStore(LocalWriter(tmp_path))
    started = datetime(2026, 11, 16, tzinfo=UTC)
    info = store.save_payloads("cisa_kev", "run1", started, [RawPayload("catalog", {"count": 0})], {})
    assert info["prefix"] == "raw/cisa_kev/ingest_date=2026-11-16/run_id=run1"
    assert store.load_payloads("cisa_kev", info["prefix"])[0].body == {"count": 0}
    with pytest.raises(FileExistsError):
        store.save_payloads("cisa_kev", "run1", started, [RawPayload("catalog", {"count": 1})], {})


def test_api_key_is_masked_in_logs(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "super-secret-key")
    record = logging.LogRecord("x", logging.INFO, "", 0, "calling ?apiKey=%s", ("super-secret-key",), None)
    SecretMaskFilter().filter(record)
    assert "super-secret-key" not in record.getMessage()
