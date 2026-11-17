"""Retry, backoff, Retry-After and non-retryable errors of the shared HTTP client."""

import json

import pytest
import requests

from cybersentinel.http import HttpClient, SourceUnavailableError


class FakeSession:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        status, headers = answer if isinstance(answer, tuple) else (answer, {})
        r = requests.Response()
        r.status_code = status
        r.headers.update(headers)
        r._content = json.dumps({"ok": status < 400}).encode()
        return r


def make(answers, **kw):
    sleeps = []
    client = HttpClient("test", session=FakeSession(answers), sleep=sleeps.append, **kw)
    return client, sleeps


def test_retries_server_errors_with_exponential_backoff():
    client, sleeps = make([503, 502, 200])
    assert client.get_json("https://x") == {"ok": True}
    assert sleeps == [2.0, 4.0]
    assert client.requests_made == 3 and client.errors == 2


def test_network_errors_are_retried():
    client, _ = make([requests.ConnectionError("reset"), requests.Timeout("slow"), 200])
    assert client.get_json("https://x") == {"ok": True}


def test_retry_after_header_is_respected():
    client, sleeps = make([(429, {"Retry-After": "30"}), 200])
    client.get_json("https://x")
    assert sleeps == [30.0]


def test_non_retryable_error_fails_immediately():
    client, sleeps = make([404])
    with pytest.raises(SourceUnavailableError, match="not retryable"):
        client.get_json("https://x")
    assert sleeps == []


def test_gives_up_after_max_retries():
    client, _ = make([503] * 3, max_retries=3)
    with pytest.raises(SourceUnavailableError, match="after 3 attempts"):
        client.get_json("https://x")


def test_error_message_never_contains_query_string_secrets():
    client, _ = make([404])
    with pytest.raises(SourceUnavailableError) as err:
        client.get_json("https://x/api?apiKey=SECRET123")
    assert "SECRET123" not in str(err.value)
