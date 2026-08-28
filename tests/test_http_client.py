import httpx
import pytest

from conftest import make_client
from triage_lens.errors import FetchError
from triage_lens.http_client import get_json


def test_成功すれば1回の通信で返る(recorded_sleeps):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    with make_client(handler) as client:
        assert get_json("https://example.invalid/data", client=client) == {"ok": True}

    assert len(requests) == 1
    assert recorded_sleeps == []


def test_一時的な失敗はリトライして成功する(recorded_sleeps):
    attempts = []

    def handler(request):
        attempts.append(request)
        if len(attempts) < 3:
            raise httpx.ConnectError("接続できません")
        return httpx.Response(200, json={"ok": True})

    with make_client(handler) as client:
        assert get_json("https://example.invalid/data", client=client) == {"ok": True}

    assert len(attempts) == 3
    assert recorded_sleeps == [1.0, 2.0]


def test_3回失敗したら諦めてFetchErrorになる(recorded_sleeps):
    attempts = []

    def handler(request):
        attempts.append(request)
        raise httpx.ConnectError("接続できません")

    with make_client(handler) as client:
        with pytest.raises(FetchError, match="3回失敗しました"):
            get_json("https://example.invalid/data", client=client)

    assert len(attempts) == 3
    assert recorded_sleeps == [1.0, 2.0]


@pytest.mark.parametrize("status", [429, 500, 503])
def test_エラー応答もリトライ対象(status, recorded_sleeps):
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(status)

    with make_client(handler) as client:
        with pytest.raises(FetchError):
            get_json("https://example.invalid/data", client=client)

    assert len(attempts) == 3


def test_JSONとして壊れた応答もリトライ対象():
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(200, content=b"<html>error</html>")

    with make_client(handler) as client:
        with pytest.raises(FetchError):
            get_json("https://example.invalid/data", client=client)

    assert len(attempts) == 3


def test_リトライ回数と待機時間は調整できる(recorded_sleeps):
    def handler(request):
        raise httpx.ConnectError("接続できません")

    with make_client(handler) as client:
        with pytest.raises(FetchError, match="5回失敗しました"):
            get_json("https://example.invalid/x", client=client, max_attempts=5, backoff_base=0.5)

    assert recorded_sleeps == [0.5, 1.0, 2.0, 4.0]


def test_クエリパラメータが送られる():
    seen = []

    def handler(request):
        seen.append(request.url)
        return httpx.Response(200, json={})

    with make_client(handler) as client:
        get_json("https://example.invalid/data", params={"cve": "CVE-2020-0001"}, client=client)

    assert seen[0].params["cve"] == "CVE-2020-0001"
