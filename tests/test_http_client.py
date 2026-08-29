from datetime import UTC, datetime

import httpx
import pytest

from conftest import make_client
from triage_lens import http_client
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


# --- post_json の実行時間の上限 -----------------------------------------


def test_残り時間を超える待機はしない(recorded_sleeps, monkeypatch):
    monkeypatch.setattr(http_client, "monotonic", lambda: 0.0)

    def handler(request):
        return httpx.Response(429, headers={"retry-after": "60"}, json={"error": "x"})

    with make_client(handler) as client, pytest.raises(FetchError):
        http_client.post_json("https://example.test/x", payload={}, client=client, time_budget=5.0)

    assert recorded_sleeps == [5.0, 5.0]


def test_残り時間を使い切ったらリトライしない(recorded_sleeps, monkeypatch):
    clock = iter([0.0, 0.0, 999.0, 999.0])
    monkeypatch.setattr(http_client, "monotonic", lambda: next(clock))
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(500, json={"error": "x"})

    with make_client(handler) as client, pytest.raises(FetchError):
        http_client.post_json("https://example.test/x", payload={}, client=client, time_budget=10.0)

    assert len(attempts) == 1


def test_時間の上限を渡さなければ従来どおり待つ(recorded_sleeps):
    def handler(request):
        return httpx.Response(500, json={"error": "x"})

    with make_client(handler) as client, pytest.raises(FetchError):
        http_client.post_json("https://example.test/x", payload={}, client=client)

    assert recorded_sleeps == [1.0, 2.0]


# --- retry-after の書き方（RFC 9110 は2種類を認める） --------------------


def _retry_after(value):
    return http_client.retry_after_seconds(httpx.Response(429, headers={"retry-after": value}))


def test_retry_afterの秒数形式を読む():
    assert _retry_after("7") == 7.0


def test_retry_afterのHTTP_date形式を読む(monkeypatch):
    monkeypatch.setattr(http_client, "now", lambda: datetime(2026, 10, 21, 7, 27, 30, tzinfo=UTC))

    assert _retry_after("Wed, 21 Oct 2026 07:28:00 GMT") == 30.0


def test_過ぎた時刻のHTTP_dateは待たない(monkeypatch):
    monkeypatch.setattr(http_client, "now", lambda: datetime(2026, 10, 22, 0, 0, 0, tzinfo=UTC))

    assert _retry_after("Wed, 21 Oct 2026 07:28:00 GMT") == 0.0


def test_遠すぎるHTTP_dateは上限で頭打ちにする(monkeypatch):
    monkeypatch.setattr(http_client, "now", lambda: datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC))

    assert _retry_after("Wed, 21 Oct 2026 07:28:00 GMT") == http_client.MAX_RETRY_AFTER_SECONDS


def test_読めないretry_afterはバックオフに任せる():
    # HTTP ヘッダは ASCII しか運べないため、壊れた値も ASCII で表す
    assert _retry_after("later") is None
    assert _retry_after("nan") is None
    assert _retry_after("") is None


# --- 1リクエストのタイムアウト配分 --------------------------------------


def test_残り時間はフェーズ数で割って配分する():
    with httpx.Client(timeout=20.0) as client:
        timeout = http_client._timeout(client, 8.0)

    # 接続 / 送信 / 受信 / プール待ちの合計が残り時間を超えない
    assert timeout.read * http_client.TIMEOUT_PHASES <= 8.0
    assert timeout.connect == timeout.read == timeout.write == timeout.pool


def test_残り時間が十分ならクライアントの既定を超えない():
    with httpx.Client(timeout=20.0) as client:
        timeout = http_client._timeout(client, 4000.0)

    assert timeout.read == 20.0


# --- リトライして意味のあるステータスかどうか ---------------------------


@pytest.mark.parametrize("status", [400, 401, 403, 404, 405, 413, 415, 422])
def test_やり直しても変わらない4xxはリトライしない(status):
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(status, json={"error": "x"})

    with make_client(handler) as client, pytest.raises(FetchError):
        http_client.post_json("https://example.test/x", payload={}, client=client)

    assert len(attempts) == 1


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503])
def test_一時的な失敗はリトライする(status):
    attempts = []

    def handler(request):
        attempts.append(request)
        return httpx.Response(status, json={"error": "x"})

    with make_client(handler) as client, pytest.raises(FetchError):
        http_client.post_json("https://example.test/x", payload={}, client=client)

    assert len(attempts) == 3


def test_クライアントのフェーズごとの設定を伸ばさない():
    timeout = httpx.Timeout(connect=0.1, read=20.0, write=5.0, pool=20.0)
    with httpx.Client(timeout=timeout) as client:
        capped = http_client._timeout(client, 8.0)

    assert capped.connect == 0.1
    assert capped.write == 2.0
    assert capped.read == 2.0
