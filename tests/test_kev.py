import json
import os

import httpx
import pytest

from conftest import make_client
from triage_lens.kev import (
    SOURCE_CACHE,
    SOURCE_NETWORK,
    SOURCE_STALE_CACHE,
    SOURCE_UNAVAILABLE,
    default_cache_path,
    load_kev_ids,
)

CATALOG = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.08.01",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2"},
        {"cveID": "CVE-2014-0160", "vendorProject": "OpenSSL", "product": "OpenSSL"},
    ],
}


def _handler_returning(payload, calls):
    def handler(request):
        calls.append(request.url)
        return httpx.Response(200, json=payload)

    return handler


def _failing_handler(calls):
    def handler(request):
        calls.append(request.url)
        raise httpx.ConnectError("接続できません")

    return handler


def test_初回はダウンロードしてキャッシュに保存する(tmp_path):
    calls = []
    cache_path = tmp_path / "kev.json"

    with make_client(_handler_returning(CATALOG, calls)) as client:
        ids, source = load_kev_ids(client=client, cache_path=cache_path, now=1_000.0)

    assert ids == {"CVE-2021-44228", "CVE-2014-0160"}
    assert source == SOURCE_NETWORK
    assert len(calls) == 1
    assert json.loads(cache_path.read_text(encoding="utf-8")) == CATALOG


def test_24時間以内はキャッシュを使い通信しない(tmp_path):
    cache_path = tmp_path / "kev.json"
    cache_path.write_text(json.dumps(CATALOG), encoding="utf-8")
    os.utime(cache_path, (1_000.0, 1_000.0))

    def handler(request):  # pragma: no cover - 呼ばれないことを検証する
        raise AssertionError("キャッシュがあるので通信してはいけない")

    with make_client(handler) as client:
        ids, source = load_kev_ids(client=client, cache_path=cache_path, now=1_000.0 + 23 * 3600)

    assert ids == {"CVE-2021-44228", "CVE-2014-0160"}
    assert source == SOURCE_CACHE


def test_24時間を過ぎたら再取得する(tmp_path):
    calls = []
    cache_path = tmp_path / "kev.json"
    cache_path.write_text(
        json.dumps({"vulnerabilities": [{"cveID": "CVE-2000-0001"}]}), encoding="utf-8"
    )
    os.utime(cache_path, (1_000.0, 1_000.0))

    with make_client(_handler_returning(CATALOG, calls)) as client:
        ids, source = load_kev_ids(client=client, cache_path=cache_path, now=1_000.0 + 25 * 3600)

    assert ids == {"CVE-2021-44228", "CVE-2014-0160"}
    assert source == SOURCE_NETWORK
    assert len(calls) == 1


def test_キャッシュが壊れていたら取得し直す(tmp_path):
    calls = []
    cache_path = tmp_path / "kev.json"
    cache_path.write_text("{壊れている", encoding="utf-8")

    with make_client(_handler_returning(CATALOG, calls)) as client:
        ids, source = load_kev_ids(client=client, cache_path=cache_path, now=1_000.0)

    assert ids == {"CVE-2021-44228", "CVE-2014-0160"}
    assert source == SOURCE_NETWORK


def test_通信に失敗したら期限切れキャッシュで代用する(tmp_path):
    calls = []
    cache_path = tmp_path / "kev.json"
    cache_path.write_text(json.dumps(CATALOG), encoding="utf-8")
    os.utime(cache_path, (1_000.0, 1_000.0))

    with make_client(_failing_handler(calls)) as client:
        ids, source = load_kev_ids(client=client, cache_path=cache_path, now=1_000.0 + 100 * 3600)

    assert ids == {"CVE-2021-44228", "CVE-2014-0160"}
    assert source == SOURCE_STALE_CACHE
    assert len(calls) == 3  # リトライしたうえで諦めている


def test_キャッシュも通信も無ければ不明として返す(tmp_path):
    calls = []

    with make_client(_failing_handler(calls)) as client:
        ids, source = load_kev_ids(client=client, cache_path=tmp_path / "kev.json", now=1_000.0)

    assert ids is None
    assert source == SOURCE_UNAVAILABLE


def test_想定外の応答はキャッシュせず不明として返す(tmp_path):
    cache_path = tmp_path / "kev.json"

    def handler(request):
        return httpx.Response(200, json={"message": "not the catalog"})

    with make_client(handler) as client:
        ids, source = load_kev_ids(client=client, cache_path=cache_path, now=1_000.0)

    assert ids is None
    assert source == SOURCE_UNAVAILABLE
    assert not cache_path.exists()


def test_カタログ内の一部が壊れていても大半が読めれば使う(tmp_path):
    payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2020-0001"},
            {"cveID": "CVE-2020-0002"},
            {"cveID": "CVE-2020-0003"},
            "junk",
        ]
    }

    with make_client(_handler_returning(payload, [])) as client:
        ids, _ = load_kev_ids(client=client, cache_path=tmp_path / "kev.json", now=1_000.0)

    assert ids == {"CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"}


@pytest.mark.parametrize(
    ("payload", "説明"),
    [
        ({"count": 1200, "vulnerabilities": []}, "空のカタログ"),
        ({"count": 1200, "vulnerabilities": [{"broken": True}]}, "CVE IDを読めないカタログ"),
        (
            {"vulnerabilities": [{"cveID": "CVE-2020-0001"}, "junk", {}, {}]},
            "大半のエントリが壊れているカタログ",
        ),
    ],
)
def test_中身が壊れたカタログは取得失敗として扱いキャッシュしない(tmp_path, payload, 説明):
    """HTTP 200 でも中身が異常なら、24時間キャッシュに残してはいけない。"""
    cache_path = tmp_path / "kev.json"

    with make_client(_handler_returning(payload, [])) as client:
        ids, source = load_kev_ids(client=client, cache_path=cache_path, now=1_000.0)

    assert ids is None, 説明
    assert source == SOURCE_UNAVAILABLE
    assert not cache_path.exists()


def test_壊れたカタログを掴んでも期限切れキャッシュがあればそちらを使う(tmp_path):
    cache_path = tmp_path / "kev.json"
    cache_path.write_text(json.dumps(CATALOG), encoding="utf-8")
    os.utime(cache_path, (1_000.0, 1_000.0))

    with make_client(_handler_returning({"vulnerabilities": []}, [])) as client:
        ids, source = load_kev_ids(client=client, cache_path=cache_path, now=1_000.0 + 100 * 3600)

    assert ids == {"CVE-2021-44228", "CVE-2014-0160"}
    assert source == SOURCE_STALE_CACHE


def test_キャッシュ保存先が作れなくても処理は続行する(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("", encoding="utf-8")

    with make_client(_handler_returning(CATALOG, [])) as client:
        ids, source = load_kev_ids(client=client, cache_path=blocker / "kev.json", now=1_000.0)

    assert ids == {"CVE-2021-44228", "CVE-2014-0160"}
    assert source == SOURCE_NETWORK


def test_既定のキャッシュ先はホーム配下():
    path = default_cache_path()

    assert path.name == "kev.json"
    assert path.parent.name == "triage-lens"
