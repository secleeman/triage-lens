import httpx
import pytest

from conftest import make_client
from triage_lens.epss import fetch_epss_scores


def _response(entries):
    return httpx.Response(200, json={"status": "OK", "data": entries})


def test_複数CVEを1回の通信でまとめて問い合わせる():
    seen = []

    def handler(request):
        seen.append(request.url)
        return _response(
            [
                {"cve": "CVE-2020-0001", "epss": "0.12345", "percentile": "0.9"},
                {"cve": "CVE-2020-0002", "epss": "0.00042", "percentile": "0.1"},
            ]
        )

    with make_client(handler) as client:
        scores, complete = fetch_epss_scores(["CVE-2020-0001", "CVE-2020-0002"], client=client)

    assert len(seen) == 1
    assert seen[0].params["cve"] == "CVE-2020-0001,CVE-2020-0002"
    assert scores == {"CVE-2020-0001": 0.12345, "CVE-2020-0002": 0.00042}
    assert complete is True


def test_件数が多いときはチャンクに分けて問い合わせる():
    sent = []

    def handler(request):
        cve_param = request.url.params["cve"]
        sent.append(cve_param.split(","))
        return _response([{"cve": cve_id, "epss": "0.5"} for cve_id in cve_param.split(",")])

    cve_ids = [f"CVE-2020-{i:04d}" for i in range(150)]
    with make_client(handler) as client:
        scores, complete = fetch_epss_scores(cve_ids, client=client)

    assert [len(chunk) for chunk in sent] == [100, 50]
    assert len(scores) == 150
    assert complete is True


def test_チャンクサイズは変更できる():
    sent = []

    def handler(request):
        sent.append(request.url.params["cve"].split(","))
        return _response([])

    with make_client(handler) as client:
        fetch_epss_scores(
            ["CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"], client=client, chunk_size=2
        )

    assert [len(chunk) for chunk in sent] == [2, 1]


def test_重複したCVEは1回だけ問い合わせる():
    sent = []

    def handler(request):
        sent.append(request.url.params["cve"])
        return _response([])

    with make_client(handler) as client:
        fetch_epss_scores(["CVE-2020-0001", "CVE-2020-0001", ""], client=client)

    assert sent == ["CVE-2020-0001"]


def test_対象が無ければ通信しない():
    def handler(request):  # pragma: no cover - 呼ばれないことを検証する
        raise AssertionError("通信してはいけない")

    with make_client(handler) as client:
        scores, complete = fetch_epss_scores([], client=client)

    assert scores == {}
    assert complete is True


def test_EPSSに登録が無いCVEは結果に含まれない():
    def handler(request):
        return _response([{"cve": "CVE-2020-0001", "epss": "0.3"}])

    with make_client(handler) as client:
        scores, complete = fetch_epss_scores(["CVE-2020-0001", "CVE-2020-9999"], client=client)

    assert scores == {"CVE-2020-0001": 0.3}
    assert "CVE-2020-9999" not in scores
    assert complete is True


def test_壊れた応答は読み飛ばす():
    def handler(request):
        return _response(
            [
                "junk",
                {"cve": "CVE-2020-0001"},
                {"cve": "CVE-2020-0002", "epss": "たかい"},
                {"cve": "CVE-2020-0003", "epss": "1.5"},
                {"epss": "0.2"},
                {"cve": "CVE-2020-0004", "epss": "0.25"},
            ]
        )

    with make_client(handler) as client:
        scores, _ = fetch_epss_scores(["CVE-2020-0004"], client=client)

    assert scores == {"CVE-2020-0004": 0.25}


def test_取得に失敗しても取れた分は返し未完了を知らせる():
    def handler(request):
        if "CVE-2020-0001" in request.url.params["cve"]:
            raise httpx.ConnectError("接続できません")
        return _response([{"cve": "CVE-2020-0002", "epss": "0.7"}])

    with make_client(handler) as client:
        scores, complete = fetch_epss_scores(
            ["CVE-2020-0001", "CVE-2020-0002"], client=client, chunk_size=1
        )

    assert scores == {"CVE-2020-0002": 0.7}
    assert complete is False


def test_全滅しても例外を投げずに未完了を返す():
    def handler(request):
        raise httpx.ConnectError("接続できません")

    with make_client(handler) as client:
        scores, complete = fetch_epss_scores(["CVE-2020-0001"], client=client)

    assert scores == {}
    assert complete is False


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "ERROR", "data": []},
        {"status": "error", "data": [{"cve": "CVE-2020-0001", "epss": "0.5"}]},
        {"data": "temporarily unavailable"},
        {"message": "maintenance"},
        [],
        "not json object",
    ],
)
def test_HTTP200でも中身が異常なら取得失敗として扱う(payload):
    """警告なしに『EPSSは低い』と誤表示しないための回帰テスト。"""

    def handler(request):
        return httpx.Response(200, json=payload)

    with make_client(handler) as client:
        scores, complete = fetch_epss_scores(["CVE-2020-0001"], client=client)

    assert scores == {}
    assert complete is False


def test_一部のチャンクだけ異常応答なら残りは活かして未完了にする():
    def handler(request):
        if request.url.params["cve"] == "CVE-2020-0001":
            return httpx.Response(200, json={"status": "ERROR", "data": []})
        return _response([{"cve": "CVE-2020-0002", "epss": "0.7"}])

    with make_client(handler) as client:
        scores, complete = fetch_epss_scores(
            ["CVE-2020-0001", "CVE-2020-0002"], client=client, chunk_size=1
        )

    assert scores == {"CVE-2020-0002": 0.7}
    assert complete is False


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity"])
def test_NaNや無限大はEPSSとして扱わない(value):
    def handler(request):
        return _response([{"cve": "CVE-2020-0001", "epss": value}])

    with make_client(handler) as client:
        scores, complete = fetch_epss_scores(["CVE-2020-0001"], client=client)

    assert scores == {}
    assert complete is True  # 応答の形式そのものは正常なので取得失敗ではない
