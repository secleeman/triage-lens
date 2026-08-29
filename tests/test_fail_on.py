"""`--fail-on` / `--fail-on-fetch-error` の終了コードを検査する。

CI に組み込むためのオプションなので、間違えると「落ちるべきときに緑」か
「落ちるべきでないときに赤」のどちらかになる。前者は静かに見逃しを生み、
後者はオプションごと外される。どちらも起きないようにここで押さえる。

外部APIには接続しない（既存のテストと同じくすべてモック）。
"""

import json
import os
import time

import httpx
import pytest

from conftest import make_client
from test_cli import EPSS_SCORES, KEV_PAYLOAD
from triage_lens import kev
from triage_lens.cli import (
    EXIT_FAIL_ON,
    EXIT_FETCH_ERROR,
    EXIT_INPUT_ERROR,
    EXIT_OK,
    main,
)

#: 対象の CVE を1つも含まない KEV カタログ。
#: 空のカタログは「取得できなかった」扱いになるため、無関係の1件を入れておく。
NO_KEV_PAYLOAD = {
    "catalogVersion": "2026.08.01",
    "vulnerabilities": [{"cveID": "CVE-1999-0001"}],
}

#: 合成した検出のEPSS。すべて閾値（0.1）未満にして、CVSS だけで順位が決まるようにする。
SYNTHETIC_EPSS = {
    "CVE-2026-0001": "0.01000",
    "CVE-2026-0002": "0.01000",
}


def _vulnerability(cve_id: str, cvss: float) -> dict:
    return {
        "VulnerabilityID": cve_id,
        "PkgName": "example-pkg",
        "InstalledVersion": "1.0.0",
        "FixedVersion": "1.0.1",
        "Severity": "HIGH",
        "CVSS": {"nvd": {"V3Score": cvss}},
    }


def _make_handler(scores: dict[str, str], kev_payload: dict) -> object:
    """EPSS と KEV を返すハンドラを作る。"""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.first.org":
            requested = request.url.params["cve"].split(",")
            return httpx.Response(
                200,
                json={
                    "status": "OK",
                    "data": [
                        {"cve": cve, "epss": scores[cve]} for cve in requested if cve in scores
                    ],
                },
            )
        if request.url.host == "www.cisa.gov":
            return httpx.Response(200, json=kev_payload)
        raise AssertionError(f"想定外の接続先: {request.url}")

    return handler


def _offline(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("接続できません")


def _kev_down(request: httpx.Request) -> httpx.Response:
    """KEV だけ落ちている。EPSS は正常に返る。"""
    if request.url.host == "www.cisa.gov":
        raise httpx.ConnectError("接続できません")
    return _make_handler(EPSS_SCORES, KEV_PAYLOAD)(request)


def _epss_down(request: httpx.Request) -> httpx.Response:
    """EPSS だけ落ちている。KEV は正常に返る。"""
    if request.url.host == "api.first.org":
        raise httpx.ConnectError("接続できません")
    return _make_handler(EPSS_SCORES, KEV_PAYLOAD)(request)


@pytest.fixture
def p2_and_p3(tmp_path):
    """P2 と P3 だけを含むスキャン結果。P0 / P1 は存在しない。"""
    path = tmp_path / "scan.json"
    path.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactName": "example-app:1.0.0",
                "Results": [
                    {
                        "Target": "example-app:1.0.0",
                        "Type": "debian",
                        "Vulnerabilities": [
                            _vulnerability("CVE-2026-0001", 9.0),  # CVSS が高い → P2
                            _vulnerability("CVE-2026-0002", 3.0),  # どちらも低い → P3
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def synthetic_client():
    with make_client(_make_handler(SYNTHETIC_EPSS, NO_KEV_PAYLOAD)) as client:
        yield client


@pytest.mark.parametrize(
    ("rank", "expected"),
    [
        ("p0", EXIT_OK),
        ("p1", EXIT_OK),
        ("p2", EXIT_FAIL_ON),
        ("p3", EXIT_FAIL_ON),
    ],
)
def test_指定ランク以上の検出があるときだけ落ちる(
    p2_and_p3, tmp_path, synthetic_client, rank, expected
):
    """判定表そのもの。最上位が P2 の入力に対して p2 / p3 だけが落ちる。"""
    code = main(
        ["report", str(p2_and_p3), "-o", str(tmp_path / "r.md"), "--fail-on", rank],
        client=synthetic_client,
    )

    assert code == expected


def test_P0があればfail_on_p0で落ちる(fixtures_dir, tmp_path):
    with make_client(_make_handler(EPSS_SCORES, KEV_PAYLOAD)) as client:
        code = main(
            [
                "report",
                str(fixtures_dir / "trivy_sample.json"),
                "-o",
                str(tmp_path / "r.md"),
                "--fail-on",
                "p0",
            ],
            client=client,
        )

    assert code == EXIT_FAIL_ON


def test_ランクは大文字でも受け付ける(p2_and_p3, tmp_path, synthetic_client):
    code = main(
        ["report", str(p2_and_p3), "-o", str(tmp_path / "r.md"), "--fail-on", "P2"],
        client=synthetic_client,
    )

    assert code == EXIT_FAIL_ON


def test_落ちるときもレポートはファイルに残る(p2_and_p3, tmp_path, synthetic_client):
    """CI が落ちたときに原因を見るためのレポートが無い、という状態を作らない。"""
    output = tmp_path / "r.md"

    code = main(
        ["report", str(p2_and_p3), "-o", str(output), "--fail-on", "p2"],
        client=synthetic_client,
    )

    assert code == EXIT_FAIL_ON
    assert "CVE-2026-0001" in output.read_text(encoding="utf-8")


def test_落ちるときも標準出力にレポートを書く(p2_and_p3, synthetic_client, capsys):
    code = main(["report", str(p2_and_p3), "--fail-on", "p2"], client=synthetic_client)

    captured = capsys.readouterr()
    assert code == EXIT_FAIL_ON
    assert captured.out.startswith("# 脆弱性トリアージレポート")


def test_topで表示から漏れた検出も判定に入る(p2_and_p3, tmp_path, synthetic_client):
    """`--top` は表示件数であって判定件数ではない。

    表示から外れた検出を判定からも外すと、`--top` を絞るほど CI が
    甘くなるという、誰も意図しない挙動になる。
    """
    output = tmp_path / "r.md"

    code = main(
        ["report", str(p2_and_p3), "-o", str(output), "--top", "0", "--fail-on", "p2"],
        client=synthetic_client,
    )

    report = output.read_text(encoding="utf-8")
    assert code == EXIT_FAIL_ON
    assert "CVE-2026-0001" not in report, "前提が崩れている（--top 0 でも表示されている）"


def test_検出ゼロならどのランクでも落ちない(fixtures_dir, tmp_path):
    def handler(request):  # pragma: no cover - 呼ばれないことを検証する
        raise AssertionError("脆弱性が無ければ通信してはいけない")

    with make_client(handler) as client:
        code = main(
            [
                "report",
                str(fixtures_dir / "trivy_empty.json"),
                "-o",
                str(tmp_path / "r.md"),
                "--fail-on",
                "p3",
            ],
            client=client,
        )

    assert code == EXIT_OK


def test_fail_onを指定しなければ常に0のまま(fixtures_dir, tmp_path):
    """P0 があっても、指定が無ければ従来どおり 0 で終わる。"""
    with make_client(_make_handler(EPSS_SCORES, KEV_PAYLOAD)) as client:
        code = main(
            ["report", str(fixtures_dir / "trivy_sample.json"), "-o", str(tmp_path / "r.md")],
            client=client,
        )

    assert code == EXIT_OK


def test_不正なランクは使い方エラーになる(p2_and_p3):
    with pytest.raises(SystemExit) as excinfo:
        main(["report", str(p2_and_p3), "--fail-on", "p9"])

    assert excinfo.value.code == EXIT_INPUT_ERROR


def test_fail_on_fetch_errorの単独指定は使い方エラーになる(p2_and_p3):
    """何も起きないオプションを黙って受け取らない。"""
    with pytest.raises(SystemExit) as excinfo:
        main(["report", str(p2_and_p3), "--fail-on-fetch-error"])

    assert excinfo.value.code == EXIT_INPUT_ERROR


def test_取得に失敗しても既定では落とさず警告だけ出す(fixtures_dir, tmp_path, capsys):
    """既定の挙動。判定が甘くなっている可能性を標準エラーに出す。"""
    with make_client(_offline) as client:
        code = main(
            [
                "report",
                str(fixtures_dir / "trivy_sample.json"),
                "-o",
                str(tmp_path / "r.md"),
                "--fail-on",
                "p0",
            ],
            client=client,
        )

    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert "CISA KEV を取得できませんでした" in captured.err
    assert "EPSS を一部取得できませんでした" in captured.err


def test_fail_onを指定しなければ警告も出さない(fixtures_dir, tmp_path, capsys):
    with make_client(_offline) as client:
        main(
            ["report", str(fixtures_dir / "trivy_sample.json"), "-o", str(tmp_path / "r.md")],
            client=client,
        )

    assert "警告:" not in capsys.readouterr().err


@pytest.mark.parametrize("handler", [_offline, _kev_down, _epss_down])
def test_fail_on_fetch_errorを付けると取得失敗で3になる(fixtures_dir, tmp_path, handler):
    """KEV だけ・EPSS だけ・両方、いずれの失敗でも 3 を返す。"""
    with make_client(handler) as client:
        code = main(
            [
                "report",
                str(fixtures_dir / "trivy_sample.json"),
                "-o",
                str(tmp_path / "r.md"),
                "--fail-on",
                "p0",
                "--fail-on-fetch-error",
            ],
            client=client,
        )

    assert code == EXIT_FETCH_ERROR


def test_期限切れキャッシュを使った場合も取得失敗として扱う(
    fixtures_dir, tmp_path, isolated_kev_cache, capsys
):
    """再取得に失敗して古いカタログを使った状態は、KEV が最新である保証がない。"""
    isolated_kev_cache.parent.mkdir(parents=True, exist_ok=True)
    isolated_kev_cache.write_text(json.dumps(KEV_PAYLOAD), encoding="utf-8")
    expired = time.time() - kev.CACHE_TTL_SECONDS - 60
    os.utime(isolated_kev_cache, (expired, expired))

    with make_client(_kev_down) as client:
        code = main(
            [
                "report",
                str(fixtures_dir / "trivy_sample.json"),
                "-o",
                str(tmp_path / "r.md"),
                "--fail-on",
                "p0",
                "--fail-on-fetch-error",
            ],
            client=client,
        )

    captured = capsys.readouterr()
    assert code == EXIT_FETCH_ERROR
    assert "期限切れのキャッシュを使いました" in captured.err


def test_取得失敗と該当検出が同時なら3を返す(fixtures_dir, tmp_path):
    """欠けたデータで出した判定結果を「該当あり」として返すと、
    取得失敗のほうを見落とすため、3 を優先する。

    同じ入力を `--fail-on-fetch-error` の有無だけ変えて2回流し、
    「1 になる状況で 3 が返る」ことを確かめる。片方だけを見ていると、
    P0 が検出されなくなっても気づけない。
    """
    args = [
        "report",
        str(fixtures_dir / "trivy_sample.json"),
        "-o",
        str(tmp_path / "r.md"),
        "--fail-on",
        "p0",
    ]

    # EPSS だけ落ちている。KEV は引けているので P0 は検出される。
    with make_client(_epss_down) as client:
        without_flag = main(args, client=client)
    with make_client(_epss_down) as client:
        with_flag = main([*args, "--fail-on-fetch-error"], client=client)

    assert without_flag == EXIT_FAIL_ON, "前提が崩れている（該当する検出が無い）"
    assert with_flag == EXIT_FETCH_ERROR


def test_取得に成功していればfail_on_fetch_errorは影響しない(p2_and_p3, tmp_path, synthetic_client):
    code = main(
        [
            "report",
            str(p2_and_p3),
            "-o",
            str(tmp_path / "r.md"),
            "--fail-on",
            "p0",
            "--fail-on-fetch-error",
        ],
        client=synthetic_client,
    )

    assert code == EXIT_OK


def test_EPSSに登録の無いCVEは取得失敗ではない(p2_and_p3, tmp_path):
    """スコアが返らないことと、取得できないことは別。

    EPSS に載っていない CVE を取得失敗として扱うと、新しい CVE を含む
    入力で常に 3 になってしまう。
    """
    with make_client(_make_handler({}, NO_KEV_PAYLOAD)) as client:
        code = main(
            [
                "report",
                str(p2_and_p3),
                "-o",
                str(tmp_path / "r.md"),
                "--fail-on",
                "p2",
                "--fail-on-fetch-error",
            ],
            client=client,
        )

    assert code == EXIT_FAIL_ON


def test_AIコメントの失敗は終了コードを変えない(p2_and_p3, tmp_path, monkeypatch, capsys):
    """Phase 3 の約束（AIが動かなくてもレポートは出て終了コードは変わらない）を守る。"""
    from triage_lens import ai

    monkeypatch.delenv(ai.API_KEY_ENV, raising=False)

    with make_client(_make_handler(SYNTHETIC_EPSS, NO_KEV_PAYLOAD)) as client:
        code = main(
            ["report", str(p2_and_p3), "-o", str(tmp_path / "r.md"), "--ai", "--fail-on", "p0"],
            client=client,
        )

    assert code == EXIT_OK
    assert "未設定のためAIコメントをスキップしました" in capsys.readouterr().err
