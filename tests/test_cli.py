import subprocess
import sys

import httpx
import pytest

from conftest import make_client
from test_i18n import JAPANESE_CHARS
from triage_lens.cli import EXIT_INPUT_ERROR, EXIT_OK, main

KEV_PAYLOAD = {
    "catalogVersion": "2026.08.01",
    "vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2014-0160"}],
}

EPSS_SCORES = {
    "CVE-2021-44228": "0.97000",
    "CVE-2023-38545": "0.35000",
    "CVE-2022-22965": "0.94000",
    "CVE-2019-11358": "0.20000",
    "CVE-2021-33503": "0.02000",
}


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.host == "api.first.org":
        requested = request.url.params["cve"].split(",")
        return httpx.Response(
            200,
            json={
                "status": "OK",
                "data": [
                    {"cve": cve, "epss": EPSS_SCORES[cve]}
                    for cve in requested
                    if cve in EPSS_SCORES
                ],
            },
        )
    if request.url.host == "www.cisa.gov":
        return httpx.Response(200, json=KEV_PAYLOAD)
    raise AssertionError(f"想定外の接続先: {request.url}")


def _offline_handler(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("接続できません")


def test_レポートをファイルに書き出せる(fixtures_dir, tmp_path):
    output = tmp_path / "triage-report.md"

    with make_client(_handler) as client:
        code = main(
            ["report", str(fixtures_dir / "trivy_sample.json"), "-o", str(output)], client=client
        )

    report = output.read_text(encoding="utf-8")
    assert code == EXIT_OK
    assert report.startswith("# 脆弱性トリアージレポート")
    assert "- 対象: sample-app:1.4.0" in report
    assert "検出総数: 13件" in report


def test_KEV掲載のCVEがP0になる(fixtures_dir, tmp_path):
    output = tmp_path / "report.md"

    with make_client(_handler) as client:
        main(["report", str(fixtures_dir / "trivy_sample.json"), "-o", str(output)], client=client)

    report = output.read_text(encoding="utf-8")
    assert "## P0 (Act now) — 今すぐ対応（3件）" in report
    assert "| CVE-2021-44228 | log4j-core |" in report
    assert "| CVE-2014-0160 | openssl |" in report


def test_出力先を省略すると標準出力に書く(fixtures_dir, capsys):
    with make_client(_handler) as client:
        code = main(["report", str(fixtures_dir / "trivy_sample.json")], client=client)

    captured = capsys.readouterr()
    assert code == EXIT_OK
    assert captured.out.startswith("# 脆弱性トリアージレポート")


def test_topオプションでP2P3の表示件数が変わる(fixtures_dir, tmp_path):
    output = tmp_path / "report.md"

    with make_client(_handler) as client:
        main(
            ["report", str(fixtures_dir / "trivy_sample.json"), "-o", str(output), "--top", "1"],
            client=client,
        )

    report = output.read_text(encoding="utf-8")
    assert "上位1件を表示" in report


def test_出力先のフォルダが無ければ作る(fixtures_dir, tmp_path):
    output = tmp_path / "out" / "nested" / "report.md"

    with make_client(_handler) as client:
        code = main(
            ["report", str(fixtures_dir / "trivy_sample.json"), "-o", str(output)], client=client
        )

    assert code == EXIT_OK
    assert output.exists()


def test_通信が全滅しても部分レポートを出して正常終了する(fixtures_dir, tmp_path, capsys):
    output = tmp_path / "report.md"

    with make_client(_offline_handler) as client:
        code = main(
            ["report", str(fixtures_dir / "trivy_sample.json"), "-o", str(output)], client=client
        )

    report = output.read_text(encoding="utf-8")
    assert code == EXIT_OK
    assert "CISA KEV カタログを取得できませんでした" in report
    assert "EPSS スコアの一部または全部を取得できませんでした" in report
    assert "検出総数: 13件" in report


def test_検出ゼロなら通信せずレポートを出す(fixtures_dir, tmp_path):
    def handler(request):  # pragma: no cover - 呼ばれないことを検証する
        raise AssertionError("脆弱性が無ければ通信してはいけない")

    output = tmp_path / "report.md"
    with make_client(handler) as client:
        code = main(
            ["report", str(fixtures_dir / "trivy_empty.json"), "-o", str(output)], client=client
        )

    assert code == EXIT_OK
    assert "検出された脆弱性はありません。" in output.read_text(encoding="utf-8")


def test_KEVカタログは2回目以降キャッシュから読む(fixtures_dir, tmp_path, isolated_kev_cache):
    calls = []

    def handler(request):
        calls.append(request.url.host)
        return _handler(request)

    args = ["report", str(fixtures_dir / "trivy_sample.json"), "-o", str(tmp_path / "r.md")]
    with make_client(handler) as client:
        main(args, client=client)
        main(args, client=client)

    assert isolated_kev_cache.exists()
    assert calls.count("www.cisa.gov") == 1


def test_存在しないファイルは終了コード2(tmp_path, capsys):
    code = main(["report", str(tmp_path / "missing.json")])

    captured = capsys.readouterr()
    assert code == EXIT_INPUT_ERROR
    assert "入力ファイルが見つかりません" in captured.err


def test_壊れたJSONは終了コード2(fixtures_dir, capsys):
    code = main(["report", str(fixtures_dir / "trivy_invalid.json")])

    captured = capsys.readouterr()
    assert code == EXIT_INPUT_ERROR
    assert "JSON として読み込めませんでした" in captured.err


def test_対応していない形式のJSONは終了コード2(fixtures_dir, capsys):
    """Trivy JSON でも CycloneDX でもない JSON は読めないことを明示する。

    Phase 1 では `not_trivy.json`（中身は CycloneDX）を使っていたが、
    Phase 2 で CycloneDX が正式な入力形式になったため、どちらでもない
    ファイルに差し替えている。
    """
    code = main(["report", str(fixtures_dir / "unsupported.json")])

    captured = capsys.readouterr()
    assert code == EXIT_INPUT_ERROR
    assert "Trivy の JSON 出力ではないようです" in captured.err
    assert "CycloneDX 形式（JSON）でもありません" in captured.err


@pytest.mark.parametrize("top", ["-1", "abc"])
def test_topに不正な値を渡すと使い方エラーになる(fixtures_dir, top):
    with pytest.raises(SystemExit) as excinfo:
        main(["report", str(fixtures_dir / "trivy_sample.json"), "--top", top])

    assert excinfo.value.code == EXIT_INPUT_ERROR


def test_サブコマンド無しは使い方エラーになる():
    with pytest.raises(SystemExit) as excinfo:
        main([])

    assert excinfo.value.code == EXIT_INPUT_ERROR


def test_python_mコマンドでも実行できる(fixtures_dir, tmp_path):
    """`python -m triage_lens` で起動できることを実プロセスで確認する。

    検出ゼロのファイルを使うので外部通信は発生しない。
    """
    output = tmp_path / "report.md"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "triage_lens",
            "report",
            str(fixtures_dir / "trivy_empty.json"),
            "-o",
            str(output),
        ],
        capture_output=True,
    )

    assert result.returncode == EXIT_OK, result.stderr
    assert "検出された脆弱性はありません。" in output.read_text(encoding="utf-8")


def test_ネストした型異常でもスタックトレースを出さず終了コード2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"SchemaVersion": 2, "Results": [{"Vulnerabilities": 1}]}', encoding="utf-8")

    code = main(["report", str(bad)])

    captured = capsys.readouterr()
    assert code == EXIT_INPUT_ERROR
    assert "Vulnerabilities が一覧ではありません" in captured.err
    assert "Traceback" not in captured.err


def test_langにenを渡すと英語レポートになる(fixtures_dir, tmp_path):
    output = tmp_path / "report-en.md"

    with make_client(_handler) as client:
        code = main(
            ["report", str(fixtures_dir / "trivy_sample.json"), "-o", str(output), "--lang", "en"],
            client=client,
        )

    report = output.read_text(encoding="utf-8")
    assert code == EXIT_OK
    assert report.startswith("# Vulnerability Triage Report")
    assert "Total findings: 13" in report
    assert "| P0 (Act now) | 3 | Patch immediately |" in report


def test_langを省略すると日本語のまま(fixtures_dir, tmp_path):
    japanese = tmp_path / "ja.md"
    explicit = tmp_path / "ja-explicit.md"
    args = ["report", str(fixtures_dir / "trivy_sample.json"), "-o"]

    with make_client(_handler) as client:
        main([*args, str(japanese)], client=client)
        main([*args, str(explicit), "--lang", "ja"], client=client)

    assert japanese.read_text(encoding="utf-8").startswith("# 脆弱性トリアージレポート")
    assert japanese.read_text(encoding="utf-8") == explicit.read_text(encoding="utf-8")


def test_未対応の言語は使い方エラーになる(fixtures_dir):
    with pytest.raises(SystemExit) as excinfo:
        main(["report", str(fixtures_dir / "trivy_sample.json"), "--lang", "fr"])

    assert excinfo.value.code == EXIT_INPUT_ERROR


def test_英語レポートでも通信失敗の警告は英語で出る(fixtures_dir, tmp_path):
    output = tmp_path / "report-en.md"

    with make_client(_offline_handler) as client:
        code = main(
            ["report", str(fixtures_dir / "trivy_sample.json"), "-o", str(output), "--lang", "en"],
            client=client,
        )

    report = output.read_text(encoding="utf-8")
    assert code == EXIT_OK
    assert "Could not fetch the CISA KEV catalog." in report
    assert "Some or all EPSS scores could not be fetched." in report


def test_CycloneDXのSBOMからレポートを作れる(fixtures_dir, tmp_path):
    output = tmp_path / "report.md"

    with make_client(_handler) as client:
        code = main(
            ["report", str(fixtures_dir / "cyclonedx_sample.json"), "-o", str(output)],
            client=client,
        )

    report = output.read_text(encoding="utf-8")
    assert code == EXIT_OK
    assert report.startswith("# 脆弱性トリアージレポート")
    assert "- 対象: sample-app@1.4.0" in report
    assert "検出総数: 9件" in report
    assert "| CVE-2021-44228 | log4j-core |" in report


def test_CycloneDXでもKEV掲載はP0になる(fixtures_dir, tmp_path):
    output = tmp_path / "report.md"

    with make_client(_handler) as client:
        main(
            ["report", str(fixtures_dir / "cyclonedx_sample.json"), "-o", str(output)],
            client=client,
        )

    report = output.read_text(encoding="utf-8")
    assert "## P0 (Act now) — 今すぐ対応（3件）" in report


def test_CycloneDXでは修正版の有無が分からないときは不明と書く(fixtures_dir, tmp_path):
    output = tmp_path / "report.md"

    with make_client(_handler) as client:
        main(
            ["report", str(fixtures_dir / "cyclonedx_sample.json"), "-o", str(output)],
            client=client,
        )

    report = output.read_text(encoding="utf-8")
    assert "1.8.0-2 → 不明" in report
    assert "修正版なし" not in report


def test_CycloneDXを英語レポートにできる(fixtures_dir, tmp_path):
    output = tmp_path / "report-en.md"

    with make_client(_handler) as client:
        code = main(
            [
                "report",
                str(fixtures_dir / "cyclonedx_sample.json"),
                "-o",
                str(output),
                "--lang",
                "en",
            ],
            client=client,
        )

    report = output.read_text(encoding="utf-8")
    assert code == EXIT_OK
    assert report.startswith("# Vulnerability Triage Report")
    assert "Total findings: 9" in report
    assert "1.8.0-2 -> Unknown" in report
    assert "(unknown)" in report  # 部品名が引き当てられなかった行
    assert not JAPANESE_CHARS.findall(report)


def test_脆弱性が無いSBOMでも通信せずレポートを出す(fixtures_dir, tmp_path):
    def handler(request):  # pragma: no cover - 呼ばれないことを検証する
        raise AssertionError("脆弱性が無ければ通信してはいけない")

    output = tmp_path / "report.md"
    with make_client(handler) as client:
        code = main(
            ["report", str(fixtures_dir / "cyclonedx_empty.json"), "-o", str(output)],
            client=client,
        )

    assert code == EXIT_OK
    assert "検出された脆弱性はありません。" in output.read_text(encoding="utf-8")


def test_壊れたCycloneDXは終了コード2(tmp_path, capsys):
    bad = tmp_path / "bad.cdx.json"
    bad.write_text(
        '{"bomFormat": "CycloneDX", "specVersion": "1.5", "vulnerabilities": 1}',
        encoding="utf-8",
    )

    code = main(["report", str(bad)])

    captured = capsys.readouterr()
    assert code == EXIT_INPUT_ERROR
    assert "vulnerabilities が一覧ではありません" in captured.err
    assert "Traceback" not in captured.err
