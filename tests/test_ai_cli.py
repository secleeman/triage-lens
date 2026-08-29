import json

import httpx
import pytest

from conftest import make_client
from test_cli import EPSS_SCORES, KEV_PAYLOAD
from triage_lens import ai
from triage_lens.cli import EXIT_OK, main

ANTHROPIC_HOST = "api.anthropic.com"


@pytest.fixture(autouse=True)
def no_api_key(monkeypatch):
    """実行環境のAPIキー・ワークスペースIDがテスト結果に影響しないようにする。"""
    monkeypatch.delenv(ai.API_KEY_ENV, raising=False)
    monkeypatch.delenv(ai.WORKSPACE_ID_ENV, raising=False)


@pytest.fixture
def api_key(monkeypatch):
    monkeypatch.setenv(ai.API_KEY_ENV, "sk-test-key")
    return "sk-test-key"


def _ai_payload(comments):
    return {
        "id": "msg_test",
        "type": "message",
        "role": "assistant",
        "content": [
            {"type": "text", "text": json.dumps({"comments": comments}, ensure_ascii=False)}
        ],
    }


def _sent_entries(request):
    body = json.loads(request.content)
    return json.loads(body["messages"][0]["content"])


def make_handler(ai_response=None):
    """EPSS / KEV / Anthropic を振り分けるハンドラ。

    `ai_response` は Anthropic への1リクエストを受け取って応答を返す関数。
    既定では、送られてきた各件にそのCVE IDを含むコメントを返す。
    """
    ai_requests = []

    def default_ai_response(request):
        entries = _sent_entries(request)
        return httpx.Response(
            200,
            json=_ai_payload(
                [
                    {"id": entry["id"], "comment": f"{entry['cve']} は修正版へ更新してください"}
                    for entry in entries
                ]
            ),
        )

    responder = ai_response or default_ai_response

    def handler(request):
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
        if request.url.host == ANTHROPIC_HOST:
            ai_requests.append(request)
            return responder(request)
        raise AssertionError(f"想定外の接続先: {request.url}")

    handler.ai_requests = ai_requests
    return handler


def run(argv, handler, tmp_path, name="report.md"):
    output = tmp_path / name
    with make_client(handler) as client:
        code = main(["report", *argv, "-o", str(output)], client=client)
    return code, output.read_text(encoding="utf-8")


def without_timestamp(report):
    """生成日時の行だけを除いたレポート（実行時刻の差で比較が揺れないように）。"""
    return "\n".join(
        line for line in report.splitlines() if not line.startswith(("- 生成日時:", "- Generated:"))
    )


# --- --ai を付けない場合 -------------------------------------------------


def test_aiを付けなければAnthropicへの通信は発生しない(fixtures_dir, tmp_path):
    handler = make_handler()

    code, report = run([str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    assert code == EXIT_OK
    assert handler.ai_requests == []
    assert "対応方針（AI生成）" not in report


# --- APIキーが無い場合 ---------------------------------------------------


def test_APIキー未設定なら通信せず終了コード0のままレポートが出る(fixtures_dir, tmp_path, capsys):
    handler = make_handler()

    code, report = run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    assert code == EXIT_OK
    assert handler.ai_requests == []
    assert report.startswith("# 脆弱性トリアージレポート")
    assert "対応方針（AI生成）" not in report


def test_APIキー未設定のときは標準エラーに1行だけ出す(fixtures_dir, tmp_path, capsys):
    handler = make_handler()

    run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    captured = capsys.readouterr()
    assert captured.err.strip() == f"{ai.API_KEY_ENV} が未設定のためAIコメントをスキップしました。"


def test_APIキー未設定の出力はaiを付けない場合と一致する(fixtures_dir, tmp_path):
    source = str(fixtures_dir / "trivy_sample.json")

    _, plain = run([source], make_handler(), tmp_path, name="plain.md")
    _, with_ai = run(["--ai", source], make_handler(), tmp_path, name="ai.md")

    assert without_timestamp(with_ai) == without_timestamp(plain)


def test_空文字のAPIキーも未設定として扱う(fixtures_dir, tmp_path, monkeypatch):
    monkeypatch.setenv(ai.API_KEY_ENV, "  ")
    handler = make_handler()

    code, _ = run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    assert code == EXIT_OK
    assert handler.ai_requests == []


# --- 正常系 --------------------------------------------------------------


def test_AIコメントがレポートに入る(fixtures_dir, tmp_path, api_key):
    handler = make_handler()

    code, report = run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    assert code == EXIT_OK
    assert handler.ai_requests != []
    assert "### 対応方針（AI生成）" in report
    assert "CVE-2021-44228 は修正版へ更新してください" in report


def test_レポートに免責とモデル名が入る(fixtures_dir, tmp_path, api_key):
    handler = make_handler()

    _, report = run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    assert "## 対応方針コメントについて" in report
    assert "AI が生成した参考情報です" in report
    assert f"- 生成モデル: {ai.DEFAULT_MODEL}" in report
    assert "- 対象: P0 と P1 の検出のみ" in report


def test_モデルを指定できる(fixtures_dir, tmp_path, api_key):
    handler = make_handler()

    _, report = run(
        ["--ai", "--ai-model", "claude-sonnet-5", str(fixtures_dir / "trivy_sample.json")],
        handler,
        tmp_path,
    )

    assert json.loads(handler.ai_requests[0].content)["model"] == "claude-sonnet-5"
    assert "- 生成モデル: claude-sonnet-5" in report


def test_送信内容に検出箇所と対象名が含まれない(fixtures_dir, tmp_path, api_key):
    handler = make_handler()

    run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    for request in handler.ai_requests:
        body = request.content.decode("utf-8")
        assert "sample-app" not in body
        for entry in _sent_entries(request):
            assert "target" not in entry
            assert entry["priority"] in {"P0", "P1"}


def test_英語レポートでは免責も英語になる(fixtures_dir, tmp_path, api_key):
    handler = make_handler()

    _, report = run(
        ["--ai", "--lang", "en", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path
    )

    assert "## About the suggested next steps" in report
    assert "Suggested next steps (AI-generated)" in report
    assert "対応方針" not in report
    assert json.loads(handler.ai_requests[0].content)["system"] == ai._SYSTEM_PROMPTS["en"]


def test_生成前に件数とモデルを標準エラーに出す(fixtures_dir, tmp_path, api_key, capsys):
    handler = make_handler()

    run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    assert "件に対してAIコメントを生成します" in capsys.readouterr().err


def test_上限件数で絞るとレポートに明記される(fixtures_dir, tmp_path, api_key):
    handler = make_handler()

    _, report = run(
        ["--ai", "--ai-limit", "1", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path
    )

    assert len(_sent_entries(handler.ai_requests[0])) == 1
    assert "- 上限により 1件までを対象に生成しました" in report


def test_上限が0なら通信しない(fixtures_dir, tmp_path, api_key, capsys):
    handler = make_handler()

    code, report = run(
        ["--ai", "--ai-limit", "0", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path
    )

    assert code == EXIT_OK
    assert handler.ai_requests == []
    assert "対応方針（AI生成）" not in report
    assert "P0 / P1 の検出がない" in capsys.readouterr().err


# --- 異常系 --------------------------------------------------------------


def test_生成に全部失敗してもレポートは出る(fixtures_dir, tmp_path, api_key, capsys):
    handler = make_handler(lambda request: httpx.Response(500, json={"error": "down"}))
    source = str(fixtures_dir / "trivy_sample.json")

    code, report = run(["--ai", source], handler, tmp_path, name="ai.md")
    _, plain = run([source], make_handler(), tmp_path, name="plain.md")

    assert code == EXIT_OK
    assert without_timestamp(report) == without_timestamp(plain)
    assert "AIコメントを生成できませんでした" in capsys.readouterr().err


def test_認証エラーでも終了コードは0のまま(fixtures_dir, tmp_path, api_key):
    handler = make_handler(lambda request: httpx.Response(401, json={"error": "unauthorized"}))

    code, report = run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    assert code == EXIT_OK
    assert "対応方針（AI生成）" not in report


def test_通信が切れても終了コードは0のまま(fixtures_dir, tmp_path, api_key):
    def offline(request):
        raise httpx.ConnectError("接続できません")

    handler = make_handler(offline)

    code, report = run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    assert code == EXIT_OK
    assert report.startswith("# 脆弱性トリアージレポート")


def test_APIキーがレポートにも標準エラーにも出ない(fixtures_dir, tmp_path, api_key, capsys):
    handler = make_handler(lambda request: httpx.Response(401, json={"error": "unauthorized"}))

    _, report = run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    captured = capsys.readouterr()
    assert api_key not in report
    assert api_key not in captured.err
    assert api_key not in captured.out
    assert "Traceback" not in captured.err


def test_同じCVEが複数箇所で見つかってもコメント行は繰り返さない(fixtures_dir, tmp_path, api_key):
    # trivy_sample.json の CVE-2014-0160 は2箇所で検出される。
    # 検出箇所を書かないコメント行は同じ文になるため、1行にまとめる
    handler = make_handler()

    _, report = run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    section = report.split("## P0")[1].split("## P1")[0]
    comment_lines = [line for line in section.splitlines() if line.startswith("- **CVE-2014-0160")]
    assert len(comment_lines) == 1
    # 一覧表のほうには両方の検出箇所が残っている
    assert section.count("| CVE-2014-0160 ") == 2


def test_ワークスペースIDの環境変数がリクエストに反映される(
    fixtures_dir, tmp_path, api_key, monkeypatch
):
    monkeypatch.setenv(ai.WORKSPACE_ID_ENV, "wrkspc_test")
    handler = make_handler()

    run(["--ai", str(fixtures_dir / "trivy_sample.json")], handler, tmp_path)

    assert handler.ai_requests[0].headers["anthropic-workspace-id"] == "wrkspc_test"
