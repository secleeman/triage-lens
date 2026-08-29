import json

import httpx
import pytest

from conftest import make_client
from triage_lens import ai
from triage_lens.models import EnrichedVulnerability, Priority, Vulnerability


def _vuln(cve_id="CVE-2021-0001", *, pkg="openssl", fixed="1.1.1n", target="app/pkg", known=True):
    return Vulnerability(
        cve_id=cve_id,
        pkg_name=pkg,
        installed_version="1.1.1k",
        fixed_version=fixed,
        cvss=9.8,
        target=target,
        fixed_version_known=known,
    )


def _item(cve_id="CVE-2021-0001", *, priority=Priority.P0, **kwargs):
    return EnrichedVulnerability(
        vuln=_vuln(cve_id, **kwargs),
        epss=0.5,
        in_kev=True,
        priority=priority,
        reason="テスト用",
    )


def _api_response(comments):
    """Claude API の応答（構造化出力）を模した JSON。"""
    body = json.dumps({"comments": comments}, ensure_ascii=False)
    return httpx.Response(
        200,
        json={
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": body}],
        },
    )


def make_handler(response_factory):
    """送られたリクエストを記録するハンドラ。"""
    requests = []

    def handler(request):
        requests.append({"url": request.url, "headers": request.headers, "body": request.content})
        return response_factory(len(requests))

    handler.requests = requests
    return handler


def sent_entries(request):
    """リクエストのボディから、送信された脆弱性の配列を取り出す。"""
    body = json.loads(request["body"])
    return json.loads(body["messages"][0]["content"])


# --- APIキー -------------------------------------------------------------


def test_APIキーが未設定ならNoneを返す():
    assert ai.read_api_key({}) is None


def test_空文字や空白だけのAPIキーは未設定として扱う():
    assert ai.read_api_key({ai.API_KEY_ENV: ""}) is None
    assert ai.read_api_key({ai.API_KEY_ENV: "   "}) is None


def test_APIキーが設定されていれば前後の空白を落として返す():
    assert ai.read_api_key({ai.API_KEY_ENV: " sk-test \n"}) == "sk-test"


# --- 対象の選択 ----------------------------------------------------------


def test_対象はP0とP1のみ():
    items = [
        _item("CVE-2021-0001", priority=Priority.P0),
        _item("CVE-2021-0002", priority=Priority.P1),
        _item("CVE-2021-0003", priority=Priority.P2),
        _item("CVE-2021-0004", priority=Priority.P3),
    ]

    targets = ai.select_targets(items, limit=10)

    assert [item.vuln.cve_id for item in targets] == ["CVE-2021-0001", "CVE-2021-0002"]


def test_上限件数で対象を打ち切る():
    items = [_item(f"CVE-2021-{i:04d}") for i in range(10)]

    assert len(ai.select_targets(items, limit=3)) == 3
    assert ai.select_targets(items, limit=0) == []


# --- 送信内容 ------------------------------------------------------------


def test_検出箇所と対象名は送らない():
    payload = ai.request_payload(_item(target="/opt/secret-project/app/Gemfile.lock"))

    serialized = json.dumps(payload, ensure_ascii=False)
    assert "secret-project" not in serialized
    assert "target" not in payload
    assert "artifact" not in payload


def test_判定に必要な公開情報は送る():
    payload = ai.request_payload(_item("CVE-2021-0001"))

    assert payload["cve"] == "CVE-2021-0001"
    assert payload["package"] == "openssl"
    assert payload["installed_version"] == "1.1.1k"
    assert payload["fixed_version"] == "1.1.1n"
    assert payload["cvss"] == 9.8
    assert payload["epss"] == 0.5
    assert payload["in_kev"] is True
    assert payload["priority"] == "P0"


def test_修正版の状態は3つを区別する():
    assert ai.request_payload(_item(fixed="1.1.1n"))["fix_status"] == "available"
    assert ai.request_payload(_item(fixed=None))["fix_status"] == "none"
    assert ai.request_payload(_item(fixed=None, known=False))["fix_status"] == "unknown"


def test_APIキーはヘッダで送りURLには出さない():
    handler = make_handler(lambda _: _api_response([{"id": "1", "comment": "上げてください"}]))

    with make_client(handler) as client:
        ai.annotate([_item()], api_key="sk-secret", lang="ja", client=client)

    request = handler.requests[0]
    assert request["headers"]["x-api-key"] == "sk-secret"
    assert request["headers"]["anthropic-version"] == ai.API_VERSION
    assert "sk-secret" not in str(request["url"])


def test_モデルと構造化出力の指定を送る():
    handler = make_handler(lambda _: _api_response([{"id": "1", "comment": "上げてください"}]))

    with make_client(handler) as client:
        ai.annotate([_item()], api_key="k", lang="ja", model="test-model", client=client)

    body = json.loads(handler.requests[0]["body"])
    assert body["model"] == "test-model"
    assert body["output_config"]["format"]["type"] == "json_schema"
    assert body["output_config"]["format"]["schema"] == ai.RESPONSE_SCHEMA


# --- まとめ方 ------------------------------------------------------------


def test_複数のCVEを1回のリクエストにまとめる():
    items = [_item(f"CVE-2021-{i:04d}") for i in range(5)]
    handler = make_handler(
        lambda _: _api_response([{"id": str(n), "comment": f"c{n}"} for n in range(1, 6)])
    )

    with make_client(handler) as client:
        annotated, annotation = ai.annotate(items, api_key="k", lang="ja", client=client)

    assert len(handler.requests) == 1
    assert len(sent_entries(handler.requests[0])) == 5
    assert annotation.generated == 5
    assert [item.ai_comment for item in annotated] == [f"c{n}" for n in range(1, 6)]


def test_チャンクサイズを超えたら分割して送る(monkeypatch):
    monkeypatch.setattr(ai, "CHUNK_SIZE", 2)
    items = [_item(f"CVE-2021-{i:04d}") for i in range(5)]
    handler = make_handler(
        lambda _: _api_response([{"id": str(n), "comment": f"c{n}"} for n in range(1, 3)])
    )

    with make_client(handler) as client:
        ai.annotate(items, api_key="k", lang="ja", client=client)

    assert [len(sent_entries(request)) for request in handler.requests] == [2, 2, 1]


def test_送信内容が同じ検出は1回だけ問い合わせて両方に反映する():
    # 検出箇所を送らないため、検出箇所だけが違う2件は送信内容が同一になる
    items = [_item(target="app/a"), _item(target="app/b")]
    handler = make_handler(lambda _: _api_response([{"id": "1", "comment": "1回だけ"}]))

    with make_client(handler) as client:
        annotated, annotation = ai.annotate(items, api_key="k", lang="ja", client=client)

    assert len(sent_entries(handler.requests[0])) == 1
    assert [item.ai_comment for item in annotated] == ["1回だけ", "1回だけ"]
    assert annotation.generated == 2


def test_P2とP3は送らない():
    items = [
        _item("CVE-2021-0001", priority=Priority.P0),
        _item("CVE-2021-0002", priority=Priority.P2),
    ]
    handler = make_handler(lambda _: _api_response([{"id": "1", "comment": "対応方針"}]))

    with make_client(handler) as client:
        annotated, _ = ai.annotate(items, api_key="k", lang="ja", client=client)

    entries = sent_entries(handler.requests[0])
    assert [entry["cve"] for entry in entries] == ["CVE-2021-0001"]
    assert annotated[1].ai_comment is None


def test_上限で絞ったことが注記に残る():
    items = [_item(f"CVE-2021-{i:04d}") for i in range(5)]
    handler = make_handler(lambda _: _api_response([{"id": "1", "comment": "c"}]))

    with make_client(handler) as client:
        _, annotation = ai.annotate(items, api_key="k", lang="ja", limit=2, client=client)

    assert annotation.target_count == 2
    assert annotation.limited is True


def test_言語ごとに違うプロンプトを送る():
    handler = make_handler(lambda _: _api_response([{"id": "1", "comment": "c"}]))

    with make_client(handler) as client:
        ai.annotate([_item()], api_key="k", lang="en", client=client)

    system = json.loads(handler.requests[0]["body"])["system"]
    assert system == ai._SYSTEM_PROMPTS["en"]
    assert "あなた" not in system


# --- 異常系 --------------------------------------------------------------


@pytest.mark.parametrize("status", [401, 403, 400, 404])
def test_リトライしても無駄な応答は1回で諦める(status):
    handler = make_handler(lambda _: httpx.Response(status, json={"error": "x"}))

    with make_client(handler) as client:
        annotated, annotation = ai.annotate([_item()], api_key="k", lang="ja", client=client)

    assert len(handler.requests) == 1
    assert annotation is None
    assert annotated[0].ai_comment is None


def test_サーバエラーはリトライしてから諦める():
    handler = make_handler(lambda _: httpx.Response(500, json={"error": "x"}))

    with make_client(handler) as client:
        _, annotation = ai.annotate([_item()], api_key="k", lang="ja", client=client)

    assert len(handler.requests) == 3
    assert annotation is None


def test_レート制限のretry_afterを尊重して待つ(recorded_sleeps):
    def factory(count):
        if count == 1:
            return httpx.Response(429, headers={"retry-after": "7"}, json={"error": "x"})
        return _api_response([{"id": "1", "comment": "待った後に成功"}])

    handler = make_handler(factory)
    with make_client(handler) as client:
        annotated, _ = ai.annotate([_item()], api_key="k", lang="ja", client=client)

    assert recorded_sleeps == [7.0]
    assert annotated[0].ai_comment == "待った後に成功"


def test_retry_afterが長すぎる場合は上限までしか待たない(recorded_sleeps):
    def factory(count):
        if count == 1:
            return httpx.Response(429, headers={"retry-after": "99999"}, json={"error": "x"})
        return _api_response([{"id": "1", "comment": "ok"}])

    handler = make_handler(factory)
    with make_client(handler) as client:
        ai.annotate([_item()], api_key="k", lang="ja", client=client)

    assert recorded_sleeps == [60.0]


@pytest.mark.parametrize(
    "payload",
    [
        {"content": "配列ではない"},
        {"content": []},
        {"content": [{"type": "text", "text": "JSONではない"}]},
        {"content": [{"type": "text", "text": '{"comments": "配列ではない"}'}]},
        {"content": [{"type": "text", "text": "[]"}]},
        ["辞書ではない"],
    ],
)
def test_応答が想定と違えば取得失敗として扱う(payload):
    handler = make_handler(lambda _: httpx.Response(200, json=payload))

    with make_client(handler) as client:
        annotated, annotation = ai.annotate([_item()], api_key="k", lang="ja", client=client)

    assert annotation is None
    assert annotated[0].ai_comment is None


def test_一部だけ生成できた場合は取れたぶんを載せる(monkeypatch):
    monkeypatch.setattr(ai, "CHUNK_SIZE", 1)
    items = [_item("CVE-2021-0001"), _item("CVE-2021-0002")]

    def factory(count):
        if count == 1:
            return _api_response([{"id": "1", "comment": "1件目だけ"}])
        return httpx.Response(500, json={"error": "x"})

    handler = make_handler(factory)
    with make_client(handler) as client:
        annotated, annotation = ai.annotate(items, api_key="k", lang="ja", client=client)

    assert annotated[0].ai_comment == "1件目だけ"
    assert annotated[1].ai_comment is None
    assert annotation.generated == 1
    assert annotation.target_count == 2


def test_壊れた要素は読み飛ばして他の要素は残す():
    items = [_item("CVE-2021-0001"), _item("CVE-2021-0002")]
    handler = make_handler(
        lambda _: _api_response(
            ["文字列", {"id": 1, "comment": "IDが数値"}, {"id": "2", "comment": "生き残り"}]
        )
    )

    with make_client(handler) as client:
        annotated, annotation = ai.annotate(items, api_key="k", lang="ja", client=client)

    assert annotated[0].ai_comment is None
    assert annotated[1].ai_comment == "生き残り"
    assert annotation.generated == 1


def test_連続して失敗したら残りのチャンクを試さない(monkeypatch):
    monkeypatch.setattr(ai, "CHUNK_SIZE", 1)
    monkeypatch.setattr(ai, "MAX_CONSECUTIVE_FAILURES", 2)
    items = [_item(f"CVE-2021-{i:04d}") for i in range(10)]
    handler = make_handler(lambda _: httpx.Response(403, json={"error": "x"}))

    with make_client(handler) as client:
        _, annotation = ai.annotate(items, api_key="k", lang="ja", client=client)

    # 403 はリトライしないので、2チャンク分＝2リクエストで打ち切られる
    assert len(handler.requests) == 2
    assert annotation is None


def test_全体の実行時間の上限で打ち切る(monkeypatch):
    monkeypatch.setattr(ai, "CHUNK_SIZE", 1)
    clock = iter([0.0, 0.0, 999.0, 999.0, 999.0])
    monkeypatch.setattr(ai, "monotonic", lambda: next(clock))
    items = [_item(f"CVE-2021-{i:04d}") for i in range(5)]
    handler = make_handler(lambda _: _api_response([{"id": "1", "comment": "c"}]))

    with make_client(handler) as client:
        _, annotation = ai.annotate(items, api_key="k", lang="ja", client=client)

    assert len(handler.requests) == 1
    assert annotation.generated == 1


def test_APIキーはエラーになっても外に出ない():
    handler = make_handler(lambda _: httpx.Response(401, json={"error": "unauthorized"}))

    with make_client(handler) as client:
        annotated, annotation = ai.annotate(
            [_item()], api_key="sk-super-secret", lang="ja", client=client
        )

    assert annotation is None
    assert all("sk-super-secret" not in str(item) for item in annotated)


def test_対象が無ければ通信しない():
    handler = make_handler(lambda _: pytest.fail("リクエストが発生した"))

    with make_client(handler) as client:
        annotated, annotation = ai.annotate(
            [_item(priority=Priority.P2)], api_key="k", lang="ja", client=client
        )

    assert handler.requests == []
    assert annotation is None
    assert annotated[0].ai_comment is None


# --- 出力の無害化 --------------------------------------------------------


def test_表を壊す縦棒をエスケープする():
    assert ai.sanitize("a|b") == "a\\|b"


def test_改行と連続する空白を1つの空白に潰す():
    assert ai.sanitize("1行目\n2行目\r\n  3行目") == "1行目 2行目 3行目"


def test_HTMLタグをそのまま出さない():
    cleaned = ai.sanitize("<script>alert(1)</script>")

    assert "<script>" not in cleaned
    assert cleaned == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_リンク記法と画像記法とコード記法を無効化する():
    assert ai.sanitize("[link](http://x)") == "\\[link\\](http://x)"
    assert ai.sanitize("![img](http://x)") == "!\\[img\\](http://x)"
    assert ai.sanitize("`cmd`") == "\\`cmd\\`"


def test_長すぎる出力は上限で切り詰める():
    cleaned = ai.sanitize("あ" * 500, max_length=10)

    assert len(cleaned) == 10
    assert cleaned.endswith("…")


def test_空白だけの出力は捨てる():
    assert ai.sanitize("   \n  ") == ""


def test_無害化された文字列がレポートに入る():
    handler = make_handler(lambda _: _api_response([{"id": "1", "comment": "a|b <b>c</b>"}]))

    with make_client(handler) as client:
        annotated, _ = ai.annotate([_item()], api_key="k", lang="ja", client=client)

    assert annotated[0].ai_comment == "a\\|b &lt;b&gt;c&lt;/b&gt;"


def test_送っていないIDのコメントは使わない():
    handler = make_handler(
        lambda _: _api_response(
            [{"id": "999", "comment": "送っていないID"}, {"id": "1", "comment": "正しいID"}]
        )
    )

    with make_client(handler) as client:
        annotated, annotation = ai.annotate([_item()], api_key="k", lang="ja", client=client)

    assert annotated[0].ai_comment == "正しいID"
    assert annotation.generated == 1


def test_送っていないIDだけが返ったチャンクは失敗として扱う(monkeypatch):
    # 使えない応答を成功と数えると打ち切りが働かず、残りのチャンクにも課金される
    monkeypatch.setattr(ai, "CHUNK_SIZE", 1)
    monkeypatch.setattr(ai, "MAX_CONSECUTIVE_FAILURES", 2)
    items = [_item(f"CVE-2021-{i:04d}") for i in range(10)]
    handler = make_handler(lambda _: _api_response([{"id": "999", "comment": "送っていないID"}]))

    with make_client(handler) as client:
        annotated, annotation = ai.annotate(items, api_key="k", lang="ja", client=client)

    assert len(handler.requests) == 2
    assert annotation is None
    assert all(item.ai_comment is None for item in annotated)


# --- ワークスペースID（組織アカウントのキー向け） ------------------------


def test_ワークスペースIDは未設定ならヘッダに入れない():
    handler = make_handler(lambda _: _api_response([{"id": "1", "comment": "c"}]))

    with make_client(handler) as client:
        ai.annotate([_item()], api_key="k", lang="ja", client=client)

    assert "anthropic-workspace-id" not in handler.requests[0]["headers"]


def test_ワークスペースIDが設定されていればヘッダで送る():
    handler = make_handler(lambda _: _api_response([{"id": "1", "comment": "c"}]))

    with make_client(handler) as client:
        ai.annotate([_item()], api_key="k", lang="ja", workspace_id="wrkspc_1", client=client)

    assert handler.requests[0]["headers"]["anthropic-workspace-id"] == "wrkspc_1"


def test_ワークスペースIDも環境変数から読む():
    assert ai.read_workspace_id({}) is None
    assert ai.read_workspace_id({ai.WORKSPACE_ID_ENV: "  "}) is None
    assert ai.read_workspace_id({ai.WORKSPACE_ID_ENV: " wrkspc_1 "}) == "wrkspc_1"
