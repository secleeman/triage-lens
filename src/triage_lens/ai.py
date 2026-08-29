"""Claude API による対応方針コメントの生成（`--ai`）。

このモジュールは**判定（P0〜P3）に一切関与しない**。優先順位は公開データから
決定的に決めており、AI に上書きさせない。

生成に失敗してもレポート本体が壊れないよう、このモジュールは外に例外を投げない。
取得できなかったぶんは「コメントが付かない」だけになる。

外部に送るデータは `request_payload` の1箇所に固定してある（検出箇所と対象名は送らない）。
変更するときは `docs/requirements-p3.md` の表と CLAUDE.md 絶対ルール4の例外条項も
合わせて更新すること。
"""

import json
import os
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from typing import Any

import httpx

from .errors import FetchError
from .http_client import post_json
from .models import AiAnnotation, EnrichedVulnerability, Priority

#: Claude API のエンドポイント
API_URL = "https://api.anthropic.com/v1/messages"

#: API のバージョン（リクエストヘッダ）
API_VERSION = "2023-06-01"

#: API キーを読む環境変数。コマンドライン引数では受け取らない
#: （シェル履歴・`ps`・CIのログに残るため）
API_KEY_ENV = "ANTHROPIC_API_KEY"

#: ワークスペースIDを読む環境変数。
#: 組織アカウントの「identity-linked」なキーは、どのワークスペースの利用として
#: 課金するかを毎リクエストで示す必要があり、無いと 400 で拒否される。
#: 個人キーでは不要なので、設定されているときだけ送る。
WORKSPACE_ID_ENV = "ANTHROPIC_WORKSPACE_ID"

#: 既定のモデル。モデルごとの分岐は書かない（渡された文字列をそのまま使う）
DEFAULT_MODEL = "claude-haiku-4-5"

#: 生成対象の上限件数の既定値
DEFAULT_LIMIT = 50

#: コメントを付ける優先度ランク。レポートに全件表示されるのはこの2つ
TARGET_PRIORITIES = (Priority.P0, Priority.P1)

#: 1リクエストにまとめる件数（1件ずつ問い合わせない）
CHUNK_SIZE = 20

#: 1件あたりに見込む出力トークン数（`max_tokens` の見積もりに使う）
TOKENS_PER_ITEM = 160

#: `max_tokens` に足す応答の枠組み分
TOKENS_OVERHEAD = 256

#: レポートに載せる1コメントの最大文字数
MAX_COMMENT_LENGTH = 200

#: 生成全体にかける時間の上限（秒）。外部APIが応答しないときに固まって見えないようにする
TIME_BUDGET_SECONDS = 120.0

#: 連続でこの回数失敗したら、残りのチャンクを試さず打ち切る（サーキットブレーカー）
MAX_CONSECUTIVE_FAILURES = 2

#: そのまま出すと HTML として解釈されうる文字
_HTML_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}

#: そのまま出すと Markdown の記法として働く文字
_MARKDOWN_ESCAPES = ("|", "[", "]", "`")

#: 応答の構造。自由文を正規表現で切り出すような読み方をしないための固定スキーマ
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "comments": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "comment": {"type": "string"},
                },
                "required": ["id", "comment"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["comments"],
    "additionalProperties": False,
}

#: プロンプトは「レポート本文」ではないため i18n の対象外とし、ここに置く
_SYSTEM_PROMPTS: dict[str, str] = {
    "ja": (
        "あなたは脆弱性対応の実務者に向けて、対応方針を短く書くアシスタントです。\n"
        "入力は JSON の配列で、1要素が1件の脆弱性です。\n"
        "各要素について、日本語120文字以内・1〜2行の対応方針を書いてください。\n"
        "\n"
        "守ること:\n"
        "- まず何をすべきかを具体的に書く"
        "（修正版に上げる / 緩和策を採る / 影響範囲を確認する 等）\n"
        '- fix_status が "available" なら fixed_version に上げることを軸に書く\n'
        '- fix_status が "none" なら、修正版が無い前提の対処を書く\n'
        '- fix_status が "unknown" なら、修正版の有無を確認することから書く\n'
        "- priority は決定済み。優先度の判定・変更・言い換えをしない\n"
        "- 「危険です」「至急」のような煽りを書かない\n"
        "- 脆弱性そのものの技術解説を書かない\n"
        "- 入力に無いバージョン番号・コマンド・URL を作らない。確実でないことは書かない\n"
        "- 入力と同じ id をキーにして、指定された形式の JSON だけを返す"
    ),
    "en": (
        "You write short remediation guidance for engineers handling vulnerabilities.\n"
        "The input is a JSON array; each element is one finding.\n"
        "For each element, write one to two lines of guidance, at most 200 characters.\n"
        "\n"
        "Rules:\n"
        "- Say what to do first and concretely (upgrade, mitigate, confirm exposure, ...)\n"
        '- If fix_status is "available", centre the advice on moving to fixed_version\n'
        '- If fix_status is "none", advise on handling it without a fixed release\n'
        '- If fix_status is "unknown", start from confirming whether a fix exists\n'
        "- The priority is already decided. Do not judge, change, or restate it\n"
        "- No alarmist language such as 'critical' or 'urgent'\n"
        "- Do not explain the vulnerability itself\n"
        "- Never invent version numbers, commands, or URLs that are not in the input\n"
        "- Return only the specified JSON, keyed by the same id as the input"
    ),
}


def monotonic() -> float:
    """経過時間の取得。テストから差し替えられるよう1箇所にまとめてある。"""
    return time.monotonic()


def read_api_key(env: Mapping[str, str] | None = None) -> str | None:
    """環境変数から API キーを読む。未設定・空文字なら None。"""
    return _read_env(API_KEY_ENV, env)


def read_workspace_id(env: Mapping[str, str] | None = None) -> str | None:
    """環境変数からワークスペースIDを読む。未設定・空文字なら None。"""
    return _read_env(WORKSPACE_ID_ENV, env)


def _read_env(name: str, env: Mapping[str, str] | None) -> str | None:
    source = os.environ if env is None else env
    value = source.get(name, "").strip()
    return value or None


def select_targets(
    items: Sequence[EnrichedVulnerability], *, limit: int = DEFAULT_LIMIT
) -> list[EnrichedVulnerability]:
    """コメントを生成する対象。P0 / P1 のみを、上限件数まで。"""
    return [items[index] for index in _target_indexes(items, limit)]


def request_payload(item: EnrichedVulnerability) -> dict[str, Any]:
    """Anthropic に送る1件分のデータ。

    **検出箇所（target）と対象名は送らない。** 利用者の内部構成が推測できるため。
    送る項目は `docs/requirements-p3.md` の表に固定されている。
    """
    vuln = item.vuln
    return {
        "cve": vuln.cve_id,
        "package": vuln.pkg_name,
        "installed_version": vuln.installed_version,
        "fixed_version": vuln.fixed_version,
        "fix_status": _fix_status(item),
        "cvss": vuln.cvss,
        "epss": item.epss,
        "in_kev": item.in_kev,
        "priority": item.priority.name,
    }


def annotate(
    items: Sequence[EnrichedVulnerability],
    *,
    api_key: str,
    lang: str,
    model: str = DEFAULT_MODEL,
    limit: int = DEFAULT_LIMIT,
    workspace_id: str | None = None,
    client: httpx.Client | None = None,
) -> tuple[list[EnrichedVulnerability], AiAnnotation | None]:
    """対象にコメントを付けた一覧と、レポートに書く注記を返す。

    1件も生成できなかった場合、注記は None になり、一覧は入力と同じ内容になる
    （＝レポートが `--ai` を付けない場合と一致する）。
    """
    indexes = _target_indexes(items, limit)
    candidates = sum(1 for item in items if item.priority in TARGET_PRIORITIES)
    if not indexes:
        return list(items), None

    comments = _generate(
        [items[index] for index in indexes],
        api_key=api_key,
        lang=lang,
        model=model,
        workspace_id=workspace_id,
        client=client,
    )
    if not comments:
        return list(items), None

    annotated = list(items)
    generated = 0
    for index in indexes:
        comment = comments.get(_payload_key(request_payload(items[index])))
        if comment:
            annotated[index] = replace(items[index], ai_comment=comment)
            generated += 1

    if generated == 0:
        return list(items), None

    return annotated, AiAnnotation(
        model=model,
        generated=generated,
        target_count=len(indexes),
        limited=len(indexes) < candidates,
    )


def sanitize(text: str, *, max_length: int = MAX_COMMENT_LENGTH) -> str:
    """AI の出力をレポートに載せられる形にする。

    AI の出力は外部から来た文字列として扱い、Markdown の構造を壊す記法を無効化する。
    ここで無害化済みにするため、レポート側では再エスケープしない。

    `max_length` は**無害化した後の長さ**の上限。無害化は文字数を増やす（`<` が
    `&lt;` になる等）ため、先に切り詰めるだけでは上限を守れない。1文字ずつ変換して
    積み上げることで、エスケープの途中で切れることもない。
    """
    collapsed = " ".join(text.split())
    if not collapsed:
        return ""

    parts: list[str] = []
    length = 0
    truncated = False
    for char in collapsed:
        piece = _escape_char(char)
        # 打ち切り記号「…」のぶんを残しておく
        if length + len(piece) > max_length - 1:
            truncated = True
            break
        parts.append(piece)
        length += len(piece)

    escaped = "".join(parts)
    return escaped.rstrip() + "…" if truncated else escaped


def _escape_char(char: str) -> str:
    """1文字を、レポートに埋めても安全な表記に変換する。"""
    if char in _HTML_ESCAPES:
        # HTML タグをそのまま出さない
        return _HTML_ESCAPES[char]
    if char == "\\":
        # バックスラッシュを潰さないと、生成文に元から入っていた `\[` が
        # 「リテラルの \」＋「生きた [」と解釈されて無害化を素通りしてしまう
        return "\\\\"
    if char in _MARKDOWN_ESCAPES:
        # 表・リンク記法・画像記法・コード記法を無効化する
        return "\\" + char
    return char


def _target_indexes(items: Sequence[EnrichedVulnerability], limit: int) -> list[int]:
    indexes = [index for index, item in enumerate(items) if item.priority in TARGET_PRIORITIES]
    return indexes[: max(0, limit)]


def _fix_status(item: EnrichedVulnerability) -> str:
    """修正版の状態。「存在しない」と「分からない」を混同しない（Phase 2 と同じ方針）。"""
    vuln = item.vuln
    if vuln.fixed_version:
        return "available"
    return "none" if vuln.fixed_version_known else "unknown"


def _generate(
    targets: Sequence[EnrichedVulnerability],
    *,
    api_key: str,
    lang: str,
    model: str,
    workspace_id: str | None,
    client: httpx.Client | None,
) -> dict[str, str]:
    """送信内容ごとのコメントを集める。戻り値は「送信内容のキー → コメント」。"""
    payloads: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for item in targets:
        payload = request_payload(item)
        key = _payload_key(payload)
        # 検出箇所を送らないため、同じCVEが複数箇所で見つかると送信内容は同一になる。
        # 同じ内容を二度問い合わせない（そのぶん課金される）
        if key not in payloads:
            payloads[key] = payload
            order.append(key)

    comments: dict[str, str] = {}
    started = monotonic()
    consecutive_failures = 0

    for chunk in _chunks(order, CHUNK_SIZE):
        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            break
        remaining = TIME_BUDGET_SECONDS - (monotonic() - started)
        if remaining <= 0:
            break

        entries = [dict(payloads[key], id=str(number)) for number, key in enumerate(chunk, start=1)]
        # 残り時間を渡す。渡さないと、上限の直前に始まったチャンクが
        # リトライと retry-after の待機で上限を大きく超えて走る
        result = _request_comments(
            entries,
            api_key=api_key,
            lang=lang,
            model=model,
            workspace_id=workspace_id,
            client=client,
            time_budget=remaining,
        )
        if result is None:
            consecutive_failures += 1
            continue

        consecutive_failures = 0
        for number, key in enumerate(chunk, start=1):
            comment = result.get(str(number))
            if comment:
                comments[key] = comment

    return comments


def _request_comments(
    entries: list[dict[str, Any]],
    *,
    api_key: str,
    lang: str,
    model: str,
    workspace_id: str | None = None,
    client: httpx.Client | None = None,
    time_budget: float | None = None,
) -> dict[str, str] | None:
    """1チャンク分を問い合わせる。取得できなければ None（＝そのチャンクは諦める）。"""
    body = {
        "model": model,
        "max_tokens": len(entries) * TOKENS_PER_ITEM + TOKENS_OVERHEAD,
        "system": _system_prompt(lang),
        "messages": [
            {"role": "user", "content": json.dumps(entries, ensure_ascii=False, sort_keys=True)}
        ],
        "output_config": {"format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}},
    }
    try:
        payload = post_json(
            API_URL,
            payload=body,
            headers=_headers(api_key, workspace_id),
            client=client,
            time_budget=time_budget,
        )
    except FetchError:
        return None
    return _parse_comments(payload, {entry["id"] for entry in entries})


def _headers(api_key: str, workspace_id: str | None = None) -> dict[str, str]:
    """認証はヘッダで渡す。URL やクエリにキーを載せない。"""
    headers = {"x-api-key": api_key, "anthropic-version": API_VERSION}
    if workspace_id:
        headers["anthropic-workspace-id"] = workspace_id
    return headers


def _system_prompt(lang: str) -> str:
    return _SYSTEM_PROMPTS.get(lang, _SYSTEM_PROMPTS["en"])


def _parse_comments(payload: Any, expected_ids: set[str]) -> dict[str, str] | None:
    """応答を読む。想定と違えば None（＝取得失敗扱い）。例外は投げない。

    このチャンクで送っていないIDは捨てる。捨てた結果1件も残らなければ失敗として扱う。
    使えない応答を成功と数えると、打ち切りの判定が働かず、残りのチャンクにも
    無駄な課金が発生するため。
    """
    text = _first_text_block(payload)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("comments"), list):
        return None

    comments: dict[str, str] = {}
    for entry in data["comments"]:
        if not isinstance(entry, dict):
            continue
        entry_id = entry.get("id")
        comment = entry.get("comment")
        if not isinstance(entry_id, str) or not isinstance(comment, str):
            continue
        if entry_id not in expected_ids:
            continue
        cleaned = sanitize(comment)
        if cleaned:
            comments[entry_id] = cleaned
    return comments or None


def _first_text_block(payload: Any) -> str | None:
    if not isinstance(payload, dict) or not isinstance(payload.get("content"), list):
        return None
    for block in payload["content"]:
        if not isinstance(block, dict) or block.get("type") != "text":
            continue
        text = block.get("text")
        if isinstance(text, str) and text.strip():
            return text
    return None


def _payload_key(payload: dict[str, Any]) -> str:
    """送信内容が同一かどうかを判定するキー。"""
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    size = max(1, size)
    for start in range(0, len(items), size):
        yield items[start : start + size]
