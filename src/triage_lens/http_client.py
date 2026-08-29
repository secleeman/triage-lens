"""外部APIへのHTTPアクセス（リトライ付き）。"""

import math
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from . import __version__
from .errors import FetchError

#: 1リクエストあたりのタイムアウト（秒）
DEFAULT_TIMEOUT = 20.0

#: 同一リクエストの最大試行回数
MAX_ATTEMPTS = 3

#: 指数バックオフの基準秒数（1回目の待機時間）
BACKOFF_BASE_SECONDS = 1.0

#: `retry-after` に従って待つ最大秒数。
#: 極端に長い指定でコマンドが固まったように見えるのを防ぐ。
MAX_RETRY_AFTER_SECONDS = 60.0

#: 4xx のうち、投げ直せば結果が変わりうるもの。
#: これ以外の 4xx は要求そのものの誤りなので、待っても課金と待ち時間が増えるだけ。
RETRYABLE_CLIENT_STATUSES = frozenset({408, 429})

#: httpx のタイムアウトは「接続 / 送信 / 受信 / プール待ち」の各フェーズごとの上限。
#: 1リクエスト全体を残り時間で縛るには、フェーズ数で割って配分する必要がある。
TIMEOUT_PHASES = 4

USER_AGENT = f"triage-lens/{__version__} (+https://github.com/secleeman/triage-lens)"


def sleep(seconds: float) -> None:
    """待機処理。テストから差し替えられるよう1箇所にまとめてある。"""
    time.sleep(seconds)


def monotonic() -> float:
    """経過時間の取得。テストから差し替えられるよう1箇所にまとめてある。"""
    return time.monotonic()


def now() -> datetime:
    """現在時刻（UTC）。テストから差し替えられるよう1箇所にまとめてある。"""
    return datetime.now(UTC)


def build_client(timeout: float = DEFAULT_TIMEOUT) -> httpx.Client:
    """既定の設定を持つHTTPクライアントを作る。"""
    return httpx.Client(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )


def get_json(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    client: httpx.Client | None = None,
    max_attempts: int = MAX_ATTEMPTS,
    backoff_base: float = BACKOFF_BASE_SECONDS,
) -> Any:
    """JSON を取得する。失敗したら指数バックオフでリトライし、諦めたら `FetchError`。"""
    owns_client = client is None
    client = client if client is not None else build_client()
    last_error: Exception | None = None

    try:
        for attempt in range(1, max_attempts + 1):
            try:
                response = client.get(url, params=params)
                response.raise_for_status()
                return response.json()
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
                if attempt < max_attempts:
                    sleep(backoff_base * (2 ** (attempt - 1)))
    finally:
        if owns_client:
            client.close()

    raise FetchError(f"{url} の取得に{max_attempts}回失敗しました（{last_error}）") from last_error


def post_json(
    url: str,
    *,
    payload: Any,
    headers: dict[str, str] | None = None,
    client: httpx.Client | None = None,
    max_attempts: int = MAX_ATTEMPTS,
    backoff_base: float = BACKOFF_BASE_SECONDS,
    time_budget: float | None = None,
) -> Any:
    """JSON を POST して JSON を受け取る。諦めたら `FetchError`。

    `get_json` との違いは3点。やり直しても結果が変わらない応答はその場で諦めること
    （待っても結果が変わらず、無駄な待ち時間と課金を生むため）、
    `retry-after` ヘッダがあればそれに従って待つこと、そして `time_budget` に
    この呼び出し全体で使ってよい秒数を渡せること。

    `time_budget` は通信・待機の両方を縛る。残り時間より長いタイムアウトや待機は
    残り時間まで縮め、使い切ったらリトライせずに諦める。呼び出し側の「全体で
    N秒まで」という上限が、1回の呼び出しに引きずられて破られないようにするため。

    ただしこれは**厳密な実時間の保証ではない**。httpx のタイムアウトは
    「1回の読み取りが止まっている時間」に対する上限なので、相手が少しずつ
    途切れずに送り続ける場合、1リクエストが残り時間を超えて続きうる。
    実在のサーバでは起きないが、保証としてはこの範囲にとどまる。
    """
    owns_client = client is None
    client = client if client is not None else build_client()
    last_error: Exception | None = None
    deadline = None if time_budget is None else monotonic() + time_budget

    try:
        for attempt in range(1, max_attempts + 1):
            remaining = None if deadline is None else deadline - monotonic()
            if remaining is not None and remaining <= 0:
                break

            wait: float | None = None
            try:
                response = client.post(
                    url, json=payload, headers=headers, timeout=_timeout(client, remaining)
                )
                response.raise_for_status()
                return response.json()
            except httpx.HTTPStatusError as exc:
                last_error = exc
                if not _is_retryable(exc.response.status_code):
                    break
                wait = retry_after_seconds(exc.response)
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
            if attempt < max_attempts:
                sleep(_wait_seconds(wait, attempt, backoff_base, deadline))
    finally:
        if owns_client:
            client.close()

    raise FetchError(f"{url} の取得に失敗しました（{last_error}）") from last_error


def _is_retryable(status: int) -> bool:
    """同じ要求を投げ直して結果が変わりうるか。"""
    if status in RETRYABLE_CLIENT_STATUSES:
        return True
    return not 400 <= status < 500


def _timeout(client: httpx.Client, remaining: float | None) -> Any:
    """1リクエストのタイムアウト。残り時間があれば縮める（伸ばしはしない）。

    `httpx.Timeout(x)` は各フェーズに x を割り当てるため、そのまま残り時間を渡すと
    1リクエストで残り時間の数倍かかりうる。フェーズ数で割って配分することで、
    1リクエストの所要時間が残り時間を超えないようにする。
    """
    if remaining is None:
        return httpx.USE_CLIENT_DEFAULT
    per_phase = remaining / TIMEOUT_PHASES
    configured = client.timeout

    def capped(phase: str) -> float:
        value = getattr(configured, phase, None)
        return per_phase if value is None else min(per_phase, value)

    return httpx.Timeout(
        connect=capped("connect"),
        read=capped("read"),
        write=capped("write"),
        pool=capped("pool"),
    )


def _wait_seconds(
    retry_after: float | None, attempt: int, backoff_base: float, deadline: float | None
) -> float:
    """次の試行までの待機秒数。残り時間を超えて待たない。"""
    wait = retry_after if retry_after is not None else backoff_base * (2 ** (attempt - 1))
    if deadline is None:
        return wait
    return max(0.0, min(wait, deadline - monotonic()))


def retry_after_seconds(response: httpx.Response) -> float | None:
    """`retry-after` ヘッダの待ち秒数。読めなければ None（＝バックオフに任せる）。

    RFC 9110 は「秒数」と「HTTP-date」の2つの書き方を認めているため、両方を読む。
    指定の時刻を過ぎている場合は 0 秒（＝すぐ再試行してよい）として扱う。
    """
    raw = response.headers.get("retry-after")
    if raw is None:
        return None
    seconds = _delay_seconds(raw)
    if seconds is None:
        seconds = _http_date_seconds(raw)
    if seconds is None:
        return None
    return min(max(0.0, seconds), MAX_RETRY_AFTER_SECONDS)


def _delay_seconds(raw: str) -> float | None:
    try:
        seconds = float(raw)
    except (TypeError, ValueError):
        return None
    return seconds if math.isfinite(seconds) else None


def _http_date_seconds(raw: str) -> float | None:
    try:
        target = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if target is None:
        return None
    if target.tzinfo is None:
        # タイムゾーンの無い書き方は GMT とみなす（RFC 9110）
        target = target.replace(tzinfo=UTC)
    return (target - now()).total_seconds()
