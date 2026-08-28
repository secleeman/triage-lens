"""外部APIへのHTTPアクセス（リトライ付き）。"""

import time
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

USER_AGENT = f"triage-lens/{__version__} (+https://github.com/secleeman/triage-lens)"


def sleep(seconds: float) -> None:
    """待機処理。テストから差し替えられるよう1箇所にまとめてある。"""
    time.sleep(seconds)


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
