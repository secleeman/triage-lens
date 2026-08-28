"""CISA KEV（実際に悪用が確認された脆弱性カタログ）の取得とキャッシュ。"""

import json
import time
from pathlib import Path
from typing import Any

import httpx

from .errors import FetchError
from .http_client import get_json

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

#: キャッシュの有効期間（秒）。この間は再取得しない。
CACHE_TTL_SECONDS = 24 * 60 * 60

#: 取得したカタログを正常とみなすための、CVE ID を読み取れたエントリの最低割合。
#: HTTP 200 で中身が壊れたカタログを掴んだまま24時間キャッシュするのを防ぐ。
MIN_VALID_ENTRY_RATIO = 0.5

#: KEV情報の入手経路（レポートの注記に使う）
SOURCE_CACHE = "cache"
SOURCE_NETWORK = "network"
SOURCE_STALE_CACHE = "stale-cache"
SOURCE_UNAVAILABLE = "unavailable"


def default_cache_path() -> Path:
    """既定のキャッシュ保存先。"""
    return Path.home() / ".cache" / "triage-lens" / "kev.json"


def load_kev_ids(
    *,
    client: httpx.Client | None = None,
    cache_path: Path | None = None,
    ttl_seconds: float = CACHE_TTL_SECONDS,
    now: float | None = None,
) -> tuple[set[str] | None, str]:
    """KEV に載っている CVE ID の集合を返す。

    戻り値は `(CVE IDの集合, 入手経路)`。取得できなかった場合は集合が None になる
    （＝KEV掲載有無は「不明」として扱う）。
    """
    cache_path = cache_path if cache_path is not None else default_cache_path()
    now = now if now is not None else time.time()

    cached = _read_cache(cache_path)
    if cached is not None:
        cached_ids, cached_at = cached
        if now - cached_at < ttl_seconds:
            return cached_ids, SOURCE_CACHE

    try:
        payload = get_json(KEV_FEED_URL, client=client)
    except FetchError:
        payload = None

    ids = _extract_ids(payload)
    if ids is not None:
        _write_cache(cache_path, payload)
        return ids, SOURCE_NETWORK

    if cached is not None:
        return cached[0], SOURCE_STALE_CACHE
    return None, SOURCE_UNAVAILABLE


def _extract_ids(payload: Any) -> set[str] | None:
    """KEVカタログのJSONから CVE ID を取り出す。想定外の構造なら None。

    空のカタログや、大半のエントリから CVE ID を読み取れないカタログも
    「取得できなかった」とみなす（キャッシュに残さないため）。
    """
    if not isinstance(payload, dict):
        return None
    entries = payload.get("vulnerabilities")
    if not isinstance(entries, list) or not entries:
        return None

    ids = {
        entry["cveID"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("cveID"), str) and entry["cveID"]
    }
    if len(ids) < len(entries) * MIN_VALID_ENTRY_RATIO:
        return None
    return ids


def _read_cache(cache_path: Path) -> tuple[set[str], float] | None:
    """キャッシュを読む。存在しない・壊れている場合は None。"""
    try:
        raw = cache_path.read_text(encoding="utf-8")
        cached_at = cache_path.stat().st_mtime
    except (OSError, UnicodeDecodeError):
        return None

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None

    ids = _extract_ids(payload)
    if ids is None:
        return None
    return ids, cached_at


def _write_cache(cache_path: Path, payload: Any) -> None:
    """キャッシュを書く。失敗しても処理は続行する（あくまで高速化のため）。"""
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(payload), encoding="utf-8")
    except (OSError, TypeError, ValueError):
        return
