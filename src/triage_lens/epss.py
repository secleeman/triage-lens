"""EPSS（FIRST.org）から悪用確率スコアを一括取得する。"""

import math
from collections.abc import Iterable
from typing import Any

import httpx

from .errors import FetchError
from .http_client import get_json

EPSS_API_URL = "https://api.first.org/data/v1/epss"

#: 1リクエストにまとめるCVEの件数（1件ずつ問い合わせない）
CHUNK_SIZE = 100


def fetch_epss_scores(
    cve_ids: Iterable[str],
    *,
    client: httpx.Client | None = None,
    chunk_size: int = CHUNK_SIZE,
) -> tuple[dict[str, float], bool]:
    """CVE ID の一覧に対する EPSS スコアをまとめて取得する。

    戻り値は `(スコアの辞書, すべて取得できたか)`。
    一部でも取得に失敗した場合は 2つ目の要素が False になる（処理は継続する）。
    """
    unique_ids = [cve_id for cve_id in dict.fromkeys(cve_ids) if cve_id]
    if not unique_ids:
        return {}, True

    scores: dict[str, float] = {}
    complete = True
    for chunk in _chunks(unique_ids, chunk_size):
        try:
            payload = get_json(
                EPSS_API_URL,
                params={"cve": ",".join(chunk), "limit": len(chunk)},
                client=client,
            )
        except FetchError:
            complete = False
            continue

        parsed = _parse_scores(payload)
        if parsed is None:
            # HTTP 200 でも中身が想定と違う場合は「取得できなかった」として扱う
            complete = False
            continue
        scores.update(parsed)

    return scores, complete


def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
    size = max(1, size)
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _parse_scores(payload: Any) -> dict[str, float] | None:
    """EPSS API の応答を読む。応答そのものが想定外なら None（＝取得失敗扱い）。"""
    if not isinstance(payload, dict):
        return None
    status = payload.get("status")
    if isinstance(status, str) and status.upper() != "OK":
        return None
    if not isinstance(payload.get("data"), list):
        return None

    scores: dict[str, float] = {}
    for entry in payload["data"]:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cve")
        score = _as_probability(entry.get("epss"))
        if isinstance(cve_id, str) and cve_id and score is not None:
            scores[cve_id] = score
    return scores


def _as_probability(value: Any) -> float | None:
    """EPSS API は数値を文字列で返すため、0.0〜1.0 の実数に正規化する。"""
    if isinstance(value, bool):
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score) or score < 0.0 or score > 1.0:
        return None
    return score
