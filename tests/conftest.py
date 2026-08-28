from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from triage_lens import http_client, kev

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture(autouse=True)
def recorded_sleeps(monkeypatch) -> list[float]:
    """テスト中に実際の待機が発生しないようにし、待機秒数を記録する。"""
    recorded: list[float] = []
    monkeypatch.setattr(http_client, "sleep", recorded.append)
    return recorded


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    """外部に接続しないHTTPクライアントを作る。"""
    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def isolated_kev_cache(monkeypatch, tmp_path) -> Path:
    """テストが利用者のホームにあるキャッシュを読み書きしないようにする。"""
    cache_path = tmp_path / "kev-cache" / "kev.json"
    monkeypatch.setattr(kev, "default_cache_path", lambda: cache_path)
    return cache_path
