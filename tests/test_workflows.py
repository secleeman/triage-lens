"""GitHub Actions のワークフローが YAML として読めることを検査する。

ワークフローの `run: |` に書いたスクリプトは、字下げを1行でも崩すと
そこでブロックが終わってしまい、ファイル全体が YAML として壊れる。
壊れても手元では何も起きず、push したあとに GitHub 側で
「workflow file issue」として 0 秒で落ちるだけなので気づきにくい。

実際に weekly-stats.yml で1行の字下げ漏れが起き、定期実行が止まっていた。
"""

from pathlib import Path

import pytest
import yaml

WORKFLOWS_DIR = Path(__file__).resolve().parent.parent / ".github" / "workflows"

WORKFLOW_PATHS = sorted(WORKFLOWS_DIR.glob("*.yml"))


def test_workflows_exist() -> None:
    """glob が空でも各テストが通ってしまうため、1本以上あることを先に見る。"""
    assert WORKFLOW_PATHS


@pytest.mark.parametrize("path", WORKFLOW_PATHS, ids=lambda p: p.name)
def test_workflow_is_valid_yaml(path: Path) -> None:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"辞書として読めない: {path.name}"
    # YAML は裸の `on:` を真偽値の True と読む。どちらの綴りでも通す。
    assert "jobs" in document, f"jobs が無い: {path.name}"
    assert "on" in document or True in document, f"トリガーが無い: {path.name}"
