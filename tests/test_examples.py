"""examples/ に置いたレポートが、入力および現在の出力形式と合っているかを検査する。

examples/ は「インストールせずに出力の実物を見る」ための置き場で、
利用者が最初に見る成果物になる。中身が古いと、実際に動かしたときと
違うものを見せることになるため、次の3点を CI で見る。

- 置いてあるレポートが、置いてある入力から作られたものであること
- いまのコードで作り直しても同じ文面になること（出力形式の変更に取り残されていない）
- P0〜P3 が1件以上ずつ出ていて、省略された行が無いこと（例として成立している）

出力例は2組ある。Trivy の JSON（本番 / 開発を区別できない入力）と、npm 系の
CycloneDX（区別できる入力）で、レポートの見た目が変わるためどちらも置いてある。

外部APIには接続しない。レポートに書かれている EPSS / KEV の値を読み取って
そのまま作り直すため、この検査は committed されたファイルだけで完結する。
"""

import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from triage_lens.i18n import SUPPORTED_LANGS, catalog
from triage_lens.loader import load_scan
from triage_lens.models import Priority
from triage_lens.report import render_report
from triage_lens.scoring import prioritize

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = REPO_ROOT / "examples"
SAMPLE_INPUT = EXAMPLES_DIR / "trivy-sample.json"

#: 言語ごとのレポート
REPORTS = {lang: EXAMPLES_DIR / f"report-{lang}.md" for lang in SUPPORTED_LANGS}

#: 一覧表の行（先頭のセルが CVE ID になっている行）
_ROW_PREFIX = "| CVE-"

#: 一覧表のセルの並び（`report.table_header` の文言と同じ順序）
_CVE_COLUMN = 1
_EPSS_COLUMN = 6
_KEV_COLUMN = 7


def _summary_count(report: str, label: str) -> int:
    """サマリ表から、その優先度の件数を読み取る。"""
    match = re.search(rf"^\| {re.escape(label)} \| (\d+) \|", report, re.MULTILINE)
    assert match is not None, f"サマリ表に {label} の行が無い"
    return int(match.group(1))


def _rows(report: str) -> list[list[str]]:
    """一覧表の行をセルに分けて返す。"""
    return [
        [cell.strip() for cell in line.split("|")]
        for line in report.splitlines()
        if line.startswith(_ROW_PREFIX)
    ]


@pytest.fixture(scope="module", params=sorted(REPORTS))
def lang(request) -> str:
    return request.param


@pytest.fixture(scope="module")
def report(lang: str) -> str:
    return REPORTS[lang].read_text(encoding="utf-8")


def _generated_at(text: str, lang: str) -> datetime:
    """レポート冒頭の生成日時を読み取る。"""
    prefix = catalog(lang)("meta_generated_at", timestamp="")
    line = next(line for line in text.splitlines() if line.startswith(prefix))
    return datetime.strptime(line[len(prefix) :].strip(), "%Y-%m-%d %H:%M")


def _external_data(text: str, lang: str) -> tuple[dict[str, float], set[str]]:
    """レポートの一覧表から、生成時に使われた EPSS と KEV 掲載を復元する。"""
    unknown = catalog(lang)("unknown")
    kev_yes = catalog(lang)("kev_yes")

    epss_scores: dict[str, float] = {}
    kev_ids: set[str] = set()
    for cells in _rows(text):
        cve_id = cells[_CVE_COLUMN]
        if cells[_EPSS_COLUMN] != unknown:
            epss_scores[cve_id] = float(cells[_EPSS_COLUMN])
        if cells[_KEV_COLUMN] == kev_yes:
            kev_ids.add(cve_id)
    return epss_scores, kev_ids


def test_example_files_exist() -> None:
    """README から参照しているファイルが揃っていること。"""
    assert SAMPLE_INPUT.is_file()
    assert (EXAMPLES_DIR / "README.md").is_file()
    for path in REPORTS.values():
        assert path.is_file(), f"出力例が無い: {path.name}"


def test_sample_input_is_readable() -> None:
    """サンプル入力が、いまのパーサで読めること。"""
    scan = load_scan(SAMPLE_INPUT)
    assert scan.artifact_name == "sample-app:1.4.0"
    assert scan.vulnerabilities


def test_report_lists_every_finding(report: str) -> None:
    """入力の検出がすべてレポートに出ていること（省略された行が無いこと）。

    省略があると、例として不完全なうえに、下の再生成の検査も成り立たなくなる。
    そのときは `--top` を指定して作り直す。
    """
    scan = load_scan(SAMPLE_INPUT)
    assert len(_rows(report)) == len(scan.vulnerabilities), (
        "レポートに出ている件数が入力と合わない（表示件数の上限で省略された可能性）"
    )


def test_every_priority_appears(report: str) -> None:
    """P0〜P3 が1件以上ずつ出ていること（優先度の違いを見せる例として必要）。"""
    for priority in Priority:
        assert _summary_count(report, priority.label) > 0, (
            f"{priority.label} の検出が無い。EPSS / KEV が変わって偏った可能性があるため、"
            "サンプル入力を見直すこと"
        )


def test_no_fetch_warning(report: str) -> None:
    """外部データを取得できなかった状態で作られたレポートを置かないこと。"""
    assert "⚠️" not in report, "外部データが欠けたまま生成された出力例が置かれている"


def test_report_matches_current_output(report: str, lang: str) -> None:
    """いまのコードで作り直しても同じ文面になること。

    レポートの書式や判定の条件を変えたのに examples/ を作り直していないと、
    利用者に古い出力を見せることになる。ここで落として気づけるようにする。
    """
    scan = load_scan(SAMPLE_INPUT)
    epss_scores, kev_ids = _external_data(report, lang)
    items = prioritize(scan.vulnerabilities, epss_scores, kev_ids, lang=lang)
    regenerated = render_report(
        items,
        artifact_name=scan.artifact_name,
        generated_at=_generated_at(report, lang),
        lang=lang,
    )
    assert regenerated == report, (
        f"examples/{REPORTS[lang].name} が現在の出力と食い違っている。"
        "examples/README.md の手順で作り直すこと"
    )


def test_reports_share_one_data_snapshot() -> None:
    """日本語版と英語版が同じ時点のデータで作られていること。"""
    generated = {
        lang: _generated_at(path.read_text(encoding="utf-8"), lang)
        for lang, path in REPORTS.items()
    }
    timestamps = sorted(generated.values())
    assert (timestamps[-1] - timestamps[0]).total_seconds() <= 3600, (
        f"言語ごとに生成時点がずれている: {generated}"
    )


def test_reports_are_not_from_the_future() -> None:
    """生成日時が明らかに先の日付になっていないこと（手で書き換えた合図）。

    レポートの生成日時はタイムゾーンを持たない現地時刻で、生成した端末と
    このテストを回す環境（CI は UTC）がずれる。ずれの上限は前後1日なので、
    それを超えて先の日付になっているものだけを弾く。
    """
    limit = datetime.now() + timedelta(days=1)
    for lang, path in REPORTS.items():
        generated = _generated_at(path.read_text(encoding="utf-8"), lang)
        assert generated <= limit, f"生成日時が先の日付になっている: {path.name} ({generated})"


# --- npm 系の SBOM（本番 / 開発を区別できる入力）の出力例 ---------------------

#: 本番依存 / 開発依存に分かれたレポートを見せるための入力
NPM_INPUT = EXAMPLES_DIR / "cyclonedx-npm-sample.json"

#: 言語ごとのレポート
NPM_REPORTS = {lang: EXAMPLES_DIR / f"report-npm-{lang}.md" for lang in SUPPORTED_LANGS}


@pytest.fixture(scope="module", params=sorted(NPM_REPORTS))
def npm_lang(request) -> str:
    return request.param


@pytest.fixture(scope="module")
def npm_report(npm_lang: str) -> str:
    return NPM_REPORTS[npm_lang].read_text(encoding="utf-8")


def test_npm_example_files_exist() -> None:
    assert NPM_INPUT.is_file()
    for path in NPM_REPORTS.values():
        assert path.is_file(), f"出力例が無い: {path.name}"


def test_npm_sample_input_distinguishes_dependency_scope() -> None:
    """区別できる入力であること（区別できなくなったら例として成り立たない）。"""
    scan = load_scan(NPM_INPUT)

    assert scan.artifact_name == "demo-shop@1.0.0"
    assert scan.scope_known is True
    assert any(vuln.dev_only for vuln in scan.vulnerabilities), "開発依存の検出が無い"
    assert any(not vuln.dev_only for vuln in scan.vulnerabilities), "本番依存の検出が無い"


def test_npm_report_splits_by_dependency_scope(npm_report: str, npm_lang: str) -> None:
    """本番依存と開発依存が別の表に出ていること。"""
    text = catalog(npm_lang)

    assert text("group_runtime") in npm_report
    assert text("group_dev") in npm_report
    assert text("note_scope_unknown") not in npm_report


def test_npm_report_lists_every_finding(npm_report: str) -> None:
    scan = load_scan(NPM_INPUT)
    assert len(_rows(npm_report)) == len(scan.vulnerabilities), (
        "レポートに出ている件数が入力と合わない（表示件数の上限で省略された可能性）"
    )


def test_npm_report_has_no_fetch_warning(npm_report: str) -> None:
    assert "⚠️" not in npm_report, "外部データが欠けたまま生成された出力例が置かれている"


def test_npm_report_matches_current_output(npm_report: str, npm_lang: str) -> None:
    """いまのコードで作り直しても同じ文面になること。"""
    scan = load_scan(NPM_INPUT)
    epss_scores, kev_ids = _external_data(npm_report, npm_lang)
    items = prioritize(scan.vulnerabilities, epss_scores, kev_ids, lang=npm_lang)
    regenerated = render_report(
        items,
        artifact_name=scan.artifact_name,
        generated_at=_generated_at(npm_report, npm_lang),
        lang=npm_lang,
        scope_known=scan.scope_known,
    )
    assert regenerated == npm_report, (
        f"examples/{NPM_REPORTS[npm_lang].name} が現在の出力と食い違っている。"
        "examples/README.md の手順で作り直すこと"
    )


def test_npm_reports_share_one_data_snapshot() -> None:
    generated = {
        lang: _generated_at(path.read_text(encoding="utf-8"), lang)
        for lang, path in NPM_REPORTS.items()
    }
    timestamps = sorted(generated.values())
    assert (timestamps[-1] - timestamps[0]).total_seconds() <= 3600, (
        f"言語ごとに生成時点がずれている: {generated}"
    )


def test_npm_reports_are_not_from_the_future() -> None:
    limit = datetime.now() + timedelta(days=1)
    for lang, path in NPM_REPORTS.items():
        generated = _generated_at(path.read_text(encoding="utf-8"), lang)
        assert generated <= limit, f"生成日時が先の日付になっている: {path.name} ({generated})"
