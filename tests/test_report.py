from datetime import datetime

import pytest

from triage_lens.kev import SOURCE_NETWORK, SOURCE_STALE_CACHE, SOURCE_UNAVAILABLE
from triage_lens.models import Vulnerability
from triage_lens.report import render_report
from triage_lens.scoring import prioritize

GENERATED_AT = datetime(2026, 8, 28, 12, 34)


def make_vuln(
    cve_id,
    cvss=5.0,
    pkg="libdemo",
    installed="1.0.0",
    fixed="1.0.1",
    target="sample-app:1.4.0 (debian 12.5)",
):
    return Vulnerability(
        cve_id=cve_id,
        pkg_name=pkg,
        installed_version=installed,
        fixed_version=fixed,
        cvss=cvss,
        target=target,
    )


def build_items(count_p0=1, count_p1=2, count_p2=8, count_p3=7):
    """指定した件数だけ各ランクに該当する脆弱性を作る。"""
    vulns, epss, kev = [], {}, set()
    for i in range(count_p0):
        cve = f"CVE-2100-0{i:03d}"
        vulns.append(make_vuln(cve, cvss=9.0))
        epss[cve] = 0.5
        kev.add(cve)
    for i in range(count_p1):
        cve = f"CVE-2101-0{i:03d}"
        vulns.append(make_vuln(cve, cvss=8.0))
        epss[cve] = 0.4 - i * 0.01
    for i in range(count_p2):
        cve = f"CVE-2102-0{i:03d}"
        vulns.append(make_vuln(cve, cvss=7.5))
        epss[cve] = 0.05 - i * 0.001
    for i in range(count_p3):
        cve = f"CVE-2103-0{i:03d}"
        vulns.append(make_vuln(cve, cvss=3.0))
        epss[cve] = 0.01 - i * 0.0001
    return prioritize(vulns, epss, kev)


def render(items, **kwargs):
    kwargs.setdefault("artifact_name", "sample-app:1.4.0")
    kwargs.setdefault("generated_at", GENERATED_AT)
    kwargs.setdefault("kev_source", SOURCE_NETWORK)
    return render_report(items, **kwargs)


def test_見出しと対象と生成日時が入る():
    report = render(build_items())

    assert report.startswith("# 脆弱性トリアージレポート")
    assert "- 対象: sample-app:1.4.0" in report
    assert "- 生成日時: 2026-08-28 12:34" in report


def test_サマリに総数と各ランクの件数が出る():
    report = render(build_items(count_p0=1, count_p1=2, count_p2=8, count_p3=7))

    assert "検出総数: 18件" in report
    assert "| P0 (Act now) | 1 | 今すぐ対応 |" in report
    assert "| P1 (High) | 2 | 優先的に対応 |" in report
    assert "| P2 (Medium) | 8 | 計画的に対応 |" in report
    assert "| P3 (Low) | 7 | 経過観察 |" in report


def test_P0とP1は表示件数の指定に関係なく全件出る():
    report = render(build_items(count_p0=7, count_p1=9, count_p2=0, count_p3=0), top_n=5)

    assert "## P0 (Act now) — 今すぐ対応（7件）" in report
    assert "## P1 (High) — 優先的に対応（9件）" in report
    assert report.count("| CVE-2100-") == 7
    assert report.count("| CVE-2101-") == 9


def test_P2とP3は上位N件だけ出る():
    report = render(build_items(count_p2=8, count_p3=7), top_n=5)

    assert "## P2 (Medium) — 計画的に対応（8件中 上位5件を表示）" in report
    assert "## P3 (Low) — 経過観察（7件中 上位5件を表示）" in report
    assert report.count("| CVE-2102-") == 5
    assert report.count("| CVE-2103-") == 5


def test_表示件数を変えると出力件数も変わる():
    report = render(build_items(count_p2=8, count_p3=7), top_n=2)

    assert report.count("| CVE-2102-") == 2
    assert "8件中 上位2件を表示" in report


def test_件数が表示上限以下ならそのまま全件出る():
    report = render(build_items(count_p2=3, count_p3=0), top_n=5)

    assert "## P2 (Medium) — 計画的に対応（3件）" in report
    assert report.count("| CVE-2102-") == 3


def test_表示件数0なら省略と明記する():
    report = render(build_items(count_p2=8), top_n=0)

    assert "8件（表示件数の指定により省略）" in report
    assert "| CVE-2102-" not in report


def test_該当が無いランクは該当なしと書く():
    report = render(build_items(count_p0=0, count_p1=1, count_p2=0, count_p3=0))

    assert "## P0 (Act now) — 今すぐ対応（0件）" in report
    assert "該当なし。" in report


def test_検出ゼロなら明示する():
    report = render([])

    assert "検出総数: 0件" in report
    assert "検出された脆弱性はありません。" in report


def test_行に必要な項目がすべて入る():
    items = prioritize(
        [
            make_vuln(
                "CVE-2021-44228",
                cvss=10.0,
                pkg="log4j-core",
                installed="2.14.1",
                fixed="2.15.0",
                target="app/requirements.txt",
            )
        ],
        {"CVE-2021-44228": 0.97},
        {"CVE-2021-44228"},
    )

    report = render(items)

    assert (
        "| CVE-2021-44228 | log4j-core | app/requirements.txt | 2.14.1 → 2.15.0 | "
        "10.0 | 0.970 | あり | KEV掲載＝実際に悪用されている |"
    ) in report


def test_修正版が無い場合はその旨を書く():
    items = prioritize([make_vuln("CVE-2100-0001", cvss=9.0, fixed=None)], {}, set())

    assert "1.0.0 → 修正版なし" in render(items)


def test_取得できなかった値は不明と表示する():
    items = prioritize([make_vuln("CVE-2100-0001", cvss=None)], {}, None)

    report = render(items, kev_source=SOURCE_UNAVAILABLE)

    assert "| 不明 | 不明 | 不明 |" in report


def test_パッケージ名の記号が表を壊さない():
    items = prioritize([make_vuln("CVE-2100-0001", pkg="lib|pipe")], {}, set())

    assert r"lib\|pipe" in render(items)


def test_KEVが取得できなければ警告を出す():
    report = render(build_items(), kev_source=SOURCE_UNAVAILABLE)

    assert "CISA KEV カタログを取得できませんでした" in report


def test_期限切れキャッシュを使ったら警告を出す():
    report = render(build_items(), kev_source=SOURCE_STALE_CACHE)

    assert "24時間以上前のキャッシュを使用しています" in report


def test_EPSSが取れていなければ警告を出す():
    report = render(build_items(), epss_complete=False)

    assert "EPSS スコアの一部または全部を取得できませんでした" in report


def test_すべて取得できていれば警告は出ない():
    report = render(build_items())

    assert "⚠️" not in report


def test_優先度の付け方の説明が入る():
    report = render(build_items())

    assert "## 優先度の付け方" in report
    assert "データ出典: CISA KEV カタログ / FIRST.org EPSS" in report


@pytest.mark.parametrize("top_n", [0, 1, 5, 100])
def test_どの表示件数でも最後は改行1つで終わる(top_n):
    report = render(build_items(), top_n=top_n)

    assert report.endswith("\n")
    assert not report.endswith("\n\n")
