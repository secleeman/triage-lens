"""文言カタログと、英語レポート（`--lang en`）の検証。"""

import re
from datetime import datetime
from string import Formatter

import pytest

from triage_lens.i18n import DEFAULT_LANG, SUPPORTED_LANGS, catalog, message_keys, raw_message
from triage_lens.kev import SOURCE_NETWORK, SOURCE_STALE_CACHE, SOURCE_UNAVAILABLE
from triage_lens.models import Vulnerability
from triage_lens.report import render_report
from triage_lens.scoring import classify, prioritize

GENERATED_AT = datetime(2026, 8, 29, 3, 0)

#: 日本語で使う文字（全角記号 / ひらがな / カタカナ / 漢字 / 全角英数）。
#: 英語レポートにこれらが混じっていないことを確かめるために使う。
JAPANESE_CHARS = re.compile(r"[　-〿぀-ヿ一-鿿＀-￯]")


def make_vuln(
    cve_id="CVE-2020-0001",
    cvss=5.0,
    pkg="libdemo",
    installed="1.0.0",
    fixed="1.0.1",
    target="demo-service:1.0 (debian 12)",
    fixed_version_known=True,
):
    return Vulnerability(
        cve_id=cve_id,
        pkg_name=pkg,
        installed_version=installed,
        fixed_version=fixed,
        cvss=cvss,
        target=target,
        fixed_version_known=fixed_version_known,
    )


def build_items(lang):
    """P0〜P3 と「値が取れていない」ケースをすべて含む一覧を作る。"""
    vulns = [
        make_vuln("CVE-2100-0001", cvss=9.0),  # KEV → P0
        make_vuln("CVE-2101-0001", cvss=8.0),  # 両方高い → P1
        make_vuln("CVE-2102-0001", cvss=7.5),  # CVSSだけ高い → P2
        make_vuln("CVE-2102-0002", cvss=4.0),  # EPSSだけ高い → P2
        make_vuln("CVE-2103-0001", cvss=3.0),  # どちらも低い → P3
        make_vuln("CVE-2103-0002", cvss=None, fixed=None),  # 値が無い → P3
        make_vuln("CVE-2103-0003", cvss=2.0, fixed=None, fixed_version_known=False),
    ]
    epss = {
        "CVE-2100-0001": 0.5,
        "CVE-2101-0001": 0.4,
        "CVE-2102-0001": 0.01,
        "CVE-2102-0002": 0.42,
        "CVE-2103-0001": 0.001,
    }
    return prioritize(vulns, epss, {"CVE-2100-0001"}, lang=lang)


def render(lang, **kwargs):
    kwargs.setdefault("artifact_name", "demo-service:1.0")
    kwargs.setdefault("generated_at", GENERATED_AT)
    kwargs.setdefault("kev_source", SOURCE_NETWORK)
    return render_report(build_items(lang), lang=lang, **kwargs)


def placeholders(lang, key):
    """テンプレートに含まれる差し込み項目名の集合。"""
    return {name for _, name, _, _ in Formatter().parse(raw_message(lang, key)) if name}


# --- カタログそのものの健全性 -------------------------------------------------


def test_日英のカタログは同じキーを持つ():
    """片方の言語にだけキーを足す事故を防ぐ。"""
    assert message_keys("ja") == message_keys("en")


@pytest.mark.parametrize("key", sorted(message_keys(DEFAULT_LANG)))
def test_同じキーの差し込み項目は言語間で一致する(key):
    """英語版だけ `{cvss}` を書き忘れる、といった取りこぼしを防ぐ。"""
    assert placeholders("ja", key) == placeholders("en", key)


def test_未対応の言語を指定するとValueErrorになる():
    with pytest.raises(ValueError, match="対応していない言語です"):
        catalog("fr")


def test_既定は日本語で対応言語は日英():
    assert DEFAULT_LANG == "ja"
    assert set(SUPPORTED_LANGS) == {"ja", "en"}


def test_知らないキーを引くとKeyErrorになる():
    with pytest.raises(KeyError):
        catalog("ja")("no_such_key")


# --- 英語レポート -------------------------------------------------------------


def test_英語レポートに日本語が混じらない():
    report = render("en", epss_complete=False, kev_source=SOURCE_STALE_CACHE, top_n=1)

    found = JAPANESE_CHARS.findall(report)
    assert not found, f"英語レポートに日本語文字が残っている: {sorted(set(found))}"


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_差し込み漏れが残らない(lang):
    """`{count}` のような置換子が埋まらずに残っていないことを確かめる。"""
    report = render(lang, epss_complete=False, kev_source=SOURCE_UNAVAILABLE, top_n=1)

    assert "{" not in report
    assert "}" not in report


def test_英語レポートの見出しと表():
    report = render("en")

    assert report.startswith("# Vulnerability Triage Report")
    assert "- Target: demo-service:1.0" in report
    assert "- Generated: 2026-08-29 03:00" in report
    assert "- Criteria: listed in CISA KEV / EPSS >= 0.1 / CVSS >= 7.0" in report
    assert "| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |" in report


def test_英語レポートのサマリと各ランク():
    report = render("en")

    assert "## Summary" in report
    assert "Total findings: 7" in report
    assert "| Priority | Count | Action |" in report
    assert "| P0 (Act now) | 1 | Patch immediately |" in report
    assert "| P1 (High) | 1 | Fix soon |" in report
    assert "| P2 (Medium) | 2 | Plan a fix |" in report
    assert "| P3 (Low) | 3 | Monitor |" in report
    assert "## P0 (Act now) - Patch immediately (1 total)" in report


def test_英語レポートの件数表記():
    assert "top 1 of 2" in render("en", top_n=1)
    assert "2 total, hidden by the display limit" in render("en", top_n=0)


def test_英語レポートの該当なし表記():
    report = render_report(
        prioritize([make_vuln(cvss=9.0)], {}, {"CVE-2020-0001"}, lang="en"),
        artifact_name="demo",
        generated_at=GENERATED_AT,
        kev_source=SOURCE_NETWORK,
        lang="en",
    )

    assert "## P1 (High) - Fix soon (0 total)" in report
    assert "None." in report


def test_英語レポートの検出ゼロ表記():
    report = render_report(
        [], artifact_name="demo", generated_at=GENERATED_AT, kev_source=SOURCE_NETWORK, lang="en"
    )

    assert "No vulnerabilities were found." in report
    assert not JAPANESE_CHARS.findall(report)


@pytest.mark.parametrize(
    ("kev_source", "epss_complete", "expected"),
    [
        (SOURCE_UNAVAILABLE, True, "Could not fetch the CISA KEV catalog."),
        (SOURCE_STALE_CACHE, True, "a cache older than 24 hours is being used"),
        (SOURCE_NETWORK, False, "Some or all EPSS scores could not be fetched."),
    ],
)
def test_英語レポートの警告文(kev_source, epss_complete, expected):
    report = render("en", kev_source=kev_source, epss_complete=epss_complete)

    assert expected in report


def test_英語レポートの末尾説明():
    report = render("en")

    assert "## How priorities are assigned" in report
    assert "| P1 (High) | EPSS >= 0.1 AND CVSS >= 7.0 |" in report
    assert "| P2 (Medium) | EPSS >= 0.1 OR CVSS >= 7.0 (only one of the two) |" in report
    assert "Sources: CISA KEV catalog / FIRST.org EPSS" in report


# --- 優先度の理由文 -----------------------------------------------------------


@pytest.mark.parametrize(
    ("cvss", "epss", "in_kev", "expected"),
    [
        (1.0, 0.0, True, "Listed in CISA KEV - exploitation observed in the wild"),
        (9.8, 0.5, False, "High exploitation probability (EPSS 0.500) and high severity"),
        (8.1, 0.01, False, "Severity is high (CVSS 8.1), but exploitation probability is low"),
        (4.3, 0.42, False, "Exploitation probability is high (EPSS 0.420), but severity is medium"),
        (3.1, 0.001, False, "Does not meet the high-risk criteria"),
    ],
)
def test_英語の理由文(cvss, epss, in_kev, expected):
    _, reason = classify(make_vuln(cvss=cvss), epss=epss, in_kev=in_kev, lang="en")

    assert expected in reason


def test_英語でも取得できていない値を低いと書かない():
    """Phase 1 と同じ方針を英語でも守る。"""
    _, reason = classify(make_vuln(cvss=None), epss=None, in_kev=None, lang="en")

    assert "exploitation probability is unknown" in reason
    assert "severity is unknown" in reason
    assert "is low" not in reason
    assert "medium or lower" not in reason
    assert "EPSS unavailable, not used in this decision" in reason
    assert "CVSS unknown, not used in this decision" in reason
    assert "KEV data unavailable" in reason


# --- 修正版「なし」と「不明」の区別 -------------------------------------------


@pytest.mark.parametrize(
    ("lang", "arrow", "no_fix", "unknown"),
    [("ja", "→", "修正版なし", "不明"), ("en", "->", "No fix available", "Unknown")],
)
def test_修正版が無いのと分からないのを区別する(lang, arrow, no_fix, unknown):
    def report_for(fixed_version_known):
        items = prioritize(
            [make_vuln(fixed=None, fixed_version_known=fixed_version_known)],
            {},
            set(),
            lang=lang,
        )
        return render_report(
            items,
            artifact_name="demo",
            generated_at=GENERATED_AT,
            kev_source=SOURCE_NETWORK,
            lang=lang,
        )

    known = report_for(True)
    not_known = report_for(False)

    assert f"1.0.0 {arrow} {no_fix}" in known
    assert f"1.0.0 {arrow} {unknown}" in not_known
    assert f"1.0.0 {arrow} {no_fix}" not in not_known


def test_日本語の既定動作は変わらない():
    """`lang` を省略したときは Phase 1 と同じ日本語レポートになる。"""
    default = render_report(
        build_items("ja"),
        artifact_name="demo-service:1.0",
        generated_at=GENERATED_AT,
        kev_source=SOURCE_NETWORK,
    )

    assert default == render("ja")
    assert default.startswith("# 脆弱性トリアージレポート")
