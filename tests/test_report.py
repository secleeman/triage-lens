from dataclasses import replace
from datetime import datetime

import pytest

from triage_lens.i18n import catalog
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


# --- 本番依存 / 開発依存の区別（Phase 6） -------------------------------------


def make_split_items(runtime=2, development=3, cvss=7.5, epss_value=0.05):
    """本番依存と開発依存が混ざった検出を作る（既定では全件 P2）。"""
    vulns, epss = [], {}
    for index in range(runtime):
        cve = f"CVE-2110-0{index:03d}"
        vulns.append(make_vuln(cve, cvss=cvss, pkg=f"runtime-{index}"))
        epss[cve] = epss_value
    for index in range(development):
        cve = f"CVE-2111-0{index:03d}"
        vulns.append(replace(make_vuln(cve, cvss=cvss, pkg=f"dev-{index}"), dev_only=True))
        epss[cve] = epss_value
    return prioritize(vulns, epss, set())


def test_区別できない入力ではその旨を明記する():
    report = render(build_items())

    assert "区別する情報が含まれていないため" in report
    assert "### 本番依存" not in report


def test_区別できない入力のサマリは従来の3列のまま():
    """区別できないのに内訳の列を出すと「本番依存は0件」と読まれてしまう。"""
    report = render(build_items(count_p0=1, count_p1=0, count_p2=0, count_p3=0))

    assert "| 優先度 | 件数 | 目安 |" in report
    assert "| P0 (Act now) | 1 | 今すぐ対応 |" in report


def test_検出が無ければ区別情報の注記も出さない():
    report = render([])

    assert "区別する情報が含まれていないため" not in report


def test_区別できる入力では2つの表に分かれる():
    report = render(make_split_items(), scope_known=True)

    assert "### 本番依存（2件）" in report
    assert "### 開発依存のみ（3件）" in report
    assert "区別する情報が含まれていないため" not in report


def test_区別できる入力のサマリに内訳が出る():
    report = render(make_split_items(runtime=1, development=4), scope_known=True)

    assert "| 優先度 | 件数 | うち本番依存 | 目安 |" in report
    assert "| P2 (Medium) | 5 | 1 | 計画的に対応 |" in report


def test_該当が無い側も見出しを残す():
    """「本番依存 0件」であることが、いちばん伝えたい情報になる場面がある。"""
    report = render(make_split_items(runtime=0, development=2), scope_known=True)

    assert "### 本番依存（0件）" in report
    assert "### 開発依存のみ（2件）" in report


def test_表示件数は表ごとに効く():
    """ランク全体で数えると、本番依存の検出が開発依存に押し出されて見えなくなる。"""
    report = render(make_split_items(runtime=4, development=4), scope_known=True, top_n=2)

    assert "### 本番依存（4件中 上位2件を表示）" in report
    assert "### 開発依存のみ（4件中 上位2件を表示）" in report
    assert report.count("| CVE-2110-") == 2
    assert report.count("| CVE-2111-") == 2


# --- 推奨アクション（Phase 6） ------------------------------------------------


def test_推奨アクションの表が出る():
    report = render(build_items(count_p0=0, count_p1=0, count_p2=1, count_p3=0))

    assert "## 推奨アクション" in report
    assert "| パッケージ | 現在 | 上げ先 | 解消されるCVE | 最高優先度 |" in report
    assert "| libdemo | 1.0.0 | 1.0.1 | 1件 | P2 (Medium) |" in report


def test_推奨アクションは優先度の付け方より前に置く():
    """行動の指示が、判定基準の説明の後ろに埋もれないようにする。"""
    report = render(build_items())

    assert report.index("## 推奨アクション") < report.index("## 優先度の付け方")


def test_推奨アクションは表示件数に左右されない():
    """表に出ていない検出も同じパッケージのことがあり、切ると解消件数が実際より減る。"""
    report = render(build_items(count_p0=0, count_p1=0, count_p2=0, count_p3=7), top_n=1)

    assert "| libdemo | 1.0.0 | 1.0.1 | 7件 | P3 (Low) |" in report


def test_検出が無ければ推奨アクションの節も出さない():
    assert "## 推奨アクション" not in render([])


def test_区別できる入力では推奨アクションも分かれる():
    report = render(make_split_items(runtime=1, development=1), scope_known=True)

    section = report[report.index("## 推奨アクション") :]
    assert "### 本番依存（1件）" in section
    assert "### 開発依存のみ（1件）" in section


# --- 実害判定の限界（Phase 6） ------------------------------------------------


def test_限界の注意書きが最終行に出る():
    report = render(build_items())
    expected = catalog("ja")("limits_note")

    assert report.rstrip().endswith(expected)


def test_検出が無ければ限界の注意書きは出さない():
    """判定した結果が1件も無いところに判定の限界を書いても伝わらない。"""
    report = render([])

    assert catalog("ja")("limits_note") not in report


def test_上げ先が無い行は解消件数を重ねて書かない():
    """上げ先の欄に「修正版なし」と出ているので、同じことを2度書かない。"""
    items = prioritize([make_vuln("CVE-2100-0001", cvss=3.0, fixed=None)], {}, set())
    report = render(items)

    assert "| libdemo | 1.0.0 | 修正版なし | 0件 | P3 (Low) |" in report


def test_上げても残る検出があれば件数を併記する():
    items = prioritize(
        [
            make_vuln("CVE-2100-0001", cvss=3.0, fixed="1.0.1"),
            make_vuln("CVE-2100-0002", cvss=3.0, fixed=None),
        ],
        {},
        set(),
    )
    report = render(items)

    assert "| libdemo | 1.0.0 | 1.0.1 | 1件（ほかに1件は修正版なし） | P3 (Low) |" in report


# --- 区別できるが開発依存が0件のとき（Phase 6 の調整） ------------------------


def test_開発依存が0件なら分割せず従来形式にする():
    """空の「開発依存のみ（0件）」がランクの数だけ並ぶだけで、読む人に何も足さない。"""
    report = render(make_split_items(runtime=3, development=0), scope_known=True)

    assert "### 本番依存" not in report
    assert "### 開発依存のみ" not in report
    assert "| 優先度 | 件数 | 目安 |" in report, "サマリが3列に戻っていない"


def test_開発依存が0件ならその旨をサマリに明記する():
    """これが無いと、区別できずに分けなかった場合と見分けが付かない。"""
    report = render(make_split_items(runtime=3, development=0), scope_known=True)

    assert "開発依存のみの検出: 0件（すべて本番依存です）" in report
    assert catalog("ja")("note_scope_unknown") not in report


def test_区別できない入力とは表示で見分けられる():
    """同じ「1つの表」でも、0件だったのか材料が無かったのかが読み分けられること。"""
    known = render(make_split_items(runtime=3, development=0), scope_known=True)
    unknown = render(make_split_items(runtime=3, development=0), scope_known=False)
    text = catalog("ja")

    assert text("summary_dev_none") in known
    assert text("note_scope_unknown") not in known

    assert text("summary_dev_none") not in unknown
    assert text("note_scope_unknown") in unknown


def test_開発依存が0件なら推奨アクションも分割しない():
    report = render(make_split_items(runtime=2, development=0), scope_known=True)
    section = report[report.index("## 推奨アクション") :]

    assert "### 本番依存" not in section
    assert "### 開発依存のみ" not in section
    assert "| パッケージ | 現在 | 上げ先 | 解消されるCVE | 最高優先度 |" in section


def test_開発依存が1件でもあれば分割する():
    report = render(make_split_items(runtime=3, development=1), scope_known=True)

    assert "### 本番依存（3件）" in report
    assert "### 開発依存のみ（1件）" in report
    assert catalog("ja")("summary_dev_none") not in report


def test_本番依存が0件のときは分割を続ける():
    """「本番依存 0件」はいちばん伝えたい情報なので、こちらは表を残す。"""
    report = render(make_split_items(runtime=0, development=2), scope_known=True)

    assert "### 本番依存（0件）" in report
    assert "### 開発依存のみ（2件）" in report


def test_検出が無ければ0件の行も出さない():
    report = render([], scope_known=True)

    assert catalog("ja")("summary_dev_none") not in report


@pytest.mark.parametrize("lang", ["ja", "en"])
def test_0件の行は両言語で出る(lang):
    report = render(make_split_items(runtime=2, development=0), scope_known=True, lang=lang)

    assert catalog(lang)("summary_dev_none") in report


# --- 分類の根拠が scope だけのときの注記 --------------------------------------


def test_scopeだけが根拠なら注記を出す():
    report = render(make_split_items(), scope_known=True, dev_property_used=False)

    assert catalog("ja")("scope_basis_note") in report


def test_devプロパティが使われていれば注記を出さない():
    """「開発依存である」と明示されていれば、scope の揺れを心配しなくてよい。"""
    report = render(make_split_items(), scope_known=True, dev_property_used=True)

    assert catalog("ja")("scope_basis_note") not in report


def test_開発依存が0件でも注記を出す():
    """開発依存に optional を誤用した SBOM は、ここで「全件が本番」と断定表示される。

    分類が実態と真逆になりうるのは、まさにこの場合。分割していないからといって
    注記を省くと、いちばん誤解を生む状態で根拠が伝わらない。
    """
    report = render(make_split_items(runtime=3, development=0), scope_known=True)
    text = catalog("ja")

    assert text("summary_dev_none") in report
    assert text("scope_basis_note") in report


def test_区別していなければ注記を出さない():
    """分類そのものが無いので、その根拠を書いても意味がない。"""
    report = render(build_items(), scope_known=False)

    assert catalog("ja")("scope_basis_note") not in report


def test_検出が無ければ注記を出さない():
    report = render([], scope_known=True)

    assert catalog("ja")("scope_basis_note") not in report


def test_注記は限界の注意書きの直前に置く():
    report = render(make_split_items(), scope_known=True)
    text = catalog("ja")

    assert report.index(text("scope_basis_note")) < report.index(text("limits_note"))
    assert report.rstrip().endswith(text("limits_note")), "最終行は限界の注意書きのまま"


@pytest.mark.parametrize("lang", ["ja", "en"])
def test_注記は両言語で出る(lang):
    report = render(make_split_items(), scope_known=True, lang=lang)

    assert catalog(lang)("scope_basis_note") in report


# --- 部品表だけの入力（脆弱性の一覧が無い） ------------------------------


def test_部品表だけの入力なら0件の意味を書く():
    """SPDX は脆弱性を書く場所がほとんど無く、0件が普通の結果になる。

    そのまま「検出された脆弱性はありません。」だけを出すと、安全だったと読まれる。
    """
    report = render([], sbom_only=True)
    text = catalog("ja")

    assert text("note_sbom_only") in report
    assert text("no_findings") in report


def test_部品表だけの注記はサマリより前に出す():
    """「0件」の意味が変わる話なので、表を読む前に目に入る位置に置く。"""
    report = render([], sbom_only=True)
    text = catalog("ja")

    assert report.index(text("note_sbom_only")) < report.index(text("summary_heading"))


def test_脆弱性を含む入力では部品表の注記を出さない():
    report = render(build_items())

    assert catalog("ja")("note_sbom_only") not in report


def test_検出0件でも部品表でなければ注記を出さない():
    """Trivy / CycloneDX の0件は「脆弱性が見つからなかった」で、意味が違う。"""
    report = render([])

    assert catalog("ja")("note_sbom_only") not in report


@pytest.mark.parametrize("lang", ["ja", "en"])
def test_部品表だけの注記は両言語で出る(lang):
    report = render([], sbom_only=True, lang=lang)

    assert catalog(lang)("note_sbom_only") in report
