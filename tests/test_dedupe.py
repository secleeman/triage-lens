"""重複除去のときにリスクを過小表示しないことの検証（Issue #4）。

同じ検出が違うスコアで2回現れたとき、先に来た方を無条件に採用すると
低いスコアが残り、実態より安全に見えてしまう。
"""

import pytest

from triage_lens.cyclonedx import parse_bom
from triage_lens.models import Vulnerability
from triage_lens.parsing import deduplicate
from triage_lens.scoring import prioritize
from triage_lens.trivy import parse_scan


def make_vuln(cvss, cve_id="CVE-2020-0001", pkg="libdemo", installed="1.0.0", target="demo"):
    return Vulnerability(
        cve_id=cve_id,
        pkg_name=pkg,
        installed_version=installed,
        fixed_version="1.0.1",
        cvss=cvss,
        target=target,
    )


def trivy_document(*scores):
    return {
        "ArtifactName": "demo",
        "Results": [
            {
                "Target": "demo",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2020-0001",
                        "PkgName": "libdemo",
                        "InstalledVersion": "1.0.0",
                        "CVSS": {"nvd": {"V3Score": score}},
                    }
                    for score in scores
                ],
            }
        ],
    }


def cyclonedx_document(*scores):
    affect = {"ref": "c1", "versions": [{"version": "1.0.0", "status": "affected"}]}
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"bom-ref": "c1", "name": "libdemo", "version": "1.0.0"}],
        "vulnerabilities": [
            {
                "id": "CVE-2020-0001",
                "ratings": [{"score": score, "method": "CVSSv31"}],
                "affects": [dict(affect)],
            }
            for score in scores
        ],
    }


# --- 共通の重複除去ロジック ---------------------------------------------------


@pytest.mark.parametrize(
    ("scores", "expected"),
    [
        ((2.0, 10.0), 10.0),  # 後から高いスコアが来ても取りこぼさない
        ((10.0, 2.0), 10.0),  # 先に高いスコアが来た場合も維持する
        ((5.0, 5.0), 5.0),
        ((2.0, 7.5, 9.8, 4.0), 9.8),  # 3件以上でも最大値が残る
    ],
)
def test_重複したらCVSSの高い方を残す(scores, expected):
    result = deduplicate([make_vuln(score) for score in scores])

    assert len(result) == 1
    assert result[0].cvss == expected


@pytest.mark.parametrize(
    ("scores", "expected"),
    [
        ((None, 9.8), 9.8),  # 不明より、値のある方を採る
        ((9.8, None), 9.8),
        ((None, None), None),
        ((None, 2.0), 2.0),
    ],
)
def test_CVSSが不明な重複の扱い(scores, expected):
    result = deduplicate([make_vuln(score) for score in scores])

    assert len(result) == 1
    assert result[0].cvss == expected


def test_キーが違えば別の行として残す():
    result = deduplicate(
        [
            make_vuln(2.0, target="os-pkgs"),
            make_vuln(9.8, target="app/requirements.txt"),
            make_vuln(7.5, pkg="libother"),
            make_vuln(6.1, installed="2.0.0"),
            make_vuln(5.0, cve_id="CVE-2020-0002"),
        ]
    )

    assert len(result) == 5
    assert sorted(v.cvss for v in result) == [2.0, 5.0, 6.1, 7.5, 9.8]


def test_元の並び順を保つ():
    """まとめた行は、最初に現れた位置に残す。"""
    result = deduplicate(
        [
            make_vuln(1.0, cve_id="CVE-2020-0003"),
            make_vuln(2.0, cve_id="CVE-2020-0001"),
            make_vuln(9.8, cve_id="CVE-2020-0001"),
            make_vuln(3.0, cve_id="CVE-2020-0002"),
        ]
    )

    assert [v.cve_id for v in result] == ["CVE-2020-0003", "CVE-2020-0001", "CVE-2020-0002"]
    assert result[1].cvss == 9.8


def test_空の一覧でも落ちない():
    assert deduplicate([]) == []


def test_まとめた結果もVulnerabilityのまま():
    """`replace` で作り直しても重複判定のキーが失われないことを確かめる。"""
    first = make_vuln(2.0)
    second = make_vuln(9.8)

    merged = deduplicate([first, second])[0]

    assert merged.cvss == 9.8
    assert merged.dedupe_key == first.dedupe_key
    assert (merged.cve_id, merged.pkg_name, merged.installed_version, merged.target) == (
        "CVE-2020-0001",
        "libdemo",
        "1.0.0",
        "demo",
    )


# --- Trivy 入力での回帰 -------------------------------------------------------


def test_Trivy入力で高いCVSSが捨てられない():
    scan = parse_scan(trivy_document(2.0, 10.0))

    assert len(scan.vulnerabilities) == 1
    assert scan.vulnerabilities[0].cvss == 10.0


def test_Trivy入力の既存の重複除去は変わらない(fixtures_dir):
    from triage_lens.trivy import load_scan

    scan = load_scan(fixtures_dir / "trivy_sample.json")

    assert len(scan.vulnerabilities) == 13
    assert len({v.dedupe_key for v in scan.vulnerabilities}) == 13


# --- CycloneDX 入力での回帰 ---------------------------------------------------


def test_CycloneDX入力で高いCVSSが捨てられない():
    """Issue #4 の再現ケース。"""
    scan = parse_bom(cyclonedx_document(2.0, 10.0))

    assert len(scan.vulnerabilities) == 1
    assert scan.vulnerabilities[0].cvss == 10.0


def test_CycloneDX入力の既存の重複除去は変わらない(fixtures_dir):
    from triage_lens.cyclonedx import load_bom

    scan = load_bom(fixtures_dir / "cyclonedx_sample.json")

    assert len(scan.vulnerabilities) == 9
    assert len({v.dedupe_key for v in scan.vulnerabilities}) == 9


# --- 優先度への影響 -----------------------------------------------------------


def test_低いスコアが残ると優先度が下がっていた():
    """まとめ方を誤ると P1 相当の脆弱性が P3 に落ちる、という影響を明示する。"""
    scan = parse_bom(cyclonedx_document(2.0, 10.0))
    epss = {"CVE-2020-0001": 0.5}

    items = prioritize(scan.vulnerabilities, epss, set())

    assert items[0].priority.name == "P1"
    assert items[0].vuln.cvss == 10.0


# --- EPSS は食い違いようがないこと --------------------------------------------


def test_EPSSは重複でも同じ値になる():
    """EPSS は CVE ID だけを鍵に後から引き当てる。

    CVE ID は `dedupe_key` に含まれるので、まとめた結果がどちらの行になっても
    引き当たる EPSS は同じ。重複除去でスコアが食い違うことがない。
    """
    epss = {"CVE-2020-0001": 0.73}

    low_first = prioritize(deduplicate([make_vuln(2.0), make_vuln(10.0)]), epss, set())
    high_first = prioritize(deduplicate([make_vuln(10.0), make_vuln(2.0)]), epss, set())

    assert low_first[0].epss == high_first[0].epss == 0.73
    assert low_first[0].vuln.cvss == high_first[0].vuln.cvss == 10.0


# --- 修正バージョンの食い違い -------------------------------------------------


def fix(fixed_version, known=True, cvss=5.0):
    """修正バージョンの状態だけを変えた検出を作る。

    `(版数, True)` = 修正版が分かっている / `(None, True)` = 修正版なし /
    `(None, False)` = 有無そのものが不明。
    """
    return Vulnerability(
        cve_id="CVE-2020-0001",
        pkg_name="libdemo",
        installed_version="1.0.0",
        fixed_version=fixed_version,
        cvss=cvss,
        target="demo",
        fixed_version_known=known,
    )


UNKNOWN_FIX = (None, False)
NO_FIX = (None, True)


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    [
        # 1. 「不明」より、何か言えている方を採る
        (UNKNOWN_FIX, ("1.0.1", True), ("1.0.1", True)),
        (("1.0.1", True), UNKNOWN_FIX, ("1.0.1", True)),
        (UNKNOWN_FIX, NO_FIX, NO_FIX),
        (NO_FIX, UNKNOWN_FIX, NO_FIX),
        (UNKNOWN_FIX, UNKNOWN_FIX, UNKNOWN_FIX),
        # 2. 片方だけ版数がある（もう片方は「修正版なし」）なら版数を採る
        (NO_FIX, ("1.0.1", True), ("1.0.1", True)),
        (("1.0.1", True), NO_FIX, ("1.0.1", True)),
        (NO_FIX, NO_FIX, NO_FIX),
        # 3. 両方に版数があって食い違うなら新しい方
        (("1.0.1", True), ("1.0.2", True), ("1.0.2", True)),
        (("1.0.2", True), ("1.0.1", True), ("1.0.2", True)),
        (("1.2.9", True), ("1.2.10", True), ("1.2.10", True)),  # 文字列比較では負ける桁数
        (("5.3.1", True), ("5.4", True), ("5.4", True)),  # 桁数が違っても比べられる
        (("2.0", True), ("10.0", True), ("10.0", True)),
        (("1.0", True), ("1.0.0", True), ("1.0", True)),  # 同じ値なら先に来た方
        (("1.0.1", True), ("1.0.1", True), ("1.0.1", True)),
        # 4. 比較できない形式なら安全側で「不明」に倒す
        ((">=1.0.1g-1", True), ("1.0.2", True), UNKNOWN_FIX),
        (("1.0.1", True), ("1:1.2.11.dfsg-2+deb11u2", True), UNKNOWN_FIX),
        (("vers:npm/<1.0", True), ("2.1", True), UNKNOWN_FIX),
        (("1.0.1-rc1", True), ("1.0.1-rc2", True), UNKNOWN_FIX),
        (("v1.0.1", True), ("v1.0.2", True), UNKNOWN_FIX),
    ],
)
def test_修正バージョンのまとめ方(first, second, expected):
    merged = deduplicate([fix(*first), fix(*second)])

    assert len(merged) == 1
    assert (merged[0].fixed_version, merged[0].fixed_version_known) == expected


def test_比較できない修正バージョンでもCVSSは高い方を残す():
    """修正版を「不明」に倒しても、深刻度の判定は甘くしない。"""
    merged = deduplicate([fix(">=1.0.1g-1", cvss=2.0), fix("1:1.2.11.dfsg-2", cvss=9.8)])[0]

    assert merged.cvss == 9.8
    assert (merged.fixed_version, merged.fixed_version_known) == UNKNOWN_FIX


def test_修正バージョンのまとめは3件以上でも効く():
    merged = deduplicate([fix(None, known=False), fix("1.0.1"), fix("1.0.3"), fix("1.0.2")])

    assert len(merged) == 1
    assert merged[0].fixed_version == "1.0.3"


def test_レポートには不明と出る():
    """比較できず「不明」に倒したとき、レポートで「修正版なし」と書かない。"""
    from datetime import datetime

    from triage_lens.report import render_report

    items = prioritize(deduplicate([fix(">=1.0.1g-1"), fix("1.0.2")]), {}, set())
    report = render_report(items, artifact_name="demo", generated_at=datetime(2026, 1, 1))

    assert "1.0.0 → 不明" in report
    assert "修正版なし" not in report


def test_Trivy入力でも修正バージョンをまとめる():
    document = {
        "ArtifactName": "demo",
        "Results": [
            {
                "Target": "demo",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2020-0001",
                        "PkgName": "libdemo",
                        "InstalledVersion": "1.0.0",
                    },  # FixedVersion 無し = 修正版なし
                    {
                        "VulnerabilityID": "CVE-2020-0001",
                        "PkgName": "libdemo",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                    },
                ],
            }
        ],
    }

    scan = parse_scan(document)

    assert len(scan.vulnerabilities) == 1
    assert scan.vulnerabilities[0].fixed_version == "1.0.1"


def test_CycloneDX入力でも修正バージョンをまとめる():
    def entry(fixed):
        versions = [{"version": "1.0.0", "status": "affected"}]
        if fixed:
            versions.append({"version": fixed, "status": "unaffected"})
        return {
            "id": "CVE-2020-0001",
            "affects": [{"ref": "c1", "versions": versions}],
        }

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"bom-ref": "c1", "name": "libdemo", "version": "1.0.0"}],
        "vulnerabilities": [entry(None), entry("1.0.4")],
    }

    scan = parse_bom(document)

    assert len(scan.vulnerabilities) == 1
    assert scan.vulnerabilities[0].fixed_version == "1.0.4"
    assert scan.vulnerabilities[0].fixed_version_known is True
