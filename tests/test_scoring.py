import pytest

from triage_lens.models import Priority, Vulnerability
from triage_lens.scoring import (
    CVSS_THRESHOLD,
    EPSS_THRESHOLD,
    classify,
    count_by_priority,
    prioritize,
)


def make_vuln(
    cve_id: str = "CVE-2020-0001",
    cvss: float | None = 5.0,
    pkg: str = "libdemo",
    target: str = "demo-service:1.0 (debian 12)",
):
    return Vulnerability(
        cve_id=cve_id,
        pkg_name=pkg,
        installed_version="1.0.0",
        fixed_version="1.0.1",
        cvss=cvss,
        target=target,
    )


def test_KEV掲載はスコアに関係なくP0():
    priority, reason = classify(make_vuln(cvss=1.0), epss=0.0, in_kev=True)

    assert priority is Priority.P0
    assert "KEV掲載" in reason


def test_EPSSもCVSSも高ければP1():
    priority, reason = classify(make_vuln(cvss=9.8), epss=0.5, in_kev=False)

    assert priority is Priority.P1
    assert "0.500" in reason and "9.8" in reason


def test_CVSSだけ高ければP2():
    priority, reason = classify(make_vuln(cvss=8.1), epss=0.01, in_kev=False)

    assert priority is Priority.P2
    assert "深刻度は高い" in reason


def test_EPSSだけ高ければP2():
    priority, reason = classify(make_vuln(cvss=4.3), epss=0.42, in_kev=False)

    assert priority is Priority.P2
    assert "悪用確率は高い" in reason


def test_どちらも低ければP3():
    priority, _ = classify(make_vuln(cvss=3.1), epss=0.001, in_kev=False)

    assert priority is Priority.P3


@pytest.mark.parametrize(
    ("epss", "cvss", "expected"),
    [
        (EPSS_THRESHOLD, CVSS_THRESHOLD, Priority.P1),  # 閾値ちょうどは「高い」に含む
        (EPSS_THRESHOLD - 0.001, CVSS_THRESHOLD, Priority.P2),
        (EPSS_THRESHOLD, CVSS_THRESHOLD - 0.1, Priority.P2),
        (EPSS_THRESHOLD - 0.001, CVSS_THRESHOLD - 0.1, Priority.P3),
    ],
)
def test_閾値の境界(epss, cvss, expected):
    priority, _ = classify(make_vuln(cvss=cvss), epss=epss, in_kev=False)

    assert priority is expected


def test_閾値は引数で変更できる():
    vuln = make_vuln(cvss=5.0)

    default_priority, _ = classify(vuln, epss=0.05, in_kev=False)
    tuned_priority, _ = classify(
        vuln, epss=0.05, in_kev=False, epss_threshold=0.01, cvss_threshold=4.0
    )

    assert default_priority is Priority.P3
    assert tuned_priority is Priority.P1


def test_EPSS未取得ならCVSSだけで判定して理由に明記する():
    priority, reason = classify(make_vuln(cvss=8.8), epss=None, in_kev=False)

    assert priority is Priority.P2
    assert "悪用確率は不明" in reason
    assert "EPSSが取得できず判定に使えていない" in reason


def test_KEV未取得なら未判定であることを理由に明記する():
    priority, reason = classify(make_vuln(cvss=8.8), epss=0.3, in_kev=None)

    assert priority is Priority.P1
    assert "KEV情報が取得できず未判定" in reason


def test_CVSS不明でもEPSSが高ければP2():
    priority, reason = classify(make_vuln(cvss=None), epss=0.9, in_kev=False)

    assert priority is Priority.P2
    assert "CVSSが不明で判定に使えていない" in reason


def test_情報が何も無ければP3():
    priority, reason = classify(make_vuln(cvss=None), epss=None, in_kev=None)

    assert priority is Priority.P3
    assert "KEV情報が取得できず未判定" in reason
    assert "EPSSが取得できず判定に使えていない" in reason
    assert "CVSSが不明で判定に使えていない" in reason


def test_優先度順に並び同一ランクはEPSS降順CVSS降順():
    vulns = [
        make_vuln("CVE-2020-0001", cvss=9.9),  # EPSS低 → P2
        make_vuln("CVE-2020-0002", cvss=9.0),  # KEV → P0
        make_vuln("CVE-2020-0003", cvss=8.0),  # 両方高 → P1
        make_vuln("CVE-2020-0004", cvss=7.5),  # 両方高 → P1（EPSSが上より低い）
        make_vuln("CVE-2020-0005", cvss=2.0),  # 何も無し → P3
    ]
    epss = {
        "CVE-2020-0001": 0.01,
        "CVE-2020-0002": 0.01,
        "CVE-2020-0003": 0.80,
        "CVE-2020-0004": 0.30,
        "CVE-2020-0005": 0.00,
    }

    result = prioritize(vulns, epss, {"CVE-2020-0002"})

    assert [item.vuln.cve_id for item in result] == [
        "CVE-2020-0002",
        "CVE-2020-0003",
        "CVE-2020-0004",
        "CVE-2020-0001",
        "CVE-2020-0005",
    ]


def test_同一ランクでEPSSが同じならCVSS降順():
    vulns = [make_vuln("CVE-2020-0001", cvss=7.1), make_vuln("CVE-2020-0002", cvss=9.9)]
    epss = {"CVE-2020-0001": 0.5, "CVE-2020-0002": 0.5}

    result = prioritize(vulns, epss, set())

    assert [item.vuln.cve_id for item in result] == ["CVE-2020-0002", "CVE-2020-0001"]


def test_値が不明なものは同一ランク内で末尾に来る():
    vulns = [make_vuln("CVE-2020-0001", cvss=None), make_vuln("CVE-2020-0002", cvss=8.0)]

    result = prioritize(vulns, {}, set())

    assert [item.vuln.cve_id for item in result] == ["CVE-2020-0002", "CVE-2020-0001"]


def test_KEV情報が無い場合は掲載有無を不明として扱う():
    result = prioritize([make_vuln(cvss=9.0)], {"CVE-2020-0001": 0.9}, None)

    assert result[0].in_kev is None
    assert result[0].priority is Priority.P1


def test_件数集計は0件のランクも含む():
    result = prioritize([make_vuln(cvss=9.0)], {}, {"CVE-2020-0001"})

    counts = count_by_priority(result)

    assert counts == {Priority.P0: 1, Priority.P1: 0, Priority.P2: 0, Priority.P3: 0}


@pytest.mark.parametrize(
    ("cvss", "expected_priority"),
    [(8.8, Priority.P2), (3.0, Priority.P3)],
)
def test_EPSS未取得のとき悪用確率を低いと書かない(cvss, expected_priority):
    """取得できていない値を「低い」と断定すると、危険なものを安全に見せてしまう。"""
    priority, reason = classify(make_vuln(cvss=cvss), epss=None, in_kev=False)

    assert priority is expected_priority
    assert "悪用確率は不明" in reason
    assert "悪用確率は低い" not in reason


def test_CVSS不明のとき深刻度を中以下と書かない():
    _, reason = classify(make_vuln(cvss=None), epss=0.5, in_kev=False)

    assert "深刻度は不明" in reason
    assert "深刻度は中以下" not in reason


def test_値が取れていれば従来どおり高い低いで説明する():
    _, low = classify(make_vuln(cvss=8.8), epss=0.01, in_kev=False)
    _, mid = classify(make_vuln(cvss=4.0), epss=0.5, in_kev=False)

    assert "悪用確率は低い（EPSS 0.010）" in low
    assert "深刻度は中以下（CVSS 4.0）" in mid
