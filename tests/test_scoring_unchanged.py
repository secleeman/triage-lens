"""スコアリングが変わっていないことを固定する検査。

Phase 6 は**表示の変更だけ**を行い、P0〜P3 の判定には手を入れない、というのが
オーナー裁定の前提になっている。判定の変更は「レポートの見た目を直したつもりが
CI を通す条件まで変わっていた」という形で静かに起きるため、期待値をここに直接
書き出して固定する。

このファイルの期待値は、判定を意図的に変える決定があったときにだけ書き換える。
表示の変更で落ちたなら、それは設計が間違っている。
"""

import pytest

from triage_lens.i18n import SUPPORTED_LANGS, catalog
from triage_lens.models import Priority, Vulnerability
from triage_lens.scoring import (
    CVSS_THRESHOLD,
    EPSS_THRESHOLD,
    classify,
    count_by_priority,
    prioritize,
)

#: EPSS の代表値（閾値の直下 / ちょうど / 十分上）
_EPSS = {"none": None, "low": 0.099, "edge": 0.1, "high": 0.5}

#: CVSS の代表値（閾値の直下 / ちょうど / 十分上）
_CVSS = {"none": None, "low": 6.9, "edge": 7.0, "high": 9.8}

#: KEV に載っていないときの判定表。**ここは判定の期待値そのもの**であり、
#: コードから導出しない（導出すると、判定が変わっても一緒に変わってしまう）。
_EXPECTED = {
    ("none", "none"): Priority.P3,
    ("none", "low"): Priority.P3,
    ("none", "edge"): Priority.P2,
    ("none", "high"): Priority.P2,
    ("low", "none"): Priority.P3,
    ("low", "low"): Priority.P3,
    ("low", "edge"): Priority.P2,
    ("low", "high"): Priority.P2,
    ("edge", "none"): Priority.P2,
    ("edge", "low"): Priority.P2,
    ("edge", "edge"): Priority.P1,
    ("edge", "high"): Priority.P1,
    ("high", "none"): Priority.P2,
    ("high", "low"): Priority.P2,
    ("high", "edge"): Priority.P1,
    ("high", "high"): Priority.P1,
}


def make_vuln(cvss, dev_only=False):
    return Vulnerability(
        cve_id="CVE-2020-8203",
        pkg_name="lodash",
        installed_version="4.17.15",
        fixed_version="4.17.20",
        cvss=cvss,
        target="package-lock.json",
        dev_only=dev_only,
    )


# --- 閾値 ---------------------------------------------------------------------


def test_閾値が変わっていない():
    assert EPSS_THRESHOLD == 0.1
    assert CVSS_THRESHOLD == 7.0


def test_ランクの並びと名前が変わっていない():
    assert [priority.name for priority in Priority] == ["P0", "P1", "P2", "P3"]
    assert [priority.label for priority in Priority] == [
        "P0 (Act now)",
        "P1 (High)",
        "P2 (Medium)",
        "P3 (Low)",
    ]


# --- 判定表 -------------------------------------------------------------------


@pytest.mark.parametrize(("key", "expected"), sorted(_EXPECTED.items()))
def test_KEV非掲載の判定表(key, expected):
    epss_key, cvss_key = key
    priority, _ = classify(make_vuln(_CVSS[cvss_key]), _EPSS[epss_key], in_kev=False)
    assert priority is expected


@pytest.mark.parametrize("key", sorted(_EXPECTED))
def test_KEV情報が無くても非掲載と同じ判定になる(key):
    """KEV を取得できなかったことが、判定を甘くも厳しくもしない。"""
    epss_key, cvss_key = key
    vuln = make_vuln(_CVSS[cvss_key])
    assert classify(vuln, _EPSS[epss_key], in_kev=None)[0] is _EXPECTED[key]


@pytest.mark.parametrize("key", sorted(_EXPECTED))
def test_KEV掲載は常にP0になる(key):
    epss_key, cvss_key = key
    vuln = make_vuln(_CVSS[cvss_key])
    assert classify(vuln, _EPSS[epss_key], in_kev=True)[0] is Priority.P0


# --- 本番 / 開発の区別が判定に影響しないこと -----------------------------------


@pytest.mark.parametrize("key", sorted(_EXPECTED))
@pytest.mark.parametrize("in_kev", [True, False, None])
@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_開発依存かどうかは優先度にも理由にも影響しない(key, in_kev, lang):
    """Phase 6 で入った区別は、表示の分け方だけに効く。"""
    epss_key, cvss_key = key
    epss = _EPSS[epss_key]
    runtime = classify(make_vuln(_CVSS[cvss_key], dev_only=False), epss, in_kev, lang=lang)
    development = classify(make_vuln(_CVSS[cvss_key], dev_only=True), epss, in_kev, lang=lang)
    assert runtime == development


def test_並び順は開発依存かどうかに左右されない():
    """一覧の並びは EPSS / CVSS の高さだけで決まる。"""
    vulns = [make_vuln(9.8, dev_only=False), make_vuln(3.0, dev_only=True)]
    epss = {"CVE-2020-8203": 0.5}

    ordered = prioritize(vulns, epss, set())
    flipped = prioritize([make_vuln(9.8, dev_only=True), make_vuln(3.0)], epss, set())

    assert [item.priority for item in ordered] == [item.priority for item in flipped]
    assert [item.vuln.cvss for item in ordered] == [item.vuln.cvss for item in flipped]


def test_件数の数え方が開発依存かどうかに左右されない():
    items = prioritize([make_vuln(9.8, dev_only=True)], {}, set())
    assert count_by_priority(items) == {
        Priority.P0: 0,
        Priority.P1: 0,
        Priority.P2: 1,
        Priority.P3: 0,
    }


# --- 理由の文言 ---------------------------------------------------------------


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_KEV掲載の理由文が変わっていない(lang):
    _, reason = classify(make_vuln(9.8), 0.5, in_kev=True, lang=lang)
    assert reason == catalog(lang)("reason_kev")


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_取得できなかった値は理由に注記される(lang):
    """欠けたデータで判定したことを、黙って伏せない。"""
    text = catalog(lang)
    _, reason = classify(make_vuln(None), None, in_kev=None, lang=lang)

    assert text("note_kev_missing") in reason
    assert text("note_epss_missing") in reason
    assert text("note_cvss_missing") in reason


@pytest.mark.parametrize("lang", SUPPORTED_LANGS)
def test_各ランクの条件の説明が変わっていない(lang):
    """レポート末尾に出る判定条件の文面。"""
    text = catalog(lang)
    assert text("condition_p1", epss=EPSS_THRESHOLD, cvss=CVSS_THRESHOLD) == (
        "EPSS 0.1 以上 かつ CVSS 7.0 以上" if lang == "ja" else "EPSS >= 0.1 AND CVSS >= 7.0"
    )
    assert text("condition_p2", epss=EPSS_THRESHOLD, cvss=CVSS_THRESHOLD) == (
        "EPSS 0.1 以上 か CVSS 7.0 以上 の一方のみ"
        if lang == "ja"
        else "EPSS >= 0.1 OR CVSS >= 7.0 (only one of the two)"
    )
