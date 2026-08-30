"""パッケージ単位の推奨アクションの検証。

ここで守りたいのは2つ。**存在しない上げ先を案内しないこと**（比較できない版表記を
勝手に解釈しない）と、**対応が要るものを表から落とさないこと**（上げ先が決められない
パッケージも行として残す）。
"""

import pytest

from triage_lens.models import Priority, Vulnerability
from triage_lens.recommendations import build
from triage_lens.scoring import prioritize


def make_vuln(
    cve_id,
    pkg="lodash",
    installed="4.17.15",
    fixed="4.17.20",
    fixed_known=True,
    target="package-lock.json",
    cvss=5.0,
    dev_only=False,
):
    return Vulnerability(
        cve_id=cve_id,
        pkg_name=pkg,
        installed_version=installed,
        fixed_version=fixed,
        cvss=cvss,
        target=target,
        fixed_version_known=fixed_known,
        dev_only=dev_only,
    )


def recommend(vulns, epss=None, kev=None):
    """検出一覧から推奨アクションを作る（優先度付けは本番と同じ経路を通す）。"""
    items = prioritize(vulns, epss or {}, kev or set())
    return build(items)


def by_package(recommendations):
    return {item.pkg_name: item for item in recommendations}


# --- 集約の単位 ---------------------------------------------------------------


def test_検出箇所が違っても1行にまとまる():
    """同じ版が2箇所にあっても、作業は「1回上げる」で済む。"""
    result = recommend(
        [
            make_vuln("CVE-2020-8203", target="app/package-lock.json"),
            make_vuln("CVE-2020-8203", target="worker/package-lock.json"),
        ]
    )

    assert len(result) == 1
    assert result[0].resolved == 1, "同じCVEを2件と数えている"


def test_現在バージョンが違えば別の行になる():
    """上げ先が変わるため、まとめてはいけない。"""
    result = recommend(
        [
            make_vuln("CVE-2020-8203", installed="4.17.15", fixed="4.17.20"),
            make_vuln("CVE-2020-8203", installed="3.10.1", fixed="4.17.20"),
        ]
    )
    assert sorted(item.installed_version for item in result) == ["3.10.1", "4.17.15"]


def test_パッケージが違えば別の行になる():
    result = recommend(
        [
            make_vuln("CVE-2020-8203", pkg="lodash"),
            make_vuln("CVE-2020-7598", pkg="minimist", installed="1.2.0", fixed="1.2.3"),
        ]
    )
    assert sorted(by_package(result)) == ["lodash", "minimist"]


# --- 上げ先の決め方 -----------------------------------------------------------


def test_上げ先は検出された修正版の最大値になる():
    result = recommend(
        [
            make_vuln("CVE-2020-8203", fixed="4.17.20"),
            make_vuln("CVE-2021-23337", fixed="4.17.21"),
            make_vuln("CVE-2019-10744", fixed="4.17.12"),
        ]
    )

    assert result[0].fixed_version == "4.17.21"
    assert result[0].resolved == 3


def test_桁数が違っても新しい方を選ぶ():
    result = recommend(
        [
            make_vuln("CVE-2020-8203", fixed="4.17.5"),
            make_vuln("CVE-2021-23337", fixed="4.17.21"),
        ]
    )
    assert result[0].fixed_version == "4.17.21"


def test_修正版が1つだけなら比較できない表記でもそのまま使う():
    """比較する相手がいなければ、誤った大小関係を作りようがない。"""
    result = recommend([make_vuln("CVE-2022-37434", fixed="1:1.2.11.dfsg-2+deb11u2")])
    assert result[0].fixed_version == "1:1.2.11.dfsg-2+deb11u2"


def test_比較できない表記が混ざれば上げ先を決めない():
    """古い版へのダウングレードを「上げ先」として案内しないため。"""
    result = recommend(
        [
            make_vuln("CVE-2022-37434", pkg="zlib1g", fixed="1:1.2.11.dfsg-2+deb11u2"),
            make_vuln("CVE-2018-25032", pkg="zlib1g", fixed="1:1.2.11.dfsg-2+deb11u1"),
        ]
    )

    assert result[0].fixed_version is None
    assert result[0].fixed_version_known is False, "決められなかったのに「修正版なし」と書いている"
    assert result[0].resolved == 0
    assert result[0].unresolved == 2


def test_修正版が全て無ければ修正版なしと書く():
    result = recommend(
        [
            make_vuln("CVE-2011-3374", pkg="apt", fixed=None),
            make_vuln("CVE-2020-27350", pkg="apt", fixed=None),
        ]
    )

    assert result[0].fixed_version is None
    assert result[0].fixed_version_known is True
    assert result[0].unresolved == 2


def test_修正版の有無が不明なら不明と書く():
    """CycloneDX では「修正版が無い」ことを明示できないため、断定しない。"""
    result = recommend([make_vuln("CVE-2018-1000805", fixed=None, fixed_known=False)])

    assert result[0].fixed_version is None
    assert result[0].fixed_version_known is False


def test_修正版なしと不明が混ざれば不明に倒す():
    result = recommend(
        [
            make_vuln("CVE-2011-3374", fixed=None, fixed_known=True),
            make_vuln("CVE-2018-1000805", fixed=None, fixed_known=False),
        ]
    )
    assert result[0].fixed_version_known is False


# --- 解消される件数 -----------------------------------------------------------


def test_上げても残る検出は解消件数に入れない():
    result = recommend(
        [
            make_vuln("CVE-2020-8203", fixed="4.17.20"),
            make_vuln("CVE-2021-23337", fixed="4.17.21"),
            make_vuln("CVE-2099-00000", fixed=None),
        ]
    )

    assert result[0].fixed_version == "4.17.21"
    assert result[0].resolved == 2
    assert result[0].unresolved == 1
    assert result[0].unresolved_has_no_fix is True
    assert result[0].unresolved_has_unknown is False


def test_残る検出の内訳を区別する():
    result = recommend(
        [
            make_vuln("CVE-2020-8203", fixed="4.17.20"),
            make_vuln("CVE-2099-00000", fixed=None, fixed_known=True),
            make_vuln("CVE-2099-00001", fixed=None, fixed_known=False),
        ]
    )

    assert result[0].unresolved == 2
    assert result[0].unresolved_has_no_fix is True
    assert result[0].unresolved_has_unknown is True


def test_同じCVEは検出箇所が違っても1件と数える():
    result = recommend(
        [
            make_vuln("CVE-2020-8203", target="app/package-lock.json"),
            make_vuln("CVE-2020-8203", target="worker/package-lock.json"),
            make_vuln("CVE-2021-23337", fixed="4.17.21"),
        ]
    )
    assert result[0].resolved == 2


def test_一方の検出でだけ修正版が読めていれば解消できる():
    """検出箇所によって修正版の有無が食い違うことがある。読めている方を採る。"""
    result = recommend(
        [
            make_vuln("CVE-2020-8203", target="a", fixed=None, fixed_known=False),
            make_vuln("CVE-2020-8203", target="b", fixed="4.17.20"),
        ]
    )

    assert result[0].fixed_version == "4.17.20"
    assert result[0].resolved == 1
    assert result[0].unresolved == 0


def test_上げ先が決まらなければ解消件数は0になる():
    """どこまで上げればよいか言えないのに「2件片付く」と書かない。"""
    result = recommend(
        [
            make_vuln("CVE-2022-37434", fixed="1:1.2.11.dfsg-2+deb11u2"),
            make_vuln("CVE-2018-25032", fixed="1:1.2.11.dfsg-2+deb11u1"),
        ]
    )

    assert result[0].resolved == 0
    assert result[0].unresolved_has_unknown is True


# --- 最高優先度 ---------------------------------------------------------------


def test_最高優先度はそのパッケージで最も緊急なランクになる():
    result = recommend(
        [
            make_vuln("CVE-2020-8203", cvss=3.0),
            make_vuln("CVE-2021-23337", cvss=9.8, fixed="4.17.21"),
        ],
        epss={"CVE-2021-23337": 0.5},
    )
    assert result[0].priority is Priority.P1


# --- 並び順 -------------------------------------------------------------------


def test_上げ先が決まらない行は最後にまとめる():
    """P0 でも上げ先が無ければ、この表からできることは無い。"""
    result = recommend(
        [
            make_vuln("CVE-2021-44228", pkg="log4j-core", fixed=None, cvss=10.0),
            make_vuln("CVE-2020-8203", pkg="lodash", cvss=3.0),
        ],
        kev={"CVE-2021-44228"},
    )
    assert [item.pkg_name for item in result] == ["lodash", "log4j-core"]


def test_優先度の高い順に並ぶ():
    result = recommend(
        [
            make_vuln("CVE-2020-8203", pkg="lodash", cvss=3.0),
            make_vuln("CVE-2021-44228", pkg="log4j-core", installed="2.14.1", fixed="2.15.0"),
        ],
        kev={"CVE-2021-44228"},
    )
    assert [item.pkg_name for item in result] == ["log4j-core", "lodash"]


def test_同じ優先度なら解消件数の多い順に並ぶ():
    result = recommend(
        [
            make_vuln("CVE-2020-8203", pkg="lodash", cvss=3.0),
            make_vuln("CVE-2020-7598", pkg="minimist", installed="1.2.0", fixed="1.2.3", cvss=3.0),
            make_vuln("CVE-2021-44906", pkg="minimist", installed="1.2.0", fixed="1.2.6", cvss=3.0),
        ]
    )
    assert [item.pkg_name for item in result] == ["minimist", "lodash"]


def test_並び順が入力の順序に左右されない():
    vulns = [
        make_vuln("CVE-2020-7598", pkg="minimist", installed="1.2.0", fixed="1.2.3", cvss=3.0),
        make_vuln("CVE-2020-8203", pkg="lodash", cvss=3.0),
    ]
    assert [item.pkg_name for item in recommend(vulns)] == [
        item.pkg_name for item in recommend(list(reversed(vulns)))
    ]


# --- 本番依存 / 開発依存 ------------------------------------------------------


def test_本番依存で1件でも見つかれば本番依存として扱う():
    """作業は1回で済むため、開発側にも同じ行を出して二重に見せない。"""
    result = recommend(
        [
            make_vuln("CVE-2020-8203", target="a", dev_only=True),
            make_vuln("CVE-2021-23337", target="b", dev_only=False, fixed="4.17.21"),
        ]
    )
    assert result[0].dev_only is False


def test_全て開発依存なら開発依存になる():
    result = recommend([make_vuln("CVE-2020-8203", dev_only=True)])
    assert result[0].dev_only is True


# --- 全体 ---------------------------------------------------------------------


@pytest.mark.parametrize("items", [[], ()])
def test_検出が無ければ推奨アクションも無い(items):
    assert build(items) == []
