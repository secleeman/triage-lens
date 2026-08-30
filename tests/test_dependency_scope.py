"""本番依存 / 開発依存の判別の検証。

判別を間違えると「本番の問題が開発依存の表に隠れる」ことになるため、
迷ったときに**本番側へ倒れている**ことを重点的に見る。
"""

import pytest

from triage_lens.cyclonedx import parse_bom
from triage_lens.loader import load_scan
from triage_lens.models import UNKNOWN_VALUE, Vulnerability
from triage_lens.parsing import deduplicate


def bom(components, vulnerabilities=None, **overrides):
    """component と脆弱性だけを差し替えた最小限の CycloneDX 文書を作る。"""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
        "vulnerabilities": vulnerabilities if vulnerabilities is not None else [],
    }
    document.update(overrides)
    return document


def component(ref="pkg:npm/demo@1.0.0", name="demo", **extra):
    base = {"bom-ref": ref, "type": "library", "name": name, "version": "1.0.0"}
    base.update(extra)
    return base


def vulnerability(cve_id="CVE-2020-8203", ref="pkg:npm/demo@1.0.0"):
    return {"id": cve_id, "affects": [{"ref": ref}]}


def dev_flags(scan):
    """パッケージ名から `dev_only` を引けるようにする。"""
    return {vuln.pkg_name: vuln.dev_only for vuln in scan.vulnerabilities}


# --- component 1件ごとの判定 --------------------------------------------------


@pytest.mark.parametrize(
    ("scope", "expected"),
    [
        ("excluded", True),
        # optional は「実行時に任意」であって開発専用ではない。npm は
        # optionalDependencies にこの値を付けるため、開発扱いにすると本番の
        # 問題が「開発だけ」の表に隠れてしまう。
        ("optional", False),
        ("required", False),
        ("EXCLUDED", True),
        (" excluded ", True),
    ],
)
def test_scopeから判別する(scope, expected):
    scan = parse_bom(bom([component(scope=scope)], [vulnerability()]))
    assert scan.vulnerabilities[0].dev_only is expected


def test_propertiesだけでも開発依存と判別できる():
    """`scope` を書かず properties だけで dev を表す生成ツールがある。"""
    dev = component(properties=[{"name": "cdx:npm:package:development", "value": "true"}])
    scan = parse_bom(bom([dev], [vulnerability()]))

    assert scan.scope_known is True
    assert scan.vulnerabilities[0].dev_only is True


def test_propertiesはscopeより優先される():
    """npm 本体は dev にも `scope: required` を付けるため、property を先に見る。"""
    dev = component(
        scope="required",
        properties=[{"name": "cdx:npm:package:development", "value": "true"}],
    )
    scan = parse_bom(bom([dev], [vulnerability()]))
    assert scan.vulnerabilities[0].dev_only is True


@pytest.mark.parametrize(
    "properties",
    [
        [{"name": "cdx:npm:package:development", "value": "false"}],
        [{"name": "cdx:npm:package:development", "value": ""}],
        [{"name": "cdx:npm:package:development"}],
        [{"name": "cdx:npm:package:bundled", "value": "true"}],
        [{"name": "unknown:property", "value": "true"}],
        [{"value": "true"}],
        ["not-an-object"],
        "not-a-list",
    ],
)
def test_開発依存と読めないpropertiesは本番依存にする(properties):
    scan = parse_bom(bom([component(properties=properties)], [vulnerability()]))
    assert scan.vulnerabilities[0].dev_only is False


def test_scopeが省略された部品は本番依存になる():
    """仕様上、`scope` の省略時の既定は `required`。"""
    scan = parse_bom(
        bom(
            [component(ref="a", name="plain"), component(ref="b", name="dev", scope="excluded")],
            [vulnerability(ref="a"), vulnerability("CVE-2020-7598", ref="b")],
        )
    )
    assert dev_flags(scan) == {"plain": False, "dev": True}


def test_SBOMに無い部品を参照する検出は本番依存になる():
    """判別できないものを開発側に寄せない（見落としを作らないため）。"""
    scan = parse_bom(
        bom(
            [component(scope="excluded")],
            [vulnerability("CVE-2022-25883", ref="pkg:npm/missing@1.0.0")],
        )
    )
    (vuln,) = scan.vulnerabilities
    assert vuln.pkg_name == UNKNOWN_VALUE
    assert vuln.dev_only is False


def test_影響先が書かれていない検出は本番依存になる():
    scan = parse_bom(bom([component(scope="excluded")], [{"id": "CVE-2020-8203"}]))
    assert scan.vulnerabilities[0].dev_only is False


def test_入れ子のcomponentのscopeも読む():
    parent = component(ref="parent", name="bundle", components=[component(scope="excluded")])
    scan = parse_bom(bom([parent], [vulnerability()]))
    assert scan.vulnerabilities[0].dev_only is True


# --- 入力全体で区別できるかどうか ---------------------------------------------


def test_信号が1つも無ければ区別できないと扱う():
    """`scope` の省略を「本番依存だと分かった」と読み替えない。"""
    scan = parse_bom(bom([component()], [vulnerability()]))

    assert scan.scope_known is False
    assert scan.vulnerabilities[0].dev_only is False


@pytest.mark.parametrize("scope", ["required", "optional", "excluded"])
def test_scopeが1件でも書かれていれば区別できると扱う(scope):
    scan = parse_bom(
        bom([component(ref="a", name="plain"), component(ref="b", name="tagged", scope=scope)])
    )
    assert scan.scope_known is True


def test_bomrefを持たない部品のscopeも信号になる():
    """索引に載らない部品にも判別の材料が書かれていることがある。"""
    document = bom([{"type": "library", "name": "no-ref", "scope": "excluded"}])
    assert parse_bom(document).scope_known is True


@pytest.mark.parametrize("scope", [None, "", 1, [], {}])
def test_scopeの値が文字列でなければ信号にしない(scope):
    scan = parse_bom(bom([component(scope=scope)], [vulnerability()]))

    assert scan.scope_known is False
    assert scan.vulnerabilities[0].dev_only is False


def test_脆弱性が0件でも区別の有無は読み取れる():
    assert parse_bom(bom([component(scope="excluded")])).scope_known is True


# --- 入力形式ごとの既定 -------------------------------------------------------


def test_信号を持たないSBOMは区別できない(fixtures_dir):
    scan = load_scan(fixtures_dir / "cyclonedx_sample.json")

    assert scan.scope_known is False
    assert all(vuln.dev_only is False for vuln in scan.vulnerabilities)


def test_TrivyのJSONは区別できない(fixtures_dir):
    """Trivy の検出には本番 / 開発を示す項目が無いため、推測で分類しない。"""
    scan = load_scan(fixtures_dir / "trivy_sample.json")

    assert scan.scope_known is False
    assert all(vuln.dev_only is False for vuln in scan.vulnerabilities)


# --- 実際の生成ツールに近い入力 -----------------------------------------------


def test_scopeを明示したSBOMを読める(fixtures_dir):
    scan = load_scan(fixtures_dir / "cyclonedx_scope_explicit.json")

    assert scan.scope_known is True
    assert dev_flags(scan) == {
        "lodash": False,  # scope: required
        "tar": False,  # scope: optional は本番依存として扱う
        "minimist": True,  # scope: excluded
        UNKNOWN_VALUE: False,  # SBOM に無い部品
    }


def test_propertiesでdevを表すSBOMを読める(fixtures_dir):
    scan = load_scan(fixtures_dir / "cyclonedx_npm_properties.json")

    assert scan.scope_known is True
    assert dev_flags(scan) == {"lodash": False, "minimist": True}


# --- 重複した検出のまとめ方 ---------------------------------------------------


def test_重複した検出は本番依存に倒す():
    """同じ検出が本番と開発の両方で現れたら、本番として残す。"""
    common = {
        "cve_id": "CVE-2020-8203",
        "pkg_name": "lodash",
        "installed_version": "4.17.15",
        "fixed_version": "4.17.20",
        "cvss": 7.4,
        "target": "package-lock.json",
    }
    merged = deduplicate(
        [
            Vulnerability(**common, dev_only=True),
            Vulnerability(**common, dev_only=False),
        ]
    )

    assert [vuln.dev_only for vuln in merged] == [False]


def test_対象そのもののscopeは判別の材料にしない():
    """`metadata.component` はスキャン対象であって依存ではない。

    ここに `scope: required` と書かれていても、依存を区別する材料にはならない。
    材料として数えると、何も分からないまま「区別できた（全件が本番依存）」という
    レポートを出してしまう。
    """
    document = bom(
        [component()],
        [vulnerability()],
        metadata={"component": {"bom-ref": "root", "name": "app", "scope": "required"}},
    )
    scan = parse_bom(document)

    assert scan.scope_known is False
    assert scan.vulnerabilities[0].dev_only is False


def test_対象そのものが参照されても部品として引ける():
    """判別の材料としては見ないが、索引からは外さない（脆弱性から参照されうる）。"""
    document = bom(
        [],
        [vulnerability(ref="root")],
        metadata={"component": {"bom-ref": "root", "name": "app", "version": "1.0"}},
    )
    scan = parse_bom(document)

    assert scan.vulnerabilities[0].pkg_name == "app"
