"""SPDX（JSON）入力の読み取りの検証。

SPDX 2.x は部品表であって脆弱性の一覧ではない。この形式で守りたいのは2つ。

- 書ける場所（SECURITY 参照）に CVE があれば、確実に拾うこと
- 何も無いときに「検出0件」を「安全」と読ませないこと（`sbom_only`）

外部には接続しない。
"""

import pytest

from triage_lens import spdx
from triage_lens.errors import InputError
from triage_lens.models import UNKNOWN_TARGET, UNKNOWN_VALUE
from triage_lens.spdx import load_sbom, looks_like_spdx, parse_sbom


def _document(*, version="SPDX-2.3", packages=None, relationships=None, **extra):
    document = {
        "spdxVersion": version,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "demo-app@1.0.0",
        "packages": packages if packages is not None else [],
    }
    if relationships is not None:
        document["relationships"] = relationships
    document.update(extra)
    return document


def _package(name="demo-lib", *, spdx_id=None, version="1.0.0", refs=None, **extra):
    package = {
        "SPDXID": spdx_id if spdx_id is not None else f"SPDXRef-Package-{name}",
        "name": name,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
    }
    if refs is not None:
        package["externalRefs"] = refs
    package.update(extra)
    return package


def _security_ref(locator, *, kind="advisory"):
    return {
        "referenceCategory": "SECURITY",
        "referenceType": kind,
        "referenceLocator": locator,
    }


def _purl_ref(locator, *, category="PACKAGE-MANAGER"):
    return {
        "referenceCategory": category,
        "referenceType": "purl",
        "referenceLocator": locator,
    }


def _relationship(element, kind, *, related="SPDXRef-Package-app"):
    return {
        "spdxElementId": element,
        "relationshipType": kind,
        "relatedSpdxElement": related,
    }


def _advisory(cve_id="CVE-2021-23337"):
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


# --- 形式と版数 ---------------------------------------------------------


def test_spdxVersionを持つJSONをSPDXとみなす():
    assert looks_like_spdx({"spdxVersion": "SPDX-2.3"})
    assert not looks_like_spdx({"bomFormat": "CycloneDX"})
    assert not looks_like_spdx({"Results": []})
    assert not looks_like_spdx(["文字列"])


def test_SPDX22とSPDX23を読む():
    for version in ("SPDX-2.2", "SPDX-2.3"):
        scan = parse_sbom(_document(version=version))

        assert scan.artifact_name == "demo-app@1.0.0"
        assert scan.vulnerabilities == []


def test_細かい版数が付いていても読む():
    """`SPDX-2.3.1` のような表記を弾かない（3つ目以降の数字は見ない）。"""
    scan = parse_sbom(_document(version="SPDX-2.3.1"))

    assert scan.vulnerabilities == []


def test_対応していない版は対応範囲を書いて入力エラー():
    for version in ("SPDX-2.1", "SPDX-2.4", "SPDX-1.2"):
        with pytest.raises(InputError, match="対応しているのは SPDX 2.2 / 2.3"):
            parse_sbom(_document(version=version))


def test_版数が読めない書式は入力エラー():
    for version in ("2.3", "SPDX-x.y", "SPDX-2"):
        with pytest.raises(InputError, match="版数を読み取れませんでした"):
            parse_sbom(_document(version=version))


def test_SPDX3は名指しで未対応と伝える():
    """「Trivy でも CycloneDX でもない」より、次に何をすればよいかが分かる。"""
    document = {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [],
    }

    assert looks_like_spdx(document)
    with pytest.raises(InputError, match="SPDX 3.x には対応していません"):
        parse_sbom(document)


def test_SPDXでない文書を渡したら入力エラー():
    with pytest.raises(InputError, match="SPDX 形式（JSON）ではないようです"):
        parse_sbom({"bomFormat": "CycloneDX"})


# --- 脆弱性の取り出し ---------------------------------------------------


def test_advisory参照からCVEを取り出す():
    document = _document(
        packages=[_package("lodash", version="4.17.15", refs=[_security_ref(_advisory())])]
    )

    (vuln,) = parse_sbom(document).vulnerabilities

    assert vuln.cve_id == "CVE-2021-23337"
    assert vuln.pkg_name == "lodash"
    assert vuln.installed_version == "4.17.15"


def test_fixとurlの参照からもCVEを取り出す():
    """どれも「この部品に関係する脆弱性」を指す。取りこぼすほうの損が大きい。"""
    document = _document(
        packages=[
            _package("a", refs=[_security_ref(_advisory("CVE-2020-0001"), kind="fix")]),
            _package("b", refs=[_security_ref(_advisory("CVE-2020-0002"), kind="url")]),
        ]
    )

    assert [v.cve_id for v in parse_sbom(document).vulnerabilities] == [
        "CVE-2020-0001",
        "CVE-2020-0002",
    ]


def test_cpe参照からはCVEを取り出さない():
    """CPE は製品の識別子であって脆弱性ではない。引くには別のデータ源が要る。"""
    refs = [
        _security_ref("cpe:2.3:a:example:demo-lib:1.0.0:*:*:*:*:*:*:*", kind="cpe23Type"),
        _security_ref("cpe:/a:example:demo-lib:1.0.0", kind="cpe22Type"),
    ]

    assert parse_sbom(_document(packages=[_package(refs=refs)])).vulnerabilities == []


def test_SECURITY以外の分類の参照は見ない():
    ref = {
        "referenceCategory": "OTHER",
        "referenceType": "advisory",
        "referenceLocator": _advisory(),
    }

    assert parse_sbom(_document(packages=[_package(refs=[ref])])).vulnerabilities == []


def test_1つの部品に複数のCVEがあれば行を分ける():
    refs = [_security_ref(_advisory("CVE-2020-0001")), _security_ref(_advisory("CVE-2020-0002"))]

    vulns = parse_sbom(_document(packages=[_package(refs=refs)])).vulnerabilities

    assert [v.cve_id for v in vulns] == ["CVE-2020-0001", "CVE-2020-0002"]


def test_同じCVEが複数の参照に書かれていても1件にまとめる():
    refs = [
        _security_ref(_advisory("CVE-2020-0001")),
        _security_ref("https://example.test/CVE-2020-0001", kind="url"),
    ]

    vulns = parse_sbom(_document(packages=[_package(refs=refs)])).vulnerabilities

    assert [v.cve_id for v in vulns] == ["CVE-2020-0001"]


def test_小文字のCVE表記も拾って大文字にそろえる():
    refs = [_security_ref("https://example.test/advisories/cve-2020-0001")]

    (vuln,) = parse_sbom(_document(packages=[_package(refs=refs)])).vulnerabilities

    assert vuln.cve_id == "CVE-2020-0001"


def test_CVEに見える部分文字列は拾わない():
    """`XCVE-2020-0001` のような文字列から偽の検出を作らない。"""
    refs = [_security_ref("https://example.test/XCVE-2020-0001-suffix")]

    assert parse_sbom(_document(packages=[_package(refs=refs)])).vulnerabilities == []


def test_URLの末尾に語が続いてもCVEは拾う():
    """`CVE-2020-0001-notes.html` は CVE-2020-0001 を指している。"""
    refs = [_security_ref("https://example.test/advisories/CVE-2020-0001-notes.html")]

    (vuln,) = parse_sbom(_document(packages=[_package(refs=refs)])).vulnerabilities

    assert vuln.cve_id == "CVE-2020-0001"


def test_SPDX22に23の参照型が書かれていても読む():
    """仕様上 2.2 に `advisory` は無いが、書かれていれば CVE として拾う。

    仕様違反の文書だが、拾わない側に倒すと実在する脆弱性を黙って落とすことになる。
    多めに出るほうが、見落とすよりまし。
    """
    document = _document(version="SPDX-2.2", packages=[_package(refs=[_security_ref(_advisory())])])

    scan = parse_sbom(document)

    assert [v.cve_id for v in scan.vulnerabilities] == ["CVE-2021-23337"]
    assert scan.sbom_only is False


def test_CVEを含まない参照は行を作らない():
    refs = [_security_ref("https://example.test/advisories/GHSA-xxxx-yyyy-zzzz")]

    assert parse_sbom(_document(packages=[_package(refs=refs)])).vulnerabilities == []


def test_壊れた部品は読み飛ばして他の部品は残す():
    packages = ["文字列", {"name": None}, _package("生き残り", refs=[_security_ref(_advisory())])]

    vulns = parse_sbom(_document(packages=packages)).vulnerabilities

    assert [v.pkg_name for v in vulns] == ["生き残り"]


# --- 読み取れない項目 ---------------------------------------------------


def test_修正版は常に不明にする():
    """SPDX に修正版を書く場所は無い。「修正版なし」と断定すると直せないと読ませる。"""
    document = _document(packages=[_package(refs=[_security_ref(_advisory())])])

    (vuln,) = parse_sbom(document).vulnerabilities

    assert vuln.fixed_version is None
    assert vuln.fixed_version_known is False


def test_CVSSは常に不明にする():
    """SPDX に深刻度スコアを書く場所は無い。EPSS と KEV だけで優先度が付く。"""
    document = _document(packages=[_package(refs=[_security_ref(_advisory())])])

    (vuln,) = parse_sbom(document).vulnerabilities

    assert vuln.cvss is None


def test_名前とバージョンが読めなければ不明と書く():
    package = {"SPDXID": "SPDXRef-Package-x", "externalRefs": [_security_ref(_advisory())]}

    (vuln,) = parse_sbom(_document(packages=[package])).vulnerabilities

    assert vuln.pkg_name == UNKNOWN_VALUE
    assert vuln.installed_version == UNKNOWN_VALUE


# --- 検出箇所 -----------------------------------------------------------


def test_検出箇所はpurlを優先する():
    refs = [_purl_ref("pkg:npm/demo-lib@1.0.0"), _security_ref(_advisory())]

    (vuln,) = parse_sbom(_document(packages=[_package(refs=refs)])).vulnerabilities

    assert vuln.target == "pkg:npm/demo-lib@1.0.0"


def test_purlの分類は区切り文字の表記ゆれを許す():
    """`PACKAGE-MANAGER` と `PACKAGE_MANAGER` の両方が出回っている。"""
    refs = [
        _purl_ref("pkg:npm/demo-lib@1.0.0", category="PACKAGE_MANAGER"),
        _security_ref(_advisory()),
    ]

    (vuln,) = parse_sbom(_document(packages=[_package(refs=refs)])).vulnerabilities

    assert vuln.target == "pkg:npm/demo-lib@1.0.0"


def test_purlが無ければSPDXIDを検出箇所にする():
    package = _package(spdx_id="SPDXRef-Package-demo", refs=[_security_ref(_advisory())])

    (vuln,) = parse_sbom(_document(packages=[package])).vulnerabilities

    assert vuln.target == "SPDXRef-Package-demo"


def test_purlもSPDXIDも無ければ文書名を検出箇所にする():
    package = {"name": "demo-lib", "externalRefs": [_security_ref(_advisory())]}

    (vuln,) = parse_sbom(_document(packages=[package])).vulnerabilities

    assert vuln.target == "demo-app@1.0.0"


def test_文書名も無ければ検出箇所不明にする():
    package = {"name": "demo-lib", "externalRefs": [_security_ref(_advisory())]}
    document = _document(packages=[package])
    del document["name"]

    (vuln,) = parse_sbom(document).vulnerabilities

    assert vuln.target == UNKNOWN_TARGET


# --- 本番依存 / 開発依存 ------------------------------------------------


def _scan_with_relationship(kind):
    package = _package(spdx_id="SPDXRef-Package-x", refs=[_security_ref(_advisory())])
    return parse_sbom(
        _document(packages=[package], relationships=[_relationship("SPDXRef-Package-x", kind)])
    )


@pytest.mark.parametrize("kind", ["DEV_DEPENDENCY_OF", "TEST_DEPENDENCY_OF"])
def test_開発用の関係は開発依存にする(kind):
    scan = _scan_with_relationship(kind)

    assert scan.vulnerabilities[0].dev_only is True
    assert scan.scope_known is True


@pytest.mark.parametrize(
    "kind",
    [
        "RUNTIME_DEPENDENCY_OF",
        "BUILD_DEPENDENCY_OF",
        "OPTIONAL_DEPENDENCY_OF",
        "PROVIDED_DEPENDENCY_OF",
    ],
)
def test_実行時の関係は本番依存にする(kind):
    """ビルド依存も本番側に置く。生成物にコードが入りうるため、安全側は本番。"""
    scan = _scan_with_relationship(kind)

    assert scan.vulnerabilities[0].dev_only is False
    assert scan.scope_known is True


@pytest.mark.parametrize("kind", ["DEPENDENCY_OF", "DEPENDS_ON", "CONTAINS"])
def test_スコープを語らない関係だけなら区別できないとする(kind):
    scan = _scan_with_relationship(kind)

    assert scan.scope_known is False
    assert scan.vulnerabilities[0].dev_only is False


def test_部品以外を指す関係はスコープの材料に数えない():
    """SPDX の関係はファイルや文書のあいだにも書ける。

    部品以外の関係まで数えると、部品については材料が無いのに「区別できた
    （全件が本番依存）」というレポートを出してしまう。
    """
    package = _package(spdx_id="SPDXRef-Package-x", refs=[_security_ref(_advisory())])
    relationships = [_relationship("SPDXRef-File-test-helper", "TEST_DEPENDENCY_OF")]

    scan = parse_sbom(_document(packages=[package], relationships=relationships))

    assert scan.scope_known is False
    assert scan.vulnerabilities[0].dev_only is False


def test_部品を指す関係だけがスコープの材料になる():
    """部品以外の関係が混ざっていても、部品の関係があれば区別できる。"""
    package = _package(spdx_id="SPDXRef-Package-x", refs=[_security_ref(_advisory())])
    relationships = [
        _relationship("SPDXRef-File-test-helper", "TEST_DEPENDENCY_OF"),
        _relationship("SPDXRef-Package-x", "DEV_DEPENDENCY_OF"),
    ]

    scan = parse_sbom(_document(packages=[package], relationships=relationships))

    assert scan.scope_known is True
    assert scan.vulnerabilities[0].dev_only is True


def test_関係が書かれていなければ区別できないとする():
    package = _package(refs=[_security_ref(_advisory())])

    scan = parse_sbom(_document(packages=[package]))

    assert scan.scope_known is False
    assert scan.vulnerabilities[0].dev_only is False


def test_開発用と実行時の関係が両方あれば本番依存にする():
    """片方でも本番なら本番。開発側に寄せると見落としになる。"""
    package = _package(spdx_id="SPDXRef-Package-x", refs=[_security_ref(_advisory())])
    relationships = [
        _relationship("SPDXRef-Package-x", "DEV_DEPENDENCY_OF"),
        _relationship("SPDXRef-Package-x", "RUNTIME_DEPENDENCY_OF"),
    ]

    scan = parse_sbom(_document(packages=[package], relationships=relationships))

    assert scan.vulnerabilities[0].dev_only is False


def test_スコープを語らない関係は開発依存の記述を打ち消さない():
    """`A DEPENDS_ON B` の A は依存する側で、A のスコープについては何も言っていない。"""
    package = _package(spdx_id="SPDXRef-Package-x", refs=[_security_ref(_advisory())])
    relationships = [
        _relationship("SPDXRef-Package-x", "DEV_DEPENDENCY_OF"),
        _relationship("SPDXRef-Package-x", "DEPENDS_ON", related="SPDXRef-Package-y"),
    ]

    scan = parse_sbom(_document(packages=[package], relationships=relationships))

    assert scan.vulnerabilities[0].dev_only is True


def test_依存される側を開発依存と取り違えない():
    """`A DEV_DEPENDENCY_OF B` で開発依存なのは A。B は取り違えの対象になりやすい。"""
    packages = [
        _package(spdx_id="SPDXRef-Package-x", refs=[_security_ref(_advisory("CVE-2020-0001"))]),
        _package(spdx_id="SPDXRef-Package-y", refs=[_security_ref(_advisory("CVE-2020-0002"))]),
    ]
    relationships = [
        _relationship("SPDXRef-Package-x", "DEV_DEPENDENCY_OF", related="SPDXRef-Package-y")
    ]

    scan = parse_sbom(_document(packages=packages, relationships=relationships))

    assert [v.dev_only for v in scan.vulnerabilities] == [True, False]


def test_区別できるときはscope由来の注記を抑止する():
    """SPDX の関係は明示の記述で、CycloneDX の scope のような既定値の揺れが無い。"""
    assert _scan_with_relationship("DEV_DEPENDENCY_OF").dev_property_used is True
    assert _scan_with_relationship("DEPENDS_ON").dev_property_used is False


# --- 部品表だけの入力 ---------------------------------------------------


def test_脆弱性を1件も取り出せなければ部品表だけと印を付ける():
    scan = parse_sbom(_document(packages=[_package(refs=[_purl_ref("pkg:npm/demo-lib@1.0.0")])]))

    assert scan.vulnerabilities == []
    assert scan.sbom_only is True


def test_脆弱性が取り出せたら部品表だけの印は付けない():
    scan = parse_sbom(_document(packages=[_package(refs=[_security_ref(_advisory())])]))

    assert scan.sbom_only is False


# --- 壊れた構造 ---------------------------------------------------------


def test_packagesが一覧でなければ入力エラー():
    with pytest.raises(InputError, match="packages が一覧ではありません"):
        parse_sbom(_document(packages={"name": "demo"}))


def test_relationshipsが一覧でなければ入力エラー():
    with pytest.raises(InputError, match="relationships が一覧ではありません"):
        parse_sbom(_document(relationships={"spdxElementId": "SPDXRef-Package-x"}))


def test_externalRefsが一覧でなければ入力エラー():
    package = _package()
    package["externalRefs"] = {"referenceCategory": "SECURITY"}

    with pytest.raises(InputError, match="externalRefs が一覧ではありません"):
        parse_sbom(_document(packages=[package]))


def test_名前が文字列でなくても落とさず不明にする():
    """1つの部品の壊れ方で入力全体を落とさない。"""
    package = _package(refs=[_security_ref(_advisory())])
    package["name"] = {"想定外": "辞書"}

    (vuln,) = parse_sbom(_document(packages=[package])).vulnerabilities

    assert vuln.pkg_name == UNKNOWN_VALUE


def test_想定外の例外が出てもトレースバックを出さず入力エラーにする(monkeypatch):
    """防御しきれない壊れ方でも、利用者にスタックトレースを見せない。"""

    def explode(*args, **kwargs):
        raise RuntimeError("想定外の壊れ方")

    monkeypatch.setattr(spdx, "_collect_vulnerabilities", explode)

    with pytest.raises(InputError, match="SPDX の構造が想定と異なります"):
        parse_sbom(_document())


def test_packagesが無くても読める():
    document = _document()
    del document["packages"]

    scan = parse_sbom(document)

    assert scan.vulnerabilities == []
    assert scan.sbom_only is True


# --- fixture の読み込み -------------------------------------------------


def test_fixtureのSPDXを読む(fixtures_dir):
    scan = load_sbom(fixtures_dir / "spdx_sample.json")

    assert scan.artifact_name == "sample-app@1.4.0"
    assert [v.cve_id for v in scan.vulnerabilities] == [
        "CVE-2021-23337",
        "CVE-2021-32640",
        "CVE-2021-44906",
        "CVE-2020-28498",
    ]
    assert [v.dev_only for v in scan.vulnerabilities] == [False, False, True, True]
    assert scan.scope_known is True
    assert scan.sbom_only is False


def test_部品表だけのfixtureは検出0件になる(fixtures_dir):
    scan = load_sbom(fixtures_dir / "spdx_sbom_only.json")

    assert scan.artifact_name == "demo-service@0.2.0"
    assert scan.vulnerabilities == []
    assert scan.sbom_only is True
    assert scan.scope_known is False


def test_SPDX22はCVEを書く場所が無いので0件になる(fixtures_dir):
    """2.2 の SECURITY 参照は cpe22Type / cpe23Type だけで、CVE を書けない。"""
    scan = load_sbom(fixtures_dir / "spdx_22.json")

    assert scan.vulnerabilities == []
    assert scan.sbom_only is True
