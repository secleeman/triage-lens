"""CycloneDX 形式（JSON）の読み込みの検証。"""

import pytest

from triage_lens.cyclonedx import extract_cvss, load_bom, looks_like_cyclonedx, parse_bom
from triage_lens.errors import InputError


def bom(**overrides):
    """最小限の CycloneDX 文書を作る。"""
    document = {"bomFormat": "CycloneDX", "specVersion": "1.5"}
    document.update(overrides)
    return document


def by_id(scan):
    """CVE ID から行の一覧を引けるようにする（同一CVEが複数行になりうる）。"""
    grouped = {}
    for vuln in scan.vulnerabilities:
        grouped.setdefault(vuln.cve_id, []).append(vuln)
    return grouped


# --- 形式の判定 ---------------------------------------------------------------


def test_CycloneDXと判定する():
    assert looks_like_cyclonedx({"bomFormat": "CycloneDX"}) is True


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"bomFormat": "SPDX"},
        {"bomFormat": 1},
        {"Results": []},
        [],
        "text",
        None,
        # 仕様上の値は "CycloneDX" ちょうど。表記ゆれを許すと Trivy 出力を
        # CycloneDX と誤判定して検出結果を0件にしてしまう
        {"bomFormat": "cyclonedx"},
        {"bomFormat": " CycloneDX "},
        {"bomFormat": "CYCLONEDX"},
    ],
)
def test_CycloneDXと判定しない(document):
    assert looks_like_cyclonedx(document) is False


def test_CycloneDX以外を渡すと入力エラーになる():
    with pytest.raises(InputError, match="CycloneDX 形式（JSON）ではないようです"):
        parse_bom({"Results": []})


# --- 正常系 -------------------------------------------------------------------


def test_サンプルSBOMを読み込める(fixtures_dir):
    scan = load_bom(fixtures_dir / "cyclonedx_sample.json")

    assert scan.artifact_name == "sample-app@1.4.0"
    assert len(scan.vulnerabilities) == 9
    assert len({v.dedupe_key for v in scan.vulnerabilities}) == 9


def test_部品の情報が読み取れる(fixtures_dir):
    scan = load_bom(fixtures_dir / "cyclonedx_sample.json")

    log4j = by_id(scan)["CVE-2021-44228"][0]

    assert log4j.pkg_name == "log4j-core"
    assert log4j.installed_version == "2.14.1"
    assert log4j.fixed_version == "2.15.0"
    assert log4j.fixed_version_known is True
    assert log4j.cvss == 10.0
    assert log4j.target == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def test_入れ子のcomponentsも引き当てられる(fixtures_dir):
    """`components` の中に `components` がある構造でも部品名が取れる。"""
    scan = load_bom(fixtures_dir / "cyclonedx_sample.json")

    assert by_id(scan)["CVE-2020-14343"][0].pkg_name == "PyYAML"


def test_影響先が複数あれば部品ごとに行が分かれる(fixtures_dir):
    scan = load_bom(fixtures_dir / "cyclonedx_sample.json")

    rows = by_id(scan)["CVE-2014-0160"]

    assert len(rows) == 2
    assert {row.pkg_name for row in rows} == {"openssl", "sample-app-bundle"}


def test_修正版はunaffectedのエントリから取る(fixtures_dir):
    scan = load_bom(fixtures_dir / "cyclonedx_sample.json")

    openssl = next(v for v in by_id(scan)["CVE-2014-0160"] if v.pkg_name == "openssl")

    assert openssl.fixed_version == ">=1.0.1g-1"
    assert openssl.fixed_version_known is True


def test_unaffectedが複数あれば修正版を断定しない():
    """`unaffected` は「影響を受けない」であって「修正版」とは限らない。

    脆弱性が入る前の古い版も `unaffected` になりうるので、複数ある場合に
    先頭を修正版として案内するとダウングレードを勧めてしまう。
    """
    document = bom(
        components=[{"bom-ref": "c1", "name": "demo", "version": "2.0"}],
        vulnerabilities=[
            {
                "id": "CVE-2020-0001",
                "affects": [
                    {
                        "ref": "c1",
                        "versions": [
                            {"range": "vers:npm/<1.0", "status": "unaffected"},
                            {"version": "2.0", "status": "affected"},
                            {"version": "2.1", "status": "unaffected"},
                        ],
                    }
                ],
            }
        ],
    )

    vuln = parse_bom(document).vulnerabilities[0]

    assert vuln.fixed_version is None
    assert vuln.fixed_version_known is False


def test_unaffectedが1件ならそれを修正版として使う():
    document = bom(
        components=[{"bom-ref": "c1", "name": "demo", "version": "2.0"}],
        vulnerabilities=[
            {
                "id": "CVE-2020-0001",
                "affects": [
                    {
                        "ref": "c1",
                        "versions": [
                            {"version": "2.0", "status": "affected"},
                            {"version": "2.1", "status": "unaffected"},
                        ],
                    }
                ],
            }
        ],
    )

    vuln = parse_bom(document).vulnerabilities[0]

    assert vuln.fixed_version == "2.1"
    assert vuln.fixed_version_known is True


def test_修正版が書かれていなければ不明として扱う(fixtures_dir):
    """CycloneDX には「修正版なし」を明示する項目が無いため、断定しない。"""
    scan = load_bom(fixtures_dir / "cyclonedx_sample.json")

    libssh2 = by_id(scan)["CVE-2018-1000805"][0]

    assert libssh2.fixed_version is None
    assert libssh2.fixed_version_known is False


def test_参照先の部品が無くても行として残す(fixtures_dir):
    """SBOM に載っていない部品を参照していても、CVE は取りこぼさない。"""
    scan = load_bom(fixtures_dir / "cyclonedx_sample.json")

    nginx = by_id(scan)["CVE-2021-23017"][0]

    assert nginx.pkg_name == "(不明)"
    assert nginx.installed_version == "1.20.0-1"  # affects 側の版数を使う
    assert nginx.target == "pkg:deb/debian/nginx@1.20.0-1"
    assert nginx.cvss == 9.4


def test_影響先が無くても行として残す(fixtures_dir):
    scan = load_bom(fixtures_dir / "cyclonedx_sample.json")

    jquery = by_id(scan)["CVE-2019-11358"][0]

    assert jquery.pkg_name == "(不明)"
    assert jquery.installed_version == "(不明)"
    assert jquery.target == "sample-app@1.4.0"
    assert jquery.cvss == 6.1


def test_脆弱性が無いSBOMは0件として読める(fixtures_dir):
    scan = load_bom(fixtures_dir / "cyclonedx_empty.json")

    assert scan.artifact_name == "demo-service@0.2.0"
    assert scan.vulnerabilities == []


def test_vulnerabilitiesキーが無くても0件として読める():
    scan = parse_bom(bom(components=[]))

    assert scan.vulnerabilities == []


# --- 対象名 -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("component", "expected"),
    [
        ({"name": "demo", "version": "1.0"}, "demo@1.0"),
        ({"name": "demo"}, "demo"),
        ({"purl": "pkg:oci/demo@sha256:abc"}, "pkg:oci/demo@sha256:abc"),
        ({}, "(名称不明)"),
        ({"name": ""}, "(名称不明)"),
    ],
)
def test_対象名の決め方(component, expected):
    scan = parse_bom(bom(metadata={"component": component}))

    assert scan.artifact_name == expected


@pytest.mark.parametrize("metadata", [None, "text", 42, {}, {"component": "text"}])
def test_metadataが読めなければ名称不明になる(metadata):
    assert parse_bom(bom(metadata=metadata)).artifact_name == "(名称不明)"


# --- CVSS の選び方 ------------------------------------------------------------


@pytest.mark.parametrize(
    ("ratings", "expected"),
    [
        # 現行世代（v3系 / v4）を v2 より優先する
        ([{"score": 5.0, "method": "CVSSv2"}, {"score": 7.5, "method": "CVSSv31"}], 7.5),
        # 同じ世代なら nvd を優先する
        (
            [
                {"score": 9.8, "method": "CVSSv31", "source": {"name": "ghsa"}},
                {"score": 7.5, "method": "CVSSv31", "source": {"name": "nvd"}},
            ],
            7.5,
        ),
        # nvd が無ければ最大値
        (
            [
                {"score": 6.5, "method": "CVSSv3", "source": {"name": "redhat"}},
                {"score": 9.8, "method": "CVSSv31", "source": {"name": "ghsa"}},
            ],
            9.8,
        ),
        # v3系が無ければ v2
        ([{"score": 6.4, "method": "CVSSv2"}], 6.4),
        # CVSSv4 も現行世代として扱う
        ([{"score": 8.7, "method": "CVSSv4"}, {"score": 5.0, "method": "CVSSv2"}], 8.7),
        # 大文字小文字は問わない
        ([{"score": 7.1, "method": "cvssv31"}], 7.1),
    ],
)
def test_ratingsからCVSSを選ぶ(ratings, expected):
    assert extract_cvss(ratings) == expected


@pytest.mark.parametrize(
    "ratings",
    [
        None,
        "high",
        {},
        [],
        [{"severity": "critical", "method": "CVSSv31"}],  # score が無い
        [{"score": 7.4, "method": "other"}],  # CVSS 以外の尺度
        [{"score": 7.4, "method": "OWASP"}],
        [{"score": 7.4}],  # method が無いものは CVSS と断定しない
        [{"score": 42.0, "method": "CVSSv31"}],  # 範囲外
        [{"score": True, "method": "CVSSv31"}],  # bool はスコアではない
        [{"score": float("nan"), "method": "CVSSv31"}],
        ["junk", 1, None],
    ],
)
def test_CVSSとして扱えないratings(ratings):
    assert extract_cvss(ratings) is None


def test_CVSS以外の尺度は無視して有効な値を使う():
    ratings = [{"score": 9.9, "method": "SSVC"}, {"score": 4.2, "method": "CVSSv31"}]

    assert extract_cvss(ratings) == 4.2


# --- 異常系 -------------------------------------------------------------------


@pytest.mark.parametrize("entries", [1, "text", {"id": "CVE-2020-0001"}, 3.14, True])
def test_vulnerabilitiesが一覧でなければ入力エラー(entries):
    with pytest.raises(InputError, match="vulnerabilities が一覧ではありません"):
        parse_bom(bom(vulnerabilities=entries))


@pytest.mark.parametrize("components", [1, "text", {"bom-ref": "x"}, 3.14])
def test_componentsが一覧でなければ入力エラー(components):
    with pytest.raises(InputError, match="components が一覧ではありません"):
        parse_bom(bom(components=components))


@pytest.mark.parametrize("nested", [1, "text", {"bom-ref": "child"}, 3.14])
def test_入れ子のcomponentsが一覧でなければ入力エラー(nested):
    """浅い階層だけ型を検証しても意味がないので、入れ子も同じ扱いにする。"""
    document = bom(components=[{"bom-ref": "parent", "name": "p", "components": nested}])

    with pytest.raises(InputError, match="components が一覧ではありません"):
        parse_bom(document)


@pytest.mark.parametrize("affects", [1, "text", {"ref": "x"}, 3.14])
def test_affectsが一覧でなければ入力エラー(affects):
    document = bom(vulnerabilities=[{"id": "CVE-2020-0001", "affects": affects}])

    with pytest.raises(InputError, match=r"vulnerabilities\[0\].affects が一覧ではありません"):
        parse_bom(document)


def test_IDが無いエントリや壊れたエントリは読み飛ばす():
    document = bom(
        vulnerabilities=[
            "junk",
            {"ratings": []},
            {"id": ""},
            {"id": 42},
            {"id": "CVE-2020-0001"},
        ]
    )

    scan = parse_bom(document)

    assert [v.cve_id for v in scan.vulnerabilities] == ["CVE-2020-0001"]


def test_versionsの壊れたエントリは読み飛ばす():
    document = bom(
        vulnerabilities=[
            {
                "id": "CVE-2020-0001",
                "affects": [
                    {
                        "ref": "unknown-ref",
                        "versions": ["junk", {}, {"status": "unaffected"}, {"version": "1.2.3"}],
                    }
                ],
            }
        ]
    )

    vuln = parse_bom(document).vulnerabilities[0]

    assert vuln.installed_version == "1.2.3"  # status 省略は affected 扱い（仕様の既定）
    assert vuln.fixed_version is None
    assert vuln.fixed_version_known is False


def test_affectsの一覧に辞書以外が混じっていても落ちない():
    document = bom(vulnerabilities=[{"id": "CVE-2020-0001", "affects": ["junk", 1, None]}])

    scan = parse_bom(document)

    assert len(scan.vulnerabilities) == 1
    assert scan.vulnerabilities[0].pkg_name == "(不明)"


def test_同じ部品の完全に同一な行は重複として除く():
    affect = {"ref": "pkg:pypi/demo@1.0", "versions": [{"version": "1.0", "status": "affected"}]}
    document = bom(
        components=[
            {"bom-ref": "pkg:pypi/demo@1.0", "name": "demo", "version": "1.0"},
        ],
        vulnerabilities=[
            {"id": "CVE-2020-0001", "affects": [dict(affect), dict(affect)]},
        ],
    )

    assert len(parse_bom(document).vulnerabilities) == 1


def test_componentsの入れ子が深すぎても落ちない():
    """壊れた入力で再帰が止まらなくなることを防ぐ。"""
    deepest = {"bom-ref": "deepest", "name": "deepest"}
    node = deepest
    for index in range(60):
        node = {"bom-ref": f"level-{index}", "name": f"level-{index}", "components": [node]}

    scan = parse_bom(bom(components=[node], vulnerabilities=[{"id": "CVE-2020-0001"}]))

    assert len(scan.vulnerabilities) == 1


def test_bom_refが重複していても落ちない():
    document = bom(
        components=[
            {"bom-ref": "dup", "name": "first", "version": "1.0"},
            {"bom-ref": "dup", "name": "second", "version": "2.0"},
        ],
        vulnerabilities=[{"id": "CVE-2020-0001", "affects": [{"ref": "dup"}]}],
    )

    vuln = parse_bom(document).vulnerabilities[0]

    assert vuln.pkg_name == "first"


def test_壊れたJSONは入力エラーになる(fixtures_dir):
    with pytest.raises(InputError, match="JSON として読み込めませんでした"):
        load_bom(fixtures_dir / "trivy_invalid.json")


def test_存在しないファイルは入力エラーになる(tmp_path):
    with pytest.raises(InputError, match="入力ファイルが見つかりません"):
        load_bom(tmp_path / "no-such-file.json")
