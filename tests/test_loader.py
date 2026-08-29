"""入力形式の自動判別の検証。"""

import pytest

from triage_lens.errors import InputError
from triage_lens.loader import load_scan, parse_document


def test_Trivyの出力をTrivyとして読む(fixtures_dir):
    scan = load_scan(fixtures_dir / "trivy_sample.json")

    assert scan.artifact_name == "sample-app:1.4.0"
    assert len(scan.vulnerabilities) == 13


def test_CycloneDXの出力をCycloneDXとして読む(fixtures_dir):
    scan = load_scan(fixtures_dir / "cyclonedx_sample.json")

    assert scan.artifact_name == "sample-app@1.4.0"
    assert len(scan.vulnerabilities) == 9


def test_脆弱性が無いCycloneDXも読める(fixtures_dir):
    scan = load_scan(fixtures_dir / "cyclonedx_empty.json")

    assert scan.vulnerabilities == []


def test_検出ゼロのTrivy出力も読める(fixtures_dir):
    scan = load_scan(fixtures_dir / "trivy_empty.json")

    assert scan.artifact_name == "demo-service:0.2.0"
    assert scan.vulnerabilities == []


def test_CycloneDXの判定をTrivyより先に行う():
    """両方の特徴を持つ入力でも挙動が一意になることを確かめる。"""
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "Results": [],
        "vulnerabilities": [],
    }

    scan = parse_document(document)

    assert scan.artifact_name == "(名称不明)"
    assert scan.vulnerabilities == []


def test_bomFormatの表記ゆれでTrivy出力を取りこぼさない():
    """`bomFormat` が仕様どおりでなければ CycloneDX として扱わない。

    誤判定すると `vulnerabilities` が無いぶん検出0件になり、
    実在する脆弱性を黙って見落とす。
    """
    document = {
        "bomFormat": " cyclonedx ",
        "Results": [
            {
                "Target": "demo",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2099-0001", "CVSS": {"nvd": {"V3Score": 9.8}}}
                ],
            }
        ],
    }

    scan = parse_document(document)

    assert [v.cve_id for v in scan.vulnerabilities] == ["CVE-2099-0001"]
    assert scan.vulnerabilities[0].cvss == 9.8


@pytest.mark.parametrize(
    "document",
    [
        {"name": "demo-service", "dependencies": {}},
        {"spdxVersion": "SPDX-2.3", "packages": []},
        {"bomFormat": "SPDX"},
        [],
        "text",
        42,
        None,
    ],
)
def test_どちらの形式でもなければ入力エラー(document):
    with pytest.raises(InputError, match="Trivy の JSON 出力ではないようです"):
        parse_document(document)


def test_未対応形式のエラー文に両方の形式を書く(fixtures_dir):
    with pytest.raises(InputError) as excinfo:
        load_scan(fixtures_dir / "unsupported.json")

    message = str(excinfo.value)
    assert "CycloneDX 形式（JSON）でもありません" in message
    assert "--format json" in message
    assert "--format cyclonedx" in message


def test_壊れたJSONは入力エラーになる(fixtures_dir):
    with pytest.raises(InputError, match="JSON として読み込めませんでした"):
        load_scan(fixtures_dir / "trivy_invalid.json")


def test_存在しないファイルは入力エラーになる(tmp_path):
    with pytest.raises(InputError, match="入力ファイルが見つかりません"):
        load_scan(tmp_path / "no-such-file.json")


def test_入れ子が深すぎるJSONはトレースバックを出さず入力エラーになる(tmp_path):
    """壊れた入力で RecursionError が利用者に漏れないことを確かめる。"""
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 50000 + "0" + "]" * 50000, encoding="utf-8")

    with pytest.raises(InputError, match="入れ子が深すぎて読み込めませんでした"):
        load_scan(deep)


def test_テキストでないファイルは入力エラーになる(tmp_path):
    binary = tmp_path / "scan.json"
    binary.write_bytes(b"\xff\xfe\x00\x01binary")

    with pytest.raises(InputError, match="UTF-8 のテキストとして読み込めませんでした"):
        load_scan(binary)
