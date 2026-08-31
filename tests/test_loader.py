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


def test_SPDXの出力をSPDXとして読む(fixtures_dir):
    scan = load_scan(fixtures_dir / "spdx_sample.json")

    assert scan.artifact_name == "sample-app@1.4.0"
    assert len(scan.vulnerabilities) == 4


def test_部品表だけのSPDXも読める(fixtures_dir):
    """読めたうえで「部品表だけだった」と分かる状態にする（0件を安全と読ませない）。"""
    scan = load_scan(fixtures_dir / "spdx_sbom_only.json")

    assert scan.vulnerabilities == []
    assert scan.sbom_only is True


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


def test_未対応形式のエラー文にすべての形式を書く(fixtures_dir):
    """SPDX を渡して落ちた利用者が、対応していないのかどうかを判断できるようにする。"""
    with pytest.raises(InputError) as excinfo:
        load_scan(fixtures_dir / "unsupported.json")

    message = str(excinfo.value)
    assert "CycloneDX / SPDX 形式（JSON）でもありません" in message
    assert "--format json" in message
    assert "--format cyclonedx" in message
    assert "--format spdx-json" in message


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


# --------------------------------------------------------------------------
# Trivy が Results をキーごと省く場合
#
# Report 構造体の Results には `json:",omitempty"` が付いているため、
# 検出0件のとき Trivy は Results を出力しない。`Results` の有無だけで
# 形式を判定すると、正当な出力を「Trivy の出力ではない」と拒否してしまう。
# --------------------------------------------------------------------------


def test_Resultsが無いTrivy出力を読める(fixtures_dir):
    """実物の `trivy fs --format json` 出力（検出0件）を読めること。"""
    scan = load_scan(fixtures_dir / "trivy_no_results.json")

    assert scan.artifact_name == "."
    assert scan.vulnerabilities == []


def test_Resultsが無ければ対象を認識できていないと分かる(fixtures_dir):
    """0件を「安全」と読ませないための材料を立てる。"""
    scan = load_scan(fixtures_dir / "trivy_no_results.json")

    assert scan.no_targets is True


def test_Resultsが空でも対象を認識できていないと分かる(fixtures_dir):
    """キーが無い場合と空の場合で意味は同じ。扱いも揃える。"""
    scan = load_scan(fixtures_dir / "trivy_empty.json")

    assert scan.no_targets is True


def test_対象を認識したうえで0件ならno_targetsにしない():
    """スキャン対象は見つかっていて脆弱性が無いのは、素直に良い結果。

    ここで注記を出すと、本当に見直すべき入力の注記が埋もれる。
    """
    document = {
        "SchemaVersion": 2,
        "ArtifactName": "demo-service:0.2.0",
        "ArtifactType": "container_image",
        "Results": [{"Target": "demo-service:0.2.0 (alpine 3.19)", "Vulnerabilities": []}],
    }

    scan = parse_document(document)

    assert scan.vulnerabilities == []
    assert scan.no_targets is False


def test_検出があればno_targetsにしない(fixtures_dir):
    scan = load_scan(fixtures_dir / "trivy_sample.json")

    assert scan.no_targets is False


def test_Trivy固有のキーが少なすぎれば入力エラーにする():
    """`SchemaVersion` だけのような入力まで Trivy と見なさない。"""
    with pytest.raises(InputError, match="Trivy の JSON 出力ではないようです"):
        parse_document({"SchemaVersion": 2})


def test_Resultsがあれば従来どおり1つで判定する():
    """`Results` だけを持つ最小の入力は、これまでどおり Trivy として読む。"""
    document = {"Results": [{"Target": "demo", "Vulnerabilities": []}]}

    scan = parse_document(document)

    assert scan.vulnerabilities == []
