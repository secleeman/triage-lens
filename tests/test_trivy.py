import pytest

from triage_lens.errors import InputError
from triage_lens.trivy import extract_cvss, load_scan, parse_scan


def test_サンプルの全エントリが読み込まれる(fixtures_dir):
    scan = load_scan(fixtures_dir / "trivy_sample.json")

    assert scan.artifact_name == "sample-app:1.4.0"
    assert len(scan.vulnerabilities) == 13
    assert len({v.dedupe_key for v in scan.vulnerabilities}) == 13


def test_検出箇所が違う同一CVEは両方とも残す(fixtures_dir):
    """OSパッケージ側とアプリ依存側の両方を直す必要があるため、行を消さない。"""
    scan = load_scan(fixtures_dir / "trivy_sample.json")

    openssl = [v for v in scan.vulnerabilities if v.cve_id == "CVE-2014-0160"]

    assert len(openssl) == 2
    assert {v.target for v in openssl} == {
        "sample-app:1.4.0 (debian 12.5)",
        "app/requirements.txt",
    }


def test_同じ検出箇所の完全に同一な行だけ重複として除く():
    entry = {
        "VulnerabilityID": "CVE-2020-0001",
        "PkgName": "libdemo",
        "InstalledVersion": "1.0.0",
        "FixedVersion": "1.0.1",
    }
    document = {
        "Results": [{"Target": "demo (debian 12)", "Vulnerabilities": [entry, dict(entry)]}]
    }

    scan = parse_scan(document)

    assert len(scan.vulnerabilities) == 1


def test_同じCVEでもパッケージやバージョンが違えば残す():
    document = {
        "Results": [
            {
                "Target": "demo (debian 12)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2020-0001",
                        "PkgName": "libfoo",
                        "InstalledVersion": "1.0.0",
                    },
                    {
                        "VulnerabilityID": "CVE-2020-0001",
                        "PkgName": "libbar",
                        "InstalledVersion": "1.0.0",
                    },
                    {
                        "VulnerabilityID": "CVE-2020-0001",
                        "PkgName": "libfoo",
                        "InstalledVersion": "2.0.0",
                    },
                ],
            }
        ]
    }

    scan = parse_scan(document)

    assert len(scan.vulnerabilities) == 3


def test_検出箇所が無ければ不明として扱う():
    scan = parse_scan({"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2020-0001"}]}]})

    assert scan.vulnerabilities[0].target == "(検出箇所不明)"


def test_パッケージ情報が読み取れる(fixtures_dir):
    scan = load_scan(fixtures_dir / "trivy_sample.json")
    by_id = {v.cve_id: v for v in scan.vulnerabilities}

    log4j = by_id["CVE-2021-44228"]
    assert log4j.pkg_name == "log4j-core"
    assert log4j.installed_version == "2.14.1"
    assert log4j.fixed_version == "2.15.0"
    assert log4j.cvss == 10.0


def test_修正バージョンが無い場合はNoneになる(fixtures_dir):
    scan = load_scan(fixtures_dir / "trivy_sample.json")
    by_id = {v.cve_id: v for v in scan.vulnerabilities}

    assert by_id["CVE-2018-1000805"].fixed_version is None


@pytest.mark.parametrize(
    ("cve_id", "expected"),
    [
        ("CVE-2014-0160", 7.5),  # nvd の V3 を V2 より優先する
        ("CVE-2022-37434", 9.8),  # nvd が無ければ他ベンダの最大値
        ("CVE-2018-1000805", 6.4),  # V3 が無ければ V2
        ("CVE-2016-10735", None),  # CVSS 欄そのものが無い
    ],
)
def test_CVSSの選び方(fixtures_dir, cve_id, expected):
    scan = load_scan(fixtures_dir / "trivy_sample.json")
    by_id = {v.cve_id: v for v in scan.vulnerabilities}

    assert by_id[cve_id].cvss == expected


def test_検出ゼロのスキャンも読み込める(fixtures_dir):
    scan = load_scan(fixtures_dir / "trivy_empty.json")

    assert scan.artifact_name == "demo-service:0.2.0"
    assert scan.vulnerabilities == []


def test_壊れたJSONは入力エラーになる(fixtures_dir):
    with pytest.raises(InputError, match="JSON として読み込めませんでした"):
        load_scan(fixtures_dir / "trivy_invalid.json")


def test_Trivy以外のJSONは入力エラーになる(fixtures_dir):
    with pytest.raises(InputError, match="Trivy の JSON 出力ではないようです"):
        load_scan(fixtures_dir / "not_trivy.json")


def test_存在しないファイルは入力エラーになる(tmp_path):
    with pytest.raises(InputError, match="入力ファイルが見つかりません"):
        load_scan(tmp_path / "no-such-file.json")


@pytest.mark.parametrize("document", [[], "text", 42, None, {"Results": "x"}])
def test_想定外の構造は入力エラーになる(document):
    with pytest.raises(InputError):
        parse_scan(document)


def test_Resultsがnullでも空として扱う():
    scan = parse_scan({"ArtifactName": "demo-service", "Results": None})

    assert scan.vulnerabilities == []


def test_ID欠落や壊れたエントリは読み飛ばす():
    document = {
        "ArtifactName": "demo-service",
        "Results": [
            {"Vulnerabilities": [{"PkgName": "libfoo"}, "junk", {"VulnerabilityID": ""}]},
            {"Vulnerabilities": [{"VulnerabilityID": "CVE-2020-0001", "PkgName": "libbar"}]},
            "junk-result",
        ],
    }

    scan = parse_scan(document)

    assert [v.cve_id for v in scan.vulnerabilities] == ["CVE-2020-0001"]


def test_名称が無ければ不明として扱う():
    scan = parse_scan({"Results": []})

    assert scan.artifact_name == "(名称不明)"


def test_パッケージ名やバージョンが欠けていても落ちない():
    scan = parse_scan({"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2020-0001"}]}]})
    vuln = scan.vulnerabilities[0]

    assert vuln.pkg_name == "(不明)"
    assert vuln.installed_version == "(不明)"


@pytest.mark.parametrize(
    "cvss_field",
    [
        None,
        "high",
        {},
        {"nvd": "7.5"},
        {"nvd": {"V3Score": True}},  # bool はスコアとして扱わない
        {"nvd": {"V3Score": 42.0}},  # 0〜10 の範囲外は無視する
        {"nvd": {"V3Vector": "AV:N/AC:L"}},
    ],
)
def test_CVSSとして扱えない値はNoneになる(cvss_field):
    assert extract_cvss(cvss_field) is None


@pytest.mark.parametrize(
    "entries",
    [1, "text", {"VulnerabilityID": "CVE-2020-0001"}, 3.14, True],
)
def test_Vulnerabilitiesが一覧でなければ入力エラーになる(entries):
    """ネストした型の異常でも TypeError ではなく InputError にする。"""
    document = {"ArtifactName": "demo-service", "Results": [{"Vulnerabilities": entries}]}

    with pytest.raises(InputError, match="Vulnerabilities が一覧ではありません"):
        parse_scan(document)


def test_Resultsが辞書なら入力エラーになる():
    with pytest.raises(InputError, match="Results が一覧ではありません"):
        parse_scan({"Results": {"Target": "x"}})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_NaNや無限大はCVSSとして扱わない(value):
    assert extract_cvss({"nvd": {"V3Score": value}}) is None


def test_NaNの隣に正常な値があればそちらを使う():
    assert extract_cvss({"nvd": {"V3Score": float("nan")}, "ghsa": {"V3Score": 7.2}}) == 7.2


def test_テキストでないファイルは入力エラーになる(tmp_path):
    binary = tmp_path / "scan.json"
    binary.write_bytes(b"\xff\xfe\x00\x01binary")

    with pytest.raises(InputError, match="UTF-8 のテキストとして読み込めませんでした"):
        load_scan(binary)
