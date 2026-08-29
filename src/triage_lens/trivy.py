"""Trivy の JSON 出力（`--format json`）を読み込む。"""

from pathlib import Path
from typing import Any

from .errors import InputError
from .models import UNKNOWN_NAME, UNKNOWN_TARGET, UNKNOWN_VALUE, ScanInput, Vulnerability
from .parsing import (
    as_cvss_score,
    as_optional_text,
    as_text,
    deduplicate,
    read_json_document,
)

_UNSUPPORTED_FORMAT_MESSAGE = (
    "Trivy の JSON 出力ではないようです。"
    "`trivy image --format json -o result.json` で出力したファイルを指定してください。"
)


def looks_like_trivy(document: Any) -> bool:
    """Trivy の JSON 出力かどうかを判定する。"""
    return isinstance(document, dict) and "Results" in document


def load_scan(path: str | Path) -> ScanInput:
    """Trivy の JSON ファイルを読み込んで `ScanInput` を返す。

    読めない・想定形式でない場合は `InputError` を送出する。
    形式を判別して読みたい場合は `loader.load_scan` を使う。
    """
    return parse_scan(read_json_document(path))


def parse_scan(document: Any) -> ScanInput:
    """パース済みの Trivy JSON（辞書）から脆弱性一覧を取り出す。

    どんな構造の入力を渡されても、送出するのは `InputError` だけにする
    （利用者にスタックトレースを見せないため）。
    """
    if not looks_like_trivy(document):
        raise InputError(_UNSUPPORTED_FORMAT_MESSAGE)

    results = document.get("Results") or []
    if not isinstance(results, list):
        raise InputError(f"{_UNSUPPORTED_FORMAT_MESSAGE}（Results が一覧ではありません）")

    artifact_name = as_text(document.get("ArtifactName"), UNKNOWN_NAME)

    try:
        vulnerabilities = _collect_vulnerabilities(results)
    except InputError:
        raise
    except Exception as exc:  # 想定外の構造でもスタックトレースは出さない
        raise InputError(
            f"Trivy の JSON 出力の構造が想定と異なります（{type(exc).__name__}: {exc}）。"
            "スキャン結果のファイルが壊れていないか確認してください。"
        ) from exc

    return ScanInput(artifact_name=artifact_name, vulnerabilities=vulnerabilities)


def _collect_vulnerabilities(results: list[Any]) -> list[Vulnerability]:
    vulnerabilities: list[Vulnerability] = []

    for index, result in enumerate(results):
        if not isinstance(result, dict):
            continue

        entries = result.get("Vulnerabilities")
        if entries is None:
            continue
        if not isinstance(entries, list):
            raise InputError(
                "Trivy の JSON 出力の形式が想定と異なります"
                f"（Results[{index}].Vulnerabilities が一覧ではありません）。"
                "`trivy image --format json` の出力をそのまま指定してください。"
            )

        target = as_text(result.get("Target"), UNKNOWN_TARGET)
        for entry in entries:
            vuln = _parse_vulnerability(entry, target)
            if vuln is not None:
                vulnerabilities.append(vuln)

    return deduplicate(vulnerabilities)


def _parse_vulnerability(entry: Any, target: str) -> Vulnerability | None:
    if not isinstance(entry, dict):
        return None
    cve_id = entry.get("VulnerabilityID")
    if not isinstance(cve_id, str) or not cve_id:
        return None

    return Vulnerability(
        cve_id=cve_id,
        pkg_name=as_text(entry.get("PkgName"), UNKNOWN_VALUE),
        installed_version=as_text(entry.get("InstalledVersion"), UNKNOWN_VALUE),
        fixed_version=as_optional_text(entry.get("FixedVersion")),
        cvss=extract_cvss(entry.get("CVSS")),
        target=target,
        # Trivy は修正版が無いときに FixedVersion を省略する。
        # 「書かれていない＝修正版なし」と読んでよい。
        fixed_version_known=True,
    )


def extract_cvss(cvss_field: Any) -> float | None:
    """Trivy の CVSS 欄からスコアを1つ選ぶ。

    NVD を優先し、無ければ他ベンダの V3 スコアの最大値、
    それも無ければ V2 スコアの最大値を使う。どれも無ければ None。
    """
    if not isinstance(cvss_field, dict):
        return None

    for score_key in ("V3Score", "V2Score"):
        nvd = cvss_field.get("nvd")
        if isinstance(nvd, dict):
            score = as_cvss_score(nvd.get(score_key))
            if score is not None:
                return score

        scores = [
            score
            for vendor in cvss_field.values()
            if isinstance(vendor, dict)
            for score in [as_cvss_score(vendor.get(score_key))]
            if score is not None
        ]
        if scores:
            return max(scores)

    return None
