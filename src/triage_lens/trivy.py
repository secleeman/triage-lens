"""Trivy の JSON 出力（`--format json`）を読み込む。"""

import json
import math
from pathlib import Path
from typing import Any

from .errors import InputError
from .models import ScanInput, Vulnerability

_UNSUPPORTED_FORMAT_MESSAGE = (
    "Trivy の JSON 出力ではないようです。"
    "`trivy image --format json -o result.json` で出力したファイルを指定してください。"
)


def load_scan(path: str | Path) -> ScanInput:
    """Trivy の JSON ファイルを読み込んで `ScanInput` を返す。

    読めない・想定形式でない場合は `InputError` を送出する。
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InputError(f"入力ファイルが見つかりません: {path}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(
            f"入力ファイルを UTF-8 のテキストとして読み込めませんでした: {path}"
            "（テキストではないファイルを指定していませんか）"
        ) from exc
    except OSError as exc:
        raise InputError(f"入力ファイルを読み込めませんでした: {path} ({exc})") from exc

    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputError(
            f"JSON として読み込めませんでした: {path} （{exc.msg} / {exc.lineno}行目）"
        ) from exc

    return parse_scan(document)


def parse_scan(document: Any) -> ScanInput:
    """パース済みの Trivy JSON（辞書）から脆弱性一覧を取り出す。

    どんな構造の入力を渡されても、送出するのは `InputError` だけにする
    （利用者にスタックトレースを見せないため）。
    """
    if not isinstance(document, dict) or "Results" not in document:
        raise InputError(_UNSUPPORTED_FORMAT_MESSAGE)

    results = document.get("Results") or []
    if not isinstance(results, list):
        raise InputError(f"{_UNSUPPORTED_FORMAT_MESSAGE}（Results が一覧ではありません）")

    artifact_name = document.get("ArtifactName")
    if not isinstance(artifact_name, str) or not artifact_name:
        artifact_name = "(名称不明)"

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
    seen: set[tuple[str, str, str, str]] = set()

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

        target = _as_text(result.get("Target"), "(検出箇所不明)")
        for entry in entries:
            vuln = _parse_vulnerability(entry, target)
            if vuln is None or vuln.dedupe_key in seen:
                continue
            seen.add(vuln.dedupe_key)
            vulnerabilities.append(vuln)

    return vulnerabilities


def _parse_vulnerability(entry: Any, target: str) -> Vulnerability | None:
    if not isinstance(entry, dict):
        return None
    cve_id = entry.get("VulnerabilityID")
    if not isinstance(cve_id, str) or not cve_id:
        return None

    return Vulnerability(
        cve_id=cve_id,
        pkg_name=_as_text(entry.get("PkgName"), "(不明)"),
        installed_version=_as_text(entry.get("InstalledVersion"), "(不明)"),
        fixed_version=_as_optional_text(entry.get("FixedVersion")),
        cvss=extract_cvss(entry.get("CVSS")),
        target=target,
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
            score = _as_score(nvd.get(score_key))
            if score is not None:
                return score

        scores = [
            score
            for vendor in cvss_field.values()
            if isinstance(vendor, dict)
            for score in [_as_score(vendor.get(score_key))]
            if score is not None
        ]
        if scores:
            return max(scores)

    return None


def _as_score(value: Any) -> float | None:
    """CVSS スコアとして妥当な値だけを返す（NaN / 無限大 / 範囲外は無効）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    score = float(value)
    if not math.isfinite(score) or score < 0.0 or score > 10.0:
        return None
    return score


def _as_text(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


def _as_optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None
