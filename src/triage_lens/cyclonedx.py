"""CycloneDX 形式（JSON）の SBOM を読み込む。

対象は CycloneDX 1.4 以降の JSON 表現（脆弱性情報 `vulnerabilities` が
仕様に入ったのが 1.4 のため）。XML 表現は対象外。

triage-lens は脆弱性を検出しない。`components` しか持たない純粋な部品表は
「脆弱性0件」として扱う。
"""

from collections.abc import Iterator
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

#: CycloneDX の JSON が名乗る形式名
BOM_FORMAT = "CycloneDX"

#: `components` の入れ子をたどる深さの上限（壊れた入力での無限再帰よけ）
MAX_COMPONENT_DEPTH = 20

#: `ratings[].method` の値。現行世代（v3系 / v4）を先に見て、無ければ v2 を見る。
#: 世代の違うスコアを混ぜて最大値を取ると、実態より高い深刻度になってしまう。
RATING_METHOD_GROUPS: tuple[tuple[str, ...], ...] = (
    ("cvssv4", "cvssv31", "cvssv3"),
    ("cvssv2",),
)

_COMPONENTS_NOT_LIST_MESSAGE = (
    "CycloneDX の形式が想定と異なります（components が一覧ではありません）。"
    "`trivy image --format cyclonedx` の出力をそのまま指定してください。"
)

_UNSUPPORTED_FORMAT_MESSAGE = (
    "CycloneDX 形式（JSON）ではないようです。"
    "`bomFormat` が `CycloneDX` の JSON ファイルを指定してください。"
)


def looks_like_cyclonedx(document: Any) -> bool:
    """CycloneDX の JSON かどうかを判定する。

    仕様上 `bomFormat` の値は `CycloneDX` ちょうどなので、厳密に一致させる。
    大文字小文字や前後の空白を許すと、`Results` を持つ Trivy 出力が
    CycloneDX と誤判定され、検出結果が黙って0件になってしまう。
    """
    if not isinstance(document, dict):
        return False
    return document.get("bomFormat") == BOM_FORMAT


def load_bom(path: str | Path) -> ScanInput:
    """CycloneDX の JSON ファイルを読み込んで `ScanInput` を返す。"""
    return parse_bom(read_json_document(path))


def parse_bom(document: Any) -> ScanInput:
    """パース済みの CycloneDX JSON（辞書）から脆弱性一覧を取り出す。

    どんな構造の入力を渡されても、送出するのは `InputError` だけにする。
    """
    if not looks_like_cyclonedx(document):
        raise InputError(_UNSUPPORTED_FORMAT_MESSAGE)

    artifact_name = _artifact_name(document)
    try:
        components = _index_components(document)
        vulnerabilities = _collect_vulnerabilities(document, components, artifact_name)
    except InputError:
        raise
    except Exception as exc:  # 想定外の構造でもスタックトレースは出さない
        raise InputError(
            f"CycloneDX の構造が想定と異なります（{type(exc).__name__}: {exc}）。"
            "SBOM のファイルが壊れていないか確認してください。"
        ) from exc

    return ScanInput(artifact_name=artifact_name, vulnerabilities=vulnerabilities)


def _artifact_name(document: Any) -> str:
    """レポートの対象名。`metadata.component` から作る。"""
    metadata = document.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict):
        return UNKNOWN_NAME

    name = as_optional_text(component.get("name"))
    if name:
        version = as_optional_text(component.get("version"))
        return f"{name}@{version}" if version else name
    return as_optional_text(component.get("purl")) or UNKNOWN_NAME


def _index_components(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """`bom-ref` から component を引けるようにする。

    `components` は入れ子にできる仕様なので、たどれる範囲をすべて対象にする。
    `metadata.component` 自身も参照されうるため索引に含める。
    """
    index: dict[str, dict[str, Any]] = {}

    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        _add_component(index, metadata.get("component"), depth=0)

    _add_components(index, document.get("components"), depth=0)
    return index


def _add_components(index: dict[str, dict[str, Any]], components: Any, *, depth: int) -> None:
    """入れ子の階層でも型を検証する（浅い階層だけ厳しくしても意味がないため）。"""
    if components is None or depth > MAX_COMPONENT_DEPTH:
        return
    if not isinstance(components, list):
        raise InputError(_COMPONENTS_NOT_LIST_MESSAGE)
    for component in components:
        _add_component(index, component, depth=depth)


def _add_component(index: dict[str, dict[str, Any]], component: Any, *, depth: int) -> None:
    if not isinstance(component, dict) or depth > MAX_COMPONENT_DEPTH:
        return
    ref = as_optional_text(component.get("bom-ref"))
    # 同じ bom-ref が重複していたら最初のものを採用する（仕様上は一意）
    if ref and ref not in index:
        index[ref] = component
    _add_components(index, component.get("components"), depth=depth + 1)


def _collect_vulnerabilities(
    document: dict[str, Any],
    components: dict[str, dict[str, Any]],
    artifact_name: str,
) -> list[Vulnerability]:
    entries = document.get("vulnerabilities")
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise InputError(
            "CycloneDX の形式が想定と異なります（vulnerabilities が一覧ではありません）。"
            "`trivy image --format cyclonedx` の出力をそのまま指定してください。"
        )

    vulnerabilities: list[Vulnerability] = []
    for index, entry in enumerate(entries):
        vulnerabilities += _parse_vulnerability(entry, index, components, artifact_name)
    return deduplicate(vulnerabilities)


def _parse_vulnerability(
    entry: Any,
    index: int,
    components: dict[str, dict[str, Any]],
    artifact_name: str,
) -> list[Vulnerability]:
    """1件の `vulnerabilities` エントリを、影響を受ける部品ごとの行に展開する。"""
    if not isinstance(entry, dict):
        return []
    cve_id = as_optional_text(entry.get("id"))
    if not cve_id:
        return []

    affects = entry.get("affects")
    if affects is None:
        affects = []
    if not isinstance(affects, list):
        raise InputError(
            "CycloneDX の形式が想定と異なります"
            f"（vulnerabilities[{index}].affects が一覧ではありません）。"
            "`trivy image --format cyclonedx` の出力をそのまま指定してください。"
        )

    cvss = extract_cvss(entry.get("ratings"))
    rows = [
        _build_vulnerability(cve_id, cvss, affect, components, artifact_name)
        for affect in affects
        if isinstance(affect, dict)
    ]
    if rows:
        return rows
    # 影響先が書かれていなくても、CVE ID が読めていれば1行として残す
    return [_build_vulnerability(cve_id, cvss, {}, components, artifact_name)]


def _build_vulnerability(
    cve_id: str,
    cvss: float | None,
    affect: dict[str, Any],
    components: dict[str, dict[str, Any]],
    artifact_name: str,
) -> Vulnerability:
    ref = as_optional_text(affect.get("ref"))
    component = components.get(ref) if ref else None
    if not isinstance(component, dict):
        component = {}

    installed = as_optional_text(component.get("version")) or _affected_version(affect)
    fixed = _fixed_version(affect)

    return Vulnerability(
        cve_id=cve_id,
        pkg_name=as_text(component.get("name"), UNKNOWN_VALUE),
        installed_version=installed or UNKNOWN_VALUE,
        fixed_version=fixed,
        cvss=cvss,
        target=_target(component, ref, artifact_name),
        # CycloneDX には「修正版が存在しない」ことを明示する項目が無い。
        # 読み取れなかったときは「修正版なし」と断定せず「不明」と表示する。
        fixed_version_known=fixed is not None,
    )


def _target(component: dict[str, Any], ref: str | None, artifact_name: str) -> str:
    """検出箇所。部品を特定できる文字列を優先する。"""
    purl = as_optional_text(component.get("purl"))
    if purl:
        return purl
    if ref:
        return ref
    return artifact_name if artifact_name != UNKNOWN_NAME else UNKNOWN_TARGET


def _version_entries(affect: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """`affects[].versions[]` を `(バージョン表記, 状態)` として順に返す。"""
    versions = affect.get("versions")
    if not isinstance(versions, list):
        return
    for item in versions:
        if not isinstance(item, dict):
            continue
        value = as_optional_text(item.get("version")) or as_optional_text(item.get("range"))
        if not value:
            continue
        status = item.get("status")
        yield value, status.strip().lower() if isinstance(status, str) else ""


def _affected_version(affect: dict[str, Any]) -> str | None:
    """影響を受けているバージョン。状態の記載が無い場合は affected とみなす（仕様の既定値）。"""
    for value, status in _version_entries(affect):
        if status in ("", "affected"):
            return value
    return None


def _fixed_version(affect: dict[str, Any]) -> str | None:
    """修正済みバージョン。`status: unaffected` のエントリだけを採用する。

    `unaffected` は「その版は影響を受けない」という意味でしかなく、修正版とは限らない。
    脆弱性が入る前の古い版も `unaffected` になりうるため、複数ある場合はどれが修正版か
    決められない。その場合は修正版を断定せず「不明」として扱う
    （古い版へのダウングレードを修正版として案内しないため）。
    """
    unaffected = [value for value, status in _version_entries(affect) if status == "unaffected"]
    return unaffected[0] if len(unaffected) == 1 else None


def extract_cvss(ratings: Any) -> float | None:
    """`ratings[]` から CVSS スコアを1つ選ぶ。

    現行世代（CVSSv3 / CVSSv31 / CVSSv4）を優先し、無ければ CVSSv2 を使う。
    同じ世代に複数あれば `source.name` に nvd を含むものを優先し、
    それも無ければ最大値を取る。

    `method` が無い、または CVSS 以外（OWASP / SSVC / other）のスコアは
    CVSS として扱わない。深刻度の尺度が違うものを CVSS 欄に出すと誤解を招くため。
    """
    if not isinstance(ratings, list):
        return None

    scored: list[tuple[str, float, bool]] = []
    for rating in ratings:
        if not isinstance(rating, dict):
            continue
        score = as_cvss_score(rating.get("score"))
        if score is None:
            continue
        method = rating.get("method")
        method = method.strip().lower() if isinstance(method, str) else ""
        scored.append((method, score, _is_nvd(rating.get("source"))))

    for group in RATING_METHOD_GROUPS:
        candidates = [(score, nvd) for method, score, nvd in scored if method in group]
        if not candidates:
            continue
        from_nvd = [score for score, nvd in candidates if nvd]
        return max(from_nvd) if from_nvd else max(score for score, _ in candidates)

    return None


def _is_nvd(source: Any) -> bool:
    if not isinstance(source, dict):
        return False
    name = source.get("name")
    return isinstance(name, str) and "nvd" in name.lower()
