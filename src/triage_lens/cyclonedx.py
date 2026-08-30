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

#: `scope` の値のうち、開発・テストなど実行時に到達しない部品を表すもの。
#: `optional` は「実行時に任意」であって開発専用ではないため、ここには入れない
#: （npm は optionalDependencies にこの値を付ける）。
SCOPE_EXCLUDED = "excluded"

#: 開発依存であることを示す `properties[].name`。値が "true" のときだけ採用する。
#: 生成ツールごとの項目名の対応表であって、個別の事例に対する分岐ではない。
#: `scope` を使わずにこれで dev を表す生成ツールがあるため、両方を見る必要がある。
DEV_PROPERTY_NAMES = frozenset(
    {
        # npm 本体の `npm sbom --sbom-format cyclonedx`
        "cdx:npm:package:development",
    }
)

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
        scope_known = _scope_known(document)
        vulnerabilities = _collect_vulnerabilities(document, components, artifact_name)
    except InputError:
        raise
    except Exception as exc:  # 想定外の構造でもスタックトレースは出さない
        raise InputError(
            f"CycloneDX の構造が想定と異なります（{type(exc).__name__}: {exc}）。"
            "SBOM のファイルが壊れていないか確認してください。"
        ) from exc

    return ScanInput(
        artifact_name=artifact_name,
        vulnerabilities=vulnerabilities,
        scope_known=scope_known,
    )


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
    for component in _iter_components(document):
        ref = as_optional_text(component.get("bom-ref"))
        # 同じ bom-ref が重複していたら最初のものを採用する（仕様上は一意）
        if ref and ref not in index:
            index[ref] = component
    return index


def _iter_components(document: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """SBOM に載っている component を、入れ子も含めて順に返す。

    `metadata.component`（スキャン対象そのもの）も含む。脆弱性から参照されうるため。
    """
    metadata = document.get("metadata")
    if isinstance(metadata, dict):
        yield from _walk_component(metadata.get("component"), depth=0)
    yield from _iter_dependency_components(document)


def _iter_dependency_components(document: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """`components[]` 配下の component だけを、入れ子も含めて順に返す。

    `metadata.component` を含めない。あれはスキャン対象そのものであって依存ではなく、
    そこに書かれた `scope` は依存の区別について何も語らないため。
    """
    yield from _walk_components(document.get("components"), depth=0)


def _walk_components(components: Any, *, depth: int) -> Iterator[dict[str, Any]]:
    """入れ子の階層でも型を検証する（浅い階層だけ厳しくしても意味がないため）。"""
    if components is None or depth > MAX_COMPONENT_DEPTH:
        return
    if not isinstance(components, list):
        raise InputError(_COMPONENTS_NOT_LIST_MESSAGE)
    for component in components:
        yield from _walk_component(component, depth=depth)


def _walk_component(component: Any, *, depth: int) -> Iterator[dict[str, Any]]:
    if not isinstance(component, dict) or depth > MAX_COMPONENT_DEPTH:
        return
    yield component
    yield from _walk_components(component.get("components"), depth=depth + 1)


def _scope_known(document: dict[str, Any]) -> bool:
    """入力が本番依存 / 開発依存を区別できるか。

    `scope` は省略時に `required` とみなす仕様なので、何も書かれていない SBOM を
    素直に読むと「全件が本番依存」に見えてしまう。**明示的に書かれた材料が1つも
    無ければ「区別できない」** とし、区別できているかのように見せない。

    見るのは `components[]` 配下だけで、`metadata.component` は見ない。あれは
    スキャン対象そのもので、そこに `scope: required` と書かれていても依存の区別に
    ついては何も分からない。含めてしまうと、材料が無いのに「区別できた（全件が
    本番依存）」というレポートを出してしまう。

    索引（`_index_components`）ではなく SBOM をたどり直すのは、`bom-ref` を持たない
    component にも判別の材料が書かれていることがあるため。
    """
    return any(_has_scope_signal(component) for component in _iter_dependency_components(document))


def _has_scope_signal(component: dict[str, Any]) -> bool:
    """この component に、本番 / 開発を判別する材料が明示されているか。"""
    if as_optional_text(component.get("scope")) is not None:
        return True
    return _has_dev_property(component)


def _is_dev_only(component: dict[str, Any]) -> bool:
    """開発時にしか使われない依存か。判別できないものは本番依存に倒す。

    `properties` を先に見るのは、`scope` を使わずに properties だけで dev を表す
    生成ツールがあるため（npm 本体の `npm sbom` など）。
    """
    if _has_dev_property(component):
        return True
    scope = as_optional_text(component.get("scope"))
    return scope is not None and scope.strip().lower() == SCOPE_EXCLUDED


def _has_dev_property(component: dict[str, Any]) -> bool:
    """`properties[]` に「開発依存」を示す項目があるか。"""
    properties = component.get("properties")
    if not isinstance(properties, list):
        return False
    for item in properties:
        if not isinstance(item, dict):
            continue
        name = as_optional_text(item.get("name"))
        value = as_optional_text(item.get("value"))
        if name in DEV_PROPERTY_NAMES and value is not None and value.strip().lower() == "true":
            return True
    return False


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
        # SBOM に載っていない部品を参照している検出は、component が空になるため
        # 本番依存として扱われる。判別できないものを開発側に寄せない。
        dev_only=_is_dev_only(component),
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
