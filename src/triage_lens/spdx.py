"""SPDX 形式（JSON）の SBOM を読み込む。

対象は SPDX 2.2 / 2.3 の JSON 表現。tag-value / RDF / YAML の表現と SPDX 3.x は対象外。

**SPDX 2.x は部品表であって脆弱性の一覧ではない。** CycloneDX の `vulnerabilities[]` に
あたる項目が仕様に無く、CVE を書ける場所は `packages[].externalRefs[]` の SECURITY 参照
だけ（しかも `advisory` / `fix` / `url` が使えるのは 2.3 から）。実際に出回る SBOM の
ほとんどはここに何も持たないため、**素直に読むと検出0件になる。**

0件が「脆弱性が無い」ではなく「判定する材料が無い」ことを示すため、脆弱性を1件も
取り出せなかった入力には `ScanInput.sbom_only` を立てて呼び出し側に伝える。
"""

import re
from pathlib import Path
from typing import Any

from .errors import InputError
from .models import UNKNOWN_NAME, UNKNOWN_TARGET, UNKNOWN_VALUE, ScanInput, Vulnerability
from .parsing import as_optional_text, as_text, deduplicate, read_json_document

#: `spdxVersion` の接頭辞（`SPDX-2.3` の `SPDX-`）
VERSION_PREFIX = "SPDX-"

#: 読み込む SPDX の版。2.2 は CVE を書く場所が無いが、対象名と依存の区別は取れるため読む。
SUPPORTED_VERSIONS = frozenset({(2, 2), (2, 3)})

#: 脆弱性を指す外部参照。`referenceCategory` がこれのものだけを見る。
SECURITY_CATEGORY = "SECURITY"

#: SECURITY 参照のうち、CVE を書きうる `referenceType`。
#: `cpe22Type` / `cpe23Type` は入れない。CPE は製品の識別子であって脆弱性ではなく、
#: そこから CVE を引くには別のデータ源が要る（CLAUDE.md 4）。
SECURITY_REFERENCE_TYPES = frozenset({"advisory", "fix", "url"})

#: 部品を特定できる外部参照（検出箇所に使う）
PACKAGE_MANAGER_CATEGORY = "PACKAGE-MANAGER"
PURL_REFERENCE_TYPE = "purl"

#: 参照から CVE ID を取り出す。`https://nvd.nist.gov/vuln/detail/CVE-2020-28498` のような
#: URL が仕様の例に載っている。番号の桁数は年によって変わるため下限だけを決める。
#: 前後を語境界で挟むのは、`XCVE-2020-0001` のような文字列から偽の検出を作らないため。
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

#: 開発時にしか使われない依存を表す関係。
#: `A DEV_DEPENDENCY_OF B` は「A が B の開発依存」で、開発依存なのは A（`spdxElementId`）。
DEV_RELATIONSHIP_TYPES = frozenset({"DEV_DEPENDENCY_OF", "TEST_DEPENDENCY_OF"})

#: 実行時に使われる依存だと**明示した**関係。
#: `BUILD_DEPENDENCY_OF` をここに入れるのは、ビルド依存が生成物にコードを混ぜうるため。
#: 迷ったら本番依存に倒す（Phase 6 と同じ方針。開発側に寄せると見落としになる）。
RUNTIME_RELATIONSHIP_TYPES = frozenset(
    {
        "RUNTIME_DEPENDENCY_OF",
        "BUILD_DEPENDENCY_OF",
        "OPTIONAL_DEPENDENCY_OF",
        "PROVIDED_DEPENDENCY_OF",
    }
)

#: 本番 / 開発を語る関係。1件でもあれば、その入力は区別できるとみなす。
#: `DEPENDENCY_OF` と `DEPENDS_ON` は**入れない**。どちらも依存関係があることしか
#: 言っておらず、スコープについては何も語らないため。これらしか無い SBOM を
#: 「区別できた（全件が本番依存）」と出すのは、材料が無いのに区別したふりをすること。
SCOPE_RELATIONSHIP_TYPES = DEV_RELATIONSHIP_TYPES | RUNTIME_RELATIONSHIP_TYPES

_UNSUPPORTED_FORMAT_MESSAGE = (
    "SPDX 形式（JSON）ではないようです。`spdxVersion` を持つ JSON ファイルを指定してください。"
)

_SPDX3_MESSAGE = (
    "SPDX 3.x には対応していません（対応しているのは SPDX 2.2 / 2.3 の JSON です）。"
    "`trivy image --format spdx-json -o sbom.spdx.json` のように "
    "SPDX 2.x で出力し直したファイルを指定してください。"
)

_PACKAGES_NOT_LIST_MESSAGE = (
    "SPDX の形式が想定と異なります（packages が一覧ではありません）。"
    "`trivy image --format spdx-json` の出力をそのまま指定してください。"
)

_RELATIONSHIPS_NOT_LIST_MESSAGE = (
    "SPDX の形式が想定と異なります（relationships が一覧ではありません）。"
    "`trivy image --format spdx-json` の出力をそのまま指定してください。"
)


def looks_like_spdx(document: Any) -> bool:
    """SPDX の JSON かどうかを判定する。

    SPDX 3.x（`spdxVersion` を持たない JSON-LD）も真にする。未対応であることを
    名指しで伝えるため。「Trivy でも CycloneDX でもない」と言われるより、
    利用者が次に何をすればよいか分かる。
    """
    if not isinstance(document, dict):
        return False
    if isinstance(document.get("spdxVersion"), str):
        return True
    return _looks_like_spdx3(document)


def _looks_like_spdx3(document: dict[str, Any]) -> bool:
    """SPDX 3.x の JSON-LD か。文脈の URL が spdx.org を指していることで見分ける。"""
    context = document.get("@context")
    return context is not None and "spdx.org" in str(context)


def load_sbom(path: str | Path) -> ScanInput:
    """SPDX の JSON ファイルを読み込んで `ScanInput` を返す。"""
    return parse_sbom(read_json_document(path))


def parse_sbom(document: Any) -> ScanInput:
    """パース済みの SPDX JSON（辞書）から脆弱性一覧を取り出す。

    どんな構造の入力を渡されても、送出するのは `InputError` だけにする
    （利用者にスタックトレースを見せないため）。
    """
    if not looks_like_spdx(document):
        raise InputError(_UNSUPPORTED_FORMAT_MESSAGE)
    _check_version(document)

    artifact_name = as_text(document.get("name"), UNKNOWN_NAME)
    try:
        packages = _packages(document)
        dev_ids, scope_known = _dependency_scopes(document, _package_ids(packages))
        vulnerabilities = _collect_vulnerabilities(packages, dev_ids, artifact_name)
    except InputError:
        raise
    except Exception as exc:  # 想定外の構造でもスタックトレースは出さない
        raise InputError(
            f"SPDX の構造が想定と異なります（{type(exc).__name__}: {exc}）。"
            "SBOM のファイルが壊れていないか確認してください。"
        ) from exc

    return ScanInput(
        artifact_name=artifact_name,
        vulnerabilities=vulnerabilities,
        scope_known=scope_known,
        # SPDX の関係は「開発依存である」と明示した記述で、CycloneDX の `scope` のような
        # 「省略時は本番」という既定値の規則が無い。`scope` の揺れを断る注記は
        # SPDX には当てはまらないため、根拠が明示的であることを立てて抑止する。
        dev_property_used=scope_known,
        # 脆弱性を1件も取り出せなかったことを呼び出し側へ伝える。
        # SPDX ではこれが普通の状態で、0件を「安全」と読ませないための材料になる。
        sbom_only=not vulnerabilities,
    )


def _check_version(document: dict[str, Any]) -> None:
    """対応している版かを確かめる。対応外なら理由が分かる `InputError`。"""
    raw = as_optional_text(document.get("spdxVersion"))
    if raw is None:
        # `spdxVersion` が無いのに SPDX に見えたということは 3.x の JSON-LD
        raise InputError(_SPDX3_MESSAGE)

    version = _version_parts(raw)
    if version is None:
        raise InputError(
            f"SPDX の版数を読み取れませんでした（spdxVersion: {raw}）。"
            "`SPDX-2.3` のような表記の SPDX 2.2 / 2.3 のファイルを指定してください。"
        )
    if version not in SUPPORTED_VERSIONS:
        raise InputError(
            f"SPDX {version[0]}.{version[1]} には対応していません"
            "（対応しているのは SPDX 2.2 / 2.3 の JSON です）。"
        )


def _version_parts(raw: str) -> tuple[int, int] | None:
    """`SPDX-2.3` から `(2, 3)` を取り出す。読めない書式なら None。

    3つ目以降の数字は無視する（`SPDX-2.3.1` のような表記を弾かないため）。
    """
    text = raw.strip()
    if not text.upper().startswith(VERSION_PREFIX):
        return None
    numbers = text[len(VERSION_PREFIX) :].split(".")
    if len(numbers) < 2:
        return None
    try:
        return int(numbers[0]), int(numbers[1])
    except ValueError:
        return None


def _packages(document: dict[str, Any]) -> list[dict[str, Any]]:
    """`packages[]` のうち、辞書として読めるものだけを返す。"""
    packages = document.get("packages")
    if packages is None:
        return []
    if not isinstance(packages, list):
        raise InputError(_PACKAGES_NOT_LIST_MESSAGE)
    return [package for package in packages if isinstance(package, dict)]


def _package_ids(packages: list[dict[str, Any]]) -> set[str]:
    """`packages[]` に載っている SPDXID の集合。"""
    ids = {as_optional_text(package.get("SPDXID")) for package in packages}
    return {spdx_id for spdx_id in ids if spdx_id is not None}


def _dependency_scopes(document: dict[str, Any], package_ids: set[str]) -> tuple[set[str], bool]:
    """`relationships[]` から `(開発依存の SPDXID, 区別できるか)` を求める。

    見るのは `spdxElementId` の側。`A DEV_DEPENDENCY_OF B` は「A が B の開発依存」で、
    開発依存なのは A のほうだから。

    **`packages[]` に載っている部品を指す関係だけを見る。** SPDX の関係はファイルや
    文書のあいだにも書けるため、部品以外の関係まで数えると、部品については材料が
    無いのに「区別できた（全件が本番依存）」というレポートを出してしまう
    （Phase 6 で `metadata.component` を除いたのと同じ理由）。

    開発用と**明示の**本番用の関係が両方書かれている部品は本番依存にする。片方でも
    本番なら本番（見落としを作らない側に倒す）。スコープを語らない関係
    （`DEPENDENCY_OF` / `DEPENDS_ON`）は、開発依存の記述を打ち消さない。
    """
    relationships = document.get("relationships")
    if relationships is None:
        return set(), False
    if not isinstance(relationships, list):
        raise InputError(_RELATIONSHIPS_NOT_LIST_MESSAGE)

    dev_ids: set[str] = set()
    runtime_ids: set[str] = set()
    scope_known = False

    for entry in relationships:
        if not isinstance(entry, dict):
            continue
        kind = as_optional_text(entry.get("relationshipType"))
        ref = as_optional_text(entry.get("spdxElementId"))
        if kind is None or ref is None or ref not in package_ids:
            continue
        kind = kind.strip().upper()
        if kind in SCOPE_RELATIONSHIP_TYPES:
            scope_known = True
        if kind in DEV_RELATIONSHIP_TYPES:
            dev_ids.add(ref)
        elif kind in RUNTIME_RELATIONSHIP_TYPES:
            runtime_ids.add(ref)

    return dev_ids - runtime_ids, scope_known


def _collect_vulnerabilities(
    packages: list[dict[str, Any]],
    dev_ids: set[str],
    artifact_name: str,
) -> list[Vulnerability]:
    vulnerabilities: list[Vulnerability] = []
    for package in packages:
        vulnerabilities += _parse_package(package, dev_ids, artifact_name)
    return deduplicate(vulnerabilities)


def _parse_package(
    package: dict[str, Any],
    dev_ids: set[str],
    artifact_name: str,
) -> list[Vulnerability]:
    """1件の package を、参照されている CVE ごとの行に展開する。"""
    refs = package.get("externalRefs")
    if refs is None:
        return []
    if not isinstance(refs, list):
        raise InputError(
            "SPDX の形式が想定と異なります"
            f"（packages[].externalRefs が一覧ではありません: {package.get('SPDXID')}）。"
            "`trivy image --format spdx-json` の出力をそのまま指定してください。"
        )

    cve_ids = _cve_ids(refs)
    if not cve_ids:
        return []

    spdx_id = as_optional_text(package.get("SPDXID"))
    target = _target(refs, spdx_id, artifact_name)
    return [
        Vulnerability(
            cve_id=cve_id,
            pkg_name=as_text(package.get("name"), UNKNOWN_VALUE),
            installed_version=as_text(package.get("versionInfo"), UNKNOWN_VALUE),
            # SPDX に修正版を書く場所は無い（`fix` は修正コミットの URL であって版数ではない）。
            # 「修正版なし」と断定すると、直せるものを直せないと読ませてしまう。
            fixed_version=None,
            # SPDX に深刻度スコアを書く場所は無い。EPSS と KEV だけで優先度が付く。
            cvss=None,
            target=target,
            fixed_version_known=False,
            dev_only=spdx_id is not None and spdx_id in dev_ids,
        )
        for cve_id in cve_ids
    ]


def _cve_ids(refs: list[Any]) -> list[str]:
    """SECURITY 参照から CVE ID を取り出す。書かれた順を保ち、重複は除く。"""
    found: dict[str, None] = {}
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if _category(ref) != SECURITY_CATEGORY:
            continue
        if _reference_type(ref) not in SECURITY_REFERENCE_TYPES:
            continue
        locator = as_optional_text(ref.get("referenceLocator"))
        if locator is None:
            continue
        for cve_id in CVE_PATTERN.findall(locator):
            found[cve_id.upper()] = None
    return list(found)


def _target(refs: list[Any], spdx_id: str | None, artifact_name: str) -> str:
    """検出箇所。部品を特定できる文字列を優先する（CycloneDX と同じ考え方）。"""
    purl = _purl(refs)
    if purl:
        return purl
    if spdx_id:
        return spdx_id
    return artifact_name if artifact_name != UNKNOWN_NAME else UNKNOWN_TARGET


def _purl(refs: list[Any]) -> str | None:
    """`externalRefs[]` の purl。無ければ None。"""
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if _category(ref) != PACKAGE_MANAGER_CATEGORY:
            continue
        if _reference_type(ref) != PURL_REFERENCE_TYPE:
            continue
        locator = as_optional_text(ref.get("referenceLocator"))
        if locator:
            return locator
    return None


def _category(ref: dict[str, Any]) -> str:
    """`referenceCategory` を比較用に揃える。

    仕様の版や生成ツールによって `PACKAGE-MANAGER` と `PACKAGE_MANAGER` の
    両方の表記が出回っているため、区切り文字を寄せてから比べる。
    """
    text = as_optional_text(ref.get("referenceCategory"))
    return text.strip().upper().replace("_", "-") if text else ""


def _reference_type(ref: dict[str, Any]) -> str:
    text = as_optional_text(ref.get("referenceType"))
    return text.strip().lower() if text else ""
