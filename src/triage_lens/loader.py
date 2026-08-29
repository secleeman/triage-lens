"""入力ファイルの形式を判別して読み込む。

利用者に形式を指定させない。CycloneDX か Trivy JSON かは中身から判断する。
判別の順序を固定しておくことで、挙動を一意にする。
"""

from pathlib import Path
from typing import Any

from .cyclonedx import looks_like_cyclonedx, parse_bom
from .errors import InputError
from .models import ScanInput
from .parsing import read_json_document
from .trivy import looks_like_trivy, parse_scan

_UNSUPPORTED_FORMAT_MESSAGE = (
    "Trivy の JSON 出力ではないようです（CycloneDX 形式（JSON）でもありません）。"
    "`trivy image --format json -o result.json` か "
    "`trivy image --format cyclonedx -o sbom.cdx.json` で出力したファイルを指定してください。"
)


def load_scan(path: str | Path) -> ScanInput:
    """入力ファイルを形式に応じて読み込む。読めない場合は `InputError`。"""
    return parse_document(read_json_document(path))


def parse_document(document: Any) -> ScanInput:
    """パース済みの JSON から、形式を判別して脆弱性一覧を取り出す。"""
    if looks_like_cyclonedx(document):
        return parse_bom(document)
    if looks_like_trivy(document):
        return parse_scan(document)
    raise InputError(_UNSUPPORTED_FORMAT_MESSAGE)
