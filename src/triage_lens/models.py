"""triage-lens のデータモデル。"""

from dataclasses import dataclass
from enum import Enum


class Priority(Enum):
    """トリアージの優先度ランク。値が小さいほど緊急。"""

    P0 = 0
    P1 = 1
    P2 = 2
    P3 = 3

    @property
    def label(self) -> str:
        """`P0 (Act now)` のような英語ラベル。"""
        return f"{self.name} ({_PRIORITY_LABELS[self][0]})"

    @property
    def action(self) -> str:
        """日本語の行動指針。"""
        return _PRIORITY_LABELS[self][1]


_PRIORITY_LABELS: dict[Priority, tuple[str, str]] = {
    Priority.P0: ("Act now", "今すぐ対応"),
    Priority.P1: ("High", "優先的に対応"),
    Priority.P2: ("Medium", "計画的に対応"),
    Priority.P3: ("Low", "経過観察"),
}


@dataclass(frozen=True)
class Vulnerability:
    """スキャナ出力から読み取った1件の脆弱性。"""

    cve_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str | None
    cvss: float | None
    target: str

    @property
    def dedupe_key(self) -> tuple[str, str, str, str]:
        """完全に同一の検出だけを重複とみなすためのキー。

        検出箇所（Target）が違えば別の行として残す。同じCVEでも
        OSパッケージ側とアプリ依存側の両方を直す必要があるため。
        """
        return (self.target, self.cve_id, self.pkg_name, self.installed_version)


@dataclass(frozen=True)
class EnrichedVulnerability:
    """公開データで補強し、優先度を付けた脆弱性。"""

    vuln: Vulnerability
    epss: float | None
    in_kev: bool | None
    priority: Priority
    reason: str


@dataclass(frozen=True)
class ScanInput:
    """スキャナ出力ファイル全体から読み取った内容。"""

    artifact_name: str
    vulnerabilities: list[Vulnerability]
