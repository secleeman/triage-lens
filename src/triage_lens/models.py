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
        """`P0 (Act now)` のようなランク名。

        ランクの識別子なので日英で共通にする（翻訳しない）。行動指針の文言は
        言語ごとに変わるため `i18n` 側に置いてある。
        """
        return f"{self.name} ({_PRIORITY_LABELS[self]})"


_PRIORITY_LABELS: dict[Priority, str] = {
    Priority.P0: "Act now",
    Priority.P1: "High",
    Priority.P2: "Medium",
    Priority.P3: "Low",
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
    #: 修正バージョンの有無そのものが分かっているか。
    #: CycloneDX には「修正版が存在しない」ことを明示する項目が無いため、
    #: 修正版が読み取れなかったときに「修正版なし」と断定せず「不明」と書くために使う。
    fixed_version_known: bool = True

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
    #: `--ai` で生成した対応方針コメント（無効・失敗時は None）。
    #: 既に無害化済みの文字列が入るため、レポート側で再エスケープしない。
    ai_comment: str | None = None


@dataclass(frozen=True)
class AiAnnotation:
    """AIコメントの生成結果のうち、レポートに書くもの。"""

    #: 生成に使ったモデル。「これは何が書いたのか」を後から追えるようにする
    model: str
    #: 実際にコメントが付いた件数
    generated: int
    #: 生成の対象にした件数
    target_count: int
    #: 上限（--ai-limit）で対象を絞ったか
    limited: bool


@dataclass(frozen=True)
class ScanInput:
    """スキャナ出力ファイル全体から読み取った内容。"""

    artifact_name: str
    vulnerabilities: list[Vulnerability]


#: 値が読み取れなかったときに入れる表記。
#: レポート言語に合わせて `report` 側で差し替えるため、定数として1箇所にまとめる。
UNKNOWN_NAME = "(名称不明)"
UNKNOWN_VALUE = "(不明)"
UNKNOWN_TARGET = "(検出箇所不明)"
