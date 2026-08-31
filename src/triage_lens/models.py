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
    #: 開発時にしか使われない依存か。
    #: 判別の材料が入力に無いときは全件 False（本番依存）になるため、この値だけでは
    #: 「本番依存だと分かっている」のか「区別できていない」のかを区別できない。
    #: 入力全体で区別できたかどうかは `ScanInput.scope_known` を見ること。
    dev_only: bool = False

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
    #: 入力が本番依存 / 開発依存を区別できるか。
    #: CycloneDX の `scope` は省略時に `required` とみなす仕様のため、何も書かれていない
    #: SBOM をそのまま読むと「全件が本番依存」に見えてしまう。区別できているのか、
    #: 区別する材料が無いだけなのかを取り違えないよう、入力単位で持つ。
    scope_known: bool = False
    #: 入力が部品表だけで、脆弱性の一覧を含んでいなかったか。
    #: SPDX 2.x には脆弱性を書く場所がほとんど無く、検出0件が普通の結果になる。
    #: 0件を「脆弱性が無い」ではなく「判定する材料が無い」と示すために使う。
    sbom_only: bool = False
    #: スキャナが判定対象を1つも認識しなかったか。
    #: Trivy は検出0件のとき `Results` をキーごと出力しない（Report 構造体の
    #: `json:",omitempty"`）。対象を認識したうえで0件だったのか、そもそも
    #: 対象を見つけられなかったのかは意味が違うため、区別して持つ。
    no_targets: bool = False
    #: 区別の根拠に、開発依存を明示する property が使われたか。
    #: `scope` の値は生成ツールによって意味が揺れる（開発依存に `optional` を付ける
    #: 誤用が実際にある）ため、`scope` だけを根拠にした分類には注記を添える。
    #: property は「開発依存である」と直接書いたものなので、揺れの心配が小さい。
    dev_property_used: bool = False


#: 値が読み取れなかったときに入れる表記。
#: レポート言語に合わせて `report` 側で差し替えるため、定数として1箇所にまとめる。
UNKNOWN_NAME = "(名称不明)"
UNKNOWN_VALUE = "(不明)"
UNKNOWN_TARGET = "(検出箇所不明)"
