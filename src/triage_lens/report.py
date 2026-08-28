"""トリアージレポート（Markdown）の生成。"""

from collections.abc import Sequence
from datetime import datetime

from .kev import SOURCE_STALE_CACHE, SOURCE_UNAVAILABLE
from .models import EnrichedVulnerability, Priority
from .scoring import (
    CVSS_THRESHOLD,
    EPSS_THRESHOLD,
    count_by_priority,
    format_cvss,
    format_epss,
    format_kev,
)

#: P2 / P3 で表示する件数の既定値
DEFAULT_TOP_N = 5

#: 全件表示するランク
_FULL_LIST_PRIORITIES = (Priority.P0, Priority.P1)

_TABLE_HEADER = (
    "| CVE | パッケージ | 検出箇所 | 現在 → 修正 | CVSS | EPSS | KEV | 優先度の理由 |",
    "| --- | --- | --- | --- | --- | --- | --- | --- |",
)


def render_report(
    items: Sequence[EnrichedVulnerability],
    *,
    artifact_name: str,
    generated_at: datetime,
    top_n: int = DEFAULT_TOP_N,
    epss_complete: bool = True,
    kev_source: str = "",
) -> str:
    """優先度付きの脆弱性一覧から日本語の Markdown レポートを組み立てる。"""
    counts = count_by_priority(items)
    lines: list[str] = ["# 脆弱性トリアージレポート", ""]
    lines += [
        f"- 対象: {_escape(artifact_name)}",
        f"- 生成日時: {generated_at:%Y-%m-%d %H:%M}",
        f"- 判定基準: CISA KEV 掲載 / EPSS {EPSS_THRESHOLD} 以上 / CVSS {CVSS_THRESHOLD} 以上",
        "",
    ]

    warnings = _warnings(epss_complete=epss_complete, kev_source=kev_source)
    if warnings:
        lines += [f"> ⚠️ {warning}" for warning in warnings]
        lines.append("")

    lines += _summary_section(items, counts)

    if not items:
        lines += ["検出された脆弱性はありません。", ""]
    else:
        for priority in Priority:
            limit = None if priority in _FULL_LIST_PRIORITIES else top_n
            lines += _priority_section(items, priority, counts[priority], limit)

    lines += _footer()
    return "\n".join(lines).rstrip() + "\n"


def _warnings(*, epss_complete: bool, kev_source: str) -> list[str]:
    warnings: list[str] = []
    if kev_source == SOURCE_UNAVAILABLE:
        warnings.append(
            "CISA KEV カタログを取得できませんでした。"
            "KEV 掲載有無は「不明」として扱い、P0 の判定はできていません。"
        )
    elif kev_source == SOURCE_STALE_CACHE:
        warnings.append(
            "CISA KEV カタログの再取得に失敗したため、24時間以上前のキャッシュを使用しています。"
        )
    if not epss_complete:
        warnings.append(
            "EPSS スコアの一部または全部を取得できませんでした。"
            "取得できなかったものは CVSS のみで判定しています。"
        )
    return warnings


def _summary_section(
    items: Sequence[EnrichedVulnerability], counts: dict[Priority, int]
) -> list[str]:
    lines = ["## サマリ", "", f"検出総数: {len(items)}件", ""]
    lines.append("| 優先度 | 件数 | 目安 |")
    lines.append("| --- | --- | --- |")
    for priority in Priority:
        lines.append(f"| {priority.label} | {counts[priority]} | {priority.action} |")
    lines.append("")
    return lines


def _priority_section(
    items: Sequence[EnrichedVulnerability],
    priority: Priority,
    count: int,
    limit: int | None,
) -> list[str]:
    shown = [item for item in items if item.priority is priority]
    if limit is not None:
        shown = shown[: max(0, limit)]

    if limit is None or count <= len(shown):
        scope = f"{count}件"
    elif not shown:
        scope = f"{count}件（表示件数の指定により省略）"
    else:
        scope = f"{count}件中 上位{len(shown)}件を表示"

    lines = [f"## {priority.label} — {priority.action}（{scope}）", ""]
    if not shown:
        lines += ["該当なし。" if count == 0 else "（表示なし）", ""]
        return lines

    lines += list(_TABLE_HEADER)
    lines += [_row(item) for item in shown]
    lines.append("")
    return lines


def _row(item: EnrichedVulnerability) -> str:
    vuln = item.vuln
    fixed = _escape(vuln.fixed_version) if vuln.fixed_version else "修正版なし"
    cells = [
        _escape(vuln.cve_id),
        _escape(vuln.pkg_name),
        _escape(vuln.target),
        f"{_escape(vuln.installed_version)} → {fixed}",
        format_cvss(vuln.cvss),
        format_epss(item.epss),
        format_kev(item.in_kev),
        _escape(item.reason),
    ]
    return "| " + " | ".join(cells) + " |"


def _footer() -> list[str]:
    return [
        "## 優先度の付け方",
        "",
        "| 優先度 | 条件 |",
        "| --- | --- |",
        "| P0 (Act now) | CISA KEV に掲載＝実際に悪用が確認されている |",
        f"| P1 (High) | EPSS {EPSS_THRESHOLD} 以上 かつ CVSS {CVSS_THRESHOLD} 以上 |",
        f"| P2 (Medium) | EPSS {EPSS_THRESHOLD} 以上 か CVSS {CVSS_THRESHOLD} 以上 の一方のみ |",
        "| P3 (Low) | 上記のいずれにも当てはまらない |",
        "",
        "同一ランク内は EPSS の高い順、次に CVSS の高い順に並べています。",
        "",
        "データ出典: CISA KEV カタログ / FIRST.org EPSS / CVSS はスキャナ出力の値。",
        "",
    ]


def _escape(text: str) -> str:
    """Markdown の表を壊さないように整形する。"""
    return text.replace("|", r"\|").replace("\n", " ").strip()
