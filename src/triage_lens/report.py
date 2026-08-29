"""トリアージレポート（Markdown）の生成。"""

from collections.abc import Sequence
from datetime import datetime

from .i18n import DEFAULT_LANG, Catalog, catalog
from .kev import SOURCE_STALE_CACHE, SOURCE_UNAVAILABLE
from .models import (
    UNKNOWN_NAME,
    UNKNOWN_TARGET,
    UNKNOWN_VALUE,
    EnrichedVulnerability,
    Priority,
)
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

#: 一覧表の区切り行（列数は `table_header` の文言と揃える）
_TABLE_DIVIDER = "| " + " | ".join(["---"] * 8) + " |"

#: パーサが入れた「読み取れなかった」表記と、その文言キーの対応。
#: 形式の解釈は言語に依存しないため、表示するときにレポート言語へ差し替える。
_PLACEHOLDER_KEYS = {
    UNKNOWN_NAME: "placeholder_unknown_name",
    UNKNOWN_VALUE: "placeholder_unknown_value",
    UNKNOWN_TARGET: "placeholder_unknown_target",
}

#: 日時の表記。曖昧さを避けるため両言語で共通にする。
_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M"


def render_report(
    items: Sequence[EnrichedVulnerability],
    *,
    artifact_name: str,
    generated_at: datetime,
    top_n: int = DEFAULT_TOP_N,
    epss_complete: bool = True,
    kev_source: str = "",
    lang: str = DEFAULT_LANG,
) -> str:
    """優先度付きの脆弱性一覧から Markdown レポートを組み立てる。"""
    text = catalog(lang)
    counts = count_by_priority(items)
    lines: list[str] = [f"# {text('report_title')}", ""]
    lines += [
        text("meta_target", artifact=_field(text, artifact_name)),
        text("meta_generated_at", timestamp=generated_at.strftime(_TIMESTAMP_FORMAT)),
        text("meta_criteria", epss=EPSS_THRESHOLD, cvss=CVSS_THRESHOLD),
        "",
    ]

    warnings = _warnings(text, epss_complete=epss_complete, kev_source=kev_source)
    if warnings:
        lines += [f"> ⚠️ {warning}" for warning in warnings]
        lines.append("")

    lines += _summary_section(text, items, counts)

    if not items:
        lines += [text("no_findings"), ""]
    else:
        for priority in Priority:
            limit = None if priority in _FULL_LIST_PRIORITIES else top_n
            lines += _priority_section(text, items, priority, counts[priority], limit)

    lines += _footer(text)
    return "\n".join(lines).rstrip() + "\n"


def _warnings(text: Catalog, *, epss_complete: bool, kev_source: str) -> list[str]:
    warnings: list[str] = []
    if kev_source == SOURCE_UNAVAILABLE:
        warnings.append(text("warn_kev_unavailable"))
    elif kev_source == SOURCE_STALE_CACHE:
        warnings.append(text("warn_kev_stale_cache"))
    if not epss_complete:
        warnings.append(text("warn_epss_incomplete"))
    return warnings


def _summary_section(
    text: Catalog, items: Sequence[EnrichedVulnerability], counts: dict[Priority, int]
) -> list[str]:
    lines = [
        f"## {text('summary_heading')}",
        "",
        text("summary_total", count=len(items)),
        "",
        text("summary_table_header"),
        "| --- | --- | --- |",
    ]
    for priority in Priority:
        lines.append(f"| {priority.label} | {counts[priority]} | {_action(text, priority)} |")
    lines.append("")
    return lines


def _priority_section(
    text: Catalog,
    items: Sequence[EnrichedVulnerability],
    priority: Priority,
    count: int,
    limit: int | None,
) -> list[str]:
    shown = [item for item in items if item.priority is priority]
    if limit is not None:
        shown = shown[: max(0, limit)]

    if limit is None or count <= len(shown):
        scope = text("scope_all", count=count)
    elif not shown:
        scope = text("scope_omitted", count=count)
    else:
        scope = text("scope_top", count=count, shown=len(shown))

    heading = text(
        "section_heading", label=priority.label, action=_action(text, priority), scope=scope
    )
    lines = [f"## {heading}", ""]
    if not shown:
        lines += [text("section_none") if count == 0 else text("section_hidden"), ""]
        return lines

    lines += [text("table_header"), _TABLE_DIVIDER]
    lines += [_row(text, item) for item in shown]
    lines.append("")
    return lines


def _action(text: Catalog, priority: Priority) -> str:
    return text(f"action_{priority.name}")


def _row(text: Catalog, item: EnrichedVulnerability) -> str:
    vuln = item.vuln
    cells = [
        _escape(vuln.cve_id),
        _field(text, vuln.pkg_name),
        _field(text, vuln.target),
        text(
            "version_transition",
            installed=_field(text, vuln.installed_version),
            fixed=_fixed_version(text, item),
        ),
        format_cvss(vuln.cvss, text.lang),
        format_epss(item.epss, text.lang),
        format_kev(item.in_kev, text.lang),
        _escape(item.reason),
    ]
    return "| " + " | ".join(cells) + " |"


def _fixed_version(text: Catalog, item: EnrichedVulnerability) -> str:
    """修正版の表記。「存在しない」と「分からない」を混同しない。"""
    vuln = item.vuln
    if vuln.fixed_version:
        return _escape(vuln.fixed_version)
    return text("no_fix_available") if vuln.fixed_version_known else text("unknown")


def _footer(text: Catalog) -> list[str]:
    conditions = {
        Priority.P0: text("condition_p0"),
        Priority.P1: text("condition_p1", epss=EPSS_THRESHOLD, cvss=CVSS_THRESHOLD),
        Priority.P2: text("condition_p2", epss=EPSS_THRESHOLD, cvss=CVSS_THRESHOLD),
        Priority.P3: text("condition_p3"),
    }
    lines = [
        f"## {text('footer_heading')}",
        "",
        text("footer_table_header"),
        "| --- | --- |",
    ]
    lines += [f"| {priority.label} | {conditions[priority]} |" for priority in Priority]
    lines += [
        "",
        text("footer_sort_note"),
        "",
        text("footer_sources"),
        "",
    ]
    return lines


def _field(text: Catalog, value: str) -> str:
    """表に出す値。読み取れなかったことを表す表記はレポート言語に合わせる。"""
    key = _PLACEHOLDER_KEYS.get(value)
    return text(key) if key else _escape(value)


def _escape(value: str) -> str:
    """Markdown の表を壊さないように整形する。"""
    return value.replace("|", r"\|").replace("\n", " ").strip()
