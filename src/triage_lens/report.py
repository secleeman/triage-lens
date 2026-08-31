"""トリアージレポート（Markdown）の生成。"""

from collections.abc import Sequence
from datetime import datetime

from .i18n import DEFAULT_LANG, Catalog, catalog
from .kev import SOURCE_STALE_CACHE, SOURCE_UNAVAILABLE
from .models import (
    UNKNOWN_NAME,
    UNKNOWN_TARGET,
    UNKNOWN_VALUE,
    AiAnnotation,
    EnrichedVulnerability,
    Priority,
)
from .recommendations import Recommendation
from .recommendations import build as build_recommendations
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

#: 推奨アクションの表の区切り行（列数は `recommend_table_header` の文言と揃える）
_RECOMMEND_DIVIDER = "| " + " | ".join(["---"] * 5) + " |"

#: 本番依存 / 開発依存に分けて出すときの並び順。本番依存を先に出す。
_GROUPS = (("group_runtime", False), ("group_dev", True))

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
    ai: AiAnnotation | None = None,
    scope_known: bool = False,
    dev_property_used: bool = False,
    sbom_only: bool = False,
    no_targets: bool = False,
) -> str:
    """優先度付きの脆弱性一覧から Markdown レポートを組み立てる。

    `scope_known` は、入力が本番依存 / 開発依存を区別できるかどうか。表示は3通りになる。

    | 状態 | 表示 |
    | --- | --- |
    | 区別できない | 1つの表。冒頭に「区別情報が無い」と明記する |
    | 区別できて開発依存が0件 | 1つの表。サマリに「開発依存のみの検出: 0件」と明記する |
    | 区別できて開発依存がある | 本番依存 / 開発依存のみ の2つの表に分ける |

    上の2つはどちらも1つの表になるが、**「材料が無かった」のか「区別したうえで0件
    だった」のかは書き分ける**。読む人にとって意味がまったく違うため。

    `dev_property_used` は、その区別の根拠に「開発依存である」と明示した property が
    使われたか。**使われておらず `scope` だけが根拠のときは、末尾に注記を出す。**
    `scope` の意味は生成ツールによって揺れ、誤用されていると分類が実態と逆になる。

    **区別の有無は優先度には影響しない**（表示の分け方だけが変わる）。

    `sbom_only` は、入力が部品表だけで脆弱性の一覧を含んでいなかったかどうか。
    `no_targets` は、スキャナが判定できる構成要素を1つも見つけなかったかどうか。
    真なら冒頭に注記を出す。SPDX のように脆弱性を書く場所がほとんど無い形式では
    「検出0件」が普通の結果になり、そのままでは「安全だった」と読まれるため。
    """
    text = catalog(lang)
    counts = count_by_priority(items)
    # 開発依存の検出が1件も無いなら分けない。空の「開発依存のみ（0件）」が
    # ランクの数だけ並ぶだけで、読む人には何も足さないため。
    # 代わりにサマリへ「0件」と明記して、区別できなかった場合と見分けられるようにする。
    split = scope_known and any(item.vuln.dev_only for item in items)
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

    # 「0件」の意味が変わる話なので、表より先に出す。入力の性質の説明であって
    # 取得の失敗ではないため、警告の印（⚠️）は付けない。
    if sbom_only:
        lines += [f"> {text('note_sbom_only')}", ""]

    # 部品表だけの入力は sbom_only 側で説明が付くため、重ねて出さない。
    if no_targets and not sbom_only:
        lines += [f"> {text('note_no_targets')}", ""]

    # 区別できないことは異常ではないので、警告の印（⚠️）は付けない。
    # 検出が無いときは分ける対象そのものが無いため出さない。
    if items and not scope_known:
        lines += [f"> {text('note_scope_unknown')}", ""]

    lines += _summary_section(text, items, counts, scope_known=scope_known, split=split)

    if not items:
        lines += [text("no_findings"), ""]
    else:
        for priority in Priority:
            limit = None if priority in _FULL_LIST_PRIORITIES else top_n
            lines += _priority_section(text, items, priority, counts[priority], limit, split=split)
        lines += _recommendations_section(text, build_recommendations(items), split=split)

    lines += _footer(text)
    lines += _ai_footer(text, ai)
    lines += _scope_basis_section(
        text, items, scope_known=scope_known, dev_property_used=dev_property_used
    )
    lines += _limits_section(text, items)
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
    text: Catalog,
    items: Sequence[EnrichedVulnerability],
    counts: dict[Priority, int],
    *,
    scope_known: bool,
    split: bool,
) -> list[str]:
    lines = [
        f"## {text('summary_heading')}",
        "",
        text("summary_total", count=len(items)),
    ]

    # 「区別したうえで0件だった」ことを書く。これが無いと、区別できずに分けなかった
    # 場合（冒頭に注記が出る）と見分けが付かない。
    if items and scope_known and not split:
        lines.append(text("summary_dev_none"))
    lines.append("")

    if not split:
        # 区別できないのに内訳の列を出すと「本番依存は0件」と読まれてしまう。
        # 開発依存が0件のときも、内訳の列は件数と同じ数が並ぶだけで意味がない。
        lines += [text("summary_table_header"), "| --- | --- | --- |"]
        lines += [
            f"| {priority.label} | {counts[priority]} | {_action(text, priority)} |"
            for priority in Priority
        ]
        lines.append("")
        return lines

    runtime = count_by_priority(item for item in items if not item.vuln.dev_only)
    lines += [text("summary_table_header_split"), "| --- | --- | --- | --- |"]
    lines += [
        f"| {priority.label} | {counts[priority]} | {runtime[priority]} "
        f"| {_action(text, priority)} |"
        for priority in Priority
    ]
    lines.append("")
    return lines


def _priority_section(
    text: Catalog,
    items: Sequence[EnrichedVulnerability],
    priority: Priority,
    count: int,
    limit: int | None,
    *,
    split: bool,
) -> list[str]:
    matching = [item for item in items if item.priority is priority]

    if not split:
        shown = _limited(matching, limit)
        lines = [f"## {_heading(text, priority, _scope(text, count, len(shown), limit))}", ""]
        lines += _table(text, shown, count)
        lines += _ai_comment_lines(text, shown)
        return lines

    # 分けるときは、ランクの見出しには総数だけを出し、省略の有無は表ごとに書く。
    lines = [f"## {_heading(text, priority, text('scope_all', count=count))}", ""]
    shown_all: list[EnrichedVulnerability] = []
    for label_key, dev_only in _GROUPS:
        group = [item for item in matching if bool(item.vuln.dev_only) is dev_only]
        # 表示件数の指定は表ごとに効かせる。ランク全体で数えると、本番依存の検出が
        # 開発依存に押し出されて見えなくなることがあるため。
        shown = _limited(group, limit)
        shown_all += shown
        scope = _scope(text, len(group), len(shown), limit)
        lines += [f"### {text('group_heading', label=text(label_key), scope=scope)}", ""]
        lines += _table(text, shown, len(group))
    # AIコメントは表ごとではなくランクごとに1箇所へまとめる（見出しの階層を深くしないため）
    lines += _ai_comment_lines(text, shown_all)
    return lines


def _limited(
    items: Sequence[EnrichedVulnerability], limit: int | None
) -> list[EnrichedVulnerability]:
    if limit is None:
        return list(items)
    return list(items[: max(0, limit)])


def _scope(text: Catalog, count: int, shown: int, limit: int | None) -> str:
    """「17件」「17件中 上位5件を表示」のような、件数と省略の有無を表す語。"""
    if limit is None or count <= shown:
        return text("scope_all", count=count)
    if shown == 0:
        return text("scope_omitted", count=count)
    return text("scope_top", count=count, shown=shown)


def _heading(text: Catalog, priority: Priority, scope: str) -> str:
    return text(
        "section_heading", label=priority.label, action=_action(text, priority), scope=scope
    )


def _table(text: Catalog, shown: Sequence[EnrichedVulnerability], count: int) -> list[str]:
    if not shown:
        return [text("section_none") if count == 0 else text("section_hidden"), ""]
    return [text("table_header"), _TABLE_DIVIDER, *[_row(text, item) for item in shown], ""]


def _ai_comment_lines(text: Catalog, shown: Sequence[EnrichedVulnerability]) -> list[str]:
    """AIコメントは一覧表の下に置く。列を増やすと表が横に伸びて読めなくなるため。"""
    commented = [item for item in shown if item.ai_comment]
    if not commented:
        return []

    # 同じCVEが複数の検出箇所で見つかると、検出箇所を書かないこの行は同じ文になる。
    # 一覧表には両方が出ているので、ここで同じ行を繰り返さない。
    rendered: list[str] = []
    for item in commented:
        line = text(
            "ai_comment_item",
            cve=_escape(item.vuln.cve_id),
            pkg=_field(text, item.vuln.pkg_name),
            # `ai_comment` は生成時に無害化済みなので、ここで再エスケープしない
            comment=item.ai_comment,
        )
        if line not in rendered:
            rendered.append(line)

    return [f"### {text('ai_section_heading')}", "", *rendered, ""]


def _recommendations_section(
    text: Catalog, recommendations: Sequence[Recommendation], *, split: bool
) -> list[str]:
    """パッケージ単位の推奨アクション。

    「優先度の付け方」より前に置く。あちらは判定基準の説明であって付録にあたるので、
    行動の指示をその後ろに置くと埋もれる。
    """
    if not recommendations:
        return []

    lines = [f"## {text('recommend_heading')}", "", text("recommend_note"), ""]

    if not split:
        return lines + _recommend_table(text, recommendations)

    for label_key, dev_only in _GROUPS:
        group = [item for item in recommendations if bool(item.dev_only) is dev_only]
        scope = text("scope_all", count=len(group))
        lines += [f"### {text('group_heading', label=text(label_key), scope=scope)}", ""]
        lines += _recommend_table(text, group) if group else [text("section_none"), ""]
    return lines


def _recommend_table(text: Catalog, recommendations: Sequence[Recommendation]) -> list[str]:
    rows = [_recommend_row(text, item) for item in recommendations]
    return [text("recommend_table_header"), _RECOMMEND_DIVIDER, *rows, ""]


def _recommend_row(text: Catalog, recommendation: Recommendation) -> str:
    cells = [
        _field(text, recommendation.pkg_name),
        _field(text, recommendation.installed_version),
        _upgrade_target(text, recommendation),
        _resolved_count(text, recommendation),
        recommendation.priority.label,
    ]
    return "| " + " | ".join(cells) + " |"


def _upgrade_target(text: Catalog, recommendation: Recommendation) -> str:
    """上げ先の表記。「修正版が無い」と「どこまで上げればよいか分からない」を混同しない。"""
    if recommendation.fixed_version is not None:
        return _escape(recommendation.fixed_version)
    return text("no_fix_available") if recommendation.fixed_version_known else text("unknown")


def _resolved_count(text: Catalog, recommendation: Recommendation) -> str:
    """解消される件数。上げても残る検出があれば、同じセルに件数を併記する。

    1件も解消できないときは併記しない。そのときは上げ先の欄が「修正版なし」「不明」に
    なっており、同じことを2度書くことになるため。
    """
    if recommendation.unresolved == 0 or recommendation.resolved == 0:
        return text("recommend_resolved", count=recommendation.resolved)

    kinds = []
    if recommendation.unresolved_has_no_fix:
        kinds.append(text("no_fix_available"))
    if recommendation.unresolved_has_unknown:
        kinds.append(text("unknown"))
    return text(
        "recommend_resolved_rest",
        count=recommendation.resolved,
        rest=recommendation.unresolved,
        kind=text("recommend_kind_separator").join(kinds),
    )


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


def _ai_footer(text: Catalog, ai: AiAnnotation | None) -> list[str]:
    """AIコメントを1件でも載せたときだけ、免責と生成条件を書く。"""
    if ai is None or ai.generated == 0:
        return []

    lines = [
        f"## {text('ai_footer_heading')}",
        "",
        text("ai_disclaimer"),
        "",
        text("ai_model_note", model=_escape(ai.model)),
        text("ai_scope_note"),
    ]
    if ai.limited:
        lines.append(text("ai_limit_note", count=ai.target_count))
    lines.append("")
    return lines


def _scope_basis_section(
    text: Catalog,
    items: Sequence[EnrichedVulnerability],
    *,
    scope_known: bool,
    dev_property_used: bool,
) -> list[str]:
    """本番 / 開発の分類を `scope` だけで決めたときに添える注記。

    `scope` の意味は生成ツールによって揺れる。開発依存へ `optional` を付ける SBOM が
    実際にあり、triage-lens はそれを本番依存として扱うため、**分類が実態と真逆に
    なりうる**。根拠が `scope` しか無かったことを、読む人に伝えておく。

    「開発依存である」と明示した property が使われていれば揺れの心配は小さいので、
    そのときは出さない。区別していないとき（`scope_known` が偽）も、分類そのものが
    無いので出さない。
    """
    if not items or not scope_known or dev_property_used:
        return []
    return [text("scope_basis_note"), ""]


def _limits_section(text: Catalog, items: Sequence[EnrichedVulnerability]) -> list[str]:
    """このレポートで分かることの限界。最後に読ませたいので最終行に置く。

    検出が無いときは出さない。判定した結果が1件も無いところに判定の限界を書いても、
    何のことか伝わらないため。
    """
    if not items:
        return []
    return [text("limits_note"), ""]


def _field(text: Catalog, value: str) -> str:
    """表に出す値。読み取れなかったことを表す表記はレポート言語に合わせる。"""
    key = _PLACEHOLDER_KEYS.get(value)
    return text(key) if key else _escape(value)


def _escape(value: str) -> str:
    """Markdown の表を壊さないように整形する。"""
    return value.replace("|", r"\|").replace("\n", " ").strip()
