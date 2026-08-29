"""レポートの文言カタログ（日本語 / 英語）。

レポートに出る文字列はすべてこのモジュールに集約する。各モジュールに
日本語リテラルを散らさないことで、対応言語を増やしたときの漏れを防ぐ。

対象はあくまで**レポート本文**であり、エラーメッセージや `--help` の説明文は
日本語のまま（Phase 2 のスコープ外）。
"""

from typing import Any

#: 既定の出力言語
DEFAULT_LANG = "ja"

#: 対応している出力言語
SUPPORTED_LANGS = ("ja", "en")

_JA: dict[str, str] = {
    # 見出しとメタ情報
    "report_title": "脆弱性トリアージレポート",
    "meta_target": "- 対象: {artifact}",
    "meta_generated_at": "- 生成日時: {timestamp}",
    "meta_criteria": "- 判定基準: CISA KEV 掲載 / EPSS {epss} 以上 / CVSS {cvss} 以上",
    # 外部データが取れなかったときの警告
    "warn_kev_unavailable": (
        "CISA KEV カタログを取得できませんでした。"
        "KEV 掲載有無は「不明」として扱い、P0 の判定はできていません。"
    ),
    "warn_kev_stale_cache": (
        "CISA KEV カタログの再取得に失敗したため、24時間以上前のキャッシュを使用しています。"
    ),
    "warn_epss_incomplete": (
        "EPSS スコアの一部または全部を取得できませんでした。"
        "取得できなかったものは CVSS のみで判定しています。"
    ),
    # サマリ
    "summary_heading": "サマリ",
    "summary_total": "検出総数: {count}件",
    "summary_table_header": "| 優先度 | 件数 | 目安 |",
    "no_findings": "検出された脆弱性はありません。",
    # 各ランクの行動指針
    "action_P0": "今すぐ対応",
    "action_P1": "優先的に対応",
    "action_P2": "計画的に対応",
    "action_P3": "経過観察",
    # 各ランクの節
    "section_heading": "{label} — {action}（{scope}）",
    "scope_all": "{count}件",
    "scope_omitted": "{count}件（表示件数の指定により省略）",
    "scope_top": "{count}件中 上位{shown}件を表示",
    "section_none": "該当なし。",
    "section_hidden": "（表示なし）",
    # 一覧表
    "table_header": (
        "| CVE | パッケージ | 検出箇所 | 現在 → 修正 | CVSS | EPSS | KEV | 優先度の理由 |"
    ),
    "version_transition": "{installed} → {fixed}",
    "no_fix_available": "修正版なし",
    "unknown": "不明",
    "placeholder_unknown_name": "(名称不明)",
    "placeholder_unknown_value": "(不明)",
    "placeholder_unknown_target": "(検出箇所不明)",
    "kev_yes": "あり",
    "kev_no": "なし",
    # 優先度の理由
    "reason_kev": "KEV掲載＝実際に悪用されている",
    "clause_epss_unknown": "悪用確率は不明",
    "clause_epss_high": "悪用確率は高い",
    "clause_epss_low": "悪用確率は低い",
    "clause_cvss_unknown": "深刻度は不明",
    "clause_cvss_high": "深刻度は高い",
    "clause_cvss_low": "深刻度は中以下",
    "reason_p1": "悪用確率が高く（EPSS {epss}）、深刻度も高い（CVSS {cvss}）",
    "reason_p2_cvss": "深刻度は高い（CVSS {cvss}）が、{epss_clause}（EPSS {epss}）",
    "reason_p2_epss": "悪用確率は高い（EPSS {epss}）が、{cvss_clause}（CVSS {cvss}）",
    "reason_p3": (
        "{epss_clause}・{cvss_clause}で、高リスクの条件に当てはまらない"
        "（EPSS {epss} / CVSS {cvss}）"
    ),
    "note_kev_missing": "KEV情報が取得できず未判定",
    "note_epss_missing": "EPSSが取得できず判定に使えていない",
    "note_cvss_missing": "CVSSが不明で判定に使えていない",
    "notes_separator": " / ",
    "notes_wrapper": "{reason}［{notes}］",
    # 末尾の説明
    "footer_heading": "優先度の付け方",
    "footer_table_header": "| 優先度 | 条件 |",
    "condition_p0": "CISA KEV に掲載＝実際に悪用が確認されている",
    "condition_p1": "EPSS {epss} 以上 かつ CVSS {cvss} 以上",
    "condition_p2": "EPSS {epss} 以上 か CVSS {cvss} 以上 の一方のみ",
    "condition_p3": "上記のいずれにも当てはまらない",
    "footer_sort_note": "同一ランク内は EPSS の高い順、次に CVSS の高い順に並べています。",
    "footer_sources": (
        "データ出典: CISA KEV カタログ / FIRST.org EPSS / CVSS はスキャナ出力の値。"
    ),
}

_EN: dict[str, str] = {
    "report_title": "Vulnerability Triage Report",
    "meta_target": "- Target: {artifact}",
    "meta_generated_at": "- Generated: {timestamp}",
    "meta_criteria": "- Criteria: listed in CISA KEV / EPSS >= {epss} / CVSS >= {cvss}",
    "warn_kev_unavailable": (
        "Could not fetch the CISA KEV catalog. KEV listing is reported as unknown, "
        "so no finding was ranked P0 on that basis."
    ),
    "warn_kev_stale_cache": (
        "Could not refresh the CISA KEV catalog, so a cache older than 24 hours is being used."
    ),
    "warn_epss_incomplete": (
        "Some or all EPSS scores could not be fetched. Those findings were ranked using CVSS alone."
    ),
    "summary_heading": "Summary",
    "summary_total": "Total findings: {count}",
    "summary_table_header": "| Priority | Count | Action |",
    "no_findings": "No vulnerabilities were found.",
    "action_P0": "Patch immediately",
    "action_P1": "Fix soon",
    "action_P2": "Plan a fix",
    "action_P3": "Monitor",
    "section_heading": "{label} - {action} ({scope})",
    "scope_all": "{count} total",
    "scope_omitted": "{count} total, hidden by the display limit",
    "scope_top": "top {shown} of {count}",
    "section_none": "None.",
    "section_hidden": "(not shown)",
    "table_header": ("| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |"),
    "version_transition": "{installed} -> {fixed}",
    "no_fix_available": "No fix available",
    "unknown": "Unknown",
    "placeholder_unknown_name": "(unknown name)",
    "placeholder_unknown_value": "(unknown)",
    "placeholder_unknown_target": "(unknown location)",
    "kev_yes": "Yes",
    "kev_no": "No",
    "reason_kev": "Listed in CISA KEV - exploitation observed in the wild",
    "clause_epss_unknown": "exploitation probability is unknown",
    "clause_epss_high": "exploitation probability is high",
    "clause_epss_low": "exploitation probability is low",
    "clause_cvss_unknown": "severity is unknown",
    "clause_cvss_high": "severity is high",
    "clause_cvss_low": "severity is medium or lower",
    "reason_p1": ("High exploitation probability (EPSS {epss}) and high severity (CVSS {cvss})"),
    "reason_p2_cvss": "Severity is high (CVSS {cvss}), but {epss_clause} (EPSS {epss})",
    "reason_p2_epss": (
        "Exploitation probability is high (EPSS {epss}), but {cvss_clause} (CVSS {cvss})"
    ),
    "reason_p3": (
        "Does not meet the high-risk criteria: {epss_clause}, {cvss_clause} "
        "(EPSS {epss} / CVSS {cvss})"
    ),
    "note_kev_missing": "KEV data unavailable, so this was not checked",
    "note_epss_missing": "EPSS unavailable, not used in this decision",
    "note_cvss_missing": "CVSS unknown, not used in this decision",
    "notes_separator": " / ",
    "notes_wrapper": "{reason} [{notes}]",
    "footer_heading": "How priorities are assigned",
    "footer_table_header": "| Priority | Condition |",
    "condition_p0": "Listed in CISA KEV - exploitation has been observed in the wild",
    "condition_p1": "EPSS >= {epss} AND CVSS >= {cvss}",
    "condition_p2": "EPSS >= {epss} OR CVSS >= {cvss} (only one of the two)",
    "condition_p3": "None of the above",
    "footer_sort_note": (
        "Within a rank, findings are sorted by EPSS descending, then CVSS descending."
    ),
    "footer_sources": (
        "Sources: CISA KEV catalog / FIRST.org EPSS / CVSS as reported by the scanner."
    ),
}

_CATALOGS: dict[str, dict[str, str]] = {"ja": _JA, "en": _EN}


class Catalog:
    """1つの言語の文言を引くためのオブジェクト。"""

    __slots__ = ("_messages", "lang")

    def __init__(self, lang: str) -> None:
        if lang not in _CATALOGS:
            raise ValueError(
                f"対応していない言語です: {lang}（対応: {', '.join(SUPPORTED_LANGS)}）"
            )
        self.lang = lang
        self._messages = _CATALOGS[lang]

    def __call__(self, key: str, **fields: Any) -> str:
        """文言を取り出す。`{}` を含むものは `fields` で埋める。"""
        template = self._messages[key]
        return template.format(**fields) if fields else template


def catalog(lang: str = DEFAULT_LANG) -> Catalog:
    """指定した言語のカタログを返す。未対応の言語なら `ValueError`。"""
    return Catalog(lang)


def message_keys(lang: str) -> frozenset[str]:
    """カタログが持つキーの集合（言語間のずれを検出するテスト用）。"""
    return frozenset(_CATALOGS[lang])


def raw_message(lang: str, key: str) -> str:
    """差し込み前のテンプレート文字列（言語間のずれを検出するテスト用）。"""
    return _CATALOGS[lang][key]
