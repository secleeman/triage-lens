"""優先度の判定ロジック。

閾値はこのモジュールの定数に集約する。将来（Phase 2 以降）に設定可能にできるよう、
判定関数は閾値を引数でも受け取れるようにしてある。

理由の説明文は言語ごとに変わるため、文言は `i18n` に置き、ここでは
`lang` を受け取って組み立てるだけにする。
"""

from collections.abc import Iterable, Mapping

from .i18n import DEFAULT_LANG, Catalog, catalog
from .models import EnrichedVulnerability, Priority, Vulnerability

#: EPSS（今後30日間に悪用される確率）が「高い」と見なす下限
EPSS_THRESHOLD = 0.1

#: CVSS（深刻度スコア）が「高い」と見なす下限
CVSS_THRESHOLD = 7.0


def format_epss(epss: float | None, lang: str = DEFAULT_LANG) -> str:
    """EPSS を表示用の文字列にする。"""
    return catalog(lang)("unknown") if epss is None else f"{epss:.3f}"


def format_cvss(cvss: float | None, lang: str = DEFAULT_LANG) -> str:
    """CVSS を表示用の文字列にする。"""
    return catalog(lang)("unknown") if cvss is None else f"{cvss:.1f}"


def format_kev(in_kev: bool | None, lang: str = DEFAULT_LANG) -> str:
    """KEV 掲載有無を表示用の文字列にする。"""
    text = catalog(lang)
    if in_kev is None:
        return text("unknown")
    return text("kev_yes") if in_kev else text("kev_no")


def _epss_clause(text: Catalog, epss: float | None, high: bool) -> str:
    """EPSS の状態を表す語。取得できていない値を「低い」と書かないためのもの。"""
    if epss is None:
        return text("clause_epss_unknown")
    return text("clause_epss_high") if high else text("clause_epss_low")


def _cvss_clause(text: Catalog, cvss: float | None, high: bool) -> str:
    """CVSS の状態を表す語。取得できていない値を「中以下」と書かないためのもの。"""
    if cvss is None:
        return text("clause_cvss_unknown")
    return text("clause_cvss_high") if high else text("clause_cvss_low")


def classify(
    vuln: Vulnerability,
    epss: float | None,
    in_kev: bool | None,
    *,
    epss_threshold: float = EPSS_THRESHOLD,
    cvss_threshold: float = CVSS_THRESHOLD,
    lang: str = DEFAULT_LANG,
) -> tuple[Priority, str]:
    """1件の脆弱性を P0〜P3 に分類し、その理由の説明文を返す。"""
    text = catalog(lang)
    cvss = vuln.cvss

    if in_kev:
        return Priority.P0, text("reason_kev")

    high_epss = epss is not None and epss >= epss_threshold
    high_cvss = cvss is not None and cvss >= cvss_threshold

    epss_text = format_epss(epss, lang)
    cvss_text = format_cvss(cvss, lang)
    epss_clause = _epss_clause(text, epss, high_epss)
    cvss_clause = _cvss_clause(text, cvss, high_cvss)

    if high_epss and high_cvss:
        priority = Priority.P1
        reason = text("reason_p1", epss=epss_text, cvss=cvss_text)
    elif high_cvss:
        priority = Priority.P2
        reason = text("reason_p2_cvss", cvss=cvss_text, epss=epss_text, epss_clause=epss_clause)
    elif high_epss:
        priority = Priority.P2
        reason = text("reason_p2_epss", epss=epss_text, cvss=cvss_text, cvss_clause=cvss_clause)
    else:
        priority = Priority.P3
        reason = text(
            "reason_p3",
            epss_clause=epss_clause,
            cvss_clause=cvss_clause,
            epss=epss_text,
            cvss=cvss_text,
        )

    notes = []
    if in_kev is None:
        notes.append(text("note_kev_missing"))
    if epss is None:
        notes.append(text("note_epss_missing"))
    if cvss is None:
        notes.append(text("note_cvss_missing"))
    if notes:
        reason = text("notes_wrapper", reason=reason, notes=text("notes_separator").join(notes))

    return priority, reason


def sort_key(item: EnrichedVulnerability) -> tuple[int, float, float, str, str, str]:
    """同一ランク内は EPSS 降順 → CVSS 降順。値が不明なものは末尾に置く。"""
    epss = item.epss if item.epss is not None else -1.0
    cvss = item.vuln.cvss if item.vuln.cvss is not None else -1.0
    return (
        item.priority.value,
        -epss,
        -cvss,
        item.vuln.cve_id,
        item.vuln.pkg_name,
        item.vuln.target,
    )


def prioritize(
    vulnerabilities: Iterable[Vulnerability],
    epss_scores: Mapping[str, float],
    kev_ids: set[str] | None,
    *,
    epss_threshold: float = EPSS_THRESHOLD,
    cvss_threshold: float = CVSS_THRESHOLD,
    lang: str = DEFAULT_LANG,
) -> list[EnrichedVulnerability]:
    """脆弱性一覧に公開データを突き合わせ、優先度順に並べて返す。

    `kev_ids` が None の場合は KEV 情報が取得できなかったことを意味し、
    KEV 掲載有無は「不明」として扱う。
    """
    enriched = [
        EnrichedVulnerability(
            vuln=vuln,
            epss=epss_scores.get(vuln.cve_id),
            in_kev=None if kev_ids is None else vuln.cve_id in kev_ids,
            priority=priority,
            reason=reason,
        )
        for vuln in vulnerabilities
        for priority, reason in [
            classify(
                vuln,
                epss_scores.get(vuln.cve_id),
                None if kev_ids is None else vuln.cve_id in kev_ids,
                epss_threshold=epss_threshold,
                cvss_threshold=cvss_threshold,
                lang=lang,
            )
        ]
    ]
    return sorted(enriched, key=sort_key)


def count_by_priority(items: Iterable[EnrichedVulnerability]) -> dict[Priority, int]:
    """優先度ごとの件数を返す（0件のランクも含む）。"""
    counts = dict.fromkeys(Priority, 0)
    for item in items:
        counts[item.priority] += 1
    return counts
