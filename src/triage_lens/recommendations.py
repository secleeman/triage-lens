"""パッケージ単位の推奨アクションの組み立て。

検出は CVE ごとに並ぶが、実際の作業は「このパッケージをこの版に上げる」であり、
1つのパッケージが5件のCVEで出てきても作業は1回で済む。ここでは検出をパッケージ単位に
畳み直し、「どれをどこまで上げれば何件片付くか」を1行にまとめる。

優先度そのものには一切触れない。ここで作るのは並べ替えと集約だけで、P0〜P3 の判定は
`scoring` が出した結果をそのまま使う。
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from .models import EnrichedVulnerability, Priority
from .parsing import newest_version


@dataclass(frozen=True)
class Recommendation:
    """1つのパッケージ（同じ現在バージョン）に対する推奨アクション。"""

    pkg_name: str
    installed_version: str
    #: 上げ先。決められないときは None
    fixed_version: str | None
    #: 上げ先が決められないとき、それが「修正版が無い」ためか「分からない」ためか。
    #: `fixed_version` が None のときだけ意味を持つ。
    fixed_version_known: bool
    #: 上げ先へ更新することで解消されるCVEの件数
    resolved: int
    #: 上げても残るCVEの件数（修正版が無い / 分からないもの）
    unresolved: int
    #: 残るCVEに「修正版なし」が含まれるか
    unresolved_has_no_fix: bool
    #: 残るCVEに「不明」が含まれるか
    unresolved_has_unknown: bool
    #: このパッケージの検出のうち最も緊急なランク
    priority: Priority
    #: 本番依存に1件も現れなかった（開発依存でしか使われていない）か
    dev_only: bool

    @property
    def actionable(self) -> bool:
        """上げ先が決まっているか。決まっていない行は表の最後にまとめる。"""
        return self.fixed_version is not None


def build(items: Iterable[EnrichedVulnerability]) -> list[Recommendation]:
    """優先度付きの検出一覧から、推奨アクションの一覧を作る。

    集約の単位は `(パッケージ名, 現在バージョン)`。検出箇所は跨いでまとめる
    （同じ版が2箇所にあっても作業は1回）。版が違えば上げ先も変わるため別の行にする。

    `--top` による表示件数の絞り込みは**受けない**。表に出ていない検出が、表に出て
    いるパッケージと同じことがあり、切り捨てると解消件数が実際より少なく出るため。
    """
    grouped: dict[tuple[str, str], list[EnrichedVulnerability]] = {}
    for item in items:
        key = (item.vuln.pkg_name, item.vuln.installed_version)
        grouped.setdefault(key, []).append(item)

    recommendations = [_build_one(key, group) for key, group in grouped.items()]
    return sorted(recommendations, key=_sort_key)


def _build_one(key: tuple[str, str], group: Sequence[EnrichedVulnerability]) -> Recommendation:
    pkg_name, installed_version = key

    # 同じCVEが複数の検出箇所で見つかることがある。作業の単位はCVEなので件数はCVE ID で
    # 数え、修正版のほうは読み取れたものをすべて集める（比較できない表記が混ざっていたら
    # 上げ先を決めない、という判断を `newest_version` に任せるため）。
    fixed_versions: list[str] = []
    resolved_cves: set[str] = set()
    #: CVE ID → 「修正版の有無そのものは分かっている」検出が1件でもあったか
    known_by_cve: dict[str, bool] = {}

    for item in group:
        cve_id = item.vuln.cve_id
        known_by_cve[cve_id] = known_by_cve.get(cve_id, False) or item.vuln.fixed_version_known
        if item.vuln.fixed_version is not None:
            fixed_versions.append(item.vuln.fixed_version)
            resolved_cves.add(cve_id)

    unresolved_cves = set(known_by_cve) - resolved_cves
    fixed_version = newest_version(fixed_versions)

    if fixed_version is None:
        # 上げ先が決まらなければ、この表からできることは無い。修正版が読めていたCVEも
        # 「どこまで上げればよいか分からない」側として数える。
        return Recommendation(
            pkg_name=pkg_name,
            installed_version=installed_version,
            fixed_version=None,
            # 修正版を1つも読めておらず、かつ全件が「修正版なし」と分かっているときだけ
            # 「修正版なし」と言い切る。それ以外は「不明」に倒す。
            fixed_version_known=(
                not resolved_cves and all(known_by_cve[cve] for cve in unresolved_cves)
            ),
            resolved=0,
            unresolved=len(known_by_cve),
            unresolved_has_no_fix=any(known_by_cve[cve] for cve in unresolved_cves),
            unresolved_has_unknown=(
                any(not known_by_cve[cve] for cve in unresolved_cves) or bool(resolved_cves)
            ),
            priority=_highest_priority(group),
            dev_only=all(item.vuln.dev_only for item in group),
        )

    return Recommendation(
        pkg_name=pkg_name,
        installed_version=installed_version,
        fixed_version=fixed_version,
        fixed_version_known=True,
        resolved=len(resolved_cves),
        unresolved=len(unresolved_cves),
        unresolved_has_no_fix=any(known_by_cve[cve] for cve in unresolved_cves),
        unresolved_has_unknown=any(not known_by_cve[cve] for cve in unresolved_cves),
        priority=_highest_priority(group),
        dev_only=all(item.vuln.dev_only for item in group),
    )


def _highest_priority(group: Sequence[EnrichedVulnerability]) -> Priority:
    """そのパッケージの検出のうち最も緊急なランク。"""
    return min((item.priority for item in group), key=lambda priority: priority.value)


def _sort_key(recommendation: Recommendation) -> tuple[int, int, int, str, str]:
    """上げ先が決まっている行を先に、次に優先度の高い順、解消件数の多い順。

    上げ先が決まらない行を最後にまとめるのは、そこだけ人手の調査が要るため。
    優先度の高さより先に効かせる（P0 でも上げ先が無ければ、この表からは何もできない）。
    """
    return (
        0 if recommendation.actionable else 1,
        recommendation.priority.value,
        -recommendation.resolved,
        recommendation.pkg_name,
        recommendation.installed_version,
    )
