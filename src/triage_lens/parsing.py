"""入力を読むときの共通処理。

Trivy JSON と CycloneDX で共通の「入力を読む」「値を安全に取り出す」部分を
ここにまとめる。形式ごとの解釈は各モジュール（`trivy` / `cyclonedx`）に置く。

入力元はファイルと標準入力の2つがあるが、読み終えたあとの扱いは同じにする
（同じ中身なら、どちらから来ても同じレポートになる）。
"""

import json
import math
import re
import sys
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any

from .errors import InputError
from .models import Vulnerability

#: 確実に大小を比較できるバージョン表記（数字とドットだけ）
SIMPLE_VERSION = re.compile(r"\d+(?:\.\d+)*")

#: 入力パスにこれを指定すると標準入力から読む（UNIX の慣習に合わせる）
STDIN_PATH = "-"

#: エラー文で標準入力を指すときの表記
STDIN_LABEL = "標準入力"


def read_json_document(path: str | Path) -> Any:
    """JSON を読み込んでパース結果を返す。

    入力パスが `-` なら標準入力から読む。読めない・JSON として壊れている
    場合は `InputError` を送出する（利用者にスタックトレースを見せないため）。
    """
    if str(path) == STDIN_PATH:
        return _parse_json(read_stdin_text(), STDIN_LABEL)
    return _parse_json(_read_file_text(Path(path)), str(path))


def read_stdin_text() -> str:
    """標準入力を最後まで読み切って返す。

    読み切ることが仕様上の要件になる。Trivy の output mode は
    スキャン結果を標準入力で渡してくるが、受け取り側が読み切る前に終了すると
    Trivy がハングする。途中で諦めず、まず全部読んでから中身を判断する。

    文字コードの解釈も自分で行う（`sys.stdin` のテキスト層に任せると、
    端末の文字コード設定によって読めたり読めなかったりする）。
    """
    stream = getattr(sys.stdin, "buffer", None)
    if stream is None:
        raise InputError("標準入力を読み込めませんでした（標準入力がありません）")

    if _is_interactive(sys.stdin):
        # 読みにいくと EOF を待って止まり、利用者にはハングしたように見える。
        raise InputError(
            "標準入力から読む指定（-）ですが、データが渡されていません。"
            "`trivy image --format json <対象> | triage-lens report -` のように"
            "パイプでつないでください。"
        )

    try:
        raw = stream.read()
    except OSError as exc:
        raise InputError(f"標準入力を読み込めませんでした（{exc}）") from exc

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(
            "標準入力を UTF-8 のテキストとして読み込めませんでした"
            "（テキストではないデータが渡されていませんか）"
        ) from exc


def _is_interactive(stream: Any) -> bool:
    """端末に繋がっているか。判断できない場合はパイプ扱いにする。"""
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError, ValueError):
        return False


def _read_file_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InputError(f"入力ファイルが見つかりません: {path}") from exc
    except UnicodeDecodeError as exc:
        raise InputError(
            f"入力ファイルを UTF-8 のテキストとして読み込めませんでした: {path}"
            "（テキストではないファイルを指定していませんか）"
        ) from exc
    except OSError as exc:
        raise InputError(f"入力ファイルを読み込めませんでした: {path} ({exc})") from exc


def _parse_json(raw: str, source: str) -> Any:
    """読み込んだテキストを JSON として解釈する。`source` はエラー文に出す入力元。"""
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputError(
            f"JSON として読み込めませんでした: {source} （{exc.msg} / {exc.lineno}行目）"
        ) from exc
    except RecursionError as exc:
        # 入れ子が深すぎる JSON。放っておくとトレースバックが利用者に出てしまう。
        raise InputError(
            f"JSON の入れ子が深すぎて読み込めませんでした: {source}"
            "（スキャナの出力ではないファイルを指定していませんか）"
        ) from exc


def as_text(value: Any, fallback: str) -> str:
    """空でない文字列ならそのまま、そうでなければ `fallback`。"""
    return value if isinstance(value, str) and value else fallback


def as_optional_text(value: Any) -> str | None:
    """空でない文字列ならそのまま、そうでなければ None。"""
    return value if isinstance(value, str) and value else None


def as_cvss_score(value: Any) -> float | None:
    """CVSS スコアとして妥当な値だけを返す（NaN / 無限大 / 範囲外は無効）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    score = float(value)
    if not math.isfinite(score) or score < 0.0 or score > 10.0:
        return None
    return score


def deduplicate(vulnerabilities: Iterable[Vulnerability]) -> list[Vulnerability]:
    """完全に同一の検出（`dedupe_key` が一致）を1件にまとめる。

    まとめるときに **CVSS は高い方を残す**。同じ検出が違うスコアで2回現れたとき
    （SBOM を結合した場合など）、先に来た方を無条件に採用すると、低いスコアが
    残って実態より安全に見えてしまう。危険なものを安全に見せない側に倒す。

    修正バージョンが食い違う場合の扱いは `_merge_fixed_version` を参照。

    EPSS はここでは扱わない。EPSS は CVE ID だけを鍵に後から引き当てる値で、
    CVE ID は `dedupe_key` に含まれるため、まとめた結果がどちらになっても
    同じ値になる（食い違いようがない）。

    元の並び順は保つ（最初に現れた位置に残す）。
    """
    kept: dict[tuple[str, str, str, str], Vulnerability] = {}
    for vuln in vulnerabilities:
        existing = kept.get(vuln.dedupe_key)
        kept[vuln.dedupe_key] = vuln if existing is None else _merge(existing, vuln)
    return list(kept.values())


def _merge(kept: Vulnerability, duplicate: Vulnerability) -> Vulnerability:
    """重複した2件から、リスクを過小に見せない1件を作る。"""
    cvss = _higher_score(kept.cvss, duplicate.cvss)
    fixed_version, fixed_version_known = _merge_fixed_version(kept, duplicate)
    # 片方でも本番依存なら本番依存にする。本番のものを「開発だけ」に寄せると
    # 見落としになるが、逆は多めに出るだけで見落としにはならない。
    dev_only = kept.dev_only and duplicate.dev_only

    unchanged = (kept.cvss, kept.fixed_version, kept.fixed_version_known, kept.dev_only)
    if (cvss, fixed_version, fixed_version_known, dev_only) == unchanged:
        return kept
    return replace(
        kept,
        cvss=cvss,
        fixed_version=fixed_version,
        fixed_version_known=fixed_version_known,
        dev_only=dev_only,
    )


def _higher_score(kept: float | None, duplicate: float | None) -> float | None:
    """高い方のスコア。None は「情報が無い」扱いで、値がある方を優先する。"""
    if kept is None:
        return duplicate
    if duplicate is None:
        return kept
    return max(kept, duplicate)


def _merge_fixed_version(kept: Vulnerability, duplicate: Vulnerability) -> tuple[str | None, bool]:
    """修正バージョンをまとめて `(修正版, 有無が分かっているか)` を返す。

    優先順位は次のとおり。

    1. 「不明」（`fixed_version_known` が False）より、何か言えている方を採る
    2. 片方だけ版数がある（もう片方は「修正版なし」）なら、版数がある方を採る
    3. 両方に版数があって食い違うなら、比較して新しい方を採る
    4. 比較できない形式なら「不明」に倒す。どちらが正しいか決められないまま
       片方を表示すると、誤った修正版へ誘導してしまうため
    """
    if not kept.fixed_version_known:
        return duplicate.fixed_version, duplicate.fixed_version_known
    if not duplicate.fixed_version_known:
        return kept.fixed_version, kept.fixed_version_known

    if kept.fixed_version == duplicate.fixed_version:
        return kept.fixed_version, True
    if kept.fixed_version is None:
        return duplicate.fixed_version, True
    if duplicate.fixed_version is None:
        return kept.fixed_version, True

    newer = _newer_version(kept.fixed_version, duplicate.fixed_version)
    if newer is None:
        return None, False
    return newer, True


def _newer_version(kept: str, duplicate: str) -> str | None:
    """新しい方のバージョン文字列。比較できない形式なら None。"""
    return newest_version((kept, duplicate))


def newest_version(versions: Iterable[str]) -> str | None:
    """与えられたバージョンのうち最も新しいもの。比較できない形式が混ざれば None。

    「1つでも比較できない形式が混ざったら None」にしているのは、`1:1.2.11.dfsg-2+deb11u2`
    のような表記を独自に解釈すると、**古い版を「新しい方」として選びかねない**ため。
    どれが新しいか決められないなら、決めない。

    値が1つだけのときは、その形式が比較できるかに関わらずそのまま返す。
    比較する相手がいなければ、誤った大小関係を作りようがない。
    """
    unique = list(dict.fromkeys(versions))
    if not unique:
        return None
    if len(unique) == 1:
        return unique[0]

    parsed = [(_version_parts(version), version) for version in unique]
    if any(parts is None for parts, _ in parsed):
        return None

    width = max(len(parts) for parts, _ in parsed)
    return max(parsed, key=lambda item: item[0] + (0,) * (width - len(item[0])))[1]


def _version_parts(version: str) -> tuple[int, ...] | None:
    """`1.2.10` のような数字と区切りだけのバージョンを比較用の組にする。

    Debian の `1:1.2.11.dfsg-2+deb11u2` や CycloneDX の範囲表記 `>=1.0.1g-1` は
    形式がまちまちで、独自に解釈すると誤った大小関係を作りかねない。
    確実に比較できる形だけを対象にし、それ以外は比較不能として扱う。
    """
    if not SIMPLE_VERSION.fullmatch(version):
        return None
    return tuple(int(part) for part in version.split("."))
