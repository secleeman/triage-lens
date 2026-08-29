"""コマンドラインインターフェース。"""

import argparse
import sys
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path

import httpx

from .ai import (
    API_KEY_ENV,
    DEFAULT_LIMIT,
    DEFAULT_MODEL,
    annotate,
    read_api_key,
    read_workspace_id,
    select_targets,
)
from .epss import fetch_epss_scores
from .errors import InputError
from .http_client import build_client
from .i18n import DEFAULT_LANG, SUPPORTED_LANGS
from .kev import SOURCE_STALE_CACHE, SOURCE_UNAVAILABLE, load_kev_ids
from .loader import load_scan
from .models import AiAnnotation, EnrichedVulnerability, Priority, ScanInput
from .report import DEFAULT_TOP_N, render_report
from .scoring import prioritize

#: 正常終了
EXIT_OK = 0

#: `--fail-on` で指定したランク以上の検出があった
EXIT_FAIL_ON = 1

#: 入力ファイルが読めない・想定形式でない
EXIT_INPUT_ERROR = 2

#: `--fail-on-fetch-error` 指定時に、外部データを取得できなかった
EXIT_FETCH_ERROR = 3

#: `--fail-on` に指定できるランク
FAIL_ON_CHOICES = [priority.name.lower() for priority in Priority]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triage-lens",
        description="スキャナの脆弱性リストを公開データで優先順位付けし、トリアージレポートを生成します。",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    report_parser = subparsers.add_parser(
        "report",
        help="スキャナ出力（Trivy JSON / CycloneDX JSON）からトリアージレポート（Markdown）を作る",
    )
    report_parser.add_argument(
        "input",
        help="スキャナ出力のJSONファイル（Trivy の --format json / CycloneDX。形式は自動判別）",
    )
    report_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="出力先のMarkdownファイル（省略時は標準出力）",
    )
    report_parser.add_argument(
        "--top",
        type=_positive_int,
        default=DEFAULT_TOP_N,
        metavar="N",
        help=f"P2 / P3 で表示する件数（既定: {DEFAULT_TOP_N}）",
    )
    report_parser.add_argument(
        "--lang",
        choices=SUPPORTED_LANGS,
        default=DEFAULT_LANG,
        help=f"レポートの言語（既定: {DEFAULT_LANG}）",
    )
    report_parser.add_argument(
        "--fail-on",
        type=str.lower,
        choices=FAIL_ON_CHOICES,
        default=None,
        metavar="RANK",
        help=(
            f"指定したランク以上の検出があれば終了コード {EXIT_FAIL_ON} で終わる"
            f"（{' / '.join(FAIL_ON_CHOICES)}。p3 は実質すべての検出が対象。"
            "既定では指定なしで、常に 0 で終わる）"
        ),
    )
    report_parser.add_argument(
        "--fail-on-fetch-error",
        action="store_true",
        help=(
            f"--fail-on と併用し、EPSS / CISA KEV を取得できなかった場合に"
            f"終了コード {EXIT_FETCH_ERROR} で終わる（既定では警告を出すだけ）"
        ),
    )
    report_parser.add_argument(
        "--ai",
        action="store_true",
        help=f"各CVEにAIが生成した対応方針コメントを付ける（環境変数 {API_KEY_ENV} が必要）",
    )
    report_parser.add_argument(
        "--ai-limit",
        type=_positive_int,
        default=DEFAULT_LIMIT,
        metavar="N",
        help=f"AIコメントを生成する上限件数（既定: {DEFAULT_LIMIT}）",
    )
    report_parser.add_argument(
        "--ai-model",
        default=DEFAULT_MODEL,
        metavar="NAME",
        help=f"AIコメントの生成に使うモデル（既定: {DEFAULT_MODEL}）",
    )
    report_parser.set_defaults(handler=run_report)
    return parser


def main(argv: list[str] | None = None, *, client: httpx.Client | None = None) -> int:
    """CLI のエントリポイント。終了コードを返す。"""
    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_options(parser, args)
    try:
        return args.handler(args, client=client)
    except InputError as exc:
        _write_error(f"エラー: {exc}")
        return EXIT_INPUT_ERROR


def _validate_options(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """オプション同士の組み合わせを検査する。

    何も起きないオプションを黙って受け取ると、利用者は「指定したのに
    落ちない」理由に辿り着けない。指定ミスとしてその場で落とす。
    """
    if args.fail_on_fetch_error and args.fail_on is None:
        parser.error("--fail-on-fetch-error は --fail-on と併せて指定してください")


def run_report(args: argparse.Namespace, *, client: httpx.Client | None = None) -> int:
    scan = load_scan(args.input)
    items, epss_complete, kev_source = enrich(scan, client=client, lang=args.lang)

    ai_annotation: AiAnnotation | None = None
    if args.ai:
        items, ai_annotation = add_ai_comments(args, items, client=client)

    report = render_report(
        items,
        artifact_name=scan.artifact_name,
        generated_at=datetime.now(),
        top_n=args.top,
        epss_complete=epss_complete,
        kev_source=kev_source,
        lang=args.lang,
        ai=ai_annotation,
    )
    _write_output(report, args.output)

    # 判定はレポートを書き出し切ってから行う。CI が落ちたときに
    # 原因を見るためのレポートが無い、という状態を作らないため。
    return decide_exit_code(args, items, epss_complete=epss_complete, kev_source=kev_source)


def decide_exit_code(
    args: argparse.Namespace,
    items: list[EnrichedVulnerability],
    *,
    epss_complete: bool,
    kev_source: str,
) -> int:
    """レポート出力後の終了コードを決める。

    `--fail-on` を指定していなければ、従来どおり常に 0 を返す。
    """
    if args.fail_on is None:
        return EXIT_OK

    warnings = fetch_warnings(epss_complete=epss_complete, kev_source=kev_source)
    for warning in warnings:
        _write_error(warning)

    if warnings and args.fail_on_fetch_error:
        # 取得失敗のほうを優先する。欠けたデータで出した判定結果を
        # 「該当あり」として返すと、取得失敗のほうを見落とすため。
        return EXIT_FETCH_ERROR

    threshold = Priority[args.fail_on.upper()]
    if any(item.priority.value <= threshold.value for item in items):
        return EXIT_FAIL_ON
    return EXIT_OK


def fetch_warnings(*, epss_complete: bool, kev_source: str) -> list[str]:
    """取得できなかった外部データについての警告文を並べる。

    レポート本文にも同じことが書かれるが、CI では緑になったログを誰も
    読まない。判定が実際より甘くなっている可能性は標準エラーにも出す。
    """
    warnings = []
    if kev_source == SOURCE_UNAVAILABLE:
        warnings.append(
            "警告: CISA KEV を取得できませんでした。KEV 掲載を根拠とする P0 判定が出ないため、"
            "--fail-on の判定が実際より甘くなっている可能性があります。"
        )
    elif kev_source == SOURCE_STALE_CACHE:
        warnings.append(
            "警告: CISA KEV を再取得できず、期限切れのキャッシュを使いました。"
            "最近 KEV に追加された脆弱性を見落としている可能性があります。"
        )
    if not epss_complete:
        warnings.append(
            "警告: EPSS を一部取得できませんでした。EPSS を根拠とする判定が出ないため、"
            "--fail-on の判定が実際より甘くなっている可能性があります。"
        )
    return warnings


def add_ai_comments(
    args: argparse.Namespace,
    items: list[EnrichedVulnerability],
    *,
    client: httpx.Client | None = None,
) -> tuple[list[EnrichedVulnerability], AiAnnotation | None]:
    """AIコメントを付ける。何が起きてもレポートは出す（終了コードも変えない）。

    生成しなかった / できなかったことは標準エラーに1行だけ書く。黙って機能が
    消えると「静かに壊れた」状態になり、利用者が理由に辿り着けないため。
    """
    api_key = read_api_key()
    if api_key is None:
        _write_error(f"{API_KEY_ENV} が未設定のためAIコメントをスキップしました。")
        return list(items), None

    targets = select_targets(items, limit=args.ai_limit)
    if not targets:
        _write_error("AIコメントの対象となる P0 / P1 の検出がないため、生成しませんでした。")
        return list(items), None

    _write_error(f"{len(targets)}件に対してAIコメントを生成します（モデル: {args.ai_model}）。")

    with ExitStack() as stack:
        ai_client = client if client is not None else stack.enter_context(build_client())
        annotated, annotation = annotate(
            items,
            api_key=api_key,
            lang=args.lang,
            model=args.ai_model,
            limit=args.ai_limit,
            workspace_id=read_workspace_id(),
            client=ai_client,
        )

    if annotation is None:
        _write_error("AIコメントを生成できませんでした。AIコメント無しでレポートを出力します。")
    return annotated, annotation


def enrich(
    scan: ScanInput, *, client: httpx.Client | None = None, lang: str = DEFAULT_LANG
) -> tuple[list[EnrichedVulnerability], bool, str]:
    """公開データを引き当てて優先度を付ける。取得できなくても処理は継続する。"""
    if not scan.vulnerabilities:
        return [], True, ""

    with ExitStack() as stack:
        if client is None:
            client = stack.enter_context(build_client())
        kev_ids, kev_source = load_kev_ids(client=client)
        epss_scores, epss_complete = fetch_epss_scores(
            [vuln.cve_id for vuln in scan.vulnerabilities], client=client
        )

    items = prioritize(scan.vulnerabilities, epss_scores, kev_ids, lang=lang)
    return items, epss_complete, kev_source


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"整数を指定してください: {value}") from None
    if number < 0:
        raise argparse.ArgumentTypeError(f"0以上の整数を指定してください: {value}")
    return number


def _write_output(text: str, output: str | None) -> None:
    if output:
        path = Path(output)
        try:
            if path.parent != Path(""):
                path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise InputError(f"出力ファイルに書き込めませんでした: {path} ({exc})") from exc
        return

    _write_stream(sys.stdout, text)


def _write_error(message: str) -> None:
    _write_stream(sys.stderr, message + "\n")


def _write_stream(stream, text: str) -> None:
    """端末の文字コードが日本語を扱えない場合でも落ちないように書き出す。"""
    try:
        stream.write(text)
    except UnicodeEncodeError:
        buffer = getattr(stream, "buffer", None)
        if buffer is None:
            stream.write(text.encode("utf-8", "replace").decode("ascii", "replace"))
        else:
            buffer.write(text.encode("utf-8"))
            buffer.flush()
