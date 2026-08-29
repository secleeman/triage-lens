"""コマンドラインインターフェース。"""

import argparse
import sys
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path

import httpx

from .epss import fetch_epss_scores
from .errors import InputError
from .http_client import build_client
from .i18n import DEFAULT_LANG, SUPPORTED_LANGS
from .kev import load_kev_ids
from .loader import load_scan
from .models import EnrichedVulnerability, ScanInput
from .report import DEFAULT_TOP_N, render_report
from .scoring import prioritize

#: 正常終了
EXIT_OK = 0

#: 入力ファイルが読めない・想定形式でない
EXIT_INPUT_ERROR = 2


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
    report_parser.set_defaults(handler=run_report)
    return parser


def main(argv: list[str] | None = None, *, client: httpx.Client | None = None) -> int:
    """CLI のエントリポイント。終了コードを返す。"""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args, client=client)
    except InputError as exc:
        _write_error(f"エラー: {exc}")
        return EXIT_INPUT_ERROR


def run_report(args: argparse.Namespace, *, client: httpx.Client | None = None) -> int:
    scan = load_scan(args.input)
    items, epss_complete, kev_source = enrich(scan, client=client, lang=args.lang)
    report = render_report(
        items,
        artifact_name=scan.artifact_name,
        generated_at=datetime.now(),
        top_n=args.top,
        epss_complete=epss_complete,
        kev_source=kev_source,
        lang=args.lang,
    )
    _write_output(report, args.output)
    return EXIT_OK


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
