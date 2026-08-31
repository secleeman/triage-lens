#!/usr/bin/env python3
"""Trivy のプラグインとして triage-lens を呼び出すラッパー。

Trivy からの呼ばれ方は2通りある。

1. サブコマンド

       trivy triage-lens <対象> [triage-lens のオプション]

   Trivy はこのファイルを引数付きで起動するだけで、スキャンは行わない。
   このラッパーが内部で `trivy image --format json <対象>` を実行し、
   その出力を triage-lens に渡す。

2. output モード

       trivy image --format json --output plugin=triage-lens \
           --output-plugin-arg "<triage-lens のオプション>" <対象>

   Trivy がスキャン結果を標準入力で渡してくる。`--output-plugin-arg` の
   中身だけが引数として渡り、対象名は渡ってこない。

見分け方は「最初の引数が `-` で始まらないか」。始まらなければ、それを
スキャン対象とみなしてサブコマンドとして動く。始まる場合と引数が無い場合は
output モードとして標準入力を読む。

依存は標準ライブラリだけにする。triage-lens が入っていない環境でも
このファイル自身は動いて、入れ方を案内できる必要があるため。
"""

import os
import shutil
import subprocess
import sys

#: 呼び出す triage-lens の実行ファイル名
TRIAGE_LENS = "triage-lens"

#: 内部でスキャンするときに呼ぶ Trivy の実行ファイル名
TRIVY = "trivy"

#: このラッパー自身の問題で終わるときの終了コード。
#: triage-lens 本体の終了コード（0 / 1 / 2 / 3）と意味を揃えてある。
EXIT_PLUGIN_ERROR = 2

#: 自分自身を呼び出していないかを見るための環境変数。
#: Trivy の設定ファイル（trivy.yaml）に output plugin が書かれていると、
#: 内部で呼んだ Trivy がこのプラグインを呼び返して止まらなくなる。
RECURSION_ENV = "TRIAGE_LENS_PLUGIN_RUNNING"

#: `report -` に対応した最初の版。これより古いと標準入力を渡せない。
REQUIRED_VERSION = "0.8.0"

USAGE = f"""triage-lens - スキャン結果を CISA KEV / EPSS / CVSS で優先順位付けする

使い方:
  trivy triage-lens <対象> [オプション]
      対象をスキャンして、そのままトリアージレポートにする。

  trivy image --format json --output plugin=triage-lens \\
      --output-plugin-arg "<オプション>" <対象>
      すでに走っているスキャンの出力を受け取ってレポートにする。

オプションは triage-lens report のものがそのまま使える
（-o / --lang / --top / --fail-on / --ai など）。詳しくは:

  {TRIAGE_LENS} report --help
"""


def main(argv: list[str]) -> int:
    if argv and argv[0] in ("-h", "--help", "help"):
        sys.stdout.write(USAGE)
        return 0

    triage_lens = shutil.which(TRIAGE_LENS)
    if triage_lens is None:
        return _fail(_missing_triage_lens_message())

    # 対象名が来ていればサブコマンド、来ていなければ output モード。
    if argv and not argv[0].startswith("-"):
        target, options = argv[0], argv[1:]
        scan = _scan(target)
        if scan is None:
            return EXIT_PLUGIN_ERROR
    else:
        target, options = None, argv
        scan = _read_stdin()
        if scan is None:
            return EXIT_PLUGIN_ERROR

    return _report(triage_lens, options, scan)


def _scan(target: str) -> bytes | None:
    """対象をスキャンして Trivy の JSON を返す。失敗したら None。"""
    if os.environ.get(RECURSION_ENV) == "1":
        # 内部で呼んだ Trivy がこのプラグインを呼び返している。
        # 放っておくと呼び合いが止まらないので、ここで断ち切る。
        _write_error(
            "triage-lens プラグインが自分自身を呼び出しています。"
            "Trivy の設定ファイルで output plugin に triage-lens を指定していないか"
            "確認してください。"
        )
        return None

    trivy = shutil.which(TRIVY)
    if trivy is None:
        _write_error(
            f"{TRIVY} が見つかりません。"
            "対象を渡してスキャンから行うには Trivy が PATH 上にある必要があります。"
        )
        return None

    environment = dict(os.environ)
    environment[RECURSION_ENV] = "1"

    # `--output plugin=` は絶対に付けない。付けるとこのプラグインが呼び返される。
    command = [trivy, "image", "--format", "json", "--", target]
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, env=environment, check=False)
    except OSError as exc:
        _write_error(f"{TRIVY} を実行できませんでした（{exc}）")
        return None

    if completed.returncode != 0:
        _write_error(f"{TRIVY} のスキャンが失敗しました（終了コード {completed.returncode}）")
        return None
    if not completed.stdout.strip():
        _write_error(f"{TRIVY} がスキャン結果を出力しませんでした")
        return None

    return completed.stdout


def _read_stdin() -> bytes | None:
    """標準入力を最後まで読み切る。

    読み切る前に終了すると Trivy がハングする、と公式ガイドが明記している。
    後段の triage-lens が失敗しても読み残しが起きないよう、渡す前にここで
    すべて読んでしまう。
    """
    stream = getattr(sys.stdin, "buffer", None)
    if stream is None:
        _write_error("標準入力を読み込めませんでした（標準入力がありません）")
        return None

    try:
        interactive = bool(sys.stdin.isatty())
    except (AttributeError, OSError, ValueError):
        interactive = False
    if interactive:
        # 読みにいくと EOF を待って止まり、利用者にはハングしたように見える。
        _write_error("スキャン結果が渡されていません。\n\n" + USAGE)
        return None

    try:
        return stream.read()
    except OSError as exc:
        _write_error(f"標準入力を読み込めませんでした（{exc}）")
        return None


def _report(triage_lens: str, options: list[str], scan: bytes) -> int:
    """triage-lens にスキャン結果を渡す。終了コードはそのまま返す。

    `--fail-on` を付けた利用者が、プラグイン経由でも同じ終了コードを
    受け取れるようにする。
    """
    command = [triage_lens, "report", "-", *options]
    try:
        completed = subprocess.run(command, input=scan, check=False)
    except OSError as exc:
        return _fail(f"{TRIAGE_LENS} を実行できませんでした（{exc}）")
    return completed.returncode


def _missing_triage_lens_message() -> str:
    return (
        f"{TRIAGE_LENS} が見つかりません。このプラグインは PATH 上の "
        f"{TRIAGE_LENS} を呼び出します。次のいずれかで入れてください。\n"
        f"\n"
        f"  pip install 'triage-lens>={REQUIRED_VERSION}'\n"
        f"  pipx install 'triage-lens>={REQUIRED_VERSION}'\n"
        f"\n"
        f"標準入力からの読み込みに対応したのは {REQUIRED_VERSION} からです。"
        f"すでに入っている場合は版を上げてください。"
    )


def _fail(message: str) -> int:
    _write_error(message)
    return EXIT_PLUGIN_ERROR


def _write_error(message: str) -> None:
    """端末の文字コードが日本語を扱えない場合でも落ちないように書き出す。"""
    text = f"エラー: {message}\n"
    try:
        sys.stderr.write(text)
    except UnicodeEncodeError:
        buffer = getattr(sys.stderr, "buffer", None)
        if buffer is None:
            sys.stderr.write(text.encode("utf-8", "replace").decode("ascii", "replace"))
        else:
            buffer.write(text.encode("utf-8"))
            buffer.flush()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
