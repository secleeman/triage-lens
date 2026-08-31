"""標準入力からの読み込みの検証。

Trivy の output mode はスキャン結果を標準入力で渡してくる。守るべきことは2つ。

- ファイル経由と標準入力経由で、同じ入力からは同じレポートが出ること
- 成功時も失敗時も標準入力を読み切ってから終わること
  （読み切る前に終了すると Trivy がハングする、と公式ガイドが明記している）
"""

import io
from datetime import datetime

import pytest

from conftest import make_client
from test_cli import _handler
from triage_lens import cli
from triage_lens.cli import EXIT_INPUT_ERROR, EXIT_OK, main


class FakeStdin:
    """`sys.stdin` の差し替え。実装が使う `buffer` と `isatty` だけを持つ。"""

    def __init__(self, data: bytes, *, tty: bool = False) -> None:
        self.buffer = io.BytesIO(data)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def drained(self) -> bool:
        """最後まで読まれたか。"""
        return self.buffer.read() == b""


@pytest.fixture
def fixed_now(monkeypatch):
    """生成日時を固定する。2つの経路の出力を1文字も違わずに突き合わせるため。"""

    class Clock:
        @staticmethod
        def now() -> datetime:
            return datetime(2026, 8, 30, 12, 0)

    monkeypatch.setattr(cli, "datetime", Clock)


def _report_from_file(source, output, client) -> str:
    main(["report", str(source), "-o", str(output)], client=client)
    return output.read_text(encoding="utf-8")


def _report_from_stdin(source, output, client, monkeypatch) -> tuple[str, FakeStdin]:
    stdin = FakeStdin(source.read_bytes())
    monkeypatch.setattr("sys.stdin", stdin)
    main(["report", "-", "-o", str(output)], client=client)
    return output.read_text(encoding="utf-8"), stdin


@pytest.mark.parametrize(
    "fixture_name",
    ["trivy_sample.json", "cyclonedx_sample.json", "spdx_sample.json"],
)
def test_標準入力とファイルで同じレポートになる(
    fixture_name, fixtures_dir, tmp_path, monkeypatch, fixed_now
):
    """入力元が変わってもレポートは変わらない。形式の自動判別も経路に依存しない。"""
    source = fixtures_dir / fixture_name

    with make_client(_handler) as client:
        from_file = _report_from_file(source, tmp_path / "file.md", client)
    with make_client(_handler) as client:
        from_stdin, _ = _report_from_stdin(source, tmp_path / "stdin.md", client, monkeypatch)

    assert from_stdin == from_file


def test_標準入力から読んだレポートが空でない(fixtures_dir, tmp_path, monkeypatch, fixed_now):
    """一致だけを見ると、両方とも空でも通ってしまうため中身も確かめる。"""
    with make_client(_handler) as client:
        report, _ = _report_from_stdin(
            fixtures_dir / "trivy_sample.json", tmp_path / "out.md", client, monkeypatch
        )

    assert report.startswith("# 脆弱性トリアージレポート")
    assert "- 対象: sample-app:1.4.0" in report
    assert "検出総数: 13件" in report


def test_成功しても標準入力を読み切る(fixtures_dir, tmp_path, monkeypatch, fixed_now):
    with make_client(_handler) as client:
        _, stdin = _report_from_stdin(
            fixtures_dir / "trivy_sample.json", tmp_path / "out.md", client, monkeypatch
        )

    assert stdin.drained()


@pytest.mark.parametrize(
    ("data", "expected_message"),
    [
        (b"{ this is not json", "JSON として読み込めませんでした"),
        (b"{}", "Trivy の JSON 出力ではないようです"),
        (b"", "JSON として読み込めませんでした"),
    ],
    ids=["壊れたJSON", "対応形式でない", "空の入力"],
)
def test_失敗しても標準入力を読み切る(data, expected_message, monkeypatch, capsys):
    """ここが本命。読み切る前に終了すると Trivy が待ち続ける。"""
    stdin = FakeStdin(data)
    monkeypatch.setattr("sys.stdin", stdin)

    code = main(["report", "-"])

    assert code == EXIT_INPUT_ERROR
    assert stdin.drained(), "標準入力を読み切らずに終了している"
    assert expected_message in capsys.readouterr().err


def test_エラー文が標準入力を指す(monkeypatch, capsys):
    """ファイル名の位置に `-` とだけ出ると、何が起きたのか分からない。"""
    monkeypatch.setattr("sys.stdin", FakeStdin(b"{ broken"))

    main(["report", "-"])

    assert "標準入力" in capsys.readouterr().err


def test_端末から呼ばれたらハングせずに使い方を示す(monkeypatch, capsys):
    """パイプ無しで `-` を渡すと EOF 待ちで止まる。利用者にはハングに見える。"""
    stdin = FakeStdin(b"", tty=True)
    monkeypatch.setattr("sys.stdin", stdin)

    code = main(["report", "-"])

    error = capsys.readouterr().err
    assert code == EXIT_INPUT_ERROR
    assert "パイプでつないでください" in error


def test_テキストでない標準入力は入力エラーになる(monkeypatch, capsys):
    stdin = FakeStdin(b"\xff\xfe\x00\x01binary")
    monkeypatch.setattr("sys.stdin", stdin)

    code = main(["report", "-"])

    assert code == EXIT_INPUT_ERROR
    assert "UTF-8 のテキストとして読み込めませんでした" in capsys.readouterr().err
    assert stdin.drained()


def test_標準入力でもfail_onが効く(fixtures_dir, tmp_path, monkeypatch, fixed_now):
    """output mode から使うとき、判定が経路によって変わらないことを確かめる。"""
    stdin = FakeStdin((fixtures_dir / "trivy_sample.json").read_bytes())
    monkeypatch.setattr("sys.stdin", stdin)

    with make_client(_handler) as client:
        code = main(
            ["report", "-", "-o", str(tmp_path / "out.md"), "--fail-on", "p0"], client=client
        )

    assert code != EXIT_OK


def test_ファイル名としての単独ハイフンは受け付けない(tmp_path, monkeypatch, capsys):
    """`-` という名前のファイルがあっても、標準入力の指定として扱う。

    どちらとも取れる指定を黙って選ぶと、読んだ先が実行するたびに変わりうる。
    """
    (tmp_path / "-").write_text('{"Results": []}', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.stdin", FakeStdin(b"", tty=True))

    code = main(["report", "-"])

    assert code == EXIT_INPUT_ERROR
    assert "パイプでつないでください" in capsys.readouterr().err
