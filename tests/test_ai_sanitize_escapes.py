"""生成文の無害化のうち、バックスラッシュが絡む境界だけをまとめたテスト。

`\\` を含む文字列はエスケープが読みにくいので、`chr(92)` で組み立てて
「実際に何文字のバックスラッシュか」を明示している。
"""

from triage_lens.ai import sanitize

BS = chr(92)  # バックスラッシュ1文字


def test_元からあるバックスラッシュを先に潰す():
    # 生成文が `\[x\](url)` だった場合。バックスラッシュを後から潰すと
    # `\\[` になり、CommonMark では「リテラルの \」＋「生きた [」になってしまう
    source = f"{BS}[x{BS}](http://example.test)"

    cleaned = sanitize(source)

    # `\\`（リテラルの \）のあとが `\[`（リテラルの [）になっていること
    assert cleaned == f"{BS * 3}[x{BS * 3}](http://example.test)"
    assert cleaned.startswith(BS * 2 + BS + "[")


def test_バックスラッシュ単体もリテラルとして出す():
    assert sanitize(f"C:{BS}path") == f"C:{BS * 2}path"


def test_バックスラッシュ付きのコード記法も無効化する():
    assert sanitize(f"{BS}`cmd{BS}`") == f"{BS * 3}`cmd{BS * 3}`"


def test_バックスラッシュ付きの縦棒も無効化する():
    assert sanitize(f"a{BS}|b") == f"a{BS * 3}|b"


def test_普通の文はそのまま通る():
    text = "修正版 1.1.1n に更新してください。影響範囲は依存関係を確認のこと。"

    assert sanitize(text) == text
    assert BS not in sanitize(text)


def test_上限は無害化した後の長さで守る():
    # `<` は `&lt;` に膨らむ。切り詰めを先にやると上限を大きく超える
    cleaned = sanitize("<" * 200, max_length=40)

    assert len(cleaned) <= 40
    assert cleaned.endswith("…")
    # エスケープの途中で切れていない
    assert "&lt" not in cleaned.replace("&lt;", "")


def test_バックスラッシュの連続でも上限を超えない():
    cleaned = sanitize(BS * 300, max_length=50)

    assert len(cleaned) <= 50
    # 2文字1組のエスケープが割れていない
    assert cleaned.count(BS) % 2 == 0
