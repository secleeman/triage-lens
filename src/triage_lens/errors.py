"""triage-lens の例外定義。"""


class TriageLensError(Exception):
    """triage-lens が送出する例外の基底クラス。"""


class InputError(TriageLensError):
    """入力ファイルが読めない・想定した形式ではない場合に送出する（終了コード 2）。"""


class FetchError(TriageLensError):
    """外部APIの取得がリトライしても成功しなかった場合に送出する。"""
