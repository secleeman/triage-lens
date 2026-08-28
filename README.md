# triage-lens

スキャナ（Trivy）が出力した脆弱性の一覧を、公開データで優先順位付けして、
**「どれから直せばいいか」が分かる日本語のトリアージレポート（Markdown）** にする CLI ツールです。

判定に使う情報:

| データ | 何が分かるか | 出典 |
| --- | --- | --- |
| CISA KEV | 実際に悪用が確認されているか | CISA 公開カタログ |
| EPSS | 今後30日以内に悪用される確率（0〜1） | FIRST.org 公開API |
| CVSS | 深刻度スコア（0〜10） | スキャナ出力に含まれる値 |

いずれも認証キーは不要です。

## 必要なもの

- Python 3.11 以上
- スキャン対象の Trivy JSON 出力（`trivy --format json`）

## インストール

```bash
git clone https://github.com/secleeman/triage-lens.git
cd triage-lens
python -m venv .venv
.venv/bin/pip install .
```

Windows（PowerShell）の場合は最後の行を次に置き換えてください。

```bash
.venv\Scripts\pip install .
```

## 使い方

### 1. Trivy でスキャンして JSON を出す

```bash
trivy image --format json -o trivy-result.json sample-app:1.4.0
```

### 2. トリアージレポートを作る

```bash
triage-lens report trivy-result.json -o triage-report.md
```

`-o` を省略すると標準出力に表示します。

| オプション | 説明 | 既定値 |
| --- | --- | --- |
| `-o`, `--output` | 出力先の Markdown ファイル | 標準出力 |
| `--top N` | P2 / P3 で表示する件数（P0 / P1 は常に全件） | 5 |

## 出力例

```markdown
# 脆弱性トリアージレポート

- 対象: sample-app:1.4.0
- 生成日時: 2026-08-28 22:06
- 判定基準: CISA KEV 掲載 / EPSS 0.1 以上 / CVSS 7.0 以上

## サマリ

検出総数: 13件

| 優先度 | 件数 | 目安 |
| --- | --- | --- |
| P0 (Act now) | 4 | 今すぐ対応 |
| P1 (High) | 3 | 優先的に対応 |
| P2 (Medium) | 4 | 計画的に対応 |
| P3 (Low) | 2 | 経過観察 |

## P0 (Act now) — 今すぐ対応（4件）

| CVE | パッケージ | 検出箇所 | 現在 → 修正 | CVSS | EPSS | KEV | 優先度の理由 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-44228 | log4j-core | app/requirements.txt | 2.14.1 → 2.15.0 | 10.0 | 1.000 | あり | KEV掲載＝実際に悪用されている |
| CVE-2014-0160 | openssl | app/requirements.txt | 1.0.1e-2 → 1.0.1g-1 | 7.5 | 1.000 | あり | KEV掲載＝実際に悪用されている |
| CVE-2014-0160 | openssl | sample-app:1.4.0 (debian 12.5) | 1.0.1e-2 → 1.0.1g-1 | 7.5 | 1.000 | あり | KEV掲載＝実際に悪用されている |
```

（実際のレポートには P1〜P3 の一覧と、優先度の付け方の説明が続きます）

## 優先度の付け方

| 優先度 | 条件 | 意味 |
| --- | --- | --- |
| P0 (Act now) | CISA KEV に掲載されている | 実際に悪用されている。今すぐ対応 |
| P1 (High) | EPSS 0.1 以上 **かつ** CVSS 7.0 以上 | 悪用される確率が高く、深刻度も高い |
| P2 (Medium) | EPSS 0.1 以上 **または** CVSS 7.0 以上（片方のみ） | どちらか一方が高い |
| P3 (Low) | 上記のいずれにも当てはまらない | 経過観察 |

同一ランク内は **EPSS の高い順 → CVSS の高い順** に並びます。値が不明なものはその中で末尾になります。

同じ CVE でも、検出箇所（Trivy の Target）やパッケージ、バージョンが違えば別々の行として残します。
上の例では `openssl` の CVE-2014-0160 が OS パッケージ側とアプリ依存側の両方で見つかっており、
どちらも直す必要があるため2行に出ています。完全に同一の検出だけを重複として除きます。

外部データ（EPSS / KEV）が取得できなかった項目は、理由欄に「悪用確率は不明」のように
**「不明」であることを明記** します（取得できていない値を「低い」とは書きません）。

閾値（0.1 / 7.0）は [`src/triage_lens/scoring.py`](src/triage_lens/scoring.py) の
`EPSS_THRESHOLD` / `CVSS_THRESHOLD` に集約してあります。

## 外部データの扱い

- **KEV カタログ**: `~/.cache/triage-lens/kev.json` に保存し、24時間は再取得しません。
- **EPSS**: 検出された CVE をまとめて（100件ずつ）問い合わせます。1件ずつは叩きません。
- **失敗したとき**: 最大3回まで、1秒 → 2秒と間隔を空けてリトライします。
  それでも取得できない場合は **レポート冒頭に「取得できなかった」と明記した上で、
  残っている情報だけで判定を続行** します（処理は止まりません）。
  KEV の再取得に失敗した場合は、期限切れのキャッシュがあればそれを使います。

## 終了コード

| コード | 意味 |
| --- | --- |
| 0 | 正常終了（外部データを取得できず部分的なレポートになった場合も 0） |
| 2 | 入力エラー（ファイルが無い / JSON が壊れている / Trivy 以外の形式 / オプションの指定ミス） |

## 開発

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check .
```

テストは外部APIに接続しません（すべてモック化しています）。
GitHub Actions で push / Pull Request のたびに Python 3.11 / 3.12 / 3.13 で
テストと lint が実行されます。

## この版（Phase 1）でできること・できないこと

できること:

- Trivy の JSON 出力の読み込み
- EPSS / CISA KEV による優先順位付け
- 日本語 Markdown レポートの生成

まだできないこと（今後のフェーズ）:

- CycloneDX / SPDX 形式の入力
- 英語レポート
- 設定ファイル / Web UI

## ライセンス

MIT License. 詳細は [LICENSE](LICENSE) を参照してください。
