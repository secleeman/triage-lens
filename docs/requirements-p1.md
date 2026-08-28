# Phase 1 要件 — 最小で動くtriage-lens

## ゴール
Trivy のJSON出力を入力に、優先順位付きトリアージレポート（Markdown）を
1コマンドで生成できること。

```
triage-lens report trivy-result.json -o triage-report.md
```

## 機能要件

### 入力
- Trivy の `--format json` 出力ファイルを読み込む
- 不正なJSONや未対応形式は、分かりやすいエラーメッセージで終了する

### データ照会（enrichment）
- 検出された各CVEについて以下を取得:
  - **EPSS スコア**: FIRST.org の公開API（https://api.first.org/data/v1/epss）
  - **CISA KEV 掲載有無**: KEVカタログJSON（https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json）を取得して突合
- KEVカタログはローカルにキャッシュし、24時間は再取得しない
- EPSS APIは複数CVEをまとめて問い合わせる（1件ずつ叩かない）
- ネットワーク失敗時はリトライ（最大3回、指数バックオフ）し、それでも失敗したら「取得できなかった」と明示してCVSSのみで処理を続行する

### 優先順位付けロジック
各CVEを4段階に分類する:
- **P0 (Act now)**: CISA KEV掲載あり
- **P1 (High)**: EPSS >= 0.1 かつ CVSS >= 7.0
- **P2 (Medium)**: CVSS >= 7.0（EPSSは低い）、または EPSS >= 0.1（CVSSは中以下）
- **P3 (Low)**: 上記以外

同一ランク内は EPSS降順 → CVSS降順で並べる。
閾値（0.1 / 7.0）は定数として1箇所にまとめ、将来設定可能にできる構造にする。

### 出力（Markdownレポート）
- サマリ: 検出総数、P0/P1/P2/P3の件数
- P0とP1は全件、P2/P3は件数と上位5件のみ表示
- 各CVEの行: CVE ID / パッケージ名 / 現バージョン→修正バージョン / CVSS / EPSS / KEV有無 / 優先度の理由（例: "KEV掲載=実際に悪用されている"）
- レポート言語は日本語（英語対応はPhase 2）

### CLI
- `typer` または `argparse` で実装
- `--top N`（P2/P3の表示件数）、`-o`（出力先）オプション
- 終了コード: 正常0 / 入力エラー2 / ネットワーク完全失敗でも部分レポートが出せれば0

## 非機能要件
- Python 3.11+、依存は requests/httpx, typer, pytest, ruff 程度に留める
- pytestでロジックのユニットテスト（外部APIはモック化）
- GitHub Actions: push/PR時に pytest + ruff 実行
- README.md: インストール方法、使い方、スコアリングロジックの説明

## テストデータ
- `tests/fixtures/` にTrivy出力のサンプルJSONを置く（公開CVE ID＋架空のプロジェクト名で作る）

## Phase 1 でやらないこと（実装禁止）
- CycloneDX/SPDX対応、英語レポート、AI機能、Web UI、設定ファイル
