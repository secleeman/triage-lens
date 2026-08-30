# 出力例 / Example output

triage-lens が実際に出力したレポートです。インストールしなくても、
**何が出てくるのか**をここで確認できます。

These are reports that triage-lens actually produced. You can see
**what the output looks like** here without installing anything.

出力例は2組あります。**本番依存 / 開発依存を区別できる入力かどうかで、レポートの
見た目が変わります。**

There are two sets. **The report looks different depending on whether the input can
distinguish runtime from development dependencies.**

| ファイル / File | 中身 / Contents |
| --- | --- |
| [`trivy-sample.json`](trivy-sample.json) | 入力にしたスキャン結果（Trivy の JSON） / The scan result used as input (Trivy JSON) |
| [`report-ja.md`](report-ja.md) | 日本語のレポート（既定） / The report in Japanese (default) |
| [`report-en.md`](report-en.md) | 英語のレポート（`--lang en`） / The report in English (`--lang en`) |
| [`cyclonedx-npm-sample.json`](cyclonedx-npm-sample.json) | npm 系の SBOM（CycloneDX）。本番 / 開発の区別を持つ / An npm-style CycloneDX SBOM that carries the runtime/development distinction |
| [`report-npm-ja.md`](report-npm-ja.md) | 上を入力にした日本語のレポート / The Japanese report built from it |
| [`report-npm-en.md`](report-npm-en.md) | 上を入力にした英語のレポート / The English report built from it |

## このサンプルについて / About this sample

- `sample-app:1.4.0` は**架空のイメージ名**で、実在の組織・サービスとは関係ありません。
  一方、**パッケージ名と CVE は実在のもの**です（すべて公開されている脆弱性）。
  実データで優先順位が付くことを見せるために、あえて実在の CVE を使っています。
- P0 / P1 / P2 / P3 が1件以上ずつ出るように選んであります。
- 入力は Trivy の JSON から **triage-lens が読む項目だけを残したもの**です。
  実際の `trivy image --format json` の出力はもっと多くの項目を含みますが、そのまま渡せます。

- `sample-app:1.4.0` is a **made-up image name** and refers to no real organisation or
  service. The **package names and CVEs are real**, however — all publicly disclosed.
  Real CVEs are used on purpose, so you can see prioritisation against live data.
- The findings are chosen so that each of P0 / P1 / P2 / P3 appears at least once.
- The input keeps **only the fields triage-lens reads** from a Trivy JSON file. Real
  `trivy image --format json` output contains more fields; you can pass it as-is.

### npm 系のサンプルについて / About the npm sample

- `demo-shop` も**架空のプロジェクト名**です。パッケージ名と CVE は実在のものです。
- 本番 / 開発の区別は、npm 系の生成ツールが実際に使う2通りの書き方をどちらも入れてあります。
  `scope`（`required` / `optional`）と、`properties` の `cdx:npm:package:development` です。
  **`scope: optional` は本番依存として扱います**（npm は optionalDependencies に
  この値を付けるため。実行時に使われうるものを「開発だけ」に隠さないためです）。
- **注意: `npm sbom --sbom-format cyclonedx` の出力そのものではありません。**
  `npm sbom` が出すのは部品表だけで、脆弱性情報（`vulnerabilities`）は含まれません。
  このサンプルは、その形に脆弱性情報を足したものです。

- `demo-shop` is also a **made-up project name**; the package names and CVEs are real.
- The sample carries both of the ways npm-side tools express the distinction: `scope`
  (`required` / `optional`) and the `cdx:npm:package:development` property.
  **`scope: optional` counts as a runtime dependency** — npm sets it on
  optionalDependencies, which may well be used at runtime.
- **Note: this is not raw `npm sbom --sbom-format cyclonedx` output.** `npm sbom`
  emits a component list with no `vulnerabilities` section; this sample adds one.

## データの取得時点 / When the data was fetched

レポート冒頭の **「生成日時」（`Generated`）が、そのまま EPSS / CISA KEV を取得した時点**です。
ここに置いてある2つのレポートは、キャッシュを消したうえで同じ時刻に生成しています
（EPSS は毎回取得します。CISA KEV は最大24時間キャッシュされます）。

**EPSS と KEV は日々変わります。** 同じ入力でも、あとから実行すると優先度が変わることが
あります（例: KEV に追加されると P0 になります）。ここにあるのは、その時点の実データで
作った1回分の結果です。

The **`Generated` line at the top of each report is also the point in time the EPSS and
CISA KEV data came from.** The two reports here were generated at the same time, with the
cache cleared first (EPSS is fetched on every run; the CISA KEV catalog is cached for up
to 24 hours).

**EPSS and KEV change daily.** The same input can produce different priorities later
(for example, a finding becomes P0 once it is added to KEV). What is committed here is
one run, made with the live data at that moment.

## 再生成する / Regenerating

リポジトリのルートで実行します。実行には EPSS / CISA KEV への通信が必要です
（APIキーは不要）。

Run from the repository root. It needs network access to EPSS and CISA KEV
(no API key required).

```bash
triage-lens report examples/trivy-sample.json -o examples/report-ja.md
triage-lens report examples/trivy-sample.json --lang en -o examples/report-en.md
triage-lens report examples/cyclonedx-npm-sample.json -o examples/report-npm-ja.md
triage-lens report examples/cyclonedx-npm-sample.json --lang en -o examples/report-npm-en.md
```

`tests/test_examples.py` が、置いてあるレポートが入力および現在の出力形式と
食い違っていないかを検査します。

`tests/test_examples.py` checks that the committed reports still match the input
and the current output format.
