# triage-lens

スキャナが出力した脆弱性の一覧を、公開データで優先順位付けして、
**「どれから直せばいいか」が分かるトリアージレポート（Markdown）** にする CLI ツールです。
インストールは `pip install triage-lens` の1行です。

*English: [README.en.md](https://github.com/secleeman/triage-lens/blob/main/README.en.md)*

判定に使う情報:

| データ | 何が分かるか | 出典 |
| --- | --- | --- |
| CISA KEV | 実際に悪用が確認されているか | CISA 公開カタログ |
| EPSS | 今後30日以内に悪用される確率（0〜1） | FIRST.org 公開API |
| CVSS | 深刻度スコア（0〜10） | スキャナ出力に含まれる値 |

いずれも認証キーは不要です。

任意で `--ai` を付けると、各CVEに「で、何をすればいいのか」を1〜2行で
書いた対応方針コメントを添えられます（Claude API を使うため、こちらは
利用者ご自身のAPIキーと料金が必要です）。付けなければ通信は発生しません。

## 出力例を見る

インストールする前に、**実際に出力されたレポート**を読めます。

- [日本語のレポート](https://github.com/secleeman/triage-lens/blob/main/examples/report-ja.md)
- [English report](https://github.com/secleeman/triage-lens/blob/main/examples/report-en.md)
- [本番依存 / 開発依存に分かれたレポート](https://github.com/secleeman/triage-lens/blob/main/examples/report-npm-ja.md)（npm の SBOM を入力にした場合）
- [もとにしたスキャン結果と補足](https://github.com/secleeman/triage-lens/blob/main/examples/README.md)

## 必要なもの

- Python 3.11 以上
- スキャン結果の JSON ファイル（対応形式は次のとおり）

### 対応している入力形式

| 形式 | 作り方 | 備考 |
| --- | --- | --- |
| Trivy の JSON | `trivy image --format json -o result.json <対象>` | Phase 1 から対応 |
| CycloneDX（JSON） | `trivy image --format cyclonedx -o sbom.cdx.json <対象>` | 仕様 1.4 以降。他のツールが出力した SBOM も読めます |
| SPDX（JSON） | `trivy image --format spdx-json -o sbom.spdx.json <対象>` | SPDX 2.2 / 2.3。**下記のとおり、多くの場合は検出0件になります** |

**形式は中身を見て自動で判別します。** オプションでの指定は不要です。

CycloneDX は SBOM（部品表）の形式なので、脆弱性の一覧（`vulnerabilities`）を
含まないファイルもあります。その場合は「検出0件」のレポートになります
（triage-lens 自身は脆弱性を検出しません）。

#### SPDX を渡したときに気をつけること

**SPDX 2.x には脆弱性の一覧を書く場所がほとんどありません。** CVE を書けるのは
`packages[].externalRefs[]` のうち `referenceCategory` が `SECURITY` のものだけで
（しかも `advisory` などの参照が使えるのは 2.3 から）、実際に出回る SPDX の多くは
ここに何も持っていません。そのため **SPDX を渡すと、たいていは「検出0件」になります。**

これは「脆弱性が無い」という意味ではありません。判定する材料が入っていない、という意味です。
その場合、triage-lens はレポートの冒頭と標準エラーにその旨を出します。

逆に SECURITY 参照がある場合も、**その参照は「影響を受ける」と断言しているとは限りません**
（仕様上、影響が無いことを示す勧告も同じ形で書けます）。SPDX からの検出は
多めに出ることがあります。

脆弱性まで見たいときは、SBOM をスキャンし直した出力を渡してください。

```bash
trivy sbom sbom.spdx.json --format json -o result.json
triage-lens report result.json
```

SPDX 3.x、tag-value / RDF / YAML 表現、CycloneDX の XML 表現には対応していません。

## インストール

```bash
pip install triage-lens
```

インストールできたか確認します。

```bash
triage-lens --help
```

`pip` が見つからないと言われる場合は、`python -m pip install triage-lens` を試してください。

### 他のパッケージと混ぜたくない場合

コマンドとして使うだけなら、[pipx](https://pipx.pypa.io/) を使うと
triage-lens 専用の環境に隔離してインストールできます。

```bash
pipx install triage-lens
```

### 更新する

```bash
pip install --upgrade triage-lens
```

### 開発版（GitHub の最新）を使う

公開されていない変更を試したいときだけ必要です。

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

### 1. スキャンして JSON を出す

Trivy の JSON 形式:

```bash
trivy image --format json -o trivy-result.json sample-app:1.4.0
```

CycloneDX 形式（SBOM）:

```bash
trivy image --format cyclonedx -o sbom.cdx.json sample-app:1.4.0
```

#### Windows で入力ファイルを作るとき

Trivy が配布している Windows 向けのバイナリには**コード署名がありません**。
Smart App Control や SmartScreen が有効な環境では、実行がブロックされることがあります。
これは Trivy 側の配布方法によるもので、triage-lens からは回避できません。

セキュリティ機能を無効にする必要はありません。次のいずれかで入力ファイルを作れます。

| 経路 | コマンド例 |
| --- | --- |
| WSL 上の Trivy | `wsl trivy fs . --format json -o result.json` |
| Docker Desktop 経由の Trivy | `docker run --rm -v "%cd%:/src" aquasec/trivy fs /src --format json -o /src/result.json` |
| osv-scanner の CycloneDX 出力 | `osv-scanner --format cyclonedx-1-5 -L package-lock.json > sbom.cdx.json` |

WSL や Docker から出力する場合は、**Windows 側から読めるパスに書き出してください**
（WSL なら `/mnt/c/...`、Docker ならマウントしたディレクトリの中）。

**`npm sbom` の出力をそのまま渡さないでください。**

```bash
npm sbom --sbom-format cyclonedx > sbom.cdx.json   # これは脆弱性リストではありません
```

`npm sbom` が出すのは**部品表だけ**で、脆弱性の一覧（`vulnerabilities`）を含みません。
triage-lens に渡すと「検出0件」のレポートになりますが、これは**安全という意味ではなく、
判定する材料が無かった**という意味です。脆弱性を検出するのはスキャナ側の仕事です。

`npm audit --json` の形式には対応していません。

### 2. トリアージレポートを作る

```bash
triage-lens report trivy-result.json -o triage-report.md
```

CycloneDX でも同じコマンドです（形式は自動判別されます）。

```bash
triage-lens report sbom.cdx.json -o triage-report.md
```

英語のレポートが欲しい場合は `--lang en` を付けます。

```bash
triage-lens report trivy-result.json --lang en -o triage-report-en.md
```

`-o` を省略すると標準出力に表示します。

| オプション | 説明 | 既定値 |
| --- | --- | --- |
| `-o`, `--output` | 出力先の Markdown ファイル | 標準出力 |
| `--top N` | P2 / P3 で表示する件数（P0 / P1 は常に全件） | 5 |
| `--lang {ja,en}` | レポートの言語 | `ja`（日本語） |
| `--fail-on {p0,p1,p2,p3}` | 指定したランク以上の検出があれば終了コード 1 で終わる | 指定なし（常に 0） |
| `--fail-on-fetch-error` | `--fail-on` と併用し、外部データを取得できなければ終了コード 3 で終わる | 付けない |
| `--ai` | AI による対応方針コメントを付ける | 付けない |
| `--ai-limit N` | AI コメントを生成する上限件数 | 50 |
| `--ai-model NAME` | AI コメントの生成に使うモデル | `claude-haiku-4-5` |

`--lang` はレポート本文の言語です。エラーメッセージと `--help` の説明は日本語のままです。

### 3. 深刻な検出があったら止める（`--fail-on`）

```bash
triage-lens report trivy-result.json -o triage-report.md --fail-on p1
```

指定したランク**以上に緊急な**検出が1件でもあれば、終了コード 1 で終わります。
`p1` なら P0 と P1 が対象です。`p3` は最下位なので、実質「検出が1件でもあれば落ちる」
という意味になります。

- **レポートは落ちるときも必ず生成されます。** 判定はレポートを書き出し切ったあとに
  行います。落ちたのに原因を見るレポートが無い、という状態は作りません
- **`--top` は判定に影響しません。** 表示件数を絞るだけで、判定は常に全件が対象です
- `--ai` が動かなかった場合も、判定の結果は変わりません

#### 外部データを取得できなかったとき

EPSS や CISA KEV を取得できないと、**判定は実際より甘くなります**。
KEV が引けなければ KEV 掲載を根拠とする P0 判定が出ず、本来 P0 の検出が
P2 / P3 に落ちるためです。

このとき triage-lens は標準エラーに警告を出しますが、**終了コードは変えません**
（外部サービスの一時的な不調で CI が落ち続けるのを避けるためです）。

厳しくしたい場合は `--fail-on-fetch-error` を付けてください。
取得に失敗していた場合、終了コード 3 で終わります。

```bash
triage-lens report trivy-result.json -o triage-report.md --fail-on p1 --fail-on-fetch-error
```

「データが取れなかった」と「該当する検出があった」は別の話なので、終了コードを分けています。
両方が同時に起きた場合は 3 を返します。

## GitHub Actions で使う

CI に組み込む場合は composite action が使えます。
**スキャンそのものは行いません。** 別のステップで出力した JSON を渡してください。

```yaml
name: Vulnerability triage

on: [pull_request]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: スキャンする
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy.json

      - name: トリアージレポートを作る
        uses: secleeman/triage-lens@v0.7.0
        with:
          scan-file: trivy.json
          fail-on: p1

      - name: レポートを残す
        if: always()          # fail-on で落ちてもレポートは残す
        uses: actions/upload-artifact@v4
        with:
          name: triage-report
          path: triage-report.md
```

### 入力

| 名前 | 必須 | 既定値 | 説明 |
| --- | --- | --- | --- |
| `scan-file` | ✅ | — | スキャナ出力の JSON のパス（形式は自動判別） |
| `lang` | | `ja` | レポートの言語（`ja` / `en`） |
| `fail-on` | | 空（落とさない） | `p0` / `p1` / `p2` / `p3` |
| `fail-on-fetch-error` | | `false` | `true` にすると、取得失敗時に終了コード 3 で落とす |
| `ai` | | `false` | `true` にすると AI コメントを付ける |
| `output` | | `triage-report.md` | 出力先の Markdown ファイル |

出力は `report-path`（生成したレポートのパス）だけです。

### 使うときに気をつけること

- **`uses:` は `@vX.Y.Z` の固定タグで書いてください。** `@v1` のような動くタグは
  出していません。セキュリティツールの中身が黙って変わらないようにするためです
- **動作を確認しているのは `ubuntu-latest` だけです。**
- **`if: always()` を付けてレポートを残してください。** これが無いと、`fail-on` で
  落ちたときに肝心のレポートが取れません
- **`ai` は既定の `false` のままを勧めます。** PR ごとに動かすと課金が積み上がります。
  使う場合は手動起動や main への push に限ってください。APIキーは `with` ではなく
  `env` で渡します（`with` に書くとワークフローファイルに直書きしがちなためです）

```yaml
      - name: トリアージレポートを作る
        uses: secleeman/triage-lens@v0.7.0
        with:
          scan-file: trivy.json
          ai: 'true'
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## AI による対応方針コメント（`--ai`）

優先順位は「どれから手を付けるか」までしか教えてくれません。
その次に出てくる「これは何をすればいいのか」を、Claude API に1〜2行で書かせて
レポートに載せる機能です。

```bash
export ANTHROPIC_API_KEY=sk-ant-...
triage-lens report trivy-result.json --ai -o triage-report.md
```

出力はこうなります（一覧表の下に付きます）。

```markdown
### 対応方針（AI生成）

- **CVE-2021-44228**（log4j-core）: 2.15.0 に更新してください。...
```

### 前提

- **APIキーは環境変数から読みます。** コマンドライン引数では受け取りません
  （シェル履歴・`ps` の出力・CI のログに残るためです）
- **キーが未設定なら、この機能は動きません。** ただしエラーにはならず、
  標準エラーに1行だけ出して、レポートは通常どおり出力されます
- 組織アカウントで発行された「identity-linked」なキーを使う場合は、
  ワークスペースIDも必要です

| 環境変数 | 必須か | 内容 |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | `--ai` を使うなら必須 | Claude API のキー |
| `ANTHROPIC_WORKSPACE_ID` | 組織アカウントのキーのみ必須 | 課金先のワークスペースID |

### 優先順位は AI が決めるのではありません

**P0〜P3 の判定は公開データ（KEV / EPSS / CVSS）だけで機械的に決めています。**
AI に判定させたり、判定を書き換えさせたりはしません。AI が書くのは
「決まった優先順位に対して、何をすればよいか」の部分だけです。

生成されたコメントは参考情報です。レポートの末尾にもその旨と、
使用したモデル名を記載します。

### Anthropic に送られるデータ

送るものを最小限に固定しています。

| 項目 | 送る |
| --- | --- |
| CVE ID | ○ |
| パッケージ名 | ○ |
| 現バージョン / 修正バージョン | ○ |
| CVSS / EPSS / KEV 掲載有無 | ○ |
| 優先度ランク（P0〜P3） | ○ |
| **検出箇所（ファイルパス / purl）** | **×** |
| **対象名（プロジェクト名 / イメージ名）** | **×** |
| 入力ファイルそのもの | × |

検出箇所と対象名を送らないのは、利用者の内部構成が推測できてしまうためです。

### 費用

料金は利用者の負担です。無駄に高くならないようにしています。

- **対象は P0 と P1 の検出だけ**です（レポートに全件表示されるのはこの2つのため）
- 既定で **50件まで**です（`--ai-limit` で変更できます）
- **20件ずつまとめて**問い合わせます。1件ずつは叩きません
- 同じ内容の問い合わせは **1回だけ**行い、結果を使い回します
  （同じ CVE が複数の場所で見つかっても、課金は1回です）

既定の `claude-haiku-4-5` で、50件生成しても数セント程度の見込みです。

### うまくいかなかったとき

**どの失敗でもレポート本体は出ますし、終了コードは 0 のままです。**
AI コメントが付かないだけで、優先順位付けの結果は通常どおり得られます。

| 起きたこと | どうなるか |
| --- | --- |
| APIキーが未設定 | 通信せずスキップ。標準エラーに1行 |
| キーが無効 / 権限がない | AI コメント無しでレポートを出力 |
| レート制限 | `retry-after` に従って待ち、諦めたらスキップ |
| 通信できない / 応答が壊れている | 同上 |
| 一部だけ生成できた | 取れたぶんだけ載せます |

外部APIの不調でコマンドが固まらないよう、AI の処理全体に時間の上限があります。

## 出力例

```markdown
# 脆弱性トリアージレポート

- 対象: sample-app:1.4.0
- 生成日時: 2026-08-29 03:00
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
```

`--lang en` を付けると同じ内容が英語になります。

```markdown
# Vulnerability Triage Report

- Target: sample-app:1.4.0
- Generated: 2026-08-29 03:00
- Criteria: listed in CISA KEV / EPSS >= 0.1 / CVSS >= 7.0

## P0 (Act now) - Patch immediately (4 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-44228 | log4j-core | app/requirements.txt | 2.14.1 -> 2.15.0 | 10.0 | 1.000 | Yes | Listed in CISA KEV - exploitation observed in the wild |
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

同じ CVE でも、検出箇所やパッケージ、バージョンが違えば別々の行として残します。
OS パッケージ側とアプリ依存側の両方で同じ CVE が見つかった場合、どちらも直す必要があるためです。
完全に同一の検出だけを重複として除きます。

完全に同一の検出が複数回出てきた場合（SBOM を結合したときなど）、値が食い違うときは
次のようにまとめます。

| 項目 | まとめ方 |
| --- | --- |
| CVSS | **高い方を残す**（低い方を採ると実態より安全に見えるため） |
| 修正バージョン | 「不明」より、版数が分かっている方を優先。両方に版数があって食い違う場合は**新しい方**。比較できない表記なら安全側で「不明」 |

修正バージョンの比較は、`1.2.10` のように数字とドットだけの表記に限ります。
`1:1.2.11.dfsg-2+deb11u2` や `>=1.0.1g-1` のような表記は独自に解釈すると
誤った新旧を作りかねないため、比較せずに「不明」と表示します。

外部データ（EPSS / KEV）が取得できなかった項目は、理由欄に「悪用確率は不明」のように
**「不明」であることを明記** します（取得できていない値を「低い」とは書きません）。

閾値（0.1 / 7.0）は [`src/triage_lens/scoring.py`](src/triage_lens/scoring.py) の
`EPSS_THRESHOLD` / `CVSS_THRESHOLD` に集約してあります。

## 「修正版なし」と「不明」の違い

修正版の欄には次の3通りが出ます。

| 表示 | 意味 |
| --- | --- |
| `1.0.0 → 1.0.1` | 修正版がある |
| `1.0.0 → 修正版なし` | 修正版がまだ出ていない |
| `1.0.0 → 不明` | 修正版があるかどうか、入力ファイルからは分からない |

Trivy の JSON では「書かれていない＝修正版なし」と読めるため「修正版なし」と表示します。
CycloneDX には修正版の不在を明示する項目が無いため、読み取れなかった場合は
**「修正版なし」と断定せず「不明」** と表示します。

## CycloneDX を読むときの対応関係

| レポートの項目 | CycloneDX の取得元 |
| --- | --- |
| 対象 | `metadata.component` の `name`（＋ `version`）→ 無ければ `purl` |
| CVE | `vulnerabilities[].id` |
| パッケージ | `affects[].ref` から引いた component の `name` |
| 現バージョン | component の `version` → 無ければ `affects[].versions[]` の `affected` |
| 修正 | `affects[].versions[]` の `unaffected` |
| 検出箇所 | component の `purl` → 無ければ `bom-ref` → 無ければ対象名 |
| CVSS | `ratings[].score` |

- 1つの脆弱性が複数の部品に影響する場合、**部品ごとに1行** に分かれます
- CVSS は現行世代（CVSSv3 / CVSSv31 / CVSSv4）を優先し、無ければ CVSSv2 を使います。
  同じ世代に複数あれば NVD のスコアを優先します
- `method` が書かれていないスコアや、CVSS 以外の尺度（`other` / `OWASP` / `SSVC`）は
  **CVSS として扱わず「不明」** にします。尺度の違う数値を並べると誤解を招くためです
- SBOM に載っていない部品を参照している脆弱性も、行としては残します
  （パッケージ名は「(不明)」になります）

## 本番依存と開発依存の区別

入力にその情報が含まれている場合、レポートを **「本番依存」と「開発依存のみ」の2つの表**
に分けて表示します。サマリにも「うち本番依存」の列が出ます。

```
| 優先度 | 件数 | うち本番依存 | 目安 |
| P2 (Medium) | 17 | 3 | 計画的に対応 |
```

**優先度（P0〜P3）の付け方は変わりません。** 開発依存だからといってランクを下げたり、
`--fail-on` の対象から外したりはしません。変わるのは表示の分け方だけです。

### 何を見て判別しているか

CycloneDX の SBOM から、次の順で判別します。

| 材料 | 判定 |
| --- | --- |
| `properties[]` の `cdx:npm:package:development` が `"true"` | 開発依存のみ |
| `scope` が `excluded` | 開発依存のみ |
| `scope` が `required` / `optional` / 書かれていない | 本番依存 |
| SBOM に載っていない部品 | 本番依存 |

- **`scope: optional` は本番依存として扱います。** npm は optionalDependencies に
  この値を付けるためです。「実行時に任意」であって「開発用」ではありません。
  実行時に使われうるものを「開発だけ」の表に隠さないための判断です
- **`properties` を先に見ます。** npm 本体の `npm sbom` は開発依存にも
  `scope: required` を付け、dev であることは property でしか表しません。
  `scope` だけを見ると npm の SBOM で区別が付きません
- 迷ったときは**本番依存に倒します**。本番のものを「開発だけ」に入れると見落としになりますが、
  逆は多めに出るだけで見落としにはなりません

### ⚠️ `scope` の意味は生成ツールによって揺れます

**`scope` の使い方は SBOM を作るツールに委ねられており、仕様どおりとは限りません。**

実際に、**開発依存に `scope: optional` を付けている SBOM** が確認されています。
triage-lens は仕様どおり `optional` を本番依存として扱うため、この SBOM では
**「開発依存の検出: 0件（すべて本番依存）」と、実態と真逆の分類が出ます。**

- **npm 系では `npm sbom --sbom-format cyclonedx` の property 方式が確実です。**
  `cdx:npm:package:development` は「開発依存である」と直接書いたものなので、
  `scope` のような解釈の揺れがありません
- `scope: optional` は**本番依存**になります。開発依存を表す意図で使われていても、
  triage-lens はそれを読み取れません
- **分類の根拠が `scope` だけだった場合、レポートの末尾に次の1行が入ります。**
  property が使われていれば出ません

> 本番 / 開発の分類は SBOM の scope 値に基づいています。生成元により意味が異なる場合があります。

分類が実態と合っているか怪しいときは、`package.json` の `devDependencies` と
見比べるか、`npm sbom` で作り直した SBOM を渡してみてください。

### 開発依存の検出が0件のとき

区別はできたものの開発依存の検出が1件も無い場合は、**分割せずに従来どおり1つの表**で
表示します。空の「開発依存のみ（0件）」がランクの数だけ並んでも読みにくいだけだからです。
代わりにサマリへ1行入ります。

```
検出総数: 8件
開発依存のみの検出: 0件（すべて本番依存です）
```

なお **本番依存が0件のときは分割したまま**です。「本番依存 0件」はいちばん伝えたい
情報なので、表を残します。

### 区別できない入力のとき

判別する材料が入力に1つも無い場合は、**区別せずに従来どおり1つの表**で表示し、
レポート冒頭にその旨を1行書きます。

> この入力には本番依存 / 開発依存を区別する情報が含まれていないため、区別せずに全件を表示しています。

どちらも1つの表になりますが、**「材料が無かった」のか「区別したうえで0件だった」のかは
書き分けています**（前者は冒頭の1行、後者はサマリの1行）。

`scope` は仕様上「書かれていなければ `required`」なので、何も書かれていない SBOM を
素直に読むと全件が本番依存に見えてしまいます。**区別できているのか、区別する材料が
無いだけなのかを取り違えない**ようにするための表示です。

**Trivy の JSON は区別できません。** Trivy の検出（`Results[].Vulnerabilities[]`）には
本番 / 開発を示す項目が無いためです。推測で分類はしません
（なお Trivy は既定で開発依存をスキャン対象から外します）。

## 推奨アクション

レポートの末尾に、検出を**パッケージ単位にまとめた表**が出ます。
1つのパッケージが5件の CVE で出てきても、実際の作業は「1回上げる」で済むためです。

```
| パッケージ | 現在 | 上げ先 | 解消されるCVE | 最高優先度 |
| lodash | 4.17.15 | 4.17.21 | 2件 | P1 (High) |
| apt | 2.2.4 | 修正版なし | 0件 | P3 (Low) |
```

- **AI は使いません。** `--ai` を付けなくても出ますし、付けても内容は変わりません
- **`--top` の影響を受けません。** 表示件数の指定で省略された検出も集約に含めます。
  切り捨てると解消件数が実際より少なく出て、「上げても片付かない」ように見えるためです
- 同じパッケージでも**現在バージョンが違えば別の行**になります（上げ先が変わるため）。
  同じ版が複数の場所で見つかった場合は1行にまとめます
- 上げ先は、検出された修正版のうち**確実に比較できる形式のものの最大値**です。
  `1:1.2.11.dfsg-2+deb11u2` のように比較できない表記が混ざる場合は「不明」と書きます。
  独自に解釈すると、古い版へのダウングレードを案内しかねないためです
- **上げ先が決められないパッケージも表から落としません。** 「表に無い＝対応不要」と
  読まれないよう、「修正版なし」「不明」と書いて最後にまとめます

## このレポートで分かることの限界

レポートの最後に、次の注意書きが必ず入ります。

> この判定は「その版が依存関係に含まれているか」に基づいています。該当する機能を実際に
> 使っているか、外部から到達しうるかまでは見ていないため、実際の影響はここに書かれたものより
> 小さいことも大きいこともあります。

triage-lens は**依存関係にその版があるかどうか**しか見ていません。
到達性の解析（その脆弱なコードが実際に呼ばれるか）は行いません。

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
| 1 | `--fail-on` で指定したランク以上の検出があった |
| 2 | 入力エラー（ファイルが無い / JSON が壊れている / 対応形式でない / オプションの指定ミス） |
| 3 | `--fail-on-fetch-error` を指定していて、外部データを取得できなかった |

1 と 3 は `--fail-on` を指定した場合にだけ返します。指定しなければ、
従来どおり正常に処理できた限り 0 で終わります。

## 開発

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check .
```

テストは外部APIに接続しません（すべてモック化しています）。
GitHub Actions で push / Pull Request のたびに Python 3.11 / 3.12 / 3.13 で
テストと lint が実行されます。

## この版（v0.7.0）でできること・できないこと

できること:

- Trivy の JSON 出力の読み込み
- CycloneDX（JSON）の SBOM の読み込み（形式は自動判別）
- SPDX（JSON）の SBOM の読み込み（**多くの場合は検出0件になります**）
- EPSS / CISA KEV による優先順位付け
- 日本語・英語の Markdown レポートの生成
- AI による対応方針コメント（`--ai`。APIキーを設定した場合のみ）
- 深刻な検出があったときに CI を止めること（`--fail-on`）
- GitHub Actions への組み込み（composite action）
- **本番依存 / 開発依存を分けた表示**（入力にその情報がある場合）
- **パッケージ単位の推奨アクション**（どれをどこまで上げれば何件片付くか）

まだできないこと（今後のフェーズ）:

- SPDX 3.x / tag-value / RDF / YAML 表現の入力
- CycloneDX の XML 表現
- `npm audit --json` / OSV 形式のネイティブ入力
- **到達性の解析**（脆弱なコードが実際に呼ばれるかの判定）
- Trivy の JSON での本番 / 開発の区別（Trivy の出力に情報が無いため）
- エラーメッセージ・`--help` の英語化
- 日英以外の言語
- 設定ファイル / Web UI
- AI にパッチや修正 PR を作らせること

## バグ報告

バグ報告は [GitHub Issues](https://github.com/secleeman/triage-lens/issues) で受け付けています。
うまく動かなかったときの入力ファイルの形式・実行したコマンド・出たメッセージを
書いていただけると助かります。

**Issue のコメントでの個別の返信は行っていません。** 内容は必ず読んでいます。
対応した結果は、コミットとリリースノート（[ROADMAP](https://github.com/secleeman/triage-lens/blob/main/docs/ROADMAP.md)）に
反映されます。対応済みの Issue は、コメントなしで close することがあります。

## ライセンス

MIT License. 詳細は [LICENSE](https://github.com/secleeman/triage-lens/blob/main/LICENSE) を参照してください。
