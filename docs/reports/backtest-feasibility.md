# バックテスト実現性調査

- 日付: 2026-08-31
- 目的: 「**CVSS≥7 のみで対応した場合** vs **triage-lens default で対応した場合**」の
  修正件数と悪用CVE捕捉率を、過去データで比較できるかを調べる
- **実装には着手していません。** この文書は調査結果と判定案だけです。
- この調査で書いた数値は、すべて 2026-08-31 に実際にデータを取得して計測したものです。
  推測値には「推定」と明記しています。

---

## 0. 結論（先に読むところ）

**判定: 条件付きで実装可（Conditional GO）。ただし「元の設計のまま」では実装しないでください。**

データは全部そろっています。EPSS の日次過去スナップショットも、KEV の追加日も、
母集団の作り方も、無料・認証不要・再現可能な形で入手できます。
**技術的な障害はありません。**

問題はデータではなく **統計です。**

| 何が問題か | 実測値 |
| --- | --- |
| 正例（＝あとから実際に悪用されたCVE）が少なすぎる | 特定エコシステム（Debian）1件の基準日で **20〜29件** |
| 全CVEを母集団にしても足りない | 基準日 2025-01-01 で **120件**、2023-01-01 で **170件** |
| 静的コホート設計が、悪用シグナルの大半を捨てている | 2023-01-01 以降の KEV 追加 819件のうち、**649件（79%）は基準日時点でまだ存在しないCVE** |
| 結果として信頼区間が広すぎる | 正例29件のとき、捕捉率の95%信頼区間の幅は **約30ポイント**（例: 72.4% [54.3, 85.3]） |

**そのまま実装すると「CVSS≥7 は捕捉率72%、triage-lens P0+P1 は38%」のような数字が出ますが、
信頼区間が重なっていて、どちらが良いとも言えません。**
「triage-lens のほうが優れている」という主張の根拠には**なりません**。
むしろ現状の閾値だと、素朴に読めば「CVSS≥7 のほうが捕捉率が高い」と読めてしまいます
（詳細は [6. パイロット実測](#6-パイロット実測いちばん重要な発見)）。

### 実装するなら、こう変えること

1. **静的コホート設計をやめ、ローリング設計にする。**
   「基準日時点で公開済みのCVE」ではなく「**各CVEを、公開された日のスコアで評価し、
   その後を追跡する**」。正例が 170件 → **約819件** に増え、捕捉率80%付近の95%信頼区間の幅が
   28.5ポイント → 5.5ポイントになります。
2. **必ず信頼区間を併記する。** 点推定だけを出さない。
3. **「捕捉率」だけでなく「同じ捕捉率を出すのに必要な工数」で比較する。**
   triage-lens の強みは工数側にあります（P0+P1 は母集団の 1.4〜2.2% しか対応対象にしない）。
4. **CVSS を「基準日時点の値」で取る手当てをする。** ここが唯一の未解決の技術課題です
   （[4-4](#4-4-cvss-をどこから取るか未解決の課題)）。
5. **結果が triage-lens に不利でも、そのまま公開する。**
   不利な結果を出せない実験なら、最初からやらないほうがいいです。

工数の見積もりは [7. 概算工数とデータ量](#7-概算工数とデータ量) にあります。
最小構成で **4.5〜5.5人日**、推奨構成（ローリング設計＋as-of CVSS）で **10〜13人日** です。

---

## 1. この調査の環境と制約

調査は、外向き通信が制限された環境で行いました。**到達できたホストと、できなかったホストを
そのまま書きます。** 到達できなかったものは、その旨を明記しています。

| ホスト | 状態 | この調査での扱い |
| --- | --- | --- |
| `raw.githubusercontent.com` | ✅ 到達可 | EPSS 過去スナップショット / KEV / CVE List の取得に使用 |
| `osv-vulnerabilities.storage.googleapis.com` | ✅ 到達可 | OSV の一括ダウンロードに使用 |
| `pypi.org` | ✅ 到達可 | 解析用ライブラリ（`cvss`）の取得に使用 |
| `epss.empiricalsecurity.com` / `epss.cyentia.com` | ❌ 403（egress policy） | GitHub 上の公式ミラーで代替 |
| `api.first.org` | ❌ 403 | 未検証。日次CSVで代替できたため実害なし |
| `www.first.org` | ❌ 403 | **EPSS の一次ドキュメントを直接読めていません**（後述） |
| `www.cisa.gov` | ❌ 403 | CISA 公式の GitHub リポジトリで代替 |
| `services.nvd.nist.gov` / `nvd.nist.gov` | ❌ 403 | **NVD は一切検証できていません。** NVD を使う案は机上のみ |
| `docs.github.com` / `arxiv.org` | ❌ 403 | 二次情報＋GitHub 上のミラーで代替 |

**実装時には、NVD と FIRST API を実際に叩いて確認しなおしてください。**
この文書で NVD / FIRST API について書いていることは、公開情報からの引用であって、
この調査で実測したものではありません。

---

## 2. 調査項目1: EPSS の過去スナップショットは入手できるか

### 結論: **できます。日次で、2021-04-14 から昨日まで、認証不要・無料。**

### 2-1. 入手先と形式（実測）

公式の配布先は FIRST のサイト（`https://www.first.org/epss/data_stats`）ですが、
**同じデータが GitHub の公式リポジトリ [`empiricalsec/epss_scores`](https://github.com/empiricalsec/epss_scores)
にも置かれています。** README にこう書かれています（原文ママ）:

> This is the official repository for current and historical EPSS Scores. Scores are also available
> for [direct download](https://www.first.org/epss/data_stats), or scores for individual
> vulenrabilities can be retrieved throug the [FIRST API](https://api.first.org/epss/).

URL の形は次のとおりです（実測で 200 を確認）:

```
https://raw.githubusercontent.com/empiricalsec/epss_scores/main/<YYYY>/epss_scores-<YYYY-MM-DD>.csv.gz
```

指定日のファイルを取って中身を見た実測結果（2025-01-01）:

```
$ curl -sSL -o epss-2025-01-01.csv.gz \
    https://raw.githubusercontent.com/empiricalsec/epss_scores/main/2025/epss_scores-2025-01-01.csv.gz
http_code=200 size=1640466

$ gunzip -c epss-2025-01-01.csv.gz | head -5
#model_version:v2023.03.01,score_date:2025-01-01T00:00:00+0000
cve,epss,percentile
CVE-1999-0001,0.00383,0.72779
CVE-1999-0002,0.01328,0.85717
CVE-1999-0003,0.04409,0.92305

$ gunzip -c epss-2025-01-01.csv.gz | grep -c '^CVE-'
271765
```

| 項目 | 実測値 |
| --- | --- |
| 形式 | gzip 圧縮 CSV。1行目が `#` で始まるコメント（モデル版とスコア生成時刻）、2行目がヘッダ |
| 列 | `cve`, `epss`, `percentile` |
| 圧縮後サイズ | 1,640,466 バイト（2025-01-01） |
| 展開後サイズ | 8,280,748 バイト（約 7.9 MiB） |
| CVE 件数 | 271,765 件 |
| 圧縮率 | 約 5.0倍 |

### 2-2. 取得できる期間（実測）

`HEAD` で存在を確認しました。

| 日付 | HTTP |
| --- | --- |
| 2021-04-13 | **404** |
| 2021-04-14 | 200 |
| 2021-04-15 | 200 |
| 2026-08-30 | 200 |

リポジトリ README にも次の記載があります（原文ママ）:

> No scores are available before 2021-04-14

**指示にあった 2025-01-01 時点のスコアは、問題なく取得できます。**

### 2-3. ⚠️ 落とし穴: モデル版がまたいでいる

**これは実験設計に直接効きます。** EPSS はモデルが何度も入れ替わっており、
入れ替わった日にスコアが不連続に動きます。README の記載（原文ママ）:

> - EPSS v2 (v2022.01.01) started publishing on 2022-02-04, you will see a
>   major shift in most scores on that day, and the files now include a
>   comment at the start with `#` stating the model version and publish
>   date.
> - EPSS v3 (v2023.03.01) started publishing on 2023-03-07, you will see a
>   shift in scores on that day.
> - EPSS v4 (v2025.03.14) started publishing on 2025-03-17, you will see a
>   shift in scores on that day.

**README に書かれていない、もう1回の入れ替わりを実測で見つけました。**

```
2026-06-14 : #model_version:v2025.03.14,score_date:2026-06-14T12:55:00Z
2026-06-15 : #model_version:v2026.06.15,score_date:2026-06-15T12:03:41Z
```

**2026-06-15 にモデルが `v2026.06.15` に切り替わっています。** README はこれを載せていません
（2026-08-31 時点）。

実験への影響:

- **各ファイルの1行目の `#model_version` を必ず読んで記録すること。** README を信用しない。
- **異なる基準日の結果を直接比べないこと。** 各基準日のモデル版を実測しました:

  | 基準日 | `#model_version` | 世代 |
  | --- | --- | --- |
  | 2023-01-01 | `v2022.01.01` | **v2** |
  | 2024-01-01 | `v2023.03.01` | v3 |
  | 2025-01-01 | `v2023.03.01` | v3 |
  | 2026-01-01 | `v2025.03.14` | v4 |
  | 2026-06-15 以降 | `v2026.06.15` | 世代の呼称は不明（README 未記載） |

  **後述のパイロットで使った3つの基準日は、v2 と v3 にまたがっています。**
  「モデルが違うものを並べて優劣を語らない」のは、triage-lens が
  「尺度の違う数値を並べない」と決めているのと同じ話です。
- 逆に言うと、**1つの基準日の中では一貫しています。** 基準日ごとに独立した実験として扱えば問題ありません。

### 2-4. ライセンス

`empiricalsec/epss_scores` リポジトリに LICENSE ファイルはありません（実測で 404）。
EPSS のデータそのものは FIRST の **Usage Agreement** の下にあります。全文（ScanCode の
ライセンスDBに収録されたもの。原文ママ）:

> Usage Agreement
>
> EPSS is an emerging standard developed by a volunteer group of researchers, practitioners,
> academics and government personnel. We grant the use of EPSS scores freely to the public,
> subject to the conditions below. We reserve the right to update the model and these webpages
> periodically, as necessary, though we will make every attempt to provide sufficient notice to
> users in the event of material changes. While membership in the EPSS SIG is not required to use
> or implement EPSS, however, we ask that if you are using EPSS, that you provide appropriate
> attribution where possible. EPSS can be cited either from this website (e.g. "See EPSS at
> https://www.first.org/epss), or as: Jay Jacobs, Sasha Romanosky, Benjamin Edwards,
> Michael Roytman, Idris Adjerid, (2021), Exploit Prediction Scoring System,
> Digital Threats Research and Practice, 2(3)

出典: <https://raw.githubusercontent.com/aboutcode-org/scancode-toolkit/develop/src/licensedcode/data/licenses/first-epss-usage.LICENSE>
（一次情報は <https://www.first.org/epss/#Usage-Agreement>。この環境からは到達できませんでした）

**まとめ: 自由に使ってよい。ただし出典表記が求められている。**
実装するなら、生成物（レポート・README）に上記の引用形式で出典を書いてください。

---

## 3. 調査項目2: KEV の追加履歴は使えるか

### 結論: **`dateAdded` は必ずあります。悪用の代理指標として使えますが、大きな注意が2つあります。**

### 3-1. `dateAdded` の有無（実測）

CISA 公式の GitHub リポジトリ [`cisagov/kev-data`](https://github.com/cisagov/kev-data) から取得しました。
README にこうあります（原文ママ）:

> This repository is home to the data files that make up the Known Exploited Vulnerabilities (KEV)
> catalog. The data is originally sourced from https://www.cisa.gov/known-exploited-vulnerabilities-catalog

CISA 自身が公開している JSON スキーマの定義（原文ママ）:

```json
"dateAdded": {
  "description": "The date the vulnerability was added to the catalog in the format YYYY-MM-DD",
  "type": "string",
  "format": "date"
}
```

そして `dateAdded` は **必須フィールド**です（スキーマの `required` に入っています）:

```
['cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded', 'shortDescription', 'requiredAction', 'dueDate']
```

実データでも確認しました。

| 項目 | 実測値（catalogVersion 2026.08.27） |
| --- | --- |
| エントリ数 | 1,685 |
| `dateAdded` が空でないもの | **1,685（100%）** |
| 最古 | 2021-11-03 |
| 最新 | 2026-08-27 |

年ごとの追加数:

| 年 | 追加数 |
| --- | --- |
| 2021 | 311（カタログ初期投入を含む） |
| 2022 | 555 |
| 2023 | 187 |
| 2024 | 186 |
| 2025 | 245 |
| 2026 | 201（8月27日まで） |

**基準日以降に KEV へ追加された CVE を「悪用が起きた」の代理指標にする、という設計は成立します。**

### 3-2. ⚠️ 注意1: `dateAdded` は「悪用された日」ではない

`dateAdded` は **CISA がカタログに載せた日**です。実際に悪用が始まった日でも、
悪用が観測された日でもありません。ラグがあります。

さらに KEV は **米国連邦政府機関にとっての重要度でフィルタされたカタログ**です
（追加は BOD の権限に基づく）。エンタープライズ製品・ネットワーク機器に偏っており、
**OSS のライブラリ脆弱性は相対的に載りにくい**傾向があります。
これは後述のパイロット結果に強く出ています。

**レポートには「KEV 追加 = 悪用の代理指標であり、悪用の全体像ではない」と明記が必要です。**

### 3-3. ⚠️ 注意2（最重要）: 静的コホート設計だと、悪用シグナルの79%が消える

これが今回いちばん重要な発見です。

基準日を 2023-01-01 に置いた場合:

| 項目 | 実測値 |
| --- | --- |
| 2023-01-01 以降に KEV に追加された CVE | **819件** |
| うち、基準日時点で既に公開されていたもの | **170件（21%）** |
| うち、基準日時点でまだ存在しなかったもの | **649件（79%）** |

| 基準日 | 以降のKEV追加 | 基準日時点で公開済み | 割合 |
| --- | --- | --- | --- |
| 2023-01-01 | 819 | 170 | 21% |
| 2024-01-01 | 632 | 146 | 23% |
| 2025-01-01 | 446 | 120 | 27% |

裏付けとして、**2023-01-01 以降の KEV 追加 819件のうち 511件（62%）は、
CVE ID の年と KEV 追加の年が同じ**です。つまり「新しく採番された CVE がすぐ悪用される」
のが KEV の主流です。

**「基準日時点のCVE集合を固定して、その後を追う」という設計は、
この主流のケースを構造的に全部捨てます。**

さらに、拾えた170件も追跡期間が長い:

| 基準日 2023-01-01、公開済みコホート170件の KEV 追加までのラグ | 実測 |
| --- | --- |
| 25パーセンタイル | 179日 |
| 中央値 | **625日** |
| 75パーセンタイル | 975日 |
| 90パーセンタイル | 1,159日 |

観測窓を1年で切ると、170件のうち **60件しか正例になりません**。
2年でも102件です。

**EPSS は「今後30日以内の悪用確率」を出すモデルです。それを中央値625日の
アウトカムで評価するのは、モデルの設計と合っていません。**
この点はレポートで明示するか、観測窓を短く（90〜180日）取り直す必要があります。

### 3-4. ライセンス

`cisagov/kev-data` の LICENSE ファイル冒頭（原文ママ）:

> The KEV database is distributed under the Creative Commons 0 1.0 License. You may use this data
> in any legal manner but note that information provided at any 3rd party links included in the KEV
> database are bound by the policies and licenses of those 3rd party websites. Use of the
> information does not authorize you to use the CISA Logo or DHS Seal, nor should such use be
> interpreted as an endorsement by CISA or DHS.

**CC0 1.0。制約は実質ありません**（CISA / DHS のロゴは使うな、というだけ）。

---

## 4. 調査項目3: 母集団の作り方

「基準日時点で公開済みのCVE集合」をどう切り出すか。**3案を実測付きで出します。**

### 4-0. 先に: 「基準日時点で公開済み」の判定方法

NVD の `published` を引くのが素直ですが、**もっと安い方法があります。**

**EPSS の基準日スナップショットに載っているかどうかを見ればいい。**
EPSS は公開済みの全CVEにスコアを振るので、スナップショットへの掲載＝その日に公開済み、
とほぼ同義です。1ファイル取るだけで判定できます。

実測で裏を取りました。PyPI エコシステムの CVE（OSV の `published < 2025-01-01`）3,450件のうち、
**3,443件（99.8%）が 2025-01-01 の EPSS スナップショットに載っていました。**

**副次的な発見**: OSV レコードの `published` は「その勧告レコードが OSV に載った日」で、
**CVE が公開された日ではありません。** 例えば Red Hat のレコードは大半が 2024-09-12 の
一括投入日になっており、2023-01-01 基準では母集団が 0件になってしまいます。
**OSV の `published` を「CVE公開日」として使わないでください。**

### 4-1. 案A: 特定エコシステムに限定（OSV の一括ダウンロード）

OSV は エコシステムごとに全レコードの ZIP を配っています。認証不要です。

```
https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip
https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt   # 一覧
```

実測したサイズ:

| エコシステム | ZIP サイズ |
| --- | --- |
| PyPI | 33,962,738 B（約 32 MiB） |
| npm | 221,704,103 B（約 211 MiB） |
| Maven | 10,270,749 B |
| Go | 11,481,601 B |
| Packagist | 10,502,601 B |
| NuGet | 2,508,028 B |
| Debian | 75,657,448 B |
| Alpine | 4,145,910 B |
| Red Hat | 26,548,240 B |
| Ubuntu | 653,252,780 B（約 623 MiB） |

**CVE の取り出し方はエコシステムで違います**（実測）:

- 言語系（PyPI / npm / Maven ...）: `aliases[]` に `CVE-...`
- Alpine / Red Hat: `upstream[]` に `CVE-...`（`aliases` は無い）
- Debian: `id` が `DEBIAN-CVE-...` / `DSA-...` / `DLA-...`、CVE は `upstream[]`

`aliases` だけを見ると Alpine / Red Hat が 0件になります。**3つ全部見てください。**

母集団と正例の実測（正例 = 基準日以降に KEV 追加）:

| エコシステム | 全CVE数 | KEVと重なる数 | 母集団@2023-01-01 | 正例 | 母集団@2025-01-01 | 正例 |
| --- | --- | --- | --- | --- | --- | --- |
| PyPI | 6,052 | 18 | 2,262 | 1 | 3,450 | **0** |
| npm | 5,826 | 13 | 2,070 | 1 | 2,832 | 1 |
| Maven | 6,848 | 53 | 3,891 | 10 | 5,337 | 2 |
| Go | 4,417 | 9 | 986 | 0 | 2,043 | 1 |
| Packagist | 5,909 | 24 | 2,713 | 5 | 3,987 | 4 |
| NuGet | 1,020 | 16 | 476 | 2 | 626 | 2 |
| **言語系6つの和集合** | 29,733 | 125 | 12,242 | **15** | 18,032 | **7** |
| Debian | 58,976 | 242 | 29,167 | **31** | 38,008 | 21 |
| Alpine | 4,611 | 20 | 3,140 | 2 | 3,670 | 2 |
| Red Hat | 24,067 | 213 | （※） | - | 20,153 | 14 |

※ Red Hat は OSV への一括投入が 2024年のため、`published` ベースでは 2023/2024 基準の母集団が 0件になります（4-0 の落とし穴）。

**評価:**

- ✅ 実装が最も軽い。ZIP 1本をダウンロードして解凍するだけ。認証不要
- ✅ triage-lens の実際の利用像（コンテナ／依存関係のスキャン結果）に近い
- ❌ **PyPI 単独では正例 0件。実験が成立しません**
- ❌ 言語系エコシステムは KEV との重なりが構造的に薄い（PyPI 6,052件中 KEV は18件）
- ⚠️ Debian（OS パッケージ）にすると正例が 21〜31件まで増える。**それでもまだ足りません**

### 4-2. 案B: 全CVE（EPSS スナップショットを母集団そのものにする）

EPSS の基準日スナップショットに載っている CVE 全部を母集団にします。

| 基準日 | 母集団 | 正例（基準日以降にKEV追加） | 正例率 |
| --- | --- | --- | --- |
| 2023-01-01 | 191,184 | **170** | 0.089% |
| 2024-01-01 | 219,848 | **146** | 0.066% |
| 2025-01-01 | 270,526 | **120** | 0.044% |

**評価:**

- ✅ 追加のダウンロードがほぼ不要（EPSS ファイル1本 + KEV 1本 = 約 3.3 MB）
- ✅ 正例が案Aより1桁多い
- ❌ **triage-lens の利用像から遠い。** 実際のユーザは「全CVE」に対応するわけではありません。
  ここでの「対応件数」は現実の工数と対応していません
- ❌ **CVSS が別途必要**（[4-4](#4-4-cvss-をどこから取るか未解決の課題)）
- ❌ 正例170件でもまだ信頼区間が広い（捕捉率80%付近で幅 12.0ポイント）

### 4-3. 案C: 実際のスキャン結果を母集団にする（推奨したいが重い）

代表的なコンテナイメージ・OSS リポジトリを N個選び、**基準日時点のタグ／ダイジェストに固定して**
Trivy でスキャンし、その検出結果を母集団にします。

**評価:**

- ✅ **「工数」が本物になる。** 「このイメージを直すのに何件対応するか」が実際の数字になります。
  案A・案Bの「工数」は抽象的な CVE 件数でしかありません
- ✅ triage-lens の主張（「対応すべき件数を減らす」）を、そのまま検証できます
- ❌ 過去のイメージを再現するのが重い。ダイジェスト固定のイメージが今も pull できるとは限りません
- ❌ **スキャナ（Trivy）の脆弱性DBも当時の版が必要。** 現在の DB でスキャンすると、
  基準日時点では知られていなかった脆弱性まで出てきます（**リーク**）
- ❌ 対象の選び方に恣意性が入る。選定基準を先に文書化しないと、結果を都合よく作れます
- ❌ 正例数は案A以下になる可能性が高い（イメージ数を増やしても、KEV との重なりは増えにくい）

**この案は「工数の現実性」では最良ですが、単独では正例が足りません。**
案B（またはローリング設計）で捕捉率を測り、案Cで工数の実感値を示す、
という**2本立てが現実的**です。

### 4-4. CVSS をどこから取るか（未解決の課題）

**3つの案すべてに共通する、いちばん厄介な問題です。**

比較の片方が「CVSS≥7」である以上、**基準日時点の CVSS 値**が要ります。
EPSS と違って、**CVSS には日次スナップショットのアーカイブがありません。**

| 取得元 | 状況 |
| --- | --- |
| NVD API | **この環境からは到達できず未検証。** 公開情報では、APIキーなしで30秒あたり5リクエスト、APIキーありで50リクエスト、`resultsPerPage` 最大2000。**現在の値しか返さないため、as-of 値にはならない** |
| OSV レコードの `severity[]` | 実測: Debian の68.4%、Alpine の98.9%、PyPI の40.7% に CVSS ベクタあり。**ただし現在の値。欠損も多い** |
| `CVEProject/cvelistV5` の日次リリース | 実測: リポジトリは到達可。README に `<Year-Month-Day>_all_CVEs_at_midnight.zip` を毎日リリースすると記載。**過去日のリリース資産が残っていれば as-of 値が取れる**（未検証） |
| `CVEProject/cvelistV5` の git 履歴 | 過去日の状態を `git checkout` で再現できる。**リポジトリが巨大**（未計測） |

**現実的な選択肢は2つです。**

- **(a) 現在の CVSS を使い、その旨を明記する。** CVSS の基本値は改定されることが稀なので
  実用上は近似になります。ただし「近似である」ことをレポートに書く必要があります。
  実装コストはほぼゼロ。
- **(b) `cvelistV5` の履歴から as-of 値を再構成する。** 正しいが、+2〜3人日。

**(a) で始めて、結果が僅差になったときだけ (b) に上げる**のが妥当だと考えます。

**また、CVSS の欠損の扱いを先に決めてください。** パイロットでは Debian 母集団の
31.7〜41.1% に CVSS がありませんでした。triage-lens は「不明」を閾値未満として扱うので、
実験もそれに合わせるべきですが、**その選択が「CVSS≥7」側の捕捉率を下げる方向に働きます。**
公平性のため、レポートには「CVSS 欠損を除外した場合」の数字も併記すべきです。

---

## 5. 調査項目4: 評価指標（Coverage / Effort / Efficiency）の当てはめ

### 5-1. 定義

FIRST / EPSS の文脈で使われている定義です。

| 指標 | 式 | 意味 |
| --- | --- | --- |
| **Coverage（捕捉率）** | TP / (TP + FN) | 実際に悪用された脆弱性のうち、対応対象に入れられた割合。**再現率** |
| **Efficiency（効率）** | TP / (TP + FP) | 対応した脆弱性のうち、実際に悪用されたものの割合。**適合率** |
| **Effort（工数）** | (TP + FP) / 母集団全体 | 母集団のうち、対応対象にした割合 |

一次情報は Jay Jacobs, Sasha Romanosky, Octavian Suciu, Benjamin Edwards, Armin Sarabi,
"Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven
Insights"（arXiv:2302.14172, 2023）および FIRST の EPSS ドキュメントです。

> ⚠️ **この定義は二次情報から確認したものです。** `arxiv.org` と `www.first.org` はこの環境から
> 到達できませんでした。**実装前に一次情報で式を確認してください。**
> 特に Effort の分母（母集団全体 か TP+FP か）は文献によって表記の揺れがあります。

### 5-2. この実験への当てはめ

| 記号 | この実験での意味 |
| --- | --- |
| 母集団 | 基準日時点で公開済みのCVE集合（案A/B/C のいずれか）。**基準日時点で既に KEV にあるものは除外** |
| Positive（正例） | 基準日より後に KEV に追加された CVE |
| Negative | それ以外 |
| **戦略A（ベースライン）** | 「CVSS ≥ 7.0 を対応対象にする」 |
| **戦略B（triage-lens default）** | 下記のとおり複数定義できます |

**「triage-lens default で対応した場合」の定義を先に決めてください。** ツールは P0〜P3 を
出すだけで、「どこまで対応するか」は決めていません。少なくとも次の3つが考えられます。

| 戦略 | 対応対象 | 性格 |
| --- | --- | --- |
| B1 | P0 + P1 | 「KEV掲載 または （EPSS≥0.1 かつ CVSS≥7）」。**工数最小** |
| B2 | P0 + P1 + P2 | 「KEV掲載 または EPSS≥0.1 または CVSS≥7」。**捕捉率最大** |
| B3 | P0 のみ | 「実際に悪用されているものだけ」。ベースラインの意味 |

**B1 と B2 は性格が正反対です。** どちらを「default」と呼ぶかで結論が変わります。
**3つ全部を出して、Effort-Coverage 平面にプロットする**のが誠実だと思います。

### 5-3. ⚠️ 「基準日時点で既に KEV にあるCVE」の扱い

母集団から**必ず除外してください。** 残すと、triage-lens の P0（KEV掲載）が
「答えを知っている」状態になり、捕捉率が不当に上がります。
パイロットでは除外しています。

### 5-4. 追加で出すべき指標

3つの標準指標に加えて、次を出すことを推奨します。

- **信頼区間（Wilson）。** 正例が少ないので、点推定だけでは誤読されます
- **同じ Coverage を出すのに必要な Effort。** これが triage-lens の実質的な主張です
- **「対応件数」の絶対値。** オーナーが非エンジニアに説明するとき、割合より件数のほうが伝わります

---

## 6. パイロット実測（いちばん重要な発見）

**「実装できるか」だけでなく「実装したら何が出るか」を先に測りました。**
これは feasibility の判断材料であって、実験の結果ではありません。
スクリプトはリポジトリにコミットしていません（実装着手は指示の範囲外のため）。

### 6-1. 条件

| 項目 | 内容 |
| --- | --- |
| 母集団 | OSV の Debian エコシステムの CVE のうち、基準日の EPSS スナップショットに載っているもの。基準日時点で既に KEV にあるものは除外 |
| 正例 | 基準日以降に KEV に追加されたもの（観測窓は「今日まで」、つまり打ち切りなし） |
| EPSS | 基準日の日次スナップショット。**モデル版は 2023-01-01 が v2、2024-01-01 と 2025-01-01 が v3。基準日をまたいだ比較はできません** |
| CVSS | **現在の** OSV レコードの `severity[]` から算出（`cvss` ライブラリ）。**欠損は 0 として扱う**＝閾値未満 |
| 実行時間 | ローカルデータから **5.4秒**（ダウンロード除く。約120MB 取得済み） |

### 6-2. 結果

**基準日 2023-01-01（母集団 28,930件 / 正例 29件 / CVSS 判明率 58.9%）**

| 戦略 | 対応件数 | Effort | TP | Coverage | Efficiency |
| --- | --- | --- | --- | --- | --- |
| A: CVSS≥7 のみ | 9,607 | 33.2% | 21 | **72.4%** | 0.219% |
| B1: P0+P1 | 643 | **2.2%** | 11 | 37.9% | **1.711%** |
| B2: P0+P1+P2 | 10,800 | 37.3% | 24 | **82.8%** | 0.222% |
| C: EPSS≥0.1 のみ | 1,836 | 6.3% | 14 | 48.3% | 0.763% |

**基準日 2024-01-01（母集団 31,357件 / 正例 22件 / CVSS 判明率 62.1%）**

| 戦略 | 対応件数 | Effort | TP | Coverage | Efficiency |
| --- | --- | --- | --- | --- | --- |
| A: CVSS≥7 のみ | 10,879 | 34.7% | 17 | 77.3% | 0.156% |
| B1: P0+P1 | 427 | **1.4%** | 4 | 18.2% | **0.937%** |
| B2: P0+P1+P2 | 12,416 | 39.6% | 18 | 81.8% | 0.145% |
| C: EPSS≥0.1 のみ | 1,964 | 6.3% | 5 | 22.7% | 0.255% |

**基準日 2025-01-01（母集団 37,710件 / 正例 20件 / CVSS 判明率 68.3%）**

| 戦略 | 対応件数 | Effort | TP | Coverage | Efficiency |
| --- | --- | --- | --- | --- | --- |
| A: CVSS≥7 のみ | 13,266 | 35.2% | 16 | 80.0% | 0.121% |
| B1: P0+P1 | 523 | **1.4%** | 3 | 15.0% | **0.574%** |
| B2: P0+P1+P2 | 14,999 | 39.8% | 17 | 85.0% | 0.113% |
| C: EPSS≥0.1 のみ | 2,256 | 6.0% | 4 | 20.0% | 0.177% |

### 6-3. この結果をどう読むか

**この数字をそのまま公開してはいけません。** 理由を3つ書きます。

**(1) 信頼区間が広すぎて、差が言えない。**

基準日 2023-01-01（正例29件）の Coverage を Wilson 法の95%信頼区間で出すと:

| 戦略 | Coverage | 95%信頼区間 | 幅 |
| --- | --- | --- | --- |
| A: CVSS≥7 | 72.4% | [54.3, 85.3] | 31.0pt |
| B1: P0+P1 | 37.9% | [22.7, 56.0] | 33.3pt |
| B2: P0+P1+P2 | 82.8% | [65.5, 92.4] | 27.0pt |
| C: EPSS≥0.1 | 48.3% | [31.4, 65.6] | 34.2pt |

**A と B2 の区間は大きく重なっています。** 「B2 のほうが捕捉率が高い」とは言えません。
必要な正例数の目安（Coverage が 0.8 付近のとき）:

| 正例数 | 95%信頼区間の幅 |
| --- | --- |
| 29 | 28.5pt |
| 100 | 15.5pt |
| 200 | 11.0pt |
| **400** | **7.8pt** |
| 600 | 6.4pt |

**まともな結論を出すには正例が数百件必要です。**

**(2) 素朴に読むと triage-lens に不利。**

「CVSS≥7 のみ」の Coverage（72〜80%）は、「P0+P1」（15〜38%）より**高い**です。
これは当然で、P0+P1 は母集団のたった 1.4〜2.2% しか対応対象にしていないからです。
**捕捉率だけを並べたら triage-lens は負けます。**

triage-lens の主張が成立するのは Efficiency のほうです。
基準日 2023-01-01 で、B1 の Efficiency（1.711%）は A（0.219%）の **約7.8倍**。
つまり「**対応件数を 9,607件 → 643件（15分の1）に減らして、捕捉率は 72.4% → 37.9%
（約半分）にとどまる**」という話です。

**この「工数を1/15にして捕捉率は半分」というトレードオフこそが実験の結論になるはずで、
「捕捉率で勝つ」という話ではありません。** 実験を設計するときに、
ここを取り違えないでください。

**(3) 言語エコシステムでは正例が 0 になる。**

PyPI を母集団にした場合、基準日 2025-01-01 で **正例は0件**でした。
「PyPI の CVE で、2025-01-01 時点で公開済みかつその後 KEV に追加されたもの」が
1件もありません。**この母集団では実験そのものが成立しません。**

---

## 7. 概算工数とデータ量

### 7-1. データ量（実測ベース）

| 設計 | 取得するもの | 圧縮後サイズ |
| --- | --- | --- |
| **最小構成**（基準日3点 × 全CVE母集団） | EPSS 3ファイル + KEV 1ファイル | **約 6 MB** |
| **案A**（Debian エコシステム） | 上記 + OSV Debian ZIP | **約 82 MB** |
| **案A（言語系6つ）** | 上記 + OSV 6エコシステム | **約 296 MB** |
| **ローリング設計**（2023-01-01 以降、日次全取得） | EPSS 日次 1,338ファイル + KEV | **約 2.2 GB**（展開 約 11 GB） |
| **ローリング設計**（全履歴 2021-04-14 以降、1,965日） | 同上 | **約 2.6 GB**（展開 約 13 GB） |

日次ファイルのサイズは年々増えています（実測）:

| 日付 | 圧縮後サイズ |
| --- | --- |
| 2021-04-14 | 243,932 B |
| 2022-10-01 | 745,502 B |
| 2023-01-01 | 770,241 B |
| 2024-01-01 | 1,397,032 B |
| 2025-01-01 | 1,640,466 B |
| 2026-01-01 | 2,055,383 B |
| 2026-08-01 | 2,507,180 B |

**節約案**: ローリング設計でも、日次を全部取る必要はありません。
**週次（約190ファイル、約 320 MB）または月次（約44ファイル、約 70 MB）**でも、
CVE の公開日に最も近いスナップショットを使えば近似できます。
EPSS スコアは日々わずかにしか動かないので、**週次で十分**だと考えます
（ただしモデル入れ替え日をまたぐ週は要注意）。

**計算量は問題になりません。** パイロット（母集団 38,000件 × 基準日3点）は
ローカルデータから **5.4秒**で完了しました。

### 7-2. 工数

1人日 = 6時間程度の実作業として見積もります。

**最小構成（案B: 全CVE母集団、基準日3点、CVSS は現在値で近似）**

| 作業 | 見積 |
| --- | --- |
| データ取得層（EPSS スナップショット取得・キャッシュ、KEV 取得、モデル版の記録） | 1.0人日 |
| 実験ランナー（母集団構築、戦略の適用、指標計算、信頼区間） | 1.0人日 |
| テスト（固定フィクスチャでの指標計算・境界値。**外部APIに触れないこと**） | 1.0人日 |
| レポート生成と文書化（前提・限界・出典の明記） | 1.0〜1.5人日 |
| 予備 | 0.5人日 |
| **合計** | **4.5〜5.5人日** |

**推奨構成（ローリング設計 + as-of CVSS + 案C の工数実感値）**

| 作業 | 見積 |
| --- | --- |
| 上記の最小構成 | 4.5〜5.5人日 |
| ローリング設計への変更（CVE公開日の特定、週次スナップショットの取得と索引化、観測窓の実装） | 2.0〜2.5人日 |
| as-of CVSS の再構成（`cvelistV5` の履歴 or 日次リリースから） | 2.0〜3.0人日 |
| 案C（実スキャン結果での工数実感値。イメージ 5〜10本、選定基準の文書化を含む） | 1.5〜2.0人日 |
| **合計** | **10〜13人日** |

### 7-3. 依存パッケージの追加について

CLAUDE.md の「依存パッケージは最小限」に照らすと、**この機能を triage-lens 本体に
入れるべきではありません。**

- CVSS ベクタの計算に `cvss`、集計に必要なら `pandas` 等が要ります
- これらは **レポート生成の実行時には不要**です

**`scripts/` 配下の運用スクリプト**として置き、依存を `[dev]` extras か
専用の extras に分離してください。CLAUDE.md も
「`scripts/` 配下の運用スクリプトは、認証不要の公開APIに限り利用してよい」と
書いており、今回のデータソース（EPSS / KEV / OSV / GitHub）はすべて認証不要です。

---

## 8. 実装可否の判定案

### 判定: **条件付き実装可（Conditional GO）**

**やる価値はあります。** triage-lens が「判断エンジン」を名乗るなら、
その判断が過去データでどう振る舞うかを自分で測って公開できることは、
主張そのものの裏付けになります。データも障害なくそろいます。

**ただし、次の5つを守れないなら、やらないほうがいいです。**

| # | 条件 | 理由 |
| --- | --- | --- |
| 1 | **ローリング設計にする**（静的コホートでは正例が足りない） | 正例 170件 → 約819件。捕捉率80%付近の95%信頼区間の幅が 12.0pt → 5.5pt |
| 2 | **信頼区間を必ず併記する** | 正例29件で「72.4% vs 82.8%」を出すのは誤誘導 |
| 3 | **「工数を減らす」を主軸に据える。「捕捉率で勝つ」と書かない** | パイロットでは捕捉率は CVSS≥7 のほうが高い。事実に反する主張はできない |
| 4 | **KEV 追加が悪用の代理指標にすぎないこと、EPSS の30日ホライズンと観測窓（中央値625日）が合っていないことを、レポートに明記する** | 「分からない入力では判断しない」という triage-lens の方針と同じ話 |
| 5 | **結果が triage-lens に不利でも公開する。事前に評価計画（母集団・戦略の定義・観測窓）を文書化してから実行する** | 後から都合のよい切り口を選べてしまう。それをやったら、この実験には何の価値もない |

### 段階的にやる場合の順序

**Phase 1（4.5〜5.5人日）**: 最小構成を作り、**社外に出さずに**結果を見る。
ここで「工数削減の効果が実測でどれくらいか」が分かります。

**Phase 2（+2.0〜2.5人日）**: ローリング設計に変更。正例を約800件に増やし、
信頼区間が実用的な幅になるか確認する。

**Phase 3（+2.0〜3.0人日）**: as-of CVSS。Phase 2 で結果が僅差だった場合のみ。

**Phase 4（+1.5〜2.0人日）**: 実スキャン結果での工数実感値。公開用の説明に使う。

**Phase 1 の結果を見てから Phase 2 以降を判断する**ことを推奨します。
Phase 1 で「工数削減の効果が小さい」と出たら、そこで止めるのが正しい判断です。

### やらないほうがいい場合

- **「triage-lens が優れている」という結論を先に決めているなら、やらないでください。**
  パイロットの実測は、素朴な読み方だとその逆を示します
- 出せる工数が 3人日未満なら、中途半端な数字を出すより、
  README に「まだ実測していない」と書いておくほうが誠実です

---

## 9. 出典

すべて 2026-08-31 に取得。（実測）と書いたものは、この調査で実際に叩いて確認したものです。

**EPSS**

- 過去スナップショット（実測）: <https://github.com/empiricalsec/epss_scores>
  （`https://raw.githubusercontent.com/empiricalsec/epss_scores/main/<YYYY>/epss_scores-<YYYY-MM-DD>.csv.gz`）
- 公式配布ページ（到達できず・未検証）: <https://www.first.org/epss/data_stats>
- API（到達できず・未検証）: <https://api.first.org/epss/>
- Usage Agreement 全文（実測、ミラー経由）:
  <https://raw.githubusercontent.com/aboutcode-org/scancode-toolkit/develop/src/licensedcode/data/licenses/first-epss-usage.LICENSE>
  （一次情報: <https://www.first.org/epss/#Usage-Agreement>）

**CISA KEV**

- データと LICENSE、JSON スキーマ（実測）: <https://github.com/cisagov/kev-data>
- 一次情報（到達できず）: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

**母集団の候補**

- OSV 一括ダウンロード（実測）: `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`、
  エコシステム一覧は `https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt`
- CVE List V5（実測: README のみ）: <https://github.com/CVEProject/cvelistV5>
- NVD API（到達できず・未検証）: <https://services.nvd.nist.gov/rest/json/cves/2.0>、
  レート制限の記載は <https://nvd.nist.gov/general/news/API-Key-Announcement>

**評価指標**

- Jay Jacobs, Sasha Romanosky, Octavian Suciu, Benjamin Edwards, Armin Sarabi,
  "Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with
  Community-Driven Insights", arXiv:2302.14172 (2023) — **到達できず。二次情報経由**
- Jay Jacobs, Sasha Romanosky, Benjamin Edwards, Michael Roytman, Idris Adjerid,
  "Exploit Prediction Scoring System", Digital Threats: Research and Practice, 2(3), 2021

**この文書の数値の再現方法**

パイロットは次のデータだけで再現できます（合計 約120MB、実行 5.4秒）。

```bash
# EPSS 基準日スナップショット
curl -sSLO https://raw.githubusercontent.com/empiricalsec/epss_scores/main/2023/epss_scores-2023-01-01.csv.gz
curl -sSLO https://raw.githubusercontent.com/empiricalsec/epss_scores/main/2024/epss_scores-2024-01-01.csv.gz
curl -sSLO https://raw.githubusercontent.com/empiricalsec/epss_scores/main/2025/epss_scores-2025-01-01.csv.gz

# KEV（dateAdded 付き）
curl -sSLO https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json

# 母集団（Debian エコシステム）
curl -sSL -o osv-Debian.zip https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip
```
