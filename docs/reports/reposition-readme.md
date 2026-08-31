# ポジショニング刷新（README / SECURITY.md）作業報告

- 日付: 2026-08-31
- ブランチ: `docs/reposition-readme`
- 対象: タスク1（README 説明文の刷新）、タスク2（SECURITY.md 追加）
- 状態: **PR まで。マージはしていません。**

---

## 1. 何を変えたか

### 1-1. 自己定義を「優先順位付け CLI」→「判断エンジン」に

`README.md` / `README.en.md` の冒頭を差し替えました。

| | 変更前 | 変更後 |
| --- | --- | --- |
| 日本語 | 「スキャナが出力した脆弱性の一覧を、公開データで優先順位付けして、『どれから直せばいいか』が分かるトリアージレポート（Markdown）にする CLI ツールです」 | 「スキャナが見つけた脆弱性を、**説明可能で再現可能な『対応判断』に変換するオープンな判断エンジン** です。スキャナの検出結果と公開された脅威データを入れると、根拠の付いたトリアージレポート（Markdown）が出てきます」 |
| 英語 | "A CLI tool that takes a scanner's vulnerability list, prioritises it using public data, and produces a **triage report (Markdown) that tells you what to fix first**." | "**An open, explainable vulnerability prioritisation engine.** Scanner findings and public threat data go in; reproducible triage decisions come out, as a Markdown report that shows its reasoning." |

英語は指示の原文が `prioritization`（米綴り）でしたが、`README.en.md` 全体が英綴り
（`prioritises`）で統一されているため、**`prioritisation` に合わせました。**
綴りだけの変更で、意味は変えていません。

### 1-2. 既存の差別化記述を新定義の下に整理

冒頭に見出しを1つ増やしました（日: 「この判断エンジンが守っていること」／
英: "What this engine commits to"）。**記述の中身は既存の各節から拾ったもので、
新しい主張は足していません。** それぞれ本文の該当節にリンクしています。

| 項目 | 中身 | リンク先（既存節） |
| --- | --- | --- |
| 決定論的判定 | P0〜P3 は KEV / EPSS / CVSS の値だけから機械的に決まる。同じ入力からは同じ結論 | 優先度の付け方 |
| AI は判断しない | `--ai` で AI が書くのは説明文だけ。順位を決めることも、書き換えることもしない | 優先順位は AI が決めるのではありません |
| 到達性は見ない | 見ているのは依存関係に該当版があるかだけ | このレポートで分かることの限界 |
| 分からない入力では判断しない | 取得・読み取りできなかった値は「低い」ではなく「不明」と書く | 「修正版なし」と「不明」の違い |

### 1-3. 機能の羅列は変更なし

- 「この版（v0.8.0）でできること・できないこと」の一覧、対応形式の表、
  オプションの説明、出力例 — **1文字も変えていません。**
- **Lens / VEX など未実装の機能は書いていません。** 実装していない機能の先取りは
  一切していません（`grep -n "VEX\|Lens" README*.md` で0件）。

### 1-4. Issue ポリシーの変更

| | 変更前 | 変更後 |
| --- | --- | --- |
| 日本語 | 「**Issue のコメントでの個別の返信は行っていません。**（中略）対応済みの Issue は、コメントなしで close することがあります」 | 「**Issue には `secleeman` として返信します。** ただし、**対応するかどうか、いつ対応するかは約束できません。**（中略）『対応しない』と返すこともあります」 |
| 英語 | "**We do not reply in the issue threads.**（中略）An issue may be closed without a comment once it has been addressed." | "**Issues get a reply from `secleeman`.** What cannot be promised is whether or when anything gets fixed（中略）it may be \"not planned\"." |

あわせて、**脆弱性の報告は Issue ではなく SECURITY.md の非公開窓口へ**という
1文を両方の README に足しました。

### 1-5. SECURITY.md（新規）

同じファイルに日本語 → 英語の順で書いています（GitHub が拾うのは `SECURITY.md` 1本のため）。

- **報告窓口**: GitHub Private Vulnerability Reporting（Security → Advisories →
  Report a vulnerability）。直リンクも記載。**メールアドレスは書いていません。**
  窓口がまだ有効化されていない場合に備えて、「詳細を書かずに連絡だけする Issue」を
  逃げ道として書いてあります。
- **対象/対象外**: 「スキャン対象に見つかった脆弱性」は triage-lens の入力であって
  triage-lens の脆弱性ではない、という切り分けを表で明記。
- **サポート対象バージョン**: **最新リリースのみ。** 1.0 前なのでバックポートなし。
- **対応の目安**: **ベストエフォート。SLA は書いていません。**
  「何日以内に返信します」と書かないことを、明示的に方針として書いています。

---

## 2. 動作確認

ドキュメントのみの変更で、コードには手を入れていません。品質ゲートは通っています。

```bash
git clone -b docs/reposition-readme https://github.com/secleeman/triage-lens.git
cd triage-lens
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/ruff check .
.venv/bin/pytest
```

実測結果（2026-08-31）:

```
$ .venv/bin/ruff check .
All checks passed!

$ .venv/bin/pytest
910 passed in 2.49s
```

冒頭の表示を確認する:

```bash
head -35 README.md
head -38 README.en.md
head -30 SECURITY.md
```

---

## 3. オーナーの作業（PR マージとは別に必要なもの）

### 3-1. Private Vulnerability Reporting の有効化

**これはリポジトリの設定操作なので、こちらでは実行していません。**
SECURITY.md は「有効化されている前提」で書いてあるため、**マージ後に有効化してください。**
有効化するまでは、報告者に窓口のボタンが見えません（SECURITY.md にはその場合の
逃げ道も書いてありますが、正規の窓口は開けたほうが良いです）。

手順（画面から）:

1. <https://github.com/secleeman/triage-lens> を開く
2. **Settings**（リポジトリ名の下のタブ）
3. 左サイドバーの **Security** セクション → **Advanced Security**
4. **Private vulnerability reporting** の右の **Enable** を押す

> **見つからない場合**: GitHub はこの項目の場所を何度か動かしています。
> 以前は **Settings → Code security and analysis** にありました。
> 現在の画面で「Private vulnerability reporting」を探してください。
> （参考: [community discussion #174783](https://github.com/orgs/community/discussions/174783) —
> 「見つからない」という報告が実際に上がっています）

手順（API から。同じことを CLI でやる場合）:

```bash
gh api --method PUT /repos/secleeman/triage-lens/private-vulnerability-reporting
# 確認
gh api /repos/secleeman/triage-lens | jq '.security_and_analysis'
```

補足:

- **public リポジトリのみの機能**です。triage-lens は public なので対象です。
- 有効化できるのは **リポジトリの owner / admin** です。
- 有効化すると、報告者に Security タブの Advisories 画面で
  **Report a vulnerability** ボタンが出ます。
- 報告のやり取りは、Advisory を公開するまで報告者とメンテナだけに見えます。
- 匿名性について: この窓口は GitHub アカウント上のやり取りなので、
  **`secleeman` 名義のまま完結します。メールアドレスの開示は不要です。**

出典（本文を読んだうえで記載していますが、この作業環境からは
`docs.github.com` に直接アクセスできなかったため、**画面のラベルは
実際の設定画面で確認してください**）:

- <https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository>
- <https://github.blog/changelog/2023-08-16-enable-or-disable-private-vulnerability-reporting-on-repositories-via-rest-api/>

### 3-2. 有効化したあとの確認

```bash
# 有効なら、このURLに「Report a vulnerability」のフォームが出る
open https://github.com/secleeman/triage-lens/security/advisories/new
```

---

## 4. やっていないこと

- **マージしていません。** PR で止めています。
- **リポジトリ設定は変更していません。**（Private Vulnerability Reporting の
  有効化はオーナー判断のため）
- 機能・優先度判定・テストには一切手を入れていません。
- 未実装機能（Lens / VEX 等）への言及は書いていません。
