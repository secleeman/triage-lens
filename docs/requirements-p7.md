# Phase 7 要件 — SPDX（JSON）入力対応（v0.7.0）

> 2026-08-30 のオーナー指示にもとづく。判断が要る論点は**推奨案を仮採用**して実装まで
> 進めてある（末尾の「論点と仮採用」を参照）。裁定で差し戻された項目は実装ごと直す。
> 本書に書いていないことは実装しない。

## 背景

Phase 6 の調査で、入力形式の穴が1つ残っていた。

- CycloneDX と Trivy JSON は読める。**SPDX は読めない**
- SPDX は SBOM の標準としていちばん広く使われている形式で、Trivy 自身も
  `--format spdx-json` で出せる
- 現状 SPDX を渡すと「Trivy の JSON 出力ではないようです」というエラーになる。
  利用者から見ると、標準的な SBOM を渡したのに理由の分からない拒否をされる

同時に、SPDX には CycloneDX と決定的に違う性質がある。**SPDX 2.x は部品表であって、
脆弱性の一覧を持てる場所がほとんど無い。** この性質をどう扱うかが Phase 7 の中心にある。

## ゴール

SPDX（JSON）を渡した利用者が、**次に何をすればよいかが分かる**状態にする。

- SPDX を第3の入力形式として受け付ける（形式は自動判別。利用者に指定させない）
- 脆弱性情報が入っていない SPDX を渡したとき、**「検出0件」を「安全」と読ませない**
- SPDX が本番 / 開発の区別を持っているときは、CycloneDX と同じように区別して表示する

## スコープ

1. SPDX 2.2 / 2.3 の JSON 表現を入力形式として読む
2. 脆弱性情報を持たない SPDX に対する注記（レポート本文 + 標準エラー）
3. `relationships` による本番依存 / 開発依存の区別
4. 対応していない SPDX（2.1 以前 / 3.x）への、理由が分かるエラーメッセージ
5. README（日英）の入力形式の記述の更新

上記以外は実装しない。

## 変えないもの（最重要の制約）

- **スコアリングは一切変更しない。** `scoring.py` に手を入れない。
  `tests/test_scoring_unchanged.py` は1行も変えない
- **既存の2形式（Trivy JSON / CycloneDX）の読み取り結果を変えない。** 入力を増やすだけ
- **`--fail-on` の挙動を変えない。** SPDX で検出0件になったときも終了コードは従来どおり
  （→ 論点 8）
- レポートの節の並び（Phase 6 の「4. レポートの節の並び」）を変えない

---

## 機能要件

### 1. 事前調査の結果（この設計の前提）

実装方針を決める前に、SPDX の仕様と生成ツールの実物を調べた。

| 調べたこと | 分かったこと | 出典 |
| --- | --- | --- |
| SPDX 2.x に脆弱性の一覧はあるか | **無い。** CycloneDX の `vulnerabilities[]` に相当する項目そのものが存在しない | SPDX 2.3 仕様 |
| CVE を書ける場所はあるか | `packages[].externalRefs[]` の `referenceCategory: SECURITY`。**2.3 で `advisory` / `fix` / `url` が追加された**。仕様の例が `https://nvd.nist.gov/vuln/detail/CVE-2020-28498` そのもの | SPDX 2.3 仕様 Annex F |
| SPDX 2.2 の SECURITY 参照 | **`cpe22Type` と `cpe23Type` の2つだけ。** CVE を書く場所が無い | SPDX 2.2.2 仕様 Annex F |
| 本番 / 開発を区別できるか | **できる。** `relationships[].relationshipType` に `DEV_DEPENDENCY_OF` / `TEST_DEPENDENCY_OF` / `RUNTIME_DEPENDENCY_OF` / `BUILD_DEPENDENCY_OF` / `OPTIONAL_DEPENDENCY_OF` / `PROVIDED_DEPENDENCY_OF` / `DEPENDENCY_OF` がある | SPDX 2.3 仕様 |
| CycloneDX の `scope` との違い | SPDX の関係は**書かれていれば明示の記述**で、「省略時は本番とみなす」という既定値の規則が無い。`scope` のような取り違えが起きにくい | 同上 |
| CVSS を書けるか | **書けない。** SPDX 2.x に深刻度スコアの項目は無い | 同上 |
| 修正版を書けるか | **書けない。** `fix` は修正コミットの URL であって、版数ではない | 同上 |
| Trivy の `--format spdx-json` 出力 | 部品表のみ。**脆弱性は入らない** | Trivy ドキュメント |
| 既存の SBOM から脆弱性を出す経路 | `trivy sbom <ファイル>` が SPDX / SPDX-JSON を**入力として**受け取り、脆弱性スキャンを行う | Trivy ドキュメント（SBOM scanning） |

**この調査から出る結論は3つ。**

1. **SPDX 入力の既定の結果は「検出0件」になる。** 実際に出回る SPDX（Trivy / Syft の
   出力）は SECURITY 参照に CVE を持たない。0件を「脆弱性が無い」と読ませない手当てが
   本体の仕事になる（→ 3.）
2. **SPDX 2.2 では CVE が原理的に入らない。** それでも 2.2 を読めるようにする意味はある
   （対象名と依存の区別は取れる）。読めないふりをすると、利用者は理由に辿り着けない
3. **本番 / 開発の区別は CycloneDX より素直に取れる。** `relationships` は明示の記述で、
   `scope` のような既定値の落とし穴が無い

### 2. 対象バージョンと判別

#### 2-1. 判別

`spdxVersion` が文字列として存在すれば SPDX 文書とみなす。CycloneDX（`bomFormat`）とも
Trivy JSON（`Results`）とも項目が重ならないため、誤判定の余地は無い。

判別の順序は `CycloneDX → Trivy → SPDX` とする（既存2形式の判定に手を入れない）。

#### 2-2. 対応するバージョン

| `spdxVersion` | 扱い |
| --- | --- |
| `SPDX-2.2` / `SPDX-2.3`（`SPDX-2.3.1` のような細かい版も含む） | **読む** |
| `SPDX-2.1` 以前 / `SPDX-2.4` 以降 | **読まない。**「2.2 / 2.3 に対応している」と版数を示して落とす |
| SPDX 3.x（`@context` を持つ JSON-LD。`spdxVersion` を持たない） | **読まない。** 3.x は未対応だと名指しで落とす（→ 論点 5） |

版数の比較は `SPDX-<major>.<minor>` の先頭2つの数字だけを見る。3つ目以降は無視する。
読めない書式は「SPDX として解釈できない」として落とす。

### 3. 脆弱性情報の有無の扱い（この Phase の中心）

#### 3-1. 脆弱性の取り出し先

`packages[].externalRefs[]` のうち、**`referenceCategory` が `SECURITY`** のものを見て、
`referenceLocator` から CVE ID（`CVE-<西暦>-<番号>`）を抜き出す。

- 対象の `referenceType` は **`advisory` / `fix` / `url`**（→ 論点 3）
- `cpe22Type` / `cpe23Type` は**見ない**。CPE は製品の識別子であって脆弱性ではない。
  ここから CVE を引くには別のデータ源（NVD の CPE 検索）が要り、規範（CLAUDE.md 4）の
  判断が必要になる（→ Phase 7 でやらないこと）
- 1つの package に複数の SECURITY 参照があれば、**CVE ごとに1行**にする
- 同じ CVE が同じ package に2回書かれていたら1件にまとめる（既存の `deduplicate`）
- CVE ID は**語境界で挟んで**探す。`XCVE-2020-0001` のような文字列から偽の検出を
  作らないため
- **SPDX 2.2 の文書に 2.3 の参照型（`advisory` など）が書かれていても読む**（→ 論点 15）

**この参照は「影響を受ける」と断言していない。** 仕様上 `advisory` は「影響あり」の
勧告にも「影響なし」の表明にも使え、`url` に至っては種類を特定しない関連情報を指す。
つまり **triage-lens が SPDX から作る検出は、多めに出ることがある**（→ 論点 14）。
それでも拾う側に倒すのは、拾わなければ SPDX からは何も出せず、実在する脆弱性を
黙って落とすことになるため。Phase 6 の「多めに出るだけなら見落としにはならない」と
同じ判断で、レポート末尾の限界の注意書きがこの不確かさを受け持つ。

#### 3-2. 読み取る項目の対応

| triage-lens の項目 | SPDX のどこから取るか | 取れないとき |
| --- | --- | --- |
| CVE ID | `externalRefs[]`（SECURITY / advisory・fix・url）の `referenceLocator` | その package からは1件も作らない |
| パッケージ名 | `packages[].name` | `(不明)` |
| 現在バージョン | `packages[].versionInfo` | `(不明)` |
| 修正バージョン | **SPDX に無い** | 常に**「不明」**（`fixed_version_known=False`）。「修正版なし」と断定しない |
| CVSS | **SPDX に無い** | 常に `None`。EPSS と KEV だけで優先度が付く |
| 検出箇所 | `externalRefs[]` の purl（`referenceCategory: PACKAGE-MANAGER` / `referenceType: purl`）→ 無ければ `SPDXID` → 無ければ文書名 | `(検出箇所不明)` |
| 対象名 | 文書の `name` | `(名称不明)` |

**CVSS が常に不明になる影響を、優先度の判定側では特別扱いしない。** 既存の `classify()` は
CVSS 不明をすでに扱える（理由文に「CVSSが不明で判定に使えていない」と出る）。
SPDX のためにスコアリングを変えることはしない。

#### 3-3. 脆弱性が1件も取れなかったときの表示

**エラーにはしない。0件のレポートを出したうえで、0件の意味を書く**（→ 論点 1）。

レポートの冒頭（既存の取得失敗警告と同じ位置、`⚠️` は付けない）に1行出す。

- ja: `この入力は部品表（SBOM）のみで、脆弱性の一覧を含んでいません。「検出0件」は脆弱性が無いという意味ではありません。 `trivy sbom <ファイル> --format json` でこの SBOM をスキャンした出力を渡すと、優先順位を付けられます。`
- en: `This input is a bill of materials only - it carries no vulnerability list. "0 findings" does not mean there are none. Run `trivy sbom <file> --format json` on this SBOM and pass that output instead to get a prioritised report.`

**同じことを標準エラーにも1行出す。** CI で `--fail-on` を付けて回している利用者は、
レポート本文を読まずに終了コードだけを見る。0件で緑になったことに気づけないと、
「静かに壊れた」状態になる。

この注記を出す条件は「**SPDX を読んで脆弱性が0件だったとき**」に限る。Trivy JSON や
CycloneDX の0件には出さない（→ 論点 9）。

### 4. 本番依存 / 開発依存の区別

#### 4-1. 判定（package 1件ごと）

`relationships[]` を読み、`relatedSpdxElement` ではなく **`spdxElementId` の側**（＝依存
される側ではなく依存している側）が、その package を指す関係を見る。

| `relationshipType` | 扱い |
| --- | --- |
| `DEV_DEPENDENCY_OF` / `TEST_DEPENDENCY_OF` | **開発依存のみ** |
| `RUNTIME_DEPENDENCY_OF` / `BUILD_DEPENDENCY_OF` / `OPTIONAL_DEPENDENCY_OF` / `PROVIDED_DEPENDENCY_OF` / `DEPENDENCY_OF` / `DEPENDS_ON` | **本番依存** |
| 関係が書かれていない package | **本番依存** |

- `BUILD_DEPENDENCY_OF` を本番側に置くのは、ビルド依存が生成物にコードを混ぜうるため
  （→ 論点 7）。Phase 6 の「迷ったら本番依存に倒す」をそのまま適用する
- 同じ package に開発用と**明示の**本番用の関係が両方あるときは**本番依存**にする。
  片方でも本番なら本番（既存の重複マージと同じ考え方）
- **スコープを語らない関係（`DEPENDENCY_OF` / `DEPENDS_ON`）は、開発依存の記述を
  打ち消さない。** とくに `DEPENDS_ON` は主語が「依存する側」で、主語自身のスコープに
  ついては何も言っていない。これで開発依存の印を消すと、開発依存が本番の表に混ざる

#### 4-2. 入力全体を「区別できる / できない」で分ける

Phase 6 の 1-3 と同じ枠組みを使う。**区別を語る関係が1件も無ければ「区別できない」** とし、
区別できているかのように見せない。

| 状態 | 条件 |
| --- | --- |
| 区別できる | `DEV_DEPENDENCY_OF` / `TEST_DEPENDENCY_OF` / `RUNTIME_DEPENDENCY_OF` / `BUILD_DEPENDENCY_OF` / `OPTIONAL_DEPENDENCY_OF` / `PROVIDED_DEPENDENCY_OF` が1件以上ある |
| 区別できない | 上記が1件も無い（`DEPENDENCY_OF` / `DEPENDS_ON` しか無い場合を含む） |

**数えるのは `packages[]` に載っている部品を指す関係だけ。** SPDX の関係はファイルや
文書のあいだにも書けるため、`SPDXRef-File-... TEST_DEPENDENCY_OF ...` のような関係まで
数えると、**部品については材料が無いのに「区別できた（全件が本番依存）」というレポートを
出してしまう。** Phase 6 で `metadata.component` を判別の材料から除いたのと同じ理由。

`DEPENDENCY_OF` と `DEPENDS_ON` を「区別できる材料」に数えないのは、仕様上どちらも
**スコープを語らない**関係だから。これらだけの SBOM を「区別できた（全件が本番依存）」と
出すのは、Phase 6 が避けた誤りと同じ。

#### 4-3. `scope` 由来の注記は出さない

Phase 6 で入れた「本番 / 開発の分類は SBOM の scope 値に基づいています」という注記
（`scope_basis_note`）は、**SPDX 入力では出さない**。SPDX に `scope` は無く、関係型は
明示の記述で、注記が指す揺れ（生成ツールによる `scope` の誤用）が起こらないため。

実装上は既存の `ScanInput.dev_property_used` を真にして注記を抑止する。この項目名は
CycloneDX 由来で SPDX には合わないが、**改名は Phase 7 の範囲外**とする（→ 論点 13）。

### 5. エラーメッセージ

| 状況 | メッセージの要点 |
| --- | --- |
| SPDX 2.1 以前 / 2.4 以降 | 対応しているのは 2.2 / 2.3 であること、渡された版数 |
| SPDX 3.x | 3.x は未対応であること、2.2 / 2.3 で出力し直す案内 |
| `packages` が一覧でない | SPDX の構造が想定と異なること |
| 想定外の構造 | 例外の型と内容を1行で。**スタックトレースは出さない**（既存方針） |

いずれも既存の `InputError` を使い、終了コードは 2（入力エラー）のまま変えない。

### 6. CLI とレポートへの影響

- `report` サブコマンドのヘルプと入力の説明に SPDX を足す（`Trivy JSON / CycloneDX JSON /
  SPDX JSON`）
- 形式判別に失敗したときのメッセージにも SPDX を足す。現状は Trivy と CycloneDX しか
  挙げていないため、SPDX を渡して落ちた利用者が「SPDX は対応していないのか」を判断できない
- レポートの節の並びは変えない。3-3 の注記は既存の警告と同じ位置に入る

---

## テスト方針

すべて外部に接続しない。CI（pytest + ruff）が緑になるまで PR を完成扱いしない。

| テスト | 何を守るか |
| --- | --- |
| `tests/test_spdx.py`（新規） | 版数の判定（2.2 / 2.3 を読む・2.1 / 2.4 / 3.x を落とす）/ SECURITY 参照からの CVE 抽出（advisory・fix・url を拾い、cpe を拾わない）/ 複数 CVE の展開 / 修正版と CVSS が「不明」になること / 検出箇所の決め方 / `relationships` による本番・開発の区別 / 区別できる・できないの判定 / 壊れた構造で `InputError` になること |
| `tests/test_loader.py`（追記） | SPDX が自動判別で読めること / 未対応形式のメッセージに SPDX が含まれること |
| `tests/test_report.py`（追記） | 脆弱性を持たない SPDX で 3-3 の注記が出ること / Trivy・CycloneDX の0件では出ないこと / `scope_basis_note` が SPDX では出ないこと |
| `tests/test_cli.py`（追記） | 標準エラーに 3-3 の1行が出ること / 終了コードが変わらないこと |
| `tests/test_i18n.py`（既存の仕組み） | 追加した文言キーが日英で揃っていること |
| `tests/test_scoring_unchanged.py`（**変更禁止**） | スコアリングの回帰。**1行も変えない** |

新しい fixture（架空のプロジェクト名 + 公開されている CVE のみ。CLAUDE.md 5）:

- `tests/fixtures/spdx_sample.json` — SPDX 2.3。SECURITY 参照に CVE を持ち、`relationships` で
  本番 / 開発を区別できる
- `tests/fixtures/spdx_sbom_only.json` — SPDX 2.3。部品表のみ（SECURITY 参照なし、
  スコープを語る関係なし）。実際に出回る SBOM に相当する
- `tests/fixtures/spdx_22.json` — SPDX 2.2。CVE を書く場所が無いことの確認用

---

## Phase 7 でやらないこと（実装禁止）

- **スコアリングの変更**（閾値・判定条件・理由文・並び順）
- SPDX 3.x 対応（構造が別物。需要を見てから）
- SPDX の tag-value 形式 / RDF / YAML 表現（**JSON のみ**）
- `cpe22Type` / `cpe23Type` から CVE を引くこと。**別のデータ源（NVD の CPE 検索）が
  必要になり、規範（CLAUDE.md 4）に触れる**
- SBOM と脆弱性リストを別ファイルで受け取って突き合わせる機能（`--sbom` + `--vulns` のような
  入力の複数指定）
- SPDX の出力（triage-lens は読むだけ）
- `examples/` への SPDX の出力例の追加（→ 論点 12）
- CycloneDX の部品表のみ入力に対する同じ注記（→ 論点 9）
- `ScanInput.dev_property_used` の改名（→ 論点 13）
- npm audit JSON / OSV JSON のネイティブ対応（Phase 6 の調査結果のまま据え置き）

---

## 論点と仮採用（オーナー裁定待ち）

**すべて推奨案を仮採用して実装済み。** 差し戻す場合は該当項目だけを直せばよいように、
論点ごとに実装箇所を書いてある。

| # | 論点 | 仮採用 | 理由 | 差し戻すときに直す場所 |
| --- | --- | --- | --- | --- |
| 1 | 脆弱性を持たない SPDX を**エラーにするか** | **エラーにせず0件レポート + 注記** | エラーにすると、CVE を持つ SPDX まで読めなくなる。CycloneDX の部品表と扱いを揃える | `spdx.py` / `report.py` |
| 2 | CVE の取り出し先 | **SECURITY 参照の `referenceLocator`** | SPDX 2.x で CVE を書ける唯一の場所 | `spdx.py` |
| 3 | `fix` / `url` も見るか | **見る（`advisory` と同じ扱い）** | どれも「この部品に関係する脆弱性」を指す。取りこぼす側の損のほうが大きい | `spdx.py` の `SECURITY_REFERENCE_TYPES` |
| 4 | SPDX 2.2 を読むか（CVE は原理的に入らない） | **読む** | 対象名と依存の区別は取れる。弾くと利用者が理由に辿り着けない | `spdx.py` の `SUPPORTED_VERSIONS` |
| 5 | SPDX 3.x の扱い | **名指しで未対応と伝える** | 「Trivy でも CycloneDX でもない」と言われるより、次の行動が決まる | `spdx.py` / `loader.py` |
| 6 | 本番 / 開発の区別に `relationships` を使うか | **使う** | 明示の記述で、`scope` のような既定値の落とし穴が無い | `spdx.py` |
| 7 | `BUILD_DEPENDENCY_OF` の扱い | **本番依存** | ビルド依存は生成物にコードが入りうる。Phase 6 の「迷ったら本番」に従う | `spdx.py` の `DEV_RELATIONSHIP_TYPES` |
| 8 | 0件のとき `--fail-on` を落とすか | **落とさない（現状維持）** | `--fail-on` の意味を変えるのは別の意思決定。代わりに標準エラーへ1行出す | `cli.py` |
| 9 | CycloneDX の部品表のみ入力にも同じ注記を出すか | **出さない** | Phase の範囲外。SPDX は0件が既定だが、CycloneDX は例外的な状態で、必要性が違う | `report.py` |
| 10 | CVSS が常に不明になることへの手当て | **しない** | 既存の `classify()` が CVSS 不明を扱える。SPDX のためにスコアリングを触らない | （変更なし） |
| 11 | 修正版の扱い | **常に「不明」** | 「修正版なし」と断定すると、直せるものを直せないと読ませる | `spdx.py` |
| 12 | `examples/` に SPDX の例を足すか | **足さない** | 既存の例は P0〜P3 が揃っていることを CI で見ている。0件の例はその枠組みに乗らない | `examples/` |
| 13 | `dev_property_used` の改名 | **据え置き** | 呼び出し側（`cyclonedx` / `report` / `cli` / テスト）に波及する。名前の是正だけで別 PR にするほうが安全 | `models.py` ほか |
| 14 | SECURITY 参照は「影響あり」とは限らない | **それでも検出として出す** | 拾わなければ SPDX からは何も出せない。多めに出るだけなら見落としにはならず、限界の注意書きが不確かさを受け持つ | `spdx.py` の `SECURITY_REFERENCE_TYPES` |
| 15 | SPDX 2.2 に 2.3 の参照型が書かれていた場合 | **仕様違反だが読む** | 弾くと、実在する脆弱性を「版数が古いから」という理由で黙って落とすことになる | `spdx.py` |
