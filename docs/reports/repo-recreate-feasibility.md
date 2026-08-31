# 案N「リポジトリ作り直し」実現性検証

- 日付: 2026-08-31
- 案N: `secleeman/triage-lens` を削除 → 同 Org 同名で再作成 → クリーンな `main` を push し、
  PR・Actions 29件・孤立コミット `b5cff9b`・セッションURL を一括で消す
- **実行はしていません。** 削除・再作成・設定変更・PR 操作のいずれも行っていません。
  この文書は調査と報告だけです。
- 数値と仕様は一次情報（公式ドキュメントのソース、warehouse のソースコード、GitHub API）
  から取りました。検証できなかった項目は「**未検証**」と明記しています。

---

## 0. 結論

### 判定: **Conditional GO。ただし「一括消去できる」という前提は成立しません。**

検証の結果、**良い驚きと悪い驚きが1つずつ**出ました。

| | 結果 |
| --- | --- |
| 🟢 **良い驚き** | **PyPI Trusted Publishing は壊れません。** warehouse のソースを読んだところ、OIDC の照合に**リポジトリの数値ID（`repository_id`）は使われていません**。むしろ明示的に「照合しない」リストに入っています。同 Org・同名で作り直せば、**publisher の再登録は不要**です |
| 🔴 **悪い驚き** | **GH Archive に、既に出てしまっている可能性が高い。** GitHub の公開イベントは第三者（GH Archive）が毎時アーカイブし、BigQuery の公開データセットとして誰でも SQL で引けます。**リポジトリを消しても、この記録は消せません。** そして PushEvent のペイロードには**コミット author のメールアドレスが含まれます** |

### つまり案Nは「github.com 上の見た目」しか消せません

| 消したい露出 | 案N で消えるか |
| --- | --- |
| github.com 上の PR #1〜#4（author = 個人アカウント） | ✅ 消える |
| github.com 上の Actions 実行 29件 | ✅ 消える |
| github.com 上の孤立コミット `b5cff9b` | ✅ 消える（fork 0 のため確実） |
| PR 本文の Claude Code セッションURL | ✅ 消える |
| **GH Archive のイベント記録（actor = 個人アカウント）** | ❌ **消せない** |
| **GH Archive の PushEvent に含まれるコミット author のメール** | ❌ **消せない**（要確認・[6-2](#6-2-gh-archive-最大の残存露出)） |
| Org 監査ログ | ❌ 残る（ただし**非公開**。org owner のみ閲覧、180日で消える） |

**「casual な観察者からは見えなくなる」のが案Nの実際の効果です。**
「調べようと思った人から隠せる」わけではありません。そこを承知のうえで
やるなら妥当、というのが Conditional GO の中身です。

### 実行するなら、先にこれを確かめてください

- [ ] **A. 直近1週間の clone 数**（Insights → Traffic）。**100 を超えていたら中止。**
      名前空間が引退して同名で作り直せなくなる可能性があります（[3-3](#3-3-最大のリスク-名前が再利用できない場合)）
- [ ] **B. GH Archive に既に出ているか**（[6-2](#6-2-gh-archive-最大の残存露出) のコマンド）。
      **既にメールが出ていたら、案Nの費用対効果は大きく下がります**
- [ ] **C. Org が repo 削除を許可しているか**（org のポリシー設定）

**B が黒なら、案Nをやる意味はかなり薄くなります。** 先に B を確認してください。

---

## 1. 調査環境の制約

前回までと同じく、この環境からは GitHub へ**未認証のリクエストを出せません**。
加えて今回は、外部アーカイブのホストも遮断されていました。

| ホスト | 状態 | 影響 |
| --- | --- | --- |
| `raw.githubusercontent.com` | ✅ | 公式ドキュメント・warehouse・gharchive のソースを直接取得 |
| `pypi.org` | ✅ | 配布物のメタデータを取得 |
| GitHub API（MCP 経由） | ✅ | 認証済み（個人アカウント名義）の view のみ |
| `github.com` / `api.github.com`（直接） | ❌ 403 | ハーネスのプロキシが遮断 |
| **`data.gharchive.org`** | ❌ 403 | **GH Archive に実際に出ているかを実測できていません** |
| **`archive.softwareheritage.org`** | ❌ 403 | **Software Heritage のクロール状況を実測できていません** |
| **`web.archive.org`** | ❌ 403 | **Wayback Machine の取得状況を実測できていません** |

**検証項目5の「外部アーカイブが既にクロール済みか実測」は、この環境では実行できませんでした。**
仕組みは一次情報で確認し、[6章](#6-検証項目5-リポジトリ外に残る露出)に
オーナーが自分で1分で確かめるコマンドを用意しました。

なお、第三者サービスへの問い合わせは**読み取り専用のものだけ**を試みています。
Software Heritage の "Save Code Now" のような**アーカイブを新規に発生させる操作は
一切行っていません**（それをやると、消したいものを永久保存してしまうため）。

---

## 2. 検証項目1: PyPI Trusted Publishing

### 結論: **壊れません。再登録も不要です。**

これは案Nにとって決定的に有利な材料です。そして**移管（案A/B）の場合とは正反対**です。

### 2-1. 照合に使う全フィールド（warehouse のソース）

`warehouse/oidc/models/github.py` の `GitHubPublisherMixin` から、そのまま引用します。

**DB に保存されるフィールド（＝登録時に指定するもの）:**

```python
    repository_name: Mapped[str] = mapped_column(String, nullable=False)
    repository_owner: Mapped[str] = mapped_column(String, nullable=False)
    repository_owner_id: Mapped[str] = mapped_column(String, nullable=False)
    workflow_filename: Mapped[str] = mapped_column(String, nullable=False)
    environment: Mapped[str] = mapped_column(String, nullable=False)
```

**必ず検証されるクレーム:**

```python
    __required_verifiable_claims__: dict[str, CheckClaimCallable[Any]] = {
        "repository": _check_repository,
        "repository_owner": check_claim_binary(str.__eq__),
        "repository_owner_id": check_claim_binary(str.__eq__),
        "job_workflow_ref": _check_job_workflow_ref,
        "jti": check_existing_jti,
        "event_name": _check_event_name,
    }

    __required_unverifiable_claims__: set[str] = {"ref", "sha"}

    __optional_verifiable_claims__: dict[str, CheckClaimCallable[Any]] = {
        "environment": _check_environment,
    }
```

**検証しないクレーム（ここが決め手です）:**

```python
    __unchecked_claims__ = {
        "sub",
        "actor",
        "actor_id",
        "run_id",
        "run_number",
        "run_attempt",
        "head_ref",
        "base_ref",
        "ref_type",
        "repository_id",          ← ★ リポジトリの数値ID
        "workflow",
        "repository_visibility",
        "workflow_sha",
        "job_workflow_sha",
        "workflow_ref",
        "runner_environment",
        "environment_node_id",
        "enterprise",
        "enterprise_id",
        "ref_protected",
        "check_run_id",
    }
```

**`repository_id` は `__unchecked_claims__` に入っています。**
GitHub の OIDC トークンには `repository_id` が含まれますが、
**PyPI はそれを照合に使いません。**

### 2-2. 各検証関数の中身（すべて名前ベース）

```python
def _check_repository(ground_truth, signed_claim, _all_signed_claims, **_kwargs) -> bool:
    # Defensive: GitHub should never give us an empty repository claim.
    if not signed_claim:
        return False
    # GitHub repository names are case-insensitive.
    return signed_claim.lower() == ground_truth.lower()
```

```python
def _check_job_workflow_ref(ground_truth, signed_claim, all_signed_claims, **_kwargs) -> bool:
    # We expect a string formatted as follows:
    #   OWNER/REPO/.github/workflows/WORKFLOW.yml@REF
```

```python
def _check_event_name(ground_truth, signed_claim, _all_signed_claims, **_kwargs) -> bool:
    if signed_claim == "pull_request_target":
        raise InvalidPublisherError(...)
    return True
```

`_check_environment` は environment 名の大文字小文字を無視した比較です。

**照合はすべて「名前の文字列」で行われ、リポジトリの実体（ID）は見ていません。**

### 2-3. 作り直した場合にどうなるか

| クレーム | 作り直し前 | 作り直し後 | 一致するか |
| --- | --- | --- | --- |
| `repository` | `secleeman/triage-lens` | `secleeman/triage-lens` | ✅ 同じ |
| `repository_owner` | `secleeman` | `secleeman` | ✅ 同じ |
| `repository_owner_id` | `322111724`（**Org の ID**） | `322111724` | ✅ 同じ（Org は消さないため） |
| `repository_id` | `1349631653` | **変わる** | — **照合対象外** |
| `job_workflow_ref` | `.../release.yml@refs/tags/vX.Y.Z` | 同じ（`release.yml` を同じパスに置く限り） | ✅ |
| `environment` | `pypi` | `pypi`（再作成が必要） | ✅ |

**結論: 同 Org・同名・同ワークフローファイル名・同 environment 名で作り直せば、
Trusted Publisher はそのまま通ります。再登録は不要です。**

> **前回の移管（案A/B）調査との違い**: あちらは所有者が変わるため
> `repository_owner` と `repository_owner_id` の両方が変わり、必ず壊れました。
> 今回は所有者（Org）を変えないので、変わるのは照合対象外の `repository_id` だけです。

### 2-4. 実行時に気をつけること

- **`release.yml` のファイル名を変えない**（`job_workflow_ref` に効きます）
- **`pypi` という environment を再作成する**（Settings → Environments）。
  environment が無い状態でタグを push すると、`environment` クレームが空になり
  `_check_environment` が `False` を返して弾かれます
- **リリースできない期間**: 削除してから再作成・push が終わるまでの間だけです。
  publisher 側は何も触らないので、作業は数十分で済みます
- **万一 `invalid-publisher` が出たら**: PyPI の Publishing 画面で
  owner / repo / workflow / environment の4つを見比べてください。
  作り直しで変わりうるのは environment の綴りだけです

---

## 3. 検証項目2: 削除 → 同名再作成の制約

### 3-1. 削除の公式仕様（原文ママ）

> {Organization owners and repository admins} delete an organization repository, and these users may be prevented from deleting a repository by an organization or enterprise policy.

> Deleting a public repository will not delete any forks of the repository.

> **Warning**
> * Deleting a repository will **permanently** delete team permissions. This action **cannot** be undone.
> * Deleting a private or internal repository will delete all forks of the repository.

> Some deleted repositories can be restored within 90 days of deletion.

操作手順（原文ママ）:

> 1. On the "General" settings page (which is selected by default), scroll down to the "Danger Zone" section and click **Delete this repository**.
> 1. Click **I want to delete this repository**.
> 1. Read the warnings and click **I have read and understand these effects**.
> 1. To verify that you're deleting the correct repository, in the text box, type the name of the repository you want to delete.
> 1. Click **Delete this repository**.

### 3-2. 削除で消えるもの / 残るもの

| | 内容 |
| --- | --- |
| **消える** | コード、ブランチ、タグ、**Issue、Pull Request**、Wiki、**Actions 実行履歴と artifact**、Star、Watch、リポジトリ設定、environment、webhook、deploy key、team permission、Insights |
| **残る（public repo の場合）** | **fork**（今回は fork 0 なので該当なし） |
| **残る（リポジトリ外）** | Org 監査ログ、**GH Archive などの第三者アーカイブ**（[6章](#6-検証項目5-リポジトリ外に残る露出)） |
| **90日間 GitHub 内に保持** | 復元用のデータ。**公開はされませんが、消えてもいません** |

**復元について（原文ママ）:**

> A deleted repository can be restored within 90 days, unless the repository was part of a fork network that is not currently empty.

> **It can take up to an hour after a repository is deleted before that repository is available for restoration.**

> Restoring a repository will not restore team permissions.

> Organization owners can restore deleted repositories that were owned by the organization.

**この復元機能が、案Nの唯一の安全網です。** 再作成に失敗しても、90日以内なら
元に戻せます（PR も Actions も一緒に戻ってきますが、少なくとも「repo を失う」
事態は避けられます）。ただし**削除直後の最大1時間は復元できません。**

### 3-3. 最大のリスク: 名前が再利用できない場合

**ここが案Nで唯一「詰む」ポイントです。そして公式ドキュメントに明確な記載がありません。**

分かっていること:

- 移管については、GitHub が名前空間を「引退」させる条件が明記されています（原文ママ）:

  > If the transferred repository contains an action listed on GitHub Marketplace, or had more than 100 clones or more than 100 uses of GitHub Actions in the week prior to the transfer, GitHub permanently retires the owner name and repository name combination (`OWNER/REPOSITORY-NAME`) when you transfer the repository. If you try to create a repository using a retired owner name and repository name combination, you will see the error: "The repository `REPOSITORY_NAME` has been retired and cannot be reused."

- この仕組みは **"popular repository namespace retirement"** と呼ばれ、
  repojacking（削除・改名された名前を第三者が乗っ取る攻撃）対策として
  導入されたものです。セキュリティ研究でもこの名前で繰り返し扱われています

**分かっていないこと（未検証）:**

- **単純な「削除」でも引退が発動するか。** 公式ドキュメントは移管とリネームについてしか
  書いていません。ただし repojacking の研究は削除経由の乗っ取りも扱っており、
  **削除にも同じ保護が効いていると考えるのが安全側**です
- **削除直後に同名で作れるか。** 90日の復元枠があるため、名前が予約されている
  可能性があります。公式ドキュメントに記載がありません

**このリポジトリの場合の見通し:**

- star 0 / fork 0 / watcher 0。**clone 数が週100を超えているとは考えにくい**
- Marketplace 掲載はしていません（`action.yml` に「掲載作業そのものは行っていない」と記載）
- したがって**引退条件には該当しない見込み**ですが、**clone 数だけは実測してください**
  （Insights → Traffic）。この環境からは Traffic API を取得できませんでした

**詰み方**: 削除 → 同名で作ろうとしたら "has been retired and cannot be reused" が出る
→ その名前は**永久に使えません**。復元はできますが、復元した repo は
PR も Actions も全部戻ってきます。つまり**時間を失って元の場所に戻る**だけです。

---

## 4. 検証項目3: 孤立コミット `b5cff9b` の消滅確認方法

### 4-1. 消えると考えてよい根拠

孤立コミットが「消えない」ケースは、**fork ネットワーク経由でオブジェクトが
別のリポジトリから参照できてしまう**場合です。

**このリポジトリは `forks_count: 0` です**（実測）。fork ネットワークが存在しないため、
リポジトリを削除すれば、そのオブジェクトを保持する場所は他にありません。

ただし **90日間は GitHub 内部に復元用データとして保持されます**（3-2）。
「公開されない」であって「消滅した」ではない点は正確に理解してください。

### 4-2. 確認手順（削除後・再作成後の両方で実施）

**認証を付けないでください。** `gh` はトークンを付けるので、外から見える状態の
確認になりません。

```bash
SHA=b5cff9b855dc15d00ff73e59a7f0ed50cf50dcac

# 削除直後（再作成の前）— 両方 404 になること
curl -sS -o /dev/null -w "api      %{http_code}\n" \
  "https://api.github.com/repos/secleeman/triage-lens/commits/$SHA"
curl -sS -o /dev/null -w "web      %{http_code}\n" \
  "https://github.com/secleeman/triage-lens/commit/$SHA"

# 再作成して push したあと — やはり 404 のままであること
curl -sS -o /dev/null -w "api(new) %{http_code}\n" \
  "https://api.github.com/repos/secleeman/triage-lens/commits/$SHA"

# git からも取れないこと（fatal になれば OK）
git init -q /tmp/chk && cd /tmp/chk \
  && git remote add origin https://github.com/secleeman/triage-lens.git \
  && git fetch origin "$SHA" ; echo "exit=$?"
```

**期待値**: 削除後・再作成後とも **404**、`git fetch` は失敗。

### 4-3. Support 依頼が不要になるかの判定

| 結果 | 判断 |
| --- | --- |
| 削除後・再作成後とも 404 | **Support 依頼は不要**。案Nがこの問題を解決したことになります |
| どちらかで 200 が返る | fork ネットワークか別の保持経路がある。**Support 依頼が必要** |

**ただし前提として、[6-2](#6-2-gh-archive-最大の残存露出) の GH Archive を先に確認してください。**
`b5cff9b` のコミット author メールが GH Archive の PushEvent ペイロードに
出ている場合、github.com から消しても**そちらは残ります**。
その場合、この確認と Support 依頼の価値は大きく下がります。

---

## 5. 検証項目4: 再設定が必要な項目

### 5-1. 現在の設定の棚卸し（実測）

`GET /repos/secleeman/triage-lens` から取得した現在値です。

| 設定 | 現在値 | 再作成後に手で戻すか |
| --- | --- | --- |
| `name` | `triage-lens` | 作成時に指定 |
| `description` | `スキャナの脆弱性リストを公開データ(CISA KEV / EPSS / CVSS)で優先順位付けし、日本語・英語のトリアージレポートを生成するCLIツール` | **要設定** |
| `visibility` | `public` | 作成時に指定 |
| `default_branch` | `main` | push で自動 |
| `license` | MIT（`LICENSE` ファイル由来） | ファイルなので自動 |
| `has_issues` | `true` | 既定 true。確認 |
| `has_wiki` | **`false`** | **要変更**（既定は true） |
| `has_projects` | `true` | 既定 true。確認 |
| `has_discussions` | `false` | 既定 false |
| `has_downloads` | **`false`** | **要確認**（既定 true のことがあります） |
| `has_pages` | `false` | — |
| `allow_forking` | `true` | 既定 |
| `web_commit_signoff_required` | `false` | 既定 |
| `is_template` | `false` | 既定 |
| `archived` | `false` | — |
| **branch protection（`main`）** | **設定なし**（`protected: false` を実測） | **不要**（元から無い） |
| **environment `pypi`** | 存在（`release.yml` が参照） | **必ず再作成**（[2-4](#2-4-実行時に気をつけること)） |
| **Actions secrets** | **0個**（両ワークフローとも `secrets.` を使わない。`test_release_workflow_has_no_long_lived_token` が禁止） | **不要** |
| **Private Vulnerability Reporting** | 未有効化（前回報告書 3-1 のとおり） | **要有効化**（どのみち必要） |
| **Artifact and log retention** | 既定 90日 | 変えるなら**再設定**（新規リポジトリは既定値） |
| `homepage` / `topics` | **未確認**（API のこの応答形に含まれず） | 設定していれば要復元。**作業前に画面で確認してください** |
| collaborator | `boobooyuta` 1名（admin） | Org owner なので自動 |
| Team 権限 | **0件**（team 未使用を実測） | 不要 |
| webhook / deploy key | **未確認**（この環境で取得不可） | **作業前に確認してください** |

### 5-2. Git 側で戻すもの

| 項目 | 現状 | 備考 |
| --- | --- | --- |
| ブランチ | `main` + `docs/account-migration-feasibility` + `docs/org-anonymity-hardening` | クリーンな `main` だけ push すればよい |
| **タグ** | **7件**（`v0.4.0`〜`v0.8.0`） | **push し忘れ注意**。`git push --tags` |
| GitHub Release | 0件 | 元から無いので復元不要 |

> ⚠️ **タグを push すると `release.yml` が発火し、PyPI に既存版を再アップロードしようとして
> 失敗します**（PyPI は同一版数を上書き不可）。**タグは push しないか、
> ワークフローを置いてから push するかを決めてください。**
> 安全なのは「先にタグだけ push → 失敗した Actions 実行を削除 → その後ワークフローを追加」
> ではなく、**「ワークフローを含む main を push したあと、タグは push しない」**です。
> タグは git の歴史には要らない情報なので、**過去タグを復元しない**のが最も安全です。

---

## 6. 検証項目5: リポジトリ外に残る露出

### 6-1. 一覧

| 場所 | 公開性 | 案Nで消えるか | 状態 |
| --- | --- | --- | --- |
| **GH Archive** | **完全公開**（HTTP + BigQuery） | ❌ **消えない** | **未実測**（[6-2](#6-2-gh-archive-最大の残存露出)） |
| Software Heritage | 公開 | ❌ 消えない | **未実測**（この環境から到達不可） |
| Wayback Machine | 公開 | ❌ 消えない | **未実測**（同上） |
| 検索エンジンのキャッシュ | 公開 | △ 時間で消える | 未実測 |
| **Org 監査ログ** | **非公開**（org owner のみ） | ❌ 残る | 実測済み（下記） |
| **PyPI の配布物** | 公開 | — | ✅ **元から露出なし**（実測。下記） |
| GitHub 内部の復元用データ | 非公開 | 90日で消える | 仕様どおり |

### 6-2. GH Archive: 最大の残存露出

**これが案Nの前提を崩す発見です。**

GH Archive 公式サイトの記述（原文ママ）:

> GH Archive is a project to record the public GitHub timeline, archive it, and make it easily accessible for further analysis.

> These events are aggregated into hourly archives, which you can access with any HTTP client

> Activity archives are available starting 2/12/2011. Activity archives for dates between 2/12/2011-12/31/2014 was recorded from the (now deprecated) Timeline API. **Activity archives for dates starting 1/1/2015 is recorded from the Events API.**

> The entire GH Archive is also available as a public dataset on Google BigQuery: **the dataset is automatically updated every hour** and enables you to run arbitrary SQL-like queries over the entire dataset in seconds.

つまり:

- `secleeman/triage-lens` が public になった **2026-08-28 13:27 UTC 以降のすべての公開イベント**
  （`PushEvent` / `PullRequestEvent` / `CreateEvent` / `IssueCommentEvent` など）が、
  毎時アーカイブに取り込まれている見込みです
- 各イベントには **`actor.login`** が入ります＝個人アカウント名
- **`PushEvent` のペイロードには `commits[].author.email` が含まれます。**
  つまり **`b5cff9b` を作った squash マージに伴う push で、
  `boobooyuta@gmail.com` が GH Archive に入っている可能性があります**
- **リポジトリを削除しても、GH Archive のファイルと BigQuery のデータは消えません。**
  第三者が保持する別のコピーです

**確認コマンド**（オーナー実施。読み取りのみ）:

```bash
# b5cff9b が main に入った時刻は 2026-08-31T09:22:12Z → 09時台のアーカイブ
wget https://data.gharchive.org/2026-08-31-9.json.gz
zcat 2026-08-31-9.json.gz | grep -c 'secleeman/triage-lens'         # 件数
zcat 2026-08-31-9.json.gz | grep 'secleeman/triage-lens' \
  | jq -r '[.type, .actor.login] | @tsv' | sort | uniq -c           # 種類と actor
zcat 2026-08-31-9.json.gz | grep 'secleeman/triage-lens' \
  | jq -r 'select(.type=="PushEvent") | .payload.commits[]?.author.email' | sort -u
                                                                     # ★ メールが出るか
```

BigQuery で全期間を一度に見る場合（Google アカウントが必要）:

```sql
SELECT created_at, type, actor.login
FROM `githubarchive.day.2026*`
WHERE _TABLE_SUFFIX BETWEEN '0828' AND '0901'
  AND repo.name = 'secleeman/triage-lens'
ORDER BY created_at;
```

> **未実測**: この環境から `data.gharchive.org` に到達できないため（403）、
> **実際に出ているかは確認していません。** 仕組みから「出ている見込み」と
> 書いていますが、断定はしません。**上のコマンドで必ず確かめてください。**

**もしメールが出ていた場合**: 案Nを実行しても、そのメールは消えません。
GH Archive は Google BigQuery の公開データセットにもミラーされており、
削除を依頼する窓口も実務上ありません。**この場合、案Nの費用対効果は大きく下がります。**

### 6-3. Org 監査ログ: 公開されないので実害は小さい

公式ドキュメント（原文ママ）:

> The audit log lists events triggered by activities that affect your organization within the last 180 days. **Only owners can access an organization's audit log.**

> The audit log contains data for the last 180 days.

- **第三者には見えません。** 匿名性の観点では露出になりません
- **180日で自然に消えます**
- リポジトリを削除しても監査ログの記録は残りますが、上の2点により**対処不要**と判断します

### 6-4. PyPI の配布物: 元から露出していません（実測）

`docs/` が sdist に含まれていれば、報告書に書いた個人アカウント名やメールが
PyPI に永久公開されるところでした。**実際に sdist をビルドして確認しました。**

```
$ python -m build --sdist
$ tar -tzf dist/triage_lens-0.8.0.tar.gz
LICENSE
MANIFEST.in
PKG-INFO
README.md
pyproject.toml
setup.cfg
src/triage_lens/*.py
src/triage_lens.egg-info/*

$ grep -rl "boobooyuta" triage_lens-0.8.0/
（ヒットなし）
```

**`docs/` は sdist に入りません。個人アカウント名もメールも含まれていません。**
`MANIFEST.in` の `prune tests` と、`pyproject.toml` のパッケージ指定が効いています。

> ⚠️ **ただし今後の注意**: `docs/reports/` 配下の報告書には個人アカウント名と
> メールアドレスが書かれています。**将来 sdist の対象を広げる変更をすると、
> これらが PyPI に載ります。** PyPI は公開済み版数を上書きできないので、
> 載せたら実質取り消せません。`MANIFEST.in` を触るときは必ず中身を確認してください。

---

## 7. 検証項目6: 移行手順書ドラフト

**実行していません。実行する場合の順番と所要時間の目安です。**

### 事前確認（実行の判断材料。ここで止まる可能性があります）

| # | 作業 | 時間 | 詰むポイント |
| --- | --- | --- | --- |
| 0-a | Insights → Traffic で**直近1週間の clone 数**を確認 | 2分 | **100超なら中止**。名前が引退して作り直せない恐れ |
| 0-b | [6-2](#6-2-gh-archive-最大の残存露出) で **GH Archive を確認** | 10分 | **メールが出ていたら費用対効果を再検討** |
| 0-c | Org のポリシーで repo 削除が許可されているか | 2分 | 禁止されていたら実行不可 |
| 0-d | `homepage` / `topics` / webhook / deploy key を画面で控える | 5分 | 控え忘れると復元できない |

### 実行手順

| # | 作業 | 時間 | 詰むポイント |
| --- | --- | --- | --- |
| 1 | **バックアップ**: `git clone --mirror` でローカルに完全複製。別ディレクトリに `git clone` も取る | 5分 | **これを飛ばすと復元手段が90日の GitHub 復元だけになります。必ず取る** |
| 2 | クリーンな `main` を手元で用意（現 `main` そのままでよい。名義は既に統一済み） | 5分 | — |
| 3 | PyPI の Publishing 画面を**スクリーンショットで控える**（owner/repo/workflow/environment） | 2分 | 触らない。壊れないので変更不要 |
| 4 | **リポジトリを削除**（Settings → Danger Zone） | 2分 | ここから後戻りは「90日以内の復元」のみ。**削除直後の1時間は復元もできません** |
| 5 | **同 Org 同名で再作成**（public、README なし・.gitignore なし・ライセンスなしの空で作る） | 2分 | ★ **"has been retired and cannot be reused" が出たら詰み。** その場合は 90日以内に復元して案N'へ切り替え |
| 6 | `git push` でクリーンな `main` を投入（**タグは push しない**） | 3分 | タグを push すると `release.yml` が走り PyPI 再アップロードで失敗 |
| 7 | **設定を復元**（[5-1](#5-1-現在の設定の棚卸し実測) の表）: description / Wiki off / Downloads / topics / homepage | 10分 | Wiki は既定 on なので**必ず off に戻す** |
| 8 | **environment `pypi` を再作成**（Settings → Environments） | 3分 | ★ 忘れると次のリリースが `invalid-publisher` で失敗 |
| 9 | **Private Vulnerability Reporting を有効化** | 2分 | SECURITY.md がこれを前提に書かれています |
| 10 | Artifact and log retention を短く設定（例 7日） | 2分 | 任意 |
| 11 | **Trusted Publishing の疎通確認**: `pyproject.toml` の版を上げてタグ push（例 `v0.8.1`）→ PyPI 公開が通ることを確認 | 15分 | ★ ここで初めて TP が本当に通るか分かります。**失敗したら environment 名を確認** |
| 12 | **[4-2](#4-2-確認手順削除後再作成後の両方で実施) で `b5cff9b` の 404 を確認** | 3分 | — |
| 13 | 未認証のシークレットウィンドウで Actions / PR / commits を目視 | 5分 | — |

**合計: 事前確認 20分 + 実行 60分 ≒ 1時間20分**（ステップ11 の PyPI 反映待ちを含む）

### 失敗時の退避

| 失敗 | 退避 |
| --- | --- |
| ステップ5で名前が引退していた | **90日以内に復元**（Org Settings → Deleted repositories）。PR も Actions も戻ります＝振り出しに戻るが repo は失わない |
| ステップ11で `invalid-publisher` | environment 名 / workflow ファイル名 / owner / repo を突き合わせる。最悪でも PyPI 側で publisher を追加登録すれば復旧できます |
| push を間違えた | ステップ1のミラーから再 push |

---

## 8. 判定と案N' との比較

### 8-1. 判定: **Conditional GO**

**技術的には成立します。** PyPI Trusted Publishing が壊れないことが分かった時点で、
案Nの最大の技術リスクは消えました。作業も1時間半程度です。

**ただし、案Nの目的（全露出の一括消去）は達成できません。**
GH Archive という第三者の恒久記録が、GitHub の外にあります。

**GO の条件:**

1. **clone 数が週100未満**であること（名前の引退を避ける）
2. **GH Archive を先に確認**し、そこに何が出ているかを把握したうえで判断すること
3. **ミラーバックアップを取ってから**削除すること
4. **「github.com 上の見た目を消す」という目的で納得できる**こと

**条件2が黒（メールが既に出ている）なら、判定は NO-GO に傾きます。**
消せないものを消すために、消せるものを消す作業をする意味が薄いためです。

### 8-2. 案N vs 案N' の比較

**案N'** = Actions 29件削除 + PR 露出は許容 + `b5cff9b` のみ Support 依頼

| 項目 | **案N（作り直し）** | **案N'（部分掃除）** |
| --- | --- | --- |
| **作業時間** | 事前20分 + 実行60分 = **約1時間20分** | Actions 削除30分 + Support 依頼10分 = **約40分** |
| **不可逆性** | **高**（90日の復元枠のみ） | **低**（Actions 削除は不可逆だが影響は限定的） |
| **詰むリスク** | **あり**（名前の引退で repo と名前を同時に失う） | **なし** |
| PyPI Trusted Publishing | **壊れない**（実測） | 触らない |
| PyPI の公開済み版 | 影響なし | 影響なし |
| リポジトリの作成日 | **リセットされる**（2026-08-28 → 実行日） | 保持 |
| 過去タグ 7件 | **復元しない前提**（push すると PyPI への再アップロードで失敗） | 保持 |
| 外部からのリンク | 同名同 Org なので**そのまま有効** | 影響なし |

**残存露出の差分:**

| 露出 | 案N | 案N' |
| --- | --- | --- |
| github.com の PR #1〜#4（actor = 個人アカウント） | ✅ **消える** | ❌ **残る**（削除手段なし） |
| github.com の PR コメント | ✅ 消える | ❌ 残る |
| github.com の PR 本文のセッションURL | ✅ 消える | ❌ 残る |
| github.com の Actions 実行 29件 | ✅ 消える | ✅ 消える |
| github.com の Actions artifact | ✅ 消える | ✅ 消える |
| github.com の孤立コミット `b5cff9b`（実名メール） | ✅ 消える（fork 0 のため確実） | △ **Support 次第**（有料プラン要件あり） |
| **GH Archive のイベント（actor）** | ❌ 残る | ❌ 残る |
| **GH Archive の PushEvent 内のメール** | ❌ 残る | ❌ 残る |
| Org 監査ログ | ❌ 残る（非公開・180日） | ❌ 残る（同じ） |
| PyPI 配布物 | — 元から露出なし | — 元から露出なし |

**差分は「github.com 上の PR 4本ぶんの露出」だけです。**
そのために、名前を失うリスクと1時間半を払うかどうかが判断のすべてです。

### 8-3. 判断材料としての所見

- **GH Archive にメールが出ていなかった場合**: 案Nの価値は相対的に上がります。
  github.com から実名メールと個人アカウントの痕跡がほぼ消えるので、
  「調べられても出てこない」状態に近づきます。**Conditional GO**
- **GH Archive にメールが出ていた場合**: 一番消したいものが消せません。
  案N' で Actions だけ消し、**今後の露出をマシンアカウントで止める**ほうが
  費用対効果が高いと考えます。**NO-GO 寄り**
- **どちらの場合でも**、前回報告書の「マシンアカウントで蛇口を締める」は先にやる価値があります。
  案Nをやっても、次の push でまた個人アカウントの記録が GH Archive に入るためです

---

## 9. 出典

すべて 2026-08-31 に取得。（実測）は、この調査で実際に取得・実行して確認したものです。

**PyPI Trusted Publishing（実測。ソースコードを直接取得）**

- 照合クレームの定義と検証関数:
  <https://raw.githubusercontent.com/pypi/warehouse/main/warehouse/oidc/models/github.py>
  （`__required_verifiable_claims__` / `__unchecked_claims__` に `repository_id` が
  含まれること、`_check_repository` / `_check_job_workflow_ref` / `_check_environment` /
  `_check_event_name` の実装）

**GitHub 公式ドキュメント（実測。`github/docs` のソースを直接取得）**

- リポジトリの削除:
  <https://raw.githubusercontent.com/github/docs/main/content/repositories/creating-and-managing-repositories/deleting-a-repository.md>
- 削除したリポジトリの復元（90日、fork ネットワーク条件、1時間の待ち）:
  <https://raw.githubusercontent.com/github/docs/main/content/repositories/creating-and-managing-repositories/restoring-a-deleted-repository.md>
- 名前空間の引退条件（移管の項）:
  <https://raw.githubusercontent.com/github/docs/main/content/repositories/creating-and-managing-repositories/transferring-a-repository.md>
- Org 監査ログ（180日・owner のみ）:
  <https://raw.githubusercontent.com/github/docs/main/content/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization.md>

**GH Archive（実測。プロジェクトのソースを直接取得）**

- <https://raw.githubusercontent.com/igrigorik/gharchive.org/master/README.md>
- <https://raw.githubusercontent.com/igrigorik/gharchive.org/gh-pages/index.html>
  （毎時アーカイブ、2011-02-12 以降、2015-01-01 以降は Events API 由来、
  BigQuery 公開データセットへの毎時同期）

**このリポジトリの実測（GitHub API 経由。認証は個人アカウント）**

- リポジトリ設定一式（`has_wiki: false`、`forks_count: 0`、`stargazers_count: 0` 等）
- `main` の `protected: false`（branch protection 未設定）
- ブランチ 3本、タグ 7本
- Team 0件、collaborator 1名

**ローカルでの実測**

- `python -m build --sdist` で sdist を作り、`docs/` が含まれないこと、
  個人アカウント名・メールが含まれないことを確認

**未検証（この環境の制約）**

- GH Archive に実際に何が入っているか（`data.gharchive.org` が 403）
- Software Heritage / Wayback Machine のクロール状況（いずれも 403）
- 直近1週間の clone 数（Traffic API を取得できず）
- 単純な「削除」で名前空間の引退が発動するか（公式ドキュメントに記載なし）
- 削除直後に同名で再作成できるか（公式ドキュメントに記載なし）
- `homepage` / `topics` / webhook / deploy key の現在値
