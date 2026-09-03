# Organization 運用のまま匿名性を締める — 調査

- 日付: 2026-08-31
- 前提: リポジトリの移管は見送り、**Organization `secleeman` のまま運用を続ける**（案C採用）
- 調査項目:
  ① GitHub Actions 実行履歴の削除手順（API 一括削除の可否、削除後に残る痕跡）
  ② Org `secleeman` のメンバー・オーナー一覧の公開状態を、**未認証の外から実測**
  ③ 新規マシンアカウントを Org に追加して push / Actions / PR 作成を行う場合の最小権限構成
- **実行はしていません。** 削除・アカウント作成・権限変更・設定変更のいずれも行っていません。
- 実測していない箇所は「**未実測**」と明記しています。

---

## 0. 結論

### 0-1. いま何が漏れているか（実測）

コミット履歴は既に安全です。**漏れているのは Actions と PR です。**

| 場所 | 何が見えるか | 件数（実測） |
| --- | --- | --- |
| **コミットの author / committer** | `secleeman`（Organization、ID `322111724`）に紐づく。**`boobooyuta` は出ません** | main 全16件 ✅ |
| **Actions の実行履歴** | 全実行の `actor` / `triggering_actor` が **`boobooyuta`（ID `201195462`）** | **29 / 29件** ❌ |
| **Pull Request** | `user` と `merged_by` が **`boobooyuta`** | **3 / 3件**（#1 #2 #3） ❌ |
| **PR コメント** | 投稿者が **`boobooyuta`** | 複数 ❌ |
| **孤立コミット `b5cff9b`** | author が **`boobooyuta@gmail.com`**（実名メール）。SHA 直指定でまだ取得できます | 1件 ❌ |
| **Actions の成果物（artifact）** | `dist`（158,563 バイト）が保持中。期限 2026-11-29 | 7リリース分 |

### 0-2. ⚠️ Actions 履歴の削除だけでは目的を達成しません

**これが今回いちばん重要な結論です。**

Actions の実行履歴は API で全部消せます（[3章](#3-actions-実行履歴の削除調査項目1)）。
しかし **Pull Request は GitHub では削除できません。** Issue には削除機能がありますが
（権限表でも「Delete an issue」は Admin のみと定義されています）、
**PR には対応する行が権限表に存在せず、UI にも API にも削除手段がありません。**

つまり Actions を全消ししても、**PR #1〜#3 とそのコメントに `boobooyuta` が
残り続けます。** 現状 PR は3本しかないので影響は小さいですが、
**「Actions を消せば匿名になる」わけではない**ことを先に理解してください。

### 0-3. ② は、この環境では実測できませんでした

**依頼の「未認証の外から実測」は、この作業環境では原理的に実行できません。**
GitHub への通信がすべてハーネスのプロキシを経由し、認証が注入されるためです
（[2章](#2-調査環境の制約-項目2が実測できない理由)に生の応答を貼りました）。

**代わりに、オーナーがご自身で1分で実測できるコマンドを [4-3](#4-3-オーナー自身で実測する手順) に用意しました。**
推測で埋めるより、実際に叩いていただくほうが確実です。

### 0-4. 推奨する順番

| 優先 | やること | 効果 | 手間 |
| --- | --- | --- | --- |
| **1** | ② の実測（org メンバー公開状態の確認と、必要なら Private 化） | 大。1クリックで直る可能性 | 5分 |
| **2** | マシンアカウントを作り、以後の push / PR / Actions をそれに寄せる | 大。**今後の**露出が止まる | 1〜2時間 |
| **3** | 既存 Actions 実行履歴 29件を削除 | 中。過去の露出が減る | 30分 |
| **4** | 孤立コミット `b5cff9b` の purge を GitHub Support に依頼 | 小だが実名メールなので価値あり | 依頼のみ |
| — | PR #1〜#3 | **打つ手がありません**（削除不可） | — |

**2 を 3 より先にやってください。** 先に履歴を消しても、次の push でまた
`boobooyuta` の実行履歴が増えます。蛇口を締めてから拭くほうが早いです。

---

## 1. 現状の実測

### 1-1. コミットは既に安全（`secleeman` に紐づいている）

前回の作業でコミット名義を `secleeman <secleeman@users.noreply.github.com>` に
統一しました。GitHub がこのメールをどのアカウントに紐づけているかを確認しました。

```
GET /repos/secleeman/triage-lens/commits?sha=main
```

```json
{"sha": "3802a99...", 
 "author":    {"login": "secleeman", "id": 322111724},
 "committer": {"login": "secleeman", "id": 322111724}}
```

**`secleeman@users.noreply.github.com` は Organization `secleeman`（ID 322111724）に
解決されています。** コミット一覧・contributors・blame のどこにも `boobooyuta` は
出ません。ここは追加の対策不要です。

### 1-2. Actions が全部 `boobooyuta` を露出している

```
GET /repos/secleeman/triage-lens/actions/runs
→ total_count: 29
```

| ワークフロー | 実行数 | `actor` |
| --- | --- | --- |
| `ci.yml` | 22 | 全件 `boobooyuta`（ID 201195462） |
| `release.yml` | 7 | 全件 `boobooyuta`（ID 201195462） |
| **合計** | **29** | **29件すべて** |

public リポジトリなので、**Actions タブは誰でも見られます。**
各実行に実行者のアバターとログイン名が出ます。

### 1-3. 力技の push では Actions 実行は消えません（実測）

前回 `main` を force-push して `b5cff9b` を歴史から外しましたが、
**そのコミットに対する CI 実行はいまも残っています。**

```
run_number 18 / id 33377326264
head_sha:  b5cff9b855dc15d00ff73e59a7f0ed50cf50dcac   ← どのブランチからも到達不能
actor:     boobooyuta
head_commit.message: "docs: triage-lens の自己定義を「判断エンジン」に…"（全文）
```

**force-push は Actions 実行履歴を掃除しません。** 実行レコードは
コミットの到達可能性とは無関係に残り、コミットメッセージ全文と実行者を保持します。
そして `b5cff9b` 自体も、SHA を指定すればいまも取得でき、author は
`boobooyuta@gmail.com` のままです。

### 1-4. artifact も残っている

```
GET /repos/secleeman/triage-lens/actions/runs/33351056626/artifacts
→ name: dist / size: 158,563 B / expired: false / expires_at: 2026-11-29
```

既定の90日保持のため、7回のリリース分の `dist` が保持中です。

---

## 2. 調査環境の制約: 項目2が実測できない理由

**この環境からは、GitHub に対して未認証のリクエストを1本も出せません。**

`github.com` / `api.github.com` へのすべての通信が、Anthropic 側のセッション
プロキシに横取りされます。生の応答です。

```
$ curl -sS -i https://api.github.com/orgs/secleeman
HTTP/1.1 403 Forbidden
{"message":"This GitHub API path is not available: sessions are bound to their
configured repositories. Use repository-scoped endpoints (repos/{owner}/{repo}/...)."}
```

```
$ curl -sS -i https://github.com/orgs/secleeman/people
HTTP/1.1 403 Forbidden
（同じ本文）
```

```
$ curl -sS -i https://api.github.com/repos/secleeman/triage-lens
HTTP/1.1 403 Forbidden
{"message":"GitHub access is not enabled for this session. An org admin must
connect the Claude GitHub App for this organization."}
```

つまり:

- **`/orgs/...` 系のエンドポイントはパスごと遮断**されています
- リポジトリスコープの読み取りは **MCP サーバ経由の認証済みアクセスのみ**で、
  これは `boobooyuta` として認証された view です
- **「ログアウトした第三者に何が見えるか」を、この環境で再現する手段はありません**

第三者のミラーサービスを使う手もありますが、**そのサービスに
「`secleeman` という org を調べている」という事実を渡すことになります。**
匿名性を高める調査でそれをやるのは筋が悪いので、**意図的に行いませんでした。**

代わりに [4-3](#4-3-オーナー自身で実測する手順) にコマンドを用意しました。

---

## 3. Actions 実行履歴の削除（調査項目1）

> 依頼の①に対応します。

### 3-1. 削除できる条件と必要な権限（公式ドキュメント、原文ママ）

> You can delete a workflow run that has been completed, or is more than two weeks old.

> Write access to the repository is required to perform these steps.

- **完了済み、または2週間以上前の実行**だけが消せます。実行中のものは消せません
- 必要な権限は **Write**（Admin は不要）
- 29件すべて `completed` なので、**全件が削除対象になります**

### 3-2. API での一括削除は「可能。ただし専用の一括エンドポイントは無い」

**まとめて消す単一のエンドポイントはありません。** 一覧を取って1件ずつ
`DELETE` を回す形になります。使うエンドポイントは3つです。

| 用途 | エンドポイント |
| --- | --- |
| 実行の一覧 | `GET /repos/{owner}/{repo}/actions/runs` |
| **実行の削除** | `DELETE /repos/{owner}/{repo}/actions/runs/{run_id}` |
| ログだけ削除（実行レコードは残す） | `DELETE /repos/{owner}/{repo}/actions/runs/{run_id}/logs` |

（エンドポイントの存在は、GitHub の OpenAPI から生成されている
`octokit/plugin-rest-endpoint-methods.js` の `endpoints.ts` で確認しました。
`deleteWorkflowRun` / `deleteWorkflowRunLogs` / `listWorkflowRunsForRepo`）

`gh` CLI にも `gh run delete` があります（公式ドキュメントが
「using the GitHub Actions UI, the REST API, or using the GitHub CLI」と案内しています）。

**29件なので、API のレート制限（認証済み 5,000 req/時）は問題になりません。**

実行する場合の形（**このコマンドは実行していません**）:

```bash
# 1. まず何が消えるかを確認する（消さない）
gh api --paginate /repos/secleeman/triage-lens/actions/runs \
  --jq '.workflow_runs[] | [.id, .name, .run_number, .head_sha[0:7], .actor.login] | @tsv'

# 2. 件数を数える
gh api /repos/secleeman/triage-lens/actions/runs --jq '.total_count'

# 3. 実際に消す（戻せません）
gh api --paginate /repos/secleeman/triage-lens/actions/runs --jq '.workflow_runs[].id' \
  | while read -r id; do
      gh api -X DELETE "/repos/secleeman/triage-lens/actions/runs/$id" && echo "deleted $id"
    done

# 4. 残りを確認
gh api /repos/secleeman/triage-lens/actions/runs --jq '.total_count'
```

> **注意**: 削除は取り消せません。公式ドキュメントも artifact について
> 「Once you delete an artifact, it cannot be restored.」と警告しています。

### 3-3. 削除で消えるもの（公式ドキュメント、原文ママ）

> When a workflow run is deleted all artifacts associated with the run are also deleted from storage.

- 実行レコードそのもの（Actions タブから消えます）
- **その実行の artifact**（`dist` もここで消えます）
- 実行ログ

### 3-4. ⚠️ 削除しても残る痕跡

**ここは公式ドキュメントに記載がありません。** そして**この調査では検証していません**
（検証するには実際に1件削除する必要があり、「実行はしない」という指示の範囲外のため）。

**確実に残るもの（実測または構造から確定）:**

| 残るもの | 根拠 |
| --- | --- |
| **Pull Request の作者・マージ実行者** | 実測。PR #1 は `user: boobooyuta` / `merged_by: boobooyuta`。**PR は削除できません**（権限表に「Delete an issue」はあるが PR に相当する行が無く、UI / API にも手段が無い） |
| **PR 本文・コメントの投稿者** | 実測。`boobooyuta` として投稿されています |
| **孤立コミット `b5cff9b`** | 実測。SHA 指定でいまも取得でき、author は `boobooyuta@gmail.com` |
| **コミットそのもの** | git オブジェクト。Actions とは無関係（ただし 1-1 のとおり `secleeman` に紐づいており安全） |
| **PR 本文に埋め込まれた Claude Code のセッションURL** | 実測。PR #1 の本文末尾に `https://claude.ai/code/session_01TYtkwHxqUZ9vcxsA6fY9Lg` が入っています（サーバ側で付与されたもの） |

**残るかどうか分からないもの（要検証）:**

| 項目 | なぜ分からないか |
| --- | --- |
| コミットに紐づく **check run / commit status** | 実行を消したときに一緒に消えるのか、コミット側に残るのかが未文書。「実行を消すと必須ステータスチェックが満たせなくなって PR がマージできなくなることがある」という報告があり、**両者が別管理である可能性**を示唆します（二次情報・未検証） |
| `pypi` **environment の deployment 記録** | `release.yml` は `environment: pypi` を使うため deployment レコードが作られます。実行削除で消えるかは未文書・未検証 |
| GitHub 内部の**課金・使用量の記録** | 公開されないが、消えるとは書かれていません |

**検証のしかた（1件だけ試す）**:

```bash
# 消す前に、対象コミットの check run を控える
gh api /repos/secleeman/triage-lens/commits/<SHA>/check-runs --jq '.total_count'
gh api /repos/secleeman/triage-lens/deployments --jq 'length'

# 一番古い実行を1件だけ消す
gh api -X DELETE /repos/secleeman/triage-lens/actions/runs/33175752561

# 消えたか / 残ったかを見る
gh api /repos/secleeman/triage-lens/commits/<SHA>/check-runs --jq '.total_count'
gh api /repos/secleeman/triage-lens/deployments --jq 'length'
```

**1件で挙動を確かめてから29件に広げてください。**

### 3-5. 予防策: 保持期間を短くする

公式ドキュメント（原文ママ）:

> By default, the artifacts and log files generated by workflows are retained for 90 days before they are automatically deleted.
> * For public repositories: you can change this retention period to anywhere between 1 day or 90 days.

> **When you customize the retention period, it only applies to new artifacts and log files, and does not retroactively apply to existing objects.**

- 設定場所: Settings → Actions → General → **Artifact and log retention**
- public リポジトリは **1〜90日**に設定できます
- **既存のものには遡って効きません。** 過去分は 3-2 の削除で消す必要があります
- なお **実行レコード自体（actor を含む）は保持期間の対象外**です。
  消えるのはログと artifact だけで、「誰がいつ実行したか」は残ります

---

## 4. Org のメンバー・オーナー一覧の公開状態（調査項目2）

> 依頼の②に対応します。

### 4-1. 仕組み

GitHub の org メンバーの公開状態は **メンバー1人ずつが選ぶ**もので、
API も2本に分かれています。

| エンドポイント | 誰が読めるか | 何が返るか |
| --- | --- | --- |
| `GET /orgs/{org}/public_members` | **未認証でも読める** | 公開設定にしているメンバーだけ |
| `GET /orgs/{org}/members` | org メンバーとして認証が必要 | 全メンバー |
| `GET /orgs/{org}/public_members/{username}` | 未認証でも読める | その人が公開メンバーかどうか |

公式ドキュメントの手順（原文ママ）:

> 1. Locate your username in the list of members. If the list is large, you can search for your username in the search box.
> 1. Next to your username, select the visibility dropdown menu, then click a new visibility.
>    * To publicize your membership, choose **Public**.
>    * To hide your membership, choose **Private**.

つまり **`boobooyuta` の org メンバーシップが Public になっていれば、
未認証の第三者から `github.com/orgs/secleeman/people` で見えます。**
Private なら見えません。

> **未実測**: 現在の設定がどちらかは、[2章](#2-調査環境の制約-項目2が実測できない理由)の
> とおりこの環境からは確認できませんでした。ドキュメントのスクリーンショット説明文では
> ドロップダウンが "Private" とラベルされていますが、**これを既定値の根拠とは扱いません。**
> 必ず 4-3 で実測してください。

### 4-2. 認証ありで測れた範囲

| 項目 | 実測値 |
| --- | --- |
| Org の種別 | Organization（ID `322111724`） |
| リポジトリの collaborator | **`boobooyuta` 1人のみ**（role: `admin`） |
| `boobooyuta` が属する Team | **0件**（`{"org":"secleeman","teams":[]}`） |

**Team を使っていません。** 権限は org メンバーシップと直接の collaborator 設定だけで
成り立っています。③のマシンアカウント設計はこの前提で考えます。

### 4-3. オーナー自身で実測する手順

**未認証であることが重要なので、`gh` は使わず素の `curl` で叩いてください。**
`gh api` は認証トークンを付けてしまうため、外から見える範囲の測定になりません。

```bash
# 1. 公開メンバーの一覧（未認証。これが「外から見える」全部）
curl -sS https://api.github.com/orgs/secleeman/public_members | jq -r '.[].login'

# 2. boobooyuta が公開メンバーか（204 なら公開、404 なら非公開）
curl -sS -o /dev/null -w "%{http_code}\n" \
  https://api.github.com/orgs/secleeman/public_members/boobooyuta

# 3. org の基本情報（未認証。公開メンバー数などが出ます）
curl -sS https://api.github.com/orgs/secleeman \
  | jq '{login, id, public_repos, public_members_url, created_at, email, blog, location, name, description}'

# 4. 認証を付けたときとの差分（自分には見えるが外には見えないものを把握する）
gh api /orgs/secleeman/members --jq '.[].login'
```

さらに**ブラウザのシークレットウィンドウ（ログアウト状態）**で、次を目視してください。
API では出ない表示上の露出を拾えます。

```
https://github.com/orgs/secleeman/people
https://github.com/secleeman
https://github.com/secleeman/triage-lens/actions      ← 実行者のアバターが並びます
https://github.com/secleeman/triage-lens/pulls?q=is%3Apr
```

**見えてしまっていた場合の直しかた:**

Organization → **People** → 自分の行の右の visibility ドロップダウン → **Private**。
1クリックで、以後 `public_members` から外れます。

> なお **オーナー（Owner ロール）かどうかは、公開メンバーであっても API では区別されません。**
> `/orgs/{org}/members?role=admin` はメンバー認証が必要です。
> 外から見えるのは「公開メンバーである」ことまでで、役割までは出ません。

### 4-4. 3章より先にこれをやってください

Actions を29件消すより、**この確認と（必要なら）1クリックのほうが効果が大きい**です。
公開メンバーになっていれば、`github.com/secleeman` のトップに
`boobooyuta` のアバターが常時出ている状態なので、Actions を消しても意味がありません。

---

## 5. マシンアカウントの最小権限構成（調査項目3）

> 依頼の③に対応します。

### 5-1. ToS 上、作ってよいか → **よい。ただし1つまで**

GitHub 利用規約（原文ママ）:

> * You must be a human to create an Account. Accounts registered by "bots" or other automated methods are not permitted. We do permit machine accounts:
> * A machine account is an Account set up by an individual human who accepts the Terms on behalf of the Account, provides a valid email address, and is responsible for its actions. A machine account is used exclusively for performing automated tasks. Multiple users may direct the actions of a machine account, but the owner of the Account is ultimately responsible for the machine's actions. **You may maintain no more than one free machine account in addition to your free Personal Account.**

要点:

- **無料の個人アカウント1つ + 無料のマシンアカウント1つ**まで
- **有効なメールアドレスが別途必要**です（`boobooyuta@gmail.com` は既に使用済みなので、
  別アドレスを用意してください。Gmail の `+` エイリアスが使えるかは GitHub 側の
  判定次第なので**未検証**。専用アドレスを推奨します）
- **「自動化されたタスクの実行にのみ使う」** アカウントである必要があります。
  人間としての活動（Issue で議論する等）を混ぜると規約の趣旨から外れます

そして、匿名性の観点で効いてくる公式の記述（原文ママ）:

> Any time you take any action on GitHub, such as creating an issue or reviewing a pull request, the action is attributed to your user account.

**GitHub 上の行為は必ずアカウントに紐づきます。** これを変えることはできないので、
「紐づく先を差し替える」のがマシンアカウントの意味です。

### 5-2. 必要な権限（公式の権限表からの実測）

権限表から、今回必要な操作の行だけ抜き出しました（列は Read / Triage / Write / Maintain / Admin）。

| 操作 | Read | Triage | **Write** | Maintain | Admin |
| --- | --- | --- | --- | --- | --- |
| Push to (write) the person or team's assigned repositories | ✗ | ✗ | **✓** | ✓ | ✓ |
| Create, edit, run, re-run, and cancel GitHub Actions workflows | ✗ | ✗ | **✓** | ✓ | ✓ |
| Create, update, and delete GitHub Actions secrets（リポジトリ） | ✗ | ✗ | **✓** | ✓ | ✓ |
| Create and edit releases | ✗ | ✗ | **✓** | ✓ | ✓ |
| Send pull requests from forks | ✓ | ✓ | ✓ | ✓ | ✓ |
| Push to protected branches | ✗ | ✗ | ✗ | ✓ | ✓ |
| Manage branch protection rules | ✗ | ✗ | ✗ | ✗ | ✓ |
| Delete or transfer repositories out of the organization | ✗ | ✗ | ✗ | ✗ | ✓ |

**結論: 必要なのは `Write` です。** Maintain も Admin も要りません。

- **push** → Write
- **Actions の実行・再実行・実行削除** → Write
  （実行削除は権限表に行がありませんが、削除の手順書に
  「Write access to the repository is required」とあります）
- **PR 作成** → 同一リポジトリのブランチから出すなら、ブランチを push できること＝Write。
  fork から出すだけなら Read でも足りますが、運用が煩雑になるので Write を推奨します

### 5-3. 推奨する構成

| 項目 | 推奨 | 理由 |
| --- | --- | --- |
| Org での立場 | **Outside collaborator**（org メンバーにしない） | org メンバーにすると `public_members` に載る余地が生まれます。outside collaborator なら **org のメンバー一覧に出ません**。今回 Team を使っていない（実測: 0件）ので、メンバーである必要がありません |
| リポジトリ権限 | **Write** | 5-2 のとおり必要十分 |
| Org の Base permissions | **None** に設定 | 「org メンバーなら全リポジトリに自動で権限」を止めます |
| 認証 | **Fine-grained PAT**（対象を `triage-lens` 1本に限定、Contents: Read and write / Pull requests: Read and write / Actions: Read and write、有効期限を短く） | classic PAT はアカウント全体に効くので範囲が広すぎます |
| 2FA | **必ず有効化** | コードを push するアカウントには GitHub 側で必須化されています |
| コミット名義 | `secleeman <secleeman@users.noreply.github.com>` を維持 | 既に Organization に紐づいており（1-1）、マシンアカウントを作っても**コミット表示は変わりません** |
| Actions の権限 | `release.yml` の `permissions: {}` を維持 | 既に最小です |

**Admin を持つアカウントは `boobooyuta` に残してください。** リポジトリ設定・
branch protection・Private Vulnerability Reporting の有効化などはマシンアカウントに
やらせる必要がなく、admin を渡すと事故と露出の両方が増えます。

### 5-4. マシンアカウントにしても残る露出

正直に書きます。**マシンアカウントは万能ではありません。**

- **過去の29件の Actions 実行と3本の PR は `boobooyuta` のままです。**
  マシンアカウントは「これから」にしか効きません
- **マシンアカウント名から辿られる可能性**があります。作成時期・活動パターン・
  メールアドレスが `boobooyuta` と結びつくと意味がなくなります。
  **名前に `boobooyuta` と関連する文字列を入れないでください**
- **規約上、責任は所有者（＝オーナーご本人）にあります。** 匿名性は
  「公開画面に出ない」という意味であって、GitHub に対して匿名になるわけではありません
- **PyPI の Trusted Publisher には影響しません。** OIDC の照合は
  リポジトリ所有者・リポジトリ名・ワークフロー名・environment で行われ、
  **実行者アカウントは条件に入っていません**（前回の調査で warehouse の
  ソースを確認済み）。マシンアカウントに切り替えてもリリースは通ります

---

## 6. まとめ: やることリスト

**実行はしていません。** 判断と実施はオーナーにお任せします。

- [ ] **1.（5分）** 4-3 のコマンドで、未認証の外から org メンバー公開状態を実測する
- [ ] **2.（1分）** 公開になっていたら People 画面で **Private** に変える
- [ ] **3.（5分）** シークレットウィンドウで Actions / PR / org トップを目視する
- [ ] **4.（1〜2時間）** マシンアカウントを作り、Outside collaborator + Write で追加。
      Fine-grained PAT を発行し、以後の push / PR / タグ push をそちらに寄せる
- [ ] **5.（5分）** Settings → Actions → General で Artifact and log retention を短く（例: 7日）
- [ ] **6.（10分）** 3-4 の手順で **1件だけ** 実行を削除し、check run と deployment が
      どうなるかを確かめる
- [ ] **7.（20分）** 問題なければ残り28件を削除する
- [ ] **8.（依頼のみ）** 孤立コミット `b5cff9b` の purge を GitHub Support に依頼する
      （<https://support.github.com/contact>）
- [ ] — PR #1〜#3 は**打つ手がありません**。GitHub に PR の削除機能は存在しません

**4 を 6・7 より先に。** 蛇口を締めてから拭くほうが早いです。

---

## 7. 出典

すべて 2026-08-31 に取得。（実測）は、この調査で実際に取得・実行して確認したものです。

**GitHub 公式ドキュメント**（ソースの `github/docs` から直接取得。実測）

- Actions 実行の削除:
  <https://raw.githubusercontent.com/github/docs/main/content/actions/how-tos/manage-workflow-runs/delete-a-workflow-run.md>
- artifact の削除と保持期間:
  <https://raw.githubusercontent.com/github/docs/main/content/actions/how-tos/manage-workflow-runs/remove-workflow-artifacts.md>
- 保持期間の範囲（public は 1〜90日、遡及しない）:
  <https://raw.githubusercontent.com/github/docs/main/data/reusables/actions/about-artifact-log-retention.md>
- 実行削除に必要な権限（Write）:
  <https://raw.githubusercontent.com/github/docs/main/data/reusables/repositories/permissions-statement-write.md>
- 実行削除で artifact も消える:
  <https://raw.githubusercontent.com/github/docs/main/data/reusables/actions/artifacts/artifacts-from-deleted-workflow-runs.md>
- リポジトリ role ごとの権限表:
  <https://raw.githubusercontent.com/github/docs/main/content/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization.md>
- org メンバーシップの公開/非公開:
  <https://raw.githubusercontent.com/github/docs/main/content/account-and-profile/how-tos/organization-membership/publicizing-or-hiding-organization-membership.md>
- 利用規約 B.3（マシンアカウント）:
  <https://raw.githubusercontent.com/github/docs/main/content/site-policy/github-terms/github-terms-of-service.md>
- アカウント種別と machine user:
  <https://raw.githubusercontent.com/github/docs/main/content/get-started/learning-about-github/types-of-github-accounts.md>

**REST エンドポイントの確認**（GitHub の OpenAPI から生成されたもの。実測）

- <https://raw.githubusercontent.com/octokit/plugin-rest-endpoint-methods.js/main/src/generated/endpoints.ts>
  （`deleteWorkflowRun` / `deleteWorkflowRunLogs` / `listWorkflowRunsForRepo` /
  `listPublicMembers` / `checkPublicMembershipForUser`）

**このリポジトリの実測**（GitHub API 経由。認証は `boobooyuta`）

- 実行履歴 29件と全件の `actor`
- PR #1 の `user` / `merged_by`
- main 全16コミットの author/committer 紐づけ先
- collaborator 一覧（1人）と team 一覧（0件）
- artifact の保持状態
- 孤立コミット `b5cff9b` がいまも取得できること

**未実測（この環境の制約）**

- 未認証の第三者から見た org メンバー・オーナー一覧（[2章](#2-調査環境の制約-項目2が実測できない理由)）
- 実行削除後に check run / deployment が残るか（削除操作が必要なため未実施）
