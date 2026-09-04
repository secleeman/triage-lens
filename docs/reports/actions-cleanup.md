# Actions 実行履歴の削除 — 実行手順と記録用（⚠️ **未実行**）

> ## ⚠️ この文書は「作業記録」ではありません
>
> **削除は1件も実行していません。** 2026-09-04 時点で、Actions の実行履歴は
> すべて残っています。この文書は、**オーナーがご自身の環境で実行するための
> 手順書と、結果を書き込むための空欄**です。
>
> 実行後に [6章](#6-実行結果の記録欄) を埋めてください。**埋まっていない間は
> 「未実行」と読んでください。**

- 日付: 2026-09-04
- 目的: `secleeman/triage-lens` の Actions 実行履歴を全件削除し、
  各実行に記録されている実行者アカウントの露出を消す
- 関連: `docs/reports/org-anonymity-hardening.md`（調査の本体。削除の可否・
  残る痕跡・優先順位はそちらに記載）

---

## 1. なぜこの作業環境で実行できなかったか

**実行削除の経路が2つとも塞がっています。** 実測した結果です。

### 1-1. GitHub MCP に実行削除のツールが無い

この環境から GitHub を操作できるのは MCP サーバ経由だけです。Actions 系で
使えるメソッドは次のとおりで、**実行レコードそのものを削除するものがありません。**

| ツール | 使えるメソッド |
| --- | --- |
| `actions_list` | `list_workflows` / `list_workflow_runs` / `list_workflow_jobs` / `list_workflow_run_artifacts` |
| `actions_get` | `get_workflow` / `get_workflow_run` / `get_workflow_job` / `download_workflow_run_artifact` / `get_workflow_run_usage` / `get_workflow_run_logs_url` |
| `actions_run_trigger` | `run_workflow` / `rerun_workflow_run` / `rerun_failed_jobs` / `cancel_workflow_run` / **`delete_workflow_run_logs`** |

**`delete_workflow_run_logs` はログだけを消します。実行レコードは残り、
そこに記録された実行者アカウントも残ります。**
つまりこれを使っても目的を達成せず、ログだけが不可逆に失われます。
**そのため実行していません。**

### 1-2. REST API を直接叩く経路も塞がっている

```
$ curl -sS -i https://api.github.com/repos/secleeman/triage-lens/actions/runs
HTTP/1.1 403 Forbidden
{"message":"GitHub access is not enabled for this session. An org admin must
connect the Claude GitHub App for this organization."}
```

`gh` CLI もこの環境にはありません。

**結論: この作業は、オーナーの手元（`gh` が使える環境）で実行する必要があります。**

---

## 2. 実行前に確認すること

- [ ] `gh auth status` が通ること
- [ ] そのアカウントが `secleeman/triage-lens` に **Write 以上**の権限を持つこと
      （公式ドキュメント: "Write access to the repository is required to perform these steps."）
- [ ] **削除は取り消せない**ことを了解していること
- [ ] **artifact も一緒に消える**ことを了解していること
      （公式ドキュメント: "When a workflow run is deleted all artifacts associated
      with the run are also deleted from storage."）

> **順番の注意**: `docs/reports/org-anonymity-hardening.md` の 0-4 に書いたとおり、
> **マシンアカウントへの切り替えを先に済ませたほうが効率的**です。
> 先に履歴を消しても、次の push でまた同じアカウントの実行が増えます。

---

## 3. 実行前スナップショット（削除の直前に取る）

**件数は push のたびに増えます。**（この文書を push した時点でも1件増えます。）
**スナップショットは削除の直前にご自身で取ってください。**

```bash
cd /path/to/triage-lens

# 総数
gh api /repos/secleeman/triage-lens/actions/runs --jq '.total_count' | tee before-count.txt

# 一覧（削除対象のワークリスト。これが「before」の記録になります）
gh api --paginate /repos/secleeman/triage-lens/actions/runs \
  --jq '.workflow_runs[] | [.id, .name, .run_number, .status, .head_sha[0:7], .actor.login] | @tsv' \
  | tee before-runs.tsv

# 実行者の内訳（何件が誰の名義か）
cut -f6 before-runs.tsv | sort | uniq -c
```

**参考（過去の実測値。現在値ではありません）:**

| 時点 | 実測 |
| --- | --- |
| 2026-08-31 | リポジトリ全体で **29件**（`ci.yml` 22 / `release.yml` 7）。**29件すべて**が同一の個人アカウント名義 |
| 2026-09-03 | `main` ブランチ分だけで **19件**。`ci.yml` の `run_number` は **24** まで進行 |

---

## 4. まず1件だけ削除して、残存痕跡を確認する

**ご指示のとおり、1件で挙動を確かめてから残りに進みます。**
`org-anonymity-hardening.md` の 3-4 に書いたとおり、**削除後に check run や
deployment が残るかは公式ドキュメントに記載がなく、未検証**です。ここで確定させます。

### 4-1. 対象を選ぶ

**いちばん古い実行**を選んでください（影響が最小）。

```bash
RUN_ID=$(tail -1 before-runs.tsv | cut -f1)
SHA=$(tail -1 before-runs.tsv | cut -f5)
echo "target run=$RUN_ID sha=$SHA"
```

### 4-2. 削除前の状態を控える

```bash
echo "--- before ---"
gh api "/repos/secleeman/triage-lens/commits/$SHA/check-runs" --jq '.total_count'
gh api /repos/secleeman/triage-lens/deployments --jq 'length'
gh api "/repos/secleeman/triage-lens/actions/runs/$RUN_ID/artifacts" --jq '.total_count'
```

### 4-3. 1件だけ削除する

```bash
gh api -X DELETE "/repos/secleeman/triage-lens/actions/runs/$RUN_ID"
```

### 4-4. 削除後の状態を控える

```bash
echo "--- after ---"
gh api "/repos/secleeman/triage-lens/commits/$SHA/check-runs" --jq '.total_count'
gh api /repos/secleeman/triage-lens/deployments --jq 'length'
gh api "/repos/secleeman/triage-lens/actions/runs/$RUN_ID" --jq '.id' 2>&1 | tail -1   # 404 になるはず
gh api /repos/secleeman/triage-lens/actions/runs --jq '.total_count'                   # 1 減るはず
```

### 4-5. 判断

| 観察 | 意味 | 次の行動 |
| --- | --- | --- |
| check-runs が **0 になった** | 実行削除で check run も消える | そのまま5章へ |
| check-runs が **変わらない** | **check run はコミット側に残る**。Actions を全消ししても、コミットのチェック表示は残ります | 5章へ進んでよいが、[6章](#6-実行結果の記録欄) に記録し、必要なら別途対応を検討 |
| deployments の数が **変わらない** | `pypi` environment の deployment 記録は独立して残る | 同上 |

---

## 5. 残りを削除する

1件目で問題がなければ、残りを回します。

```bash
gh api --paginate /repos/secleeman/triage-lens/actions/runs --jq '.workflow_runs[].id' \
  | while read -r id; do
      if gh api -X DELETE "/repos/secleeman/triage-lens/actions/runs/$id"; then
        echo "deleted $id" | tee -a deleted.log
      else
        echo "FAILED  $id" | tee -a failed.log
      fi
    done

# 残数の確認（0 になるはず）
gh api /repos/secleeman/triage-lens/actions/runs --jq '.total_count' | tee after-count.txt
```

**注意点:**

- **削除できるのは完了済みの実行だけ**です（公式ドキュメント:
  "You can delete a workflow run that has been completed, or is more than two weeks old."）。
  実行中のものがあれば終わるまで待ってください
- **専用の一括削除エンドポイントはありません。** 1件ずつ `DELETE` を回す形が唯一の方法です
- API のレート制限（認証済み 5,000 req/時）は、この件数では問題になりません
- **この削除操作自体は新しい実行を発生させません**（push ではないため）

---

## 6. 実行結果の記録欄

**実行後にここを埋めてください。空欄のままなら未実行です。**

```
実行日時（JST）:
実行者:

--- 件数 ---
削除前の総数:
削除に成功した数:
削除に失敗した数:
削除後の総数:

--- 1件目の残存痕跡テスト（4章） ---
対象 run_id:
対象 sha:
check-runs  before →  after:
deployments before →  after:
削除した run の GET:            （404 なら OK）

--- 気づいたこと ---


--- 未対応で残したもの ---

```

---

## 7. これを実行しても残るもの

`org-anonymity-hardening.md` の 3-4 と 0-2 の再掲です。**期待値を間違えないために、
ここにも書いておきます。**

| 残るもの | 理由 |
| --- | --- |
| **Pull Request の作者・マージ実行者・コメント** | **GitHub に PR の削除機能がありません。** Issue にはありますが PR にはなく、UI にも API にも手段がありません |
| **孤立コミット `b5cff9b`** | SHA 直指定で取得できます。Actions とは別系統。**Support 依頼はしない方針** |
| **PR 本文に埋め込まれた Claude Code のセッションURL** | PR が消せない以上、これも消せません |
| **GH Archive のイベント記録** | 第三者が毎時アーカイブしており、GitHub 側の削除は届きません（`repo-recreate-feasibility.md` 6-2） |
| **Org 監査ログ** | 残りますが**非公開**（org owner のみ）で、180日で消えます |

**この作業で消えるのは「github.com の Actions タブに出ている実行者名」だけ**です。
それでも意味はありますが、**これで匿名になるわけではありません。**

---

## 8. 出典

公式ドキュメントは `github/docs` のソースから直接取得したものです（2026-08-31）。

- 削除の条件と必要権限:
  <https://raw.githubusercontent.com/github/docs/main/content/actions/how-tos/manage-workflow-runs/delete-a-workflow-run.md>
- 必要権限（Write）:
  <https://raw.githubusercontent.com/github/docs/main/data/reusables/repositories/permissions-statement-write.md>
- 実行削除で artifact も消えること:
  <https://raw.githubusercontent.com/github/docs/main/data/reusables/actions/artifacts/artifacts-from-deleted-workflow-runs.md>
- REST エンドポイントの確認（GitHub の OpenAPI から生成されたもの）:
  <https://raw.githubusercontent.com/octokit/plugin-rest-endpoint-methods.js/main/src/generated/endpoints.ts>
  （`deleteWorkflowRun` / `deleteWorkflowRunLogs` / `listWorkflowRunsForRepo`）
