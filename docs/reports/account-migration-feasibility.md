# アカウント移管 実現性調査

- 日付: 2026-08-31
- 目的: triage-lens リポジトリを、新規の GitHub アカウント（`secleeman` 本体）へ
  移管する場合の作業一覧と影響を洗い出す
- **実行はしていません。** リポジトリ設定・アカウント作成・PyPI 設定のいずれも触っていません。
- 数値と挙動は 2026-08-31 に実測したものです。実測していない箇所は
  「**未実測**」と明記しています。

---

## 0. 結論（先に読むところ）

**移管そのものは可能です。ただし、いま想定されている形のままだと2つの壁があります。**

| # | 論点 | 判定 |
| --- | --- | --- |
| 1 | **新アカウントを `secleeman` と名乗れない** | ⚠️ **ブロッカー**。現在 `secleeman` は **Organization**（ID `322111724`）が占有しています。GitHub のユーザ名と Organization 名は同じ名前空間（どちらも `github.com/<名前>`）なので、org がその名前を持っている限り、同名の個人アカウントは作れません |
| 2 | **名前を空けると、旧URLのリダイレクトが道連れになる可能性が高い** | ⚠️ **要検証**。org をリネーム/削除して名前を空ける → 新アカウントがその名前を取る、という順番だと、`github.com/secleeman/triage-lens` からのリダイレクトは失効する見込みです（後述 [7-4](#7-4-名前を空けるとリダイレクトはどうなるか)） |
| 3 | PyPI Trusted Publishing | 🔧 **確実に壊れる。再登録が必要**（所有者の数値IDまで照合しているため、同名でも別アカウントなら通りません） |
| 4 | GitHub Actions（`uses: secleeman/triage-lens@v...`） | 🔧 **壊れる**。GitHub は action の解決でリポジトリのリダイレクトを追いません |
| 5 | `pip install triage-lens` | ✅ **無傷**。PyPI から取るので GitHub の所有者は関係ありません |
| 6 | Zenn / dev.to などの記事内リンク | ✅ リダイレクトされます（**壊すのは 2 の操作**） |
| 7 | Trivy プラグインの導入 | ✅ **git のリダイレクトで通る見込み**（git 追従は実測済み） |
| 8 | star / issue / PR / コミット履歴 | ✅ **引き継がれます**（そもそも現在 star は **0件**） |

### 今やるなら、いちばん良いタイミングです

実測: **star 0 / fork 0 / watcher 0 / open issue 0 / GitHub Release 0件。**
外部から参照されている実績がほぼありません。**失うものが最小の今のうちに動かすのが、
いちばん傷が浅い**です。1年後に star が付いてからでは、同じ判断はできません。

### 推奨する順番

**新アカウント名を `secleeman` 以外にできるなら、話は単純です**（[10-A](#10-a-新アカウント名を変える推奨)）。
どうしても `secleeman` を名乗りたい場合は、旧URLのリダイレクトを捨てる覚悟が要ります
（[10-B](#10-b-どうしても-secleeman-を名乗る)）。

---

## 1. 現状の実測

移管の影響を測る前提として、いま何がどうなっているかを実際に取得しました。

### 1-1. GitHub 側

| 項目 | 実測値 |
| --- | --- |
| リポジトリ | `secleeman/triage-lens`（repo ID `1349631653`） |
| **所有者の種別** | **Organization**（`"type": "Organization"`、node_id が `O_` 始まり） |
| 所有者 ID | `322111724` |
| 作成日 | 2026-08-28 |
| 可視性 | public / MIT / 既定ブランチ `main` |
| **star** | **0** |
| **fork** | **0** |
| **watcher** | **0** |
| **open issue** | **0** |
| リポジトリサイズ | 341 KB |
| タグ | 7件（`v0.4.0` 〜 `v0.8.0`） |
| **GitHub Release** | **0件**（タグはあるが Release オブジェクトは作っていない） |
| 操作しているアカウント | `boobooyuta`（ID `201195462`、public repos 2）。このリポジトリに admin 権限あり |

> **補足**: `secleeman` が Organization であることは、リポジトリ検索 API が返す
> `owner.type` と `node_id`（`O_kgDOEzMI7A`）で確認しました。あわせてユーザ検索
> （`type:user` に自動限定される）で `secleeman` は 0件でした。

### 1-2. PyPI 側

```
$ curl -sS https://pypi.org/pypi/triage-lens/json
name: triage-lens
version: 0.8.0
author: secleeman
releases: ['0.4.0', '0.4.1', '0.5.0', '0.6.0', '0.7.0', '0.7.1', '0.8.0']
project_urls: {
  "Homepage":      "https://github.com/secleeman/triage-lens",
  "Repository":    "https://github.com/secleeman/triage-lens",
  "Issues":        "https://github.com/secleeman/triage-lens/issues",
  "Documentation": "https://github.com/secleeman/triage-lens/blob/main/README.md",
  "Changelog":     "https://github.com/secleeman/triage-lens/blob/main/docs/ROADMAP.md"
}
```

**PyPI のプロジェクト所有権は GitHub とは別勘定です。** リポジトリを移管しても
PyPI 上の `triage-lens` の所有者は変わりません。変わるのは
**「どの GitHub リポジトリからの公開を信用するか」（Trusted Publisher）だけ**です。

### 1-3. リポジトリ内の `secleeman` 参照

```
$ grep -rln "secleeman" --include="*.md" --include="*.yml" --include="*.yaml" \
    --include="*.toml" --include="*.py" .
```

**12ファイル・61箇所**。

| ファイル | 件数 | 中身 |
| --- | --- | --- |
| `README.md` | 14 | 各種リンク |
| `README.en.md` | 14 | 各種リンク |
| `SECURITY.md` | 8 | Advisory の直リンクなど |
| `docs/reports/reposition-readme.md` | 8 | 過去の報告書（履歴なので書き換え不要） |
| `pyproject.toml` | 6 | `authors` 1 + `urls` 5 |
| `tests/test_packaging.py` | 3 | **`PUBLIC_REPO_URL` 定数と author 検査** |
| `plugin.yaml` | 2 | `repository:` と `maintainer:` |
| `docs/ROADMAP.md` | 2 | リンク |
| `.github/workflows/release.yml` | 1 | コメント |
| `action.yml` | 1 | `author:` |
| `src/triage_lens/http_client.py` | 1 | **User-Agent 文字列** |
| `CLAUDE.md` | 1 | リポジトリの記載 |

---

## 2. 調査環境の制約

この作業環境は外向き通信が制限されています。**到達できなかったものは実測していません。**

| ホスト | 状態 | 代替 |
| --- | --- | --- |
| `raw.githubusercontent.com` | ✅ | GitHub 公式ドキュメント・PyPI/Trivy のソースを直接読んだ |
| `pypi.org` | ✅ | パッケージメタデータを直接取得 |
| GitHub API（MCP 経由） | ✅ | リポジトリ・アカウント情報を取得 |
| `github.com`（HTML） | ❌ 403 | **Web のリダイレクト挙動を実測できていません**（ドキュメントの記載のみ） |
| `docs.github.com` | ❌ | ソースの `github/docs` リポジトリの Markdown を直接読んで代替 |
| `docs.pypi.org` | ❌ | ソースの `pypi/warehouse` の Markdown とコードを直接読んで代替 |

**GitHub Actions の実際の挙動（`uses:` の解決）は、この環境では実行できないため
未実測です。** 公式ドキュメントの記載と、公開されている不具合報告に基づいています。

---

## 3. 移管手順（Organization → 個人アカウント）

GitHub 公式ドキュメントのソース（`github/docs`）から引用します。

### 3-1. 前提条件（原文ママ）

> * To transfer a repository you must have administrator access to the repository.
> * When you transfer a repository that you own to another personal account, the new owner will receive a confirmation email. The confirmation email includes instructions for accepting the transfer. **If the new owner doesn't accept the transfer within one day, the invitation will expire.**
> * **The target account must not have a repository with the same name, or a fork in the same network.**
> * The original owner of the repository is added as a collaborator on the transferred repository.

**「1日以内に受諾しないと招待が失効する」**点に注意してください。移管操作をしたら、
その日のうちに新アカウント側でメールから受諾する必要があります。

### 3-2. 操作手順（原文ママ）

Organization 所有のリポジトリを個人アカウントへ移す場合:

> 1. Sign into your personal account that has admin or owner permissions in the organization that owns the repository.

そのうえで:

> 1. Under your repository name, click **Settings**.
> 1. At the bottom of the page, in the "Danger Zone" section, click **Transfer**.
> 1. Read the information about transferring a repository, then, under "New owner", choose how to specify the new owner.
>    * To specify an organization or username, select **Specify an organization or username**, then type the organization name or the new owner's username.
> 1. Read the warnings about potential loss of features depending on the new owner's GitHub subscription.
> 1. Following **Type REPOSITORY NAME to confirm**, type the name of the repository you'd like to transfer, then click **I understand, transfer this repository**.

つまり `boobooyuta`（org に admin 権限あり）でサインインしたまま操作できます。

### 3-3. ⚠️ 名前が「引退」する条件（原文ママ）

> If the transferred repository contains an action listed on GitHub Marketplace, or had more than 100 clones or more than 100 uses of GitHub Actions in the week prior to the transfer, GitHub permanently retires the owner name and repository name combination (`OWNER/REPOSITORY-NAME`) when you transfer the repository.

このリポジトリの場合:

- **Marketplace 掲載は行っていません。** `action.yml` に
  「Marketplace に掲載する場合にそのまま使えるよう、先に入れてある（掲載作業そのものは行っていない）」
  とコメントがあり、`branding` だけが用意された状態です
- **直近1週間の clone 数 / Actions 実行数は未実測です。** Traffic API は
  この環境の権限では取得できませんでした。**移管前に
  Insights → Traffic で clone 数を確認してください**（100 未満なら引退しません）

なお引退しても実害はほぼありません。旧パスに**新しいリポジトリを作れなくなるだけ**で、
むしろリダイレクトを保護する方向に働きます。

---

## 4. ⚠️ 最大の論点: アカウント名 `secleeman` の取り合い

**これが今回いちばん重要な発見です。**

GitHub では **ユーザ名と Organization 名が同じ名前空間を共有します。**
どちらも `https://github.com/<名前>` に住むので、1つの名前を2つのアカウントが
同時に持つことはできません。

実測のとおり、いま `secleeman` は **Organization（ID 322111724）が占有中**です。

したがって **「新規アカウントを作って `secleeman` と名乗る」は、そのままでは実行できません。**
選べるのは次の3つです。

| 案 | 内容 | 旧URLのリダイレクト |
| --- | --- | --- |
| **A** | 新アカウントを **別名**にする（例: `secleeman-dev`, `sec-leeman`） | ✅ 生きる |
| **B** | org を先にリネーム/削除して `secleeman` を空け、新アカウントで取得 | ❌ **失効する見込み**（[7-4](#7-4-名前を空けるとリダイレクトはどうなるか)） |
| **C** | 移管せず、**org のまま運用を続ける** | ✅ 現状維持 |

**案C を先に検討する価値があります。** そもそも org のままで困っていることは何か、
を先に言語化してください。匿名性が目的なら、org 運用のままでも
「org の public メンバー表示を切る」「コミット名義を noreply に統一する」（既に完了）
で足りる可能性があります。

---

## 5. PyPI Trusted Publishing（OIDC）の再設定

### 5-1. 現在の設定（リポジトリから実測）

`.github/workflows/release.yml` の実態:

| 項目 | 値 |
| --- | --- |
| ワークフローファイル名 | `release.yml` |
| environment 名 | `pypi` |
| 発行元 | `pypa/gh-action-pypi-publish@v1.14.2`（版数固定） |
| 権限 | `id-token: write`（OIDC 発行用） |
| **長期トークン** | **無し**。`tests/test_packaging.py` が `secrets.` や `pypi_api_token` の記述を禁止しており、CI で落ちます |

したがって PyPI 側の Trusted Publisher には、
**`secleeman` / `triage-lens` / `release.yml` / `pypi`** が登録されているはずです。

### 5-2. 移管すると必ず壊れます（一次情報で確認）

PyPI（warehouse）の公式トラブルシューティング（原文ママ）:

> `invalid-publisher` for a previously-working project: this usually indicates
> a typo or that something has changed on either side. One example we've seen
> is when a source repository is renamed, and the configuration on PyPI
> continues to use the old repository name. For GitHub, check that the
> `repository_owner`, `repository` and workflow filename values are the same on
> both sides.

**さらに悪いことに、名前を合わせるだけでは足りません。**
warehouse のソース（`warehouse/oidc/models/github.py`）を読むと、
publisher の照合には **所有者の数値ID** が含まれています。

```python
    repository_owner: Mapped[str] = mapped_column(String, nullable=False)
    repository_owner_id: Mapped[str] = mapped_column(String, nullable=False)
    ...
    __required_verifiable_claims__: dict[str, CheckClaimCallable[Any]] = {
        "repository": _check_repository,
        "repository_owner": check_claim_binary(str.__eq__),
        "repository_owner_id": check_claim_binary(str.__eq__),
        ...
    }
```

照合クエリも数値IDで絞り込んでいます:

```python
        query: Query = Query(cls).filter_by(
            repository_name=repository_name,
            repository_owner=repository_owner,
            repository_owner_id=signed_claims["repository_owner_id"],
            workflow_filename=job_workflow_filename,
        )
```

**つまり、新アカウントの名前を `secleeman` に揃えても、アカウントが別なら
数値IDが違うので publisher は一致しません。** 案B を採っても再登録は必須です。

### 5-3. 登録時に GitHub へ問い合わせが飛びます

`warehouse/oidc/forms/github.py`:

```python
    def _lookup_owner(self, owner: str) -> dict[str, str | int]:
        ...
                f"https://api.github.com/users/{owner}",
        ...
                    _("Unknown GitHub user or organization.")
        ...
        owner_info = self._lookup_owner(owner)
        self.normalized_owner = owner_info["login"]
        self.owner_id = owner_info["id"]
```

**新アカウントが実在していないと登録できません。** 順番は
「新アカウント作成 → PyPI に publisher 追加 → 移管」です。

### 5-4. 無停止で切り替える手順

PyPI 公式ドキュメント（原文ママ）:

> A publisher can be registered against multiple PyPI projects (e.g. for a
> multi-project repository), and a single PyPI project can have multiple
> publishers (e.g. for multiple workflows on different architectures, operating
> systems).

**1プロジェクトに複数 publisher を登録できます。** これを使って、次の順で
公開を止めずに移せます。

1. 新 GitHub アカウントを作る
2. PyPI の `triage-lens` → Manage → **Publishing** で、**新**所有者の publisher を
   **追加**する（旧はまだ消さない）。
   入力するのは4つ: 所有者名 / リポジトリ名 `triage-lens` / ワークフロー `release.yml` / environment `pypi`
3. リポジトリを移管する
4. 移管後に一度リリースして、新 publisher で通ることを確認する
5. **通ったら、旧（org）の publisher を削除する**

**手順5を忘れないでください。** 残したままだと、org 側から引き続き PyPI へ
公開できる状態が残ります。移管の目的が「org から手を切る」ことなら、これは穴になります。

### 5-5. environment の扱い

`release.yml` は `environment: name: pypi` を使っています。
GitHub の environment は**リポジトリに属する**ので移管で一緒に移りますが、
**移管後に Settings → Environments で `pypi` が残っているか目視確認してください**（未実測）。
publisher 側の environment 名と食い違うと `invalid-publisher` になります。

---

## 6. GitHub Actions の動作

### 6-1. ワークフロー自体（CI / Release）は問題なし

- `ci.yml` / `release.yml` とも **Secrets を1つも使っていません**（`test_release_workflow_has_no_long_lived_token` が禁止）。
  したがって「org レベルの Secrets が移管で失われる」問題は**該当しません**
- public リポジトリなので Actions の実行時間は引き続き無料枠です
- `uses:` している外部 action（`actions/checkout@v7` 等）は所有者が変わっても無関係

**移管でワークフローが動かなくなる要因は、5章の PyPI publisher だけ**です。

### 6-2. ⚠️ 逆向きは壊れる: 利用者の `uses: secleeman/triage-lens@v...`

README は GitHub Action としての利用を案内しています
（`uses: secleeman/triage-lens@vX.Y.Z`）。**これは移管で壊れます。**

GitHub 公式ドキュメント（リネームの項。原文ママ）:

> **Note**
> GitHub will not redirect calls to an action hosted by a renamed repository.
> Any workflow that uses that action will fail with the error `repository not found`.
> Instead, create a new repository and action with the new name and archive the old repository.

> **注意**: この記載は「リネーム」の項にあります。**「移管」の項には同じ注記がありません。**
> ただし action の解決は `OWNER/REPO` を鍵にしているため、所有者が変わる移管でも
> 同じことが起きると考えるのが自然です。実際に
> [community discussion #43111](https://github.com/orgs/community/discussions/43111)
> は "Ownership transfer - Error: Unable to resolve actions. Repository not found" という
> 表題で、移管でも同じ症状が報告されています。
> **この環境では Actions を実行できないため未実測です。壊れる前提で計画してください。**

**影響範囲は現時点では小さい**です。star 0 / fork 0 で、外部に利用者がいる形跡が
ありません。ただし移管後は README の `uses:` の記載を新しい所有者名に直す必要があります。

---

## 7. 既存URLのリダイレクト

### 7-1. `pip install triage-lens` — ✅ 無傷

PyPI から取得するため、GitHub の所有者は一切関係ありません。
**既に公開済みの 0.4.0〜0.8.0 も、そのままインストールできます。**

ただし PyPI のページに出るリンク（`project_urls`）は旧URLのままなので、
7-2 のリダイレクトに乗ります。次のリリースで新URLに差し替わります。

**既に公開済みの版のメタデータは書き換えられません**（PyPI は同一版数の上書き不可）。
0.8.0 のページのリンクは、リダイレクトが生きている限りは機能します。

### 7-2. Web のリンク（Zenn / dev.to の記事内リンク） — ✅ リダイレクトされる

GitHub 公式ドキュメント（原文ママ）:

> All links to the previous repository location are automatically redirected to the new location.

> **未実測**: この環境からは `github.com` の HTML に到達できず（403）、
> リダイレクトを自分で確認できていません。ドキュメントの記載のみです。

### 7-3. git 操作 — ✅ **実測で確認しました**

GitHub 公式ドキュメント（原文ママ）:

> When you use `git clone`, `git fetch`, or `git push` on a transferred repository,
> these commands will redirect to the new repository location or URL.

実際に、**移管済みの公開リポジトリで確かめました**（`facebook/jest` は
`jestjs/jest` へ移管済み）:

```
$ git ls-remote https://github.com/facebook/jest HEAD
be425a0b0e3bd60a74e4a7e350aa38c63a2d25ef

$ git ls-remote https://github.com/jestjs/jest HEAD
be425a0b0e3bd60a74e4a7e350aa38c63a2d25ef
```

**旧パスと新パスで HEAD が完全に一致**。git は移管先へ透過的に追従しています。

**この結果は Trivy プラグインにも効きます。** Trivy の
`pkg/plugin/manager.go` は go-getter の git 取得を使っており、
引数の解釈も go-getter の Git セクションを参照しています:

```go
func (m *Manager) parseArg(ctx context.Context, arg string) Input {
	before, after, found := strings.Cut(arg, "@v")
	...
	// cf. https://github.com/hashicorp/go-getter/blob/.../README.md#git-git
```

したがって `trivy plugin install github.com/secleeman/triage-lens@v0.8.0` は
**git のリダイレクトで通る見込み**です（go-getter の git 取得を経由するという
推論であり、Trivy を実際に動かしての確認はしていません）。

### 7-4. 名前を空けるとリダイレクトはどうなるか

**ここが案B の急所です。**

ドキュメントに明記されているのは、この警告だけです（原文ママ）:

> **Warning**
> If you create a new repository or fork at the previous repository location,
> the redirects to the transferred repository will be permanently deleted.

**「org 自体をリネーム/削除した場合」については書かれていません（未実測・推論）。**
ただし構造的に考えると:

- リダイレクトは `github.com/secleeman/triage-lens` という**旧パス**に紐づいています
- org をリネーム/削除すると、その名前は解放されます
- 新しい個人アカウントが `secleeman` を取ると、`github.com/secleeman/` は
  **その新アカウントの名前空間**になります
- 上の警告と同じ理屈（旧パスを別の誰かが占有したらリダイレクトは消える）が働くはずです

**つまり案B では「旧URLのリダイレクト」と「`secleeman` という名前」は
両立しない可能性が高い**です。どちらを取るかを先に決めてください。

なお案B を採っても、**`pip install triage-lens` は無傷**です（7-1）。
壊れるのは記事内リンクと `git clone` の旧パスです。

---

## 8. star / issue / コミット履歴の引き継ぎ

GitHub 公式ドキュメント（原文ママ）:

> When you transfer a repository, its issues, pull requests, wiki, stars, and watchers are also transferred. If the transferred repository contains webhooks, services, secrets, or deploy keys, they will remain associated after the transfer is complete. **Git information about commits, including contributions, is preserved.**

**全部引き継がれます。** そして実測のとおり、

- star **0** / watcher **0** / fork **0** / open issue **0**
- GitHub Release **0件**（タグ7件は git のオブジェクトなので当然移動します）

**引き継ぐ中身がほぼありません。今なら実質ノーリスクです。**

org → 個人アカウントで**失われるもの**（原文ママ）:

> When you transfer a repository from an organization to a personal account, the repository's read-only collaborators will not be transferred.

> When you transfer a repository from an organization to a personal account, only issues assigned to the repository's owner are kept, and all other issue assignees are removed.

いずれも該当なし（collaborator は実質1人、open issue 0件）。

**コミット履歴の名義**は git オブジェクトそのものなので変わりません。
先日 main 全16コミットを `secleeman <secleeman@users.noreply.github.com>` に
統一済みで、その状態のまま移ります。

---

## 9. コードの書き換えと、壊れるテスト

移管しただけでは**テストは緑のままです**（`secleeman` という文字列同士で
内部的に整合しているため）。壊れるのは**中途半端に直したとき**です。

### 9-1. 実測: pyproject.toml だけ直すと3件落ちる

`pyproject.toml` の URL だけを別の所有者名に変えて `tests/test_packaging.py` を
走らせました。

```
FAILED tests/test_packaging.py::test_urls_point_to_the_public_repository
FAILED tests/test_packaging.py::test_bug_report_url_is_published
FAILED tests/test_packaging.py::test_pyproject_links_only_to_the_public_repository
```

原因は `tests/test_packaging.py:20` の定数です。

```python
PUBLIC_REPO_URL = "https://github.com/secleeman/triage-lens"
```

**`pyproject.toml` と `tests/test_packaging.py` は必ず同じコミットで直してください。**

### 9-2. 書き換えが必要なファイル

| ファイル | 直すもの | 必須か |
| --- | --- | --- |
| `tests/test_packaging.py` | `PUBLIC_REPO_URL`（20行目） | **必須**（CI が落ちる） |
| `pyproject.toml` | `urls` の5つ | **必須**（PyPI のページのリンク） |
| `src/triage_lens/http_client.py` | User-Agent（35行目） | 推奨。外部APIに名乗る文字列 |
| `plugin.yaml` | `repository:` / `maintainer:` | **必須**（Trivy プラグインの導入元） |
| `action.yml` | `author:` | 推奨 |
| `README.md` / `README.en.md` | リンク14箇所ずつ、`uses:` の記載 | **必須** |
| `SECURITY.md` | Advisory 直リンクなど8箇所 | **必須** |
| `docs/ROADMAP.md` | リンク2箇所 | 推奨 |
| `CLAUDE.md` | リポジトリの記載 | 推奨 |
| `.github/workflows/release.yml` | コメント1箇所 | 任意 |
| `docs/reports/*.md` | 過去の報告書 | **直さない**（当時の記録なので） |

**新アカウント名が `secleeman` のままなら、`authors = [{ name = "secleeman" }]` と
`test_author_has_no_personal_information` は無変更で通ります。**
別名にする場合は、そこも揃えるか、表示名としての `secleeman` を残すか決めてください。

---

## 10. 作業一覧とチェックリスト

### 10-A. 新アカウント名を変える（推奨）

所要 **1〜2時間**（GitHub の受諾待ちを除く）。

- [ ] 1. 新しい GitHub アカウントを作る（`secleeman` 以外の名前）
- [ ] 2. 移管前に Insights → Traffic で **clone 数が週100未満**か確認（名前引退の判定）
- [ ] 3. PyPI の `triage-lens` → Manage → Publishing で **新所有者の publisher を追加**
      （所有者名 / `triage-lens` / `release.yml` / `pypi`）。**旧はまだ消さない**
- [ ] 4. `boobooyuta` でサインインしたまま、Settings → Danger Zone → Transfer
- [ ] 5. **同日中に**新アカウントのメールから移管を受諾（1日で失効）
- [ ] 6. 移管後、Settings → Environments に `pypi` が残っているか確認
- [ ] 7. 9-2 の表に沿ってファイルを書き換え、`pytest` と `ruff` が緑になることを確認 → PR → マージ
- [ ] 8. パッチ版（例 `v0.8.1`）をタグ push して、**新 publisher で PyPI 公開が通ることを確認**
- [ ] 9. **通ったら PyPI の旧 publisher（org 側）を削除**
- [ ] 10. `git remote set-url origin <新URL>` でローカルの clone を更新
- [ ] 11. Zenn / dev.to の記事内リンクを新URLに更新（リダイレクトは効くが、
      将来のために直しておく）
- [ ] 12. 旧 org `secleeman` をどうするか決める（**残せばリダイレクトが生き続けます**）

### 10-B. どうしても `secleeman` を名乗る

上に加えて、**旧URLのリダイレクトを捨てる**判断が要ります。

- [ ] 先に 10-A の 2〜9 を、**一時的な別名**の新アカウントで完了させる
- [ ] リダイレクトが不要になったと判断してから、org をリネーム/削除して名前を解放
- [ ] 新アカウントの名前を `secleeman` に変更（Settings → Account → Change username）
- [ ] **アカウント名を変えると PyPI publisher が再び一致しなくなります。**
      publisher を作り直して、もう一度リリースで疎通確認
- [ ] 9-2 のファイルをもう一度書き換え

**手順が二重になります。** `secleeman` を名乗ることに、この手間と
旧URL失効を払う価値があるかを先に判断してください。

---

## 11. 判定

**判定: 実行可能。ただし「新アカウント名を `secleeman` にする」という前提だけは、
いまのままでは成立しません。**

| 判断 | 内容 |
| --- | --- |
| ✅ **やるなら今** | star 0 / fork 0 / Release 0。失うものが最小 |
| ✅ 技術的な障害 | ありません。PyPI は publisher 追加で無停止に切り替えられます |
| ⚠️ **要決断** | `secleeman` という名前と、旧URLのリダイレクトは両立しない見込み |
| ⚠️ **壊れるもの** | PyPI Trusted Publisher（再登録で解決）、`uses:` による action 参照（README 更新で解決） |
| ❓ **先に言語化すべき** | そもそも org のままだと何が困るのか。匿名性が目的なら org 運用でも達成できる可能性があります |

### 未実測で残っている項目（実行前に確認してください）

1. **直近1週間の clone 数 / Actions 実行数**（Insights → Traffic）。100 を超えると
   `secleeman/triage-lens` の名前が永久に引退します
2. **Web リダイレクトの実挙動**。この環境から `github.com` の HTML に到達できませんでした
3. **移管で `uses:` が壊れること**。ドキュメントの明記はリネームの項のみ。
   Actions を実行できないため未確認
4. **org をリネーム/削除したときのリダイレクトの生死**。ドキュメントに記載がありません。
   構造からの推論です
5. **移管後に environment `pypi` が残るか**

---

## 12. 出典

すべて 2026-08-31 に取得。（実測）は、この調査で実際に取得・実行して確認したものです。

**GitHub**

- リポジトリ移管（実測、ドキュメントのソースを直接取得）:
  <https://raw.githubusercontent.com/github/docs/main/content/repositories/creating-and-managing-repositories/transferring-a-repository.md>
  （公開ページ: <https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository>）
- 移管の操作手順（実測）:
  <https://raw.githubusercontent.com/github/docs/main/data/reusables/repositories/transfer-repository-steps.md>
- リネームと action のリダイレクト（実測）:
  <https://raw.githubusercontent.com/github/docs/main/content/repositories/creating-and-managing-repositories/renaming-a-repository.md>
- 移管で action が解決できなくなる報告（未検証・二次情報）:
  <https://github.com/orgs/community/discussions/43111>
- リポジトリ・アカウント情報（実測、GitHub API 経由）

**PyPI**

- Trusted Publishers 入門（実測）:
  <https://raw.githubusercontent.com/pypi/warehouse/main/docs/user/trusted-publishers/index.md>
- publisher の追加（実測）:
  <https://raw.githubusercontent.com/pypi/warehouse/main/docs/user/trusted-publishers/adding-a-publisher.md>
- トラブルシューティング（実測）:
  <https://raw.githubusercontent.com/pypi/warehouse/main/docs/user/trusted-publishers/troubleshooting.md>
- 所有者IDの照合ロジック（実測、ソースコード）:
  <https://raw.githubusercontent.com/pypi/warehouse/main/warehouse/oidc/models/github.py>
- 登録時の GitHub 問い合わせ（実測、ソースコード）:
  <https://raw.githubusercontent.com/pypi/warehouse/main/warehouse/oidc/forms/github.py>
- `triage-lens` のメタデータ（実測）: <https://pypi.org/pypi/triage-lens/json>

**Trivy**

- プラグインの取得方式（実測、ソースコード）:
  <https://raw.githubusercontent.com/aquasecurity/trivy/main/pkg/plugin/manager.go>

**リダイレクトの実測**

- `git ls-remote https://github.com/facebook/jest` と
  `https://github.com/jestjs/jest` の HEAD 一致を確認（2026-08-31）
