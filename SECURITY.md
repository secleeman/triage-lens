# Security Policy / セキュリティポリシー

*English follows Japanese.*

---

## 日本語

### 脆弱性の報告先

**triage-lens 自体の脆弱性は、公開の Issue ではなく GitHub の非公開の報告窓口
（Private Vulnerability Reporting）からお願いします。**

1. このリポジトリの **Security** タブを開く
2. **Advisories** → **Report a vulnerability** を押す
3. フォームに、再現手順・影響・確認した版を書いて送信する

直リンク: <https://github.com/secleeman/triage-lens/security/advisories/new>

このやり取りは、公開するまで報告者とメンテナ以外には見えません。

> **窓口が見つからない場合**、まだリポジトリ側で機能を有効化できていない可能性があります。
> そのときは、脆弱性の詳細を書かずに「セキュリティの件で連絡したい」とだけ書いた Issue を
> 立ててください。窓口を開けてから、そちらでやり取りします。
> **Issue に詳細を書かないでください。**

**メールアドレスは公開していません。** 連絡は上記の GitHub 上の窓口に一本化しています。

### 対象になるもの・ならないもの

| 対象 | 例 |
| --- | --- |
| ✅ 対象 | triage-lens が読み込んだ入力ファイル（Trivy JSON / CycloneDX / SPDX）によって、任意のコードが実行される・想定外のファイルを読み書きする |
| ✅ 対象 | `ANTHROPIC_API_KEY` などの秘密情報が、レポート・標準出力・標準エラー・キャッシュに漏れる |
| ✅ 対象 | キャッシュ（`~/.cache/triage-lens/`）の内容を細工することで、優先度の判定を外部から操作できる |
| ✅ 対象 | 外部データ（KEV / EPSS）の取得経路を細工して、判定を操作できる |
| ✅ 対象 | GitHub Actions / Trivy プラグインとして動かしたときに、入力から権限が昇格する |
| ❌ 対象外 | **スキャン対象に見つかった脆弱性そのもの**（それは triage-lens の入力であって、triage-lens の脆弱性ではありません） |
| ❌ 対象外 | 優先度の判定結果が期待と違う、順位が妥当でない（バグまたは仕様の議論として、通常の [Issue](https://github.com/secleeman/triage-lens/issues) へ） |
| ❌ 対象外 | NVD / EPSS / CISA KEV 側のデータの誤り |
| ❌ 対象外 | 依存パッケージの既知の脆弱性そのもの（ただし **triage-lens 経由で悪用できる** 場合は対象です。その経路を書いてください） |

### サポート対象バージョン

**最新のリリースだけをサポートします。** 1.0 より前のため、古い版へのバックポートは行いません。
修正は次のリリースに含める形で公開します。

| バージョン | サポート |
| --- | --- |
| 最新リリース（[Releases](https://github.com/secleeman/triage-lens/releases) の最上段） | ✅ |
| それより前のすべての版 | ❌ |

インストール済みの版は `pip show triage-lens` で確認できます。

### 対応の目安

**SLA は約束しません。ベストエフォートです。**

これは個人が空き時間で保守しているツールです。報告を受けたら読みますが、
返信・修正・公開の時期は状況によります。**「何日以内に返信します」とは書きません。**
書けないことを書かないのが、このプロジェクトの方針です
（[README](https://github.com/secleeman/triage-lens/blob/main/README.md) の
「この判断エンジンが守っていること」と同じ考え方です）。

実際に行うのは次のことだけです。

- 報告は読みます
- 修正するかどうかを決めたら、報告のスレッドで伝えます（「修正しない」と返すこともあります）
- 修正する場合は、GitHub Security Advisory を公開し、修正を含むリリースを出します
- 希望があれば、Advisory に報告者としてクレジットします

### 公開の方針

修正が公開できる状態になってから、GitHub Security Advisory として公開します。
報告者と調整して、公開のタイミングを決めます。

---

## English

### Where to report

**Please report vulnerabilities in triage-lens itself through GitHub's private
reporting channel, not in a public issue.**

1. Open the **Security** tab of this repository
2. Go to **Advisories** → **Report a vulnerability**
3. Describe how to reproduce it, the impact, and the version you tested

Direct link: <https://github.com/secleeman/triage-lens/security/advisories/new>

The thread stays private between you and the maintainer until it is published.

> **If you cannot find the form**, the feature may not be enabled on the repository
> yet. In that case, open an issue saying only that you would like to make a security
> report — **do not put any details in it** — and it will be moved to a private thread.

**No email address is published.** All contact goes through the GitHub channel above.

### In scope / out of scope

| Scope | Example |
| --- | --- |
| ✅ In | An input file that triage-lens reads (Trivy JSON / CycloneDX / SPDX) causing arbitrary code execution, or reads/writes outside the expected files |
| ✅ In | Secrets such as `ANTHROPIC_API_KEY` leaking into the report, stdout, stderr, or the cache |
| ✅ In | Tampering with the cache (`~/.cache/triage-lens/`) to control the priority a finding gets |
| ✅ In | Tampering with how external data (KEV / EPSS) is fetched in order to control the outcome |
| ✅ In | Privilege escalation from the input when run as a GitHub Action or a Trivy plugin |
| ❌ Out | **A vulnerability found in whatever you scanned** — that is triage-lens's input, not a flaw in triage-lens |
| ❌ Out | Disagreement with the priority a finding was assigned (that is a bug report or a design discussion — please use a normal [issue](https://github.com/secleeman/triage-lens/issues)) |
| ❌ Out | Incorrect data on the NVD / EPSS / CISA KEV side |
| ❌ Out | A known vulnerability in a dependency, by itself. If it is **exploitable through triage-lens**, it is in scope — describe that path |

### Supported versions

**Only the latest release is supported.** This project is pre-1.0, so fixes are not
backported; they ship in the next release.

| Version | Supported |
| --- | --- |
| Latest release (top of [Releases](https://github.com/secleeman/triage-lens/releases)) | ✅ |
| Everything older | ❌ |

`pip show triage-lens` reports the version you have installed.

### What to expect

**No SLA is promised. This is best effort.**

triage-lens is maintained by one person in their spare time. Reports get read, but
when a reply, a fix, or a publication happens depends on circumstances.
**No "we will respond within N days" is claimed here** — not writing down what cannot
be guaranteed is the same principle the tool itself follows (see "What this engine
commits to" in the [README](https://github.com/secleeman/triage-lens/blob/main/README.en.md)).

What actually happens:

- The report is read.
- Once it is decided whether to fix it, that is said in the report thread — including
  when the answer is that it will not be fixed.
- If it is fixed, a GitHub Security Advisory is published along with a release
  containing the fix.
- The reporter is credited in the advisory if they want to be.

### Disclosure

An advisory is published once a fix is ready to ship, at a time agreed with the
reporter.
