# triage-lens

A CLI tool that takes a scanner's vulnerability list, prioritises it using public data,
and produces a **triage report (Markdown) that tells you what to fix first**.
Install with a single line: `pip install triage-lens`.

*日本語: [README.md](https://github.com/secleeman/triage-lens/blob/main/README.md)*

What the priority is based on:

| Data | What it tells you | Source |
| --- | --- | --- |
| CISA KEV | Whether exploitation has actually been observed | CISA public catalog |
| EPSS | Probability of exploitation in the next 30 days (0–1) | FIRST.org public API |
| CVSS | Severity score (0–10) | Value reported by the scanner |

None of these require an API key.

Optionally, `--ai` adds a one- or two-line note to each finding saying what to
actually do about it. That part uses the Claude API, so it needs your own API key
and is billed to you. Without `--ai`, no request is made.

## See the output first

You can read a **report that triage-lens actually produced** before installing anything.

- [English report](https://github.com/secleeman/triage-lens/blob/main/examples/report-en.md)
- [日本語のレポート](https://github.com/secleeman/triage-lens/blob/main/examples/report-ja.md)
- [A report split by runtime / development dependencies](https://github.com/secleeman/triage-lens/blob/main/examples/report-npm-en.md) (from an npm SBOM)
- [The scan result it was made from, and notes](https://github.com/secleeman/triage-lens/blob/main/examples/README.md)

## Requirements

- Python 3.11 or later
- A scan result in JSON (see the supported formats below)

### Supported input formats

| Format | How to produce it | Notes |
| --- | --- | --- |
| Trivy JSON | `trivy image --format json -o result.json <target>` | Supported since Phase 1 |
| CycloneDX (JSON) | `trivy image --format cyclonedx -o sbom.cdx.json <target>` | Spec 1.4 or later. SBOMs from other tools work too |

**The format is detected from the file contents.** There is no flag to specify it.

CycloneDX is an SBOM format, so a file may contain no vulnerability list
(`vulnerabilities`). In that case you get a report with zero findings —
triage-lens does not detect vulnerabilities itself.

SPDX and the XML representation of CycloneDX are not supported.

## Installation

```bash
pip install triage-lens
```

Check that it worked:

```bash
triage-lens --help
```

If `pip` is not found, try `python -m pip install triage-lens`.

### Keeping it isolated

If you only need the command, [pipx](https://pipx.pypa.io/) installs it into its
own environment:

```bash
pipx install triage-lens
```

### Upgrading

```bash
pip install --upgrade triage-lens
```

### Installing from source

Only needed to try changes that are not released yet.

```bash
git clone https://github.com/secleeman/triage-lens.git
cd triage-lens
python -m venv .venv
.venv/bin/pip install .
```

On Windows (PowerShell), replace the last line with:

```bash
.venv\Scripts\pip install .
```

## Usage

### 1. Scan and write JSON

Trivy JSON:

```bash
trivy image --format json -o trivy-result.json sample-app:1.4.0
```

CycloneDX (SBOM):

```bash
trivy image --format cyclonedx -o sbom.cdx.json sample-app:1.4.0
```

#### Producing the input file on Windows

The Windows binaries Trivy ships are **not code-signed**. Where Smart App Control or
SmartScreen is enabled, running them may be blocked. That comes from how Trivy is
distributed; triage-lens cannot work around it.

You do not need to turn any security feature off. Any of these produces a usable input:

| Route | Example |
| --- | --- |
| Trivy under WSL | `wsl trivy fs . --format json -o result.json` |
| Trivy via Docker Desktop | `docker run --rm -v "%cd%:/src" aquasec/trivy fs /src --format json -o /src/result.json` |
| osv-scanner CycloneDX output | `osv-scanner --format cyclonedx-1-5 -L package-lock.json > sbom.cdx.json` |

When writing from WSL or Docker, **write to a path Windows can read** (`/mnt/c/...`
under WSL, or the mounted directory under Docker).

**Do not pass `npm sbom` output straight through.**

```bash
npm sbom --sbom-format cyclonedx > sbom.cdx.json   # this is not a vulnerability list
```

`npm sbom` emits **a component list only** — it has no `vulnerabilities` section. Passing
it to triage-lens produces a report with zero findings, which means **there was nothing to
assess**, not that the project is clean. Detecting vulnerabilities is the scanner's job.

The `npm audit --json` format is not supported.

### 2. Build the triage report

```bash
triage-lens report trivy-result.json --lang en -o triage-report.md
```

The same command works for CycloneDX — the format is detected automatically.

```bash
triage-lens report sbom.cdx.json --lang en -o triage-report.md
```

Without `--lang en` the report is written in Japanese, which is the default.
Omit `-o` to print to standard output.

| Option | Description | Default |
| --- | --- | --- |
| `-o`, `--output` | Output Markdown file | standard output |
| `--top N` | How many P2 / P3 rows to show (P0 / P1 always show all) | 5 |
| `--lang {ja,en}` | Report language | `ja` (Japanese) |
| `--fail-on {p0,p1,p2,p3}` | Exit with code 1 when a finding at this rank or above exists | unset (always 0) |
| `--fail-on-fetch-error` | With `--fail-on`, exit with code 3 when external data could not be fetched | off |
| `--ai` | Add AI-generated remediation notes | off |
| `--ai-limit N` | Maximum number of findings to annotate | 50 |
| `--ai-model NAME` | Model used for the notes | `claude-haiku-4-5` |

`--lang` controls the report body only. Error messages and `--help` text are in Japanese.

### 3. Stop the build on serious findings (`--fail-on`)

```bash
triage-lens report trivy-result.json --lang en -o triage-report.md --fail-on p1
```

Exits with code 1 when at least one finding sits at the given rank **or above**.
`p1` covers P0 and P1. `p3` is the lowest rank, so it effectively means
"fail if there is any finding at all".

- **The report is always written, including when the command fails.** The verdict is
  decided after the report has been written out, so you never lose the one document
  that explains why the build went red
- **`--top` does not affect the verdict.** It only limits how many rows are shown;
  every finding is considered
- A failed `--ai` run does not change the verdict either

#### When external data could not be fetched

If EPSS or the CISA KEV catalog cannot be fetched, **the verdict becomes more lenient
than it should be**. Without KEV, findings that would be P0 on the strength of their
KEV listing drop to P2 or P3.

triage-lens writes a warning to standard error in that case but **does not change the
exit code** — a brief outage at an upstream service should not turn the build red
every time.

Pass `--fail-on-fetch-error` if you want it to. The command then exits with code 3
when the fetch failed.

```bash
triage-lens report trivy-result.json -o triage-report.md --fail-on p1 --fail-on-fetch-error
```

"The data could not be fetched" and "there is a matching finding" are different
situations, so they get different exit codes. When both happen, 3 wins.

## Using it in GitHub Actions

A composite action is available for CI. **It does not run the scanner** — pass it the
JSON that an earlier step produced.

```yaml
name: Vulnerability triage

on: [pull_request]

jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy.json

      - name: Build the triage report
        uses: secleeman/triage-lens@v0.6.0
        with:
          scan-file: trivy.json
          lang: en
          fail-on: p1

      - name: Keep the report
        if: always()          # keep it even when fail-on fails the job
        uses: actions/upload-artifact@v4
        with:
          name: triage-report
          path: triage-report.md
```

### Inputs

| Name | Required | Default | Description |
| --- | --- | --- | --- |
| `scan-file` | ✅ | — | Path to the scanner output JSON (format detected automatically) |
| `lang` | | `ja` | Report language (`ja` / `en`) |
| `fail-on` | | empty (never fails) | `p0` / `p1` / `p2` / `p3` |
| `fail-on-fetch-error` | | `false` | `true` exits with code 3 when the fetch failed |
| `ai` | | `false` | `true` adds AI-generated remediation notes |
| `output` | | `triage-report.md` | Path of the generated Markdown report |

The only output is `report-path`, the path of the generated report.

### Things worth knowing

- **Pin `uses:` to a `@vX.Y.Z` tag.** There is no moving `@v1` tag on purpose: the
  contents of a security tool should not change without you noticing
- **`ubuntu-latest` is the only runner this is tested on.**
- **Add `if: always()` so the report survives.** Without it you lose the report
  exactly when `fail-on` fails the job
- **Leave `ai` at `false` unless you mean it.** Running it on every pull request adds
  up in API charges. Limit it to manual runs or pushes to main, and pass the key
  through `env` rather than `with` — keys in `with` tend to end up hardcoded in the
  workflow file

```yaml
      - name: Build the triage report
        uses: secleeman/triage-lens@v0.6.0
        with:
          scan-file: trivy.json
          ai: 'true'
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

## AI-generated remediation notes (`--ai`)

A priority tells you what to fix first. It does not tell you what to do about it.
This option asks the Claude API to write one or two lines per finding and puts them
in the report.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
triage-lens report trivy-result.json --ai --lang en -o triage-report.md
```

The notes appear underneath each rank's table:

```markdown
### Suggested next steps (AI-generated)

- **CVE-2021-44228** (log4j-core): Upgrade to 2.15.0. ...
```

### Prerequisites

- **The key is read from the environment.** There is no command-line flag for it,
  because that would leave the key in shell history, `ps` output, and CI logs
- **If the key is not set, the feature simply does not run.** It is not an error:
  one line goes to standard error and the report is produced as usual
- Identity-linked keys (issued by organisation accounts) also need a workspace id

| Environment variable | Required | Purpose |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | Yes, to use `--ai` | Claude API key |
| `ANTHROPIC_WORKSPACE_ID` | Only for organisation keys | Workspace the usage is billed to |

### The AI does not decide the priority

**P0-P3 are derived mechanically from public data (KEV / EPSS / CVSS) only.**
The model never assigns or revises a priority. It only writes what to do about a
finding whose priority has already been decided.

The notes are reference information. The report says so at the end, together with
the model that produced them.

### What is sent to Anthropic

The payload is fixed and minimal.

| Field | Sent |
| --- | --- |
| CVE ID | Yes |
| Package name | Yes |
| Installed / fixed version | Yes |
| CVSS / EPSS / KEV listing | Yes |
| Priority rank (P0-P3) | Yes |
| **Location (file path / purl)** | **No** |
| **Target name (project or image name)** | **No** |
| The input file itself | No |

Location and target name are withheld because they would reveal how your systems
are put together.

### Cost

You pay for it, so the tool tries not to spend more than it needs to.

- **Only P0 and P1 findings** are annotated - those are the ranks shown in full
- **At most 50 findings** by default (`--ai-limit` changes this)
- Findings are sent **20 at a time**, never one request per finding
- Identical payloads are requested **once** and reused, so the same CVE found in
  several places is billed once

With the default `claude-haiku-4-5`, annotating 50 findings costs a few cents.

### When it does not work

**The report is always produced and the exit code stays 0.** You lose the notes,
not the triage.

| What happened | Result |
| --- | --- |
| No API key set | Skipped without any request; one line on standard error |
| Invalid key or no permission | Report produced without notes |
| Rate limited | Waits per `retry-after`, then gives up on that batch |
| Cannot connect / malformed response | Same as above |
| Only some findings annotated | Whatever came back is used |

The whole AI step is time-limited so a struggling API cannot make the command hang.

## Example output

```markdown
# Vulnerability Triage Report

- Target: sample-app:1.4.0
- Generated: 2026-08-29 03:00
- Criteria: listed in CISA KEV / EPSS >= 0.1 / CVSS >= 7.0

## Summary

Total findings: 13

| Priority | Count | Action |
| --- | --- | --- |
| P0 (Act now) | 4 | Patch immediately |
| P1 (High) | 3 | Fix soon |
| P2 (Medium) | 4 | Plan a fix |
| P3 (Low) | 2 | Monitor |

## P0 (Act now) - Patch immediately (4 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-44228 | log4j-core | app/requirements.txt | 2.14.1 -> 2.15.0 | 10.0 | 1.000 | Yes | Listed in CISA KEV - exploitation observed in the wild |
| CVE-2014-0160 | openssl | app/requirements.txt | 1.0.1e-2 -> 1.0.1g-1 | 7.5 | 1.000 | Yes | Listed in CISA KEV - exploitation observed in the wild |
```

(The full report continues with P1–P3 and an explanation of how priorities are assigned.)

## How priorities are assigned

| Priority | Condition | Meaning |
| --- | --- | --- |
| P0 (Act now) | Listed in CISA KEV | Being exploited in the wild. Patch immediately |
| P1 (High) | EPSS >= 0.1 **and** CVSS >= 7.0 | Likely to be exploited, and severe |
| P2 (Medium) | EPSS >= 0.1 **or** CVSS >= 7.0 (only one) | One of the two is high |
| P3 (Low) | None of the above | Monitor |

Within a rank, findings are sorted by **EPSS descending, then CVSS descending**.
Findings with unknown values come last within their rank.

The same CVE stays on separate rows when the location, package, or version differs.
If the same CVE is found both in an OS package and in an application dependency,
both need fixing. Only completely identical findings are de-duplicated.

When identical findings appear more than once (for example after merging SBOMs) and
their values disagree, they are combined as follows.

| Field | How it is combined |
| --- | --- |
| CVSS | The **higher score wins** (keeping the lower one would make the finding look safer than it is) |
| Fixed version | A known version beats "Unknown". If both are known and differ, the **newer** one wins. If the two cannot be compared, it falls back to "Unknown" |

Version comparison only applies to plain numeric forms such as `1.2.10`.
Forms like `1:1.2.11.dfsg-2+deb11u2` or `>=1.0.1g-1` are not compared — guessing at their
ordering could point you at the wrong fix — so they report "Unknown" instead.

When EPSS or KEV data cannot be fetched, the reason column says so explicitly
(for example "exploitation probability is unknown"). A value that could not be
fetched is never reported as "low".

The thresholds (0.1 / 7.0) live in
[`src/triage_lens/scoring.py`](src/triage_lens/scoring.py) as
`EPSS_THRESHOLD` / `CVSS_THRESHOLD`.

## "No fix available" vs "Unknown"

The fixed-version column has three possible forms.

| Shown | Meaning |
| --- | --- |
| `1.0.0 -> 1.0.1` | A fix is available |
| `1.0.0 -> No fix available` | No fix has been released yet |
| `1.0.0 -> Unknown` | The input file does not say whether a fix exists |

In Trivy JSON, a missing fixed version means there is no fix, so it is reported as
"No fix available". CycloneDX has no field that states the *absence* of a fix, so when
no fix can be read from it, triage-lens reports "Unknown" rather than asserting there is none.

## How CycloneDX fields are mapped

| Report column | Taken from |
| --- | --- |
| Target | `metadata.component` `name` (+ `version`), else `purl` |
| CVE | `vulnerabilities[].id` |
| Package | `name` of the component resolved from `affects[].ref` |
| Installed | Component `version`, else the `affected` entry in `affects[].versions[]` |
| Fixed | The `unaffected` entry in `affects[].versions[]` |
| Location | Component `purl`, else `bom-ref`, else the target name |
| CVSS | `ratings[].score` |

- When one vulnerability affects several components, it becomes **one row per component**
- CVSS prefers the current generation (CVSSv3 / CVSSv31 / CVSSv4) and falls back to CVSSv2.
  Within the same generation, an NVD score wins
- Scores with no `method`, or with a non-CVSS method (`other` / `OWASP` / `SSVC`), are
  **not treated as CVSS** and show as "Unknown". Mixing different scales would be misleading
- A vulnerability referencing a component that is not in the SBOM still gets a row
  (the package name shows as "(unknown)")

## Runtime vs development dependencies

When the input carries that information, findings are split into **two tables — runtime
dependencies and development-only dependencies**. The summary gains a "Runtime" column.

```
| Priority | Count | Runtime | Action |
| P2 (Medium) | 17 | 3 | Plan a fix |
```

**Priorities (P0-P3) are unaffected.** A development-only finding is not downgraded, and
it is not excluded from `--fail-on`. Only the grouping of the tables changes.

### What the distinction is read from

From a CycloneDX SBOM, in this order:

| Signal | Result |
| --- | --- |
| `properties[]` has `cdx:npm:package:development` set to `"true"` | Development-only |
| `scope` is `excluded` | Development-only |
| `scope` is `required` / `optional` / absent | Runtime |
| The component is not in the SBOM | Runtime |

- **`scope: optional` counts as runtime.** npm sets it on optionalDependencies. It means
  "optional at runtime", not "for development" — something that may well run in production
  should not be hidden in the development-only table
- **`properties` are checked first.** npm's own `npm sbom` puts `scope: required` on
  development dependencies too, and marks dev through a property instead. Reading `scope`
  alone would find no distinction at all in an npm SBOM
- When in doubt, findings fall to **runtime**. Putting a runtime package in the
  development-only table hides it; the reverse only makes the list longer

### When there are no development-only findings

If the distinction is available but no finding lands in development-only, the report is
**not split** — a row of empty "Development-only dependencies (0 total)" headings under
every rank helps no one. The summary carries one line instead.

```
Total findings: 8
Development-only findings: 0 (every finding is a runtime dependency)
```

Note that **a zero runtime count keeps the split**. "Runtime dependencies (0 total)" is
exactly the thing worth showing, so that table stays.

### When the input cannot distinguish them

If the input carries no such signal at all, findings are listed together as before, and
the report says so in one line near the top.

> This input carries no information distinguishing runtime from development dependencies,
> so all findings are listed together.

Both cases yield a single table, but they are **worded differently** — "nothing to tell it
from" is a note at the top, "told apart, and none were development-only" is a line in the
summary.

By spec, an absent `scope` means `required` — so reading a silent SBOM literally would
make every finding look like a runtime dependency. The note keeps **"we can tell" and
"we have nothing to tell it from"** apart.

**Trivy JSON cannot distinguish them.** Trivy findings
(`Results[].Vulnerabilities[]`) carry no runtime/development field, and triage-lens does
not guess. (Trivy also excludes development dependencies from scans by default.)

## Recommended actions

The report ends with a table that **groups findings by package**. One package may appear
under five CVEs, but the actual work is a single upgrade.

```
| Package | Installed | Upgrade to | CVEs resolved | Highest priority |
| lodash | 4.17.15 | 4.17.21 | 2 | P1 (High) |
| apt | 2.2.4 | No fix available | 0 | P3 (Low) |
```

- **No AI involved.** The table appears without `--ai`, and `--ai` does not change it
- **`--top` does not apply.** Findings hidden by the display limit are still aggregated.
  Dropping them would understate the resolved count and make an upgrade look pointless
- The same package at **a different installed version gets its own row** (the upgrade
  target differs). The same version found in several places collapses into one row
- The upgrade target is the **highest of the fix versions that can be compared reliably**.
  If versions like `1:1.2.11.dfsg-2+deb11u2` are mixed in, it shows "Unknown" — guessing
  the ordering could point you at a downgrade
- **Packages with no determinable target are still listed.** They show "No fix available"
  or "Unknown" and sort last, so "absent from the table" never reads as "nothing to do"

## What this report cannot tell you

Every report ends with this note:

> These priorities are based on whether an affected version is present in your
> dependencies. Whether the affected code is actually used, or reachable from outside,
> is not assessed - the real impact may be smaller or larger than shown here.

triage-lens only looks at **whether an affected version is in your dependency tree**.
It performs no reachability analysis.

## How external data is handled

- **KEV catalog**: cached at `~/.cache/triage-lens/kev.json` and not refetched for 24 hours.
- **EPSS**: queried in batches of 100 CVEs, never one at a time.
- **On failure**: up to 3 attempts with a 1s → 2s backoff. If it still fails,
  the report says so at the top and **continues with the data that is available**.
  If refreshing KEV fails, an expired cache is used when one exists.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (including a partial report when external data could not be fetched) |
| 1 | A finding at or above the `--fail-on` rank exists |
| 2 | Input error (missing file / broken JSON / unsupported format / bad option) |
| 3 | `--fail-on-fetch-error` was set and external data could not be fetched |

1 and 3 are only ever returned when `--fail-on` is set. Without it, a run that
completes still exits 0, as before.

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check .
```

Tests never reach the network — every external call is mocked.
GitHub Actions runs the tests and lint on Python 3.11 / 3.12 / 3.13 for every push
and pull request.

## What this version (v0.6.0) can and cannot do

It can:

- Read Trivy JSON output
- Read CycloneDX (JSON) SBOMs, with automatic format detection
- Prioritise using EPSS and CISA KEV
- Produce Markdown reports in Japanese and English
- Add AI-generated remediation notes (`--ai`, only when an API key is set)
- Fail the build on serious findings (`--fail-on`)
- Run inside GitHub Actions as a composite action
- **Split runtime and development-only dependencies** when the input says which is which
- **Recommend actions per package** - what to upgrade, how far, and how much it clears

It cannot yet (planned for later phases):

- Read SPDX input
- Read the XML representation of CycloneDX
- Read `npm audit --json` or OSV format natively
- **Perform reachability analysis** (whether the affected code is actually called)
- Tell runtime from development dependencies in Trivy JSON (that output carries no such field)
- Show error messages and `--help` in English
- Produce reports in languages other than Japanese and English
- Use a config file or a web UI
- Have the AI produce patches or open fix pull requests

## Bug reports

Bug reports are welcome via [GitHub Issues](https://github.com/secleeman/triage-lens/issues). Including the input
format, the command you ran, and the message you saw makes them easier to act on.

**We do not reply in the issue threads.** Every report is read, and the response
arrives as a fix in a commit and in the release notes
([ROADMAP](https://github.com/secleeman/triage-lens/blob/main/docs/ROADMAP.md)). An issue may be closed without a
comment once it has been addressed.

## License

MIT License. See [LICENSE](https://github.com/secleeman/triage-lens/blob/main/LICENSE) for details.
