# triage-lens

A CLI tool that takes a scanner's vulnerability list, prioritises it using public data,
and produces a **triage report (Markdown) that tells you what to fix first**.

*日本語: [README.md](README.md)*

What the priority is based on:

| Data | What it tells you | Source |
| --- | --- | --- |
| CISA KEV | Whether exploitation has actually been observed | CISA public catalog |
| EPSS | Probability of exploitation in the next 30 days (0–1) | FIRST.org public API |
| CVSS | Severity score (0–10) | Value reported by the scanner |

None of these require an API key.

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

`--lang` controls the report body only. Error messages and `--help` text are in Japanese.

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
| 2 | Input error (missing file / broken JSON / unsupported format / bad option) |

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check .
```

Tests never reach the network — every external call is mocked.
GitHub Actions runs the tests and lint on Python 3.11 / 3.12 / 3.13 for every push
and pull request.

## What this version (Phase 2) can and cannot do

It can:

- Read Trivy JSON output
- Read CycloneDX (JSON) SBOMs, with automatic format detection
- Prioritise using EPSS and CISA KEV
- Produce Markdown reports in Japanese and English

It cannot yet (planned for later phases):

- Read SPDX input
- Read the XML representation of CycloneDX
- Show error messages and `--help` in English
- Produce reports in languages other than Japanese and English
- Use a config file or a web UI

## License

MIT License. See [LICENSE](LICENSE) for details.
