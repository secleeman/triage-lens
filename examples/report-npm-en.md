# Vulnerability Triage Report

- Target: demo-shop@1.0.0
- Generated: 2026-08-30 09:40
- Criteria: listed in CISA KEV / EPSS >= 0.1 / CVSS >= 7.0

## Summary

Total findings: 8

| Priority | Count | Runtime | Action |
| --- | --- | --- | --- |
| P0 (Act now) | 0 | 0 | Patch immediately |
| P1 (High) | 2 | 1 | Fix soon |
| P2 (Medium) | 4 | 3 | Plan a fix |
| P3 (Low) | 2 | 1 | Monitor |

## P0 (Act now) - Patch immediately (0 total)

### Runtime dependencies (0 total)

None.

### Development-only dependencies (0 total)

None.

## P1 (High) - Fix soon (2 total)

### Runtime dependencies (1 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-23337 | lodash | pkg:npm/lodash@4.17.15 | 4.17.15 -> 4.17.21 | 7.2 | 0.213 | No | High exploitation probability (EPSS 0.213) and high severity (CVSS 7.2) |

### Development-only dependencies (1 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2022-29078 | ejs | pkg:npm/ejs@3.1.6 | 3.1.6 -> 3.1.7 | 9.8 | 0.328 | No | High exploitation probability (EPSS 0.328) and high severity (CVSS 9.8) |

## P2 (Medium) - Plan a fix (4 total)

### Runtime dependencies (3 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-3749 | axios | pkg:npm/axios@0.21.0 | 0.21.0 -> 0.21.2 | 7.5 | 0.085 | No | Severity is high (CVSS 7.5), but exploitation probability is low (EPSS 0.085) |
| CVE-2020-8203 | lodash | pkg:npm/lodash@4.17.15 | 4.17.15 -> 4.17.20 | 7.4 | 0.052 | No | Severity is high (CVSS 7.4), but exploitation probability is low (EPSS 0.052) |
| CVE-2021-37713 | tar | pkg:npm/tar@6.1.0 | 6.1.0 -> 6.1.9 | 8.2 | 0.013 | No | Severity is high (CVSS 8.2), but exploitation probability is low (EPSS 0.013) |

### Development-only dependencies (1 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-44906 | minimist | pkg:npm/minimist@1.2.0 | 1.2.0 -> 1.2.6 | 9.8 | 0.046 | No | Severity is high (CVSS 9.8), but exploitation probability is low (EPSS 0.046) |

## P3 (Low) - Monitor (2 total)

### Runtime dependencies (1 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2020-28168 | axios | pkg:npm/axios@0.21.0 | 0.21.0 -> 0.21.1 | 5.9 | 0.023 | No | Does not meet the high-risk criteria: exploitation probability is low, severity is medium or lower (EPSS 0.023 / CVSS 5.9) |

### Development-only dependencies (1 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2020-7598 | minimist | pkg:npm/minimist@1.2.0 | 1.2.0 -> 1.2.3 | 5.6 | 0.019 | No | Does not meet the high-risk criteria: exploitation probability is low, severity is medium or lower (EPSS 0.019 / CVSS 5.6) |

## Recommended actions

Findings grouped by package. This table covers every finding, regardless of the display limit (--top).

### Runtime dependencies (3 total)

| Package | Installed | Upgrade to | CVEs resolved | Highest priority |
| --- | --- | --- | --- | --- |
| lodash | 4.17.15 | 4.17.21 | 2 | P1 (High) |
| axios | 0.21.0 | 0.21.2 | 2 | P2 (Medium) |
| tar | 6.1.0 | 6.1.9 | 1 | P2 (Medium) |

### Development-only dependencies (2 total)

| Package | Installed | Upgrade to | CVEs resolved | Highest priority |
| --- | --- | --- | --- | --- |
| ejs | 3.1.6 | 3.1.7 | 1 | P1 (High) |
| minimist | 1.2.0 | 1.2.6 | 2 | P2 (Medium) |

## How priorities are assigned

| Priority | Condition |
| --- | --- |
| P0 (Act now) | Listed in CISA KEV - exploitation has been observed in the wild |
| P1 (High) | EPSS >= 0.1 AND CVSS >= 7.0 |
| P2 (Medium) | EPSS >= 0.1 OR CVSS >= 7.0 (only one of the two) |
| P3 (Low) | None of the above |

Within a rank, findings are sorted by EPSS descending, then CVSS descending.

Sources: CISA KEV catalog / FIRST.org EPSS / CVSS as reported by the scanner.

These priorities are based on whether an affected version is present in your dependencies. Whether the affected code is actually used, or reachable from outside, is not assessed - the real impact may be smaller or larger than shown here.
