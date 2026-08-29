# Vulnerability Triage Report

- Target: sample-app:1.4.0
- Generated: 2026-08-29 23:04
- Criteria: listed in CISA KEV / EPSS >= 0.1 / CVSS >= 7.0

## Summary

Total findings: 14

| Priority | Count | Action |
| --- | --- | --- |
| P0 (Act now) | 3 | Patch immediately |
| P1 (High) | 3 | Fix soon |
| P2 (Medium) | 5 | Plan a fix |
| P3 (Low) | 3 | Monitor |

## P0 (Act now) - Patch immediately (3 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2021-44228 | org.apache.logging.log4j:log4j-core | app/pom.xml | 2.14.1 -> 2.15.0 | 10.0 | 1.000 | Yes | Listed in CISA KEV - exploitation observed in the wild |
| CVE-2023-4863 | libwebp6 | sample-app:1.4.0 (debian 11.9) | 0.6.1-2.1 -> 0.6.1-2.1+deb11u1 | 8.8 | 1.000 | Yes | Listed in CISA KEV - exploitation observed in the wild |
| CVE-2022-22965 | org.springframework:spring-beans | app/pom.xml | 5.3.13 -> 5.3.18 | 9.8 | 0.996 | Yes | Listed in CISA KEV - exploitation observed in the wild |

## P1 (High) - Fix soon (3 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2023-38545 | curl | sample-app:1.4.0 (debian 11.9) | 7.74.0-1.3 -> 7.74.0-1.3+deb11u10 | 9.8 | 0.785 | No | High exploitation probability (EPSS 0.785) and high severity (CVSS 9.8) |
| CVE-2021-23017 | nginx | sample-app:1.4.0 (debian 11.9) | 1.18.0-6.1 -> 1.18.0-6.1+deb11u2 | 9.4 | 0.535 | No | High exploitation probability (EPSS 0.535) and high severity (CVSS 9.4) |
| CVE-2022-37434 | zlib1g | sample-app:1.4.0 (debian 11.9) | 1:1.2.11.dfsg-2 -> 1:1.2.11.dfsg-2+deb11u2 | 9.8 | 0.179 | No | High exploitation probability (EPSS 0.179) and high severity (CVSS 9.8) |

## P2 (Medium) - Plan a fix (5 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2019-11358 | jquery | app/package-lock.json | 3.3.1 -> 3.4.0 | 6.1 | 0.872 | No | Exploitation probability is high (EPSS 0.872), but severity is medium or lower (CVSS 6.1) |
| CVE-2020-14343 | PyYAML | app/requirements.txt | 5.3.1 -> 5.4 | 9.8 | 0.060 | No | Severity is high (CVSS 9.8), but exploitation probability is low (EPSS 0.060) |
| CVE-2020-8203 | lodash | app/package-lock.json | 4.17.15 -> 4.17.20 | 7.4 | 0.052 | No | Severity is high (CVSS 7.4), but exploitation probability is low (EPSS 0.052) |
| CVE-2021-33503 | urllib3 | app/requirements.txt | 1.26.4 -> 1.26.5 | 7.5 | 0.033 | No | Severity is high (CVSS 7.5), but exploitation probability is low (EPSS 0.033) |
| CVE-2021-33503 | urllib3 | worker/requirements.txt | 1.26.4 -> 1.26.5 | 7.5 | 0.033 | No | Severity is high (CVSS 7.5), but exploitation probability is low (EPSS 0.033) |

## P3 (Low) - Monitor (3 total)

| CVE | Package | Location | Installed -> Fixed | CVSS | EPSS | KEV | Why |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CVE-2022-40897 | setuptools | app/requirements.txt | 65.3.0 -> 65.5.1 | 5.9 | 0.026 | No | Does not meet the high-risk criteria: exploitation probability is low, severity is medium or lower (EPSS 0.026 / CVSS 5.9) |
| CVE-2011-3374 | apt | sample-app:1.4.0 (debian 11.9) | 2.2.4 -> No fix available | 3.7 | 0.012 | No | Does not meet the high-risk criteria: exploitation probability is low, severity is medium or lower (EPSS 0.012 / CVSS 3.7) |
| CVE-2023-45803 | urllib3 | app/requirements.txt | 1.26.4 -> 1.26.18 | 4.2 | 0.005 | No | Does not meet the high-risk criteria: exploitation probability is low, severity is medium or lower (EPSS 0.005 / CVSS 4.2) |

## How priorities are assigned

| Priority | Condition |
| --- | --- |
| P0 (Act now) | Listed in CISA KEV - exploitation has been observed in the wild |
| P1 (High) | EPSS >= 0.1 AND CVSS >= 7.0 |
| P2 (Medium) | EPSS >= 0.1 OR CVSS >= 7.0 (only one of the two) |
| P3 (Low) | None of the above |

Within a rank, findings are sorted by EPSS descending, then CVSS descending.

Sources: CISA KEV catalog / FIRST.org EPSS / CVSS as reported by the scanner.
