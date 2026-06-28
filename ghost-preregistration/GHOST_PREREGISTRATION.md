# Ghost CMS Vulnerability Pre-Registration
## SBOM-Driven LLM-Assisted Dependency Remediation — Master's Thesis

**Application:** Ghost CMS v5.76.0  
**Thesis:** Context-Aware Dependency Remediation in SBOM-Driven CI/CD Pipelines Using Large Language Models  
**Author:** Santosh Nagaraj — SRH University Berlin  
**Date of scan and data snapshot:** 2026-06-28  
**Tools:** Syft v1.44.0 · Grype v0.112.0 · Python 3.x

---

## What This Document Is

This README records every step taken to arrive at the 6 pre-registered vulnerability scenarios for Ghost CMS v5.76.0. It follows the same process established for Juice Shop. It exists so that:

1. The supervisor can verify the selection was not arbitrary
2. The process is reproducible and consistent across all three applications
3. All scripts and API results are preserved alongside the rationale

---

## Prerequisites

```bash
syft version       # must show v1.44.0
grype version      # must show v0.112.0
python3 --version  # any 3.x is fine
```

Ghost must be cloned at exactly v5.76.0:

```bash
git clone https://github.com/TryGhost/Ghost.git
cd Ghost
git checkout v5.76.0
```

---

## Step 1 — Generate the SBOM

```bash
# Run from inside the Ghost directory
syft dir:. -o spdx-json --file ghost-sbom.spdx.json
```

**Verify the SBOM captured npm packages:**

```bash
python3 -c "
import json
with open('ghost-sbom.spdx.json') as f:
    data = json.load(f)
pkgs = data.get('packages', data.get('artifacts', []))
print(f'Total packages: {len(pkgs)}')
for p in pkgs[:5]:
    print(p.get('name'), p.get('version', p.get('versionInfo')))
"
```

---

## Step 2 — Run Grype Vulnerability Scan

```bash
grype sbom:ghost-sbom.spdx.json -o json --file ghost-grype.json
```

**Verify the scan captured npm-level vulnerabilities:**

```bash
python3 -c "
import json
with open('ghost-grype.json') as f:
    data = json.load(f)
matches = data.get('matches', [])
print(f'Total matches: {len(matches)}')
npm_matches = [m for m in matches if m['artifact']['type'] in ['npm', 'node-module', 'javascript']]
print(f'npm matches: {len(npm_matches)}')
for m in npm_matches[:10]:
    vuln = m['vulnerability']
    fix = vuln.get('fix', {}).get('versions', [])
    print(f\"{vuln['id']} | {m['artifact']['name']} {m['artifact']['version']} | fix: {fix} | {vuln.get('severity','?')}\")
"
```

**Results:** 286 total matches, all 286 npm matches (no OS packages — Ghost scanned cleanly as a pure npm project).

---

## Step 3 — Filter to Usable Candidates

Same filter rules as Juice Shop:

- Exclude OS packages and runtime packages
- Exclude packages where fix version does not exist on npm
- Require High or Critical severity
- Deduplicate by package+CVE

**Filter script (`trim_npm.py`):**

```python
import json

EXCLUDE_TYPES = {'deb', 'UnknownPackage'}
EXCLUDE_PKGS = {
    'node', 'libc6', 'libssl1.1', 'openssl',
    'libgcc-s1', 'libgomp1', 'libstdc++6'
}

with open('ghost-grype.json') as f:
    data = json.load(f)

seen = {}
for m in data['matches']:
    art = m['artifact']
    vuln = m['vulnerability']

    if art['type'] in EXCLUDE_TYPES:
        continue
    if art['name'] in EXCLUDE_PKGS:
        continue

    fix_versions = vuln.get('fix', {}).get('versions', [])
    if not fix_versions:
        continue

    severity = vuln.get('severity', '')
    if severity not in ['High', 'Critical']:
        continue

    pkg = art['name']
    vid = vuln['id']
    key = f'{pkg}:{vid}'

    if key not in seen:
        seen[key] = {
            'id': vid,
            'package': pkg,
            'current_version': art['version'],
            'fix_version': fix_versions[0],
            'severity': severity,
            'type': art['type']
        }

for k, v in seen.items():
    print(f"{v['severity']:8} | {v['package']:30} {v['current_version']:15} -> {v['fix_version']:15} | {v['id']}")
```

```bash
python3 trim_npm.py
```

---

## Step 4 — Map GHSA IDs to CVE IDs

Grype reports vulnerabilities using GHSA IDs. CVE IDs are required for NVD verification.

**Additional disqualification applied before mapping:**

`lodash-es` and `lodash.template` both listed fix version `4.18.0` via `GHSA-r5fr-rjxr-66jc`. This version does not exist on npm (lodash latest is 4.17.21). Both disqualified before proceeding.

```python
# save as get_cve_mappings_ghost.py
import urllib.request, json, time

candidates = [
    ('growl', 'GHSA-qh2h-chj9-jffq'),
    ('underscore', 'GHSA-cf4h-3jhx-xvhq'),
    ('mysql2', 'GHSA-fpw7-j2hg-69v5'),
    ('mysql2', 'GHSA-pmh2-wpjm-fj45'),
    ('handlebars', 'GHSA-2w6w-674q-4c4q'),
    ('protobufjs', 'GHSA-xq3m-2v4x-88gg'),
    ('elliptic', 'GHSA-vjh7-7g9h-fjfh'),
    ('sha.js', 'GHSA-95m3-7q98-8xr5'),
    ('cipher-base', 'GHSA-cpq7-6gpm-g9rc'),
    ('pbkdf2', 'GHSA-v62p-rq8g-8h59'),
    ('fast-xml-parser', 'GHSA-m7jm-9gc2-mpf2'),
    ('knex', 'GHSA-4jv9-3563-23j3'),
    ('jsonwebtoken', 'GHSA-8cf7-32gw-wr33'),
    ('vitest', 'GHSA-5xrq-8626-4rwp'),
    ('nth-check', 'GHSA-rp65-9cf3-cjxr'),
]

for pkg, ghsa in candidates:
    time.sleep(1)
    try:
        url = f'https://api.osv.dev/v1/vulns/{ghsa}'
        resp = urllib.request.urlopen(url, timeout=5)
        data = json.loads(resp.read())
        aliases = data.get('aliases', [])
        cves = [a for a in aliases if a.startswith('CVE')]
        print(f'{ghsa} | {pkg:20} | CVE: {cves}')
    except Exception as e:
        print(f'{ghsa} | {pkg:20} | ERROR: {e}')
```

```bash
python3 get_cve_mappings_ghost.py
```

**Results (2026-06-28):**

| GHSA | Package | Mapped CVE | Decision |
|------|---------|------------|----------|
| GHSA-qh2h-chj9-jffq | growl | CVE-2017-16042 | Proceed |
| GHSA-cf4h-3jhx-xvhq | underscore | CVE-2021-23358 | Proceed |
| GHSA-fpw7-j2hg-69v5 | mysql2 | CVE-2024-21508 | Proceed |
| GHSA-pmh2-wpjm-fj45 | mysql2 | CVE-2024-21512 | Proceed |
| GHSA-2w6w-674q-4c4q | handlebars | CVE-2026-33937 | Proceed |
| GHSA-xq3m-2v4x-88gg | protobufjs | CVE-2026-41242 | Proceed |
| GHSA-vjh7-7g9h-fjfh | elliptic | (none) | **DISQUALIFIED — no CVE mapping** |
| GHSA-95m3-7q98-8xr5 | sha.js | CVE-2025-9288 | Proceed |
| GHSA-cpq7-6gpm-g9rc | cipher-base | CVE-2025-9287 | Proceed |
| GHSA-v62p-rq8g-8h59 | pbkdf2 | CVE-2025-6547 | Proceed |
| GHSA-m7jm-9gc2-mpf2 | fast-xml-parser | CVE-2026-25896 | Proceed |
| GHSA-4jv9-3563-23j3 | knex | CVE-2016-20018 | Proceed |
| GHSA-8cf7-32gw-wr33 | jsonwebtoken | CVE-2022-23539 | Proceed |
| GHSA-5xrq-8626-4rwp | vitest | CVE-2026-47429 | Proceed |
| GHSA-rp65-9cf3-cjxr | nth-check | CVE-2021-3803 | Proceed |

**elliptic disqualified** — GHSA-vjh7-7g9h-fjfh has no CVE alias in OSV. No CVE means no NVD verification is possible. Pre-registration requires NVD confirmation.

---

## Step 5 — Verify Fix Versions Exist on npm

```python
# save as verify_npm_versions_ghost.py
import urllib.request, json

checks = [
    ('growl', '1.10.0'),
    ('underscore', '1.12.1'),
    ('mysql2', '3.9.4'),
    ('mysql2', '3.9.8'),
    ('protobufjs', '7.5.5'),
    ('sha.js', '2.4.12'),
    ('cipher-base', '1.0.5'),
    ('pbkdf2', '3.1.3'),
    ('fast-xml-parser', '4.5.4'),
    ('knex', '2.4.0'),
    ('jsonwebtoken', '9.0.0'),
    ('vitest', '3.2.6'),
    ('nth-check', '2.0.1'),
    ('handlebars', '4.7.9'),
]

for pkg, fix_ver in checks:
    try:
        url = f'https://registry.npmjs.org/{pkg}/{fix_ver}'
        resp = urllib.request.urlopen(url, timeout=5)
        data = json.loads(resp.read())
        print(f'OK  | {pkg:25} {fix_ver}')
    except urllib.error.HTTPError as e:
        print(f'FAIL| {pkg:25} {fix_ver} -> HTTP {e.code}')
    except Exception as e:
        print(f'ERR | {pkg:25} {fix_ver} -> {e}')
```

```bash
python3 verify_npm_versions_ghost.py
```

**Results (2026-06-28):** All fix versions confirmed on npm registry.

---

## Step 6 — NVD Verification

```python
# save as nvd_verify_ghost.py
import urllib.request, json, time

cves = [
    ('growl', 'CVE-2017-16042'),
    ('underscore', 'CVE-2021-23358'),
    ('mysql2', 'CVE-2024-21508'),
    ('mysql2', 'CVE-2024-21512'),
    ('handlebars', 'CVE-2026-33937'),
    ('protobufjs', 'CVE-2026-41242'),
    ('sha.js', 'CVE-2025-9288'),
    ('cipher-base', 'CVE-2025-9287'),
    ('pbkdf2', 'CVE-2025-6547'),
    ('fast-xml-parser', 'CVE-2026-25896'),
    ('knex', 'CVE-2016-20018'),
    ('jsonwebtoken', 'CVE-2022-23539'),
    ('vitest', 'CVE-2026-47429'),
    ('nth-check', 'CVE-2021-3803'),
]

for pkg, cve in cves:
    time.sleep(6)
    try:
        url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'
        req = urllib.request.Request(url, headers={'User-Agent': 'thesis-research/1.0'})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        total = data.get('totalResults', 0)
        if total > 0:
            vuln = data['vulnerabilities'][0]['cve']
            cvss = 'N/A'
            metrics = vuln.get('metrics', {})
            for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if key in metrics:
                    cvss = metrics[key][0]['cvssData']['baseScore']
                    break
            status = vuln.get('vulnStatus', '?')
            print(f'FOUND | {cve:20} | {pkg:20} | CVSS: {cvss} | Status: {status}')
        else:
            print(f'NOT FOUND | {cve:20} | {pkg:20} | DISQUALIFIED')
    except Exception as e:
        print(f'ERROR | {cve:20} | {pkg:20} | {e}')
```

```bash
python3 nvd_verify_ghost.py
```

**Results (2026-06-28):**

| CVE | Package | CVSS | NVD Status | Decision |
|-----|---------|------|------------|----------|
| CVE-2017-16042 | growl | 9.8 | Modified | PASS |
| CVE-2021-23358 | underscore | 3.3 | Modified | **DROPPED — CVSS too low** |
| CVE-2024-21508 | mysql2 | 9.8 | Deferred | PASS |
| CVE-2024-21512 | mysql2 | 8.2 | Deferred | **DROPPED — package concentration** |
| CVE-2026-33937 | handlebars | 9.8 | Analyzed | PASS |
| CVE-2026-41242 | protobufjs | 9.8 | Analyzed | PASS |
| CVE-2025-9288 | sha.js | 9.1 | Modified | PASS |
| CVE-2025-9287 | cipher-base | 9.1 | Modified | PASS (not selected — redundant with sha.js) |
| CVE-2025-6547 | pbkdf2 | N/A | Deferred | **DROPPED — no CVSS score** |
| CVE-2026-25896 | fast-xml-parser | 9.3 | Analyzed | PASS (not selected) |
| CVE-2016-20018 | knex | 7.5 | Modified | PASS |
| CVE-2022-23539 | jsonwebtoken | 5.9 | Modified | **DROPPED — CVSS too low** |
| CVE-2026-47429 | vitest | — | NOT FOUND | **DISQUALIFIED** |
| CVE-2021-3803 | nth-check | 7.5 | Modified | PASS |

**Disqualification notes:**

- **CVE-2026-47429 (vitest)** — NOT FOUND in NVD. Hard disqualification.
- **CVE-2021-23358 (underscore)** — CVSS 3.3. Below threshold, dropped.
- **CVE-2022-23539 (jsonwebtoken)** — CVSS 5.9. Below threshold, dropped.
- **CVE-2025-6547 (pbkdf2)** — NVD status Deferred with no CVSS score. Unreliable for pre-registration, dropped.
- **CVE-2024-21512 (mysql2)** — Valid CVE but same package as CVE-2024-21508. Two scenarios on the same package version is a concentration problem. Higher CVSS (9.8 vs 8.2) takes priority, CVE-2024-21512 dropped.
- **cipher-base CVE-2025-9287** — Valid but functionally overlaps with sha.js (both are low-level cryptographic primitives, patch-level fixes). Dropped to maintain package diversity.

---

## Step 7 — Collect EPSS Scores

```python
# save as get_epss_ghost.py
import urllib.request, json, time

cves = [
    'CVE-2017-16042',
    'CVE-2024-21508',
    'CVE-2026-33937',
    'CVE-2026-41242',
    'CVE-2025-9288',
    'CVE-2016-20018',
    'CVE-2021-3803',
]

for cve in cves:
    time.sleep(2)
    try:
        url = f'https://api.first.org/data/v1/epss?cve={cve}'
        resp = urllib.request.urlopen(url, timeout=10)
        data = json.loads(resp.read())
        if data['data']:
            d = data['data'][0]
            print(f"{d['cve']:20} | EPSS: {float(d['epss']):.4f} | Percentile: {float(d['percentile']):.2f}")
        else:
            print(f'{cve:20} | NOT FOUND in EPSS')
    except Exception as e:
        print(f'{cve:20} | ERROR: {e}')
```

```bash
python3 get_epss_ghost.py
```

**Results (2026-06-28):**

| CVE | EPSS Score | Percentile |
|-----|------------|------------|
| CVE-2017-16042 | 0.0441 | 90th |
| CVE-2024-21508 | 0.0255 | 83rd |
| CVE-2026-33937 | 0.0129 | 67th |
| CVE-2026-41242 | 0.0057 | 43rd |
| CVE-2025-9288 | 0.0065 | 47th |
| CVE-2016-20018 | 0.0085 | 53rd |
| CVE-2021-3803 | 0.0201 | 78th |

---

## Step 8 — Check CISA KEV Status

```python
# save as check_kev_ghost.py
import urllib.request, json

url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
resp = urllib.request.urlopen(url, timeout=15)
data = json.loads(resp.read())

targets = {
    'CVE-2017-16042', 'CVE-2024-21508', 'CVE-2026-33937',
    'CVE-2026-41242', 'CVE-2025-9288', 'CVE-2016-20018', 'CVE-2021-3803'
}

found = set()
for v in data['vulnerabilities']:
    if v['cveID'] in targets:
        found.add(v['cveID'])
        print(f"KEV=TRUE  | {v['cveID']} | {v['vendorProject']} | {v['vulnerabilityName']}")

for cve in targets - found:
    print(f'KEV=FALSE | {cve}')
```

```bash
python3 check_kev_ghost.py
```

**Results (2026-06-28):** All 7 candidates returned KEV=FALSE. All 6 selected scenarios are KEV=FALSE.

**Protocol note:** Zero KEV-positive cases in Ghost is consistent with Juice Shop. KEV sub-question scoped to EPSS signal analysis per protocol.md.

---

## Final Pre-Registered Scenarios — Ghost CMS v5.76.0

All data snapshotted on 2026-06-28.

| ID | CVE | Package | Vuln Ver | Fix Ver | CVSS | EPSS | Percentile | KEV | Severity | Jump Type |
|----|-----|---------|----------|---------|------|------|------------|-----|----------|-----------|
| GH-01 | CVE-2017-16042 | growl | 1.9.2 | 1.10.0 | 9.8 | 0.0441 | 90th | No | Critical | Patch |
| GH-02 | CVE-2024-21508 | mysql2 | 3.2.0 | 3.9.4 | 9.8 | 0.0255 | 83rd | No | Critical | Minor |
| GH-03 | CVE-2026-41242 | protobufjs | 7.2.5 | 7.5.5 | 9.8 | 0.0057 | 43rd | No | Critical | Minor |
| GH-04 | CVE-2025-9288 | sha.js | 2.4.11 | 2.4.12 | 9.1 | 0.0065 | 47th | No | Critical | Patch |
| GH-05 | CVE-2016-20018 | knex | 0.20.15 | 2.4.0 | 7.5 | 0.0085 | 53rd | No | High | Major (0→2) |
| GH-06 | CVE-2021-3803 | nth-check | 1.0.2 | 2.0.1 | 7.5 | 0.0201 | 78th | No | High | Major (1→2) |

### Selection Rationale

**GH-01 growl** — CVSS 9.8, EPSS 90th percentile, highest exploitation probability in the Ghost pool. Patch-level fix (1.9.2→1.10.0), low remediation risk. Serves as the high-severity control scenario where both baseline and LLM should succeed. growl is a rarely discussed package — adds diversity to the overall scenario set.

**GH-02 mysql2** — CVSS 9.8, database driver vulnerability. Minor version jump (3.2→3.9). Database layer dependency not represented in Juice Shop scenarios. Only one mysql2 CVE selected despite two being available — CVE-2024-21512 dropped to avoid package concentration (same package, same vulnerable version, two scenarios would be scientifically redundant).

**GH-03 protobufjs** — CVSS 9.8, EPSS only 43rd percentile. Strongest CVSS vs low EPSS signal contrast in the Ghost pool — directly relevant to the research sub-question on whether CVSS-only prioritisation is sufficient. Minor version jump (7.2→7.5), low breaking change risk.

**GH-04 sha.js** — CVSS 9.1, cryptographic hashing library. Patch-level fix (2.4.11→2.4.12). Different from crypto-js in Juice Shop — sha.js is a lower-level primitive used in hashing pipelines. Low EPSS (47th) despite Critical CVSS — another signal contrast data point.

**GH-05 knex** — CVSS 7.5, SQL injection in query builder. Major version jump (0.20→2.4) across two major versions — significant API surface changes expected. Correct LLM output should flag migration risk and recommend testing rather than blindly applying the version bump.

**GH-06 nth-check** — CVSS 7.5, EPSS 78th percentile, ReDoS in CSS selector parsing. Major version jump (1→2). nth-check is a transitive dependency unlikely to appear in Ghost's direct dependency list. This tests whether the pipeline and LLM handle transitive dependency remediation correctly — an important practical edge case.

### Composition of the 6 Scenarios

- CVSS range: 9.8, 9.8, 9.8, 9.1, 7.5, 7.5
- Severity: 4 Critical, 2 High
- Jump type: 2 patch, 2 minor, 2 major
- Package categories: notification utility, database driver, serialisation, cryptographic hashing, SQL query builder, CSS selector parsing
- No package overlap within Ghost scenarios
- No CVE repeated from Juice Shop scenarios
- KEV: 0/6 — all KEV=FALSE
- All fix versions confirmed on npm registry 2026-06-28
- All CVEs confirmed in NVD 2026-06-28

---

## Files Produced

| File | Description |
|------|-------------|
| `ghost-sbom.spdx.json` | Syft SPDX-JSON SBOM |
| `ghost-grype.json` | Grype scan output, 286 matches, all npm |
| `trim_npm.py` | Filter script — reused from Juice Shop |
| `get_cve_mappings_ghost.py` | Maps GHSA IDs to CVE IDs via OSV API |
| `verify_npm_versions_ghost.py` | Confirms fix versions exist on npm registry |
| `nvd_verify_ghost.py` | Verifies each CVE exists in NVD with CVSS score |
| `get_epss_ghost.py` | Retrieves EPSS scores from FIRST API |
| `check_kev_ghost.py` | Checks CVEs against CISA KEV catalogue |

---

## Next Steps

Repeat this process for:

**Apache Airflow v2.9.2** — target 6 scenarios (PyPI/Python ecosystem)

Key difference from Juice Shop and Ghost: Airflow is a Python application. The Grype artifact type will be `python` or `pip` instead of `npm`. The fix version verification uses PyPI JSON API instead of npm registry. The filter script must be updated accordingly.
