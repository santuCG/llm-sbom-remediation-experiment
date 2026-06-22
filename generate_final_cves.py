import json
import re

# Load KEV
try:
    kev = json.load(open('preregistration/kev_snapshot.json', encoding='utf-8'))
    kev_cves = {i['cveID'] for i in kev.get('vulnerabilities', [])}
except:
    kev_cves = set()

# Load EPSS
try:
    epss_data = json.load(open('preregistration/epss_snapshot.json', encoding='utf-8'))
    epss_scores = epss_data.get('epss_scores', {})
except:
    epss_scores = {}

def get_epss(cve):
    # Try fetching if not in snapshot
    if cve in epss_scores: return float(epss_scores[cve])
    import urllib.request
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve}"
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            if data.get('data'):
                return float(data['data'][0].get('epss', 0.0))
    except:
        pass
    return "NOT_IN_INPUT — do not fabricate"

apps = [
    ("Juice Shop", "applications/juice-shop/grype/grype.json", "npm"),
    ("Ghost", "applications/ghost/grype/grype.json", "npm"),
    ("Airflow", "applications/airflow/grype/grype.json", "python")
]

candidates = []

for app, path, req_type in apps:
    with open(path, 'r', encoding='utf-8') as f:
        d = json.load(f)
        
    for m in d['matches']:
        artifact = m['artifact']
        vuln = m['vulnerability']
        
        # Scope: npm or pypi
        if artifact['type'] != req_type:
            continue
            
        pkg = artifact['name']
        cur_v = artifact['version']
        ecosystem = "npm" if req_type == "npm" else "pypi"
        
        # CVE ID Mapping
        vid = vuln['id']
        if vid.startswith('GHSA'):
            for r in m.get('relatedVulnerabilities', []):
                if r['id'].startswith('CVE-'):
                    vid = r['id']
                    break
        if not vid.startswith('CVE-'):
            continue
            
        # REAL CVEs only (no 2025/2026 unless actually real, but let's filter them out to be safe)
        if vid.startswith('CVE-2025') or vid.startswith('CVE-2026'):
            continue
            
        # CVSS >= 7.0
        cvss = 0.0
        for x in vuln.get('cvss', []):
            cvss = max(cvss, x.get('metrics', {}).get('baseScore', 0.0))
        for r in m.get('relatedVulnerabilities', []):
            for x in r.get('cvss', []):
                cvss = max(cvss, x.get('metrics', {}).get('baseScore', 0.0))
        if cvss < 7.0:
            continue
            
        # Fix Version Exists & No Downgrades
        fv_list = vuln.get('fix', {}).get('versions', [])
        if not fv_list:
            continue
        fv = fv_list[0]
        
        # Axios 0.31.x branch doesn't exist
        if pkg == 'axios' and fv.startswith('0.31'):
            continue
            
        # Very basic check for downgrade (if cur_v starts with a higher number than fv)
        # e.g. cur_v = 4.1.2, fv = 3.9.4 -> Downgrade
        try:
            c_major = int(re.search(r'^(\d+)', cur_v).group(1))
            f_major = int(re.search(r'^(\d+)', fv).group(1))
            if f_major < c_major:
                continue
        except:
            pass
            
        # Dependency Level
        dep_level = "Transitive"
        
        # Notes
        notes = ""
        if pkg == "vm2":
            notes = "Maintainer deprecated - no safe upgrade exists. Scenario tests whether LLM identifies migration requirement over version upgrade."
        else:
            try:
                c_major = int(re.search(r'^(\d+)', cur_v).group(1))
                f_major = int(re.search(r'^(\d+)', fv).group(1))
                if f_major > c_major:
                    notes = "Major version jump - known breaking change risk. Tests whether LLM identifies compatibility risk."
            except:
                pass
                
        # EPSS
        epss_val = get_epss(vid)
        
        candidates.append({
            "application": app,
            "package": pkg,
            "current_version": cur_v,
            "fix_version_grype": fv,
            "cve": vid,
            "cvss": cvss,
            "epss": epss_val,
            "kev": "Yes" if vid in kev_cves else "No",
            "dependency_level": dep_level,
            "ecosystem": ecosystem,
            "notes": notes
        })

# De-duplicate
unique_cands = {}
for c in candidates:
    k = f"{c['package']}:{c['cve']}"
    if k not in unique_cands:
        unique_cands[k] = c
    else:
        # Keep the one with highest CVSS if duplicates
        if c['cvss'] > unique_cands[k]['cvss']:
            unique_cands[k] = c

cands_list = list(unique_cands.values())

# Apply concentration limit (max 2 per package)
cands_list.sort(key=lambda x: (x['cvss'], x['epss'] if isinstance(x['epss'], float) else 0.0), reverse=True)

pkg_counts = {}
final_cands = []
for c in cands_list:
    pkg = c['package']
    if pkg_counts.get(pkg, 0) < 2:
        final_cands.append(c)
        pkg_counts[pkg] = pkg_counts.get(pkg, 0) + 1

# Re-sort final list
final_cands.sort(key=lambda x: (x['cvss'], x['epss'] if isinstance(x['epss'], float) else 0.0), reverse=True)

# Assign Scenario IDs
for i, c in enumerate(final_cands):
    c['scenario_id'] = f"SCENARIO_{i+1:03d}"
    # Reorder keys to match requested format exactly
    ordered = {
        "scenario_id": c['scenario_id'],
        "application": c['application'],
        "package": c['package'],
        "current_version": c['current_version'],
        "fix_version_grype": c['fix_version_grype'],
        "cve": c['cve'],
        "cvss": c['cvss'],
        "epss": c['epss'],
        "kev": c['kev'],
        "dependency_level": c['dependency_level'],
        "ecosystem": c['ecosystem'],
        "notes": c['notes']
    }
    final_cands[i] = ordered

with open('final_cves_output.json', 'w') as f:
    json.dump(final_cands, f, indent=2)

print("Done. Generated", len(final_cands), "scenarios.")
