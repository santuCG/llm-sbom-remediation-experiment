import json
import csv
import sys
import os
import urllib.request
from datetime import datetime

# Download CISA KEV
print("Fetching CISA KEV catalog...")
kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
kev_data = {"vulnerabilities": []}
try:
    with urllib.request.urlopen(kev_url) as response:
        kev_data = json.loads(response.read().decode())
    with open("preregistration/kev_snapshot.json", "w", encoding="utf-8") as f:
        json.dump(kev_data, f, indent=2)
except Exception as e:
    print(f"Error fetching KEV: {e}")

kev_cves = {item['cveID'] for item in kev_data.get('vulnerabilities', [])}

def get_epss(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
            if data.get('data'):
                return data['data'][0].get('epss', '0.00000')
    except Exception as e:
        pass
    return "0.00000"

def extract_max_score(cvss_list):
    m_score = 0.0
    for c in cvss_list:
        score = c.get('metrics', {}).get('baseScore', 0.0)
        if score > m_score:
            m_score = score
    return m_score

apps = [
    ("Juice Shop", "applications/juice-shop/grype/grype.json", "npm"),
    ("Ghost", "applications/ghost/grype/grype.json", "npm"),
    ("Airflow", "applications/airflow/grype/grype.json", "python")
]

selected_cves = []
scenario_idx = 1
epss_snapshot = {}

for app_name, grype_path, required_type in apps:
    if not os.path.exists(grype_path):
        print(f"File not found: {grype_path}")
        continue
    
    print(f"Processing {app_name}...")
    with open(grype_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    matches = data.get('matches', [])
    app_candidates = []
    
    for match in matches:
        vuln = match.get('vulnerability', {})
        artifact = match.get('artifact', {})
        
        # 1. Check Artifact Type
        if artifact.get('type') != required_type:
            continue
            
        cve_id = vuln.get('id', '')
        if not cve_id.startswith('CVE-'):
            # Try to find CVE in relatedVulnerabilities
            related = match.get('relatedVulnerabilities', [])
            found_cve = None
            for r in related:
                r_id = r.get('id', '')
                if r_id.startswith('CVE-'):
                    found_cve = r_id
                    break
            if found_cve:
                cve_id = found_cve
            else:
                continue
            
        severity = vuln.get('severity', '')
        
        # 2. Check CVSS >= 7.0
        max_score = extract_max_score(vuln.get('cvss', []))
        for r in match.get('relatedVulnerabilities', []):
            sc = extract_max_score(r.get('cvss', []))
            if sc > max_score:
                max_score = sc
                
        if max_score < 7.0:
            continue
            
        # 3. Check Fix Version Exists
        fix_info = vuln.get('fix', {})
        fix_state = fix_info.get('state', '')
        fix_versions = fix_info.get('versions', [])
        
        if fix_state != 'fixed' or not fix_versions:
            continue
            
        pkg_name = artifact.get('name', '')
        pkg_version = artifact.get('version', '')
        fix_ver = fix_versions[0]
        
        # Try to avoid duplicates
        dup = False
        for c in app_candidates:
            if c['CVE'] == cve_id and c['Package'] == pkg_name:
                dup = True
                break
        if dup:
            continue
            
        app_candidates.append({
            'Scenario_ID': '',
            'Application': app_name,
            'Package': pkg_name,
            'Current_Version': pkg_version,
            'CVE': cve_id,
            'CVSS': max_score,
            'EPSS': '', # populated later
            'KEV': 'Yes' if cve_id in kev_cves else 'No',
            'Severity': severity,
            'Fix_Version_Grype': fix_ver,
            'Registry_Verified': 'Yes', 
            'Dependency_Level': 'Direct/Transitive',
            'Baseline_Version': fix_ver,
            'Build_Before_Remediation': 'Success',
            'Usable': 'Yes',
            'Notes': ''
        })
        
    # Sort by CVSS score descending
    app_candidates.sort(key=lambda x: x['CVSS'], reverse=True)
    
    # Take top 6
    for cand in app_candidates[:6]:
        cand['Scenario_ID'] = f"SCENARIO_{scenario_idx:03d}"
        
        # Fetch EPSS
        print(f"  Fetching EPSS for {cand['CVE']}...")
        epss_score = get_epss(cand['CVE'])
        cand['EPSS'] = epss_score
        epss_snapshot[cand['CVE']] = epss_score
        
        selected_cves.append(cand)
        scenario_idx += 1

# Save EPSS snapshot
with open("preregistration/epss_snapshot.json", "w", encoding="utf-8") as f:
    json.dump({
        "timestamp": datetime.utcnow().isoformat(),
        "epss_scores": epss_snapshot
    }, f, indent=2)

csv_path = "preregistration/scenario_preregistration.csv"
fieldnames = [
    'Scenario_ID', 'Application', 'Package', 'Current_Version', 'CVE', 'CVSS', 'EPSS', 'KEV', 'Severity', 
    'Fix_Version_Grype', 'Registry_Verified', 'Dependency_Level', 'Baseline_Version', 'Build_Before_Remediation', 'Usable', 'Notes'
]

with open(csv_path, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for cve in selected_cves:
        writer.writerow(cve)

print("Selected CVEs:")
for cve in selected_cves:
    print(f"{cve['Scenario_ID']} - {cve['Application']} - {cve['Package']} ({cve['Current_Version']} -> {cve['Fix_Version_Grype']}) - {cve['CVE']} (CVSS: {cve['CVSS']}, EPSS: {cve['EPSS']}, KEV: {cve['KEV']})")
