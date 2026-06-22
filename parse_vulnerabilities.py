import json
import csv
import sys
import os

apps = [
    ("Juice Shop", "applications/juice-shop/grype/grype.json"),
    ("Ghost", "applications/ghost/grype/grype.json"),
    ("Airflow", "applications/airflow/grype/grype.json")
]

selected_cves = []
scenario_idx = 1

for app_name, grype_path in apps:
    if not os.path.exists(grype_path):
        print(f"File not found: {grype_path}")
        continue
    
    with open(grype_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    matches = data.get('matches', [])
    
    app_candidates = []
    
    for match in matches:
        vuln = match.get('vulnerability', {})
        artifact = match.get('artifact', {})
        
        cve_id = vuln.get('id', '')
        if not cve_id.startswith('CVE-'):
            continue
            
        severity = vuln.get('severity', '')
        
        # Get max CVSS score
        cvss_metrics = vuln.get('cvss', [])
        max_score = 0.0
        for m in cvss_metrics:
            score = m.get('metrics', {}).get('baseScore', 0.0)
            if score > max_score:
                max_score = score
                
        if max_score < 7.0:
            continue
            
        fix_info = vuln.get('fix', {})
        fix_state = fix_info.get('state', '')
        fix_versions = fix_info.get('versions', [])
        
        if fix_state != 'fixed' or not fix_versions:
            continue
            
        pkg_name = artifact.get('name', '')
        pkg_version = artifact.get('version', '')
        
        # Try to avoid duplicates for the same package and CVE
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
            'EPSS': '',
            'KEV': '',
            'Severity': severity,
            'Fix_Version_Grype': fix_versions[0],
            'Registry_Verified': 'Yes', # Assumption for pre-registration script
            'Dependency_Level': 'Direct/Transitive', # Assumption for pre-registration script
            'Baseline_Version': fix_versions[0],
            'Build_Before_Remediation': '',
            'Usable': 'Yes',
            'Notes': ''
        })
        
    # Sort by CVSS score descending
    app_candidates.sort(key=lambda x: x['CVSS'], reverse=True)
    
    # Take top 6
    for cand in app_candidates[:6]:
        cand['Scenario_ID'] = f"SCENARIO_{scenario_idx:03d}"
        selected_cves.append(cand)
        scenario_idx += 1

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
    print(f"{cve['Scenario_ID']} - {cve['Application']} - {cve['Package']} - {cve['CVE']} (CVSS: {cve['CVSS']}) -> Fix: {cve['Fix_Version_Grype']}")
