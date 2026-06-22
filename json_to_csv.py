import json
import csv

# Load the generated JSON array with UTF-16 since Powershell output redirection defaults to it
with open('final_18_cves.json', 'r', encoding='utf-16') as f:
    cves = json.load(f)

# Define CSV columns based on the original structure + required rules
fieldnames = [
    'Scenario_ID', 'Application', 'Package', 'Current_Version', 'CVE', 'CVSS', 'EPSS', 'KEV', 
    'Fix_Version_Grype', 'Dependency_Level', 'Ecosystem', 'Notes'
]

# Write to CSV
with open('preregistration/scenario_preregistration.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for row in cves:
        writer.writerow({
            'Scenario_ID': row['scenario_id'],
            'Application': row['application'],
            'Package': row['package'],
            'Current_Version': row['current_version'],
            'CVE': row['cve'],
            'CVSS': row['cvss'],
            'EPSS': row['epss'],
            'KEV': row['kev'],
            'Fix_Version_Grype': row['fix_version_grype'],
            'Dependency_Level': row['dependency_level'],
            'Ecosystem': row['ecosystem'],
            'Notes': row['notes']
        })

print(f"Successfully wrote {len(cves)} rows to scenario_preregistration.csv")
