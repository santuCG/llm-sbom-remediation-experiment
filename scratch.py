import json

kev = json.load(open('preregistration/kev_snapshot.json', encoding='utf-8'))
kev_cves = {i['cveID'] for i in kev.get('vulnerabilities', [])}

for app, p in [('Juice Shop', 'applications/juice-shop/grype/grype.json'), ('Ghost', 'applications/ghost/grype/grype.json'), ('Airflow', 'applications/airflow/grype/grype.json')]:
    d = json.load(open(p, encoding='utf-8'))
    print(f'\n--- {app} ---')
    req_type = 'npm' if app != 'Airflow' else 'python'
    for m in d['matches']:
        if m['artifact']['type'] != req_type:
            continue
        vid = m['vulnerability']['id']
        if vid.startswith('GHSA'):
            for r in m.get('relatedVulnerabilities', []):
                if r['id'].startswith('CVE-'):
                    vid = r['id']
                    break
        if not vid.startswith('CVE-'):
            continue
            
        if vid in kev_cves:
            cvss = 0.0
            for x in m['vulnerability'].get('cvss', []):
                cvss = max(cvss, x.get('metrics', {}).get('baseScore', 0.0))
            for r in m.get('relatedVulnerabilities', []):
                for x in r.get('cvss', []):
                    cvss = max(cvss, x.get('metrics', {}).get('baseScore', 0.0))
            
            pkg = m['artifact']['name']
            fv = m['vulnerability'].get('fix', {}).get('versions', ['None'])
            print(f"KEV POSITIVE FOUND: {pkg} : {vid} [CVSS: {cvss}] -> {fv[0]}")
