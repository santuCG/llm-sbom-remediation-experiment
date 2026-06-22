# Apache Airflow Baseline

- **Application:** Apache Airflow v2.9.2
- **Docker Image:** `apache/airflow:2.9.2`
- **Dependency Ecosystem:** Python

This folder contains the raw Software Bill of Materials (SBOM) and Grype vulnerability scans for the Apache Airflow application prior to any LLM remediation.

### Contents
- `image_info.md`: Basic metadata about the target container image.
- `sbom/sbom.json`: Syft output (SPDX JSON).
- `grype/grype.json`: Grype vulnerability scan output.
- `candidates/`: Reserved for LLM-generated patch suggestions or candidate dependencies.
