# Ghost Baseline

- **Application:** Ghost v5.76.0
- **Docker Image:** `ghost:5.76.0`
- **Dependency Ecosystem:** NPM

This folder contains the raw Software Bill of Materials (SBOM) and Grype vulnerability scans for the Ghost CMS application prior to any LLM remediation.

### Contents
- `image_info.md`: Basic metadata about the target container image.
- `sbom/sbom.json`: Syft output (SPDX JSON).
- `grype/grype.json`: Grype vulnerability scan output.
- `candidates/`: Reserved for LLM-generated patch suggestions or candidate dependencies.
