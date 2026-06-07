# Experimental Protocol

## Phase 1 – Application Acquisition
Container images:
- `bkimminich/juice-shop:v15.3.0`
- `ghost:5.76.0`
- `apache/airflow:2.9.2`

Images are pulled directly from Docker Hub.

## Phase 2 – SBOM Generation
- **Tool:** Syft
- **Output format:** SPDX JSON

## Phase 3 – Vulnerability Detection
- **Tool:** Grype
- **Inclusion threshold:** CVSS >= 7.0

## Phase 4 – Vulnerability Selection
A vulnerability is eligible only when:
- A patched version exists.
- The patched version is available on the official package registry.
- The dependency is direct or first-level transitive.
- The baseline version is the minimum stable patched release.

## Phase 5 – LLM Remediation
The same prompt template is used for all scenarios.

## Phase 6 – Evaluation
**Metrics:**
- Successful remediation
- Build success
- Test success
- Version correctness
- Over-remediation
- Under-remediation
- Hallucinated versions
