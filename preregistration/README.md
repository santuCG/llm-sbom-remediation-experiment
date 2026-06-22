# Pre-registration Data

This directory contains the artifacts generated prior to executing the LLM remediation experiments. This establishes a verifiable, timestamped baseline.

## Contents
- `protocol.md`: Experimental methodology and inclusion criteria.
- `selection_criteria.md`: Detailed rules for selecting the CVEs.
- `scenario_preregistration.csv`: The 18 finalized CVEs representing the experimental testbed.
- `epss_snapshot.json`: A static snapshot of the FIRST EPSS scores at the time of pre-registration.
- `kev_snapshot.json`: A static snapshot of the CISA KEV catalog at the time of pre-registration.
- `tool_versions.md`: Environment tooling versions.

## Updates
- **CVE Filtering Refined:** The original extraction script blindly selected OS-level and binary dependencies from the container images (e.g., `openssl`, `libc6`, Go `stdlib`). The extraction logic was updated to strictly enforce `artifact.type` constraints, ensuring only `npm` and `python` application dependencies are selected.
- **EPSS & KEV Integration:** The extraction script dynamically queried the FIRST API and CISA KEV feeds to populate these metrics for all scenarios, capturing their state prior to experimentation.
