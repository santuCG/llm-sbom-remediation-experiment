# LLM-Assisted Dependency Vulnerability Remediation in DevSecOps Pipelines

## Master Thesis Research Repository
**Researcher:** Santosh Nagaraj  
**Institution:** SRH Berlin University of Applied Sciences  
**Supervisor:** Knut Haufe  

## Objective
Evaluate the effectiveness of Large Language Models in remediating software dependency vulnerabilities detected in real-world applications.

## Applications
- OWASP Juice Shop v15.3.0
- Ghost v5.76.0
- Apache Airflow v2.9.2

## Vulnerability Selection
Scenarios are pre-registered before experiment execution.

**Inclusion criteria:**
- CVSS score ≥ 7.0
- Stable patched version exists
- Fix version available in package registry
- Direct dependency or first-level transitive dependency

**Target sample size:**
- Up to 6 vulnerabilities per application
- Maximum 18 scenarios total

## Reproducibility
All SBOMs, vulnerability reports, prompts, model outputs, build logs, and analysis scripts are preserved within this repository.
