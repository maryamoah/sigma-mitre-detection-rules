# Sigma MITRE Detection Rules

A vendor-neutral detection engineering repository containing Sigma rules mapped to MITRE ATT&CK. The initial release focuses on practical, explainable detections across Windows, Linux, web, network, AWS, and Microsoft 365 telemetry.

> **Project status:** Experimental. Test and tune every rule against your own telemetry before production use.

## Highlights

- 26 original Sigma rules
- ATT&CK tactic and technique mappings
- Meaningful false-positive guidance
- YAML and metadata validation through GitHub Actions
- Conversion notes for Wazuh, Microsoft Sentinel, Splunk, Elastic, and QRadar

## Repository structure

```text
rules/       Sigma detections grouped by platform
mappings/    ATT&CK coverage and machine-readable mapping
docs/        Writing, testing, architecture, and roadmap guidance
examples/    SIEM conversion notes
```

## Validate locally

```bash
python -m pip install -r requirements-dev.txt
python scripts/validate_rules.py
```

For full Sigma parsing and backend conversion, install Sigma CLI and the required backend plugin. pySigma is the current parsing and conversion framework used by the Sigma ecosystem.

## Detection philosophy

Rules in this repository target observable attacker behavior rather than isolated indicators. A rule should have a clear telemetry dependency, an explainable ATT&CK mapping, and actionable investigation context. Coverage numbers alone are not treated as evidence of detection quality.

## Usage

1. Select rules matching your available log sources.
2. Validate field mappings against your data model.
3. Convert with a supported pySigma backend or translate manually.
4. Test using benign simulations or an isolated lab.
5. Tune known administrative activity before enabling alerting.

## License

MIT License. See [LICENSE](LICENSE).
