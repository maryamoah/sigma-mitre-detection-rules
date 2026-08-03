# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

Versioning applies to the ruleset as a whole:

- **Major** — breaking changes to repository structure, rule file paths, or
  metadata conventions that would affect automated consumers.
- **Minor** — new rules, new documentation, new tooling.
- **Patch** — rule tuning, false positive fixes, corrections.

## [Unreleased]

### Added

- GitHub Actions workflow validating rules with `scripts/validate_rules.py`
  and `sigma check`, across Python 3.11 and 3.12.
- GitHub Actions workflow running yamllint, markdownlint, and link checking.
- Backend conversion smoke test for Splunk and Elasticsearch.
- Issue templates for bug reports, feature requests, new rule proposals, and
  false positive reports.
- Pull request template with rule metadata and validation checklists.
- `CODEOWNERS` and Dependabot configuration.
- `scripts/generate_coverage.py`, generating the ATT&CK coverage table and an
  ATT&CK Navigator layer directly from rule tags.
- `yamllint` and `markdownlint` configuration.

### Changed

- Expanded `CONTRIBUTING.md` with rule requirements, validation steps, review
  expectations, and testing evidence guidance.
- Expanded `SECURITY.md` with scope, bypass reporting, and data handling.
- Added `sigma-cli` and `yamllint` to `requirements-dev.txt`, which
  previously declared only PyYAML and could not run the validation described
  in the README.
- Expanded `.gitignore` to exclude converted query output and local telemetry
  samples.

### Fixed

- Corrected the 0.1.0 entry below, which claimed CI validation before any
  workflow existed in the repository.

## [0.1.0] - 2026-08-02

Initial release.

### Added

- 26 Sigma rules across six telemetry domains: Windows, Linux, web, network,
  AWS, and Microsoft 365.
- MITRE ATT&CK tactic and technique mappings, with coverage documentation.
- Local validation through `scripts/validate_rules.py`.
- SIEM conversion notes for Wazuh, Microsoft Sentinel, Splunk, Elastic, and
  QRadar.
- Contribution guidance, security policy, and MIT license.

### Notes

All rules in this release are experimental. They are derived from public
research and Sigma taxonomy conventions rather than from validation against
production telemetry at scale. Test and tune before enabling alerting.

[Unreleased]: https://github.com/maryamoah/sigma-mitre-detection-rules/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/maryamoah/sigma-mitre-detection-rules/releases/tag/v0.1.0
