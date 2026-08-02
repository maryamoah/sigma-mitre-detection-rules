# Build status

Tracked against the specification. Update as tranches land.

## Complete

| Item | State |
| --- | --- |
| Directory structure | Full tree per spec |
| `scripts/validate_rules.py` | Convention validator, 20+ checks |
| `scripts/generate_coverage.py` | Coverage MD, Navigator layer, mapping CSV |
| `mappings/` (3 artefacts) | Generated from rule tags |
| Windows rules | **28 rules, 33 techniques, 10 of 14 tactics** |
| `.github/` (CI, templates, CODEOWNERS, Dependabot) | Complete |
| `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md` | Complete |
| Lint configuration | yamllint, markdownlint |

All 28 rules pass `validate_rules.py` with 0 errors and 0 warnings.

## Windows coverage delivered

| Tactic area | Rules |
| --- | --- |
| Credential access | 5 |
| Execution | 6 |
| Persistence | 4 |
| Defense evasion | 5 |
| Discovery | 3 |
| Privilege escalation | 2 |
| Lateral movement | 2 |
| Impact | 1 |

## Remaining

| Item | Notes |
| --- | --- |
| Linux rules | auditd execution and persistence |
| Web rules | Apache, Nginx, IIS |
| Cloud rules | AWS CloudTrail, Azure, Microsoft 365 |
| Firewall rules | Fortigate, Palo Alto, Cisco |
| Network rules | DNS, proxy |
| `docs/` (9 files) | Architecture, testing, rule writing, philosophy, FAQ, etc. |
| `examples/` (5 files) | Splunk, Sentinel, Elastic, QRadar, Wazuh conversion |
| Per-category READMEs | One per rule directory |
| `CODE_OF_CONDUCT.md` | Contributor Covenant |

## Before you publish

1. Run `sigma check rules/` — needs network for `pip install sigma-cli`,
   which was unavailable in the build environment. The rules are valid YAML
   and pass repository conventions, but specification validation has not run.
2. Read every rule. If you cannot explain why a filter is scoped the way it
   is, remove the rule rather than ship it.
3. Set the repository description and topics.
4. Tag `v0.1.0`.
