# Security Policy

This repository contains detection content. It is not a deployed service, so
"security issue" here means something different than it does for an
application. This policy covers what to report and how.

## Reporting a vulnerability

Use a [private security advisory][advisory] rather than a public issue.

[advisory]: https://github.com/maryamoah/sigma-mitre-detection-rules/security/advisories/new

In scope:

- A rule that causes harm when deployed — a query that is catastrophically
  expensive on a large dataset, or logic that could be abused to enumerate
  sensitive data in query results.
- Malicious content in a script or workflow.
- A supply-chain concern in the declared dependencies.
- Accidentally committed sensitive data. Report this privately even if it
  appears to be sample data.

Expect an initial response within roughly seven days. This is a maintained
side project, not a funded programme, so please size your expectations
accordingly.

## Out of scope

- **Active security incidents.** Do not report an ongoing intrusion here.
  Contact your own incident response team. Nothing in this repository is a
  channel for incident handling.
- **Credentials, keys, or tokens.** Never paste them into an issue, an
  advisory, a pull request, or a log sample. If you have exposed a
  credential, rotate it first and report it to the owning organisation.
- **A rule failing to detect something.** That is a detection gap. Open a
  public issue — gaps benefit from open discussion.
- **False positives.** Use the false positive report template.

## Detection bypass reports

Evasion research is welcome and improves the ruleset. To keep it
constructive, a bypass report should include:

1. **Which rule is bypassed** and the specific logic that fails.
2. **Why it fails** — the field, modifier, or assumption being exploited.
3. **A defensive rationale.** What should the rule do instead? A bypass
   without a proposed direction is a problem statement, not a contribution.
4. **Safe reproduction details.** Describe the technique at a level that
   lets a defender test it. Do not attach working offensive tooling,
   packed payloads, or live malware samples.

Bypasses against `experimental` rules can go in public issues; those rules
already carry an explicit maturity warning. Bypasses against `stable` rules
should start as a private advisory so a fix can land alongside disclosure.

## Data handling

Anything submitted to this repository is public and permanent. Before opening
an issue or pull request, remove hostnames, usernames, internal IP addresses
and ranges, internal domain names, file paths containing organisation
identifiers, customer names, and any indicator from a private feed or under
TLP:AMBER or TLP:RED.

Redact before submitting. Deleting a comment does not remove it from the
repository's history or from anyone who received the notification email.

## A note on the rules themselves

Every rule here carries a maturity status, and most are `experimental`.
Deploying an untuned detection rule to production alerting has a real cost:
alert fatigue degrades a SOC's ability to respond to genuine incidents.

Test and tune against your own telemetry before enabling alerting. That is a
safety consideration, not just an operational one.
