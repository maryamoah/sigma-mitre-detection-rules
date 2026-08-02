# Rule Writing Guide

## Required metadata

Every rule must include a clear title, UUIDv4 `id`, status, description, references, author, date, ATT&CK tags, log source, detection logic, false positives, and severity.

## Detection logic

Use the narrowest reliable telemetry. Separate selections from filters, avoid brittle full command-line matches, and do not claim maliciousness when the event only indicates suspicious behavior. Field names must follow the selected Sigma log source or be documented as environment-specific.

## ATT&CK mapping

Map only behavior directly represented by the detection. Do not map downstream attacker objectives that are merely possible. Prefer sub-techniques when the observed behavior supports them.

## Severity

- `low`: useful hunting signal with common benign explanations
- `medium`: suspicious behavior requiring contextual review
- `high`: strong attacker behavior or security-control tampering
- `critical`: behavior strongly associated with destructive impact
