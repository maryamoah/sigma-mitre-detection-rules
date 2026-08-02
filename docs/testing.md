# Testing

1. Run `python scripts/validate_rules.py` for YAML, required-field, UUID, and ATT&CK-tag checks.
2. Parse rules with Sigma CLI or pySigma.
3. Convert using the backend and processing pipeline matching the target SIEM.
4. Verify target fields against real sample events.
5. Execute a controlled benign simulation in an isolated lab.
6. Record expected events, query output, known false positives, and tuning decisions.

Atomic Red Team may help generate test telemetry, but a successful atomic test does not prove production efficacy. Collection configuration, field normalization, parent-child context, and retention all affect detection reliability.
