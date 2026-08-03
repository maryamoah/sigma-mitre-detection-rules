# Pull request

## Summary

<!-- What does this change and why. Link the issue it closes, if any. -->

Closes #

## Type of change

- [ ] New detection rule
- [ ] Rule tuning (false positive reduction)
- [ ] Rule logic correction
- [ ] Documentation
- [ ] Tooling, CI, or repository structure

## Detection rule checklist

<!-- Delete this section if the change touches no rule files. -->

- [ ] `id` is a newly generated UUIDv4 and unique within the repository
- [ ] `title` describes the behaviour, not the tool or the rule file
- [ ] `status` reflects real maturity (`experimental` unless field-tested)
- [ ] `description` explains what the rule detects and why it matters
- [ ] `references` cite public research rather than blog aggregators
- [ ] `logsource` matches a telemetry source a reader can actually collect
- [ ] `tags` include the correct ATT&CK tactic and technique
- [ ] `falsepositives` list realistic benign sources, not `Unknown`
- [ ] `level` is justified by the expected signal-to-noise ratio
- [ ] Field names match the Sigma taxonomy for the declared log source
- [ ] `mappings/` updated if this changes ATT&CK coverage

## Validation

- [ ] `python scripts/validate_rules.py` passes
- [ ] `sigma check rules/` passes
- [ ] Rule converts cleanly on at least one backend

<!-- Paste the converted query for the backend you tested. -->

```
```

## Testing evidence

<!--
How was this verified? Benign-log testing, lab simulation, Atomic Red Team
test number, or production telemetry review. State plainly if the rule is
untested — that is acceptable for `experimental` status and better than an
unsupported claim.
-->

## Known limitations

<!-- Evasion paths, telemetry gaps, or environments where this will not fire. -->

## Confirmation

- [ ] This is my own work and I have the right to contribute it
- [ ] No customer data, private indicators, or proprietary content is included
- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md)
