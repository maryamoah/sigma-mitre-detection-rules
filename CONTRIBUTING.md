# Contributing

Thanks for your interest in this project. This guide covers what a good
contribution looks like, how rules are reviewed, and the standards a rule must
meet before it is merged.

Contributions are welcome regardless of size. A well-reasoned false positive
report is worth more to this repository than a rule nobody has tested.

---

## Ground rules

Three requirements are non-negotiable:

1. **Contribute only your own work.** Rules copied from SigmaHQ, a vendor
   ruleset, or another repository will not be merged without explicit
   attribution and a license review confirming compatibility with MIT.
2. **Never submit customer or environment data.** No hostnames, usernames,
   internal IP addresses, domain names, private indicators, or log samples
   that identify an organisation. Redact before opening anything.
3. **Do not submit rules you cannot explain.** If you cannot describe the
   telemetry a rule depends on and how an attacker would evade it, the rule
   is not ready.

---

## Ways to contribute

| Contribution | Start with | Notes |
| --- | --- | --- |
| New detection | [New rule proposal][nr] issue | Propose before implementing |
| Rule tuning | [False positive report][fp] issue | The highest-value contribution |
| Logic correction | [Bug report][br] issue | Include the failing sample |
| Documentation | Pull request directly | No issue required for typos |
| Tooling or CI | [Feature request][fr] issue | Discuss approach first |

[nr]: https://github.com/maryamoah/sigma-mitre-detection-rules/issues/new?template=new_rule_proposal.yml
[fp]: https://github.com/maryamoah/sigma-mitre-detection-rules/issues/new?template=false_positive_report.yml
[br]: https://github.com/maryamoah/sigma-mitre-detection-rules/issues/new?template=bug_report.yml
[fr]: https://github.com/maryamoah/sigma-mitre-detection-rules/issues/new?template=feature_request.yml

Opening a proposal issue before writing a rule keeps review focused on the
detection idea rather than on YAML formatting. It also avoids duplicated work.

---

## Development setup

```bash
git clone https://github.com/maryamoah/sigma-mitre-detection-rules.git
cd sigma-mitre-detection-rules

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

For backend conversion, install Sigma CLI and the plugin for your target:

```bash
python -m pip install sigma-cli
sigma plugin list
sigma plugin install splunk
```

---

## Rule requirements

Every rule must satisfy the following before review.

### Identity and metadata

- `id` is a freshly generated UUIDv4, unique across the repository.
  Generate with `python -c "import uuid; print(uuid.uuid4())"`.
- `title` describes the **behaviour**, not the tool and not the filename.
  Keep it under roughly 70 characters and avoid ending punctuation.
- `status` is honest. Use `experimental` unless the rule has been run against
  real telemetry over a meaningful period. Do not claim `stable` to look
  mature — a reviewer will ask what you tested it against.
- `description` explains what the rule detects and why that behaviour matters
  to an analyst reading the alert at 3 a.m.
- `author` and `date` are present; `modified` is updated on material change.
- `references` cite primary research, vendor threat reporting, or ATT&CK
  documentation. Avoid link aggregators and content farms.

### Detection content

- `logsource` corresponds to telemetry a reader can realistically collect,
  and field names match the Sigma taxonomy for that log source.
- The detection targets observable behaviour rather than a single hardcoded
  indicator. A rule matching one hash or one filename ages out immediately.
- `condition` is as simple as the behaviour allows. Complexity that does not
  reduce false positives is complexity that will not survive maintenance.
- `tags` include the correct ATT&CK tactic and technique in current
  `attack.` notation, and nothing that is not genuinely applicable.
- `falsepositives` lists realistic benign sources. `Unknown` is acceptable
  only where the behaviour truly has no known benign analogue, which is rare.
- `level` matches expected signal-to-noise. A rule that fires hourly is not
  `high` no matter how interesting the behaviour is.

### What will be rejected

- Detections built on unrealistic attacker behaviour or invented telemetry.
- Rules whose only evidence of quality is that they convert without error.
- Coverage padding — rules written to claim an ATT&CK technique rather than
  to catch something.
- `falsepositives: - None` on a behavioural detection.

---

## Validation

Run both checks locally before opening a pull request. CI runs the same
commands and a pull request that fails them will not be reviewed until green.

```bash
python scripts/validate_rules.py     # repository metadata conventions
sigma check rules/                   # Sigma specification compliance
```

Confirm the rule converts on at least one backend, and include the output in
your pull request:

```bash
sigma convert -t splunk -p splunk_windows rules/path/to/your_rule.yml
```

Conversion success is a compatibility signal, not a correctness guarantee. It
proves the backend can express your logic. It proves nothing about whether the
logic catches the behaviour.

---

## Testing expectations

State plainly how the rule was verified. Acceptable evidence, strongest first:

1. Production telemetry review over a defined period, with observed volume.
2. Lab detonation in an isolated environment.
3. Atomic Red Team test execution, citing the test number.
4. Benign-log testing confirming the rule does not fire on normal activity.
5. Untested — logic derived from public research only.

Option 5 is acceptable for `experimental` rules. An unsupported claim of
testing is not. Reviewers would rather see an honest gap than a confident
assertion that turns out to be hollow.

---

## Pull request process

1. Branch from `main` using a descriptive name:
   `rule/lsass-memory-access`, `fix/rundll32-fp`, `docs/testing-guide`.
2. Keep pull requests focused. One rule, or one coherent set of related
   changes. Large mixed pull requests get slower review, not faster.
3. Write [conventional commit][cc] messages:
   - `feat(rules): add detection for LSASS memory access via comsvcs`
   - `fix(rules): reduce rundll32 false positives from Citrix agents`
   - `docs(testing): document benign-log validation approach`
4. Fill in the pull request template completely. Delete sections that do not
   apply rather than leaving them blank.
5. Update `mappings/` if the change affects ATT&CK coverage.
6. Update `CHANGELOG.md` under the `Unreleased` heading.

[cc]: https://www.conventionalcommits.org/

---

## Review

Pull requests are reviewed against detection quality, not volume. Expect
questions along these lines:

- What telemetry does this depend on, and how common is it?
- What does an analyst do when this fires?
- How would an attacker who knows about this rule avoid it?
- What benign activity looks similar?
- Why this `level`?

Review may take some time. This is a maintained side project rather than a
funded one, and a slow review is more useful than a fast merge of an untested
rule. Feedback on your rule is not criticism of you — every rule in this
repository has been through the same questions.

---

## Reporting security issues

Do not open a public issue for a security vulnerability. Follow the process in
[SECURITY.md](SECURITY.md).

---

## Licensing

Contributions are licensed under the [MIT License](LICENSE). By submitting a
pull request you confirm you have the right to contribute the content and
agree to it being released under those terms.
