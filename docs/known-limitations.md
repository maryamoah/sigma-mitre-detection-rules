# Known Limitations

Every detection repository has gaps. Listing them is more useful than
implying they do not exist, and it lets you decide whether this ruleset fits
your environment before you deploy it.

## Validation status

Most rules carry `status: experimental`. That is accurate, not modesty. It
means the logic is derived from public research and Sigma taxonomy
conventions rather than from observation of the behaviour in production
telemetry at scale.

A rule is promoted only when there is evidence behind the promotion. See
[Rule lifecycle](../README.md#rule-lifecycle).

## Field name portability

Sigma normalises a great deal, but ingestion pipelines differ. A rule
referencing `CommandLine` assumes your pipeline preserves that field name.
If you normalise to ECS, to CIM, or to a vendor-specific schema, expect to
map fields before rules fire.

This is most acute for:

- **Firewall rules.** There is no rich Sigma taxonomy for firewall logs. The
  rules under `rules/firewall/` use vendor-native field names and state the
  expected log format in each rule's `definition`. Treat them as templates.
- **Network rules.** Proxy and DNS schemas vary more than endpoint schemas.
- **Cloud rules.** CloudTrail and the Microsoft 365 unified audit log are
  reasonably stable, but connector-specific table names differ between
  Sentinel, Splunk and Elastic.

## Telemetry dependencies

A rule cannot fire on data you do not collect. Silent failure from missing
log sources is the most common reason a deployed ruleset appears quiet.

| Dependency | Affects | Consequence if absent |
| --- | --- | --- |
| Sysmon | Many Windows rules | Rules using Sysmon-specific fields degrade or never fire |
| Command line auditing | All process creation rules | `CommandLine` is empty; most Windows rules become useless |
| Registry auditing (Sysmon 13) | `registry_set` rules | Rules never fire |
| auditd execve rules | Linux process rules | `CommandLine` unpopulated |
| auditd filesystem watches | Linux persistence rules | File events never generated |
| Entra ID P2 licence | `azure_signin_from_anonymised_infrastructure` | `riskLevelDuringSignIn` unpopulated |
| Mailbox auditing | Microsoft 365 Exchange rules | Operations not recorded |

Each rule states its dependency in the `logsource.definition` field. Read it
before concluding a rule is broken.

## Rules that are not alerts

Several rules are deliberately low-fidelity and are documented as such in
their `falsepositives` block. They exist to provide clean base events for
correlation, threshold alerting, or hunting — not to page an analyst.

| Rule | Why it is not an alert |
| --- | --- |
| `cisco_asa_vpn_login_from_unexpected_geography` | Matches every successful VPN login; requires geolocation enrichment |
| `cisco_asa_denied_connection_burst` | Matches internet background noise; requires aggregation by source |
| `fortigate_vpn_bruteforce_failed_logins` | Single failures are meaningless; requires a threshold |
| `proc_creation_win_system_network_discovery` | Individually benign admin commands; value is in sequence |
| `paloalto_outbound_connection_to_nonstandard_port` | High ports have legitimate uses; hunting input |

Deploying these as standalone alerts will generate noise. That is a
deployment error, not a rule defect.

## Coverage is not effectiveness

The coverage artefacts in [`mappings/`](../mappings/) report which ATT&CK
techniques have at least one rule mapped to them. ATT&CK techniques are
broad, and most contain procedures no single rule detects.

A green cell on the Navigator layer means an attempt exists. It does not mean
the technique is comprehensively covered, and it should never be presented to
leadership as a measure of defensive strength.

## Evasion

Every rule here can be bypassed by an attacker who knows it exists. Signed
binary proxy detections can be evaded by choosing a different signed binary;
command line detections by obfuscating arguments; path-based filters by
staging from a different directory.

Filters are deliberately scoped narrowly — to a parent process path rather
than a filename, for example — because a broad exclusion is the easiest thing
for an attacker to occupy. This makes the rules noisier than they could be.
That trade is intentional.

## Backend conversion

Conversion is a compatibility signal, not a correctness guarantee. A rule
that converts cleanly may still fail to match anything in your environment.

Wazuh has no maintained pySigma backend, so those rules require manual
translation to Wazuh XML. See [`examples/`](../examples/).

## Scope

This repository is not a replacement for [SigmaHQ][sigmahq], which is
substantially larger and maintained by a community. This is original work
maintained to a narrower scope, and where the two overlap SigmaHQ is likely
to be the better-tested option.

[sigmahq]: https://github.com/SigmaHQ/sigma
