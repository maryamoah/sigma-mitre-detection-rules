# SIEM Conversion

Sigma rules are backend-neutral. Conversion turns them into a query for a
specific platform, using [pySigma][pysigma] backends invoked through
[Sigma CLI][cli].

| Platform | Guide | Backend | Maturity |
| --- | --- | --- | --- |
| Splunk | [sigma_to_splunk.md](sigma_to_splunk.md) | `pySigma-backend-splunk` | Mature |
| Microsoft Sentinel | [sigma_to_sentinel.md](sigma_to_sentinel.md) | `pySigma-backend-microsoft365defender` | Good |
| Elastic | [sigma_to_elastic.md](sigma_to_elastic.md) | `pySigma-backend-elasticsearch` | Mature |
| QRadar | [sigma_to_qradar.md](sigma_to_qradar.md) | `pySigma-backend-QRadar-aql` | Limited |
| Wazuh | [sigma_to_wazuh.md](sigma_to_wazuh.md) | None | Manual |

## Install

```bash
python -m pip install sigma-cli
sigma plugin list
sigma plugin install splunk
```

## Convert

```bash
sigma convert -t splunk -p splunk_windows rules/windows/
```

## The thing to understand about conversion

Successful conversion proves a backend can express the logic. It proves
nothing about whether the logic matches anything in your environment.

Two failure modes are common and neither produces an error:

1. **Field mismatch.** The rule references `CommandLine`; your pipeline
   normalised it to `process.command_line`. The query is syntactically
   valid and returns nothing, forever.
2. **Missing telemetry.** The rule needs Sysmon Event ID 1; you collect only
   Security 4688 without command line auditing. The field exists but is
   always empty.

Both look identical from the SIEM: a rule that never fires. Validate against
known-true data before assuming a quiet rule means a quiet network.

Pipelines exist to solve the first problem. Use one that matches your
ingestion, and check the output query before deploying it.

[pysigma]: https://github.com/SigmaHQ/pySigma
[cli]: https://github.com/SigmaHQ/sigma-cli
