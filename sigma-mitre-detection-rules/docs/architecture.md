# Architecture

```text
Telemetry -> Normalization -> Sigma rule -> Backend conversion -> SIEM query -> Alert triage
```

Sigma is the portable detection layer. Backend pipelines translate generic fields into the target SIEM data model. Wazuh XML is not a native pySigma output in this project and should be treated as a manual semantic translation requiring decoder-specific fields.
