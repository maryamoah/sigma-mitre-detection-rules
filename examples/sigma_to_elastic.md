# Converting to Elastic

## Install

```bash
python -m pip install sigma-cli
sigma plugin install elasticsearch
```

## Convert

```bash
# Lucene, for Kibana and Discover
sigma convert -t lucene -p ecs_windows rules/windows/

# ES|QL
sigma convert -t esql -p ecs_windows rules/windows/

# EQL, for sequence and correlation rules
sigma convert -t eql -p ecs_windows rules/windows/

# Elastic detection rule NDJSON, importable via the Security app
sigma convert -t lucene -p ecs_windows -f siem_rule_ndjson rules/windows/
```

## Pipelines

| Pipeline | Use for |
| --- | --- |
| `ecs_windows` | Winlogbeat and Elastic Agent, Windows |
| `ecs_windows_old` | Winlogbeat 6.x and earlier |
| `ecs_zeek_beats` | Zeek via Filebeat |
| `ecs_kubernetes` | Kubernetes audit logs |

Using no pipeline produces a query with raw Sigma field names, which will not
match ECS-normalised data. This is the single most common mistake.

## Field mapping

| Sigma | ECS |
| --- | --- |
| `Image` | `process.executable` |
| `CommandLine` | `process.command_line` |
| `ParentImage` | `process.parent.executable` |
| `User` | `user.name` |
| `TargetFilename` | `file.path` |

## Importing detection rules

```bash
sigma convert -t lucene -p ecs_windows -f siem_rule_ndjson \
  rules/windows/ > windows-rules.ndjson
```

Import through **Security → Rules → Import**. Review severity and risk score
before enabling — the backend maps Sigma `level` to Elastic severity, but the
risk score defaults may not match your triage model.

## Limitations

- **Wildcards at the start of a value are slow.** Rules using
  `|endswith` become leading wildcards in Lucene, which cannot use the index.
  This is unavoidable and affects most process-creation rules.
- **`|contains|all` becomes multiple clauses**, which is correct but
  increases query cost on large indices.
- **Case sensitivity.** ECS `keyword` fields are case-sensitive; Sigma is
  not. Values that differ only in case will not match unless your ingest
  pipeline normalises them.
- **EQL is a better fit for parent-child rules** than Lucene, since it can
  express sequence and process lineage directly.
