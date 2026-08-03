# Converting to Microsoft Sentinel

## Install

```bash
python -m pip install sigma-cli
sigma plugin install microsoft365defender
```

## Convert

```bash
sigma convert -t microsoft365defender \
  rules/windows/credential-access/proc_creation_win_lsass_comsvcs_minidump.yml
```

## Table mapping

This is where most Sentinel conversions go wrong. The same telemetry lands in
different tables depending on which connector ingested it.

| Sigma logsource | Defender XDR table | Sentinel (Security Events connector) |
| --- | --- | --- |
| `process_creation` | `DeviceProcessEvents` | `SecurityEvent` where `EventID == 4688` |
| `registry_set` | `DeviceRegistryEvents` | `Event` (Sysmon channel) |
| `network_connection` | `DeviceNetworkEvents` | `Event` (Sysmon channel) |
| `aws/cloudtrail` | — | `AWSCloudTrail` |
| `azure/auditlogs` | — | `AuditLogs` |
| `azure/signinlogs` | — | `SigninLogs` |
| `m365/exchange` | — | `OfficeActivity` |

The `microsoft365defender` backend targets the Defender XDR schema. If your
data arrives through the legacy Security Events connector, the converted
query will reference tables you do not have.

## Field name differences

| Sigma | Defender XDR | SecurityEvent |
| --- | --- | --- |
| `Image` | `FolderPath` | `NewProcessName` |
| `CommandLine` | `ProcessCommandLine` | `CommandLine` |
| `ParentImage` | `InitiatingProcessFolderPath` | `ParentProcessName` |
| `User` | `AccountName` | `SubjectUserName` |

## Deploying as an analytics rule

Converted KQL is the query body only. An analytics rule also needs a
frequency, a lookback period, entity mappings and a severity. Set the
lookback longer than the frequency to avoid gaps at the boundary.

## Limitations

- **Cloud rules do not use this backend.** AWS, Azure and Microsoft 365 rules
  in this repository target native Sentinel tables. Translate those by hand
  against the table reference above.
- **Entity mapping is manual.** Without it, incidents have no linked account
  or host and cannot be correlated.
- **Cost.** Sentinel bills on ingestion and on query. Rules that scan
  `DeviceProcessEvents` over long lookbacks get expensive quickly.
