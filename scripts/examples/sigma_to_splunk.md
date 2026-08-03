# Converting to Splunk

## Install

```bash
python -m pip install sigma-cli
sigma plugin install splunk
```

## Convert

```bash
# Single rule
sigma convert -t splunk -p splunk_windows \
  rules/windows/credential-access/proc_creation_win_lsass_comsvcs_minidump.yml

# Whole directory
sigma convert -t splunk -p splunk_windows rules/windows/

# As a saved search, ready for savedsearches.conf
sigma convert -t splunk -p splunk_windows -f savedsearches rules/windows/
```

## Pipelines

| Pipeline | Use for |
| --- | --- |
| `splunk_windows` | Sysmon and Windows Security via the Splunk TA |
| `splunk_windows_sysmon_acceleration` | Adds tstats acceleration hints |
| `splunk_cim_dm` | Common Information Model data models |

## Output format

Conversion produces a search expression, not a complete search. It has no
index, no time range and no output formatting. You must add those:

```
index=windows source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
earliest=-24h
[converted expression here]
| table _time host user Image CommandLine ParentImage
```

## Limitations

- **No index selection.** The backend cannot know your index layout. Every
  converted search needs an index constraint or it will scan everything.
- **CIM field names differ from Sysmon field names.** If you normalise to
  CIM, use `splunk_cim_dm` rather than `splunk_windows`, or the field names
  will not match.
- **Case sensitivity.** Splunk search is case-insensitive for values but
  case-sensitive for field names. Sigma is case-insensitive for both.
- **`|contains|all` produces multiple `AND` terms.** On high-volume indexes
  these can be expensive. Consider `tstats` acceleration for the noisier
  rules.
- **Regex modifiers convert to `| regex`**, which runs after the initial
  search and does not benefit from indexing. Rules relying on `|re` will be
  slower than their converted form suggests.
