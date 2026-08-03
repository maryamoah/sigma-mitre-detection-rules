# Converting to QRadar

## Install

```bash
python -m pip install sigma-cli
sigma plugin install qradar-aql
```

## Convert

```bash
sigma convert -t qradar-aql \
  rules/windows/credential-access/proc_creation_win_lsass_comsvcs_minidump.yml
```

## Expect manual work

QRadar conversion requires more hand-finishing than any other backend in this
list. Plan for it rather than being surprised by it.

QRadar normalises events into properties defined by a DSM. Whether a Sigma
field has an equivalent depends entirely on which DSM parsed the event and
whether a custom property was defined for it.

| Sigma field | Typical QRadar property | Reliably present? |
| --- | --- | --- |
| `Image` | `Process Name` | Usually |
| `CommandLine` | Custom property | **Often not** |
| `ParentImage` | Custom property | **Often not** |
| `User` | `username` | Usually |

`CommandLine` is the critical gap. Most Windows rules in this repository
depend on it, and if no custom property extracts it, those rules cannot be
translated meaningfully.

## Before converting

1. Confirm the Windows DSM is parsing Sysmon events.
2. Check which custom properties exist for command line and parent process.
3. Create the missing ones. Optimise them, or query performance will suffer
   badly at scale.

## Output shape

```sql
SELECT * FROM events
WHERE "Process Name" ILIKE '%\rundll32.exe'
  AND "Command Line" ILIKE '%comsvcs%'
  AND "Command Line" ILIKE '%MiniDump%'
  START '2026-08-01 00:00' STOP '2026-08-02 00:00'
```

Add a log source or event category constraint. Without one the search scans
every event in the time range.

## Limitations

- **Unoptimised custom properties are extracted at search time**, making
  queries that depend on them slow enough to be impractical on large
  deployments.
- **No direct equivalent for some Sigma modifiers.** `|re` maps to
  `IMATCHES`; `|base64offset` has no equivalent and must be handled manually.
- **Building blocks are usually the right deployment shape** for
  low-fidelity rules, rather than offences.
