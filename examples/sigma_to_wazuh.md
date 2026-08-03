# Converting to Wazuh

## There is no maintained backend

Sigma CLI cannot convert to Wazuh. No pySigma backend exists, so translation
is manual. This document explains how to do it correctly rather than
pretending a tool exists.

## Wazuh rule structure

Wazuh rules are XML, evaluated against decoded fields. A Sigma rule maps onto
a Wazuh rule as follows:

| Sigma | Wazuh |
| --- | --- |
| `title` | `<description>` |
| `level: critical` | `<level>15</level>` |
| `level: high` | `<level>12</level>` |
| `level: medium` | `<level>8</level>` |
| `level: low` | `<level>5</level>` |
| `level: informational` | `<level>3</level>` |
| `tags: attack.tNNNN` | `<mitre><id>TNNNN</id></mitre>` |
| `detection` selections | `<field>` elements |
| `condition` | Implicit AND within a rule; OR needs sibling rules |

## Worked example

Sigma:

```yaml
detection:
    selection_img:
        Image|endswith: '\rundll32.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'comsvcs'
            - 'MiniDump'
    condition: all of selection_*
```

Wazuh:

```xml
<group name="windows,sysmon,attack,">
  <rule id="100501" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image">rundll32\.exe$</field>
    <field name="win.eventdata.commandLine">comsvcs</field>
    <field name="win.eventdata.commandLine">MiniDump</field>
    <description>LSASS memory dump via comsvcs.dll MiniDump export</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
  </rule>
</group>
```

## Translation rules

- **Custom rule IDs must be 100000 or above.** Lower ranges are reserved and
  will be overwritten on upgrade.
- **`|endswith` becomes a regex anchored with `$`.** Escape the backslash and
  the dot.
- **`|contains|all` becomes multiple `<field>` elements** with the same name.
  They are ANDed.
- **OR conditions need separate sibling rules**, since multiple `<field>`
  elements are always ANDed.
- **Field names come from the decoder**, not from Sigma. Sysmon fields are
  under `win.eventdata.*`; Security log fields differ.

## Testing

```bash
# Verify syntax before restarting the manager
/var/ossec/bin/wazuh-logtest

# Restart to load new rules
systemctl restart wazuh-manager
```

Always test with `wazuh-logtest` first. A malformed rule file prevents the
manager from starting, which takes your monitoring offline.

## Limitations

- **Manual translation does not scale.** Budget roughly 15 to 30 minutes per
  rule including testing.
- **Regex is PCRE2 via `<field>`**, with different escaping from Sigma.
- **No equivalent to Sigma `near` or correlation rules.** Use Wazuh's own
  `frequency` and `timeframe` attributes instead.
