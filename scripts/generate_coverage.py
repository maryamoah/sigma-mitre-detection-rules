#!/usr/bin/env python3
"""Generate ATT&CK coverage artefacts from the Sigma ruleset.

Reads every rule under ``rules/`` and produces:

  1. A Markdown coverage table, for ``mappings/`` or the README.
  2. An ATT&CK Navigator layer (JSON), for visualising coverage.

Coverage counts are derived from rule ``tags`` rather than maintained by
hand, so they cannot drift away from the ruleset. Note that a technique
being covered means a rule exists for it, not that the rule is effective
against every procedure under that technique.

Usage:
    python scripts/generate_coverage.py
    python scripts/generate_coverage.py --rules-dir rules --out-dir mappings
    python scripts/generate_coverage.py --check
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: python -m pip install -r requirements-dev.txt")

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_TAGS = {
    "attack.reconnaissance": "Reconnaissance",
    "attack.resource_development": "Resource Development",
    "attack.initial_access": "Initial Access",
    "attack.execution": "Execution",
    "attack.persistence": "Persistence",
    "attack.privilege_escalation": "Privilege Escalation",
    "attack.defense_evasion": "Defense Evasion",
    "attack.credential_access": "Credential Access",
    "attack.discovery": "Discovery",
    "attack.lateral_movement": "Lateral Movement",
    "attack.collection": "Collection",
    "attack.command_and_control": "Command and Control",
    "attack.exfiltration": "Exfiltration",
    "attack.impact": "Impact",
}

# Technique names for CSV output. Extend as the ruleset grows; unknown
# techniques emit an empty name rather than a guessed one.
TECHNIQUE_NAMES = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.002": "OS Credential Dumping: Security Account Manager",
    "T1003.003": "OS Credential Dumping: NTDS",
    "T1003.006": "OS Credential Dumping: DCSync",
    "T1016": "System Network Configuration Discovery",
    "T1027": "Obfuscated Files or Information",
    "T1047": "Windows Management Instrumentation",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1082": "System Information Discovery",
    "T1087.002": "Account Discovery: Domain Account",
    "T1105": "Ingress Tool Transfer",
    "T1134": "Access Token Manipulation",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1197": "BITS Jobs",
    "T1204.002": "User Execution: Malicious File",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1021.006": "Remote Services: Windows Remote Management",
    "T1482": "Domain Trust Discovery",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1546.003": "Event Triggered Execution: WMI Event Subscription",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys",
    "T1548.002": "Abuse Elevation Control Mechanism: Bypass UAC",
    "T1555.004": "Credentials from Password Stores: Windows Credential Manager",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1562.004": "Impair Defenses: Disable or Modify System Firewall",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1098.002": "Account Manipulation: Additional Email Delegate Permissions",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1114.002": "Email Collection: Remote Email Collection",
    "T1114.003": "Email Collection: Email Forwarding Rule",
    "T1530": "Data from Cloud Storage",
    "T1556": "Modify Authentication Process",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1070.003": "Indicator Removal: Clear Command History",
    "T1071": "Application Layer Protocol",
    "T1098": "Account Manipulation",
    "T1098.004": "Account Manipulation: SSH Authorized Keys",
    "T1110": "Brute Force",
    "T1133": "External Remote Services",
    "T1136.001": "Create Account: Local Account",
    "T1190": "Exploit Public-Facing Application",
    "T1543.002": "Create or Modify System Process: Systemd Service",
    "T1546.004": "Event Triggered Execution: Unix Shell Configuration Modification",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1571": "Non-Standard Port",
    "T1595.001": "Active Scanning: Scanning IP Blocks",
}

LEVEL_ORDER = ["critical", "high", "medium", "low", "informational"]


class Rule:
    """A parsed Sigma rule with the metadata this script reports on."""

    def __init__(self, path: Path, data: dict):
        self.path = path
        self.title = data.get("title", "<untitled>")
        self.id = data.get("id")
        self.status = data.get("status", "unknown")
        self.level = data.get("level", "unknown")
        tags = data.get("tags") or []
        self.tags = [str(t).lower() for t in tags]
        logsource = data.get("logsource") or {}
        self.product = logsource.get("product", "unspecified")
        self.category = logsource.get("category", "")
        self.service = logsource.get("service", "")

    @property
    def techniques(self) -> list[str]:
        found = []
        for tag in self.tags:
            match = TECHNIQUE_RE.match(tag)
            if match:
                found.append(match.group(1).upper())
        return sorted(set(found))

    @property
    def tactics(self) -> list[str]:
        return sorted({TACTIC_TAGS[t] for t in self.tags if t in TACTIC_TAGS})

    @property
    def logsource_label(self) -> str:
        parts = [p for p in (self.product, self.category or self.service) if p]
        return " / ".join(parts) if parts else "unspecified"


def load_rules(rules_dir: Path) -> tuple[list[Rule], list[str]]:
    """Load all rules, returning parsed rules and any parse errors."""
    rules: list[Rule] = []
    errors: list[str] = []

    paths = sorted(
        p for p in rules_dir.rglob("*")
        if p.suffix.lower() in {".yml", ".yaml"}
    )

    for path in paths:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{path}: YAML parse error: {exc}")
            continue

        if not isinstance(data, dict):
            errors.append(f"{path}: not a YAML mapping")
            continue
        if "detection" not in data:
            # Not a Sigma rule -- likely a config or filter file.
            continue

        rules.append(Rule(path, data))

    return rules, errors


def audit(rules: list[Rule]) -> list[str]:
    """Report metadata problems that weaken coverage reporting."""
    problems: list[str] = []
    seen_ids: dict[str, Path] = {}

    for rule in rules:
        if not rule.id:
            problems.append(f"{rule.path}: missing 'id'")
        elif rule.id in seen_ids:
            problems.append(
                f"{rule.path}: duplicate id {rule.id} "
                f"(also in {seen_ids[rule.id]})"
            )
        else:
            seen_ids[rule.id] = rule.path

        if not rule.techniques:
            problems.append(f"{rule.path}: no attack.tNNNN technique tag")
        if not rule.tactics:
            problems.append(f"{rule.path}: no ATT&CK tactic tag")

    return problems


def markdown_report(rules: list[Rule], out_dir: Path) -> str:
    """Build the Markdown coverage report.

    Rule links are written relative to ``out_dir``, since the report lives
    in ``mappings/`` rather than at the repository root.
    """
    by_tactic: dict[str, list[Rule]] = defaultdict(list)
    for rule in rules:
        for tactic in rule.tactics:
            by_tactic[tactic].append(rule)

    technique_counts = Counter(t for r in rules for t in r.techniques)
    logsource_counts = Counter(r.logsource_label for r in rules)
    status_counts = Counter(r.status for r in rules)
    level_counts = Counter(r.level for r in rules)

    out: list[str] = []
    out.append("# ATT&CK Coverage")
    out.append("")
    out.append(
        "Generated by `scripts/generate_coverage.py`. Do not edit by hand."
    )
    out.append("")
    out.append(f"- Generated: {date.today().isoformat()}")
    out.append(f"- Rules: {len(rules)}")
    out.append(f"- Distinct techniques: {len(technique_counts)}")
    out.append(f"- Tactics represented: {len(by_tactic)} of {len(TACTIC_TAGS)}")
    out.append("")
    out.append(
        "> Coverage means a rule exists for a technique. It does not mean "
        "every procedure under that technique is detected."
    )
    out.append("")

    out.append("## Coverage by tactic")
    out.append("")
    out.append("| Tactic | Rules | Techniques |")
    out.append("| --- | ---: | ---: |")
    for tactic in TACTIC_TAGS.values():
        tactic_rules = by_tactic.get(tactic, [])
        techs = {t for r in tactic_rules for t in r.techniques}
        count = len(tactic_rules) if tactic_rules else 0
        out.append(f"| {tactic} | {count} | {len(techs)} |")
    out.append("")

    out.append("## Coverage by log source")
    out.append("")
    out.append("| Log source | Rules |")
    out.append("| --- | ---: |")
    for label, count in sorted(logsource_counts.items(), key=lambda x: -x[1]):
        out.append(f"| {label} | {count} |")
    out.append("")

    out.append("## Rule maturity")
    out.append("")
    out.append("| Status | Rules |")
    out.append("| --- | ---: |")
    for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        out.append(f"| {status} | {count} |")
    out.append("")

    out.append("| Severity | Rules |")
    out.append("| --- | ---: |")
    ordered = sorted(
        level_counts.items(),
        key=lambda x: LEVEL_ORDER.index(x[0]) if x[0] in LEVEL_ORDER else 99,
    )
    for level, count in ordered:
        out.append(f"| {level} | {count} |")
    out.append("")

    out.append("## Rule inventory")
    out.append("")
    out.append("| Rule | Log source | Techniques | Level | Status |")
    out.append("| --- | --- | --- | --- | --- |")
    for rule in sorted(rules, key=lambda r: str(r.path)):
        techs = ", ".join(rule.techniques) or "—"
        rel = os.path.relpath(rule.path.resolve(), out_dir.resolve())
        rel = Path(rel).as_posix()
        out.append(
            f"| [{rule.title}]({rel}) | {rule.logsource_label} | "
            f"{techs} | {rule.level} | {rule.status} |"
        )
    out.append("")

    return "\n".join(out)


def navigator_layer(rules: list[Rule], name: str) -> dict:
    """Build an ATT&CK Navigator layer scored by rule count."""
    counts = Counter(t for r in rules for t in r.techniques)
    max_count = max(counts.values()) if counts else 1

    techniques = []
    for tech, count in sorted(counts.items()):
        matching = [r.title for r in rules if tech in r.techniques]
        techniques.append({
            "techniqueID": tech,
            "score": count,
            "enabled": True,
            "comment": "; ".join(matching),
            "metadata": [{"name": "rules", "value": str(count)}],
        })

    return {
        "name": name,
        "versions": {"attack": "17", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            "Detection coverage generated from the Sigma ruleset. "
            "Scores reflect the number of rules mapped to each technique."
        ),
        "filters": {"platforms": [
            "Windows", "Linux", "macOS", "IaaS", "SaaS", "Office Suite",
        ]},
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#e8f5e9", "#2e7d32"],
            "minValue": 0,
            "maxValue": max_count,
        },
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
    }


def csv_mapping(rules: list[Rule]) -> str:
    """Build the flat rule-to-technique mapping CSV."""
    import csv
    import io

    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([
        "Rule Name", "Technique ID", "Technique Name",
        "Tactic", "Severity", "Platform", "Status", "File",
    ])

    for rule in sorted(rules, key=lambda r: str(r.path)):
        techniques = rule.techniques or ["—"]
        tactics = "; ".join(rule.tactics) or "—"
        for tech in techniques:
            writer.writerow([
                rule.title,
                tech,
                TECHNIQUE_NAMES.get(tech, ""),
                tactics,
                rule.level,
                rule.product,
                rule.status,
                rule.path.as_posix(),
            ])

    return buf.getvalue()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-dir", default="rules", type=Path)
    parser.add_argument("--out-dir", default="mappings", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report metadata problems and exit non-zero; write nothing.",
    )
    args = parser.parse_args()

    if not args.rules_dir.is_dir():
        print(f"error: no such directory: {args.rules_dir}", file=sys.stderr)
        return 2

    rules, errors = load_rules(args.rules_dir)

    for err in errors:
        print(f"error: {err}", file=sys.stderr)

    if not rules:
        print("error: no Sigma rules found", file=sys.stderr)
        return 2

    problems = audit(rules)

    if args.check:
        for problem in problems:
            print(f"warning: {problem}", file=sys.stderr)
        print(f"{len(rules)} rules checked, {len(problems)} problems found")
        return 1 if (problems or errors) else 0

    for problem in problems:
        print(f"warning: {problem}", file=sys.stderr)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    md_path = args.out_dir / "attack-coverage.md"
    md_path.write_text(markdown_report(rules, args.out_dir), encoding="utf-8")
    print(f"wrote {md_path}")

    csv_path = args.out_dir / "mitre_attack_mapping.csv"
    csv_path.write_text(csv_mapping(rules), encoding="utf-8")
    print(f"wrote {csv_path}")

    layer_path = args.out_dir / "attack-navigator-layer.json"
    layer = navigator_layer(rules, "Sigma MITRE Detection Rules")
    layer_path.write_text(
        json.dumps(layer, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {layer_path}")

    print(
        f"{len(rules)} rules, "
        f"{len({t for r in rules for t in r.techniques})} techniques"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
