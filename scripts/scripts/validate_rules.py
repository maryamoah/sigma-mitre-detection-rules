#!/usr/bin/env python3
"""Validate Sigma rules against this repository's conventions.

This complements `sigma check`, which validates the Sigma specification.
The checks here enforce repository conventions the specification does not
cover: filename style, UUID uniqueness, honest false-positive documentation,
ATT&CK tag correctness, and reference quality.

Exit codes:
    0   all rules pass
    1   one or more errors
    2   invocation problem (no rules directory, unreadable files)

Usage:
    python scripts/validate_rules.py
    python scripts/validate_rules.py --rules-dir rules --strict
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: python -m pip install -r requirements-dev.txt")

REQUIRED_FIELDS = [
    "title", "id", "status", "description", "references",
    "author", "date", "logsource", "detection", "falsepositives",
    "level", "tags",
]

VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
VALID_LEVEL = {"informational", "low", "medium", "high", "critical"}

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
FILENAME_RE = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)*\.yml$")
TECHNIQUE_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

TACTIC_TAGS = {
    "attack.reconnaissance", "attack.resource_development",
    "attack.initial_access", "attack.execution", "attack.persistence",
    "attack.privilege_escalation", "attack.defense_evasion",
    "attack.credential_access", "attack.discovery",
    "attack.lateral_movement", "attack.collection",
    "attack.command_and_control", "attack.exfiltration", "attack.impact",
}

# Placeholder false positives that indicate the author did not investigate.
LAZY_FALSE_POSITIVES = {
    "unknown", "none", "n/a", "na", "no", "tbd", "todo",
    "not applicable", "unlikely",
}

# Aggregator and content-farm domains are not primary research.
WEAK_REFERENCE_HOSTS = ("medium.com/@", "pinterest.", "quora.", "chatgpt.")


class Finding:
    __slots__ = ("path", "level", "message")

    def __init__(self, path: Path, level: str, message: str):
        self.path = path
        self.level = level
        self.message = message

    def __str__(self) -> str:
        return f"{self.level}: {self.path}: {self.message}"


def check_rule(path: Path, data: dict) -> list[Finding]:
    """Validate a single parsed rule."""
    out: list[Finding] = []

    def err(msg: str) -> None:
        out.append(Finding(path, "error", msg))

    def warn(msg: str) -> None:
        out.append(Finding(path, "warning", msg))

    # --- Required fields -------------------------------------------------
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] in (None, "", [], {}):
            err(f"missing required field '{field}'")

    # --- Filename --------------------------------------------------------
    if not FILENAME_RE.match(path.name):
        err(f"filename must be lowercase snake_case ending .yml: {path.name}")

    # --- Identifier ------------------------------------------------------
    rule_id = data.get("id")
    if rule_id and not UUID_RE.match(str(rule_id)):
        err(f"id is not a valid UUIDv4: {rule_id}")

    # --- Title -----------------------------------------------------------
    title = data.get("title", "")
    if isinstance(title, str) and title:
        if len(title) > 120:
            err(f"title exceeds 120 characters ({len(title)})")
        elif len(title) > 70:
            warn(f"title is long ({len(title)} chars); aim for under 70")
        if title.endswith("."):
            err("title must not end with a full stop")
        if title[0].islower():
            warn("title should start with a capital letter")

    # --- Status and level ------------------------------------------------
    status = data.get("status")
    if status and status not in VALID_STATUS:
        err(f"invalid status '{status}'; expected one of {sorted(VALID_STATUS)}")

    level = data.get("level")
    if level and level not in VALID_LEVEL:
        err(f"invalid level '{level}'; expected one of {sorted(VALID_LEVEL)}")

    # --- Description -----------------------------------------------------
    desc = data.get("description", "")
    if isinstance(desc, str) and desc and len(desc.strip()) < 40:
        warn("description is very short; explain what fires and why it matters")

    # --- Date ------------------------------------------------------------
    for field in ("date", "modified"):
        value = data.get(field)
        if value is None:
            continue
        text = value.isoformat() if hasattr(value, "isoformat") else str(value)
        if not DATE_RE.match(text):
            err(f"{field} must be ISO format YYYY-MM-DD, got '{text}'")
        else:
            try:
                datetime.strptime(text, "%Y-%m-%d")
            except ValueError:
                err(f"{field} is not a real date: {text}")

    # --- References ------------------------------------------------------
    refs = data.get("references") or []
    if isinstance(refs, list):
        for ref in refs:
            ref_text = str(ref)
            if not ref_text.startswith(("http://", "https://")):
                warn(f"reference is not a URL: {ref_text[:60]}")
            if any(h in ref_text for h in WEAK_REFERENCE_HOSTS):
                warn(f"reference may not be primary research: {ref_text[:60]}")

    # --- Log source ------------------------------------------------------
    logsource = data.get("logsource")
    if isinstance(logsource, dict):
        if not any(k in logsource for k in ("product", "category", "service")):
            err("logsource needs at least one of product, category, service")
    elif logsource is not None:
        err("logsource must be a mapping")

    # --- Detection -------------------------------------------------------
    detection = data.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            err("detection block has no condition")
        else:
            condition = str(detection["condition"])
            named = [k for k in detection if k != "condition"]
            if not named:
                err("detection block has a condition but no selections")
            for key in named:
                bare = key.split("|")[0]
                referenced = (
                    bare in condition
                    or any(
                        bare.startswith(p.rstrip("*"))
                        for p in re.findall(r"[\w]+\*", condition)
                    )
                )
                if not referenced:
                    warn(f"selection '{key}' is not referenced in the condition")
    elif detection is not None:
        err("detection must be a mapping")

    # --- False positives -------------------------------------------------
    fps = data.get("falsepositives")
    if isinstance(fps, str):
        err("falsepositives must be a list, not a string")
        fps = [fps]
    if isinstance(fps, list):
        for fp in fps:
            if str(fp).strip().lower().rstrip(".") in LAZY_FALSE_POSITIVES:
                err(
                    f"falsepositives entry '{fp}' is a placeholder; "
                    "document realistic benign sources"
                )
            elif len(str(fp).strip()) < 15:
                warn(f"falsepositives entry is very terse: '{fp}'")

    # --- Tags ------------------------------------------------------------
    tags = data.get("tags") or []
    if isinstance(tags, list):
        lowered = [str(t).lower() for t in tags]
        techniques = [t for t in lowered if TECHNIQUE_RE.match(t)]
        tactics = [t for t in lowered if t in TACTIC_TAGS]

        if not techniques:
            err("no ATT&CK technique tag (expected attack.tNNNN[.NNN])")
        if not tactics:
            err("no ATT&CK tactic tag")

        for tag in lowered:
            if tag.startswith("attack.t") and not TECHNIQUE_RE.match(tag):
                err(f"malformed technique tag '{tag}'")
            if tag != str(tag).lower():
                err(f"tags must be lowercase: '{tag}'")
            if "attack.T" in str(tag):
                err(f"technique tag must be lowercase: '{tag}'")

        if len(set(lowered)) != len(lowered):
            err("duplicate tags")

    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules-dir", default="rules", type=Path)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Print the summary only.",
    )
    args = parser.parse_args()

    if not args.rules_dir.is_dir():
        print(f"error: no such directory: {args.rules_dir}", file=sys.stderr)
        return 2

    paths = sorted(
        p for p in args.rules_dir.rglob("*")
        if p.suffix.lower() in {".yml", ".yaml"}
    )
    if not paths:
        print(f"error: no rules found under {args.rules_dir}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    ids: dict[str, list[Path]] = defaultdict(list)
    titles: dict[str, list[Path]] = defaultdict(list)
    rule_count = 0

    for path in paths:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            findings.append(Finding(path, "error", f"YAML parse error: {exc}"))
            continue

        if not isinstance(data, dict):
            findings.append(Finding(path, "error", "not a YAML mapping"))
            continue
        if "detection" not in data:
            continue  # configuration or filter file, not a rule

        rule_count += 1
        findings.extend(check_rule(path, data))

        if data.get("id"):
            ids[str(data["id"]).lower()].append(path)
        if data.get("title"):
            titles[str(data["title"]).strip().lower()].append(path)

    # --- Cross-rule uniqueness ------------------------------------------
    for rule_id, owners in ids.items():
        if len(owners) > 1:
            listed = ", ".join(str(p) for p in owners)
            findings.append(
                Finding(owners[0], "error", f"duplicate id {rule_id}: {listed}")
            )
    for title, owners in titles.items():
        if len(owners) > 1:
            listed = ", ".join(str(p) for p in owners)
            findings.append(
                Finding(owners[0], "warning", f"duplicate title: {listed}")
            )

    errors = [f for f in findings if f.level == "error"]
    warnings = [f for f in findings if f.level == "warning"]

    if not args.quiet:
        for finding in sorted(findings, key=lambda f: (str(f.path), f.level)):
            stream = sys.stderr if finding.level == "error" else sys.stdout
            print(finding, file=stream)

    print(
        f"\n{rule_count} rules validated | "
        f"{len(errors)} errors | {len(warnings)} warnings"
    )

    if errors:
        return 1
    if warnings and args.strict:
        print("strict mode: warnings treated as errors")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
