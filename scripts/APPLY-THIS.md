# How to apply this archive

**This is an overlay, not a replacement repository.**

It contains no `rules/`, `docs/`, `mappings/`, or `examples/` directories,
because those were never uploaded. Extracting this over your repository is
safe — it will not touch your 26 rules.

```bash
cd /path/to/sigma-mitre-detection-rules
unzip -o /path/to/sigma-mitre-detection-rules-overlay.zip
rm APPLY-THIS.md
git status
```

`git status` must show nothing under `rules/`. If it does, stop.

## Contents

| Path | Change |
| --- | --- |
| `README.md` | Rewritten — full structure, badges, Mermaid diagrams |
| `CONTRIBUTING.md` | Rewritten — was 322 bytes |
| `SECURITY.md` | Expanded — was 259 bytes |
| `CHANGELOG.md` | Restructured to Keep a Changelog; false CI claim corrected |
| `requirements-dev.txt` | **Fixed** — added `sigma-cli`, `yamllint` |
| `.gitignore` | Expanded |
| `scripts/generate_coverage.py` | New — generates coverage + Navigator layer |
| `.github/workflows/` | New — validation and linting |
| `.github/ISSUE_TEMPLATE/` | New — 4 templates + chooser config |
| `.github/PULL_REQUEST_TEMPLATE.md` | New |
| `.github/CODEOWNERS` | New |
| `.github/dependabot.yml` | New |
| `.yamllint.yml`, `.markdownlint.yaml` | New |

## Run this first

```bash
python -m pip install -r requirements-dev.txt
python scripts/generate_coverage.py
```

This writes `mappings/attack-coverage.md` and
`mappings/attack-navigator-layer.json` from your actual rule tags. The README
links to both. Commit them — CI fails if they are stale.

Expect warnings about missing ATT&CK tags or duplicate UUIDs. Those are real
findings in your ruleset; fix them before tagging a release.

## Three TODO markers in README.md

Search for `TODO`. All three are screenshot placeholders or a structure check:

1. Terminal screenshot of validation output.
2. Verify `rules/` subdirectory names match your actual layout.
3. ATT&CK Navigator screenshot — upload the generated layer JSON to
   the Navigator, screenshot the heatmap, save to `docs/assets/`.

The Navigator heatmap is the highest-value visual in the repository. Do it.

## Suggested commits

```bash
git add requirements-dev.txt && \
  git commit -m "fix: add sigma-cli and yamllint to dev requirements"

git add .github/workflows/ .yamllint.yml .markdownlint.yaml && \
  git commit -m "ci: add Sigma validation and linting workflows"

git add .github/ISSUE_TEMPLATE/ .github/PULL_REQUEST_TEMPLATE.md && \
  git commit -m "docs: add issue and pull request templates"

git add .github/CODEOWNERS .github/dependabot.yml && \
  git commit -m "chore: add CODEOWNERS and Dependabot configuration"

git add scripts/generate_coverage.py mappings/ && \
  git commit -m "feat(scripts): generate ATT&CK coverage and Navigator layer"

git add CONTRIBUTING.md SECURITY.md CHANGELOG.md .gitignore && \
  git commit -m "docs: expand contribution, security, and changelog content"

git add README.md && \
  git commit -m "docs: rewrite README with architecture and coverage detail"
```

Then set the repository description and topics, and tag `v0.1.0`.
