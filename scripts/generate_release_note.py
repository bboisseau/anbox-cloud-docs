#!/usr/bin/env python3
"""
Generate an Anbox Cloud release note file.

Usage:
    python3 scripts/generate_release_note.py --version 1.29.0
    python3 scripts/generate_release_note.py --version 1.29.0 --input scripts/release_inputs/1.29.0.yaml
    python3 scripts/generate_release_note.py --version 1.29.0 --dry-run
    python3 scripts/generate_release_note.py --version 1.29.0 --overwrite

The script will:
  1. Read scripts/release_inputs/<version>.yaml for features, CVEs, deprecations,
     removed functionality, and known issues.
  2. Fetch fixed bugs for that milestone from the Launchpad REST API (no auth needed).
  3. Write reference/release-notes/<version>.md with the result.

Run `make release-note VERSION=1.29.0` as a shortcut.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ---------------------------------------------------------------------------
# Paths (all relative to repo root)
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent
RELEASE_NOTES_DIR = REPO_ROOT / "reference" / "release-notes"
RELEASE_INPUTS_DIR = Path(__file__).parent / "release_inputs"

# ---------------------------------------------------------------------------
# Launchpad
# ---------------------------------------------------------------------------
LP_API_BASE = "https://api.launchpad.net/1.0"
LP_OPEN_BUGS_URL = (
    "https://bugs.launchpad.net/anbox-cloud/+bugs?"
    "field.searchtext=&orderby=-importance"
    "&field.status%3Alist=NEW&field.status%3Alist=CONFIRMED"
    "&field.status%3Alist=TRIAGED&field.status%3Alist=INPROGRESS"
    "&field.status%3Alist=INCOMPLETE_WITH_RESPONSE"
    "&field.status%3Alist=INCOMPLETE_WITHOUT_RESPONSE"
    "&assignee_option=any&field.assignee=&field.bug_reporter="
    "&field.bug_commenter=&field.subscriber=&field.structural_subscriber="
    "&field.tag=&field.tags_combinator=ANY&field.has_cve.used="
    "&field.omit_dupes.used=&field.omit_dupes=on&field.affects_me.used="
    "&field.has_patch.used=&field.has_branches.used=&field.has_branches=on"
    "&field.has_no_branches.used=&field.has_no_branches=on"
    "&field.has_blueprints.used=&field.has_blueprints=on"
    "&field.has_no_blueprints.used=&field.has_no_blueprints=on&search=Search"
)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _fetch_json(url: str, retries: int = 3) -> dict | None:
    """GET a URL and return the parsed JSON, or None on 404."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code in (429, 503) and attempt < retries - 1:
                wait = 2**attempt
                print(f"    Rate-limited ({exc.code}). Retrying in {wait}s…")
                time.sleep(wait)
                continue
            raise
        except urllib.error.URLError as exc:
            if attempt < retries - 1:
                print(f"    Network error: {exc}. Retrying…")
                time.sleep(2)
                continue
            raise
    return None


# ---------------------------------------------------------------------------
# Launchpad bug fetcher
# ---------------------------------------------------------------------------

def fetch_launchpad_bugs(version: str) -> list[dict]:
    """Return a list of bug dicts fixed in *version* milestone on Launchpad.

    Uses the Launchpad REST API's ``searchTasks`` operation on the anbox-cloud
    project, filtered to the milestone with statuses "Fix Released" and
    "Fix Committed".  No authentication is required for public bugs.
    """
    print(f"  Fetching Launchpad bugs for milestone '{version}'…")

    # Build the initial URL manually so multi-valued 'status' works correctly.
    first_url = (
        f"{LP_API_BASE}/anbox-cloud?"
        f"ws.op=searchTasks"
        f"&milestone={urllib.parse.quote(f'{LP_API_BASE}/anbox-cloud/+milestone/{version}', safe='')}"
        f"&status=Fix+Released&status=Fix+Committed"
    )

    bugs: list[dict] = []
    url: str | None = first_url
    while url:
        data = _fetch_json(url)
        if not data:
            break

        entries = data.get("entries", [])
        if not entries and not bugs:
            print(f"  ⚠  No fixed bugs found for milestone '{version}' on Launchpad.")
            return []

        for task in entries:
            title = task.get("title", "")

            # Bug number from title: 'Bug #NNNN in project: "description"'
            num_match = re.search(r"Bug #(\d+) in", title)
            bug_num = num_match.group(1) if num_match else ""

            # web_link is the canonical bug URL (e.g. https://bugs.launchpad.net/…/+bug/NNNN)
            web_link = task.get("web_link") or (
                f"https://bugs.launchpad.net/anbox-cloud/+bug/{bug_num}" if bug_num else ""
            )

            # Description from title after the colon
            desc_match = re.search(r':\s*"(.+)"$', title)
            description = desc_match.group(1) if desc_match else "Private bug"

            bugs.append(
                {
                    "number": bug_num,
                    "description": description,
                    "url": web_link,
                    "status": task.get("status", ""),
                    "importance": task.get("importance", ""),
                }
            )

        url = data.get("next_collection_link")

    print(f"  Found {len(bugs)} bug(s).")
    return bugs


# ---------------------------------------------------------------------------
# YAML input loader
# ---------------------------------------------------------------------------

def load_input(path: Path) -> dict:
    """Load the YAML release input file, returning an empty dict on failure."""
    if not path.exists():
        return {}
    if not HAS_YAML:
        print(
            "  ⚠  PyYAML is not installed. Input file will be ignored.\n"
            "     Install it with:  pip install pyyaml"
        )
        return {}
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


# ---------------------------------------------------------------------------
# Markdown renderers
# ---------------------------------------------------------------------------

def _render_features(features: list[dict]) -> str:
    if not features:
        return "<!-- TODO: describe new features -->\n"
    parts = []
    for feat in features:
        title = feat.get("title", "Feature")
        body = feat.get("body", "").strip()
        parts.append(f"### {title}\n\n{body}\n")
    return "\n".join(parts)


def _render_cves(cves: list[dict]) -> str:
    if not cves:
        return ""
    rows = ["| CVE | Affected components |", "|-----|-------------------|"]
    for cve in cves:
        cve_id = cve.get("id", "CVE-XXXX-XXXXX")
        url = cve.get("url", f"https://www.cve.org/CVERecord?id={cve_id}")
        component = cve.get("component", "TODO")
        rows.append(f"| [{cve_id}]({url}) | {component} |")
    return "\n".join(rows)


def _render_bugs(lp_bugs: list[dict], extra_bugs: list[dict]) -> str:
    all_bugs = list(lp_bugs) + list(extra_bugs or [])
    if not all_bugs:
        return "There are no bug fixes in this release."
    lines = []
    for bug in all_bugs:
        num = bug.get("number", "")
        url = bug.get("url", "")
        desc = bug.get("description", "Private bug")
        prefix = f"[LP {num}]({url}) " if num else ""
        lines.append(f"* {prefix}{desc}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate(version: str, data: dict, lp_bugs: list[dict]) -> str:
    """Return the full release note markdown as a string."""
    minor = version.split(".")[-1] == "0"
    release_kind = "minor" if minor else "patch"

    # Section: new features
    features_md = _render_features(data.get("features", []))

    # Section: removed functionality
    removed = (
        data.get("removed", "There are no removed functionalities in this release.").strip()
    )

    # Section: deprecations (optional)
    deprecations = (data.get("deprecations") or "").strip()

    # Section: known issues
    known_issues_extra = (data.get("known_issues_extra") or "").strip()
    known_issues_md = f"See our [open bugs in Launchpad]({LP_OPEN_BUGS_URL})."
    if known_issues_extra:
        known_issues_md += f"\n\n{known_issues_extra}"

    # Section: CVEs (optional)
    cves = data.get("cves") or []
    cves_md = _render_cves(cves)

    # Section: bug fixes
    extra_bugs = data.get("extra_bugs") or []
    bugs_md = _render_bugs(lp_bugs, extra_bugs)

    # Section: upgrade instructions (optional)
    upgrade_note = (data.get("upgrade_note") or "").strip()
    upgrade_base = (
        f"See [How to upgrade Anbox Cloud](https://documentation.ubuntu.com/anbox-cloud/"
        f"en/latest/howto/update/upgrade-anbox/#howto-upgrade-anbox-cloud) and "
        f"[How to upgrade the Anbox Cloud Appliance](https://documentation.ubuntu.com/"
        f"anbox-cloud/en/latest/howto/update/upgrade-appliance/#howto-upgrade-appliance) "
        f"for instructions on how to update your Anbox Cloud deployment to the {version} release."
    )
    if upgrade_note:
        upgrade_base = f"{upgrade_base}\n\n{upgrade_note}"

    # Assemble
    doc: list[str] = [
        "---",
        "orphan: true",
        "---",
        f"# {version}",
        "",
        f"These release notes cover new features and changes in Anbox Cloud {version}.",
        "",
        f"Anbox Cloud {version} is a {release_kind} release. "
        "To understand minor and patch releases, see "
        "[Release notes](https://documentation.ubuntu.com/anbox-cloud/en/latest/"
        "reference/release-notes/release-notes).",
        "",
        "Please see [Component versions](https://documentation.ubuntu.com/anbox-cloud/"
        "en/latest/reference/component-versions/) for a list of updated components.",
        "",
        "## Requirements",
        "",
        "See the [Requirements](https://documentation.ubuntu.com/anbox-cloud/en/latest/"
        "reference/requirements/) for details on general and deployment specific requirements "
        "to run Anbox Cloud.",
        "",
        "## New features & improvements",
        "",
        features_md,
        "## Removed functionality",
        "",
        removed,
        "",
    ]

    if deprecations:
        doc += [
            "## Deprecations",
            "",
            deprecations,
            "",
        ]

    doc += [
        "## Known issues",
        "",
        known_issues_md,
        "",
    ]

    if cves_md:
        doc += [
            "## CVEs",
            f"The fixes for the following CVEs are included with the {version} release:",
            "",
            cves_md,
            "",
        ]

    doc += [
        "## Bug fixes",
        "",
        bugs_md,
        "",
        "## Upgrade instructions",
        "",
        upgrade_base,
        "",
    ]

    return "\n".join(doc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an Anbox Cloud release note.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", required=True, metavar="X.Y.Z",
                        help="Release version, e.g. 1.29.0")
    parser.add_argument("--input", metavar="FILE",
                        help="YAML input file (default: scripts/release_inputs/<version>.yaml)")
    parser.add_argument("--output", metavar="FILE",
                        help="Output .md file (default: reference/release-notes/<version>.md)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the result instead of writing to disk")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite the output file if it already exists")
    parser.add_argument("--no-launchpad", action="store_true",
                        help="Skip Launchpad bug fetching")
    args = parser.parse_args()

    version = args.version

    input_path = Path(args.input) if args.input else RELEASE_INPUTS_DIR / f"{version}.yaml"
    output_path = Path(args.output) if args.output else RELEASE_NOTES_DIR / f"{version}.md"

    print(f"Generating release note for Anbox Cloud {version}")
    print(f"  Input  : {input_path}")
    print(f"  Output : {output_path}")

    if output_path.exists() and not args.overwrite and not args.dry_run:
        print(f"\nERROR: {output_path} already exists. Pass --overwrite to replace it.")
        sys.exit(1)

    data = load_input(input_path)
    if not data:
        print(
            f"  NOTE: No input file found at {input_path}.\n"
            f"        Copy scripts/release_inputs/template.yaml to\n"
            f"        {input_path} and fill it in, then re-run with --overwrite."
        )

    lp_bugs: list[dict] = []
    if not args.no_launchpad:
        try:
            lp_bugs = fetch_launchpad_bugs(version)
        except Exception as exc:  # noqa: BLE001
            print(f"  ⚠  Launchpad fetch failed: {exc}\n     Use --no-launchpad to skip.")

    print("  Building markdown…")
    content = generate(version, data, lp_bugs)

    if args.dry_run:
        print("\n" + "─" * 70)
        print(content)
        print("─" * 70)
        print("\nDry run – no files written.")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    print(f"\n✓  Written to {output_path}")
    print(
        "\nNext steps:\n"
        f"  1. Fill in {input_path}\n"
        f"     (start from scripts/release_inputs/template.yaml)\n"
        f"  2. Re-run with --overwrite to regenerate.\n"
        f"  3. Review {output_path}"
    )


if __name__ == "__main__":
    main()
