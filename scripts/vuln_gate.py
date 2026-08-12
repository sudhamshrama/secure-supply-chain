#!/usr/bin/env python3
"""Vulnerability gate with a TIME-BOXED allowlist.

Why this exists instead of `grype --fail-on high`
--------------------------------------------------
A naive gate fails the build on any HIGH or CRITICAL finding. It gets switched
off within a week, because most findings in a container image cannot be acted
on by the team that owns the application. Measured on this project's own image:

    181 total findings
      7 fixable
      0 fixable after removing pip and patching one transitive dependency
    ... except one.

So the gate blocks on **fixable** findings only. Everything else is reported
and tracked, never blocking. An alarm that fires on things nobody can fix is
an alarm people learn to ignore.

The harder problem: "fixable" is a lie sometimes
------------------------------------------------
grype marks a finding `fixed` when the advisory names a fix version. It does
not check that the version is shippable. Real example from this image:

    CVE-2026-15308  python 3.13.15  fix = 3.15.0     <- does not exist as a
                                                        stable release
    CVE-2025-15367  python 3.13.15  fix = 3.15.0a6   <- an ALPHA release

Both are "fixable". Neither can be fixed. Upgrading to python 3.14 was tested
and carries the identical findings. The only honest options are to ship an
alpha interpreter or to accept the risk with a documented expiry date.

So the allowlist entries EXPIRE. An expired entry fails the build exactly like
an unlisted vulnerability. That is the whole design: a permanent exception is
indistinguishable from having no gate, so exceptions are forced back for review
on a date somebody chose deliberately.

Usage
-----
    grype <image> -o json > scan.json
    python scripts/vuln_gate.py scan.json policy/vuln-allowlist.json
"""

from __future__ import annotations

import json
import sys
from datetime import date

BLOCKING_SEVERITIES = {"High", "Critical"}


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def fixable_blocking(scan: dict) -> list[dict]:
    """Findings that are both severe enough and actually fixable."""
    out = []
    for match in scan.get("matches", []):
        vuln = match.get("vulnerability", {})
        if vuln.get("severity") not in BLOCKING_SEVERITIES:
            continue
        if (vuln.get("fix") or {}).get("state") != "fixed":
            continue
        artifact = match.get("artifact", {})
        out.append({
            "id": vuln.get("id"),
            "severity": vuln.get("severity"),
            "package": artifact.get("name"),
            "version": artifact.get("version"),
            "fix": ", ".join((vuln.get("fix") or {}).get("versions") or []),
        })
    return out


def main(scan_path: str, allowlist_path: str) -> int:
    scan = load(scan_path)
    allowlist = load(allowlist_path)
    today = date.today()

    entries = {e["id"]: e for e in allowlist.get("allow", [])}
    findings = fixable_blocking(scan)

    blocking: list[dict] = []
    accepted: list[tuple[dict, dict]] = []
    expired: list[tuple[dict, dict]] = []

    for finding in findings:
        entry = entries.get(finding["id"])
        if entry is None:
            blocking.append(finding)
            continue
        if date.fromisoformat(entry["expires"]) < today:
            expired.append((finding, entry))
        else:
            accepted.append((finding, entry))

    total = len(scan.get("matches", []))
    print(f"scanned: {total} findings, {len(findings)} fixable {'/'.join(sorted(BLOCKING_SEVERITIES))}")
    print()

    for finding, entry in accepted:
        left = (date.fromisoformat(entry["expires"]) - today).days
        print(f"  ACCEPTED  {finding['id']:20} {finding['package']} {finding['version']}")
        print(f"            expires {entry['expires']} ({left}d left) · owner {entry['owner']}")
        print(f"            {entry['reason']}")

    for finding, entry in expired:
        print(f"  EXPIRED   {finding['id']:20} {finding['package']} {finding['version']}")
        print(f"            exception lapsed {entry['expires']} · owner {entry['owner']}")
        print("            Re-review it: fix, or set a new date with a new reason.")

    for finding in blocking:
        print(f"  BLOCKING  {finding['id']:20} {finding['severity']:8} "
              f"{finding['package']} {finding['version']} -> fix {finding['fix']}")

    # An allowlist entry that no longer matches anything is dead config. Not
    # fatal — it usually means somebody fixed the vulnerability, which is the
    # outcome we wanted — but it should not sit there forever.
    matched_ids = {f["id"] for f in findings}
    for stale in set(entries) - matched_ids:
        print(f"  STALE     {stale:20} allowlisted but no longer present — remove it")

    print()
    if blocking or expired:
        print(f"FAIL: {len(blocking)} unreviewed, {len(expired)} expired")
        return 1

    print(f"PASS: {len(accepted)} accepted exception(s), 0 unreviewed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
