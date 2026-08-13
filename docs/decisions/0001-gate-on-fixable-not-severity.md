# ADR 0001 — The vulnerability gate blocks on *fixable*, not on severity

**Status:** Accepted
**Date:** 2026-08-12

## Context

The obvious gate is `grype --fail-on high` (or Trivy's equivalent): fail the
build if any HIGH or CRITICAL vulnerability is present.

Measured on this project's own image:

```
181 findings total
  7 fixable
```

Every CRITICAL was in `libc6` or `perl-base` in the Debian base image, marked
**"won't fix"** by the distribution. No action by this repository's owner can
clear them.

A gate that blocks on all 181 blocks every build, forever, on things nobody
will ever patch. It gets disabled within a week — and a disabled gate is worse
than no gate, because the pipeline still *claims* to scan.

## Decision

The gate (`scripts/vuln_gate.py`) blocks on findings that are **HIGH or
CRITICAL _and_ marked fixable**. Everything else is reported and never blocks.

Exceptions are declared in `policy/vuln-allowlist.json` and every entry
requires a reason, a named owner, and an **expiry date**.

## Why exceptions expire

`fixed` in a vulnerability database means "an advisory names a fix version".
It does not mean the fix is shippable. On this image:

```
CVE-2026-15308   python 3.13.15   fix = 3.15.0     not a stable release
CVE-2025-15367   python 3.13.15   fix = 3.15.0a6   an ALPHA release
```

Docker Hub publishes `3.15.0a5` through `a8` and no stable 3.15. Building on
`python:3.14-slim` was tested and carries the identical finding, so upgrading
the base does not help. The honest options are to ship an alpha interpreter or
to accept the risk and record why.

An open-ended exception is indistinguishable from having no gate, so entries
lapse. An expired entry fails the build exactly like an unreviewed
vulnerability, which forces the decision back in front of a human on a date
somebody chose deliberately.

## Consequences

- The allowlist is a small maintenance burden by design.
- Findings marked "won't fix" never block, which means a genuinely dangerous
  unfixable vulnerability would not stop a deploy. Accepted: the alternative
  is a gate nobody keeps switched on. Compensating control: the full scan is
  published as a build artifact every run.
- Findings that CAN be fixed must be fixed rather than listed. Two were:
  `msgpack` (vendored inside pip — deleted pip from the runtime) and
  `starlette` (a transitive dep of fastapi — pinned explicitly). Neither could
  have been fixed by pinning a declared dependency.

## Verified

All four behaviours are exercised: accepted → pass, expired → fail,
unreviewed → fail, stale entry → warn.
