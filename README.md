# secure-supply-chain

A container supply chain where **the cluster refuses to run anything it cannot
cryptographically verify**.

Build → SBOM → vulnerability gate → keyless signature → SBOM attestation →
SLSA provenance → admission control. No private key exists anywhere in the
system.

```
signed + attested image      →  ADMITTED, pod Running, serving traffic
unsigned image, same repo    →  REJECTED: "no signatures found"
```

The application (`checkout-api`, a three-endpoint FastAPI service) is
deliberately trivial. Everything interesting is the pipeline around it.

---

## What this demonstrates

| | |
|---|---|
| **SBOM** | syft, CycloneDX, published as a signed attestation |
| **Vulnerability gating** | grype + a custom gate that blocks on *fixable* findings, with **expiring** exceptions |
| **Keyless signing** | cosign + Fulcio + Rekor — no key to steal, rotate, or leak |
| **Provenance** | SLSA build provenance attestation |
| **Admission control** | Kyverno `verifyImages`, `Enforce`, `failurePolicy: Fail`, `mutateDigest` |
| **Policy as code** | conftest/OPA on the rendered chart, with **14 unit tests for the policies themselves** |
| **Helm** | chart with a hardened pod spec |
| **Image hardening** | digest-pinned base, non-root UID, no package manager in the runtime |

Everything runs locally on kind at **$0** — GHCR, Sigstore's public good
instance and GitHub Actions are free for public repositories.

---

## Try it

```bash
make demo        # kind cluster + Kyverno + policies + enforcement proof
make gate        # build, scan, and run the vulnerability gate
```

`make verify` asserts the negative path and **fails loudly if an unsigned image
is ever admitted**. A signing pipeline nobody has watched reject something is a
pipeline nobody should trust.

---

## The vulnerability gate blocks on *fixable* findings

Not `grype --fail-on high`. Measured on this image:

```
181 findings total
  7 fixable
  1 fixable HIGH/CRITICAL after hardening
```

A gate that blocks on all 181 gets switched off within a week, because almost
none of them are actionable by the team that owns the application. So the gate
blocks on **fixable** findings and reports the rest.

**And "fixable" is sometimes false.** The one remaining finding is
`CVE-2026-15308` in CPython. grype reports `fix = 3.15.0` — a version that
exists on Docker Hub only as `3.15.0a5`…`a8` **alphas**. `python:3.14-slim` was
tested and carries the identical finding. Another advisory on the same image
lists its fix as `3.15.0a6`: the scanner is recommending an alpha interpreter
for production.

So exceptions **expire**:

```json
{
  "id": "CVE-2026-15308",
  "owner": "sudhamsh",
  "expires": "2026-11-12",
  "reason": "fix=3.15.0 is not a stable CPython release ..."
}
```

An expired entry fails the build exactly like an unreviewed vulnerability,
because **a permanent exception is indistinguishable from having no gate**.

Two findings were *fixed* rather than allowlisted, and neither could have been
fixed by a version pin:

- `msgpack` — vendored **inside pip**, at `pip/_vendor/msgpack`. Never a
  declared dependency. Fixed by deleting pip from the runtime image.
- `starlette` — a **transitive** dependency of fastapi. fastapi has no upper
  bound on it, so a patched version was reachable, but nothing would have
  pulled it in without an explicit pin.

---

## Four incompatibilities between "verified" and "runnable"

Getting from a green pipeline to a running pod took four fixes. **Every one
produced a green verification somewhere and a rejection somewhere else.**

| # | Problem | Symptom |
|---|---|---|
| 1 | **Location** — `actions/attest-sbom` writes to the OCI referrers API; Kyverno reads the `.att` tag | verified fine with two CLI tools, `no matching attestations` at admission |
| 2 | **Size** — 2251 KB SPDX SBOM | `context size limit exceeded: 2307687 bytes exceeds limit of 2097152` |
| 3 | **Predicate type** — Kyverno matches the literal string | `cyclonedx` fails, `https://cyclonedx.org/bom` works |
| 4 | **Architecture** — amd64-only image on an arm64 node | admission **approved** an image the kubelet could not pull |

On (2): 2,750 of the SPDX entries are individual **files**; package data alone
is 188 KB. Disabling syft's file cataloger only reached 1861 KB because SPDX
still emits package-owned file lists. CycloneDX carries the same 102 packages
in 962 KB.

On (4), the point worth keeping: **signature verification and runnability are
independent properties.** A green admission decision says nothing about whether
the node can execute the image.

> The single lesson: **verify with the tool that enforces, on the platform that
> runs it.** `gh attestation verify` prefix-matches predicate types and reads
> the referrers API; cosign — which Kyverno uses — does neither. Verifying with
> the more permissive tool produces a green pipeline and a cluster that refuses
> every deploy.

---

## Why `failurePolicy: Fail`

A real availability trade-off, chosen deliberately.

`Fail` means a Kyverno outage **blocks new pods**, including ones that would
have passed. `Ignore` means a webhook outage silently disables the control and
unsigned images sail straight in — failing *open*, quietly, exactly when
something is already wrong.

The mitigation is scope: the policies match namespace `apps` only, so a webhook
failure cannot block `kube-system` or the policy engine's own recovery.

---

## Layout

```
app/                      the deliberately small service
Dockerfile                digest-pinned base, non-root, no package manager
charts/checkout-api/      Helm chart with a hardened pod spec
policy/kyverno/           admission policies (signature + SBOM attestation)
policy/conftest/          manifest policy + 14 unit tests for the policy
policy/vuln-allowlist.json  time-boxed vulnerability exceptions
scripts/vuln_gate.py      the gate
scripts/verify-enforcement.sh  proves the gate actually blocks
docs/decisions/           ADRs
```
