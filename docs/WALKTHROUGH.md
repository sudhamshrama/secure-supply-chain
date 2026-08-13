# secure-supply-chain — What We Did and Why

A plain-English record of every decision and every failure in this project,
written so you can defend it out loud.

**Source:** https://github.com/sudhamshrama/secure-supply-chain
**Cost:** $0 — kind, GHCR, Sigstore's public good instance, GitHub Actions

---

## Table of contents

1. [What problem this solves](#1-what-problem-this-solves)
2. [The pipeline](#2-the-pipeline)
3. [Hardening the image](#3-hardening-the-image)
4. [The vulnerability gate](#4-the-vulnerability-gate)
5. [Keyless signing](#5-keyless-signing)
6. [Admission control](#6-admission-control)
7. [Four ways "verified" and "runnable" disagreed](#7-four-ways-verified-and-runnable-disagreed)
8. [Policy as code](#8-policy-as-code)
9. [Glossary](#9-glossary)
10. [Interview questions this answers](#10-interview-questions-this-answers)

---

## 1. What problem this solves

You pull an image called `checkout-api:main`. What do you actually know about it?

Nothing. A tag is a mutable pointer. Anyone with registry write access can
repoint it. The image might be built from a fork, from a laptop, from a commit
that never passed review. There is no way to answer "where did this come from?"
from the artifact itself.

This project makes the cluster **refuse to run anything it cannot verify**:

```
signed + attested image      →  ADMITTED, pod Running, serving traffic
unsigned image, same repo    →  REJECTED: "no signatures found"
```

The application is deliberately trivial — a three-endpoint FastAPI service. If
the app were interesting, it would distract from the thing being demonstrated.

---

## 2. The pipeline

```
build (amd64, local, not pushed)
  ├─ SBOM (syft, CycloneDX)
  ├─ scan (grype)
  ├─ VULNERABILITY GATE ─────────── fails here → nothing is published
  ├─ policy tests + manifest checks (conftest/OPA)
  ↓
push multi-arch (amd64 + arm64) to GHCR
  ├─ cosign sign          (keyless — no key exists)
  ├─ cosign attest        (the SBOM, signed)
  ├─ SLSA provenance      (how it was built)
  ↓
verify what we just published, with cosign, exact predicate types
  ↓
Kyverno admission ────────────────── unsigned → REJECTED
```

**Scan before publish, always.** Publishing and then scanning means a vulnerable
image exists in a registry where something can pull it, even if the build later
goes red. Nothing leaves the job until the gate passes.

---

## 3. Hardening the image

Every change here came from a measurement, not a checklist.

### Pin the base by digest, not tag

```dockerfile
FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a
```

`python:3.13-slim` resolves to different content over time. With a tag, "rebuild
the exact image we shipped" is impossible and an SBOM describes a build nobody
can reproduce. A digest is immutable.

### Delete pip from the runtime image

The runtime stage installs nothing — dependencies are copied from the builder.
So a package manager there is **pure attack surface**: code execution in that
container would otherwise have pip ready to fetch and run more code.

It was also a real CVE source, and a subtle one:

```
GHSA-6v7p-g79w-8964  msgpack 1.1.2  → vendored INSIDE pip, at pip/_vendor/msgpack
CVE-2025-47273       setuptools 70.3.0
```

**Neither appears in `requirements.txt`, because neither is a dependency of this
app.** No version pin could ever have fixed them. Deleting the tooling does.

> This exact problem was found first in the `url-shortener` project, where CI
> went red four days after a green build with no code change. Same cause.

One honest note: this does **not** shrink the image (370MB → 376MB). pip lives
in a base-image layer, so removing it writes a whiteout layer rather than
reclaiming space. The files are gone from the final filesystem — which is what
the scanner and an attacker see — but the byte count is not the win.

### Pin a transitive dependency

Two HIGH advisories hit `starlette 0.49.3` — which this app never chose.
fastapi pulled it in.

`fastapi 0.141.1` requires only `starlette>=0.46.0`, no upper bound, so a
patched version was reachable. But **nothing would have upgraded it** without an
explicit pin. That is the shape of most real supply-chain findings: the
vulnerable package is one you never named.

Result of all three: **181 findings → 176, fixable HIGH/CRITICAL 3 → 1.**

---

## 4. The vulnerability gate

### Why not `grype --fail-on high`

```
181 findings
  7 fixable
```

Every CRITICAL was `libc6` or `perl-base` in the Debian base, marked
**"won't fix"** by the distribution. Nothing the application team can do clears
them.

A gate that blocks on all 181 blocks every build forever. It gets switched off
within a week — and a disabled gate is worse than none, because the pipeline
still claims to scan.

So the gate blocks on **fixable** findings only.

### "Fixable" is sometimes false

The one survivor:

```
CVE-2026-15308  python 3.13.15  fix = 3.15.0
```

Docker Hub publishes `3.15.0a5` through `a8`. **There is no stable 3.15.**
`python:3.14-slim` was tested and carries the identical finding, so upgrading
the base does not help. A second advisory on the same image lists its fix as
`3.15.0a6` — the scanner is recommending an **alpha interpreter** for production.

### So exceptions expire

```json
{
  "id": "CVE-2026-15308",
  "owner": "sudhamsh",
  "expires": "2026-11-12",
  "reason": "fix=3.15.0 is not a stable CPython release; 3.14 tested and identical"
}
```

An expired entry fails the build **exactly like an unreviewed vulnerability**,
because a permanent exception is indistinguishable from having no gate. The
expiry forces the decision back in front of a human on a date somebody chose.

All four behaviours were exercised rather than assumed:

| input | result |
|---|---|
| valid exception | PASS |
| expired exception | **FAIL** |
| no allowlist entry | **FAIL** |
| allowlisted CVE no longer present | warn (stale config, not fatal) |

---

## 5. Keyless signing

```yaml
- run: cosign sign --yes "${IMAGE}@${{ steps.push.outputs.digest }}"
```

**There is no private key.** Not in GitHub secrets, not on a runner, not in a
vault. cosign exchanges the workflow's OIDC token for a short-lived certificate
from Fulcio, signs, and records the signature in the Rekor public transparency
log.

What is proven is not "someone holding the key signed this" but:

> **This workflow, in this repository, at this commit, produced this digest.**

That is a stronger claim, and it cannot be replayed by whoever steals a key —
there is no key to steal. Verification is by **identity**:

```
subject: https://github.com/sudhamshrama/secure-supply-chain/*
issuer:  https://token.actions.githubusercontent.com
```

A valid signature from the wrong repository is still a rejection.

**Sign the digest, never the tag.** A tag can be repointed after signing.

---

## 6. Admission control

Signing an image and then letting the cluster run anything is theatre. The
signature is a control only if something **checks it** when a workload is
admitted.

```yaml
validationFailureAction: Enforce   # not Audit — Audit logs and admits
failurePolicy: Fail                # if Kyverno is down, REFUSE
mutateDigest: true                 # rewrite the tag to the verified digest
```

### `mutateDigest` closes a TOCTOU hole

Without it: Kyverno verifies `:main`, admits the Pod, and the kubelet then pulls
`:main` **again** — which may by then point at different content. Pinning the
Pod to the digest that was actually verified closes the window.

### `failurePolicy: Fail` is a deliberate availability trade

`Fail` means a Kyverno outage **blocks new pods**, including ones that would
have passed. `Ignore` means a webhook outage silently disables the control and
unsigned images sail straight in.

The second is worse for a security control: it fails **open**, quietly, exactly
when something is already wrong. Mitigation is scope — the policies match
namespace `apps` only, so a webhook failure cannot block `kube-system` or
Kyverno's own recovery.

### Proving it actually blocks

The first "proof" was worthless. Deploying an image that did not exist yet
produced:

```
DENIED: requested access to the resource is denied
```

That is a **registry access error**, not a signature failure. It proves nothing
about verification.

Re-run against a real, public, pullable, unsigned image:

```
failed to verify image docker.io/library/nginx:alpine:
  .attestors[0].entries[0].keyless: no signatures found
```

`scripts/verify-enforcement.sh` now asserts that permanently, checks the
policies are `Enforce` rather than `Audit`, and **fails loudly if an unsigned
image is ever admitted**. 6/6 passing.

> A signing pipeline nobody has watched *reject* something is a pipeline nobody
> should trust.

---

## 7. Four ways "verified" and "runnable" disagreed

This is the most useful section. Getting from a green pipeline to a running pod
took four fixes, and **every one produced a green verification somewhere and a
rejection somewhere else.**

### 1. Storage location

`cosign attest` writes to the `.att` **tag**.
`actions/attest-sbom --push-to-registry` writes via the **OCI referrers API**.

Both are valid. `cosign verify-attestation` and `gh attestation verify` read
either. **Kyverno reads the `.att` tag only.**

The referrers-only image verified perfectly from a laptop and failed admission
with `no matching attestations`. I had switched *to* that action believing it
was a fix; it broke the enforcement point.

### 2. Payload size

With the attestation finally visible, Kyverno failed differently:

```
context size limit exceeded: 2307687 bytes exceeds limit of 2097152 bytes
```

The SPDX SBOM is 2251 KB. Breaking it down:

```
102    packages
2750   files          ← this is what the size is
3179   relationships
188 KB without files and relationships
```

Disabling syft's file-metadata cataloger only reached 1861 KB, because SPDX
still emits package-owned file lists. **CycloneDX carries the same 102 packages
in 962 KB.** For admission control the question is *which dependencies are in
this image*, not *what is every file path*.

### 3. Predicate type matching

`gh attestation verify` **prefix-matches**: `https://spdx.dev/Document` passes
against a `.../v2.3` attestation.

cosign requires the **exact** string. Kyverno matches literally, so
`type: cyclonedx` fails where `type: https://cyclonedx.org/bom` works.

CI was green with the loose spelling while the cluster rejected every deploy.

### 4. Architecture

The image was amd64-only; the kind cluster runs on an arm64 Mac.

```
Failed to pull image: no match for platform in manifest: not found
```

**Admission control approved an image the node could not execute.** Signature
verification and runnability are independent properties, and a green admission
decision says nothing about the second.

Fixed by building `linux/amd64,linux/arm64`. The pushed digest is the manifest
**list** digest, so the signature covers both architectures.

### The rule

> **Verify with the tool that enforces, on the platform that runs it.**
>
> A verification step more permissive than the enforcement point is worse than
> none — it produces a green pipeline and a cluster that refuses every deploy,
> and the pipeline is believed.

### A correction

An earlier commit blamed failure (1) on "no embedded certificate in the DSSE
envelope". **That was wrong.** `cosign download attestation` strips certificates
stored in OCI layer annotations, so the absence was an artifact of the
inspection command, not of the artifact. The cause was always storage location.
The incorrect explanation is left in git history rather than quietly rewritten.

---

## 8. Policy as code

Signing proves provenance. It says nothing about whether the workload is
configured safely. **A correctly signed image running as root with a writable
filesystem is a correctly signed root shell.**

conftest/OPA checks the rendered chart: digest pinning, no `:latest`, non-root
with an explicit numeric UID, read-only root filesystem, no privilege
escalation, all capabilities dropped, memory limits and requests, both probes.

26 checks pass on the real chart. A tag-based manifest fails on exactly the two
image rules.

### The policies have their own tests

14 of them. A rule with a typo in its field path matches nothing and silently
passes everything — indistinguishable from having no policy.

**Two of those tests initially passed for the wrong reason.** The helper used
`object.union`, which **deep-merges**, so replacing `resources` with only
`requests` merged the original `limits` back in. The manifest under test still
had a memory limit, and the "missing limit" rule correctly stayed silent. *The
test was broken, not the policy.* Fixed with `json.patch`, which replaces the
key outright.

### One rule deliberately warns instead of denying

A **CPU limit** is a `warn`. CFS throttling under a CPU limit produces latency
spikes that get misdiagnosed as application bugs, and costs more debugging time
than the overcommit risk it prevents. Memory *is* denied without a limit —
memory is not compressible, so a leak takes the node down, not just the pod.

---

## 9. Glossary

| Term | Meaning |
|---|---|
| **SBOM** | Software Bill of Materials — the inventory of what is inside an artifact |
| **SPDX / CycloneDX** | Two SBOM formats. CycloneDX is more compact. |
| **Attestation** | A signed statement *about* an artifact (its SBOM, how it was built) |
| **Predicate type** | The URI naming what kind of statement an attestation is |
| **Keyless signing** | Signing with a short-lived certificate from an identity provider — no long-lived private key |
| **Fulcio** | Sigstore's CA; issues the short-lived signing certificate |
| **Rekor** | Sigstore's public transparency log; records that a signature happened |
| **SLSA provenance** | A signed record of how an artifact was built |
| **Admission control** | The cluster checking a workload before it is allowed to run |
| **Kyverno** | A Kubernetes policy engine that can verify image signatures at admission |
| **`Enforce` vs `Audit`** | Enforce rejects. Audit logs the violation and admits anyway. |
| **`failurePolicy`** | What happens when the policy engine is unreachable: `Fail` refuses, `Ignore` admits |
| **TOCTOU** | Time-of-check to time-of-use — verifying one thing and then using another |
| **OCI referrers** | A registry API for attaching artifacts to an image, alternative to the `.att` tag |
| **conftest / OPA / Rego** | Policy-as-code: OPA is the engine, Rego the language, conftest the CLI |

---

## 10. Interview questions this answers

**"What does signing an image actually prove?"**
> With keyless signing, not "someone had the key" but "this workflow, in this
> repository, at this commit, produced this digest". Verification is by identity
> against GitHub's OIDC issuer, and it's recorded in a public transparency log.
> There's no key to steal, leak, or rotate.

**"Why not just fail the build on any HIGH CVE?"**
> Because my image has 181 findings and 7 are fixable — every CRITICAL was
> "won't fix" in the Debian base. That gate gets switched off in a week, and a
> disabled gate is worse than none because the pipeline still claims to scan. I
> block on *fixable* findings, with exceptions that expire.

**"Give me an example of a scanner being wrong."**
> grype flagged CPython with `fix = 3.15.0`. There is no stable 3.15 — Docker
> Hub has only alphas — and 3.14 carries the identical finding. Another advisory
> on the same image listed its fix as `3.15.0a6`. "Fixable" in a database means
> an advisory names a version, not that the version is shippable.

**"Your pipeline was green and the deploy failed. What happened?"**
> Four separate times. The best one: `actions/attest-sbom` writes to the OCI
> referrers API and Kyverno reads the `.att` tag, so the image verified
> perfectly with two CLI tools and was rejected at admission. The lesson is to
> verify with the tool that *enforces*, not with whichever command you happen to
> run by hand.

**"How do you know your admission policy actually blocks anything?"**
> There's a script that asserts it. My first attempt at proving it was worthless
> — I used an image that didn't exist, so the rejection was a registry access
> error, not a signature failure. The real test uses a public, pullable,
> unsigned image and asserts on `no signatures found`. It also checks the
> policies are `Enforce` rather than `Audit`, because `Audit` looks identical in
> every dashboard and blocks nothing.

**"`failurePolicy: Fail` will take down your cluster."**
> It can block new pods in that namespace if Kyverno is down, yes. The
> alternative fails *open* — a webhook outage silently disables the control and
> unsigned images sail in, exactly when something is already wrong. I scoped the
> policies to one namespace so a failure can't block kube-system or Kyverno's
> own recovery. It's a trade, and I picked the side where the failure is loud.

**"Tell me about a bug in your tests."**
> Two of my Rego policy tests passed for the wrong reason. The helper used
> `object.union`, which deep-merges, so a test that claimed to remove the memory
> limit actually merged it back in. The policy was fine; the test was lying.
> That's the argument for testing policies at all — a rule with a typo in its
> field path matches nothing and passes everything.

**"Where did the vulnerable package in your image come from?"**
> `msgpack`, vendored inside pip at `pip/_vendor/msgpack`. It was never in
> requirements.txt because it was never a dependency — it ships inside the base
> image's package manager. No pin could have fixed it. I deleted pip from the
> runtime stage, which also removes a ready-made way for an attacker to fetch
> and run more code.

---

*Every failure in this document was hit for real, diagnosed, and fixed. The
value of the project is in section 7.*
