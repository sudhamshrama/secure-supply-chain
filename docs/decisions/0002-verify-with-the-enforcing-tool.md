# ADR 0002 — Verify with the tool that enforces

**Status:** Accepted
**Date:** 2026-08-12

## Context

The pipeline signs an image, attaches an SBOM attestation, and adds SLSA
provenance. Kyverno then verifies all of that at admission before a Pod may run.

Four separate times, an artifact verified successfully with one tool and was
rejected by another. Every failure was a real incompatibility, not a typo.

## What happened

**1. Storage location.** `cosign attest` writes to the `.att` tag.
`actions/attest-sbom --push-to-registry` writes via the **OCI referrers API**.
Both are valid; `cosign verify-attestation` and `gh attestation verify` read
either. **Kyverno reads the `.att` tag only.** The referrers-only image
verified perfectly from a laptop and failed admission with
`no matching attestations`.

**2. Payload size.** With the attestation finally visible, Kyverno failed
differently:

```
context size limit exceeded: 2307687 bytes exceeds limit of 2097152 bytes
```

The SPDX SBOM is 2251 KB. 2750 of its entries are individual **files**;
package data alone is 188 KB. Disabling syft's file-metadata cataloger only
reached 1861 KB, because SPDX still emits package-owned file lists. CycloneDX
carries the same 102 packages in 962 KB.

**3. Predicate type matching.** `gh attestation verify` prefix-matches:
`https://spdx.dev/Document` passes against a `.../v2.3` attestation. cosign
requires the exact string. Kyverno matches literally, so `type: cyclonedx`
fails where `type: https://cyclonedx.org/bom` succeeds.

**4. Architecture.** The image was amd64-only; the verification cluster runs on
arm64. Admission **approved** it and the kubelet then could not pull it:
`no match for platform in manifest`.

## Decision

1. Produce attestations with **cosign**, because cosign is what the enforcement
   point uses.
2. Verify in CI with **cosign**, against the **exact** predicate type — not
   with a more permissive tool.
3. Use CycloneDX, sized to fit the enforcement point's limits.
4. Build multi-arch, and sign the manifest **list** digest so the signature
   covers every architecture shipped.

## The general rule

> **Verify with the tool that enforces, on the platform that runs it.**

A verification step that is more permissive than the enforcement point is worse
than no verification step, because it produces a green pipeline and a cluster
that refuses every deploy — and the pipeline is believed.

A corollary worth stating separately, from (4): **signature verification and
runnability are independent properties.** A cryptographically perfect artifact
can still be unable to start.

## A correction

An earlier commit in this repository blamed failure (1) on "no embedded
certificate in the DSSE envelope". That was wrong: `cosign download attestation`
strips certificates stored in OCI layer annotations, so the absence was an
artifact of the inspection command. The cause was always storage location. The
incorrect explanation is left in the history rather than rewritten.
