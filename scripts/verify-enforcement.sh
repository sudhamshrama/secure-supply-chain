#!/usr/bin/env bash
#
# Proves the admission control actually blocks. Run after `make cluster`.
#
# A signing pipeline nobody has watched REJECT something is a pipeline nobody
# should trust. It is easy to build a policy that silently admits everything —
# a typo in the image pattern, `Audit` left where `Enforce` was meant, a
# namespace selector that matches nothing — and every one of those looks
# identical to a working policy until the day it matters.
#
# So this asserts the negative path explicitly, and fails loudly if an
# unsigned image is ADMITTED.
set -euo pipefail

NS=apps
PASS=0
FAIL=0

ok()   { echo "  PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL  $1"; FAIL=$((FAIL+1)); }

echo "== Kyverno running =="
if kubectl -n kyverno get deploy kyverno-admission-controller >/dev/null 2>&1; then
  ok "admission controller present"
else
  bad "admission controller missing — run 'make cluster'"; exit 1
fi

echo "== Policies loaded and Ready =="
# Readiness lives in .status.conditions, NOT .status.ready. The latter returns
# an empty string on this Kyverno version, which compares unequal to "true" and
# reports a perfectly healthy policy as broken — a check that fails closed on
# its own bug is still a bad check.
for p in verify-checkout-api-signature require-sbom-attestation; do
  ready=$(kubectl get clusterpolicy "$p" \
    -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
  if [ "$ready" = "True" ]; then
    ok "$p is Ready"
  else
    bad "$p is not Ready (condition=${ready:-none})"
  fi
done

echo "== Policies are ENFORCING, not auditing =="
# `Audit` logs a violation and admits the pod anyway. It looks like a working
# policy in every dashboard and blocks nothing.
for p in verify-checkout-api-signature require-sbom-attestation; do
  action=$(kubectl get clusterpolicy "$p" -o jsonpath='{.spec.validationFailureAction}' 2>/dev/null)
  if [ "$action" = "Enforce" ]; then
    ok "$p action=Enforce"
  else
    bad "$p action=${action:-unset} (expected Enforce)"
  fi
done

echo "== An image with no signature is REJECTED =="
# Deliberately a real, public, pullable image. If the test used a nonexistent
# image, the rejection would be a registry 'access denied' and would prove
# nothing about signature verification.
cat <<'EOF' | kubectl apply -f - >/dev/null 2>&1 || true
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: test-verify-unsigned
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
    - name: verify
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [apps]
      verifyImages:
        - imageReferences: ["docker.io/library/nginx*"]
          required: true
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/sudhamshrama/secure-supply-chain/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor: { url: https://rekor.sigstore.dev }
EOF
sleep 3

output=$(kubectl run enforcement-probe -n "$NS" \
  --image=docker.io/library/nginx:alpine --dry-run=server 2>&1 || true)

if grep -q "no signatures found" <<<"$output"; then
  ok "unsigned image rejected with a signature error"
elif grep -qi "blocked due to the following policies" <<<"$output"; then
  # Blocked, but for the wrong reason — e.g. the registry refused the pull.
  bad "blocked, but NOT for a missing signature (check the message below)"
  echo "$output" | tail -4
else
  bad "UNSIGNED IMAGE WAS ADMITTED — the gate is not working"
  echo "$output" | tail -4
fi

kubectl delete clusterpolicy test-verify-unsigned >/dev/null 2>&1 || true

echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ]
