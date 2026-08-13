# Unit tests for the manifest policy, run with `conftest verify`.
#
# Policies need tests for the same reason gates do: a rule with a typo in the
# field path silently matches nothing and passes everything. Every deny here is
# asserted to fire on a manifest that violates it AND to stay silent on one
# that does not.
package main

import rego.v1

digest := "ghcr.io/sudhamshrama/checkout-api@sha256:50eae41900b8eebe1520de13fa24e10ab60e044ef4bfaaa1f57c93cdebd97a81"

# A manifest that satisfies every rule. Tests mutate copies of this.
compliant := {
	"kind": "Deployment",
	"metadata": {"name": "app"},
	"spec": {"template": {"spec": {
		"securityContext": {"runAsNonRoot": true, "runAsUser": 10001},
		"containers": [{
			"name": "app",
			"image": digest,
			"securityContext": {
				"readOnlyRootFilesystem": true,
				"allowPrivilegeEscalation": false,
				"capabilities": {"drop": ["ALL"]},
			},
			"resources": {
				"requests": {"memory": "96Mi"},
				"limits": {"memory": "192Mi"},
			},
			"readinessProbe": {"httpGet": {"path": "/healthz", "port": 8000}},
			"livenessProbe": {"httpGet": {"path": "/healthz", "port": 8000}},
		}],
	}}},
}

# Replace a field on the single container.
#
# NOTE: object.union DEEP-merges. Using it here made two tests pass for the
# wrong reason — replacing `resources` with {"requests": ...} merged the
# original `limits` back in, so the manifest under test still had a memory
# limit and the "missing limit" rule correctly stayed silent. The test was
# broken, not the policy.
#
# json.patch replaces the named key outright, which is what these tests mean.
with_container(key, value) := json.patch(compliant, [{
	"op": "replace",
	"path": sprintf("/spec/template/spec/containers/0/%s", [key]),
	"value": value,
}])

with_pod_security(sc) := json.patch(compliant, [{
	"op": "replace",
	"path": "/spec/template/spec/securityContext",
	"value": sc,
}])

# ---------------------------------------------------------------------------

test_compliant_manifest_passes if {
	count(deny) == 0 with input as compliant
}

test_tag_instead_of_digest_denied if {
	count(deny) > 0 with input as with_container("image", "ghcr.io/sudhamshrama/checkout-api:main")
}

test_latest_tag_denied if {
	count(deny) > 0 with input as with_container("image", "ghcr.io/sudhamshrama/checkout-api:latest")
}

test_writable_root_filesystem_denied if {
	patched := with_container("securityContext", {
		"readOnlyRootFilesystem": false,
		"allowPrivilegeEscalation": false,
		"capabilities": {"drop": ["ALL"]},
	})
	count(deny) > 0 with input as patched
}

test_privilege_escalation_denied if {
	patched := with_container("securityContext", {
		"readOnlyRootFilesystem": true,
		"allowPrivilegeEscalation": true,
		"capabilities": {"drop": ["ALL"]},
	})
	count(deny) > 0 with input as patched
}

test_capabilities_not_dropped_denied if {
	patched := with_container("securityContext", {
		"readOnlyRootFilesystem": true,
		"allowPrivilegeEscalation": false,
		"capabilities": {"drop": ["NET_RAW"]},
	})
	count(deny) > 0 with input as patched
}

test_run_as_root_denied if {
	count(deny) > 0 with input as with_pod_security({"runAsNonRoot": true, "runAsUser": 0})
}

test_run_as_non_root_without_uid_denied if {
	# The kubelet resolves runAsNonRoot against a numeric UID. A username-only
	# image fails to start with an unrelated-looking error.
	count(deny) > 0 with input as with_pod_security({"runAsNonRoot": true})
}

test_missing_memory_limit_denied if {
	patched := with_container("resources", {"requests": {"memory": "96Mi"}})
	count(deny) > 0 with input as patched
}

test_missing_memory_request_denied if {
	patched := with_container("resources", {"limits": {"memory": "192Mi"}})
	count(deny) > 0 with input as patched
}

test_missing_readiness_probe_denied if {
	patched := json.remove(compliant, ["/spec/template/spec/containers/0/readinessProbe"])
	count(deny) > 0 with input as patched
}

test_missing_liveness_probe_denied if {
	patched := json.remove(compliant, ["/spec/template/spec/containers/0/livenessProbe"])
	count(deny) > 0 with input as patched
}

# A CPU limit warns rather than denies — CFS throttling causes latency spikes
# that are misdiagnosed as application bugs.
test_cpu_limit_warns_but_does_not_deny if {
	patched := with_container("resources", {
		"requests": {"memory": "96Mi"},
		"limits": {"memory": "192Mi", "cpu": "500m"},
	})
	count(warn) > 0 with input as patched
	count(deny) == 0 with input as patched
}

# Non-workload objects must not be evaluated at all, or every Service and
# ConfigMap in the chart would fail every container rule.
test_service_is_ignored if {
	svc := {"kind": "Service", "metadata": {"name": "app"}, "spec": {"ports": []}}
	count(deny) == 0 with input as svc
}
