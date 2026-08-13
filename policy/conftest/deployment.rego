# Manifest policy, checked in CI on the RENDERED chart.
#
# Signing and admission control answer "did we build this, and is it what we
# say it is?". They say nothing about whether the workload is configured
# safely. A correctly signed image running as root with a writable filesystem
# is a correctly signed root shell.
#
# Kyverno enforces some of this at admission too. Checking it here as well is
# deliberate: a CI failure is a five-second feedback loop on a pull request,
# an admission rejection is discovered at deploy time. Same rule, two places,
# very different cost of being wrong.
package main

import rego.v1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job"}

is_workload if input.kind in workload_kinds

containers contains c if {
	is_workload
	some c in input.spec.template.spec.containers
}

pod_security := object.get(input, ["spec", "template", "spec", "securityContext"], {})

name := object.get(input, ["metadata", "name"], "<unnamed>")

# ---------------------------------------------------------------------------
# Image provenance
# ---------------------------------------------------------------------------

# A tag is a mutable pointer. Signature verification happens against a digest,
# so a tagged reference reintroduces the substitution gap that signing exists
# to close — the tag can be repointed between verification and pull.
deny contains msg if {
	some c in containers
	not contains(c.image, "@sha256:")
	msg := sprintf("%s/%s: image must be pinned by digest, got %q", [name, c.name, c.image])
}

deny contains msg if {
	some c in containers
	endswith(c.image, ":latest")
	msg := sprintf("%s/%s: ':latest' is never a deployable reference", [name, c.name])
}

# ---------------------------------------------------------------------------
# Container hardening
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in containers
	not c.securityContext.readOnlyRootFilesystem
	msg := sprintf("%s/%s: readOnlyRootFilesystem must be true", [name, c.name])
}

deny contains msg if {
	some c in containers
	c.securityContext.allowPrivilegeEscalation != false
	msg := sprintf("%s/%s: allowPrivilegeEscalation must be false", [name, c.name])
}

deny contains msg if {
	some c in containers
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("%s/%s: must drop ALL capabilities", [name, c.name])
}

deny contains msg if {
	is_workload
	pod_security.runAsNonRoot != true
	msg := sprintf("%s: pod securityContext.runAsNonRoot must be true", [name])
}

# runAsNonRoot is checked by the kubelet against the numeric UID. An image that
# only declares a USERNAME cannot be resolved, and the container fails to start
# with an error that does not mention this setting at all.
deny contains msg if {
	is_workload
	pod_security.runAsNonRoot == true
	not pod_security.runAsUser
	msg := sprintf("%s: runAsNonRoot needs an explicit numeric runAsUser", [name])
}

deny contains msg if {
	is_workload
	pod_security.runAsUser == 0
	msg := sprintf("%s: runAsUser 0 is root", [name])
}

# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

# Memory is NOT compressible: a leak without a limit takes the node down with
# it, not just the pod.
deny contains msg if {
	some c in containers
	not c.resources.limits.memory
	msg := sprintf("%s/%s: memory limit is required", [name, c.name])
}

# Requests drive scheduling. Without them the scheduler assumes ~nothing and
# will happily overcommit the node.
deny contains msg if {
	some c in containers
	not c.resources.requests.memory
	msg := sprintf("%s/%s: memory request is required", [name, c.name])
}

# A CPU LIMIT is deliberately NOT required — this is a warn, not a deny.
# CFS throttling under a CPU limit produces latency spikes that look exactly
# like application bugs and cost far more debugging time than the overcommit
# risk it prevents.
warn contains msg if {
	some c in containers
	c.resources.limits.cpu
	msg := sprintf("%s/%s: CPU limit set — expect CFS throttling under load", [name, c.name])
}

# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

deny contains msg if {
	some c in containers
	not c.readinessProbe
	msg := sprintf("%s/%s: readinessProbe required — without it traffic is sent to a starting pod", [name, c.name])
}

deny contains msg if {
	some c in containers
	not c.livenessProbe
	msg := sprintf("%s/%s: livenessProbe required", [name, c.name])
}
