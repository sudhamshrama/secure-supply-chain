IMAGE ?= checkout-api:local
SHA   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo local)

.PHONY: build scan gate cluster policies verify demo clean

build:  ## Build the image
	docker build --build-arg APP_VERSION=$(SHA) --build-arg GIT_SHA=$(SHA) -t $(IMAGE) .

sbom: build  ## Generate an SPDX SBOM
	syft $(IMAGE) -o spdx-json=sbom.spdx.json
	@python3 -c "import json;d=json.load(open('sbom.spdx.json'));print('packages:',len(d['packages']))"

scan: build  ## Scan for vulnerabilities
	grype $(IMAGE) -o json > scan.json
	@python3 -c "import json,collections;d=json.load(open('scan.json'));c=collections.Counter(m['vulnerability']['severity'] for m in d['matches']);print(dict(c))"

gate: scan  ## Run the vulnerability gate (fixable-only, time-boxed exceptions)
	python3 scripts/vuln_gate.py scan.json policy/vuln-allowlist.json

cluster:  ## Create the kind cluster and install Kyverno
	kind get clusters | grep -q supplychain || kind create cluster --config k8s/kind-cluster.yaml
	helm repo add kyverno https://kyverno.github.io/kyverno/ 2>/dev/null || true
	helm repo update >/dev/null
	helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace --wait --timeout 8m
	kubectl create namespace apps --dry-run=client -o yaml | kubectl apply -f -

policies:  ## Apply the admission policies
	kubectl apply -f policy/kyverno/

verify:  ## Prove the gate actually blocks
	./scripts/verify-enforcement.sh

demo: cluster policies verify  ## Full local demonstration

clean:
	kind delete cluster --name supplychain
	rm -f scan.json sbom.spdx.json
