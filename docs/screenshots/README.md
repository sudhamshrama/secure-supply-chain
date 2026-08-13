# Screenshots

This project has no web UI. Its output is a cluster refusing to run something,
so the evidence is terminal output and third-party records.

| Filename | What to capture | Why it earns its place |
|---|---|---|
| `ci-pipeline-green.png` | The Actions runs list | ✅ captured — build, scan, gate, sign, attest, verify |
| `admission-rejected.png` | Terminal: `kubectl apply` of an unsigned image, showing `no signatures found` | **The strongest image in the set.** The gate actually refusing |
| `admission-admitted.png` | Terminal: the signed image applied, then `kubectl get pods` showing `1/1 Running` | The same policy admitting a signed image |
| `rekor-entry.png` | search.sigstore.dev for the log index, certificate expanded | A public, third-party record naming the repository and commit that signed the image |
| `vuln-gate.png` | Terminal: `make gate`, showing the accepted exception with its expiry | Blocks on fixable findings; exceptions expire |

Reproduce the cluster state with `make demo`, then run the two `kubectl apply`
commands in the README.
