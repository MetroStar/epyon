# Epyon Self-Assessment Fixture

This directory is a small, deliberately vulnerable synthetic project used
**only** to validate that Epyon's own scanner layers are actually detecting
what they claim to detect — not just running without error.

It is scanned by `scripts/shell/run-self-assessment.sh`, which runs a real
`--mode full` Epyon scan against this directory and diffs the actual
findings against the ground-truth expectations in `expected-findings.json`.

## Why this exists

A scanner that silently produces zero findings (e.g. because of a broken
mount path, a misconfigured tool, or a version bump that changed CLI output)
looks identical to a scanner that ran cleanly against a genuinely secure
target. This fixture removes that ambiguity: every layer that can be
deterministically tested has at least one planted, known issue that a
correctly-functioning scanner **must** find.

See `expected-findings.json` for the full layer-by-layer manifest, including
which layers are validated with a hard pass/fail (`"validate": true`) versus
best-effort "did the tool run" checks (`"validate": false`, e.g. SonarQube,
STIG, network/API discovery — these can't be deterministically planted in a
static fixture).

## Planted issues

| Path | Layer(s) | Issue |
|---|---|---|
| `requirements.txt` | 8, 8.5, 1 | `pyyaml==5.3.1`, `requests==2.6.0` — known CVEs |
| `package.json` | 8, 1 | `lodash==4.17.4` — known CVE |
| `iac/main.tf` | 6 | Open ingress SG, unencrypted S3, public RDS |
| `secrets_test/canary.env` | 2 | Randomly generated fake AWS/GitHub credentials (never valid) |
| `inference/Dockerfile` | 7, 9, 19 | Root user, no non-root `USER`, EOL-prone base |
| `inference/docker-compose.yml` | 19 | Insecure compose settings |
| `models/malicious/backdoor.pkl` | 14 | Known dangerous pickle opcode payload |
| `config.json` (fixture root) | 18 | Typosquatted model name (`bert-base-uncased-cracked`) — the provenance scanner reads `config.json` at the scan target's root |
| `MODEL_CARD.md` | 15 | Missing "training data" / "intended use" sections |
| `malware/eicar.txt` | 4 | Standard EICAR test string — **generated at scan-time only**, never committed (real AV engines quarantine it on sight) |

## Safety notes

- No real secrets, malware, or exploitable infrastructure are present.
  `secrets_test/canary.env` contains randomly generated fake credentials that
  were never valid and don't correspond to any real account.
- `iac/main.tf` is not a deployable/applyable Terraform root module — it
  exists purely to be scanned by Checkov, never `terraform apply`'d.
- The EICAR string is the industry-standard antivirus self-test signature
  (not real malware) and is intentionally excluded from source control —
  see `run-self-assessment.sh`.
- This directory is scanned as-is by Epyon's own CI; see `.epyon-ignore.yml`
  at the repo root for the corresponding suppression entries so these
  intentional findings don't fail Epyon's own compliance scans.
