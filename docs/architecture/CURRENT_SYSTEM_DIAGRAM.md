# Epyon — System Diagram (as of 3.78.x)

Mermaid diagrams; GitHub and VS Code render them. See `SYSTEM_ARCHITECTURE.md` for prose detail.

## 1. Components and data flow

```mermaid
flowchart LR
  subgraph Triggers
    UI[Web UI SPA<br/>web/src to web/static/app.js]
    CLI[epyon.sh<br/>local CLI]
    GHA[GitHub Actions<br/>epyon-scan.yml]
  end

  subgraph API[FastAPI backend - web/api]
    R[routers: scans, stig, jira,<br/>github, metrics, reports, system]
    JOBS[jobs.py<br/>async scan jobs]
    PARS[parsers.py<br/>scan dir to JSON]
    AICFG[ai-config.json<br/>web/data]
  end

  subgraph Orchestrators
    TGT[run-target-security-scan.sh<br/>local and web scans]
    CI[run-epyon-scan-ci.sh<br/>CI scans]
  end

  subgraph Layers[Scan layers - scripts/shell/run-*]
    L1[SBOM, secrets, SAST,<br/>Trivy, Grype, Checkov,<br/>ClamAV, Xeol, Anchore]
    LML[ML layers 14, 18, 19, 20<br/>pip-audit ML-aware]
    LSTIG[STIG layer 13<br/>run-stig-scan.sh]
  end

  SCANS[(scans/app_timestamp/<br/>tool outputs, stig-results-slug.json,<br/>security-findings-summary.json)]
  CONS[consolidate-security-reports.sh<br/>generate-dashboard.py<br/>scan-manifest.json]

  UI -->|REST /api| R
  R --> JOBS
  JOBS -->|env: EPYON_STIG_FORMAT,<br/>EPYON_STIG_SAMPLES, AI provider| TGT
  CLI --> TGT
  GHA --> CI
  TGT --> Layers
  CI --> Layers
  Layers --> SCANS
  SCANS --> CONS
  CONS --> SCANS
  SCANS --> PARS --> R
  AICFG --> JOBS

  R -->|tickets| JIRA[(Jira Cloud)]
  R -->|metrics, sync| GH[(GitHub)]
  LSTIG -->|PR with docs/stig-reviews| GH
  TGT -.->|HMAC webhooks| WH[(Webhook sink)]
```

## 2. STIG assessment pipeline (layer 13)

```mermaid
flowchart TD
  A[configuration/stigs<br/>.cklb / XCCDF<br/>newest release only] --> B[Applicability detection<br/>tech stack to relevant STIGs]
  T[Target repo] --> C[Context collection<br/>source, config, markdown/JSON]
  T --> D[docs/stig-reviews/<br/>human reviews - ETK mode]
  S[security-findings-summary.json<br/>.epyon-ignore.yml] --> C
  B --> E[Per-control batches<br/>top-5 files per control]
  C --> E

  D --> F{Human-reviewed and<br/>listed paths unchanged and<br/>pre-check passes?}
  F -->|yes| G[Freeze: carry forward<br/>confidence at least 85]
  F -->|no| H[Re-open: send human review<br/>to model as claim to verify]

  P[stig-results-slug.json<br/>previous state] --> G
  E --> H
  H --> I[LLM call<br/>OpenAI or local Hopper/Gemma]
  I -->|EPYON_STIG_SAMPLES > 1| J[N samples + synthesis<br/>for disputed controls]
  I --> K[Assessment<br/>status, evidence, confidence]
  J --> K
  G --> K
  K --> L[Citation verification<br/>stig_citations.py]
  L --> M[stig-results-slug.json<br/>+ markdown findings]
  M --> N[create-stig-pr.sh<br/>docs/stig-reviews/ PR]
  M --> O[Web UI STIG page<br/>drawer, override, Jira]
```

## 3. STIG override and Jira (current behaviour)

```mermaid
sequenceDiagram
  participant U as User
  participant D as STIG drawer
  participant A as FastAPI
  participant S as scan dir stig-results
  participant J as Jira Cloud
  U->>D: change status + justification
  D->>A: PATCH /scans/{id}/stig-override
  A->>S: status, confidence 95, locked_by_human,<br/>justification prepended to evidence
  Note over S: Not carried to later scans<br/>unless published to docs/stig-reviews
  U->>D: Add to Jira
  D->>A: GET stig-jira-context
  A-->>D: config, project keys
  D->>A: POST create tickets
  A->>J: issues (JIRA_API_TOKEN from env)
```

## Key facts

- One application = one repo = the unit of scans and STIG results. There is no Project entity yet (see `docs/FUTURE_IMPROVEMENTS.md` item 14).
- Persistent volumes on deployment: `./web/data`, `./configuration`, `./scans`.
- `EPYON_STIG_FORMAT`: web scans default to `etk`; CLI/CI default to `legacy`.
- Secrets (`JIRA_API_TOKEN`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, `NVD_API_KEY`) are environment-only.
