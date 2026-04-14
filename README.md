# SecureScope

**Vulnerability Discovery, Remediation & Validation Platform**

SecureScope is an enterprise-grade web platform that unifies DAST, SAST, API security testing, secret scanning, dependency analysis, and infrastructure scanning into a single workflow with approval-gated auto-remediation and before/after validation.

## Architecture

```
                     ┌─────────────────────────────────────────┐
                     │              Web Frontend               │
                     │         React + TypeScript + TW         │
                     └──────────────────┬──────────────────────┘
                                        │ HTTP/REST
                     ┌──────────────────▼──────────────────────┐
                     │              API Server                  │
                     │            Express + Zod                 │
                     │    Routes │ Services │ Validation        │
                     └────┬──────────┬───────────────┬─────────┘
                          │          │               │
               ┌──────────▼──┐  ┌───▼────┐  ┌───────▼────────┐
               │  PostgreSQL  │  │  Redis  │  │  File Storage  │
               │   (Drizzle)  │  │ BullMQ  │  │  (Local/S3)    │
               └──────────────┘  └───┬────┘  └────────────────┘
                                     │ Job Queue
                     ┌───────────────▼─────────────────────────┐
                     │            Worker Service                │
                     │                                          │
                     │  ┌─────────┐  ┌────────────────────┐    │
                     │  │ Pipeline│  │  Scanner Adapters   │    │
                     │  │ Engine  │  │                     │    │
                     │  │         │  │  Semgrep (SAST)     │    │
                     │  │ Validate│  │  ZAP (DAST)         │    │
                     │  │ Finger- │  │  Gitleaks (Secrets) │    │
                     │  │  print  │  │  OSV-Scanner (Deps) │    │
                     │  │ Execute │  │  Trivy (Infra)      │    │
                     │  │ Normlze │  │  + extensible...    │    │
                     │  │ Corrlt  │  │                     │    │
                     │  │ Report  │  └────────────────────┘    │
                     │  └─────────┘                             │
                     └──────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Node.js >= 20
- Docker & Docker Compose
- Git

### Using Docker Compose (recommended)

```bash
# Clone the repo
git clone <repo-url> && cd securescope

# Copy environment config
cp .env.example .env

# Start all services
docker compose -f infrastructure/docker/docker-compose.yml up -d

# Run database migrations
docker exec securescope-api node apps/api/dist/db/migrate.js

# Open the app
open http://localhost:3000
```

### Local Development

```bash
# Install dependencies
npm install

# Start infrastructure (DB + Redis)
docker compose -f infrastructure/docker/docker-compose.yml up -d postgres redis

# Copy env file
cp .env.example .env

# Run migrations
npm run db:migrate

# Start all services in development mode
npm run dev  # Runs API, Worker, and Web concurrently
```

## Monorepo Structure

```
securescope/
├── apps/
│   ├── api/          # Express REST API server
│   ├── web/          # React + Tailwind frontend
│   └── worker/       # BullMQ scan pipeline worker
├── packages/
│   ├── shared-types/ # TypeScript types, enums, interfaces
│   ├── scanner-sdk/  # Scanner adapter framework + adapters
│   ├── reporting/    # Multi-format report generation
│   ├── remediation/  # Fix proposal + patch application
│   ├── ui/           # Shared UI components (future)
│   └── config/       # Shared config utilities (future)
├── infrastructure/
│   ├── docker/       # Docker Compose + Dockerfiles
│   ├── k8s/          # Kubernetes manifests (future)
│   └── terraform/    # Terraform modules (future)
├── docs/             # Architecture documentation
├── scripts/          # Build and deployment scripts
└── testbeds/         # Sample vulnerable apps for testing
```

## Supported Scanners

| Category | Scanner | Status |
|----------|---------|--------|
| SAST | Semgrep | Adapter complete |
| DAST | OWASP ZAP | Adapter complete |
| Secrets | Gitleaks | Adapter complete |
| Dependencies | OSV-Scanner | Adapter complete |
| Infra/Container | Trivy | Adapter complete |
| API Security | Schemathesis | Planned |
| DAST | Nuclei | Planned |
| Secrets | TruffleHog | Planned |

## Key Features

- **Multi-layer scanning**: SAST, DAST, API, secrets, dependencies, infrastructure
- **Pluggable adapter framework**: Add new scanners by implementing the `ScannerAdapter` interface
- **Cross-scanner correlation**: Detects compound risks (e.g., vulnerable dep + reachable endpoint)
- **Approval-gated remediation**: No code changes without explicit user approval
- **Multi-format reports**: HTML, JSON, Markdown, CSV, SARIF
- **Secret safety**: All secrets encrypted at rest, redacted in logs/reports/UI
- **Audit trail**: Full logging of scans, approvals, and changes
- **Before/after validation**: Re-scan after remediation to verify fixes

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/targets` | Register a scan target |
| POST | `/api/v1/credentials` | Store encrypted credentials |
| POST | `/api/v1/scans` | Create and start a scan |
| GET | `/api/v1/scans/:id/status` | Get scan progress |
| GET | `/api/v1/findings` | Query findings with filters |
| POST | `/api/v1/remediation/approve` | Approve remediation proposals |
| POST | `/api/v1/remediation/apply` | Apply approved fixes |
| GET | `/api/v1/remediation/patch/:scanId` | Export unified patch |
| POST | `/api/v1/reports/generate` | Generate reports |
| GET | `/health` | Health check |

## Safety Guardrails

- Only scans user-authorized targets (attestation required)
- Defaults to safe scan profile
- Strong warnings for production environments
- No destructive exploitation payloads
- Secrets never exposed in UI, reports, or logs
- No auto-fix without explicit approval
- Full audit trail for all operations
- Credentials encrypted at rest with AES-256-GCM
- Rate limiting on all API endpoints
- Scanner timeout enforcement and isolation

## Phase Roadmap

### Phase 1 — MVP (Current)
- Core scan pipeline with 5 scanner adapters
- Normalized finding schema with correlation
- Web UI for scan management and findings review
- Remediation approval workflow
- Multi-format report generation
- Docker Compose deployment

### Phase 2 — Hardening
- Authentication and RBAC
- S3 storage backend
- WebSocket real-time scan progress
- Advanced deduplication
- Custom scanner rule support
- CI/CD integration (GitHub Actions, GitLab CI)

### Phase 3 — Advanced Remediation
- AI-assisted fix generation
- Dependency upgrade path analysis
- Automated PR creation
- Regression testing integration
- Compliance framework mapping (SOC2, PCI-DSS, HIPAA)

### Phase 4 — Scale & Integrations
- Kubernetes deployment with Helm charts
- Multi-tenant support
- Jira/Slack/Teams integration
- Scanner result caching
- Scheduled/recurring scans
- API for external tool integration

## License

Private — Internal use only.
