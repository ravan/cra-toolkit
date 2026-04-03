# CLAUDE.md

## Commands

| Task | Command |
|------|---------|
| Build | `task build` |
| Test | `task test` |
| Lint | `task lint` |
| Format | `task fmt` |
| All quality gates | `task quality` |
| Clean | `task clean` |

## Structure

| Path | Purpose |
|------|---------|
| `cmd/cra/` | Binary entrypoint |
| `internal/cli/` | CLI wiring (urfave/cli v3) |
| `pkg/vex/` | VEX status determination |
| `pkg/policykit/` | CRA Annex I policy evaluation (embedded OPA) |
| `pkg/report/` | Art. 14 notification generation |
| `pkg/evidence/` | Compliance evidence bundling |
| `pkg/csaf/` | Scanner-to-CSAF advisory bridge |
| `pkg/formats/` | Shared SBOM/VEX/CSAF types |
| `pkg/vuln/` | Shared vuln data fetching |
| `policies/` | Rego policy files (embedded) |
| `templates/` | Report templates (embedded) |
