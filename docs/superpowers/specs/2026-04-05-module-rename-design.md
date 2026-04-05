# Module Rename: suse-cra-toolkit → cra-toolkit

**Date:** 2026-04-05

## Goal

Rename the Go module path from `github.com/ravan/suse-cra-toolkit` to `github.com/ravan/cra-toolkit` to match the new GitHub repository name. The local directory name (`suse-cra-toolkit`) is unchanged.

## Approach

Scripted find-and-replace using `go mod edit` (for `go.mod`) and `sed` (for all other files).

## Steps

1. **Update `go.mod`** — `go mod edit -module github.com/ravan/cra-toolkit`
2. **Bulk replace** — `sed -i` across all `.go`, `.json`, `.yaml`, `.yml`, `.md` files, replacing `github.com/ravan/suse-cra-toolkit` with `github.com/ravan/cra-toolkit`. Excludes `.worktrees/` and `.claire/` directories.
3. **Update git remote** — `git remote set-url origin git@github.com:ravan/cra-toolkit.git`
4. **Verify** — `task build && task test`

## Scope

| File type | Count | Notes |
|-----------|-------|-------|
| Go source + tests | 149 | Import paths |
| testdata JSON/YAML | ~30 | PURL/component identifiers |
| Docs/plans/specs (Markdown) | ~12 | References in text |
| `Taskfile.yml` | 1 | Any references |
| `go.mod` | 1 | Module declaration |

## Out of Scope

- Local directory rename (stays `suse-cra-toolkit`)
- Go module major version bump
- Any code logic changes
