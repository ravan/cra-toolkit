# Module Rename Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the Go module path from `github.com/ravan/suse-cra-toolkit` to `github.com/ravan/cra-toolkit` across all files in the repo.

**Architecture:** Three-pass find-and-replace: (1) `go mod edit` for `go.mod`, (2) `sed` across all Go source files, (3) `sed` across all non-Go files (JSON, YAML, Markdown). Git remote is already correct (`git@github.com:ravan/cra-toolkit.git`).

**Tech Stack:** Go, `go mod edit`, macOS `sed -i ''`, `task`

---

## Files Modified

- `go.mod` — module declaration
- `Taskfile.yml` — `MODULE` variable
- `internal/cli/*.go` (8 files) — import paths
- `cmd/cra/main.go` — import path
- `pkg/**/*.go` (140 files) — import paths
- `testdata/integration/**/*.json` (~28 files) — PURL/component identifiers
- `testdata/integration/**/*.yaml` (~3 files) — product config references
- `docs/**/*.md` (~12 files) — text references
- `site/**` — rendered site references

---

### Task 1: Update go.mod

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Run `go mod edit`**

```bash
go mod edit -module github.com/ravan/cra-toolkit
```

- [ ] **Step 2: Verify go.mod**

```bash
head -1 go.mod
```

Expected output:
```
module github.com/ravan/cra-toolkit
```

- [ ] **Step 3: Commit**

```bash
git add go.mod
git commit -m "chore: rename module to github.com/ravan/cra-toolkit"
```

---

### Task 2: Replace module path in all Go source files

**Files:**
- Modify: all `*.go` files (excluding `.worktrees/` and `.claire/`)

- [ ] **Step 1: Run bulk replacement**

```bash
find . -name "*.go" \
  -not -path "./.worktrees/*" \
  -not -path "./.claire/*" \
  | xargs sed -i '' 's|github.com/ravan/suse-cra-toolkit|github.com/ravan/cra-toolkit|g'
```

- [ ] **Step 2: Verify no old references remain in Go files**

```bash
grep -r "suse-cra-toolkit" --include="*.go" . \
  --exclude-dir=.worktrees --exclude-dir=.claire
```

Expected output: (empty — no matches)

- [ ] **Step 3: Commit**

```bash
git add -u
git commit -m "chore: update import paths to github.com/ravan/cra-toolkit"
```

---

### Task 3: Replace module path in non-Go files

**Files:**
- Modify: `Taskfile.yml`, `testdata/**/*.json`, `testdata/**/*.yaml`, `docs/**/*.md`, `site/**`

- [ ] **Step 1: Run bulk replacement across non-Go files**

```bash
find . \( -name "*.json" -o -name "*.yaml" -o -name "*.yml" -o -name "*.md" \) \
  -not -path "./.worktrees/*" \
  -not -path "./.claire/*" \
  | xargs sed -i '' 's|github.com/ravan/suse-cra-toolkit|github.com/ravan/cra-toolkit|g'
```

- [ ] **Step 2: Verify no old references remain in non-Go files**

```bash
grep -r "suse-cra-toolkit" \
  --include="*.json" --include="*.yaml" --include="*.yml" --include="*.md" \
  --exclude-dir=.worktrees --exclude-dir=.claire \
  .
```

Expected output: (empty — no matches)

- [ ] **Step 3: Verify no old references remain anywhere in the repo**

```bash
grep -r "suse-cra-toolkit" . \
  --exclude-dir=.worktrees --exclude-dir=.claire \
  --exclude-dir=.git
```

Expected output: (empty — no matches)

- [ ] **Step 4: Commit**

```bash
git add -u
git commit -m "chore: update non-Go files to github.com/ravan/cra-toolkit"
```

---

### Task 4: Build and test verification

- [ ] **Step 1: Build**

```bash
task build
```

Expected: exits 0, binary produced at expected path with no errors.

- [ ] **Step 2: Run tests**

```bash
task test
```

Expected: all tests pass, no compilation errors referencing the old module path.

- [ ] **Step 3: If build or tests fail**

Check for any remaining old references:
```bash
grep -r "suse-cra-toolkit" . --exclude-dir=.git --exclude-dir=.worktrees --exclude-dir=.claire
```

Fix any found occurrences with:
```bash
sed -i '' 's|github.com/ravan/suse-cra-toolkit|github.com/ravan/cra-toolkit|g' <file>
```

Then re-run `task build && task test`.
