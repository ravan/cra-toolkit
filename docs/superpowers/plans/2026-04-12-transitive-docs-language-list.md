# Transitive Analysis Docs: Language List Update Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update `site/docs/tools/vex.md` to list all 7 supported transitive analysis languages and add a note explaining Go's coverage via `govulncheck`.

**Architecture:** Single-file markdown edit. Replace the outdated "Python and JavaScript" language reference with the full list, and add a Go note immediately after.

**Tech Stack:** Markdown, MkDocs site at `site/docs/`.

---

## File Map

| File | Action |
|------|--------|
| `site/docs/tools/vex.md` | Modify lines 72–74 |

---

### Task 1: Update the transitive language list in vex.md

**Files:**
- Modify: `site/docs/tools/vex.md` (lines 72–74)

- [ ] **Step 1: Verify the current text**

Run: `grep -n "Python and JavaScript" site/docs/tools/vex.md`
Expected output:
```
72:For Python and JavaScript projects, the VEX command can trace call chains through
```

- [ ] **Step 2: Apply the edit**

In `site/docs/tools/vex.md`, replace lines 72–74:

**Before:**
```
For Python and JavaScript projects, the VEX command can trace call chains through
transitive dependencies to determine whether a vulnerability sitting inside a
library the application does not import directly is actually reachable.
```

**After:**
```
For Python, JavaScript, Rust, Ruby, PHP, Java, and C# projects, the VEX command
can trace call chains through transitive dependencies to determine whether a
vulnerability sitting inside a library the application does not import directly
is actually reachable.

> **Go:** Transitive call analysis for Go is handled automatically by
> `govulncheck`, which the VEX command invokes directly.
```

- [ ] **Step 3: Verify the change**

Run: `grep -n "Python, JavaScript, Rust" site/docs/tools/vex.md`
Expected output:
```
72:For Python, JavaScript, Rust, Ruby, PHP, Java, and C# projects, the VEX command
```

Run: `grep -n "govulncheck" site/docs/tools/vex.md`
Expected: line number with the Go note present.

Run: `grep -c "Python and JavaScript" site/docs/tools/vex.md`
Expected: `0` (old text gone)

- [ ] **Step 4: Commit**

```bash
git add site/docs/tools/vex.md
git commit -m "docs: update transitive analysis to list all 7 supported languages"
```
