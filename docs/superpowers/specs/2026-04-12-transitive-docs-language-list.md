# Transitive Analysis Docs: Language List Update

**Date:** 2026-04-12
**File:** `site/docs/tools/vex.md`

## Problem

The Transitive Reachability Analysis section opens with:

> "For Python and JavaScript projects, the VEX command can trace call chains through transitive dependencies..."

This is outdated. The transitive analyzer now supports 7 languages: Python, JavaScript, Rust, Ruby, PHP, Java, and C#.

## Change

### `site/docs/tools/vex.md` — lines 72–74

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

## Scope

- One file, one section, two edits (language list + Go note).
- No other documentation changes.
- No code changes.
