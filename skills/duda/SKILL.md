---
name: duda
description: >
  DUDA — Isolation guardian for Claude Code. Prevents, diagnoses, and recovers
  isolation contamination in multi-layered architectures. Blocks execution below
  95-point trust score and provides remediation paths.
  Use this skill whenever isolation, tenant separation, layer boundaries, or
  cross-layer imports are relevant — even if the user doesn't say "duda" explicitly.
  Trigger on: "duda", "DUDA", migration keywords ("migrate", "port", "copy from",
  "bring over", "use X in Y"), contamination keywords ("data leak", "wrong tenant",
  "showing other", "broken isolation"), or any multi-tenant/monorepo boundary concern.
---

# DUDA — Isolation Guardian Skill

<!-- HELP START — When ARGUMENTS is "help", output ONLY this section (until HELP END) and stop. Do NOT output mode details or internal specifications below. -->

## What is DUDA?

**A skill that prevents AI agents from breaking isolation boundaries when modifying code in multi-layered projects.**

> Moles appear separate above ground, but underground they're all connected by tunnels.
> A transplant request is executed only after mapping the entire tunnel system.
> Execution is blocked below a 95-point trust score.

### Problems DUDA Solves

| Scenario | Without DUDA | With DUDA |
|----------|-------------|-----------|
| Copy admin component to tenant layer | Admin-only data exposed to tenants. Found after deployment | Blocked before copy with `[UPPER-ONLY]` tag. Suggests adapter pattern |
| DB query missing `org_id` filter | Other tenant's data leaks. Found via customer report | Detects missing tenant identifier in query analysis. Trust score drops → blocked |
| Direct import across monorepo apps | Build breaks + permission bypass. Found in CI | `duda guard` blocks boundary violation before commit |
| Direct DB access between microservices | Service boundary collapses. Found during outage | Audit detects API bypass path. Provides fix strategy |

**In short**: AI creates "working code" but silently breaks isolation — DUDA catches this before a single line of code is touched.

### When to Use Each Command

| Situation | Command | What it does |
|-----------|---------|-------------|
| **First setup** | `duda init` | Explores codebase and generates isolation map (DUDA_MAP.md) |
| **Quick check** | `duda scan <path>` | Analyzes imports and shows risk level. **Works without a map** |
| **Feature analysis** | `duda scope <desc>` | Discovers files related to a feature, groups by layer |
| **Code migration** | `duda transplant` | 4-axis trust score → executes strategy only at 95+ points |
| **Incident response** | `duda audit` | Traces contamination path back to root cause |
| **Auto-fix** | `duda fix` | Generates fix code → diff preview → applies after confirmation |
| **Pre-commit gate** | `duda guard` | Checks changed files for isolation violations |
| **Map refresh** | `duda update` | Regenerates DUDA_MAP.md from current code state |

### What Projects Can Use DUDA?

| Isolation Type | Example | Typical Risk |
|---------------|---------|-------------|
| **Type A** Platform-Derivative | HQ platform → Franchise/Tenant apps | Upper-only features leak to lower layers |
| **Type B** Multi-tenant | Per-company data isolation in B2B SaaS | Cross-tenant data exposure |
| **Type C** Monorepo Boundary | `apps/admin` vs `apps/user` boundaries | Cross-app direct imports |
| **Type D** Microservice | Independently deployed service boundaries | Direct DB access bypassing APIs |

Multiple types can coexist in a single project (e.g., Type A + Type B).

### How It Works

```
1. Map first (INIT)     — Identify which file belongs to which layer
2. Measure trust        — 4-axis scoring (Map/Analysis/Boundary/Intent), 0~100 points
3. Block below 95       — Shows shortfall items + resolution order
4. Learn after action   — Records experience for faster processing next time
```

### Quick Start

```bash
duda init              # 1. Generate isolation map (one-time setup)
duda scan src/some/    # 2. Quick-check a specific path
duda transplant        # 3. Migrate code (trust score gate)
duda audit             # 4. Diagnose isolation contamination
duda fix               # 5. Auto-fix from diagnosis
duda guard             # 6. Pre-commit isolation breach check
```

<!-- HELP END -->

---

## Step 0 — Always First (Common to All Modes)

Before any mode, check map state and memory. Memory exists because re-analyzing the same patterns wastes time — if DUDA has seen this exact source→target before, it can skip analysis entirely.

```bash
ls DUDA_MAP.md 2>/dev/null && python scripts/trust.py --check-map || echo "MAP_MISSING"
python scripts/memory.py recall --mode [mode] --source [path] --target [path]
```

- MAP_MISSING → auto-enter **INIT mode**
- Memory CERTAIN/HIGH → skip analysis, apply cached strategy directly
- Memory MEDIUM/LOW/UNKNOWN → proceed with full or partial analysis

See `references/memory.md` for confidence levels and caching details.

---

## INIT Mode

### When
- `duda init` or `duda update` command
- DUDA_MAP.md does not exist (auto-trigger)

### Execution

```bash
python scripts/init.py --root . --mode [solo|team]
```

init.py uses topological flood fill: collect leaf files (those that import nothing from the project), traverse upward, and tag each file as `[UPPER-ONLY]`, `[SHARED]`, `[SHARED ?]` (ambiguous), or `[LAYER:X]`. This bottom-up approach ensures no file is tagged before its dependencies are understood — preventing cascade mis-classification.

**Completion output:**
```
✅ DUDA_MAP generated

Isolation types:  Type A + Type B
Hierarchy:        Platform > Organization > Tenant > Store
Files tagged:     347 complete / 12 ambiguous (manual review needed)
Boundary files:   8 checksums registered

Does this structure look correct? (Y / enter corrections)
```

Map is not used until the user approves — because a wrong map is worse than no map.

---

## SCAN Mode (No Map Required)

### When
- `duda scan <path>` command
- "Is this file safe to import in my tenant layer?"

```bash
python scripts/analyze.py --source <path> --lite
```

Analyzes imports, checks for upper-only identifiers, detects tenant identifier presence in DB queries, and flags dynamic imports as `[UNVERIFIABLE]`.

```
🔍 DUDA SCAN — src/components/MenuCard.tsx

Imports:     5 total
  [SHARED]         3  (react, next/image, @/lib/utils)
  [UPPER-ONLY]     1  (from @/platform/stores/rawCostStore)
  [NEEDS-ADAPTER]  1  (from @/platform/hooks/useMenu)

Risk Level:  🟡 MEDIUM — upper-only dependency detected
Suggestion:  Cannot import directly. Use adapter pattern (Strategy 2).
```

---

## SCOPE Mode (Feature-Centric Analysis)

### When
- `duda scope <feature-description>` command
- Developer describes a feature instead of providing a file path

```bash
python scripts/scope.py --feature "<description>" [--depth 1] [--min-score 0.3]
```

Discovers files by keyword search + import chain expansion, groups by DUDA_MAP layer, and flags cross-layer violations. Useful when you know the feature but not the file paths.

Options: `--depth N`, `--min-score F`, `--max-files N`, `--no-map`, `--files-only`, `--json`

```
🔍 DUDA SCOPE — "account permission management"

Keywords: permission, role, rbac, auth, grant, access
Discovered: 15 files across 4 directories

[PLATFORM] 3 files  [SHARED] 5 files  [TENANT] 4 files

⚠️ Cross-Layer: 3 violations (TENANT → PLATFORM)
Risk Level:  🟠 HIGH
```

---

## TRANSPLANT Mode

Code migration is where most isolation contamination originates. A developer says "use X from platform in tenant" and the AI happily copies files — breaking every boundary along the way. DUDA's transplant flow exists to make this structurally impossible.

### Phase 0 — Intent Confirmation

When migration keywords are detected, confirm before doing anything:
```
🦔 DUDA TRANSPLANT detected — "[original user message]"
Is this a migration/transplant operation? (Y / N)
```

### Phase 1 — Pre-contamination Check

```bash
python scripts/audit.py --target [destination_path] --quick
```

If the destination is already contaminated, fix that first — transplanting into a dirty target compounds the problem.

### Phase 2 — Source Dissection

```bash
python scripts/analyze.py --source [source_path]
```

Every import and dependency gets tagged:
- `[UPPER-ONLY]` — cannot be transplanted (accessing this from a lower layer leaks privileged functionality)
- `[SHARED]` — safe to reference directly
- `[NEEDS-ADAPTER]` — same interface, but needs a separate implementation per layer
- `[REBUILD]` — must be reimplemented from scratch
- `[UNVERIFIABLE]` — dynamic imports or runtime branching that static analysis can't resolve; requires manual review

### Phase 3 — Trust Score

```bash
python scripts/trust.py --mode transplant --source [path] --target [path]
```

4-axis measurement: Map Trust (×0.20), Analysis Trust (×0.35), Boundary Trust (×0.30), Intent Trust (×0.15). The 95-point threshold exists because below it, the probability of undetected isolation breach rises sharply. See `references/trust-scoring.md` for the full breakdown of each axis and why the weights are set this way.

| Score | Verdict |
|-------|---------|
| 95-100 | ✅ Execute |
| 85-94 | 🟡 Conditional — list shortfalls, re-check |
| 70-84 | 🟠 Hold — user judgment required |
| <70 | 🔴 Denied — show resolution order |

### Phase 4 — Strategy Selection (95pts+ only)

| Condition | Strategy |
|-----------|----------|
| All `[SHARED]` | **Strategy 1** — Direct reference |
| `[NEEDS-ADAPTER]` present, shared logic 60%+ | **Strategy 2** — Adapter branching |
| `[REBUILD]` present | **Strategy 3** — Reimplementation |
| `[UPPER-ONLY]` in core | **Strategy 4** — Transplant denied |

### Phase 5 — Execution + Cleanup

Execute strategy, then refresh map and record to memory:
```bash
python scripts/map_update.py --diff
python scripts/memory.py record --mode TRANSPLANT --source [s] --target [t] --result '{...}'
```

---

## AUDIT Mode

### Phase 1 — Symptom Capture

Identify: which layer shows the problem, what data/functionality shouldn't be visible, and when it started. These four questions narrow the search space dramatically.

### Phase 2 — Tunnel Tracing

```bash
python scripts/audit.py --symptom "[symptom]" --layer "[layer]"
```

audit.py runs isolation-type-specific searches:
- **Type A**: grep for upper-only imports in lower layers
- **Type B**: detect DB queries missing tenant identifiers, tables without RLS
- **Type C**: detect cross-app direct imports
- **Type D**: detect direct DB access or API bypass across service boundaries

### Phase 3 — Root Cause

Four categories — knowing which one you're dealing with determines the fix:
- **A. Policy leak** — queries without tenant identifiers
- **B. Component contamination** — `[UPPER-ONLY]` code in lower layer (most common)
- **C. State contamination** — shared store/context not separated by layer
- **D. Boundary violation** — direct import or DB access across boundaries

### Phase 4 — Recovery + Map Update

Apply type-specific fix, refresh map, record to memory. Output includes contamination path, impact scope, fix prompt, and verification checklist. See `references/patterns.md` for detailed risk/fix patterns by isolation type.

---

## ACT Mode — Automated Fix

After AUDIT or TRANSPLANT produces a diagnosis, ACT generates the actual fix code. It follows a confirm-before-apply pattern (like `terraform plan` → `apply`) because automated fixes to isolation boundaries should never be silent.

### Progressive Automation

| Stage | Trigger | What happens |
|-------|---------|-------------|
| **SHOW** | `duda scan` | Read-only risk assessment |
| **SUGGEST** | `duda audit/transplant` | Strategy + shortfalls, no code changes |
| **APPLY** | `duda fix` | Generate fix → diff preview → confirm → apply |
| **AUTO** | `duda fix --auto` | Cached fix applied instantly (requires Memory ≥ HIGH) |

Flow: parse diagnosis → generate fix plan with diff → user confirms → apply → re-audit to verify (max 3 iterations). See `references/act-guard.md` for full specification.

---

## GUARD Mode — CI / Pre-commit Gate

Catches isolation breaches before they reach the repository. Think of it as a linter for isolation boundaries — runs on staged files and blocks commits that violate the rules.

```bash
duda guard          # Interactive — human-readable with suggestions
duda guard --ci     # CI mode — JSON output, exit code 0 (pass) / 1 (breach)
```

See `references/act-guard.md` for pre-commit hook setup and GitHub Actions workflow template.

---

## Isolation Type Reference

See `references/patterns.md` for detailed risk and fix patterns per type.

| Type | Description |
|------|-------------|
| Type A Platform-Derivative | Upper→lower feature inheritance (Platform→Organization→Tenant) |
| Type B Multi-tenant | Per-company/org data isolation within shared codebase |
| Type C Monorepo Boundary | Code isolation between apps/ in monorepo |
| Type D Microservice | API boundary isolation between independently deployed services |

---

## CLAUDE.md Integration

Add this to your project's CLAUDE.md so DUDA auto-detects the architecture without asking:

```markdown
## DUDA Context

Isolation type: [Type A / B / C / D]

Hierarchy:
  - [Upper]: [role]
  - [Lower]: [role]

Isolation boundary:
  - Method: [RLS / middleware / import rules]
  - Tenant identifier: [column name]
  - Upper-only paths: [paths]
  - Lower-only paths: [paths]
  - Shared paths: [paths]

Transplant deny list:
  - [feature name]: [reason]
```

---

## Reference Files

- `references/trust-scoring.md` — Full 4-axis breakdown, why 95 points, weight rationale
- `references/memory.md` — Memory system, confidence levels, caching behavior
- `references/act-guard.md` — ACT fix specification, GUARD CI templates
- `references/patterns.md` — Risk/fix patterns by isolation type (A/B/C/D)
