---
name: duda
description: >
  DUDA — Isolation guardian skill for Claude Code. Prevents, diagnoses, and recovers
  isolation contamination in multi-layered architectures: multi-tenant SaaS,
  platform-derivative hierarchies, monorepo app boundaries, and microservice boundaries.
  Blocks execution below 95-point trust score and provides remediation paths.

  [INIT mode] Triggered by "duda init" or when DUDA_MAP.md is missing.
  Runs scripts/init.py to explore the project via topological sort and generate DUDA_MAP.md.

  [TRANSPLANT mode] Triggered when migration keywords ("migrate", "port", "copy from",
  "bring over", "use X in Y", "apply X to Y") are detected alongside file/layer/path references.
  Runs scripts/analyze.py → scripts/trust.py to measure trust, then executes strategy
  only when score >= 95.

  [AUDIT mode] Triggered by contamination keywords ("data leak", "wrong tenant",
  "showing other", "contamination", "why is X visible", "broken isolation").
  Runs scripts/audit.py to trace contamination paths and determine root cause.

  [SCAN mode] Lightweight mode: "duda scan <path>" for quick single-file/directory
  analysis without requiring DUDA_MAP. Outputs layer tag, risk assessment, import analysis.

  [ACT mode] Triggered by "duda fix", "duda act", or auto-enters after AUDIT/TRANSPLANT
  diagnosis. Generates fix code, shows diff preview, applies after confirmation.
  Evaluator-Optimizer loop: re-audits after fix, max 3 iterations.
  Progressive automation: SHOW → SUGGEST → APPLY → AUTO.

  [GUARD mode] Triggered by "duda guard" or CI/pre-commit integration.
  Checks staged/changed files for isolation breaches. Exits 0 (pass) or 1 (breach).

  Explicitly invocable via "duda" or "DUDA" keywords.
  Applies to all isolation architectures: platform→derivative hierarchies,
  B2B SaaS multi-tenant, monorepo app boundaries, and microservice boundaries.
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
| **First setup** — Applying DUDA to a project | `duda init` | Explores entire codebase and generates isolation map (DUDA_MAP.md). Auto-classifies each file by layer |
| **Quick check** — "Is this file safe to import?" | `duda scan <path>` | Analyzes imports and shows risk level instantly. **Works without a map** |
| **Code migration** — Moving features across layers | `duda transplant` | Analyzes source → measures 4-axis trust score → executes strategy only at 95+ points |
| **Incident response** — "Wrong tenant data is showing" | `duda audit` | Traces contamination path back to root cause (4 types) and provides fix strategy |
| **Auto-fix** — Apply fixes from diagnosis | `duda fix` | Generates fix code → shows diff preview → applies after confirmation. Up to 3 verification loops |
| **Pre-commit gate** — Check for breaches before commit | `duda guard` | Checks changed files for isolation violations. CI/pre-commit hook integration available |
| **Map refresh** — Codebase has changed significantly | `duda update` | Regenerates DUDA_MAP.md from current code state |

### What Projects Can Use DUDA?

| Isolation Type | Example | Typical Risk |
|---------------|---------|-------------|
| **Type A** Platform-Derivative | HQ platform → Franchise/Tenant apps | Upper-only features leak to lower layers |
| **Type B** Multi-tenant | Per-company data isolation in B2B SaaS | Cross-tenant data exposure |
| **Type C** Monorepo Boundary | `apps/admin` vs `apps/user` boundaries | Cross-app direct imports causing dependency tangles |
| **Type D** Microservice | Independently deployed service boundaries | Direct DB access bypassing API boundaries |

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

### Why Use DUDA?

- **Proactive blocking**: Catches isolation violations before code is committed or deployed
- **Self-learning**: Accumulates experience — same patterns skip analysis after 3+ encounters (cache hit)
- **Actionable guidance**: Doesn't just say "no" — tells you which strategy (direct reference / adapter / reimplementation) to use
- **Progressive automation**: SHOW (read-only) → SUGGEST (strategy) → APPLY (confirm+fix) → AUTO (cached instant fix)

<!-- HELP END -->

---

## Step 0 — Always First (Common to All Modes)

```bash
# 1. Check map state
ls DUDA_MAP.md 2>/dev/null && python scripts/trust.py --check-map || echo "MAP_MISSING"

# 2. Memory recall — check experience first (may skip analysis)
python scripts/memory.py recall --mode [mode] --source [path] --target [path]
```

- MAP_MISSING → auto-enter **INIT mode**
- Trust LOW → recommend `duda update` to user, then continue or abort
- Trust MEDIUM+ → proceed with current mode

**Memory Recall Interpretation:**

| Confidence | Meaning | Action |
|-----------|---------|--------|
| `CERTAIN` (5+ hits) | Same pattern confirmed 5+ times | Skip analysis, execute cached strategy immediately |
| `HIGH` (3+ hits) | High-confidence experience exists | Skip analysis, apply cached strategy |
| `MEDIUM` (2 hits) | Experience exists, needs verification | Quick analysis + compare with cache |
| `LOW` (1 hit) | Single prior experience | Full analysis, reference previous result |
| `UNKNOWN` | First encounter | Full analysis required |

When CERTAIN/HIGH, skip analysis steps and apply the cached strategy directly.
After every operation, record results to memory for future acceleration.

---

## INIT Mode

### When
- `duda init` or `duda initialize` command
- DUDA_MAP.md does not exist (auto-trigger)
- `duda update` command (regenerate map)

### Execution

```bash
python scripts/init.py --root . --mode [solo|team]
```

**What init.py does — Topological Flood Fill:**

```
1. Collect leaf files (files that import nothing from the project)
   → packages/shared-types, utils, constants, etc.

2. Topological Sort
   → Traverse from leaves upward sequentially
   → Skip already-tagged nodes (no duplicates)
   → Repeat until all nodes are tagged (no gaps)

3. Assign layer tags to each file
   [UPPER-ONLY ✓] — imports upper-only paths or contains upper-only identifiers
   [SHARED ✓]     — imports nothing layer-specific, or packages/ only
   [SHARED ?]     — ambiguous — collect grep evidence, then re-judge
   [LAYER:X]      — confirmed as specific layer only

4. Generate DUDA_MAP.md
5. Register boundary file checksums
6. Request user approval → approval confirms trust HIGH
```

**INIT Completion Output:**
```
✅ DUDA_MAP generated

Isolation types:  Type A + Type B
Hierarchy:        Platform > Organization > Tenant > Store
Files tagged:     347 complete / 12 ambiguous (manual review needed)
Boundary files:   8 checksums registered
Transplant deny:  4-tier BOM management, cost master data

Does this structure look correct? (Y / enter corrections)
```

Map is not used until approved.

---

## SCAN Mode (Lite — No Map Required)

### When
- `duda scan <path>` command
- Quick check without full INIT
- "Is this file safe to import in my tenant layer?"

### Execution

```bash
python scripts/analyze.py --source <path> --lite
```

**What SCAN does:**
```
1. Analyze all imports in the target file/directory
2. Check for upper-only identifiers (admin, system, platform keywords)
3. Detect tenant identifier presence in DB queries
4. Flag dynamic imports as [UNVERIFIABLE]
5. Output quick risk assessment
```

**SCAN Output:**
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

## SCOPE Mode (Feature-Centric Analysis) *(v2.1)*

### When
- `duda scope <feature-description>` command
- Developer describes a feature instead of providing a file path
- "Check isolation for the billing system"
- "Show me all files related to tenant onboarding"
- "What files are involved in the permission feature?"

### Execution

```bash
python scripts/scope.py --feature "<description>" [--depth 1] [--min-score 0.3]
```

**What scope.py does:**

```
1. Extract keywords from description + expand with synonym database
2. Search filenames and file contents for keyword matches
3. Expand via import chains (configurable depth, default 1-hop)
4. Score relevance (0.0~1.0) and filter by threshold
5. Group by DUDA_MAP layer tags (if map exists)
6. Detect cross-layer imports → flag violations
7. Assess risk level (LOW / MEDIUM / HIGH / CRITICAL)
8. Cache results for instant re-analysis
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--depth <n>` | 1 | Import chain expansion depth |
| `--min-score <f>` | 0.3 | Minimum relevance score |
| `--max-files <n>` | 20 | Maximum files to display |
| `--no-map` | false | Skip DUDA_MAP lookup |
| `--files-only` | false | Output file paths only (for piping) |
| `--json` | false | JSON output |

**SCOPE Output:**
```
🔍 DUDA SCOPE — "account permission management"

Keywords: permission, role, rbac, auth, grant, access, account, user
Discovered: 15 files across 4 directories

[PLATFORM] 3 files ██████░░░░░░░░░░░░░░ 20%
  src/platform/roles/superAdmin.ts        (0.95)
  src/platform/stores/roleStore.ts        (0.72)

[SHARED] 5 files ██████████░░░░░░░░░░ 33%
  src/shared/types/permission.ts          (0.98)
  src/shared/utils/rbac.ts                (0.91)

[TENANT] 4 files ████████░░░░░░░░░░░░ 27%
  src/tenant/admin/roleManager.tsx        (0.89)

⚠️ Cross-Layer: 3 violations (TENANT → PLATFORM)

Risk Level:  🟠 HIGH
Recommended:
  1. duda audit — trace full contamination path
  2. duda scan src/tenant/admin/roleManager.tsx
  3. duda fix — auto-generate adapter pattern
```

**Piping to other commands:**
```bash
# Scan each discovered file in detail
duda scope "auth" --files-only | xargs -I {} duda scan {}
```

---

## TRANSPLANT Mode

> **Principle: Not a single line of code is touched until trust score reaches 95.**

### Phase 0 — Intent Confirmation

When keywords are detected, do NOT execute immediately. Confirm first:
```
🦔 DUDA TRANSPLANT detected — "[original user message]"
Is this a migration/transplant operation? (Y / N)
```
N → exit. Y → proceed.

### Phase 1 — Pre-contamination Check at Destination

```bash
python scripts/audit.py --target [destination_path] --quick
```

If contamination found:
```
🔴 Existing contamination detected at destination
Recommend running AUDIT first, then TRANSPLANT.
Force proceed anyway? (not recommended)
```

### Phase 2 — Source Dissection

```bash
python scripts/analyze.py --source [source_path]
```

**What analyze.py does:**
```
- Extract all import paths + cross-reference with DUDA_MAP → layer tags
- Check hook/store/context usage
- Extract DB queries → verify isolation conditions (tenant identifiers)
- Detect dynamic import / runtime conditional logic patterns
  (import() / require( / role === / process.env)
  → [UNVERIFIABLE] tag + manual verification required
- Check for hardcoded upper-only identifiers
```

Tags assigned to each item:
- `[UPPER-ONLY]` — cannot be transplanted
- `[SHARED]` — safe to reference directly
- `[NEEDS-ADAPTER]` — same interface, separate implementation needed
- `[REBUILD]` — must be reimplemented from scratch
- `[UNVERIFIABLE]` — static analysis impossible, manual review required

### Phase 3 — Trust Score Measurement

```bash
python scripts/trust.py --mode transplant --source [path] --target [path]
```

**4-Axis Measurement:**

```
Map Trust      (×0.20):
  Boundary file checksum match    40pts
  File count unchanged            20pts
  User approval completed         30pts
  Zero ambiguous tags             10pts

Analysis Trust (×0.35):
  Import tagging completion rate  40pts (rate × 40)
  No dynamic logic               20pts (0 if exists + manual check required)
  DB isolation conditions verified 25pts
  UPPER-ONLY handling plan confirmed 15pts

Boundary Trust (×0.30):  ← NO COMPROMISE, 100pts required
  Isolation policy physically exists  40pts
  Destination contamination-free      40pts
  No transplant-deny list conflicts   20pts

Intent Trust   (×0.15):  ← 100pts required
  Source specified              30pts
  Destination specified         30pts
  Scope confirmed               20pts
  User explicitly confirmed     20pts
```

**Verdict:**
```
95~100pts → ✅ Execution permitted
85~94pts  → 🟡 Conditional — list shortfall items + re-check, then proceed
70~84pts  → 🟠 Hold — request user judgment, specify risk items
 ~69pts   → 🔴 Execution denied

On denial, output:
  Overall trust: 71pts (threshold: 95pts)
  Shortfall items:
    Analysis trust 58pts ← 3 dynamic imports unverified
    Boundary trust 60pts ← destination contamination detected
  Resolution order:
    1. Run AUDIT → boundary trust expected +40pts
    2. Manually verify 3 dynamic imports → analysis trust expected +20pts
    Expected after: 91pts → re-measure to proceed
```

### Phase 4 — Strategy Selection (95pts+ only)

Auto-selected based on tag distribution:

| Condition | Strategy |
|-----------|----------|
| All `[SHARED]` | **Strategy 1** — Direct reference |
| `[NEEDS-ADAPTER]` present, shared logic 60%+ | **Strategy 2** — Adapter branching |
| `[REBUILD]` present | **Strategy 3** — Reimplementation |
| `[UPPER-ONLY]` in core, or transplant-deny list match | **Strategy 4** — Transplant denied |

### Phase 5 — Execution

Auto-generate and run strategy-specific Claude Code execution prompts.

Execution rules (always included):
```
- Never copy source files as-is
- Never import [UPPER-ONLY] items in lower layers
- Include tenant identifiers in all DB queries
- Verify isolation policies apply to newly created files
```

### Phase 6 — Map Update + Memory Record

```bash
# Partial map refresh
python scripts/map_update.py --diff

# Record decision to memory for future learning
python scripts/memory.py record \
  --mode TRANSPLANT \
  --source [source_path] \
  --target [target_path] \
  --result '{"strategy": [number], "trust_score": [score], "risk": "[level]"}'
```

Only refresh upstream nodes of changed files. No full re-scan.
Recorded results apply instantly on next identical path request.

---

## AUDIT Mode

### Phase 1 — Symptom Capture

```
Identify:
□ Which layer/screen shows the symptom
□ What shouldn't be exposed (data? functionality? UI?)
□ Which layer's content is incorrectly visible
□ When did it start / after which operation
```

### Phase 2 — Tunnel Tracing

```bash
python scripts/audit.py --symptom "[symptom]" --layer "[layer]"
```

**What audit.py does — isolation-type-specific search:**

```
Type A (Platform-Derivative):
  grep -r "from.*platform/" [lower_layer_path] --include="*.ts" --include="*.tsx"
  → Detect upper-only imports in lower layers

Type B (Multi-tenant):
  → Detect DB queries missing tenant identifiers
  → Check for tables without RLS policies

Type C (Monorepo):
  grep -r "from.*apps/" [app_path] --include="*.ts"
  → Detect cross-app direct imports

Type D (Microservice):
  → Detect direct DB access across service boundaries
  → Detect API boundary bypass (direct function calls between services)
```

### Phase 3 — Root Cause Determination

```
A. Isolation policy leak  — queries without tenant identifiers / unapplied policies
B. Component contamination — [UPPER-ONLY] code copy-pasted to lower layer (most common)
C. State contamination     — shared store/context scope not separated
D. Boundary violation      — direct import / direct DB access across boundaries
```

### Phase 4 — Recovery + Map Update + Memory Record

After applying type-specific fixes:

```bash
# Partial map refresh
python scripts/map_update.py --diff

# Record AUDIT result to memory
python scripts/memory.py record \
  --mode AUDIT \
  --source [symptom_path] \
  --result '{"root_cause": "[type]", "contamination_path": "[path]", "fix_applied": true}'
```

If the same contamination pattern recurs, memory provides instant root cause identification.

**AUDIT Output:**
```
## 🔍 DUDA AUDIT

Symptom:          [summary]
Isolation type:   [Type A/B/C/D]
Root cause type:  [A/B/C/D]
Root cause location: [file/policy name]
Contamination path:  [A → B → C]
Impact scope:     [file list]

Fix prompt:
[executable block]

Verification:
□ [auto-generated checklist item 1]
□ [auto-generated checklist item 2]
□ [auto-generated checklist item 3]
```

---

## ACT Mode — Automated Fix Generation

> **Ref:** bkit pdca-iterator (Evaluator-Optimizer loop), ESLint --fix, Terraform plan-before-apply.
> See `references/act-guard.md` for full specification and `REFERENCES.md` for attribution.

### When
- After AUDIT identifies contamination → `duda fix`
- After TRANSPLANT selects strategy → auto-enters ACT
- Explicit: `duda act` or `duda fix`

### Progressive Automation (4 Stages)

| Stage | Command | Requires | Output |
|-------|---------|----------|--------|
| **SHOW** | `duda scan` | Nothing | Read-only risk assessment |
| **SUGGEST** | `duda audit` / `duda transplant` | Map | Strategy + shortfalls (no code changes) |
| **APPLY** | `duda fix` / `duda act` | Trust ≥ 95 | Generate fix → show diff → confirm → apply |
| **AUTO** | `duda fix --auto` | Trust ≥ 95 + Memory ≥ HIGH | Apply cached fix, notify only |

### Flow

```
1. Parse diagnosis output (AUDIT root cause or TRANSPLANT strategy)
2. Generate fix plan with diff preview (read-only)
3. User confirms → apply fixes in reverse file order
4. Re-audit to verify (Evaluator-Optimizer loop, max 3 iterations)
5. Update map + memory
```

Fix plans are root-cause-specific:
- **Policy leak** → Add tenant filter / RLS
- **Component contamination** → Create adapter or shared version
- **State contamination** → Split store/context by layer
- **Boundary violation** → Replace direct import with API call

---

## GUARD Mode — CI / Pre-commit Isolation Gate

> **Ref:** Terraform drift detection, GitHub Actions CI gate.
> See `references/act-guard.md` for setup templates and `REFERENCES.md` for attribution.

### When
- `duda guard` — check all staged files
- `duda guard --ci` — non-interactive CI mode (exit code 0/1)
- Pre-commit hook or GitHub Actions integration

### Flow

```
1. Collect staged/changed files
2. Run isolation breach check (imports, DB queries, boundary crossings)
3. Output results:
   - Interactive: human-readable with suggestions
   - CI (--ci): JSON with exit code 0 (pass) / 1 (breach)
4. Block commit/PR if breaches found
```

See `references/act-guard.md` for pre-commit hook setup and GitHub Actions workflow template.

---

## Isolation Type Reference

See `references/patterns.md` for detailed risk and fix patterns.

| Type | Description |
|------|-------------|
| Type A Platform-Derivative | Upper→lower feature inheritance (Platform→Organization→Tenant) |
| Type B Multi-tenant | Per-company/org data isolation within shared codebase |
| Type C Monorepo Boundary | Code isolation between apps/ in monorepo |
| Type D Microservice | API boundary isolation between independently deployed services |

---

## CLAUDE.md Integration

Add this section to your project root CLAUDE.md for DUDA auto-configuration:

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

## Recursive Learning Memory System

> The more you use it, the more it accumulates, and the faster it processes.
> It doesn't re-analyze from scratch — it builds on experience.

### Storage Structure

```
.duda/memory/
├── pattern_db.json    ← TRANSPLANT/AUDIT result pattern learning
│                         Strategy history per source+target combination
├── path_cache.json    ← Path→layer-tag cache
│                         Permanent reuse of flood-fill results
└── decision_log.json  ← Complete decision history
                          Accuracy auto-corrects via feedback
```

### Confidence Growth Path

```
First run    [UNKNOWN]  → Full analysis required
1 experience [LOW]      → Full analysis + reference previous
2 experiences [MEDIUM]  → Quick analysis + compare with cache
3 experiences [HIGH]    → Skip analysis, apply cache immediately  ← acceleration starts
5+ experiences [CERTAIN] → Instant processing, minimal tokens
```

### Accuracy Correction via Feedback

When results are wrong:
```bash
python scripts/memory.py feedback \
  --decision-id d0042 --correct false --note "Strategy 2 was correct"
```
→ Confidence for that pattern auto-downgrades → re-analysis triggered on next run

### Learning Status Check

```bash
python scripts/memory.py stats
```

```
🧠 DUDA Recursive Learning Status
───────────────────────────────
🚀 Acceleration Phase — mostly cache hits

Path cache:    347 entries
  CERTAIN:    89
  HIGH:      142

Pattern DB:    38 entries
  Avg hits:   4.2

Decision log:  156 entries
  Cache hit rate: 71.2%
  Processing speedup: 3.8x
```

---

## Manual Mode (No Python Required)

When Python is not available, use grep-based analysis:

- **INIT:** `grep -rn "from\|import" --include="*.ts" src/` → tag each file as SHARED/UPPER-ONLY/LAYER:X → create DUDA_MAP.md
- **TRANSPLANT:** List imports in source → check layer tags → check DB queries for tenant ID
- **AUDIT:** `grep -rn "from.*platform" src/tenant/` → find cross-layer imports → `grep -rn "\.from(" src/ | grep -v "org_id"` → find missing tenant filters

---

## Core Principles

```
1. No DUDA_MAP → INIT first
2. Migration keyword detected → confirm intent → no code touched until 95-point trust
3. Copy-first approach is structurally blocked
4. [UPPER-ONLY] items are never imported in lower layers
5. Unknown segments are marked [UNVERIFIABLE] — never filled by guessing
6. After every operation: partial map refresh + memory record
7. Self-reinforcing: map precision and memory depth grow with each use
```
