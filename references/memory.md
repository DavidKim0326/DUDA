# Recursive Learning Memory System

> Read this when working with DUDA's memory commands or when understanding the caching behavior.

## Why Memory Matters

Without memory, DUDA re-analyzes from scratch every time — even for patterns it has seen before. The memory system turns repeated operations from O(n) analysis into O(1) cache lookups. In practice, after ~3 uses on the same codebase, most operations skip the analysis phase entirely.

---

## Storage Structure

```
.duda/memory/
├── pattern_db.json    ← TRANSPLANT/AUDIT result pattern learning
│                         Strategy history per source+target combination
├── path_cache.json    ← Path→layer-tag cache
│                         Permanent reuse of flood-fill results
└── decision_log.json  ← Complete decision history
                          Accuracy auto-corrects via feedback
```

---

## Confidence Growth Path

```
First run    [UNKNOWN]  → Full analysis required
1 experience [LOW]      → Full analysis + reference previous
2 experiences [MEDIUM]  → Quick analysis + compare with cache
3 experiences [HIGH]    → Skip analysis, apply cache immediately  ← acceleration starts
5+ experiences [CERTAIN] → Instant processing, minimal tokens
```

---

## Memory Recall (Step 0)

```bash
python scripts/memory.py recall --mode [mode] --source [path] --target [path]
```

| Confidence | Action |
|-----------|--------|
| `CERTAIN` (5+ hits) | Skip analysis, execute cached strategy immediately |
| `HIGH` (3+ hits) | Skip analysis, apply cached strategy |
| `MEDIUM` (2 hits) | Quick analysis + compare with cache |
| `LOW` (1 hit) | Full analysis, reference previous result |
| `UNKNOWN` | Full analysis required |

---

## Recording Results

After every operation, record results so future runs accelerate:

```bash
python scripts/memory.py record \
  --mode [TRANSPLANT|AUDIT] \
  --source [source_path] \
  --target [target_path] \
  --result '{"strategy": N, "trust_score": S, "risk": "level"}'
```

---

## Accuracy Correction

When a cached result turns out to be wrong, feedback auto-downgrades confidence so the pattern gets re-analyzed next time:

```bash
python scripts/memory.py feedback \
  --decision-id d0042 --correct false --note "Strategy 2 was correct"
```

---

## Status Check

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
