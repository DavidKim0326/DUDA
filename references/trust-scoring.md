# Trust Score — 4-Axis Measurement Detail

> Read this when running TRANSPLANT Phase 3 or when trust score details are needed.

---

## Why 95 Points?

100 would block operations where minor ambiguities exist but the core isolation is sound — static analysis can't always resolve every dynamic import or runtime branch. 95 allows those edge cases while still blocking genuinely risky operations. The remaining 5 points account for inherent uncertainty in static analysis. Below 95, the probability of an undetected isolation breach rises sharply based on real-world contamination incidents.

---

## 4-Axis Breakdown

Each axis measures a different aspect of confidence. The weights reflect how much damage a failure in that area causes:

### Map Trust (×0.20)

The map is foundational but relatively stable once approved — hence the lower weight.

```
Boundary file checksum match    40pts
File count unchanged            20pts
User approval completed         30pts
Zero ambiguous tags             10pts
```

### Analysis Trust (×0.35)

This is the highest-weighted axis because incomplete import analysis is the #1 cause of contamination in practice. A missed `[UPPER-ONLY]` import silently leaks privileged data.

```
Import tagging completion rate  40pts (rate × 40)
No dynamic logic               20pts (0 if exists + manual check required)
DB isolation conditions verified 25pts
UPPER-ONLY handling plan confirmed 15pts
```

### Boundary Trust (×0.30)

This axis has a hard floor: 100pts required, no compromise. If the isolation policy doesn't physically exist or the destination is already contaminated, no amount of careful analysis can make the transplant safe.

```
Isolation policy physically exists  40pts
Destination contamination-free      40pts
No transplant-deny list conflicts   20pts
```

### Intent Trust (×0.15)

Also requires 100pts. This is a sanity check — did the user actually specify what they want to move and where? Prevents accidental execution from vague requests.

```
Source specified              30pts
Destination specified         30pts
Scope confirmed               20pts
User explicitly confirmed     20pts
```

---

## Verdict Thresholds

```
95~100pts → ✅ Execution permitted
85~94pts  → 🟡 Conditional — list shortfall items + re-check, then proceed
70~84pts  → 🟠 Hold — request user judgment, specify risk items
 ~69pts   → 🔴 Execution denied
```

On denial, output resolution order so the user knows exactly how to raise the score:

```
Overall trust: 71pts (threshold: 95pts)
Shortfall items:
  Analysis trust 58pts ← 3 dynamic imports unverified
  Boundary trust 60pts ← destination contamination detected
Resolution order:
  1. Run AUDIT → boundary trust expected +40pts
  2. Manually verify 3 dynamic imports → analysis trust expected +20pts
  Expected after: 91pts → re-measure to proceed
```
