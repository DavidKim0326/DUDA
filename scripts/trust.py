#!/usr/bin/env python3
from __future__ import annotations
"""
DUDA trust.py — 4-axis trust measurement + 95-point gate
Determines execution permission numerically.

Usage:
  python trust.py --check-map                          # Check map trust only
  python trust.py --mode transplant --source [path] --target [path]
  python trust.py --mode audit --symptom "[symptom]"
  python trust.py --approve                            # Register user approval
"""

import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime


# -- Constants ----------------------------------------------------------------

GATE_THRESHOLD = 95       # Execution permission threshold
CAUTION_THRESHOLD = 85    # Conditional permission
HOLD_THRESHOLD = 70       # Hold


# -- Map Loading --------------------------------------------------------------

def load_map(root: Path) -> dict:
    """Parse DUDA_MAP.md and extract key data"""
    map_path = root / "DUDA_MAP.md"
    if not map_path.exists():
        map_path = root / ".duda" / "duda-map.md"
    if not map_path.exists():
        return {"exists": False}

    content = map_path.read_text(encoding="utf-8", errors="ignore")

    result = {
        "exists": True,
        "path": str(map_path),
        "content": content,
        "approved": "PENDING_APPROVAL" not in content,
        "checksums": {},
        "total_files": 0,
        "ambiguous_count": 0,
        "generated": None,
    }

    # Checksum parsing
    import re
    checksum_matches = re.findall(r'^\s+(.+?):\s+([a-f0-9]{8})', content, re.MULTILINE)
    result["checksums"] = dict(checksum_matches)

    # Statistics parsing
    total_match = re.search(r'total_files:\s*(\d+)', content)
    if total_match:
        result["total_files"] = int(total_match.group(1))

    ambiguous_match = re.search(r'(?:모호\(ambiguous\)|ambiguous):\s*(\d+)', content)
    if ambiguous_match:
        result["ambiguous_count"] = int(ambiguous_match.group(1))

    generated_match = re.search(r'generated:\s*(.+)', content)
    if generated_match:
        result["generated"] = generated_match.group(1).strip()

    return result


def load_init_summary(root: Path) -> dict:
    """Load summary saved by init.py"""
    summary_path = root / ".duda" / "duda-init-summary.json"
    if summary_path.exists():
        return json.loads(summary_path.read_text())
    return {}


# -- Axis 1: Map Trust -------------------------------------------------------

def score_map_trust(root: Path, map_data: dict) -> tuple[float, list[str]]:
    """
    Map Trust (out of 100)
      Boundary file checksum match   40 pts
      File count unchanged           20 pts
      User approval completed        30 pts
      Ambiguous tags at 0            10 pts
    """
    if not map_data["exists"]:
        return 0.0, ["DUDA_MAP.md missing — run INIT first"]

    score = 0.0
    issues = []

    # Checksum check (40 pts)
    checksum_score = 0.0
    if map_data["checksums"]:
        matched = 0
        total = len(map_data["checksums"])
        for rel_path, expected_cs in map_data["checksums"].items():
            actual_file = root / rel_path
            if actual_file.exists():
                actual_cs = hashlib.sha256(actual_file.read_bytes()).hexdigest()[:8]
                if actual_cs == expected_cs:
                    matched += 1
                else:
                    issues.append(f"Boundary file change detected: {rel_path}")
            else:
                issues.append(f"Boundary file deleted: {rel_path}")
        checksum_score = (matched / total) * 40 if total > 0 else 20
    else:
        checksum_score = 20  # Half score if no checksums
        issues.append("Boundary file checksums not registered")
    score += checksum_score

    # File count change (20 pts)
    if map_data["total_files"] > 0:
        import os
        current_count = sum(
            1 for _, _, files in os.walk(root)
            for f in files
            if Path(f).suffix in {".ts", ".tsx", ".js", ".jsx"}
            and "node_modules" not in _
        )
        expected = map_data["total_files"]
        diff_ratio = abs(current_count - expected) / max(expected, 1)
        if diff_ratio == 0:
            score += 20
        elif diff_ratio < 0.05:
            score += 15
            issues.append(f"Minor file count change ({expected} -> {current_count})")
        elif diff_ratio < 0.15:
            score += 8
            issues.append(f"File count change detected ({expected} -> {current_count}) — update recommended")
        else:
            issues.append(f"Major file count change ({expected} -> {current_count}) — update required")
    else:
        score += 10

    # User approval (30 pts)
    if map_data["approved"]:
        score += 30
    else:
        issues.append("User approval not completed — run 'duda approve'")

    # Ambiguous tags (10 pts)
    ambiguous = map_data.get("ambiguous_count", 0)
    if ambiguous == 0:
        score += 10
    elif ambiguous <= 5:
        score += 7
        issues.append(f"{ambiguous} ambiguous tag(s) — manual review recommended")
    elif ambiguous <= 15:
        score += 3
        issues.append(f"{ambiguous} ambiguous tag(s) — manual review required")
    else:
        issues.append(f"{ambiguous} ambiguous tag(s) — re-analysis recommended")

    return min(score, 100.0), issues


# -- Axis 2: Analysis Trust --------------------------------------------------

def score_analysis_trust(
    source_path: str,
    root: Path,
    analyze_result: dict | None = None
) -> tuple[float, list[str]]:
    """
    Analysis Trust (out of 100)
      Import tagging completion rate   40 pts
      No dynamic logic                 20 pts
      DB isolation confirmed           25 pts
      UPPER-ONLY handling plan         15 pts
    """
    score = 0.0
    issues = []

    if analyze_result is None:
        # Attempt to load analyze.py result file
        result_path = root / ".duda" / "duda-analyze-result.json"
        if result_path.exists():
            analyze_result = json.loads(result_path.read_text())
        else:
            return 30.0, ["No analysis result — run analyze.py first"]

    # Import tagging completion rate (40 pts)
    total_imports = analyze_result.get("total_imports", 0)
    tagged_imports = analyze_result.get("tagged_imports", 0)
    if total_imports > 0:
        completion_rate = tagged_imports / total_imports
        score += completion_rate * 40
        if completion_rate < 1.0:
            untagged = total_imports - tagged_imports
            issues.append(f"Import tagging incomplete: {untagged} remaining")
    else:
        score += 40  # Files with no imports are considered complete

    # Dynamic logic (20 pts)
    unverifiable_count = analyze_result.get("unverifiable_count", 0)
    if unverifiable_count == 0:
        score += 20
    else:
        issues.append(f"{unverifiable_count} dynamic/runtime logic item(s) — manual review required")
        issues.append("  (import() / require( / role=== / process.env etc.)")

    # DB isolation check (25 pts)
    db_queries = analyze_result.get("db_queries", [])
    queries_with_tenant = analyze_result.get("queries_with_tenant_id", 0)
    if not db_queries:
        score += 25  # No DB queries — not applicable
    else:
        ratio = queries_with_tenant / len(db_queries) if db_queries else 1
        score += ratio * 25
        if ratio < 1.0:
            missing = len(db_queries) - queries_with_tenant
            issues.append(f"{missing} DB query(ies) missing tenant identifier")

    # UPPER-ONLY handling plan (15 pts)
    upper_only_count = analyze_result.get("upper_only_count", 0)
    upper_only_handled = analyze_result.get("upper_only_handled", 0)
    if upper_only_count == 0:
        score += 15
    elif upper_only_handled >= upper_only_count:
        score += 15
    else:
        unhandled = upper_only_count - upper_only_handled
        issues.append(f"[UPPER-ONLY] {unhandled} item(s) without confirmed handling plan")

    return min(score, 100.0), issues


# -- Axis 3: Boundary Trust (no compromise) ----------------------------------

def score_boundary_trust(
    target_path: str,
    root: Path,
    audit_result: dict | None = None
) -> tuple[float, list[str]]:
    """
    Boundary Trust (out of 100) — must be 100
      Isolation policy verified     40 pts
      No target contamination       40 pts
      No transplant-forbidden clash 20 pts
    """
    score = 0.0
    issues = []

    if audit_result is None:
        result_path = root / ".duda" / "duda-audit-quick.json"
        if result_path.exists():
            audit_result = json.loads(result_path.read_text())
        else:
            return 0.0, ["No boundary check result — run audit.py --quick first"]

    # Isolation policy verification (40 pts)
    policy_exists = audit_result.get("isolation_policy_exists", False)
    if policy_exists:
        score += 40
    else:
        issues.append("Isolation policy (RLS/middleware) not verified")

    # No target contamination (40 pts) — contamination found = 0 pts + blocking
    contamination_found = audit_result.get("contamination_found", False)
    if not contamination_found:
        score += 40
    else:
        contamination_detail = audit_result.get("contamination_detail", "")
        issues.append(f"Target contamination detected: {contamination_detail}")
        issues.append("   Run AUDIT first to remove contamination before proceeding")

    # Transplant-forbidden clash (20 pts)
    forbidden_conflict = audit_result.get("forbidden_conflict", False)
    if not forbidden_conflict:
        score += 20
    else:
        conflict_name = audit_result.get("forbidden_item", "")
        issues.append(f"Transplant-forbidden list conflict: {conflict_name}")
        issues.append("   This item cannot be transplanted (strategy 4: reject)")

    return min(score, 100.0), issues


# -- Axis 4: Intent Trust (must be 100) --------------------------------------

def score_intent_trust(
    source: str | None,
    target: str | None,
    scope: str | None,
    user_confirmed: bool
) -> tuple[float, list[str]]:
    """
    Intent Trust (out of 100) — must be 100
      Source specified      30 pts
      Target specified      30 pts
      Scope confirmed       20 pts
      User confirmed        20 pts
    """
    score = 0.0
    issues = []

    if source:
        score += 30
    else:
        issues.append("Transplant source not specified — file name or feature name required")

    if target:
        score += 30
    else:
        issues.append("Transplant target not specified — layer or path required")

    if scope:
        score += 20
    else:
        issues.append("Transplant scope not confirmed (feature only? UI only? full?)")

    if user_confirmed:
        score += 20
    else:
        issues.append("No explicit user confirmation")

    return min(score, 100.0), issues


# -- Overall Verdict ----------------------------------------------------------

def calculate_total(
    map_score: float,
    analysis_score: float,
    boundary_score: float,
    intent_score: float,
) -> float:
    """Weighted sum"""
    return (
        map_score * 0.20 +
        analysis_score * 0.35 +
        boundary_score * 0.30 +
        intent_score * 0.15
    )


def verdict(total: float) -> tuple[str, str]:
    """Verdict result"""
    if total >= GATE_THRESHOLD:
        return "Execution permitted", "GREEN"
    elif total >= CAUTION_THRESHOLD:
        return "Conditional permission — re-check failing items before proceeding", "YELLOW"
    elif total >= HOLD_THRESHOLD:
        return "Hold — user judgment required", "ORANGE"
    else:
        return "Execution denied", "RED"


def estimate_recovery(issues_by_axis: dict) -> list[str]:
    """Suggest expected score gains by resolving failing items"""
    suggestions = []
    for axis, issues in issues_by_axis.items():
        for issue in issues:
            if "Run AUDIT first" in issue:
                suggestions.append("1. Run AUDIT -> Boundary Trust +40 pts expected")
            elif "dynamic/runtime" in issue:
                suggestions.append("2. Manually verify dynamic logic -> Analysis Trust +20 pts expected")
            elif "User approval" in issue:
                suggestions.append("3. Run 'duda approve' -> Map Trust +30 pts")
            elif "update required" in issue:
                suggestions.append("4. Run 'duda update' -> Map Trust recovery")
            elif "target not specified" in issue:
                suggestions.append("5. Specify transplant target path -> Intent Trust +30 pts")
    return list(dict.fromkeys(suggestions))  # Remove duplicates


def print_report(
    map_score, map_issues,
    analysis_score, analysis_issues,
    boundary_score, boundary_issues,
    intent_score, intent_issues,
    total, verdict_text
):
    """Print trust report"""
    print("\n" + "="*60)
    print("DUDA Trust Report")
    print("="*60)
    print(f"\n  Map Trust        {map_score:5.1f} pts  (x0.20)")
    for i in map_issues:
        print(f"    x {i}")

    print(f"\n  Analysis Trust   {analysis_score:5.1f} pts  (x0.35)")
    for i in analysis_issues:
        print(f"    x {i}")

    print(f"\n  Boundary Trust   {boundary_score:5.1f} pts  (x0.30)  <- must be 100")
    for i in boundary_issues:
        print(f"    x {i}")

    print(f"\n  Intent Trust     {intent_score:5.1f} pts  (x0.15)  <- must be 100")
    for i in intent_issues:
        print(f"    x {i}")

    print(f"\n{'-'*60}")
    print(f"  Overall Trust    {total:5.1f} pts  (threshold: {GATE_THRESHOLD} pts)")
    print(f"\n  {verdict_text}")

    all_issues = {
        "map": map_issues,
        "analysis": analysis_issues,
        "boundary": boundary_issues,
        "intent": intent_issues,
    }
    suggestions = estimate_recovery(all_issues)
    if suggestions and total < GATE_THRESHOLD:
        print(f"\n  Recovery steps:")
        for s in suggestions:
            print(f"    {s}")

    print("="*60 + "\n")


# -- Main --------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="DUDA Trust Measurement")
    parser.add_argument("--root", default=".", help="Project root")
    parser.add_argument("--check-map", action="store_true", help="Check map trust only")
    parser.add_argument("--mode", choices=["transplant", "audit"], default="transplant")
    parser.add_argument("--source", default=None)
    parser.add_argument("--target", default=None)
    parser.add_argument("--scope", default=None)
    parser.add_argument("--symptom", default=None)
    parser.add_argument("--user-confirmed", action="store_true")
    parser.add_argument("--approve", action="store_true", help="Register map approval")
    parser.add_argument("--output-json", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()

    # Approval handling
    if args.approve:
        map_path = root / "DUDA_MAP.md"
        if not map_path.exists():
            map_path = root / ".duda" / "duda-map.md"
        if map_path.exists():
            content = map_path.read_text()
            content = content.replace("status: PENDING_APPROVAL", "status: APPROVED")
            map_path.write_text(content)
            print("DUDA_MAP approval complete — trust level HIGH")
        else:
            print("DUDA_MAP not found")
        return

    map_data = load_map(root)

    # Check map only
    if args.check_map:
        map_score, map_issues = score_map_trust(root, map_data)
        if map_score >= 80:
            status = "HIGH" if map_score >= 95 else "MEDIUM"
        else:
            status = "LOW"
        print(f"DUDA_MAP trust: {status} ({map_score:.0f} pts)")
        for i in map_issues:
            print(f"  x {i}")
        return

    # Full measurement
    map_score, map_issues = score_map_trust(root, map_data)

    if args.mode == "transplant":
        analysis_score, analysis_issues = score_analysis_trust(
            args.source, root
        )
        boundary_score, boundary_issues = score_boundary_trust(
            args.target, root
        )
        intent_score, intent_issues = score_intent_trust(
            args.source, args.target, args.scope, args.user_confirmed
        )
    else:  # audit
        analysis_score, analysis_issues = score_analysis_trust(None, root)
        boundary_score, boundary_issues = 100.0, []
        intent_score, intent_issues = score_intent_trust(
            args.symptom, None, None, args.user_confirmed
        )

    total = calculate_total(map_score, analysis_score, boundary_score, intent_score)
    verdict_text, color = verdict(total)

    print_report(
        map_score, map_issues,
        analysis_score, analysis_issues,
        boundary_score, boundary_issues,
        intent_score, intent_issues,
        total, verdict_text
    )

    # Save JSON (so other scripts can read it)
    result = {
        "total": round(total, 1),
        "gate_passed": total >= GATE_THRESHOLD,
        "verdict": verdict_text,
        "scores": {
            "map": round(map_score, 1),
            "analysis": round(analysis_score, 1),
            "boundary": round(boundary_score, 1),
            "intent": round(intent_score, 1),
        },
        "issues": {
            "map": map_issues,
            "analysis": analysis_issues,
            "boundary": boundary_issues,
            "intent": intent_issues,
        },
        "timestamp": datetime.now().isoformat(),
    }

    result_path = root / ".duda" / "duda-trust-result.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2))

    # Exit code: 0 if permitted, 1 if denied
    exit(0 if result["gate_passed"] else 1)


if __name__ == "__main__":
    main()
