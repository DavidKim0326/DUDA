#!/usr/bin/env python3
from __future__ import annotations
"""
DUDA memory.py — Recursive learning memory layer
Automatically saves work results and paths when a trigger fires.
On the next trigger, queries past experience first to speed up processing.
The more it runs, the more it accumulates, increasing confidence.

Storage structure:
  duda_memory/
  |- pattern_db.json    <- Type pattern learning (TRANSPLANT/AUDIT results)
  |- path_cache.json    <- Path->layer tag cache (reused by flood-fill)
  +- decision_log.json  <- Strategy decision history (instant answers for repeat requests)

Usage:
  python memory.py recall --source [path]          # Query experience
  python memory.py record --mode [TRANSPLANT|AUDIT|INIT] --result [json]
  python memory.py feedback --decision-id [id] --correct [true|false]
  python memory.py stats                           # Learning status
"""

import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict


# -- Constants ----------------------------------------------------------------

MEMORY_DIR = ".duda/memory"

# Confidence levels
CONFIDENCE_LEVELS = {
    "CERTAIN":   {"min_hits": 5,  "score": 1.00, "skip_analysis": True},
    "HIGH":      {"min_hits": 3,  "score": 0.90, "skip_analysis": True},
    "MEDIUM":    {"min_hits": 2,  "score": 0.70, "skip_analysis": False},
    "LOW":       {"min_hits": 1,  "score": 0.50, "skip_analysis": False},
    "UNKNOWN":   {"min_hits": 0,  "score": 0.00, "skip_analysis": False},
}

# Confidence threshold: above this level, use cache without analysis
CACHE_USE_THRESHOLD = "HIGH"


# -- Memory store load/save ---------------------------------------------------

class DudaMemory:
    """DUDA recursive learning memory store"""

    def __init__(self, root: Path):
        self.root = root
        self.memory_dir = root / MEMORY_DIR
        self.memory_dir.mkdir(parents=True, exist_ok=True)

        self.pattern_db_path   = self.memory_dir / "pattern_db.json"
        self.path_cache_path   = self.memory_dir / "path_cache.json"
        self.decision_log_path = self.memory_dir / "decision_log.json"

        self.pattern_db   = self._load(self.pattern_db_path,   {"patterns": {}, "meta": {}})
        self.path_cache   = self._load(self.path_cache_path,   {"paths": {}, "meta": {}})
        self.decision_log = self._load(self.decision_log_path, {"decisions": [], "index": {}})

    def _load(self, path: Path, default: dict) -> dict:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return default
        return default

    def _save_all(self):
        self.pattern_db_path.write_text(
            json.dumps(self.pattern_db, ensure_ascii=False, indent=2)
        )
        self.path_cache_path.write_text(
            json.dumps(self.path_cache, ensure_ascii=False, indent=2)
        )
        self.decision_log_path.write_text(
            json.dumps(self.decision_log, ensure_ascii=False, indent=2)
        )


# -- Path Cache ---------------------------------------------------------------

    def get_path_tag(self, rel_path: str) -> dict | None:
        """
        Look up a path's layer tag from the cache.
        Returns: {tag, confidence_level, hit_count, last_seen} or None
        """
        path_key = self._path_key(rel_path)
        entry = self.path_cache["paths"].get(path_key)
        if not entry:
            return None

        hit_count = entry.get("hit_count", 1)
        confidence_level = self._hit_to_confidence(hit_count, entry.get("wrong_count", 0))

        return {
            "tag": entry["tag"],
            "confidence_level": confidence_level,
            "confidence_score": CONFIDENCE_LEVELS[confidence_level]["score"],
            "skip_analysis": CONFIDENCE_LEVELS[confidence_level]["skip_analysis"],
            "hit_count": hit_count,
            "wrong_count": entry.get("wrong_count", 0),
            "last_seen": entry.get("last_seen"),
            "path_key": path_key,
        }

    def record_path_tag(self, rel_path: str, tag: str, confidence: str = "inferred"):
        """Record a path tag result in the cache. Increments hit_count for existing entries."""
        path_key = self._path_key(rel_path)
        existing = self.path_cache["paths"].get(path_key)

        if existing and existing["tag"] == tag:
            # Same result -> increment hit_count
            existing["hit_count"] = existing.get("hit_count", 1) + 1
            existing["last_seen"] = datetime.now().isoformat()
        else:
            # New entry or tag changed
            self.path_cache["paths"][path_key] = {
                "rel_path": rel_path,
                "tag": tag,
                "confidence_source": confidence,
                "hit_count": 1,
                "wrong_count": 0,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
            }

    def batch_record_path_tags(self, tagged: dict[str, tuple[str, str]]):
        """Batch record flood-fill results into cache. tagged = {rel_path: (tag, confidence)}"""
        for rel_path, (tag, confidence) in tagged.items():
            self.record_path_tag(rel_path, tag, confidence)

        # Update meta
        self.path_cache["meta"] = {
            "total_paths": len(self.path_cache["paths"]),
            "last_updated": datetime.now().isoformat(),
        }
        self._save_all()

    def _path_key(self, rel_path: str) -> str:
        """Convert a path to a hash key (normalized case/slashes)"""
        normalized = rel_path.lower().replace("\\", "/").strip("/")
        return hashlib.md5(normalized.encode()).hexdigest()[:12]

    def _hit_to_confidence(self, hit_count: int, wrong_count: int) -> str:
        """Determine confidence level based on hit_count and error count"""
        if wrong_count > 0:
            # Demote if there have been errors
            adjusted = hit_count - (wrong_count * 2)
        else:
            adjusted = hit_count

        if adjusted >= CONFIDENCE_LEVELS["CERTAIN"]["min_hits"]:
            return "CERTAIN"
        elif adjusted >= CONFIDENCE_LEVELS["HIGH"]["min_hits"]:
            return "HIGH"
        elif adjusted >= CONFIDENCE_LEVELS["MEDIUM"]["min_hits"]:
            return "MEDIUM"
        elif adjusted >= 1:
            return "LOW"
        return "UNKNOWN"


# -- Pattern DB ---------------------------------------------------------------

    def get_pattern(self, pattern_key: str) -> dict | None:
        """
        Look up a pattern. Returns previous results for the same source->target combination.
        pattern_key = hash(source_path + target_path + mode)
        """
        return self.pattern_db["patterns"].get(pattern_key)

    def record_pattern(
        self,
        mode: str,           # TRANSPLANT | AUDIT | INIT
        source: str | None,
        target: str | None,
        result: dict,        # strategy, trust_score, root_cause, etc.
        user_confirmed: bool = False,
    ):
        """
        Learn a work result as a pattern.
        Confidence increases as the same pattern repeats.
        """
        pattern_key = self._pattern_key(mode, source, target)

        existing = self.pattern_db["patterns"].get(pattern_key)

        if existing:
            existing["hit_count"] = existing.get("hit_count", 1) + 1
            existing["last_result"] = result
            existing["last_seen"] = datetime.now().isoformat()
            if user_confirmed:
                existing["confirmed_count"] = existing.get("confirmed_count", 0) + 1
        else:
            self.pattern_db["patterns"][pattern_key] = {
                "mode": mode,
                "source": source,
                "target": target,
                "first_result": result,
                "last_result": result,
                "hit_count": 1,
                "confirmed_count": 1 if user_confirmed else 0,
                "wrong_count": 0,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
            }

        self.pattern_db["meta"] = {
            "total_patterns": len(self.pattern_db["patterns"]),
            "last_updated": datetime.now().isoformat(),
        }
        self._save_all()

    def _pattern_key(self, mode: str, source: str | None, target: str | None) -> str:
        raw = f"{mode}:{source or ''}:{target or ''}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]


# -- Decision Log -------------------------------------------------------------

    def record_decision(
        self,
        mode: str,
        prompt: str,
        source: str | None,
        target: str | None,
        strategy: int | None,
        trust_score: float | None,
        root_cause: str | None,
        outcome: str,  # EXECUTED | BLOCKED | AUDITED
        execution_ms: int = 0,
        used_cache: bool = False,
    ) -> str:
        """Record the full decision to the log. Returns a unique ID."""
        decision_id = f"d{len(self.decision_log['decisions']) + 1:04d}"
        entry = {
            "id": decision_id,
            "mode": mode,
            "prompt_hash": hashlib.md5(prompt.encode()).hexdigest()[:8],
            "source": source,
            "target": target,
            "strategy": strategy,
            "trust_score": trust_score,
            "root_cause": root_cause,
            "outcome": outcome,
            "execution_ms": execution_ms,
            "used_cache": used_cache,
            "timestamp": datetime.now().isoformat(),
            "feedback": None,  # Awaiting post-hoc feedback
        }
        self.decision_log["decisions"].append(entry)

        # Index (for fast lookup)
        self.decision_log["index"][decision_id] = len(self.decision_log["decisions"]) - 1
        self._save_all()
        return decision_id

    def apply_feedback(self, decision_id: str, correct: bool, note: str = ""):
        """
        User reports that a decision was incorrect.
        Lowers the confidence of the corresponding pattern and flags for re-analysis.
        """
        idx = self.decision_log["index"].get(decision_id)
        if idx is None:
            print(f"Decision ID {decision_id} not found")
            return

        entry = self.decision_log["decisions"][idx]
        entry["feedback"] = {
            "correct": correct,
            "note": note,
            "timestamp": datetime.now().isoformat(),
        }

        if not correct:
            # Demote pattern confidence in the pattern DB
            pattern_key = self._pattern_key(entry["mode"], entry["source"], entry["target"])
            if pattern_key in self.pattern_db["patterns"]:
                self.pattern_db["patterns"][pattern_key]["wrong_count"] = \
                    self.pattern_db["patterns"][pattern_key].get("wrong_count", 0) + 1

            # Also reflect wrong_count in path cache
            for path in [entry["source"], entry["target"]]:
                if path:
                    path_key = self._path_key(path)
                    if path_key in self.path_cache["paths"]:
                        self.path_cache["paths"][path_key]["wrong_count"] = \
                            self.path_cache["paths"][path_key].get("wrong_count", 0) + 1

            print(f"Feedback applied: pattern {pattern_key[:8]} confidence demoted")
        else:
            print(f"Feedback applied: decision {decision_id} confirmed correct")

        self._save_all()


# -- Experience-based fast recall ---------------------------------------------

    def recall(
        self,
        mode: str,
        source: str | None = None,
        target: str | None = None,
        prompt: str | None = None,
    ) -> dict:
        """
        Query experience. Allows skipping analysis if high-confidence cache exists.

        Returns:
          {
            can_skip_analysis: bool,
            confidence: str,
            cached_strategy: int | None,
            cached_tags: dict[path, tag],
            cached_trust_score: float | None,
            cached_root_cause: str | None,
            hit_count: int,
            recommendation: str,
          }
        """
        result = {
            "can_skip_analysis": False,
            "confidence": "UNKNOWN",
            "cached_strategy": None,
            "cached_tags": {},
            "cached_trust_score": None,
            "cached_root_cause": None,
            "hit_count": 0,
            "recommendation": "Full analysis required",
            "speedup_factor": 1.0,
        }

        # 1. Look up previous results for the same pattern
        pattern_key = self._pattern_key(mode, source, target)
        pattern = self.pattern_db["patterns"].get(pattern_key)

        if pattern:
            hit_count = pattern.get("hit_count", 0)
            wrong_count = pattern.get("wrong_count", 0)
            confirmed = pattern.get("confirmed_count", 0)
            conf_level = self._hit_to_confidence(hit_count + confirmed, wrong_count)
            last_result = pattern.get("last_result", {})

            result["hit_count"] = hit_count
            result["confidence"] = conf_level
            result["cached_strategy"] = last_result.get("strategy")
            result["cached_trust_score"] = last_result.get("trust_score")
            result["cached_root_cause"] = last_result.get("root_cause")

            if CONFIDENCE_LEVELS[conf_level]["skip_analysis"]:
                result["can_skip_analysis"] = True
                result["recommendation"] = (
                    f"Cache usable ({conf_level}, {hit_count} experiences) -- "
                    f"apply strategy {last_result.get('strategy', '?')} immediately"
                )
                result["speedup_factor"] = min(hit_count * 0.4 + 1.0, 5.0)
            else:
                result["recommendation"] = (
                    f"Experience found ({hit_count} times) but confidence {conf_level} -- "
                    f"quick analysis then verify recommended"
                )

        # 2. Look up per-path tag cache
        if source:
            tag_info = self.get_path_tag(source)
            if tag_info:
                result["cached_tags"][source] = tag_info

        # 3. Look up related path patterns (experience from other files in the same directory as source)
        if source:
            source_dir = str(Path(source).parent)
            similar_patterns = []
            for pk, pv in self.pattern_db["patterns"].items():
                p_source = pv.get("source", "")
                if p_source and str(Path(p_source).parent) == source_dir:
                    similar_patterns.append(pv)

            if similar_patterns and not result["can_skip_analysis"]:
                # Infer type from same-directory experience
                strategies = [p["last_result"].get("strategy") for p in similar_patterns]
                most_common = max(set(s for s in strategies if s), key=strategies.count, default=None)
                if most_common:
                    result["recommendation"] += f" ({len(similar_patterns)} experiences in same directory: strategy {most_common} likely)"

        return result

    def recall_path_batch(self, rel_paths: list[str]) -> dict[str, dict]:
        """
        Batch query for multiple paths. Reuses already-tagged paths during flood-fill.
        Returns: {rel_path: {tag, confidence_level, skip}}
        """
        results = {}
        for path in rel_paths:
            tag_info = self.get_path_tag(path)
            if tag_info and tag_info["skip_analysis"]:
                results[path] = tag_info
        return results


# -- Statistics ---------------------------------------------------------------

    def stats(self) -> dict:
        """Learning status statistics"""
        paths = self.path_cache["paths"]
        patterns = self.pattern_db["patterns"]
        decisions = self.decision_log["decisions"]

        # Confidence distribution
        conf_dist = defaultdict(int)
        for entry in paths.values():
            level = self._hit_to_confidence(entry.get("hit_count", 1), entry.get("wrong_count", 0))
            conf_dist[level] += 1

        # Cache hit rate (based on decision log)
        total_decisions = len(decisions)
        cache_hits = sum(1 for d in decisions if d.get("used_cache"))
        hit_rate = cache_hits / max(total_decisions, 1)

        # Average processing speed improvement
        cached_times = [d["execution_ms"] for d in decisions if d.get("used_cache") and d["execution_ms"]]
        fresh_times = [d["execution_ms"] for d in decisions if not d.get("used_cache") and d["execution_ms"]]
        avg_cached = sum(cached_times) / max(len(cached_times), 1)
        avg_fresh = sum(fresh_times) / max(len(fresh_times), 1)
        speedup = avg_fresh / max(avg_cached, 1) if avg_cached > 0 else 1.0

        return {
            "path_cache": {
                "total": len(paths),
                "confidence_distribution": dict(conf_dist),
                "certain": conf_dist["CERTAIN"],
                "high": conf_dist["HIGH"],
            },
            "pattern_db": {
                "total": len(patterns),
                "avg_hit_count": sum(p.get("hit_count", 1) for p in patterns.values()) / max(len(patterns), 1),
            },
            "decision_log": {
                "total": total_decisions,
                "cache_hit_rate": f"{hit_rate*100:.1f}%",
                "speedup_factor": f"{speedup:.1f}x",
            },
            "learning_stage": self._learning_stage(len(paths), hit_rate),
        }

    def _learning_stage(self, path_count: int, hit_rate: float) -> str:
        if path_count < 50 or hit_rate < 0.2:
            return "Initial learning -- accumulating experience"
        elif path_count < 200 or hit_rate < 0.5:
            return "Growth -- key paths learned"
        elif hit_rate < 0.8:
            return "Acceleration -- mostly cache hits"
        else:
            return "Mature -- near-instant processing"

    def print_stats(self):
        s = self.stats()
        print("\n" + "="*60)
        print("DUDA Recursive Learning Status")
        print("="*60)
        print(f"\n  {s['learning_stage']}")
        print(f"\n  Path cache:     {s['path_cache']['total']} entries")
        print(f"    CERTAIN:  {s['path_cache']['confidence_distribution'].get('CERTAIN', 0)}")
        print(f"    HIGH:     {s['path_cache']['confidence_distribution'].get('HIGH', 0)}")
        print(f"    MEDIUM:   {s['path_cache']['confidence_distribution'].get('MEDIUM', 0)}")
        print(f"\n  Pattern DB:     {s['pattern_db']['total']} entries")
        print(f"    Avg hits:     {s['pattern_db']['avg_hit_count']:.1f}")
        print(f"\n  Decision log:   {s['decision_log']['total']} entries")
        print(f"    Cache hit rate: {s['decision_log']['cache_hit_rate']}")
        print(f"    Speedup:        {s['decision_log']['speedup_factor']}")
        print("="*60 + "\n")


# -- Main ---------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="DUDA recursive learning memory")
    parser.add_argument("command", choices=["recall", "record", "feedback", "stats", "reset"])
    parser.add_argument("--root", default=".", help="Project root")
    parser.add_argument("--mode", choices=["TRANSPLANT", "AUDIT", "INIT"])
    parser.add_argument("--source", default=None)
    parser.add_argument("--target", default=None)
    parser.add_argument("--result", default=None, help="JSON string")
    parser.add_argument("--decision-id", default=None)
    parser.add_argument("--correct", type=lambda x: x.lower() == "true", default=None)
    parser.add_argument("--note", default="")
    parser.add_argument("--paths", nargs="+", help="Path list for batch recall")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    mem = DudaMemory(root)

    if args.command == "recall":
        result = mem.recall(
            mode=args.mode or "TRANSPLANT",
            source=args.source,
            target=args.target,
        )
        print(f"\nDUDA Experience Recall -- {args.source or '?'} -> {args.target or '?'}")
        print(f"  Confidence:     {result['confidence']} ({result['hit_count']} experiences)")
        print(f"  Skip analysis:  {'Yes' if result['can_skip_analysis'] else 'No'}")
        print(f"  Cached strategy: {result['cached_strategy']}")
        print(f"  Speedup:        {result['speedup_factor']:.1f}x")
        print(f"  Recommendation: {result['recommendation']}")

        # Save JSON (for other scripts to read)
        out = root / ".duda" / "duda-memory-recall.json"
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2))

    elif args.command == "record":
        result_data = json.loads(args.result) if args.result else {}
        mem.record_pattern(
            mode=args.mode or "TRANSPLANT",
            source=args.source,
            target=args.target,
            result=result_data,
            user_confirmed=True,
        )
        print(f"Pattern saved: {args.mode} {args.source} -> {args.target}")

    elif args.command == "feedback":
        if args.decision_id and args.correct is not None:
            mem.apply_feedback(args.decision_id, args.correct, args.note)
        else:
            print("--decision-id and --correct are required")

    elif args.command == "stats":
        mem.print_stats()

    elif args.command == "reset":
        confirm = input("All learning data will be deleted. Continue? (yes): ")
        if confirm.strip().lower() == "yes":
            import shutil
            shutil.rmtree(root / MEMORY_DIR)
            print("Memory reset complete")


if __name__ == "__main__":
    main()
