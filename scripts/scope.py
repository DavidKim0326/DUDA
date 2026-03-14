#!/usr/bin/env python3
from __future__ import annotations
"""
DUDA scope.py — Feature-centric isolation analysis
SCOPE mode: Accepts a feature description, discovers related files,
groups by isolation layer, and detects cross-layer violations.

Usage:
  python scope.py --feature "account permission management" [--root .]
  python scope.py --feature "billing" --depth 2 --min-score 0.5
  python scope.py --feature "auth" --files-only
  python scope.py --feature "tenant onboarding" --json
"""

import os
import re
import json
import argparse
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict


# -- Configuration -----------------------------------------------------------

SKIP_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", ".turbo",
    "coverage", "__pycache__", ".cache", "out", ".vercel",
    ".duda", ".bkit", ".claude"
}

SOURCE_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".py", ".vue", ".svelte"}

STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "need", "must",
    "i", "you", "he", "she", "it", "we", "they", "me", "him", "her", "us",
    "my", "your", "his", "its", "our", "their",
    "this", "that", "these", "those", "what", "which", "who", "whom",
    "and", "or", "but", "if", "of", "at", "by", "for", "with", "about",
    "to", "from", "in", "on", "up", "out", "off", "into",
    "all", "each", "every", "both", "few", "more", "most", "some", "any",
    "not", "no", "nor", "so", "too", "very", "just",
    "check", "show", "get", "set", "find", "make", "use", "look", "see",
    "related", "file", "files", "code", "feature", "system", "module",
    "function", "class", "component", "service", "management", "manager",
    "handler", "controller", "model", "view",
}

# -- Synonym Database --------------------------------------------------------

SYNONYM_DB: dict[str, list[str]] = {
    # Auth & Access
    "permission": ["permission", "perm", "authorize", "authorization", "rbac",
                    "acl", "access", "grant", "deny", "allow", "forbidden"],
    "account": ["account", "user", "profile", "signup", "register", "credential"],
    "auth": ["auth", "login", "logout", "signin", "signout", "authenticate",
             "authentication", "session", "token", "jwt", "oauth", "sso"],
    "role": ["role", "admin", "superadmin", "moderator", "member", "owner",
             "privilege", "capability"],
    "password": ["password", "passwd", "hash", "bcrypt", "argon", "salt",
                 "reset", "forgot"],

    # Data & Storage
    "billing": ["billing", "payment", "invoice", "charge", "subscription",
                "stripe", "price", "cost", "plan", "pricing", "checkout"],
    "database": ["database", "db", "query", "table", "schema", "migration",
                 "model", "entity", "repository", "orm", "prisma", "drizzle"],
    "storage": ["storage", "upload", "file", "s3", "bucket", "blob", "asset",
                "media", "image", "attachment", "presigned"],

    # Multi-tenant
    "tenant": ["tenant", "organization", "org", "workspace", "company", "team",
               "multi-tenant", "multitenant"],
    "isolation": ["isolation", "boundary", "rls", "policy", "filter", "scope",
                  "guard", "gate", "fence"],

    # UI & Features
    "menu": ["menu", "navigation", "nav", "sidebar", "header", "drawer",
             "toolbar", "breadcrumb"],
    "dashboard": ["dashboard", "analytics", "report", "chart", "metric",
                  "stats", "statistics", "overview", "summary"],
    "notification": ["notification", "alert", "email", "push", "webhook",
                     "event", "message", "toast", "snackbar"],
    "onboarding": ["onboarding", "setup", "wizard", "welcome", "tutorial",
                   "guide", "intro", "getting-started"],
    "order": ["order", "cart", "checkout", "purchase", "item", "product",
              "catalog", "inventory", "stock"],
    "setting": ["setting", "config", "configuration", "preference", "option",
                "env", "environment"],

    # Infrastructure
    "api": ["api", "endpoint", "route", "handler", "middleware", "rest",
            "graphql", "rpc", "controller"],
    "deploy": ["deploy", "deployment", "ci", "cd", "pipeline", "docker",
               "kubernetes", "k8s", "terraform"],
    "test": ["test", "spec", "unit", "integration", "e2e", "mock", "fixture",
             "jest", "vitest", "cypress", "playwright"],
}


# -- Data Structures ---------------------------------------------------------

class FileMatch:
    __slots__ = ("path", "keyword_hits", "source", "score",
                 "layer", "imports", "imported_by")

    def __init__(self, path: str, keyword_hits: dict[str, int] | None = None,
                 source: str = "content"):
        self.path = path
        self.keyword_hits = keyword_hits or {}
        self.source = source
        self.score: float = 0.0
        self.layer: str = "NO-MAP"
        self.imports: list[str] = []
        self.imported_by: list[str] = []

    def total_hits(self) -> int:
        return sum(self.keyword_hits.values())

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "score": round(self.score, 2),
            "layer": self.layer,
            "keyword_hits": self.keyword_hits,
            "source": self.source,
        }


class CrossLayerDep:
    __slots__ = ("source_file", "source_layer", "target_file", "target_layer",
                 "import_type")

    def __init__(self, source_file: str, source_layer: str,
                 target_file: str, target_layer: str,
                 import_type: str = "direct"):
        self.source_file = source_file
        self.source_layer = source_layer
        self.target_file = target_file
        self.target_layer = target_layer
        self.import_type = import_type  # "direct" | "re-export" | "dynamic"

    def to_dict(self) -> dict:
        return {
            "source": self.source_file,
            "source_layer": self.source_layer,
            "target": self.target_file,
            "target_layer": self.target_layer,
            "import_type": self.import_type,
        }


class ScopeResult:
    def __init__(self, description: str, keywords: list[str]):
        self.description = description
        self.keywords = keywords
        self.files: list[FileMatch] = []
        self.groups: dict[str, list[FileMatch]] = {}
        self.cross_layer_deps: list[CrossLayerDep] = []
        self.risk_level: str = "LOW"
        self.recommendations: list[str] = []

    def to_dict(self) -> dict:
        return {
            "description": self.description,
            "keywords": self.keywords,
            "file_count": len(self.files),
            "risk_level": self.risk_level,
            "groups": {
                layer: [f.to_dict() for f in files]
                for layer, files in self.groups.items()
            },
            "cross_layer_deps": [d.to_dict() for d in self.cross_layer_deps],
            "recommendations": self.recommendations,
        }


# -- Keyword Extractor -------------------------------------------------------

class KeywordExtractor:
    """Extract and expand keywords from natural language feature description."""

    @staticmethod
    def extract(description: str) -> list[str]:
        """Split description into keywords, remove stopwords."""
        # Normalize: lowercase, split on non-alphanumeric
        words = re.split(r"[^a-zA-Z0-9가-힣]+", description.lower())
        # Filter stopwords and short words
        keywords = [w for w in words if w and len(w) > 1 and w not in STOPWORDS]
        return list(dict.fromkeys(keywords))  # dedupe, preserve order

    @staticmethod
    def expand_synonyms(keywords: list[str]) -> list[str]:
        """Expand keywords with synonyms from SYNONYM_DB."""
        expanded = set(keywords)
        for kw in keywords:
            # Check if keyword matches any synonym group
            for group_key, synonyms in SYNONYM_DB.items():
                if kw in synonyms or kw == group_key:
                    expanded.update(synonyms)
                # Partial match: keyword is substring of a synonym
                for syn in synonyms:
                    if kw in syn or syn in kw:
                        expanded.update(synonyms)
                        break
        return sorted(expanded)


# -- File Searcher -----------------------------------------------------------

class FileSearcher:
    """Search project files by keyword matching."""

    def __init__(self, root: str):
        self.root = Path(root).resolve()
        self._all_files: list[Path] | None = None

    def _collect_files(self) -> list[Path]:
        """Collect all source files, respecting skip dirs."""
        if self._all_files is not None:
            return self._all_files

        files = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            # Filter skip dirs in-place
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if fpath.suffix in SOURCE_EXTENSIONS:
                    files.append(fpath)
        self._all_files = files
        return files

    def search_filenames(self, keywords: list[str]) -> dict[str, FileMatch]:
        """Find files whose names contain keywords."""
        results: dict[str, FileMatch] = {}
        for fpath in self._collect_files():
            name_lower = fpath.stem.lower()
            hits = {}
            for kw in keywords:
                if kw in name_lower:
                    hits[kw] = 1
            if hits:
                relpath = str(fpath.relative_to(self.root))
                results[relpath] = FileMatch(relpath, hits, source="filename")
        return results

    def search_contents(self, keywords: list[str]) -> dict[str, FileMatch]:
        """Find files containing keywords in their content."""
        results: dict[str, FileMatch] = {}
        # Build regex pattern for all keywords
        if not keywords:
            return results
        pattern = re.compile("|".join(re.escape(kw) for kw in keywords),
                             re.IGNORECASE)

        for fpath in self._collect_files():
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            hits: dict[str, int] = defaultdict(int)
            for match in pattern.finditer(content):
                matched_kw = match.group().lower()
                # Map back to original keyword
                for kw in keywords:
                    if kw == matched_kw:
                        hits[kw] += 1
                        break

            if hits:
                relpath = str(fpath.relative_to(self.root))
                if relpath not in results:
                    results[relpath] = FileMatch(relpath, dict(hits), source="content")
                else:
                    # Merge hits
                    for k, v in hits.items():
                        results[relpath].keyword_hits[k] = \
                            results[relpath].keyword_hits.get(k, 0) + v
        return results

    def expand_imports(self, files: dict[str, FileMatch],
                       depth: int = 1) -> dict[str, FileMatch]:
        """Expand file set by following import chains."""
        if depth <= 0:
            return files

        # Parse imports for all project files (lazy, one pass)
        import_map = self._build_import_map()

        current = set(files.keys())
        for _ in range(depth):
            new_files = set()
            for fpath in current:
                # Files imported by this file
                for imp in import_map.get(fpath, []):
                    if imp not in files:
                        new_files.add(imp)
                # Files that import this file
                for other, imps in import_map.items():
                    if fpath in imps and other not in files:
                        new_files.add(other)

            for nf in new_files:
                files[nf] = FileMatch(nf, {}, source="import")
            current = new_files
            if not current:
                break

        # Record import relationships
        for fpath, fmatch in files.items():
            fmatch.imports = [i for i in import_map.get(fpath, []) if i in files]
            fmatch.imported_by = [
                o for o, imps in import_map.items()
                if fpath in imps and o in files
            ]

        return files

    def _build_import_map(self) -> dict[str, list[str]]:
        """Parse all source files to build import → file mapping."""
        import_map: dict[str, list[str]] = {}
        all_files = self._collect_files()
        file_set = {str(f.relative_to(self.root)) for f in all_files}

        # Pattern for JS/TS imports
        import_re = re.compile(
            r"""(?:import\s+.*?from\s+|require\s*\(\s*)['"]([^'"]+)['"]""",
            re.MULTILINE
        )
        # Pattern for Python imports
        py_import_re = re.compile(
            r"""(?:from\s+(\S+)\s+import|import\s+(\S+))""",
            re.MULTILINE
        )

        for fpath in all_files:
            relpath = str(fpath.relative_to(self.root))
            imports = []

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except (OSError, UnicodeDecodeError):
                continue

            if fpath.suffix in {".py"}:
                for m in py_import_re.finditer(content):
                    mod = m.group(1) or m.group(2)
                    if mod:
                        resolved = self._resolve_python_import(mod, fpath)
                        if resolved and resolved in file_set:
                            imports.append(resolved)
            else:
                for m in import_re.finditer(content):
                    imp_path = m.group(1)
                    resolved = self._resolve_js_import(imp_path, fpath)
                    if resolved and resolved in file_set:
                        imports.append(resolved)

            import_map[relpath] = imports

        return import_map

    def _resolve_js_import(self, imp_path: str, from_file: Path) -> str | None:
        """Resolve a JS/TS import path to a relative file path."""
        # Skip external packages
        if not imp_path.startswith(".") and not imp_path.startswith("@/") \
                and not imp_path.startswith("~/"):
            return None

        # Handle @ alias (common: @/ → src/)
        if imp_path.startswith("@/"):
            base = self.root / "src" / imp_path[2:]
        elif imp_path.startswith("~/"):
            base = self.root / imp_path[2:]
        else:
            base = from_file.parent / imp_path

        # Try extensions
        for ext in [".ts", ".tsx", ".js", ".jsx", ""]:
            candidate = base.with_suffix(ext) if ext else base
            if candidate.is_file():
                try:
                    return str(candidate.relative_to(self.root))
                except ValueError:
                    return None
            # Try index file
            index = candidate / f"index{ext}" if not ext else None
            if index and index.is_file():
                try:
                    return str(index.relative_to(self.root))
                except ValueError:
                    return None

        return None

    def _resolve_python_import(self, module: str, from_file: Path) -> str | None:
        """Resolve a Python import to a relative file path."""
        parts = module.replace(".", "/")
        for ext in [".py", "/__init__.py"]:
            candidate = self.root / (parts + ext)
            if candidate.is_file():
                try:
                    return str(candidate.relative_to(self.root))
                except ValueError:
                    return None
        return None


# -- Relevance Scorer --------------------------------------------------------

class RelevanceScorer:
    """Score files by relevance to the feature description."""

    WEIGHT_FILENAME = 0.3
    WEIGHT_CONTENT = 0.4
    WEIGHT_IMPORT = 0.3

    @staticmethod
    def score(files: dict[str, FileMatch], total_keywords: int) -> list[FileMatch]:
        """Score each file and return sorted list.

        total_keywords: count of ORIGINAL keywords (before synonym expansion)
                        to avoid diluting scores when many synonyms are added.
        """
        if total_keywords == 0:
            total_keywords = 1

        for fmatch in files.values():
            score = 0.0
            unique_hits = len(fmatch.keyword_hits)
            hit_count = fmatch.total_hits()

            if fmatch.source in ("filename", "filename+content"):
                # Filename matches are highly relevant
                score = RelevanceScorer.WEIGHT_FILENAME + \
                        RelevanceScorer.WEIGHT_CONTENT * min(unique_hits / total_keywords, 1.0)
                if fmatch.source == "filename+content":
                    # Bonus for matching both name and content
                    score = min(score + 0.1, 1.0)
            elif fmatch.source == "content":
                # Content matches: combine hit depth + keyword breadth
                depth_score = min(hit_count / 5.0, 1.0)  # cap at 5 hits
                breadth_score = min(unique_hits / max(total_keywords, 1), 1.0)
                score = RelevanceScorer.WEIGHT_CONTENT * depth_score * 0.5 + \
                        RelevanceScorer.WEIGHT_CONTENT * breadth_score * 0.5 + \
                        RelevanceScorer.WEIGHT_FILENAME * breadth_score * 0.3
            elif fmatch.source == "import":
                # Import-discovered files get base import score
                import_connections = len(fmatch.imports) + len(fmatch.imported_by)
                score = RelevanceScorer.WEIGHT_IMPORT * \
                        min(import_connections / 3.0, 1.0)

            fmatch.score = min(score, 1.0)

        # Sort by score descending
        ranked = sorted(files.values(), key=lambda f: f.score, reverse=True)
        return ranked

    @staticmethod
    def filter_by_threshold(files: list[FileMatch],
                            min_score: float) -> list[FileMatch]:
        """Filter files below minimum score."""
        return [f for f in files if f.score >= min_score]


# -- Layer Tagger ------------------------------------------------------------

class LayerTagger:
    """Tag files with isolation layer from DUDA_MAP.md."""

    LAYER_ALIASES = {
        "UPPER-ONLY": "PLATFORM",
        "UPPER-ONLY ✓": "PLATFORM",
        "UPPER-ONLY ?": "PLATFORM",
        "SHARED ✓": "SHARED",
        "SHARED ?": "SHARED",
        "SHARED": "SHARED",
    }

    @staticmethod
    def load_map(root: Path) -> dict[str, str]:
        """Parse DUDA_MAP.md and return {filepath: layer_tag}."""
        map_path = root / "DUDA_MAP.md"
        if not map_path.exists():
            return {}

        layer_map = {}
        try:
            content = map_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return {}

        # Parse lines like: | src/platform/foo.ts | [UPPER-ONLY ✓] | ... |
        # Or: src/platform/foo.ts  [UPPER-ONLY ✓]
        line_re = re.compile(
            r"(?:\|\s*)?(\S+\.(?:ts|tsx|js|jsx|py|vue|svelte))\s*\|?\s*"
            r"\[([^\]]+)\]"
        )
        for line in content.splitlines():
            m = line_re.search(line)
            if m:
                filepath = m.group(1).strip()
                raw_tag = m.group(2).strip()
                layer = LayerTagger.LAYER_ALIASES.get(raw_tag, raw_tag)
                # Handle LAYER:X format
                if layer.startswith("LAYER:"):
                    layer = layer.split(":")[1].strip().upper()
                layer_map[filepath] = layer

        return layer_map

    @staticmethod
    def tag_files(files: list[FileMatch], layer_map: dict[str, str],
                  has_map: bool) -> list[FileMatch]:
        """Apply layer tags to files."""
        for fmatch in files:
            if not has_map:
                fmatch.layer = "NO-MAP"
            elif fmatch.path in layer_map:
                fmatch.layer = layer_map[fmatch.path]
            else:
                # Infer from path patterns
                path_lower = fmatch.path.lower()
                if any(p in path_lower for p in ["platform/", "admin/", "superadmin/"]):
                    fmatch.layer = "PLATFORM"
                elif any(p in path_lower for p in ["shared/", "common/", "packages/",
                                                    "utils/", "lib/", "types/"]):
                    fmatch.layer = "SHARED"
                elif any(p in path_lower for p in ["tenant/", "store/", "client/",
                                                    "franchise/"]):
                    fmatch.layer = "TENANT"
                else:
                    fmatch.layer = "UNMAPPED"
        return files

    @staticmethod
    def group_by_layer(files: list[FileMatch]) -> dict[str, list[FileMatch]]:
        """Group files by layer tag."""
        groups: dict[str, list[FileMatch]] = defaultdict(list)
        for f in files:
            groups[f.layer].append(f)
        # Sort groups by priority
        priority = ["PLATFORM", "SHARED", "TENANT", "UNMAPPED", "NO-MAP"]
        ordered = {}
        for layer in priority:
            if layer in groups:
                ordered[layer] = groups.pop(layer)
        # Append remaining custom layers
        for layer, flist in sorted(groups.items()):
            ordered[layer] = flist
        return ordered


# -- Cross-Layer Analyzer ----------------------------------------------------

class CrossLayerAnalyzer:
    """Detect imports that cross isolation layer boundaries."""

    # Layer hierarchy: upper → lower
    UPPER_LAYERS = {"PLATFORM"}
    LOWER_LAYERS = {"TENANT"}
    NEUTRAL_LAYERS = {"SHARED", "UNMAPPED", "NO-MAP"}

    @staticmethod
    def find_cross_imports(files: list[FileMatch],
                           layer_map: dict[str, str]) -> list[CrossLayerDep]:
        """Find imports that cross layer boundaries."""
        violations = []
        file_layers = {f.path: f.layer for f in files}

        for fmatch in files:
            for imp_path in fmatch.imports:
                imp_layer = file_layers.get(imp_path, layer_map.get(imp_path, "UNKNOWN"))

                # Lower importing from upper = violation
                if fmatch.layer in CrossLayerAnalyzer.LOWER_LAYERS \
                        and imp_layer in CrossLayerAnalyzer.UPPER_LAYERS:
                    violations.append(CrossLayerDep(
                        fmatch.path, fmatch.layer, imp_path, imp_layer
                    ))
                # Cross-layer (non-shared) = worth flagging
                elif fmatch.layer != imp_layer \
                        and fmatch.layer not in CrossLayerAnalyzer.NEUTRAL_LAYERS \
                        and imp_layer not in CrossLayerAnalyzer.NEUTRAL_LAYERS:
                    violations.append(CrossLayerDep(
                        fmatch.path, fmatch.layer, imp_path, imp_layer
                    ))

        return violations

    @staticmethod
    def assess_risk(cross_deps: list[CrossLayerDep]) -> str:
        """Assess overall risk level."""
        # Count upper-only violations (most severe)
        upper_violations = sum(
            1 for d in cross_deps
            if d.target_layer in CrossLayerAnalyzer.UPPER_LAYERS
        )
        total = len(cross_deps)

        if upper_violations >= 3 or total >= 6:
            return "CRITICAL"
        elif upper_violations >= 1 or total >= 3:
            return "HIGH"
        elif total >= 1:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def suggest_actions(risk: str, cross_deps: list[CrossLayerDep],
                        files: list[FileMatch]) -> list[str]:
        """Generate recommended actions based on risk."""
        actions = []
        if risk in ("HIGH", "CRITICAL"):
            actions.append("duda audit — trace full contamination path")
            # Suggest scan for specific violating files
            violators = set(d.source_file for d in cross_deps)
            for v in list(violators)[:3]:
                actions.append(f"duda scan {v} — detailed analysis")
            actions.append("duda fix — auto-generate adapter pattern")
        elif risk == "MEDIUM":
            actions.append("duda scan <violating-file> — check specific files")
            actions.append("Review cross-layer imports manually")
        else:
            actions.append("No isolation issues detected. Safe to proceed.")
        return actions


# -- Scope Cache -------------------------------------------------------------

class ScopeCache:
    """Cache scope results for instant re-analysis."""

    CACHE_DIR = ".duda/memory"
    CACHE_FILE = "scope_cache.json"

    def __init__(self, root: Path):
        self.root = root
        self.cache_path = root / self.CACHE_DIR / self.CACHE_FILE

    def _normalize_key(self, description: str) -> str:
        """Normalize description to cache key."""
        words = sorted(re.split(r"\s+", description.lower().strip()))
        return "-".join(words)

    def get(self, description: str) -> dict | None:
        """Get cached result if fresh."""
        if not self.cache_path.exists():
            return None
        try:
            data = json.loads(self.cache_path.read_text())
            key = self._normalize_key(description)
            entry = data.get("entries", {}).get(key)
            if not entry:
                return None
            # Check freshness (24 hours)
            cached_at = datetime.fromisoformat(entry.get("created_at", ""))
            age_hours = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
            if age_hours > 24:
                return None
            # Check file checksums — invalidate if any file changed
            checksums = entry.get("file_checksums", {})
            for fpath, cached_hash in checksums.items():
                full_path = self.root / fpath
                if full_path.is_file():
                    try:
                        current_hash = hashlib.md5(
                            full_path.read_bytes()
                        ).hexdigest()[:12]
                        if current_hash != cached_hash:
                            return None  # file changed, invalidate
                    except OSError:
                        return None
                else:
                    return None  # file deleted, invalidate
            return entry
        except (json.JSONDecodeError, ValueError, KeyError):
            return None

    def put(self, description: str, result: ScopeResult) -> None:
        """Save result to cache."""
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)

        data = {"entries": {}}
        if self.cache_path.exists():
            try:
                data = json.loads(self.cache_path.read_text())
            except json.JSONDecodeError:
                pass

        key = self._normalize_key(description)
        # Compute file checksums for cache invalidation
        file_checksums = {}
        for f in result.files:
            fpath = self.root / f.path
            if fpath.is_file():
                try:
                    content = fpath.read_bytes()
                    file_checksums[f.path] = hashlib.md5(content).hexdigest()[:12]
                except OSError:
                    pass

        data["entries"][key] = {
            "keywords": result.keywords,
            "files": [f.path for f in result.files],
            "file_count": len(result.files),
            "risk_level": result.risk_level,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "file_checksums": file_checksums,
        }

        self.cache_path.write_text(json.dumps(data, indent=2, ensure_ascii=False))


# -- Output Formatter --------------------------------------------------------

class OutputFormatter:
    """Format scope results for terminal output."""

    @staticmethod
    def format_standard(result: ScopeResult, has_map: bool) -> str:
        """Standard human-readable output."""
        lines = []
        lines.append("")
        lines.append(f"🔍 DUDA SCOPE — \"{result.description}\"")
        lines.append("━" * 50)
        lines.append("")
        lines.append(f"Keywords: {', '.join(result.keywords[:12])}")
        if len(result.keywords) > 12:
            lines.append(f"          ... +{len(result.keywords) - 12} more")
        lines.append(f"Discovered: {len(result.files)} files")
        lines.append(f"Map: {'DUDA_MAP.md loaded ✓' if has_map else 'Not found (run `duda init` for layer analysis)'}")
        lines.append("")

        if has_map and result.groups:
            lines.append("━━━ Layer Distribution ━━━━━━━━━━━━━━━━━━━━━━━━")
            lines.append("")
            total = len(result.files) or 1
            for layer, files in result.groups.items():
                pct = len(files) * 100 // total
                bar_filled = pct // 5
                bar = "█" * bar_filled + "░" * (20 - bar_filled)
                lines.append(f"[{layer}] {len(files)} files {bar} {pct}%")
                for f in files[:5]:
                    lines.append(f"  {f.path:<50s} ({f.score:.2f})")
                if len(files) > 5:
                    lines.append(f"  ... +{len(files) - 5} more")
                lines.append("")
        else:
            lines.append("━━━ Discovered Files ━━━━━━━━━━━━━━━━━━━━━━━━━━")
            lines.append("")
            for f in result.files[:20]:
                lines.append(f"  {f.path:<50s} ({f.score:.2f})")
            if len(result.files) > 20:
                lines.append(f"  ... +{len(result.files) - 20} more")
            lines.append("")

        if result.cross_layer_deps:
            lines.append("━━━ Cross-Layer Dependencies ━━━━━━━━━━━━━━━━━━")
            lines.append("")
            lines.append(f"⚠️  {len(result.cross_layer_deps)} violation(s) found")
            lines.append("")
            for i, dep in enumerate(result.cross_layer_deps[:10], 1):
                lines.append(f"  {i}. {dep.source_file}")
                lines.append(f"     → imports {dep.target_file} [{dep.target_layer}]")
            if len(result.cross_layer_deps) > 10:
                lines.append(f"  ... +{len(result.cross_layer_deps) - 10} more")
            lines.append("")

        lines.append("━━━ Risk Assessment ━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append("")
        risk_icons = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
        lines.append(f"Risk Level:   {risk_icons.get(result.risk_level, '⚪')} {result.risk_level}")
        if result.cross_layer_deps:
            lines.append(f"Violations:   {len(result.cross_layer_deps)} cross-layer")
        lines.append("")

        if result.recommendations:
            lines.append("━━━ Recommended Actions ━━━━━━━━━━━━━━━━━━━━━━━")
            lines.append("")
            for i, rec in enumerate(result.recommendations, 1):
                lines.append(f"  {i}. {rec}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def format_files_only(result: ScopeResult) -> str:
        """Output file paths only, one per line."""
        return "\n".join(f.path for f in result.files)

    @staticmethod
    def format_json(result: ScopeResult) -> str:
        """JSON output for programmatic use."""
        return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


# -- Main Orchestrator -------------------------------------------------------

def run_scope(feature: str, root: str = ".", depth: int = 1,
              min_score: float = 0.3, max_files: int = 20,
              no_map: bool = False, no_cache: bool = False) -> ScopeResult:
    """Main scope execution pipeline."""
    root_path = Path(root).resolve()

    # Check cache
    cache = ScopeCache(root_path)
    if not no_cache:
        cached = cache.get(feature)
        if cached:
            # Return cached result as ScopeResult
            result = ScopeResult(feature, cached.get("keywords", []))
            for fp in cached.get("files", []):
                result.files.append(FileMatch(fp))
            result.risk_level = cached.get("risk_level", "LOW")
            return result

    # Step 1: Extract keywords
    keywords = KeywordExtractor.extract(feature)
    expanded = KeywordExtractor.expand_synonyms(keywords)

    # Step 2: Search files
    searcher = FileSearcher(root)
    filename_matches = searcher.search_filenames(expanded)
    content_matches = searcher.search_contents(expanded)

    # Merge results
    all_matches: dict[str, FileMatch] = {}
    for path, fmatch in filename_matches.items():
        all_matches[path] = fmatch
    for path, fmatch in content_matches.items():
        if path in all_matches:
            # Merge keyword hits
            for k, v in fmatch.keyword_hits.items():
                all_matches[path].keyword_hits[k] = \
                    all_matches[path].keyword_hits.get(k, 0) + v
            all_matches[path].source = "filename+content"
        else:
            all_matches[path] = fmatch

    # Step 3: Expand imports
    if depth > 0 and all_matches:
        all_matches = searcher.expand_imports(all_matches, depth=depth)

    # Step 4: Score and filter
    # Use original keyword count (not expanded) to avoid score dilution
    scored = RelevanceScorer.score(all_matches, len(keywords))
    filtered = RelevanceScorer.filter_by_threshold(scored, min_score)
    filtered = filtered[:max_files]

    # Step 5: Layer tagging
    has_map = not no_map
    layer_map = {}
    if has_map:
        layer_map = LayerTagger.load_map(root_path)
        has_map = bool(layer_map)

    LayerTagger.tag_files(filtered, layer_map, has_map)
    groups = LayerTagger.group_by_layer(filtered)

    # Step 6: Cross-layer analysis
    cross_deps = []
    if has_map:
        cross_deps = CrossLayerAnalyzer.find_cross_imports(filtered, layer_map)

    # Step 7: Risk assessment
    risk_level = CrossLayerAnalyzer.assess_risk(cross_deps)
    recommendations = CrossLayerAnalyzer.suggest_actions(risk_level, cross_deps,
                                                         filtered)

    # Build result
    result = ScopeResult(feature, expanded)
    result.files = filtered
    result.groups = groups
    result.cross_layer_deps = cross_deps
    result.risk_level = risk_level
    result.recommendations = recommendations

    # Cache result
    if not no_cache:
        cache.put(feature, result)

    return result


# -- CLI Entry Point ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="DUDA SCOPE — Feature-centric isolation analysis"
    )
    parser.add_argument("--feature", "-f", required=True,
                        help="Feature description to analyze")
    parser.add_argument("--root", "-r", default=".",
                        help="Project root directory (default: .)")
    parser.add_argument("--depth", "-d", type=int, default=1,
                        help="Import chain expansion depth (default: 1)")
    parser.add_argument("--min-score", type=float, default=0.3,
                        help="Minimum relevance score 0.0~1.0 (default: 0.3)")
    parser.add_argument("--max-files", type=int, default=20,
                        help="Maximum files to display (default: 20)")
    parser.add_argument("--no-map", action="store_true",
                        help="Skip DUDA_MAP lookup")
    parser.add_argument("--no-cache", action="store_true",
                        help="Skip cache, force fresh analysis")
    parser.add_argument("--files-only", action="store_true",
                        help="Output file paths only")
    parser.add_argument("--json", action="store_true", dest="json_output",
                        help="JSON output")

    args = parser.parse_args()

    result = run_scope(
        feature=args.feature,
        root=args.root,
        depth=args.depth,
        min_score=args.min_score,
        max_files=args.max_files,
        no_map=args.no_map,
        no_cache=args.no_cache,
    )

    if args.files_only:
        print(OutputFormatter.format_files_only(result))
    elif args.json_output:
        print(OutputFormatter.format_json(result))
    else:
        has_map = any(f.layer not in ("NO-MAP",) for f in result.files)
        print(OutputFormatter.format_standard(result, has_map))


if __name__ == "__main__":
    main()
