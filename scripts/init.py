#!/usr/bin/env python3
from __future__ import annotations
"""
DUDA init.py — Mole flood-fill exploration engine
Explores the project in topological sort order from leaf nodes upward
to generate DUDA_MAP.md.

Usage:
  python init.py --root /path/to/project [--mode solo|team] [--update]
"""

import os
import re
import ast
import json
import hashlib
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque


# -- Configuration ------------------------------------------------------------

SKIP_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", ".turbo",
    "coverage", "__pycache__", ".cache", "out", ".vercel"
}

SOURCE_EXTENSIONS = {".ts", ".tsx", ".js", ".jsx", ".py"}

# Upper-only path hints (defaults when CLAUDE.md is absent)
DEFAULT_UPPER_HINTS = ["platform", "admin", "superadmin", "system"]
DEFAULT_LOWER_HINTS = ["tenant", "store", "client", "franchise"]
DEFAULT_SHARED_HINTS = ["packages", "shared", "common", "utils", "types", "lib"]

# Risk patterns — dynamic/runtime logic
UNVERIFIABLE_PATTERNS = [
    r"import\s*\(",          # dynamic import()
    r"require\s*\(",         # conditional require
    r"role\s*===",           # runtime role check
    r"process\.env\.",       # env var branching
    r"window\.",             # browser-only API
    r"\[.*\]\s*import",      # computed import
]

# Boundary files — checksum registration targets (key files at layer boundaries)
BOUNDARY_PATTERNS = [
    "**/layout.tsx", "**/layout.ts",
    "**/middleware.ts", "**/middleware.js",
    "**/route.ts", "**/route.js",
    "**/index.ts",
]


# -- File collection -----------------------------------------------------------

def collect_source_files(root: Path) -> list[Path]:
    """Collect all source files in the project (excluding SKIP_DIRS)."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Remove skip directories (in-place)
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if Path(fname).suffix in SOURCE_EXTENSIONS:
                files.append(Path(dirpath) / fname)
    return files


def extract_imports(file_path: Path, root: Path) -> list[str]:
    """Extract import paths from a file (both relative and absolute)."""
    imports = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return imports

    # ES6 / TypeScript import
    patterns = [
        r'import\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]',
        r'import\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',  # dynamic
        r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)', # require
        r'export\s+.*?\s+from\s+[\'"]([^\'"]+)[\'"]',
    ]
    for pattern in patterns:
        matches = re.findall(pattern, content)
        imports.extend(matches)

    return imports


def has_unverifiable_patterns(file_path: Path) -> list[str]:
    """Detect dynamic/runtime patterns."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    found = []
    for pattern in UNVERIFIABLE_PATTERNS:
        if re.search(pattern, content):
            found.append(pattern)
    return found


def file_checksum(file_path: Path) -> str:
    """File checksum (first 8 chars of SHA256)."""
    try:
        content = file_path.read_bytes()
        return hashlib.sha256(content).hexdigest()[:8]
    except Exception:
        return "unknown"


# -- CLAUDE.md parsing ---------------------------------------------------------

def load_claude_context(root: Path) -> dict:
    """Parse the DUDA context section from CLAUDE.md."""
    ctx = {
        "isolation_types": [],
        "layers": {},
        "upper_paths": [],
        "lower_paths": [],
        "shared_paths": [],
        "tenant_id": None,
        "forbidden": [],
        "isolation_method": None,
    }

    claude_md = root / "CLAUDE.md"
    if not claude_md.exists():
        return ctx

    content = claude_md.read_text(encoding="utf-8", errors="ignore")

    # Extract DUDA context section (supports both Korean and English headers)
    duda_section = re.search(
        r'##\s*DUDA\s*(?:컨텍스트|Context)(.*?)(?=^##|\Z)',
        content, re.MULTILINE | re.DOTALL
    )
    if not duda_section:
        return ctx

    section = duda_section.group(1)

    # Isolation type
    type_match = re.search(r'(?:격리\s*유형|Isolation\s*type)\s*:\s*(.+)', section)
    if type_match:
        ctx["isolation_types"] = re.findall(r'Type\s*[ABCD]', type_match.group(1))

    # Tenant identifier
    tenant_match = re.search(r'(?:테넌트\s*식별자|Tenant\s*identifier)\s*:\s*(.+)', section)
    if tenant_match:
        ctx["tenant_id"] = tenant_match.group(1).strip()

    # Path mapping
    upper_match = re.search(r'(?:상위\s*전용\s*경로|Upper-only\s*paths)\s*:\s*(.+)', section)
    if upper_match:
        ctx["upper_paths"] = [p.strip() for p in upper_match.group(1).split(",")]

    lower_match = re.search(r'(?:하위\s*전용\s*경로|Lower-only\s*paths)\s*:\s*(.+)', section)
    if lower_match:
        ctx["lower_paths"] = [p.strip() for p in lower_match.group(1).split(",")]

    shared_match = re.search(r'(?:공유\s*가능\s*경로|Shared\s*paths)\s*:\s*(.+)', section)
    if shared_match:
        ctx["shared_paths"] = [p.strip() for p in shared_match.group(1).split(",")]

    # Isolation method
    method_match = re.search(r'(?:방식|Method)\s*:\s*(.+)', section)
    if method_match:
        ctx["isolation_method"] = method_match.group(1).strip()

    # Forbidden transplants
    forbidden_matches = re.findall(r'-\s*(.+?)\s*:\s*(.+)', section)
    ctx["forbidden"] = [{"name": m[0], "reason": m[1]} for m in forbidden_matches]

    return ctx


# -- Layer tagging -------------------------------------------------------------

def determine_layer_tag(
    file_path: Path,
    root: Path,
    imports: list[str],
    ctx: dict,
    tagged: dict[str, str]
) -> tuple[str, str]:
    """
    Determine the layer tag for a file.
    Returns: (tag, confidence) — confidence: 'confirmed' | 'inferred' | 'ambiguous'
    """
    rel_path = str(file_path.relative_to(root))

    # 1. CLAUDE.md context-based path mapping (highest priority)
    for upper_path in ctx.get("upper_paths", []):
        if upper_path and upper_path in rel_path:
            return "UPPER-ONLY", "confirmed"

    for shared_path in ctx.get("shared_paths", []):
        if shared_path and shared_path in rel_path:
            # Even for shared paths, import analysis takes precedence
            pass

    for lower_path in ctx.get("lower_paths", []):
        if lower_path and lower_path in rel_path:
            return "LOWER-ONLY", "confirmed"

    # 2. Import dependency-based tagging (core of the flood-fill)
    has_upper_dep = False
    has_lower_dep = False

    for imp in imports:
        # If importing an already-tagged file
        for tagged_path, tagged_tag in tagged.items():
            if imp.replace("/", os.sep) in tagged_path:
                if tagged_tag == "UPPER-ONLY":
                    has_upper_dep = True
                elif tagged_tag == "LOWER-ONLY":
                    has_lower_dep = True

        # Hints from the import path itself
        imp_lower = imp.lower()
        for hint in ctx.get("upper_paths", DEFAULT_UPPER_HINTS):
            if hint and hint.lower() in imp_lower:
                has_upper_dep = True
        for hint in ctx.get("shared_paths", DEFAULT_SHARED_HINTS):
            if hint and hint.lower() in imp_lower:
                pass  # Shared imports do not affect tagging

    if has_upper_dep and has_lower_dep:
        return "SHARED", "ambiguous"  # Both sides -> ambiguous, needs review
    elif has_upper_dep:
        return "UPPER-ONLY", "inferred"
    elif has_lower_dep:
        return "LOWER-ONLY", "inferred"

    # 3. Path hint-based (fallback)
    rel_lower = rel_path.lower()
    for hint in DEFAULT_UPPER_HINTS:
        if hint in rel_lower:
            return "UPPER-ONLY", "inferred"
    for hint in DEFAULT_LOWER_HINTS:
        if hint in rel_lower:
            return "LOWER-ONLY", "inferred"
    for hint in DEFAULT_SHARED_HINTS:
        if hint in rel_lower:
            return "SHARED", "confirmed"

    # 4. Unable to determine
    return "SHARED", "ambiguous"


# -- Topological sort (flood-fill) ---------------------------------------------

def topological_sort(
    files: list[Path],
    root: Path
) -> list[Path]:
    """
    Topologically sort the dependency graph, returning files from leaf to root.
    Uses Kahn's Algorithm.
    """
    # File -> index mapping
    file_index = {f: i for i, f in enumerate(files)}
    n = len(files)

    # Adjacency list + in-degree
    adj = defaultdict(set)   # file -> files that import this file
    in_degree = defaultdict(int)

    for file in files:
        imports = extract_imports(file, root)
        for imp in imports:
            # Resolve import path to actual file
            resolved = resolve_import(imp, file, root, files)
            if resolved and resolved != file:
                # file depends on resolved -> resolved must be processed first
                adj[resolved].add(file)
                in_degree[file] += 1

    # Start with in-degree 0 (leaf nodes that import nothing)
    queue = deque([f for f in files if in_degree[f] == 0])
    sorted_files = []

    while queue:
        node = queue.popleft()
        sorted_files.append(node)
        for dependent in adj[node]:
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                queue.append(dependent)

    # Files with circular dependencies (unprocessed) are appended at the end
    remaining = set(files) - set(sorted_files)
    sorted_files.extend(remaining)

    return sorted_files


def resolve_import(
    import_path: str,
    source_file: Path,
    root: Path,
    all_files: list[Path]
) -> Path | None:
    """Resolve an import path to an actual file Path."""
    if import_path.startswith("."):
        # Relative path
        base = source_file.parent / import_path
        candidates = [
            base,
            base.with_suffix(".ts"),
            base.with_suffix(".tsx"),
            base.with_suffix(".js"),
            base / "index.ts",
            base / "index.tsx",
        ]
        for c in candidates:
            if c in all_files or c.exists():
                return c.resolve() if c.exists() else None
    else:
        # Absolute/package path — search within packages/
        parts = import_path.lstrip("@").split("/")
        for f in all_files:
            if any(part in str(f) for part in parts[:2]):
                return f
    return None


# -- Boundary file collection --------------------------------------------------

def collect_boundary_files(root: Path, ctx: dict) -> list[Path]:
    """Collect key files at isolation boundaries."""
    boundary = []
    all_files = collect_source_files(root)

    # Boundary path files
    for path_hint in ctx.get("upper_paths", []) + ctx.get("lower_paths", []):
        for f in all_files:
            if path_hint and path_hint in str(f):
                # Only layout, middleware, index files
                if any(pat in f.name for pat in ["layout", "middleware", "route", "index"]):
                    boundary.append(f)

    # Limit to 15 maximum (token efficiency)
    return list(set(boundary))[:15]


# -- DUDA_MAP.md generation ----------------------------------------------------

def generate_map(
    root: Path,
    tagged: dict[str, tuple[str, str]],  # path -> (tag, confidence)
    ctx: dict,
    boundary_files: list[Path],
    mode: str,
    ambiguous_count: int,
    unverifiable: dict[str, list[str]],
) -> str:
    """Generate DUDA_MAP.md content."""

    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    total = len(tagged)
    confirmed = sum(1 for _, (_, c) in tagged.items() if c == "confirmed")
    inferred = sum(1 for _, (_, c) in tagged.items() if c == "inferred")

    # Boundary file checksums
    checksums = {}
    for bf in boundary_files:
        rel = str(bf.relative_to(root))
        checksums[rel] = file_checksum(bf)

    # Per-layer path summary (top 10 each)
    upper_files = [p for p, (t, _) in tagged.items() if t == "UPPER-ONLY"][:10]
    lower_files = [p for p, (t, _) in tagged.items() if t == "LOWER-ONLY"][:10]
    shared_files = [p for p, (t, _) in tagged.items() if t == "SHARED"][:10]

    isolation_types = ", ".join(ctx.get("isolation_types", ["unknown"])) or "unknown"
    tenant_id = ctx.get("tenant_id", "unknown")
    isolation_method = ctx.get("isolation_method", "unknown")

    forbidden_list = "\n".join(
        f"  - {f['name']}: {f['reason']}"
        for f in ctx.get("forbidden", [])
    ) or "  (none)"

    checksum_list = "\n".join(
        f"  {rel}: {cs}" for rel, cs in checksums.items()
    ) or "  (none)"

    upper_list = "\n".join(f"  {p}" for p in upper_files) or "  (none)"
    lower_list = "\n".join(f"  {p}" for p in lower_files) or "  (none)"
    shared_list = "\n".join(f"  {p}" for p in shared_files) or "  (none)"

    unverifiable_list = "\n".join(
        f"  {p}: {', '.join(pats)}"
        for p, pats in list(unverifiable.items())[:10]
    ) or "  (none)"

    map_location = ".claude/duda-map.md" if mode == "solo" else "DUDA_MAP.md"

    content = f"""# DUDA_MAP
> auto-generated by DUDA init.py — do not edit manually
> generated: {now}
> location: {map_location}
> status: PENDING_APPROVAL

---

## Isolation Structure

Isolation type:    {isolation_types}
Isolation method:  {isolation_method}
Tenant identifier: {tenant_id}

Layer hierarchy:
"""
    for layer_name, layer_role in ctx.get("layers", {}).items():
        content += f"  - {layer_name}: {layer_role}\n"

    if not ctx.get("layers"):
        content += "  - (Layer hierarchy not defined in CLAUDE.md — manual input required)\n"

    content += f"""
Path mapping:
  Upper-only:  {', '.join(ctx.get('upper_paths', ['unknown']))}
  Lower-only:  {', '.join(ctx.get('lower_paths', ['unknown']))}
  Shared:      {', '.join(ctx.get('shared_paths', ['unknown']))}

---

## File Tagging Statistics

Total:             {total}
Confirmed:         {confirmed}
Inferred:          {inferred}
Ambiguous:         {ambiguous_count}  <- manual review required

---

## Forbidden Transplant List

{forbidden_list}

---

## Boundary File Checksums

{checksum_list}

---

## Key Files by Layer (top 10)

[UPPER-ONLY]
{upper_list}

[LOWER-ONLY]
{lower_list}

[SHARED]
{shared_list}

---

## Statically Unverifiable Items [UNVERIFIABLE]

{unverifiable_list}

---

## File Snapshot

total_files: {total}
generated:   {now}

---

## Trust Score History

| Date | Overall Score | Notes |
|------|--------------|-------|
| {now} | PENDING | Initial generation, awaiting approval |

---
> This file is automatically managed by the DUDA skill.
> Team mode: adding `DUDA_MAP.md merge=ours` to .gitattributes is recommended.
"""
    return content


# -- Main ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="DUDA flood-fill initialization")
    parser.add_argument("--root", default=".", help="Project root path")
    parser.add_argument("--mode", choices=["solo", "team"], default="team")
    parser.add_argument("--update", action="store_true", help="Regenerate existing map")
    parser.add_argument("--dry-run", action="store_true", help="Print result without saving map")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    map_path = root / (".claude/duda-map.md" if args.mode == "solo" else "DUDA_MAP.md")

    if map_path.exists() and not args.update:
        print(f"[WARNING] DUDA_MAP already exists: {map_path}")
        print("   To regenerate, use the --update flag")
        return

    print(f"[DUDA] Starting flood-fill — {root}")
    print(f"   Mode: {args.mode}")

    # 1. Load CLAUDE.md context
    ctx = load_claude_context(root)
    if ctx["isolation_types"]:
        print(f"   CLAUDE.md context loaded: {ctx['isolation_types']}")
    else:
        print("   [WARNING] No DUDA context in CLAUDE.md — using auto-inference mode")

    # 2. Collect source files
    print("\n[FILES] Collecting files...")
    files = collect_source_files(root)
    print(f"   Found {len(files)} source files")

    # 3. Topological sort (from leaf nodes)
    print("\n[FLOOD-FILL] Starting flood-fill (topological sort)...")
    sorted_files = topological_sort(files, root)
    print(f"   Sort complete: {len(sorted_files)} files")

    # 4. Sequential tagging
    print("\n[TAGGING] Assigning layer tags...")
    tagged = {}       # path_str -> (tag, confidence)
    unverifiable = {} # path_str -> [patterns]
    ambiguous_count = 0

    for file in sorted_files:
        rel = str(file.relative_to(root))
        imports = extract_imports(file, root)
        tag, confidence = determine_layer_tag(file, root, imports, ctx, {
            k: v[0] for k, v in tagged.items()
        })

        # Detect dynamic patterns
        unverifiable_pats = has_unverifiable_patterns(file)
        if unverifiable_pats:
            unverifiable[rel] = unverifiable_pats

        if confidence == "ambiguous":
            ambiguous_count += 1

        tagged[rel] = (tag, confidence)

    # Print statistics
    upper_count = sum(1 for _, (t, _) in tagged.items() if t == "UPPER-ONLY")
    lower_count = sum(1 for _, (t, _) in tagged.items() if t == "LOWER-ONLY")
    shared_count = sum(1 for _, (t, _) in tagged.items() if t == "SHARED")

    print(f"   [UPPER-ONLY]:    {upper_count}")
    print(f"   [LOWER-ONLY]:    {lower_count}")
    print(f"   [SHARED]:        {shared_count}")
    print(f"   [AMBIGUOUS]:     {ambiguous_count} <- manual review required")
    print(f"   [UNVERIFIABLE]:  {len(unverifiable)}")

    # 5. Boundary file checksums
    print("\n[CHECKSUM] Registering boundary file checksums...")
    boundary_files = collect_boundary_files(root, ctx)
    print(f"   {len(boundary_files)} boundary files registered")

    # 6. Generate map
    map_content = generate_map(
        root, tagged, ctx, boundary_files,
        args.mode, ambiguous_count, unverifiable
    )

    if args.dry_run:
        print("\n[DRY RUN] Map content to be generated:")
        print(map_content[:2000])
        return

    # 7. Save
    map_path.parent.mkdir(parents=True, exist_ok=True)
    map_path.write_text(map_content, encoding="utf-8")
    print(f"\n[DONE] DUDA_MAP generated: {map_path}")

    # 8. Request user approval
    print("\n" + "="*60)
    print("Does this structure look correct?")
    print(f"  Isolation type:   {ctx.get('isolation_types', 'unknown')}")
    print(f"  Upper paths:      {ctx.get('upper_paths', 'unknown')}")
    print(f"  Lower paths:      {ctx.get('lower_paths', 'unknown')}")
    print(f"  Ambiguous items:  {ambiguous_count}")
    print(f"  Forbidden items:  {len(ctx.get('forbidden', []))}")
    print()
    print("Approving will finalize the trust score as HIGH.")
    print("(In Claude Code: enter 'Y' or provide corrections)")

    # JSON summary output (for trust.py to read)
    summary = {
        "total_files": len(tagged),
        "upper_count": upper_count,
        "lower_count": lower_count,
        "shared_count": shared_count,
        "ambiguous_count": ambiguous_count,
        "unverifiable_count": len(unverifiable),
        "boundary_files": len(boundary_files),
        "context_loaded": bool(ctx["isolation_types"]),
        "map_path": str(map_path),
        "generated": datetime.now().isoformat(),
        "approved": False,
    }
    summary_path = root / ".duda" / "init-summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\nSummary saved: {summary_path}")


if __name__ == "__main__":
    main()
