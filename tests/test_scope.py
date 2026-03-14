#!/usr/bin/env python3
"""
Test cases for DUDA scope.py — Feature-centric isolation analysis
Based on Design Document Section 9: Test Scenarios

Usage:
  python -m pytest tests/test_scope.py -v
  python tests/test_scope.py  # standalone
"""
from __future__ import annotations

import os
import sys
import json
import shutil
import tempfile
from pathlib import Path

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from scope import (
    KeywordExtractor, FileSearcher, RelevanceScorer, LayerTagger,
    CrossLayerAnalyzer, ScopeCache, OutputFormatter, FileMatch,
    CrossLayerDep, ScopeResult, run_scope, SYNONYM_DB
)


# -- Test Fixtures -----------------------------------------------------------

def create_test_project(tmpdir: Path) -> Path:
    """Create a minimal test project structure."""
    # Platform files
    (tmpdir / "src/platform/roles").mkdir(parents=True)
    (tmpdir / "src/platform/roles/superAdmin.ts").write_text(
        'import { Permission } from "@/shared/types/permission";\n'
        'export const SUPER_ADMIN_ROLE = "superadmin";\n'
        'export function grantPermission(role: string) { return role; }\n'
    )
    (tmpdir / "src/platform/roles/definitions.ts").write_text(
        'export const ROLES = ["admin", "user", "guest"];\n'
        'export type Role = "admin" | "user" | "guest";\n'
    )

    # Shared files
    (tmpdir / "src/shared/types").mkdir(parents=True)
    (tmpdir / "src/shared/types/permission.ts").write_text(
        'export interface Permission { name: string; level: number; }\n'
        'export type PermissionLevel = "read" | "write" | "admin";\n'
    )
    (tmpdir / "src/shared/utils").mkdir(parents=True)
    (tmpdir / "src/shared/utils/rbac.ts").write_text(
        'import { Permission } from "../types/permission";\n'
        'export function checkPermission(perm: Permission) { return true; }\n'
        'export function hasRole(role: string) { return role === "admin"; }\n'
    )

    # Tenant files
    (tmpdir / "src/tenant/admin").mkdir(parents=True)
    (tmpdir / "src/tenant/admin/roleManager.tsx").write_text(
        'import { ROLES } from "@/platform/roles/definitions";\n'
        'import { checkPermission } from "@/shared/utils/rbac";\n'
        'export function RoleManager() { return <div>roles</div>; }\n'
    )
    (tmpdir / "src/tenant/hooks").mkdir(parents=True)
    (tmpdir / "src/tenant/hooks/useRole.ts").write_text(
        'import { Permission } from "@/shared/types/permission";\n'
        'export function useRole() { return { role: "user" }; }\n'
    )

    # Billing files (separate feature)
    (tmpdir / "src/shared/billing").mkdir(parents=True)
    (tmpdir / "src/shared/billing/payment.ts").write_text(
        'export function processPayment(amount: number) { return amount; }\n'
        'export const STRIPE_KEY = "pk_test_xxx";\n'
    )

    # Unrelated file
    (tmpdir / "src/shared/utils/format.ts").write_text(
        'export function formatDate(d: Date) { return d.toISOString(); }\n'
    )

    return tmpdir


# -- Test Cases (Design Section 9) ------------------------------------------

class TestScope:
    """Test scenarios from Design Document Section 9."""

    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.project = create_test_project(self.tmpdir)

    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # TC1: duda scope "permission" — finds auth-related files, groups by layer
    def test_01_permission_scope(self):
        result = run_scope("permission", root=str(self.project),
                           no_map=True, no_cache=True)
        assert len(result.files) > 0, "Should find permission-related files"
        paths = [f.path for f in result.files]
        # Should find permission.ts
        assert any("permission" in p for p in paths), \
            f"Should find permission files, got: {paths}"

    # TC2: duda scope "billing" — finds payment-related files
    def test_02_billing_scope(self):
        result = run_scope("billing", root=str(self.project),
                           no_map=True, no_cache=True)
        paths = [f.path for f in result.files]
        assert any("payment" in p or "billing" in p for p in paths), \
            f"Should find billing files, got: {paths}"

    # TC3: duda scope "x" (vague) — returns few/no results
    def test_03_vague_scope(self):
        result = run_scope("x", root=str(self.project),
                           no_map=True, no_cache=True, min_score=0.5)
        assert len(result.files) <= 3, \
            f"Vague query should return few results, got: {len(result.files)}"

    # TC4: duda scope "permission" --no-map — flat list without layers
    def test_04_no_map_mode(self):
        result = run_scope("permission", root=str(self.project),
                           no_map=True, no_cache=True)
        for f in result.files:
            assert f.layer == "NO-MAP", \
                f"No-map mode should tag all as NO-MAP, got: {f.layer}"

    # TC5: duda scope "permission" --files-only — path-only output
    def test_05_files_only_output(self):
        result = run_scope("permission", root=str(self.project),
                           no_map=True, no_cache=True)
        output = OutputFormatter.format_files_only(result)
        lines = output.strip().split("\n")
        for line in lines:
            assert "/" in line or "." in line, \
                f"files-only should output paths, got: {line}"

    # TC6: duda scope "permission" --json — valid JSON output
    def test_06_json_output(self):
        result = run_scope("permission", root=str(self.project),
                           no_map=True, no_cache=True)
        output = OutputFormatter.format_json(result)
        parsed = json.loads(output)
        assert "description" in parsed
        assert "keywords" in parsed
        assert "file_count" in parsed
        assert "risk_level" in parsed
        assert "groups" in parsed

    # TC7: Same scope twice — second run uses cache
    def test_07_cache_hit(self):
        # First run — populates cache
        result1 = run_scope("permission role", root=str(self.project),
                            no_map=True, no_cache=False)
        # Second run — should use cache
        cache = ScopeCache(self.project)
        cached = cache.get("permission role")
        assert cached is not None, "Cache should have entry after first run"
        assert cached["file_count"] == len(result1.files)

    # TC8: Scope after file change — cache invalidated
    def test_08_cache_invalidation(self):
        # Run scope to populate cache
        run_scope("permission", root=str(self.project),
                  no_map=True, no_cache=False)
        # Modify a file
        perm_file = self.project / "src/shared/types/permission.ts"
        perm_file.write_text(
            perm_file.read_text() + "\n// modified\n"
        )
        # Cache should be invalidated
        cache = ScopeCache(self.project)
        cached = cache.get("permission")
        assert cached is None, "Cache should be invalidated after file change"


# -- Unit Tests for Components -----------------------------------------------

class TestKeywordExtractor:

    def test_extract_basic(self):
        kws = KeywordExtractor.extract("account permission management")
        assert "account" in kws
        assert "permission" in kws
        # "management" is a stopword
        assert "management" not in kws

    def test_extract_stopwords_removed(self):
        kws = KeywordExtractor.extract("show me all the files for auth")
        assert "show" not in kws
        assert "the" not in kws
        assert "auth" in kws

    def test_expand_synonyms(self):
        expanded = KeywordExtractor.expand_synonyms(["permission"])
        assert "rbac" in expanded
        assert "acl" in expanded
        assert "authorize" in expanded

    def test_synonym_db_not_empty(self):
        assert len(SYNONYM_DB) >= 12, \
            f"SYNONYM_DB should have 12+ groups, got: {len(SYNONYM_DB)}"


class TestRelevanceScorer:

    def test_filename_match_scores_higher(self):
        files = {
            "permission.ts": FileMatch("permission.ts", {"permission": 1}, "filename"),
            "utils.ts": FileMatch("utils.ts", {"permission": 3}, "content"),
        }
        scored = RelevanceScorer.score(files, 5)
        filename_file = next(f for f in scored if f.path == "permission.ts")
        content_file = next(f for f in scored if f.path == "utils.ts")
        assert filename_file.score > 0, "Filename match should have positive score"
        assert content_file.score > 0, "Content match should have positive score"

    def test_filter_by_threshold(self):
        files = [
            FileMatch("a.ts", {"x": 1}, "content"),
            FileMatch("b.ts", {"x": 10}, "content"),
        ]
        files[0].score = 0.1
        files[1].score = 0.8
        filtered = RelevanceScorer.filter_by_threshold(files, 0.5)
        assert len(filtered) == 1
        assert filtered[0].path == "b.ts"


class TestCrossLayerDep:

    def test_import_type_field(self):
        dep = CrossLayerDep("a.ts", "TENANT", "b.ts", "PLATFORM", "dynamic")
        assert dep.import_type == "dynamic"
        d = dep.to_dict()
        assert d["import_type"] == "dynamic"

    def test_default_import_type(self):
        dep = CrossLayerDep("a.ts", "TENANT", "b.ts", "PLATFORM")
        assert dep.import_type == "direct"


class TestCrossLayerAnalyzer:

    def test_risk_levels(self):
        assert CrossLayerAnalyzer.assess_risk([]) == "LOW"

        deps_1 = [CrossLayerDep("a", "TENANT", "b", "PLATFORM")]
        assert CrossLayerAnalyzer.assess_risk(deps_1) == "HIGH"

        deps_6 = [CrossLayerDep(f"a{i}", "TENANT", f"b{i}", "SHARED")
                   for i in range(6)]
        assert CrossLayerAnalyzer.assess_risk(deps_6) == "CRITICAL"


class TestScopeResult:

    def test_to_dict(self):
        result = ScopeResult("test feature", ["test"])
        result.files = [FileMatch("a.ts")]
        result.risk_level = "LOW"
        d = result.to_dict()
        assert d["description"] == "test feature"
        assert d["file_count"] == 1
        assert d["risk_level"] == "LOW"


# -- Standalone runner -------------------------------------------------------

def run_all_tests():
    """Run all tests without pytest."""
    passed = 0
    failed = 0
    errors = []

    test_classes = [
        TestScope, TestKeywordExtractor, TestRelevanceScorer,
        TestCrossLayerDep, TestCrossLayerAnalyzer, TestScopeResult,
    ]

    for cls in test_classes:
        instance = cls()
        for method_name in sorted(dir(instance)):
            if not method_name.startswith("test_"):
                continue
            method = getattr(instance, method_name)
            try:
                if hasattr(instance, "setup_method"):
                    instance.setup_method()
                method()
                if hasattr(instance, "teardown_method"):
                    instance.teardown_method()
                passed += 1
                print(f"  ✅ {cls.__name__}.{method_name}")
            except Exception as e:
                failed += 1
                errors.append((f"{cls.__name__}.{method_name}", str(e)))
                print(f"  ❌ {cls.__name__}.{method_name}: {e}")
                if hasattr(instance, "teardown_method"):
                    try:
                        instance.teardown_method()
                    except Exception:
                        pass

    print(f"\n{'=' * 50}")
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    if errors:
        print(f"\nFailures:")
        for name, err in errors:
            print(f"  {name}: {err}")
    return failed == 0


if __name__ == "__main__":
    print("🧪 DUDA scope.py Test Suite\n")
    success = run_all_tests()
    sys.exit(0 if success else 1)
