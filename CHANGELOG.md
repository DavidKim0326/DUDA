# Changelog

All notable changes to DUDA will be documented in this file.

## [2.1.1] - 2026-03-14

### Improved
- **SKILL.md tuned to skill-creator standards** (718 → 359 lines)
  - Description compressed from 35 lines to 10 lines with pushy trigger language
  - 4-axis Trust Score details → `references/trust-scoring.md`
  - Memory System → `references/memory.md`
  - "Why" explanations added throughout (95-point rationale, axis weights, topological sort reasoning)
  - Manual Mode and Core Principles absorbed into references
  - Progressive Disclosure: 4 reference files for 3-tier loading
- **README** — Install commands separated into individual code blocks for easy copy

## [2.1.0] - 2026-03-14

### Added
- **SCOPE mode** — Feature-centric isolation analysis (new)
  - Accepts natural language feature descriptions instead of file paths
  - `duda scope "account permission management"` discovers all related files
  - Auto keyword extraction + synonym expansion
  - Import chain expansion (configurable depth)
  - Relevance scoring (0.0~1.0) with configurable threshold
  - Layer grouping via DUDA_MAP integration
  - Cross-layer dependency detection and risk assessment
  - Risk levels: LOW / MEDIUM / HIGH / CRITICAL
  - Scope result caching for instant re-analysis
  - Works with or without DUDA_MAP (degraded mode without map)
  - JSON output (`--json`) for programmatic use
  - File-only output (`--files-only`) for piping to other DUDA commands
  - Manual mode fallback (grep-based, no Python required)

### Improved
- **Help section** rewritten with comprehensive English guide
  - Problem/solution comparison table
  - Situation-based command reference
  - Supported isolation types with examples
  - Quick start guide and key benefits

## [2.0.0] - 2026-03-14

### Added
- **ACT mode** — Automated fix generation after AUDIT/TRANSPLANT diagnosis
  - Fix plan generation with diff preview (read-only until confirmation)
  - Evaluator-Optimizer loop: re-audit after fix, max 3 iterations
  - Strategy-specific code generation (adapter, reimplementation, direct reference)
  - Progressive automation: SHOW → SUGGEST → APPLY → AUTO
- **GUARD mode** — CI/pre-commit isolation gate
  - Pre-commit hook integration (exit 0/1)
  - GitHub Actions workflow template
  - JSON output for CI parsing
  - Checks staged/changed files for isolation breaches
- **REFERENCES.md** — Attribution for patterns referenced from bkit v1.6.1 and industry tools
- Hook triggers for ACT and GUARD modes in duda-hook.js

### Referenced Patterns (see REFERENCES.md)
- bkit pdca-iterator: Evaluator-Optimizer loop (agents/pdca-iterator.md)
- bkit automation.js: Progressive automation levels (lib/pdca/automation.js)
- bkit gap-detector: Match rate → conditional branching (agents/gap-detector.md)
- bkit code-analyzer: Read-only analysis mode (agents/code-analyzer.md)
- ESLint --fix: Reverse-position batch apply
- Terraform: Plan-before-apply, drift detection
- Snyk: Fixability scoring

## [1.0.1] - 2026-03-14

### Fixed
- Python 3.8/3.9 compatibility: added `from __future__ import annotations` to init.py, trust.py, memory.py
  - `Path | None` union type syntax requires Python 3.10+; future annotations enables deferred evaluation for 3.7+

### Changed
- Restructured as Claude Code Plugin Marketplace compatible
  - `SKILL.md` → `skills/duda/SKILL.md`
  - Added `hooks/hooks.json` for automatic hook registration
- README updated with plugin install commands:
  ```
  /plugin marketplace add DavidKim0326/DUDA
  /plugin install duda
  ```

## [1.0.0] - 2026-03-14

### Added
- Initial public release
- 4 modes: INIT, SCAN, TRANSPLANT, AUDIT
- 4 isolation types: Platform-Derivative (A), Multi-tenant (B), Monorepo (C), Microservice (D)
- 4-axis trust score system with 95-point execution gate
- 6 Python automation scripts (stdlib only, no pip dependencies)
- Recursive learning memory system (UNKNOWN → CERTAIN progression)
- UserPromptSubmit hook for English trigger auto-detection
- Manual mode fallback (grep-based, no Python required)
- 16 eval test cases
- Reference patterns for all isolation types
- Apache-2.0 license
