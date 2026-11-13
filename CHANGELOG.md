# Changelog

All notable changes to **BreachBench** are documented in this file.

## [Unreleased]

### Changed
- Renamed leftover Trapni identifiers to BreachBench names. `POST /v1/trapni/posture` is now `POST /v1/workspace/posture`; `evaluate_trapni_posture` is `evaluate_workspace_posture`; `TrapniPostureRequest` is `WorkspacePostureRequest`. The posture helper is kept because `breachbench benchmark` uses it for at-risk vs hardened workspace scores. Also renamed `TRAPNI_THREAT_CANARY` to `BREACHBENCH_THREAT_CANARY`, phishing/schema keys (`expected_verdict`, `email_security`, `relevance`), and lab comments that still named Trapni / Genesis Second Brain.

## [0.0.3] - 2026-11-12

### Added
- **Optional Cognee memory retrieval** (`c9753e9`): `--use-memory` on `breachbench eval-agent` and `breachbench compare-shield`. Retrieves `SearchType.CHUNKS` from Cognee dataset `bb_smoke` (`top_k=3`) and appends the text to the task prompt before the Guardrail Shield, so it is treated as untrusted context. `_retrieve_context_from_memory` raises `RuntimeError` on import or search failure; `evaluate_agent` currently catches that, prints a warning, and continues without memory. Cognee is not a package dependency. Tests: `tests/test_memory_integration.py`.

### Changed
- **Documentation** (`#1`): README, STEPS, ETHICS, and `docs/` updated to match the post-2026-11-07 tree (Tinfoil, memory flag, CI scope, CI badge repo `tu2090-ops/breachbench-localhost`). Shielded Ollama placeholder cells removed from the results table; only numbers that exist in tests or in this README are kept.
- **README rewrite** (`#2`): numbered quick start, mermaid architecture diagram, command table. Shield internals moved to `docs/shield.md`.
- **Removed** the one-page LOCALHOST PDF that lived under `docs/` and every remaining link to it.
- **License**: project relicensed from MIT to Apache License 2.0 (`LICENSE`, `NOTICE`, README badge, `pyproject.toml` / `setup.py` classifiers).
- Package version set to `0.0.3` to follow git tags (`v0.0.1`, `v0.0.2`). In-tree metadata had still said `1.3.0`.

## [0.0.2] - 2026-11-07

Git tag `v0.0.2` (`git log -1 --format=%ci v0.0.2` → `2026-11-07 14:32:55 -0500`). CPU-only Tinfoil enclave release.

### Added
- **Tinfoil CPU-only enclave** (`c178779`, `f8502d1`, `84f7254`): `Dockerfile.tinfoil`, `tinfoil-config.yml` (`cvm-version: 0.14.7`, 2 CPUs, 8 GiB, egress allowlist `inference.tinfoil.sh`), `tinfoil/server.py` HTTP wrapper (`/health`, `/run`, `/results`, `/results.md`), and GitHub Actions `tinfoil-release.yml` / `tinfoil-release-publish.yml`. Image fetches `scripts/hf_suite.py` samples at build time and calls Tinfoil private inference (`gemma4-31b`) at run time. Tag `v0.0.2` is the published CPU enclave; attestation verification is not yet successful (`vm_shape` error; bumping `cvm-version` to `0.14.10` is a hypothesized fix, not applied here).

## [0.0.1] - 2026-11-07

Git tag `v0.0.1` (`git log -1 --format=%ci v0.0.1` → `2026-11-07 13:10:06 -0500`). First tagged tree (package metadata in this tag still said `1.3.0`).

### Added
- Initial LOCALHOST / NYC Sovereign AI Hackathon tree (`bb97f13`): CLI (`scan-code`, `scan-malware`, `eval-agent`, `compare-shield`, `deploy-machines`, `benchmark`), 3-layer Guardrail Shield, FastAPI service, tests, and sample corpora. Feature detail for that snapshot is under `[1.3.0]` / `[1.2.0]` below.
- First Tinfoil enclave wiring (`c178779`, `f8502d1`); the CPU-only image and published instance are `v0.0.2`.

### Changed
- **CI** (`c2208b6`, `dde66c4`): `.github/workflows/ci.yml` no longer runs `breachbench deploy-machines`. `scan-code` and `scan-malware` verification steps were restored. The `deploy-machines` CLI subcommand, permission gate, and unit tests remain.

## [1.3.0] - 2026-10-27

In-tree package version before git tags `v0.0.1` / `v0.0.2`. Kept for history; not a git tag.

### Added
- **3-Layer Defense-in-Depth Guardrail Shield (`breachbench/shield.py`)**:
  - **Layer 1 — Input Pre-Screen (`prescreen_input`)**: Scans untrusted prompts and embedded artifacts with BreachBench's static code vulnerability scanner (`scan_code_snippet`), malware & supply-chain hook detector (`scan_malware_payload`), phishing/BEC/MFA-pretext heuristics (`score_phishing_email`, `normalize_threat_text`), plus regex rules for malware-authoring requests (keyloggers, reverse shells, credential/SSH key exfiltration, ransomware, obfuscated droppers) and prompt-injection/tool-hijack markers (ignore previous instructions, DAN/jailbreaks, forced verdict overrides, canary/env exfiltration, `curl | sh`, and unpermitted SSH `deploy-machines` execution).
  - **Layer 2 — Hardened System Prompt & Data Spotlighting (`build_spotlighted_messages`)**: Wraps untrusted input inside `<untrusted_input_data>` spotlighting tags and injects structured pre-screen analyst telemetry (detected CWEs, OWASP categories, malware categories, and injection indicators) into the system prompt.
  - **Layer 3 — Output Enforcement (`enforce_output_shield`)**: Redacts leaked canary tokens, blocks/replaces responses that comply with malware-authoring or unauthorized SSH tool-hijack requests, neutralizes injection-induced false `clear`/`SAFE` verdicts, and appends a structured `BreachBench Shield findings` section (verdict, CWE IDs, malware categories, and remediation guidance) when the model omits detected findings.
  - Records per-task `shield_actions` in evaluation JSON reports.
- **CLI Flag `breachbench eval-agent --shield`**: Enables the 3-layer Guardrail Shield for `openai`, `ollama`, `echo`, and `deterministic` providers.
- **CLI Subcommand `breachbench compare-shield`**: Runs a target model unshielded (`--shield` off) and shielded (`--shield` on), prints a side-by-side comparison table (per-suite, overall, and per-task PASS/FAIL with triggered shield layers), and optionally writes JSON (`--out`) and Markdown (`--md`) reports.
- **Weak Stub Provider (`--provider echo`)**: Added a naive/compliance-prone stub provider that simulates an unaligned small model to verify and benchmark Guardrail Shield lift deterministically offline.
- **Release & PyPI Trusted Publishing Workflow (`.github/workflows/release.yml`)**: Automated sdist/wheel build, `twine check`, test verification, GitHub Release creation, and PyPI Trusted Publishing on `v*` tags.

### Changed
- Bumped package version to `1.3.0` across `pyproject.toml`, `setup.py`, `breachbench/__init__.py`, `breachbench/cli.py`, and `app/main.py`.
- Expanded unit and integration tests in `tests/test_breachbench.py` covering all three shield layers, unseen prompt generalization, zero false positives on benign artifacts, and `compare-shield`.

## [1.2.0] - 2026-04-12

In-tree changelog entry that shipped inside `v0.0.1`. Kept for history; not a git tag.

### Added
- Multi-domain security benchmark (`breachbench benchmark`) spanning Phishing/BEC/MFA-fatigue triage, Prompt Injection & Canary Guard, OWASP API Top 10 surface analysis, Static & Agent Code Vulnerability Scanner (`scan-code`), Malware & Supply-Chain Lure Detector (`scan-malware`), AI Agent Security Evaluator (`eval-agent`), and permission-gated multi-machine SSH runner (`deploy-machines`).
- FastAPI service (`app/main.py`) and OWASP vulnerable vs. hardened API comparison lab (`labs/vulnerable_api/app.py`).
