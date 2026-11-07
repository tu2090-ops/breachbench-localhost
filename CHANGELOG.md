# Changelog

All notable changes to **BreachBench** are documented in this file.

## [1.3.0] - 2026-10-27

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

### Added
- Multi-domain security benchmark (`breachbench benchmark`) spanning Phishing/BEC/MFA-fatigue triage, Prompt Injection & Canary Guard, OWASP API Top 10 surface analysis, Static & Agent Code Vulnerability Scanner (`scan-code`), Malware & Supply-Chain Lure Detector (`scan-malware`), AI Agent Security Evaluator (`eval-agent`), and permission-gated multi-machine SSH runner (`deploy-machines`).
- FastAPI service (`app/main.py`) and OWASP vulnerable vs. hardened API comparison lab (`labs/vulnerable_api/app.py`).
