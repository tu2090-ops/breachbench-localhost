# 3-layer Guardrail Shield

When `--shield` is passed to `breachbench eval-agent`, or when `breachbench compare-shield` runs its shielded pass, `breachbench/shield.py` applies three layers. The shield does not read task IDs or grading keywords.

`compare-shield` always runs unshielded then shielded. It does not need `--shield`.

## Layer 1 — Input pre-screen (`prescreen_input`)

Scans the untrusted prompt and any embedded code or artifacts with:

- `scan_code_snippet`
- `scan_malware_payload`
- `score_phishing_email`
- regex detectors for malware-authoring requests (keylogger, reverse shell, credential/SSH exfiltration, ransomware, obfuscated dropper)
- injection / tool-hijack markers (`ignore previous instructions`, DAN jailbreaks, system overrides, canary/env exfiltration, `curl | sh`, unpermitted `deploy-machines`)

## Layer 2 — Spotlighting (`build_spotlighted_messages`)

Wraps untrusted content in `<untrusted_input_data>…</untrusted_input_data>` and injects pre-screen telemetry (CWEs, OWASP categories, malware indicators, injection warnings) into the system prompt.

If `--use-memory` ran first, retrieved Cognee text is already appended to the user prompt. Layer 2 therefore treats that memory as **untrusted data**, not as instructions.

## Layer 3 — Output enforcement (`enforce_output_shield`)

- Redacts leaked canary secrets (`output_canary_redacted`)
- Blocks malware-authoring or unauthorized SSH tool-hijack compliance
- Neutralizes injection-forced `clear` / `SAFE` verdicts on dangerous inputs
- Appends a `BreachBench Shield findings` section when the model omits detected issues

Per-task `shield_actions` are recorded in evaluation JSON.

## Providers

`--provider` on `eval-agent` / `compare-shield`: `openai`, `ollama`, `echo`, `deterministic`.

- `ollama` — local OpenAI-compatible endpoint (default `http://127.0.0.1:11434/v1`)
- `echo` — weak stub used to measure shield lift offline
- `deterministic` — fixed reference defender for CI
- `openai` — requires `OPENAI_API_KEY`; optional `--api-mode chat|responses`
