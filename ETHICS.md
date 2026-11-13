# Ethics, Safety & Authorization Policy

**BreachBench** is a defensive security evaluation suite and static/agent vulnerability scanner. Author: Tanushree Umathe. Default posture: fully local (DGX Spark + Ollama); **evaluated models get no authority to make changes**.

1. **Explicit Permission Gate for Multi-Machine Deployment:**
   - Installing or executing BreachBench across local or lab machines via `install.sh` or `breachbench deploy-machines` requires explicit operator authorization (`--confirm-permission` or interactive `"YES_I_HAVE_AUTHORIZATION"` confirmation) and a machine allowlist (`config/machines.example.json` where `"authorized": true`).
   - Every multi-machine deployment attempt is recorded in an immutable JSONL audit trail (`results/deployment_audit.jsonl`).
   - GitHub Actions CI (`.github/workflows/ci.yml`) does **not** invoke `deploy-machines`. The CLI command and its permission gate still exist and are unit-tested.

2. **Synthetic & Inert Test Fixtures Only:**
   - All malware, phishing, prompt-injection, and vulnerable code samples in `data/` and `samples/` are synthetic, inert, non-weaponized indicators designed strictly to test detection accuracy, static analysis rules, and AI agent refusal boundaries.
   - No live command-and-control servers, real credentials, or destructive payloads are included or executed.
   - Optional Cognee memory demos in this project use a synthetic canary (for example `BB-CANARY-0001`) in a one-sentence store, not production secrets.

3. **Defensive Use Only:**
   - BreachBench must only be run against source code, AI agents, and compute nodes that you own or have explicit written permission to test.

4. **Untrusted memory and shield boundary:**
   - `--use-memory` retrieves Cognee chunks and appends them to the task prompt. When `--shield` is also on, that text is pre-screened and wrapped in `<untrusted_input_data>`. Retrieved memory is untrusted context, not an instruction channel.

5. **Tinfoil enclave egress:**
   - The CPU-only enclave (`Dockerfile.tinfoil`, `tinfoil-config.yml`) bakes Hugging Face evaluation samples into the image at build time. Runtime network egress is allowlisted to `inference.tinfoil.sh` only. Attestation of the published `v0.0.2` instance is **not yet verified** (see [docs/tinfoil.md](docs/tinfoil.md)).
