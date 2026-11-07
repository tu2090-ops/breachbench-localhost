# Ethics, Safety & Authorization Policy

**BreachBench** is a defensive security evaluation suite and static/agent vulnerability scanner.

1. **Explicit Permission Gate for Multi-Machine Deployment:**
   - Installing or executing BreachBench across local or lab machines via `install.sh` or `breachbench deploy-machines` requires explicit operator authorization (`--confirm-permission` or interactive `"YES_I_HAVE_AUTHORIZATION"` confirmation) and a machine allowlist (`config/machines.example.json` where `"authorized": true`).
   - Every multi-machine deployment attempt is recorded in an immutable JSONL audit trail (`results/deployment_audit.jsonl`).

2. **Synthetic & Inert Test Fixtures Only:**
   - All malware, phishing, prompt-injection, and vulnerable code samples in `data/` and `samples/` are synthetic, inert, non-weaponized indicators designed strictly to test detection accuracy, static analysis rules, and AI agent refusal boundaries.
   - No live command-and-control servers, real credentials, or destructive payloads are included or executed.

3. **Defensive Use Only:**
   - BreachBench must only be run against source code, AI agents, and compute nodes that you own or have explicit written permission to test.
