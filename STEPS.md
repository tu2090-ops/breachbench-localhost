# Deploy BreachBench (CPU-only) to Tinfoil — v0.0.2

## 1. Unpack into the repo, commit, push (Spark or Mac)
cd ~/hackathons/localhost-nyc-2026/breachbench
tar xzf ~/tinfoil-breachbench-cpu.tgz --strip-components=1
rm -f tinfoil/entrypoint.sh
git add -A && git commit -m "Tinfoil: CPU-only enclave, test Tinfoil inference" && git push

## 2. Release v0.0.2
gh workflow run tinfoil-release.yml -f version=v0.0.2
gh run watch      # wait for BOTH Tinfoil Release and Tinfoil Release - Publish
tinfoil repo build info tu2090-ops/breachbench-localhost   # v0.0.2 published?

## 3. Inference API key as a project secret (stdin keeps it out of history)
read -s TK && echo -n "$TK" | tinfoil repo secret create tu2090-ops/breachbench-localhost TINFOIL_API_KEY --value-file - ; unset TK

## 4. Create the instance (if v0.0.1 GPU instance exists, delete it in dashboard or use a new name)
tinfoil container create breachbench --repo tu2090-ops/breachbench-localhost --tag v0.0.2

## 5. Connect and run
tinfoil container connect breachbench -p 3301
# second terminal:
curl -s localhost:3301/health            # api_key_present: true
curl -s -X POST localhost:3301/run -d '{"suite":"all","limit":25}'
curl -s localhost:3301/health            # poll until running:false, rc:0
curl -s localhost:3301/results > enclave_gemma4-31b.json
curl -s localhost:3301/results.md
