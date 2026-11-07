# Deploy BreachBench to a Tinfoil GPU enclave

The Spark is aarch64 and the enclave is linux/amd64, so **don't build on the Spark**. GitHub Actions builds the image.

## 1. Copy files into the repo (on the Spark)
cd ~/hackathons/localhost-nyc-2026/breachbench
# copy in: Dockerfile.tinfoil, .dockerignore, tinfoil/server.py, tinfoil/entrypoint.sh,
#          tinfoil-config.yml, .github/workflows/tinfoil-release.yml, .github/workflows/tinfoil-release-publish.yml
git add -A && git commit -m "Tinfoil enclave deployment" && git push

## 2. (Optional) smoke-test the wrapper locally against your Spark Ollama
OLLAMA_URL=$OLLAMA_HOST BB_RESULTS=/tmp/bbres python tinfoil/server.py &
curl -s localhost:8080/health

## 3. Release (builds amd64 image -> ghcr, pins digest, tags, measures, publishes)
gh workflow run tinfoil-release.yml -f version=v0.0.1
gh run watch          # wait for BOTH "Tinfoil Release" and "Tinfoil Release - Publish"
# If the ghcr package is private: make it public on GitHub (Packages > settings),
# or: tinfoil registry set ghcr --username tu2090-ops --token <PAT read:packages>

## 4. Tinfoil CLI (on the Mac is easiest)
curl -fsSL https://github.com/tinfoilsh/tinfoil-cli/raw/main/install.sh | sh
tinfoil login            # org ADMIN key from dash.tinfoil.sh
tinfoil whoami
tinfoil repo build info tu2090-ops/breachbench-localhost   # confirm v0.0.1 is published

## 5. Create the instance
tinfoil container create breachbench --repo tu2090-ops/breachbench-localhost --tag v0.0.1

## 6. Use it via a verified (attested) proxy
tinfoil container connect breachbench -p 3301
curl -s localhost:3301/health                      # wait for ollama_ready: true
curl -s -X POST localhost:3301/run -d '{"suite":"all","limit":25}'
curl -s localhost:3301/health                      # running -> false, rc 0
curl -s localhost:3301/results > enclave_qwen3_8b.json
curl -s localhost:3301/results.md
