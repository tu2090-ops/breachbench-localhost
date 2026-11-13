# Tinfoil CPU-only enclave

BreachBench can be built as a **CPU-only** Tinfoil container. There is no GPU path in this tree: `tinfoil/entrypoint.sh` was removed in `84f7254`, and `Dockerfile.tinfoil` is `python:3.12-slim`.

**Attestation is not yet verified.** See [Known status](#known-status).

## Files in this repository

| Path | Role |
|---|---|
| `Dockerfile.tinfoil` | Image: install the package, fetch HF suite samples at **build** time, copy `tinfoil/server.py` to `/app/tinfoil_server.py`, listen on 8080. |
| `tinfoil-config.yml` | Tinfoil CVM spec. `cvm-version: 0.14.7`, 2 CPUs, 8192 MiB RAM, egress allowlist `inference.tinfoil.sh`, secret `TINFOIL_API_KEY`, shim paths `/health` `/run` `/results` `/results.md`. The release workflow rewrites the image digest. |
| `tinfoil/server.py` | Stdlib HTTP wrapper. `GET /health`, `POST /run`, `GET /results`, `GET /results.md`. Spawns `scripts/hf_suite.py run --compare` against Tinfoil private inference. |
| `.github/workflows/tinfoil-release.yml` | Phase 1: `workflow_dispatch` with `version`. Frees runner disk, builds `linux/amd64` from `Dockerfile.tinfoil`, pushes to `ghcr.io/<github.repository>`, updates `tinfoil-config.yml`, tags, dispatches phase 2. |
| `.github/workflows/tinfoil-release-publish.yml` | Phase 2 (auto): `tinfoilsh/measure-image-action` against `tinfoil-config.yml`. Do not run manually. |
| `.dockerignore` | Excludes `.venv/`, `results/`, `__pycache__/`, `.git/`. |

## What the image does

`Dockerfile.tinfoil` at build time:

```text
pip install --no-cache-dir -e .
python scripts/hf_suite.py fetch --suite all --ih-n 25 --jbb-harmful 25 --jbb-benign 0 \
  --seed 42 --data-dir /app/data/hf
```

Runtime env (from `tinfoil-config.yml`):

- `BB_URL=https://inference.tinfoil.sh/v1`
- `BB_MODEL=gemma4-31b`
- `TINFOIL_API_KEY` (Tinfoil project secret)
- `HOME=/tmp` (read-only root; results go under `/tmp/results`)

`POST /run` JSON body:

- `suite`: `ih` | `jbb` | `all` (default `all`)
- `limit`: integer 1–25 (default 25)

The server refuses to start a job without `TINFOIL_API_KEY` (HTTP 503) and refuses a second job while one is running (HTTP 409). Health is a local check (`api_key_present`); it does not call the inference API.

## Build and publish a tag

Requires GitHub `workflow_dispatch` permission on this repo. Example for `v0.0.2` (already released):

```bash
gh workflow run tinfoil-release.yml -f version=v0.0.2
gh run watch   # wait for both "Tinfoil Release" and "Tinfoil Release - Publish"
```

Phase 1 builds `Dockerfile.tinfoil`, pushes to GHCR, and uses `tinfoilsh/update-container-action` to pin the digest in `tinfoil-config.yml`. Phase 2 measures and attests that image. The `v0.0.2` GitHub release body records Inference Image Version `0.14.7` and a Sigstore digest.

Confirm the published build (Tinfoil CLI, not part of this repo):

```bash
tinfoil repo build info tu2090-ops/breachbench-localhost
```

## Create an instance and run

Store the inference API key as a project secret (stdin keeps it out of shell history):

```bash
read -s TK && echo -n "$TK" | tinfoil repo secret create tu2090-ops/breachbench-localhost TINFOIL_API_KEY --value-file - ; unset TK
```

Create the container from tag `v0.0.2` (CPU-only):

```bash
tinfoil container create breachbench --repo tu2090-ops/breachbench-localhost --tag v0.0.2
```

Port-forward the shim and drive the HTTP API. `tinfoil/server.py` binds **8080** inside the enclave; the CLI maps a local port (example: 3301):

```bash
tinfoil container connect breachbench -p 3301
```

In a second terminal:

```bash
curl -s localhost:3301/health            # expect api_key_present: true
curl -s -X POST localhost:3301/run -d '{"suite":"all","limit":25}'
curl -s localhost:3301/health            # poll until running:false, rc:0
curl -s localhost:3301/results
curl -s localhost:3301/results.md
```

`/run` returns HTTP 202 when accepted. Results are 404 until a job finishes.

## Known status

- **Deployed (author):** [https://breachbench.nyclocalhost.containers.tinfoil.dev](https://breachbench.nyclocalhost.containers.tinfoil.dev), tag `v0.0.2`.
- **Config in git:** `cvm-version: 0.14.7` (comment points at https://docs.tinfoil.sh/containers/quickstart). The `v0.0.2` release notes list Inference Image Version `0.14.7`.
- **Attestation:** verification currently fails with a `vm_shape` error. Switching `cvm-version` from `0.14.7` to `0.14.10` may fix it. That bump is **not** applied in this repository. **Do not treat the enclave as attestation-verified.**

This document does not change `tinfoil-config.yml`. Operator commands that use the Tinfoil CLI (`tinfoil container …`, `tinfoil repo …`) are the author’s recipe from `STEPS.md`; they are not unit-tested in this repo.
