# Deploy BreachBench (CPU-only) to Tinfoil — v0.0.2

Recipe for the files in this repo. Full file-by-file notes: [docs/tinfoil.md](docs/tinfoil.md).

**Status:** tag `v0.0.2` is deployed at https://breachbench.nyclocalhost.containers.tinfoil.dev. Attestation verification currently fails with a `vm_shape` error. Switching `cvm-version` in `tinfoil-config.yml` from `0.14.7` to `0.14.10` may fix it; that change is not in git. Treat attestation as not yet verified.

## 1. Confirm the enclave files

CPU-only image (no GPU, no `tinfoil/entrypoint.sh`):

- `Dockerfile.tinfoil` — `python:3.12-slim`, `pip install -e .`, fetch HF samples at build, `ENTRYPOINT ["python", "/app/tinfoil_server.py"]`
- `tinfoil/server.py` — HTTP on 8080: `/health`, `/run`, `/results`, `/results.md`
- `tinfoil-config.yml` — `cvm-version: 0.14.7`, 2 CPUs, 8 GiB, egress `inference.tinfoil.sh`, model `gemma4-31b`
- `.github/workflows/tinfoil-release.yml` and `tinfoil-release-publish.yml`

## 2. Release a tag (already done for v0.0.2)

From a clone of `tu2090-ops/breachbench-localhost`:

```bash
gh workflow run tinfoil-release.yml -f version=v0.0.2
gh run watch      # wait for BOTH Tinfoil Release and Tinfoil Release - Publish
tinfoil repo build info tu2090-ops/breachbench-localhost   # v0.0.2 published?
```

The release workflow frees runner disk before `docker buildx` (`f8502d1`) so the HF fetch + image push fit on `ubuntu-latest`.

## 3. Inference API key as a project secret (stdin keeps it out of history)

```bash
read -s TK && echo -n "$TK" | tinfoil repo secret create tu2090-ops/breachbench-localhost TINFOIL_API_KEY --value-file - ; unset TK
```

`tinfoil/server.py` maps that secret to `BB_API_KEY` for `scripts/hf_suite.py`.

## 4. Create the instance

CPU-only `v0.0.2`. If a `v0.0.1` GPU instance still exists, delete it in the dashboard or pick a new name.

```bash
tinfoil container create breachbench --repo tu2090-ops/breachbench-localhost --tag v0.0.2
```

## 5. Connect and run

```bash
tinfoil container connect breachbench -p 3301
```

Second terminal:

```bash
curl -s localhost:3301/health            # api_key_present: true
curl -s -X POST localhost:3301/run -d '{"suite":"all","limit":25}'
curl -s localhost:3301/health            # poll until running:false, rc:0
curl -s localhost:3301/results
curl -s localhost:3301/results.md
```

`suite` must be `ih`, `jbb`, or `all`; `limit` must be 1–25. The job runs `scripts/hf_suite.py run --compare` against `https://inference.tinfoil.sh/v1` with `BB_MODEL=gemma4-31b`.
