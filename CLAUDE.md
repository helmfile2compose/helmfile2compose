# helmfile2compose (distribution)

The full distribution of [helmfile2compose](https://github.com/helmfile2compose) — h2c-core + 8 bundled extensions, concatenated into a single `helmfile2compose.py`.

## What this repo is

This is not the core engine — that's [h2c-core](https://github.com/helmfile2compose/h2c-core). This repo is the distribution manifest — `distribution.json` + CI workflow that assembles core + bundled extensions into a single script.

## The Eight Monks

| Repo | Type | File | Purpose |
|------|------|------|---------|
| h2c-indexer-configmap | IndexerConverter | `configmap_indexer.py` | Populates `ctx.configmaps` |
| h2c-indexer-secret | IndexerConverter | `secret_indexer.py` | Populates `ctx.secrets` |
| h2c-indexer-pvc | IndexerConverter | `pvc_indexer.py` | Populates `ctx.pvc_names` |
| h2c-indexer-service | IndexerConverter | `service_indexer.py` | Populates `ctx.services_by_selector` |
| h2c-provider-simple-workload | Provider | `workloads.py` | DaemonSet, Deployment, Job, StatefulSet → compose services |
| h2c-rewriter-haproxy | IngressRewriter | `haproxy.py` | HAProxy annotations + default fallback |
| h2c-provider-caddy | IngressProvider | `caddy.py` | Caddy service + Caddyfile generation |
| h2c-transform-fix-permissions | Transform | `fix_permissions.py` | Fix bind mount permissions for non-root containers |

Extensions import from `h2c` (e.g. `from h2c.core.ingress import IngressProvider`). At build time, these imports are stripped — everything lives in one namespace in the concatenated output.

## Building

```bash
# Local dev (reads core sources from sibling checkout)
python ../h2c-core/build-distribution.py helmfile2compose \
  --extensions-dir extensions --core-dir ../h2c-core
# → helmfile2compose.py

# CI mode (fetches h2c.py from h2c-core release, build-distribution.py from repo)
python build-distribution.py helmfile2compose --extensions-dir extensions
# → helmfile2compose.py
```

The output `helmfile2compose.py` is the release artifact — not committed, built by CI on tag push.

## Testing

```bash
# Quick smoke test
python helmfile2compose.py --from-dir /tmp/rendered --output-dir /tmp/out

# Full regression via testsuite
cd ../h2c-testsuite && ./run-tests.sh --local-core ../helmfile2compose/helmfile2compose.py
```

## Null-safe YAML access

`.get("key", {})` returns `None` when the key exists with an explicit `null` value (Helm conditional blocks). Always use `.get("key") or {}` / `.get("key") or []` for fields that Helm may render as null (`annotations`, `ports`, `initContainers`, `data`, `rules`, `selector`, etc.).

## Related repos

| Repo | Description |
|------|-------------|
| [h2c-core](https://github.com/helmfile2compose/h2c-core) | Bare conversion engine (`src/h2c/`) |
| [h2c-manager](https://github.com/helmfile2compose/h2c-manager) | Package manager + extension registry |
| [helmfile2compose.github.io](https://github.com/helmfile2compose/helmfile2compose.github.io) | Documentation site |
