# helmfile2compose (distribution)

The full distribution of [dekube](https://dekube.io) — dekube-engine + 8 bundled extensions, concatenated into a single `helmfile2compose.py`.

## What this repo is

This is not the core engine — that's [dekube-engine](https://github.com/dekubeio/dekube-engine). This repo is the distribution manifest — `distribution.json` + CI workflow that assembles core + bundled extensions into a single script.

## The Eight Monks

| Repo | Type | File | Purpose |
|------|------|------|---------|
| dekube-indexer-configmap | IndexerConverter | `configmap_indexer.py` | Populates `ctx.configmaps` |
| dekube-indexer-secret | IndexerConverter | `secret_indexer.py` | Populates `ctx.secrets` |
| dekube-indexer-pvc | IndexerConverter | `pvc_indexer.py` | Populates `ctx.pvc_names` |
| dekube-indexer-service | IndexerConverter | `service_indexer.py` | Populates `ctx.services_by_selector` |
| dekube-provider-simple-workload | Provider | `workloads.py` | DaemonSet, Deployment, Job, StatefulSet → compose services |
| dekube-rewriter-haproxy | IngressRewriter | `haproxy.py` | HAProxy annotations + default fallback |
| dekube-provider-caddy | IngressProvider | `caddy.py` | Caddy service + Caddyfile generation |
| dekube-transform-fix-permissions | Transform | `fix_permissions.py` | Fix bind mount permissions for non-root containers |

Extensions import from `dekube` (e.g. `from dekube.core.ingress import IngressProvider`). At build time, these imports are stripped — everything lives in one namespace in the concatenated output.

## Building

```bash
# Local dev (reads core sources from sibling checkout)
python ../h2c-core/build-distribution.py helmfile2compose \
  --extensions-dir extensions --core-dir ../h2c-core
# → helmfile2compose.py

# CI mode (fetches dekube.py from dekube-engine release, build-distribution.py from repo)
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
| [dekube-engine](https://github.com/dekubeio/dekube-engine) | Bare conversion engine (`src/dekube/`) |
| [dekube-manager](https://github.com/dekubeio/dekube-manager) | Package manager + extension registry |
| [dekube-docs](https://docs.dekube.io) | Documentation site |
