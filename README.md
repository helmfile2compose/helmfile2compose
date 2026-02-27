# helmfile2compose

![vibe coded](https://img.shields.io/badge/vibe-coded-ff69b4)
![python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB)
![heresy: 0/0](https://img.shields.io/badge/heresy-0%2F0-black)
![deity: Yog Sa'rath](https://img.shields.io/badge/deity-Yog%20Sa'rath-8b0000)
![public domain](https://img.shields.io/badge/license-public%20domain-brightgreen)

*The full distribution. Patient zero, fully armed.*

This is where it started — a single Python script, born from the unholy request to make Kubernetes run without Kubernetes. It worked. That was the worst possible outcome. From this aberration, an [entire ecosystem](https://dekube.io) grew: a package manager, CRD extensions, documentation — a temple built for the sole purpose of dismantling a greater and more beautiful one.

Core of the problem: feed it Kubernetes manifests (from `helmfile template`, `helm template`, `kustomize build`, whatever produced them) and it will spit out a `compose.yml` + whatever configfile your proxy server will use. Not Kubernetes-in-Docker — no cluster, no kubelet, no shim. Plain `docker compose up`.

## Quick start

Download `helmfile2compose.py` from the [latest release](https://github.com/dekubeio/helmfile2compose/releases/latest).

```bash
# Convert from helmfile
python3 helmfile2compose.py --helmfile-dir ~/my-platform -e compose --output-dir .

# Or from any K8s manifests
python3 helmfile2compose.py --from-dir /tmp/rendered --output-dir .

docker compose up -d
```

If your stack uses CRDs (Keycloak, cert-manager, trust-manager), grab the extension `.py` files from their repos, drop them in a directory, and pass `--extensions-dir` to the script. For managing extensions and automating downloads, see [dekube-manager](https://github.com/dekubeio/dekube-manager).

## Requirements

- Python 3.10+
- `pyyaml`
- `helmfile` + `helm` (only if rendering from helmfile directly)

## What it converts

| K8s kind | Compose equivalent |
|----------|-------------------|
| Deployment / StatefulSet / DaemonSet | `services:` (image, env, command, volumes, ports) |
| Job | `services:` with `restart: on-failure` |
| ConfigMap / Secret | Inline `environment:` + generated files for volume mounts |
| Service | Hostname/alias/port rewriting |
| Ingress | Caddy `reverse_proxy` (auto-TLS, path routing, backend SSL) |
| PVC / volumeClaimTemplates | Host-path bind mounts |

Init containers, sidecars, fix-permissions services, and hostname truncation are handled automatically.

CRDs (Keycloak, cert-manager, trust-manager) are handled by [external extensions](https://docs.dekube.io/extensions/) via `--extensions-dir`.

## Output files

- `compose.yml` — services, volumes
- `Caddyfile` — reverse proxy config from Ingress manifests
- `dekube.yaml` — persistent config (volumes, excludes, overrides)
- `configmaps/` / `secrets/` — generated files from volume mounts

## Development

This repo contains built-in extensions under `extensions/`. The core engine lives in [dekube-engine](https://github.com/dekubeio/dekube-engine) (`src/dekube/`). The single-file `helmfile2compose.py` is a build artifact — dekube-engine + extensions concatenated by `build-distribution.py`.

```bash
# Build locally (reads core sources from sibling checkout)
python ../dekube-engine/build-distribution.py helmfile2compose \
  --extensions-dir extensions --core-dir ../dekube-engine
# → helmfile2compose.py

# Test it
python helmfile2compose.py --from-dir /tmp/rendered --output-dir .
```

See the [distributions docs](https://docs.dekube.io/distributions/) and [core architecture](https://docs.dekube.io/architecture/) for the full picture.

## Documentation

Full docs at [docs.dekube.io](https://docs.dekube.io).

## Related repos

| Repo | Description |
|------|-------------|
| [dekube-engine](https://github.com/dekubeio/dekube-engine) | Bare conversion engine (`dekube.py`) |
| [dekube-manager](https://github.com/dekubeio/dekube-manager) | Package manager + extension registry |
| [dekube-docs](https://github.com/dekubeio/dekube-docs) | Documentation site |

## License

Public domain.
