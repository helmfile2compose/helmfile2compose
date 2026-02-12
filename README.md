# helmfile2compose

*For when you maintain a helmfile but people keep asking for a docker-compose.*

![Python](https://img.shields.io/badge/python-3.10+-blue)
![License](https://img.shields.io/badge/license-public%20domain-brightgreen)
![Vibe](https://img.shields.io/badge/vibe-coded-ff69b4)

Convert `helmfile template` output to `docker-compose.yml` + `Caddyfile`.

Takes Kubernetes manifests rendered by helmfile and produces a working Docker Compose setup with Caddy as reverse proxy, so you can run your stack locally (or hobby-grade) without Kubernetes.

Vibe-coded with Claude, because maintaining two deployment systems by hand wasn't happening.

## Requirements

- Python 3.10+
- `pyyaml`
- `helmfile` + `helm` (only if rendering from helmfile directly)

## Usage

```bash
# From helmfile directly
python3 helmfile2compose.py --helmfile-dir ~/my-platform -e local --output-dir ./compose

# From pre-rendered manifests (skip helmfile)
helmfile -e local template --output-dir /tmp/rendered
python3 helmfile2compose.py --from-dir /tmp/rendered --output-dir ./compose
```

### Flags

| Flag | Description |
|------|-------------|
| `--helmfile-dir` | Directory containing `helmfile.yaml` (default: `.`) |
| `-e`, `--environment` | Helmfile environment (e.g. `local`, `production`) |
| `--from-dir` | Skip helmfile, read pre-rendered YAML from this directory |
| `--output-dir` | Where to write output files (default: `.`) |

### Output files

- `docker-compose.yml` -- services, volumes, network aliases
- `Caddyfile` -- reverse proxy config derived from Ingress manifests
- `helmfile2compose.yaml` -- persistent config (see below)

## What it converts

| K8s kind | Compose equivalent |
|----------|-------------------|
| Deployment / StatefulSet | `services:` (image, env, command, volumes, ports) |
| ConfigMap / Secret | Resolved inline into `environment:` + generated as files for volume mounts |
| Service (ClusterIP) | Network aliases on the compose service |
| Service (NodePort / LoadBalancer) | `ports:` mapping |
| Ingress | Caddyfile `reverse_proxy` blocks |
| PVC | Named volumes in `helmfile2compose.yaml` |

## Config file (`helmfile2compose.yaml`)

Created on first run, preserved across re-runs. Edit it to control volume mappings and exclusions.

```yaml
helmfile2ComposeVersion: v1

volumes:
  data-postgresql:
    driver: local          # named volume
  myapp-data:
    host_path: ./data/app  # bind mount

exclude:
  - prometheus-operator    # skip this workload
```

On first run, K8s-only workloads (matching `cert-manager`, `ingress`, `reflector`) are auto-excluded with a warning to review.

## Target projects

### [stoatchat-platform](https://github.com/baptisterajaut/stoatchat-platform)

Primary target. A chat platform (Revolt rebrand) deployed via helmfile: API, events, file server, proxy, web client, MongoDB, Redis, RabbitMQ, MinIO, LiveKit.

Stoatchat-specific: all application services mount a `Revolt.toml` config file from a ConfigMap — now auto-generated to `configmaps/revolt-toml/Revolt.toml` and bind-mounted into each service. K8s internal DNS (`*.svc.cluster.local`) is rewritten to compose service names.

### [lasuite-platform](https://github.com/baptisterajaut/lasuite-platform)

Stretch goal. A much larger helmfile (~16 charts) for a collaborative suite. If the converter handles this, it handles anything.

## Limitations

Not converted (warning emitted):
- Jobs / CronJobs
- Init containers, sidecars (takes `containers[0]` only)
- Resource limits / requests, HPA, PDB
- RBAC, ServiceAccounts, NetworkPolicies
- Probes (no healthcheck generation)
