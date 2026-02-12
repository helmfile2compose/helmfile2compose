# helmfile2compose

Convert `helmfile template` output to `docker-compose.yml` + `Caddyfile`.

## Workflow

Lint often: run `pylint helmfile2compose.py` and `pyflakes helmfile2compose.py` after any change. Fix real issues (unused imports, actual bugs, f-strings without placeholders). Pylint style warnings (too-many-locals, line-too-long, etc.) are acceptable.

## What exists

Single script `helmfile2compose.py` (~600 lines). No packages, no setup.py. Dependency: `pyyaml`.

### CLI

```bash
# From helmfile directly (needs helmfile + helm installed)
python3 helmfile2compose.py --helmfile-dir ~/stoat-platform -e local --output-dir .

# From pre-rendered manifests (skip helmfile)
python3 helmfile2compose.py --from-dir /tmp/rendered --output-dir .
```

Flags: `--helmfile-dir`, `-e`/`--environment`, `--from-dir`, `--output-dir`.

### What it does

- Parses multi-doc YAML from `helmfile template --output-dir` (recursive `.yaml` scan)
- Classifies manifests by `kind`
- Converts:
  - **Deployment/StatefulSet** → compose `services:` (image, env, command, volumes, ports)
  - **ConfigMap/Secret** → resolved inline into `environment:` (via `env`, `envFrom`, `valueFrom`)
  - **Service (ClusterIP)** → network aliases on compose service
  - **Service (NodePort/LoadBalancer)** → `ports:` mapping
  - **Ingress** → Caddyfile blocks (`reverse_proxy`), specific paths before catch-all
  - **PVC** → named volumes + `helmfile2compose.yaml` config
- Warns on stderr for: init containers, sidecars, resource limits, HPA, CronJob, Job, PDB, NetworkPolicy, ServiceAccount
- Writes `docker-compose.yml`, `Caddyfile`, `helmfile2compose.yaml`

### Config file (`helmfile2compose.yaml`)

Persistent, re-runnable. User edits are preserved across runs.

```yaml
volumes:
  data-postgresql:
    driver: local          # named volume
  myapp-data:
    host_path: ./data/app  # bind mount
exclude:
  - prometheus-operator    # skip this workload
```

### Tested with

- Synthetic multi-doc YAML (Deployment, StatefulSet, ConfigMap, Secret, Service, Ingress, HPA, CronJob)
- Real `helmfile template` output from `~/stoat-platform` (`helmfile -e local template --output-dir /tmp/h2c-rendered` then `--from-dir`)
- `docker compose config` validates generated output

## Out of scope (MVP)

Jobs/CronJobs, init containers, sidecars (warning only — takes `containers[0]`), resource limits/requests, HPA, PDB, RBAC, ServiceAccounts, NetworkPolicies, probes→healthcheck.

## Recent fixes

- **Named ports** — K8s Service `targetPort` can be a string (e.g. `http`). Now resolved to numeric via container port definitions.
- **Secret base64 decoding** — K8s `Secret.data` values are base64-encoded. Now decoded before injecting into compose `environment:`. Handles both `data` (base64) and `stringData` (plain).
- **First-run auto-exclude** — When `helmfile2compose.yaml` doesn't exist, auto-excludes K8s-only workloads (matching `cert-manager`, `ingress`, `reflector` in name) and warns that manual review is needed.
- **Ingress port resolution** — Ingress backends reference Service ports, but compose talks directly to containers. Now resolves the full chain: Service port → targetPort → containerPort (e.g. livekit Service port 80 → named targetPort `http` → containerPort 7880).

## Known gaps / next steps

- **ConfigMap mounted as volume** (e.g. `Revolt.toml` in stoat-platform) — currently skipped silently. Needs a bind-mount or config generation strategy.
- **Cross-namespace resolution** — helmfile renders per-release in separate namespaces. ConfigMaps/Secrets referenced by workloads in other namespaces (via reflector) won't resolve. May need namespace-aware indexing or the config to bridge the gap.
- **Stoat-platform specifics** — all apps mount `Revolt.toml` from a ConfigMap (stoatchat-config chart). The compose equivalent is a generated file bind-mounted. This probably needs a dedicated config section rather than generic CM→volume handling.
- **K8s internal DNS in config values** — e.g. livekit's `LIVEKIT_CONFIG` contains `redis-master.stoatchat-redis.svc.cluster.local` which won't resolve in compose. Needs a rewrite strategy or config override.
- **Redis start-scripts** — bitnami Redis StatefulSet references `/opt/bitnami/scripts/start-scripts/start-master.sh` injected via ConfigMap. Won't work as-is in compose.
