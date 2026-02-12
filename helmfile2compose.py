#!/usr/bin/env python3
"""helmfile2compose — convert helmfile template output to docker-compose.yml + Caddyfile."""

import argparse
import base64
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def run_helmfile_template(helmfile_dir: str, output_dir: str, environment: str | None = None) -> str:
    """Run helmfile template and return the path to rendered manifests."""
    rendered_dir = os.path.join(output_dir, ".helmfile-rendered")
    os.makedirs(rendered_dir, exist_ok=True)
    # helmfile auto-detects .gotmpl extension
    helmfile_path = os.path.join(helmfile_dir, "helmfile.yaml")
    if not os.path.exists(helmfile_path):
        gotmpl = helmfile_path + ".gotmpl"
        if os.path.exists(gotmpl):
            helmfile_path = gotmpl
    cmd = ["helmfile", "--file", helmfile_path]
    if environment:
        cmd.extend(["--environment", environment])
    cmd.extend(["template", "--output-dir", rendered_dir])
    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    subprocess.run(cmd, check=True)
    return rendered_dir


def parse_manifests(rendered_dir: str) -> dict[str, list[dict]]:
    """Load all YAML files from rendered_dir, classify by kind."""
    manifests: dict[str, list[dict]] = {}
    rendered = Path(rendered_dir)
    for yaml_file in sorted(rendered.rglob("*.yaml")):
        with open(yaml_file) as f:
            for doc in yaml.safe_load_all(f):
                if not doc or not isinstance(doc, dict):
                    continue
                kind = doc.get("kind", "Unknown")
                manifests.setdefault(kind, []).append(doc)
    return manifests


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    """Load helmfile2compose.yaml or return empty config."""
    if os.path.exists(path):
        with open(path) as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}
    cfg.setdefault("helmfile2ComposeVersion", "v1")
    cfg.setdefault("volumes", {})
    cfg.setdefault("exclude", [])
    return cfg


def save_config(path: str, config: dict) -> None:
    """Write helmfile2compose.yaml."""
    header = "# Configuration descriptor for https://github.com/baptisterajaut/helmfile2compose\n\n"
    # Ensure version key comes first
    ordered = {"helmfile2ComposeVersion": config.get("helmfile2ComposeVersion", "v1")}
    for k, v in config.items():
        if k != "helmfile2ComposeVersion":
            ordered[k] = v
    with open(path, "w") as f:
        f.write(header)
        yaml.dump(ordered, f, default_flow_style=False, sort_keys=False)


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------

def _full_name(manifest: dict) -> str:
    meta = manifest.get("metadata", {})
    return f"{manifest.get('kind', '?')}/{meta.get('name', '?')}"


_K8S_DNS_RE = re.compile(
    r'([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.'       # service name (captured)
    r'(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\.'       # namespace (discarded)
    r'svc\.cluster\.local'
)


def rewrite_k8s_dns(text: str) -> tuple[str, int]:
    """Replace <svc>.<ns>.svc.cluster.local with just <svc>. Returns (text, count)."""
    result, count = _K8S_DNS_RE.subn(r'\1', text)
    return result, count


def _secret_value(secret: dict, key: str) -> str | None:
    """Get a decoded value from a K8s Secret (base64 data or plain stringData)."""
    # stringData is plain text (rare in rendered output, but possible)
    val = secret.get("stringData", {}).get(key)
    if val is not None:
        return val
    # data is base64-encoded
    val = secret.get("data", {}).get(key)
    if val is not None:
        try:
            return base64.b64decode(val).decode("utf-8")
        except Exception:
            return val  # fallback: return raw if decode fails
    return None


def resolve_env(container: dict, configmaps: dict[str, dict], secrets: dict[str, dict],
                workload_name: str, warnings: list[str]) -> list[dict]:
    """Resolve env and envFrom into a flat list of {name: ..., value: ...}."""
    env_vars: list[dict] = []

    # Direct env entries
    for e in (container.get("env") or []):
        name = e.get("name", "")
        if "value" in e:
            env_vars.append({"name": name, "value": e["value"]})
        elif "valueFrom" in e:
            vf = e["valueFrom"]
            if "configMapKeyRef" in vf:
                ref = vf["configMapKeyRef"]
                cm = configmaps.get(ref.get("name", ""), {})
                data = cm.get("data", {})
                val = data.get(ref.get("key", ""))
                if val is not None:
                    env_vars.append({"name": name, "value": val})
                else:
                    warnings.append(
                        f"configMapKeyRef '{ref.get('name')}/{ref.get('key')}' "
                        f"on {workload_name} could not be resolved"
                    )
            elif "secretKeyRef" in vf:
                ref = vf["secretKeyRef"]
                sec = secrets.get(ref.get("name", ""), {})
                val = _secret_value(sec, ref.get("key", ""))
                if val is not None:
                    env_vars.append({"name": name, "value": val})
                else:
                    warnings.append(
                        f"secretKeyRef '{ref.get('name')}/{ref.get('key')}' "
                        f"on {workload_name} could not be resolved"
                    )
            else:
                warnings.append(
                    f"env var '{name}' on {workload_name} uses unsupported valueFrom — skipped"
                )

    # envFrom entries
    for ef in (container.get("envFrom") or []):
        if "configMapRef" in ef:
            cm_name = ef["configMapRef"].get("name", "")
            cm = configmaps.get(cm_name, {})
            for k, v in cm.get("data", {}).items():
                env_vars.append({"name": k, "value": v})
        elif "secretRef" in ef:
            sec_name = ef["secretRef"].get("name", "")
            sec = secrets.get(sec_name, {})
            for k in sec.get("data", {}):
                val = _secret_value(sec, k)
                if val is not None:
                    env_vars.append({"name": k, "value": val})

    # Rewrite K8s internal DNS in env var values
    total_rewrites = 0
    for ev in env_vars:
        if ev["value"] is not None and isinstance(ev["value"], str):
            rewritten, count = rewrite_k8s_dns(ev["value"])
            if count:
                ev["value"] = rewritten
                total_rewrites += count
    if total_rewrites:
        warnings.append(
            f"{workload_name}: rewrote {total_rewrites} K8s DNS reference(s) "
            f"(*.svc.cluster.local → service name)"
        )

    return env_vars


def convert_workload(manifest: dict, configmaps: dict[str, dict], secrets: dict[str, dict],
                     services_by_selector: dict, pvc_names: set, config: dict,
                     warnings: list[str], output_dir: str = ".",
                     generated_cms: set | None = None,
                     generated_secrets: set | None = None) -> dict | None:
    """Convert a Deployment or StatefulSet to a docker-compose service definition."""
    meta = manifest.get("metadata", {})
    name = meta.get("name", "unknown")
    kind = manifest.get("kind", "?")
    full = f"{kind}/{name}"

    if name in config.get("exclude", []):
        return None

    spec = manifest.get("spec", {})
    pod_spec = spec.get("template", {}).get("spec", {})
    containers = pod_spec.get("containers", [])
    init_containers = pod_spec.get("initContainers", [])

    if not containers:
        warnings.append(f"{full} has no containers — skipped")
        return None

    if len(containers) > 1:
        sidecars = [c.get("name", "?") for c in containers[1:]]
        for sc in sidecars:
            warnings.append(f"sidecar container '{sc}' on {full} ignored — only main container converted")

    if init_containers:
        for ic in init_containers:
            warnings.append(f"init container '{ic.get('name', '?')}' on {full} ignored — not supported")

    container = containers[0]
    svc = {}

    # Image
    image = container.get("image")
    if image:
        svc["image"] = image

    # Command / entrypoint
    if "command" in container:
        svc["entrypoint"] = container["command"]
    if "args" in container:
        svc["command"] = container["args"]

    # Environment
    env_list = resolve_env(container, configmaps, secrets, full, warnings)
    if env_list:
        svc["environment"] = {e["name"]: str(e["value"]) if e["value"] is not None else "" for e in env_list}

    # Ports — only expose if matching K8s Service is NodePort/LoadBalancer
    container_ports = container.get("ports", [])
    exposed_ports = _get_exposed_ports(name, meta.get("labels", {}), container_ports,
                                       services_by_selector)
    if exposed_ports:
        svc["ports"] = exposed_ports

    # Volumes
    volume_mounts = container.get("volumeMounts") or []
    pod_volumes = pod_spec.get("volumes") or []
    svc_volumes = _convert_volume_mounts(volume_mounts, pod_volumes, pvc_names, config, full, warnings,
                                         configmaps=configmaps, secrets=secrets,
                                         output_dir=output_dir, generated_cms=generated_cms,
                                         generated_secrets=generated_secrets)
    if svc_volumes:
        svc["volumes"] = svc_volumes

    # Network aliases from K8s Services selecting this workload
    aliases = _get_network_aliases(name, meta.get("labels", {}), services_by_selector)
    if aliases:
        svc["networks"] = {"default": {"aliases": aliases}}

    # Resource limits warning
    resources = container.get("resources", {})
    if resources.get("limits") or resources.get("requests"):
        warnings.append(f"resource limits on {full} ignored")

    return {name: svc}


def _resolve_named_port(name: str, container_ports: list) -> int | str:
    """Resolve a named port (e.g. 'http') to its numeric containerPort."""
    for cp in container_ports:
        if cp.get("name") == name:
            return cp["containerPort"]
    return name  # fallback: return as-is if not found


def _get_exposed_ports(workload_name: str, workload_labels: dict, container_ports: list,
                       services_by_selector: dict) -> list[str]:
    """Determine which ports to expose based on K8s Service type."""
    ports = []
    for _sel_key, svc_info in services_by_selector.items():
        svc_labels = svc_info.get("selector", {})
        if not svc_labels:
            continue
        if all(workload_labels.get(k) == v for k, v in svc_labels.items()):
            svc_type = svc_info.get("type", "ClusterIP")
            if svc_type in ("NodePort", "LoadBalancer"):
                for sp in svc_info.get("ports", []):
                    target = sp.get("targetPort", sp.get("port"))
                    if isinstance(target, str):
                        target = _resolve_named_port(target, container_ports)
                    node_port = sp.get("nodePort", sp.get("port"))
                    if isinstance(node_port, str):
                        node_port = _resolve_named_port(node_port, container_ports)
                    ports.append(f"{node_port}:{target}")
    return ports


def _get_network_aliases(workload_name: str, workload_labels: dict,
                         services_by_selector: dict) -> list[str]:
    """Get network aliases from K8s Services that select this workload."""
    aliases = []
    for _sel_key, svc_info in services_by_selector.items():
        svc_labels = svc_info.get("selector", {})
        if not svc_labels:
            continue
        if all(workload_labels.get(k) == v for k, v in svc_labels.items()):
            svc_name = svc_info.get("name", "")
            if svc_name and svc_name != workload_name:
                aliases.append(svc_name)
    return aliases


def _generate_configmap_files(cm_name: str, cm_data: dict, output_dir: str,
                              generated_cms: set, warnings: list[str]) -> str:
    """Write ConfigMap data entries as files. Returns the directory path (relative)."""
    rel_dir = os.path.join("configmaps", cm_name)
    abs_dir = os.path.join(output_dir, rel_dir)
    if cm_name not in generated_cms:
        generated_cms.add(cm_name)
        os.makedirs(abs_dir, exist_ok=True)
        for key, value in cm_data.items():
            rewritten, count = rewrite_k8s_dns(str(value))
            if count:
                warnings.append(
                    f"ConfigMap '{cm_name}' key '{key}': rewrote {count} K8s DNS reference(s)"
                )
            file_path = os.path.join(abs_dir, key)
            with open(file_path, "w") as f:
                f.write(rewritten)
    return f"./{rel_dir}"


def _generate_secret_files(sec_name: str, secret: dict, items: list | None,
                           output_dir: str, generated_secrets: set,
                           warnings: list[str]) -> str:
    """Write Secret data entries as files. Returns the directory path (relative)."""
    rel_dir = os.path.join("secrets", sec_name)
    abs_dir = os.path.join(output_dir, rel_dir)
    if sec_name not in generated_secrets:
        generated_secrets.add(sec_name)
        os.makedirs(abs_dir, exist_ok=True)
        # Determine which keys to write
        if items:
            keys = [item["key"] for item in items if "key" in item]
        else:
            keys = list(secret.get("data", {}).keys()) + list(secret.get("stringData", {}).keys())
        for key in keys:
            val = _secret_value(secret, key)
            if val is None:
                warnings.append(f"Secret '{sec_name}' key '{key}' could not be decoded — skipped")
                continue
            # Determine output filename (items can remap key → path)
            out_name = key
            if items:
                for item in items:
                    if item.get("key") == key and "path" in item:
                        out_name = item["path"]
                        break
            file_path = os.path.join(abs_dir, out_name)
            with open(file_path, "w") as f:
                f.write(val)
    return f"./{rel_dir}"


def _convert_volume_mounts(volume_mounts: list, pod_volumes: list, pvc_names: set,
                           config: dict, workload_name: str, warnings: list[str],
                           configmaps: dict | None = None, secrets: dict | None = None,
                           output_dir: str = ".", generated_cms: set | None = None,
                           generated_secrets: set | None = None) -> list[str]:
    """Convert volumeMounts to docker-compose volume strings."""
    # Build a map of volume name → volume source
    vol_map = {}
    for v in pod_volumes:
        vname = v.get("name", "")
        if "persistentVolumeClaim" in v:
            vol_map[vname] = {"type": "pvc", "claim": v["persistentVolumeClaim"].get("claimName", "")}
        elif "configMap" in v:
            vol_map[vname] = {"type": "configmap", "name": v["configMap"].get("name", ""),
                              "items": v["configMap"].get("items")}
        elif "secret" in v:
            vol_map[vname] = {"type": "secret", "name": v["secret"].get("secretName", ""),
                              "items": v["secret"].get("items")}
        elif "emptyDir" in v:
            vol_map[vname] = {"type": "emptydir"}
        else:
            vol_map[vname] = {"type": "unknown"}

    result = []
    for vm in volume_mounts:
        vname = vm.get("name", "")
        mount_path = vm.get("mountPath", "")
        source = vol_map.get(vname, {})

        if source.get("type") == "pvc":
            claim = source["claim"]
            pvc_names.add(claim)
            vol_cfg = config.get("volumes", {}).get(claim)
            if vol_cfg and isinstance(vol_cfg, dict) and "host_path" in vol_cfg:
                result.append(f"{vol_cfg['host_path']}:{mount_path}")
            elif vol_cfg is not None:
                # Named volume
                result.append(f"{claim}:{mount_path}")
            else:
                warnings.append(
                    f"PVC '{claim}' has no mapping in helmfile2compose.yaml — add it manually"
                )
                result.append(f"{claim}:{mount_path}")
        elif source.get("type") == "emptydir":
            # Use a tmpfs or anonymous volume
            result.append(mount_path)
        elif source.get("type") == "configmap" and configmaps is not None:
            cm_name = source["name"]
            cm = configmaps.get(cm_name)
            if cm is None:
                warnings.append(f"ConfigMap '{cm_name}' referenced by {workload_name} not found")
                continue
            cm_dir = _generate_configmap_files(cm_name, cm.get("data", {}),
                                               output_dir, generated_cms, warnings)
            sub_path = vm.get("subPath")
            if sub_path:
                result.append(f"{cm_dir}/{sub_path}:{mount_path}:ro")
            else:
                result.append(f"{cm_dir}:{mount_path}:ro")
        elif source.get("type") == "secret" and secrets is not None:
            sec_name = source["name"]
            sec = secrets.get(sec_name)
            if sec is None:
                warnings.append(f"Secret '{sec_name}' referenced by {workload_name} not found")
                continue
            sec_dir = _generate_secret_files(sec_name, sec, source.get("items"),
                                             output_dir, generated_secrets, warnings)
            sub_path = vm.get("subPath")
            if sub_path:
                result.append(f"{sec_dir}/{sub_path}:{mount_path}:ro")
            else:
                result.append(f"{sec_dir}:{mount_path}:ro")

    return result


def _build_service_port_map(manifests: dict, services_by_selector: dict) -> dict:
    """Build a map of (service_name, service_port) → container_port.

    Ingress backends reference Service ports, but in compose we talk directly
    to containers.  This resolves the chain: service port → targetPort → containerPort.
    """
    # Index workload labels → container ports
    workloads: list[tuple[dict, list]] = []
    for kind in ("Deployment", "StatefulSet"):
        for m in manifests.get(kind, []):
            labels = m.get("metadata", {}).get("labels", {})
            containers = m.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
            c_ports = containers[0].get("ports", []) if containers else []
            workloads.append((labels, c_ports))

    port_map: dict = {}
    for svc_name, svc_info in services_by_selector.items():
        selector = svc_info.get("selector", {})
        if not selector:
            continue
        # Find matching workload's container ports
        matched_ports: list = []
        for wl_labels, c_ports in workloads:
            if all(wl_labels.get(k) == v for k, v in selector.items()):
                matched_ports = c_ports
                break

        for sp in svc_info.get("ports", []):
            svc_port_num = sp.get("port")
            target = sp.get("targetPort", svc_port_num)
            if isinstance(target, str):
                target = _resolve_named_port(target, matched_ports)
            # Allow lookup by port number or port name
            port_map[(svc_name, svc_port_num)] = target
            if sp.get("name"):
                port_map[(svc_name, sp["name"])] = target

    return port_map


def convert_ingress(manifest: dict, service_port_map: dict, warnings: list[str]) -> list[dict]:
    """Convert Ingress to Caddyfile entries."""
    entries = []
    spec = manifest.get("spec", {})
    rules = spec.get("rules", [])
    tls_hosts = set()
    for tls in spec.get("tls", []):
        for h in tls.get("hosts", []):
            tls_hosts.add(h)

    for rule in rules:
        host = rule.get("host", "")
        if not host:
            continue
        http = rule.get("http", {})
        for path_entry in http.get("paths", []):
            path = path_entry.get("path", "/")
            backend = path_entry.get("backend", {})
            # Handle both v1 and v1beta1 ingress backend format
            if "service" in backend:
                svc_name = backend["service"].get("name", "")
                port = backend["service"].get("port", {})
                svc_port = port.get("number", port.get("name", 80))
            else:
                svc_name = backend.get("serviceName", "")
                svc_port = backend.get("servicePort", 80)

            # Resolve to container port (Service port → targetPort → containerPort)
            container_port = service_port_map.get((svc_name, svc_port), svc_port)

            scheme = "https" if host in tls_hosts else "http"
            entries.append({
                "host": host,
                "path": path,
                "upstream": f"{svc_name}:{container_port}",
                "scheme": scheme,
            })
    return entries


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def convert(manifests: dict[str, list[dict]], config: dict,
            output_dir: str = ".") -> tuple[dict, list[dict], list[str]]:
    """Main conversion: returns (compose_services, caddy_entries, warnings)."""
    warnings: list[str] = []
    compose_services: dict = {}
    caddy_entries: list[dict] = []
    pvc_names: set[str] = set()
    generated_cms: set[str] = set()
    generated_secrets: set[str] = set()

    # Index ConfigMaps and Secrets by name
    configmaps = {m["metadata"]["name"]: m for m in manifests.get("ConfigMap", [])
                  if "metadata" in m and "name" in m.get("metadata", {})}
    secrets = {m["metadata"]["name"]: m for m in manifests.get("Secret", [])
               if "metadata" in m and "name" in m.get("metadata", {})}

    # Index Services by selector for port/alias resolution
    services_by_selector: dict[str, dict] = {}
    for svc_manifest in manifests.get("Service", []):
        svc_meta = svc_manifest.get("metadata", {})
        svc_spec = svc_manifest.get("spec", {})
        selector = svc_spec.get("selector", {})
        svc_name = svc_meta.get("name", "")
        # Use service name as key (unique enough for our purposes)
        services_by_selector[svc_name] = {
            "name": svc_name,
            "selector": selector,
            "type": svc_spec.get("type", "ClusterIP"),
            "ports": svc_spec.get("ports", []),
        }

    # Convert workloads
    for kind in ("Deployment", "StatefulSet"):
        for m in manifests.get(kind, []):
            result = convert_workload(m, configmaps, secrets, services_by_selector,
                                      pvc_names, config, warnings,
                                      output_dir=output_dir,
                                      generated_cms=generated_cms,
                                      generated_secrets=generated_secrets)
            if result:
                compose_services.update(result)

    # Convert Ingresses (resolve Service ports → container ports)
    service_port_map = _build_service_port_map(manifests, services_by_selector)
    for m in manifests.get("Ingress", []):
        caddy_entries.extend(convert_ingress(m, service_port_map, warnings))

    # Update config with discovered PVCs
    for pvc in sorted(pvc_names):
        if pvc not in config["volumes"]:
            config["volumes"][pvc] = {"driver": "local"}

    # Emit warnings for unsupported kinds
    unsupported = {
        "CronJob": "not supported",
        "Job": "not supported",
        "HorizontalPodAutoscaler": "ignored",
        "PodDisruptionBudget": "ignored",
        "NetworkPolicy": "ignored",
        "ServiceAccount": "ignored",
    }
    for kind, reason in unsupported.items():
        for m in manifests.get(kind, []):
            meta = m.get("metadata", {})
            warnings.append(f"{kind} '{meta.get('name', '?')}' {reason}")

    return compose_services, caddy_entries, warnings


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_compose(services: dict, config: dict, output_dir: str) -> None:
    """Write docker-compose.yml."""
    compose = {"services": services}

    # Add top-level named volumes
    named_volumes = {}
    for vol_name, vol_cfg in config.get("volumes", {}).items():
        if isinstance(vol_cfg, dict) and "host_path" not in vol_cfg:
            named_volumes[vol_name] = vol_cfg
    if named_volumes:
        compose["volumes"] = named_volumes

    path = os.path.join(output_dir, "docker-compose.yml")
    with open(path, "w") as f:
        f.write("# Generated by helmfile2compose — do not edit manually\n")
        yaml.dump(compose, f, default_flow_style=False, sort_keys=False)
    print(f"Wrote {path}", file=sys.stderr)


def write_caddyfile(entries: list[dict], output_dir: str) -> None:
    """Write Caddyfile."""
    if not entries:
        return

    path = os.path.join(output_dir, "Caddyfile")
    # Group entries by host
    by_host: dict[str, list[dict]] = {}
    for e in entries:
        by_host.setdefault(e["host"], []).append(e)

    with open(path, "w") as f:
        f.write("# Generated by helmfile2compose — do not edit manually\n\n")
        for host, host_entries in by_host.items():
            # Sort: specific paths first, catch-all "/" last
            specific = [e for e in host_entries if e["path"] and e["path"] != "/"]
            catchall = [e for e in host_entries if not e["path"] or e["path"] == "/"]
            f.write(f"{host} {{\n")
            for entry in specific:
                f.write(f"\thandle {entry['path']}* {{\n")
                f.write(f"\t\treverse_proxy {entry['upstream']}\n")
                f.write("\t}\n")
            for entry in catchall:
                f.write(f"\treverse_proxy {entry['upstream']}\n")
            f.write("}\n\n")
    print(f"Wrote {path}", file=sys.stderr)


def emit_warnings(warnings: list[str]) -> None:
    """Print all warnings to stderr."""
    for w in warnings:
        print(f"⚠ {w}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Convert helmfile template output to docker-compose.yml + Caddyfile"
    )
    parser.add_argument(
        "--helmfile-dir", default=".",
        help="Directory containing helmfile.yaml (default: .)",
    )
    parser.add_argument(
        "-e", "--environment",
        help="Helmfile environment to use (e.g. local, production)",
    )
    parser.add_argument(
        "--from-dir",
        help="Skip helmfile template, read pre-rendered YAML from this directory",
    )
    parser.add_argument(
        "--output-dir", default=".",
        help="Where to write docker-compose.yml, Caddyfile, and helmfile2compose.yaml (default: .)",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Step 1: get rendered manifests
    if args.from_dir:
        rendered_dir = args.from_dir
    else:
        rendered_dir = run_helmfile_template(args.helmfile_dir, args.output_dir, args.environment)

    # Step 2: parse
    manifests = parse_manifests(rendered_dir)
    kinds = {k: len(v) for k, v in manifests.items()}
    print(f"Parsed manifests: {kinds}", file=sys.stderr)

    # Step 3: load config
    config_path = os.path.join(args.output_dir, "helmfile2compose.yaml")
    first_run = not os.path.exists(config_path)
    config = load_config(config_path)

    # On first run, auto-exclude K8s-only workloads
    if first_run:
        k8s_only_patterns = ("cert-manager", "ingress", "reflector")
        for kind in ("Deployment", "StatefulSet"):
            for m in manifests.get(kind, []):
                name = m.get("metadata", {}).get("name", "")
                if any(p in name for p in k8s_only_patterns):
                    if name not in config["exclude"]:
                        config["exclude"].append(name)
        if config["exclude"]:
            print(
                f"Auto-excluded K8s-only workloads: {', '.join(config['exclude'])}",
                file=sys.stderr,
            )

    # Step 4: convert
    services, caddy_entries, warnings = convert(manifests, config, output_dir=args.output_dir)

    # Step 5: emit warnings
    emit_warnings(warnings)

    # Step 6: write outputs
    if not services:
        print("No services generated — nothing to write.", file=sys.stderr)
        sys.exit(1)

    write_compose(services, config, args.output_dir)
    write_caddyfile(caddy_entries, args.output_dir)
    save_config(config_path, config)
    print(f"Wrote {config_path}", file=sys.stderr)

    if first_run:
        print(
            "\n⚠ First run — helmfile2compose.yaml was created and likely needs manual edits.\n"
            "  Review exclude list, volume mappings, and re-run.",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
