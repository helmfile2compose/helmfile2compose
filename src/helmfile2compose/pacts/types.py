"""Public data types for extensions — the sacred contracts."""

from dataclasses import dataclass, field

# Well-known named ports (used by resolve_backend in pacts/ingress.py)
WELL_KNOWN_PORTS = {"http": 80, "https": 443, "grpc": 50051}


@dataclass
class ConvertContext:
    """Shared state passed to all converters during a conversion run."""
    config: dict
    output_dir: str
    configmaps: dict
    secrets: dict
    services_by_selector: dict
    alias_map: dict
    service_port_map: dict
    replacements: list
    pvc_names: set
    warnings: list
    generated_cms: set
    generated_secrets: set
    fix_permissions: dict


@dataclass
class ConvertResult:
    """Output of a single converter."""
    services: dict = field(default_factory=dict)
    caddy_entries: list = field(default_factory=list)
