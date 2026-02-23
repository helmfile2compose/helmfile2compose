"""PVC indexer — pre-registers PersistentVolumeClaim and workload PVC references."""

from h2c import ConverterResult, IndexerConverter

_WORKLOAD_KINDS = ("DaemonSet", "Deployment", "Job", "StatefulSet")


def _register_pvc(claim, config, pvc_names):
    """Register a single PVC claim in config if not already present."""
    if claim and claim not in config.get("volumes", {}):
        config.setdefault("volumes", {})[claim] = {"host_path": claim}
        pvc_names.add(claim)


class PVCIndexer(IndexerConverter):
    """Pre-register PVCs in config so volume conversion can resolve host_path on first run."""
    name = "pvc"
    kinds = ["PersistentVolumeClaim"]

    def convert(self, _kind, manifests, ctx):
        # Register explicit PVC manifests
        for m in manifests:
            claim = m.get("metadata", {}).get("name", "")
            _register_pvc(claim, ctx.config, ctx.pvc_names)
        # Scan workload manifests for volumeClaimTemplates and persistentVolumeClaim refs
        for wl_kind in _WORKLOAD_KINDS:
            for m in ctx.manifests.get(wl_kind, []):
                spec = m.get("spec") or {}
                for vct in spec.get("volumeClaimTemplates") or []:
                    _register_pvc(vct.get("metadata", {}).get("name", ""),
                                  ctx.config, ctx.pvc_names)
                pod_vols = ((spec.get("template") or {}).get("spec") or {}).get("volumes") or []
                for v in pod_vols:
                    pvc = v.get("persistentVolumeClaim") or {}
                    _register_pvc(pvc.get("claimName", ""), ctx.config, ctx.pvc_names)
        return ConverterResult()
