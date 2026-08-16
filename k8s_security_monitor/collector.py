"""Collect cluster state from the Kubernetes API."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ClusterSnapshot:
    """Normalised snapshot used by detection modules."""

    pods: List[Dict[str, Any]] = field(default_factory=list)
    deployments: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    roles: List[Dict[str, Any]] = field(default_factory=list)
    cluster_roles: List[Dict[str, Any]] = field(default_factory=list)
    role_bindings: List[Dict[str, Any]] = field(default_factory=list)
    cluster_role_bindings: List[Dict[str, Any]] = field(default_factory=list)
    images: List[str] = field(default_factory=list)


class KubernetesCollector:
    """
    Read-only collector.
    Uses the official Kubernetes Python client when available; otherwise
    accepts an injected API stub for offline unit tests.
    """

    def __init__(self, api_client: Optional[Any] = None):
        self.api = api_client
        if self.api is None:
            self.api = self._build_default_client()

    def _build_default_client(self) -> Any:
        try:
            from kubernetes import client, config

            try:
                config.load_incluster_config()
            except config.ConfigException:
                config.load_kube_config()
            return client
        except Exception as exc:  # pragma: no cover - offline fallback
            raise RuntimeError(
                "Kubernetes client unavailable. Pass an api_client stub for tests."
            ) from exc

    def collect(self) -> ClusterSnapshot:
        """Pull live objects and return a ClusterSnapshot."""
        core = self.api.CoreV1Api()
        apps = self.api.AppsV1Api()
        rbac = self.api.RbacAuthorizationV1Api()

        pods = [p.to_dict() for p in core.list_pod_for_all_namespaces().items]
        deployments = [
            d.to_dict() for d in apps.list_deployment_for_all_namespaces().items
        ]
        services = [s.to_dict() for s in core.list_service_for_all_namespaces().items]
        roles = [r.to_dict() for r in rbac.list_role_for_all_namespaces().items]
        cluster_roles = [r.to_dict() for r in rbac.list_cluster_role().items]
        role_bindings = [
            b.to_dict() for b in rbac.list_role_binding_for_all_namespaces().items
        ]
        cluster_role_bindings = [
            b.to_dict() for b in rbac.list_cluster_role_binding().items
        ]

        images: List[str] = []
        for pod in pods:
            for container in (pod.get("spec") or {}).get("containers") or []:
                image = container.get("image")
                if image and image not in images:
                    images.append(image)

        return ClusterSnapshot(
            pods=pods,
            deployments=deployments,
            services=services,
            roles=roles,
            cluster_roles=cluster_roles,
            role_bindings=role_bindings,
            cluster_role_bindings=cluster_role_bindings,
            images=images,
        )
