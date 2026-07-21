import os
import sys

from . import arr_client, audit, discovery, qbit_client, report
from .pathmap import PathResolver


def main():
    host_root = os.environ.get("HOST_ROOT_MOUNT", "/hostroot")

    try:
        containers = discovery.discover_containers()
    except discovery.DiscoveryError as exc:
        print(f"erro na descoberta de containers: {exc}", file=sys.stderr)
        return 2

    result = audit.AuditResult()

    if not containers["radarr"] and not containers["sonarr"]:
        print(
            "nenhum container de Radarr ou Sonarr encontrado. "
            "Se os nomes fogem do padrão, defina HA_RADARR_CONTAINERS / "
            "HA_SONARR_CONTAINERS.",
            file=sys.stderr,
        )
        return 2

    arr_instances = []
    for kind in ("radarr", "sonarr"):
        for container in containers[kind]:
            resolver = PathResolver(discovery.container_mounts(container), host_root=host_root)
            try:
                instance = arr_client.ArrInstance(kind, container, resolver)
            except arr_client.ArrConfigError as exc:
                result.errors.append((container.name, str(exc)))
                continue
            arr_instances.append(instance)
            print(f"[+] {kind}/{container.name} -> {instance.base_url}", file=sys.stderr)

    for instance in arr_instances:
        audit.audit_arr_instance(instance, result)

    known_download_ids = audit.collect_seen_download_ids(result)

    if not containers["qbittorrent"]:
        result.errors.append(("discovery", "nenhum container de qBittorrent encontrado (pulando checagem de órfãos)"))
    for container in containers["qbittorrent"]:
        client = qbit_client.QbitClient(container)
        try:
            client.connect()
        except qbit_client.QbitAuthError as exc:
            result.errors.append((container.name, str(exc)))
            continue
        print(f"[+] qbittorrent/{container.name} -> {client.base_url}", file=sys.stderr)
        audit.audit_qbit_orphans(client, known_download_ids, result)

    print(report.render_text(result))

    bad_statuses = {"copied", "cross_filesystem", "missing_dropped", "missing_imported", "unresolved"}
    if any(f.status in bad_statuses for f in result.import_findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
