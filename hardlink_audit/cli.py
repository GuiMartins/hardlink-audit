import os
import sys

from . import arr_client, audit, discovery, qbit_client, report
from .pathmap import PathResolver

BAD_STATUSES = {"copied", "cross_filesystem", "missing_dropped", "missing_imported", "unresolved"}


def run_audit():
    """Discover everything and run the full audit. Returns (AuditResult, log_lines)."""
    host_root = os.environ.get("HOST_ROOT_MOUNT", "/hostroot")
    log_lines = []
    result = audit.AuditResult()

    try:
        containers = discovery.discover_containers()
    except discovery.DiscoveryError as exc:
        result.errors.append(("discovery", str(exc)))
        return result, log_lines

    if not containers["radarr"] and not containers["sonarr"]:
        result.errors.append((
            "discovery",
            "nenhum container de Radarr ou Sonarr encontrado. Se os nomes fogem do "
            "padrão, defina HA_RADARR_CONTAINERS / HA_SONARR_CONTAINERS.",
        ))
        return result, log_lines

    arr_instances = []
    resolvers_by_service = {}
    for kind in ("radarr", "sonarr"):
        for container in containers[kind]:
            resolver = PathResolver(discovery.container_mounts(container), host_root=host_root)
            try:
                instance = arr_client.ArrInstance(kind, container, resolver)
            except arr_client.ArrConfigError as exc:
                result.errors.append((container.name, str(exc)))
                continue
            arr_instances.append(instance)
            resolvers_by_service[instance.name] = resolver
            log_lines.append(f"[+] {kind}/{container.name} -> {instance.base_url}")

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
        log_lines.append(f"[+] qbittorrent/{container.name} -> {client.base_url}")
        try:
            torrents = client.torrents()
        except Exception as exc:  # noqa: BLE001
            result.errors.append((container.name, f"falha lendo torrents: {exc}"))
            continue
        qbit_resolver = PathResolver(discovery.container_mounts(container), host_root=host_root)
        audit.find_orphan_torrents(torrents, known_download_ids, result)
        audit.reclassify_relocated_downloads(result, resolvers_by_service, torrents, qbit_resolver)
        audit.scan_download_folder_links(torrents, qbit_resolver, result, known_download_ids)

    return result, log_lines


def main():
    result, log_lines = run_audit()
    for line in log_lines:
        print(line, file=sys.stderr)
    print(report.render_text(result))

    if any(f.status in BAD_STATUSES for f in result.import_findings) or result.unlinked_downloads:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
