"""Auto-discovery of qBittorrent/Radarr/Sonarr containers via the Docker socket.

No container names or paths are assumed. Containers are matched by image name;
an env var escape hatch exists for setups where that guess is wrong.
"""
import os

import docker

IMAGE_HINTS = {
    "qbittorrent": ["qbittorrent"],
    "radarr": ["radarr"],
    "sonarr": ["sonarr"],
}

ENV_OVERRIDES = {
    "qbittorrent": "HA_QBITTORRENT_CONTAINERS",
    "radarr": "HA_RADARR_CONTAINERS",
    "sonarr": "HA_SONARR_CONTAINERS",
}


class DiscoveryError(RuntimeError):
    pass


def _docker_client():
    try:
        return docker.from_env()
    except Exception as exc:  # noqa: BLE001 - want a clear, actionable message
        raise DiscoveryError(
            "não consegui falar com o Docker socket. Confirme que "
            "/var/run/docker.sock está montado no container desta ferramenta."
        ) from exc


def _env_list(name):
    raw = os.environ.get(name, "").strip()
    return [x.strip() for x in raw.split(",") if x.strip()]


def _image_tags(container):
    try:
        tags = container.image.tags
    except Exception:  # noqa: BLE001 - image may have been removed since container started
        tags = []
    if not tags:
        tags = [container.attrs.get("Config", {}).get("Image", "")]
    return [t.lower() for t in tags]


def _matches(container, hints):
    text = " ".join(_image_tags(container))
    return any(hint in text for hint in hints)


def discover_containers(client=None):
    """Return {'qbittorrent': [Container,...], 'radarr': [...], 'sonarr': [...]}.

    For each kind: an explicit HA_<KIND>_CONTAINERS env var (comma-separated
    container names) wins over auto-detection. Otherwise every running
    container whose image name contains the kind's hint is included -
    multiple Radarr/Sonarr instances (e.g. HD + 4K) are all picked up.
    """
    client = client or _docker_client()
    all_containers = client.containers.list()
    by_name = {c.name: c for c in all_containers}

    found = {kind: [] for kind in IMAGE_HINTS}
    kinds_to_autodetect = []

    for kind, env_name in ENV_OVERRIDES.items():
        names = _env_list(env_name)
        if not names:
            kinds_to_autodetect.append(kind)
            continue
        for name in names:
            container = by_name.get(name)
            if container is None:
                raise DiscoveryError(
                    f"{env_name} aponta para o container '{name}', mas ele não "
                    "está rodando (ou não é visível a partir daqui)."
                )
            found[kind].append(container)

    for container in all_containers:
        for kind in kinds_to_autodetect:
            if _matches(container, IMAGE_HINTS[kind]):
                found[kind].append(container)

    return found


def container_mounts(container):
    """[{'source': host_path, 'destination': container_path}, ...]"""
    mounts = []
    for m in container.attrs.get("Mounts", []):
        source = m.get("Source")
        destination = m.get("Destination")
        if source and destination:
            mounts.append({"source": source, "destination": destination})
    return mounts
