"""Figure out how to actually reach a container's HTTP API from wherever this
tool happens to be running - published host port, container DNS name (same
compose network), or the container's internal IP - trying each until one
answers. No assumption about network_mode is baked in.
"""
import requests


def candidate_urls(container, port, url_base=""):
    candidates = []

    port_key = f"{port}/tcp"
    bindings = (
        container.attrs.get("NetworkSettings", {}).get("Ports", {}).get(port_key) or []
    )
    for binding in bindings:
        host_ip = binding.get("HostIp") or "127.0.0.1"
        if host_ip in ("0.0.0.0", "::"):
            host_ip = "127.0.0.1"
        candidates.append(f"http://{host_ip}:{binding['HostPort']}{url_base}")

    candidates.append(f"http://{container.name}:{port}{url_base}")

    for net in container.attrs.get("NetworkSettings", {}).get("Networks", {}).values():
        ip = net.get("IPAddress")
        if ip:
            candidates.append(f"http://{ip}:{port}{url_base}")

    seen = set()
    ordered = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def find_reachable(candidates, probe):
    """probe(base_url) -> bool. Returns the first base_url that probes ok,
    or None with the list of what was tried."""
    for base_url in candidates:
        try:
            if probe(base_url):
                return base_url
        except requests.RequestException:
            continue
    return None
