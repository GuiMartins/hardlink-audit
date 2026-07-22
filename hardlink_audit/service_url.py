"""Figure out how to actually reach a container's HTTP API from wherever this
tool happens to be running - published host port, container DNS name (same
compose network), or the container's internal IP - trying each until one
answers. No assumption about network_mode is baked in.
"""
import socket

import requests


def local_outbound_ip():
    """Best-effort guess at this host's real LAN IP (the one used for
    outbound traffic) - needed because some services only bypass WebUI auth
    for a whitelisted LAN subnet, not for 127.0.0.1 reached through Docker's
    NAT (which shows up as the bridge gateway IP, not localhost or the LAN)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


def candidate_urls(container, port, url_base=""):
    candidates = []

    port_key = f"{port}/tcp"
    bindings = (
        container.attrs.get("NetworkSettings", {}).get("Ports", {}).get(port_key) or []
    )
    lan_ip = local_outbound_ip()
    for binding in bindings:
        host_ip = binding.get("HostIp") or "127.0.0.1"
        if host_ip in ("0.0.0.0", "::"):
            host_ip = "127.0.0.1"
        candidates.append(f"http://{host_ip}:{binding['HostPort']}{url_base}")
        if lan_ip:
            candidates.append(f"http://{lan_ip}:{binding['HostPort']}{url_base}")

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
