"""qBittorrent WebUI API client.

Unlike Radarr/Sonarr, credentials can't be auto-extracted: qBittorrent.conf
stores a salted hash of the password, not the password itself. If the
WebUI has no auth bypass configured for this network, HA_QBIT_USERNAME /
HA_QBIT_PASSWORD must be supplied - the tool says so plainly instead of
guessing.
"""
import os

import requests

from . import service_url


class QbitAuthError(RuntimeError):
    pass


def detect_internal_port(container):
    """qBittorrent images vary the WebUI's internal port (WEBUI_PORT on
    linuxserver's image, WEBUI_PORTS=8080/tcp on hotio's); fall back to the
    exposed tcp ports - preferring the de-facto 8080, since the torrent
    listen port is usually exposed too - then to 8080 itself."""
    env = container.attrs.get("Config", {}).get("Env", []) or []
    for entry in env:
        if entry.startswith("WEBUI_PORT="):
            return entry.split("=", 1)[1]
        if entry.startswith("WEBUI_PORTS="):
            first = entry.split("=", 1)[1].split(",")[0]
            return first.split("/")[0]
    exposed = container.attrs.get("Config", {}).get("ExposedPorts", {}) or {}
    if "8080/tcp" in exposed:
        return "8080"
    for key in exposed:
        if key.endswith("/tcp"):
            return key.split("/")[0]
    return "8080"


class QbitClient:
    def __init__(self, container):
        self.container = container
        self.name = container.name
        self.session = requests.Session()
        self.base_url = None

    def connect(self, port=None):
        port = port or detect_internal_port(self.container)
        username = os.environ.get("HA_QBIT_USERNAME")
        password = os.environ.get("HA_QBIT_PASSWORD")

        candidates = service_url.candidate_urls(self.container, port)

        def probe_open(base_url):
            r = self.session.get(f"{base_url}/api/v2/app/version", timeout=5)
            return r.status_code == 200

        def probe_login(base_url):
            r = self.session.post(
                f"{base_url}/api/v2/auth/login",
                data={"username": username, "password": password},
                timeout=5,
            )
            return r.status_code == 200 and r.text.strip() == "Ok."

        probe = probe_login if username else probe_open
        base_url = service_url.find_reachable(candidates, probe)
        if base_url is None:
            if username:
                raise QbitAuthError(
                    f"não consegui autenticar em '{self.name}' com "
                    "HA_QBIT_USERNAME/HA_QBIT_PASSWORD. Tentei: "
                    f"{candidates}"
                )
            raise QbitAuthError(
                f"'{self.name}' exige login (sem bypass de auth pra localhost) e "
                "HA_QBIT_USERNAME/HA_QBIT_PASSWORD não foram definidos. Defina as "
                f"duas env vars, ou libere 'Bypass authentication for clients on "
                "localhost' nas configs do WebUI. Tentei sem auth em: "
                f"{candidates}"
            )
        self.base_url = base_url

    def torrents(self):
        r = self.session.get(f"{self.base_url}/api/v2/torrents/info", timeout=30)
        r.raise_for_status()
        return r.json()

    def delete_torrent(self, torrent_hash, delete_files=True):
        r = self.session.post(
            f"{self.base_url}/api/v2/torrents/delete",
            data={"hashes": torrent_hash.lower(), "deleteFiles": "true" if delete_files else "false"},
            timeout=30,
        )
        r.raise_for_status()
