"""Radarr/Sonarr are both Servarr-family apps and share the same v3 API shape
(confirmed against a live instance of each: same history event schema,
data.droppedPath / data.importedPath fields, same eventType strings).
One client class covers both.
"""
import os
import xml.etree.ElementTree as ET

import requests

from . import discovery, service_url


class ArrConfigError(RuntimeError):
    pass


def _read_config_xml(container, resolver):
    for mount in discovery.container_mounts(container):
        local_dir = resolver.to_local_path(mount["destination"])
        if local_dir is None:
            continue
        candidate = os.path.join(local_dir, "config.xml")
        if os.path.isfile(candidate):
            return candidate
    return None


class ArrInstance:
    """A discovered Radarr/Sonarr container plus everything needed to reach
    it - all derived automatically, nothing hand-configured."""

    def __init__(self, kind, container, resolver):
        self.kind = kind  # "radarr" | "sonarr"
        self.container = container
        self.name = container.name
        self.resolver = resolver
        self.session = requests.Session()
        self._configure()

    def _configure(self):
        config_path = _read_config_xml(self.container, self.resolver)
        if config_path is None:
            raise ArrConfigError(
                f"não encontrei config.xml de '{self.name}' em nenhum dos mounts "
                f"conhecidos - o /config desse container está montado onde este "
                f"processo não consegue ler (checar HOST_ROOT_MOUNT)."
            )
        tree = ET.parse(config_path)
        root = tree.getroot()
        api_key = root.findtext("ApiKey")
        port = root.findtext("Port") or ("7878" if self.kind == "radarr" else "8989")
        url_base = root.findtext("UrlBase") or ""
        if not api_key:
            raise ArrConfigError(f"config.xml de '{self.name}' não tem <ApiKey>")

        self.session.headers["X-Api-Key"] = api_key

        candidates = service_url.candidate_urls(self.container, port, url_base)

        def probe(base_url):
            r = self.session.get(f"{base_url}/api/v3/system/status", timeout=5)
            return r.status_code == 200

        base_url = service_url.find_reachable(candidates, probe)
        if base_url is None:
            raise ArrConfigError(
                f"achei '{self.name}' e a API key, mas não consegui alcançar a API "
                f"HTTP dele. Tentei: {candidates}"
            )
        self.base_url = base_url

    def _get(self, path, **params):
        r = self.session.get(f"{self.base_url}{path}", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def import_events(self):
        """Yield {download_id, source_title, date, dropped_path, imported_path}
        for every downloadFolderImported event in history (paginated).

        Offset-based paging against a live, date-descending-sorted table:
        new rows landing mid-pagination can shift the list and land the same
        record on two pages. Dedupe by the record's own stable "id" to guard
        against double-counting (a row shifting the OTHER way and getting
        skipped entirely is still possible, but self-heals on the next
        run - not worth a stable-cursor rewrite for that)."""
        seen_ids = set()
        page = 1
        page_size = 250
        while True:
            data = self._get(
                "/api/v3/history",
                page=page,
                pageSize=page_size,
                sortKey="date",
                sortDirection="descending",
            )
            records = data.get("records", [])
            if not records:
                return
            for rec in records:
                rec_id = rec.get("id")
                if rec_id is not None:
                    if rec_id in seen_ids:
                        continue
                    seen_ids.add(rec_id)
                if rec.get("eventType") != "downloadFolderImported":
                    continue
                d = rec.get("data", {})
                dropped = d.get("droppedPath")
                imported = d.get("importedPath")
                if not dropped or not imported:
                    continue
                yield {
                    "download_id": (rec.get("downloadId") or "").upper() or None,
                    "source_title": rec.get("sourceTitle"),
                    "date": rec.get("date"),
                    "dropped_path": dropped,
                    "imported_path": imported,
                    "size": int(d.get("size") or 0),
                    "file_id": d.get("fileId"),
                }
            total = data.get("totalRecords", 0)
            if page * page_size >= total:
                return
            page += 1

    def current_file_ids(self):
        """IDs of files that are still the active file for a movie/episode
        today - used to tell a real problem apart from a stale history
        record for a file that was since replaced by a quality upgrade.

        Sonarr requires one /api/v3/episodefile call per series (no bulk
        endpoint) - a single series failing shouldn't blank out the whole
        set and disable supersede-filtering for every other series."""
        ids = set()
        if self.kind == "radarr":
            for movie in self._get("/api/v3/movie"):
                if movie.get("hasFile") and movie.get("movieFileId"):
                    ids.add(str(movie["movieFileId"]))
        else:
            for series in self._get("/api/v3/series"):
                try:
                    files = self._get("/api/v3/episodefile", seriesId=series["id"])
                except Exception:  # noqa: BLE001 - one bad series shouldn't blank the whole set
                    continue
                for f in files:
                    if f.get("id"):
                        ids.add(str(f["id"]))
        return ids

    def download_categories(self):
        """qBittorrent categories this instance files its downloads under
        (read from its own download client config, not guessed)."""
        cats = set()
        for client in self._get("/api/v3/downloadclient"):
            if client.get("implementation") != "QBittorrent":
                continue
            for field_ in client.get("fields", []):
                if field_.get("name") in ("movieCategory", "tvCategory") and field_.get("value"):
                    cats.add(field_["value"])
        return cats

    def queue_download_ids(self):
        """Download ids still sitting in this instance's queue - finished
        downloads waiting on (or blocked from) import live here, and must
        never be mistaken for leftovers.

        Items not mapped to any movie/series ("unknown" items) are left out:
        deleting a series/movie in *arr leaves its finished torrent in the
        queue forever as importBlocked ("title mismatch"), with nothing left
        to import into - that's exactly the deleted-library leftover, not a
        pending import."""
        data = self._get("/api/v3/queue", page=1, pageSize=1000, includeUnknownMovieItems="true",
                         includeUnknownSeriesItems="true")
        return {
            r["downloadId"].upper() for r in data.get("records", [])
            if r.get("downloadId") and (r.get("seriesId") or r.get("movieId"))
        }


def build_instances(kind, containers, resolvers):
    """resolvers: dict container.id -> PathResolver (built by caller from
    that container's own mounts)."""
    instances = []
    for container in containers:
        resolver = resolvers[container.id]
        instances.append(ArrInstance(kind, container, resolver))
    return instances
