"""Core correlation + classification logic.

Primary signal: each Radarr/Sonarr instance's own History API already
records both where an import came from (droppedPath, in the download
client's tree) and where it landed (importedPath, in the library) - both
reported in that same instance's own path-space. So the audit never needs
to cross-reference paths between different services; it only needs to
resolve one service's paths through that service's own mount table and
stat() both sides.

qBittorrent is used separately, only to flag torrents that never show up
as the source of an import (orphans) - informational, since *arr history
can be pruned/limited, so absence isn't proof of anything.
"""
import os
from dataclasses import dataclass, field


@dataclass
class ImportFinding:
    service: str
    source_title: str
    date: str
    dropped_path: str
    imported_path: str
    status: str  # ok | copied | cross_filesystem | missing_dropped | missing_imported | unresolved
    size: int = 0
    detail: str = ""
    download_id: str = None


@dataclass
class OrphanTorrent:
    name: str
    torrent_hash: str
    size: int
    save_path: str
    state: str


@dataclass
class AuditResult:
    import_findings: list = field(default_factory=list)
    orphan_torrents: list = field(default_factory=list)
    errors: list = field(default_factory=list)  # (context, message) pairs - non-fatal problems to surface


def _stat(local_path):
    try:
        return os.stat(local_path)
    except OSError:
        return None


def classify_import_event(service_name, event, resolver, current_file_ids=None):
    file_id = event.get("file_id")
    if current_file_ids is not None and file_id is not None and str(file_id) not in current_file_ids:
        return ImportFinding(
            service=service_name,
            source_title=event["source_title"],
            date=event["date"],
            dropped_path=event["dropped_path"],
            imported_path=event["imported_path"],
            size=event["size"],
            download_id=event.get("download_id"),
            status="superseded",
            detail="import antigo - o arquivo já foi trocado por um upgrade de qualidade desde então, "
                    "não é mais o arquivo ativo do item",
        )

    dropped_local = resolver.to_local_path(event["dropped_path"])
    imported_local = resolver.to_local_path(event["imported_path"])

    base_kwargs = dict(
        service=service_name,
        source_title=event["source_title"],
        date=event["date"],
        dropped_path=event["dropped_path"],
        imported_path=event["imported_path"],
        size=event["size"],
        download_id=event.get("download_id"),
    )

    if dropped_local is None or imported_local is None:
        bad = event["dropped_path"] if dropped_local is None else event["imported_path"]
        return ImportFinding(
            **base_kwargs,
            status="unresolved",
            detail=f"path fora de qualquer mount conhecido desse container: {bad}",
        )

    dropped_stat = _stat(dropped_local)
    imported_stat = _stat(imported_local)

    if imported_stat is None:
        return ImportFinding(
            **base_kwargs, status="missing_imported",
            detail=f"arquivo não existe mais na library: {imported_local}",
        )
    if dropped_stat is None:
        return ImportFinding(
            **base_kwargs, status="missing_dropped",
            detail=f"arquivo não existe mais no download: {dropped_local} "
                    "(torrent removido/movido/deletado fora do *arr)",
        )
    if dropped_stat.st_dev != imported_stat.st_dev:
        return ImportFinding(
            **base_kwargs, status="cross_filesystem",
            detail=f"download e library estão em filesystems diferentes "
                    f"(dev {dropped_stat.st_dev} vs {imported_stat.st_dev}) - "
                    "hardlink é estruturalmente impossível aqui",
        )
    if dropped_stat.st_ino != imported_stat.st_ino:
        return ImportFinding(
            **base_kwargs, status="copied",
            detail="mesmo filesystem mas inode diferente - virou cópia, não hardlink "
                    f"(desperdiçando ~{event['size']} bytes)",
        )
    return ImportFinding(**base_kwargs, status="ok")


def audit_arr_instance(instance, result):
    try:
        events = list(instance.import_events())
    except Exception as exc:  # noqa: BLE001
        result.errors.append((instance.name, f"falha lendo history: {exc}"))
        return
    try:
        current_file_ids = instance.current_file_ids()
    except Exception as exc:  # noqa: BLE001
        result.errors.append((instance.name, f"falha lendo arquivos atuais (seguindo sem filtrar imports obsoletos): {exc}"))
        current_file_ids = None
    for event in events:
        result.import_findings.append(
            classify_import_event(instance.name, event, instance.resolver, current_file_ids)
        )


def collect_seen_download_ids(result):
    return {f.download_id for f in result.import_findings if f.download_id}


def audit_qbit_orphans(qbit_client, known_download_ids, result):
    try:
        torrents = qbit_client.torrents()
    except Exception as exc:  # noqa: BLE001
        result.errors.append((qbit_client.name, f"falha lendo torrents: {exc}"))
        return
    for t in torrents:
        h = (t.get("hash") or "").upper()
        if h and h not in known_download_ids:
            result.orphan_torrents.append(
                OrphanTorrent(
                    name=t.get("name", "?"),
                    torrent_hash=h,
                    size=t.get("size", 0),
                    save_path=t.get("save_path", "?"),
                    state=t.get("state", "?"),
                )
            )
