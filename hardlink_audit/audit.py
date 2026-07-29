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
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field

_SIDECAR_EXTENSIONS = {".srt", ".sub", ".idx", ".ssa", ".ass", ".nfo", ".txt", ".jpg", ".jpeg", ".png"}


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
    dropped_host_path: str = None
    imported_host_path: str = None


@dataclass
class OrphanTorrent:
    name: str
    torrent_hash: str
    size: int
    save_path: str
    state: str


REASON_COPIED = "copied"
REASON_ORPHANED_UPGRADE = "orphaned_upgrade"
REASON_SIDECAR_ONLY = "sidecar_only"
REASON_UNKNOWN = "unknown"

REASON_TEXT = {
    REASON_COPIED: (
        "O import virou uma cópia real em vez de hardlink - o mesmo arquivo existe duas vezes no disco.",
        "Apague o arquivo na pasta de download e force o Radarr/Sonarr a re-importar (ele deve linkar "
        "certo se o download ainda estiver lá), ou apague o arquivo na library e re-hardlinke manualmente "
        "a partir da cópia em downloads. Se isso se repetir bastante, vale conferir se download e library "
        "seguem no mesmo disco/filesystem.",
    ),
    REASON_ORPHANED_UPGRADE: (
        "Esse download foi substituído por um upgrade de qualidade depois - o Radarr/Sonarr apagou a "
        "versão antiga da library, mas a cópia correspondente na pasta de download não foi limpa.",
        "Se não precisa mais seedar essa versão antiga, remova o torrent do qBittorrent com a opção de "
        "apagar os arquivos - o espaço é recuperado na hora. Se quiser manter seedando (ratio de tracker "
        "privado, por exemplo), não precisa fazer nada, é esperado ficar sem link mesmo.",
    ),
    REASON_SIDECAR_ONLY: (
        "O arquivo principal de vídeo está linkado corretamente - a diferença é só de arquivos auxiliares "
        "(legenda, nfo, etc) que não foram linkados junto.",
        "Geralmente não vale a pena mexer, é pouca coisa (poucos KB/MB por item).",
    ),
    REASON_UNKNOWN: (
        "Esse arquivo específico não bate com nenhum import marcado como cópia ou obsoleto no histórico - "
        "pode ser um item de um pacote com vários arquivos onde só esse perdeu o link depois do import "
        "(ex: um episódio apagado/movido na library fora do *arr), ou algo sem registro no histórico.",
        "Compare manualmente o arquivo na pasta de download com o correspondente na library (mesmo nome/"
        "tamanho). Se o conteúdo bater e não estiver linkado, apague uma das cópias e recrie o hardlink, "
        "ou force o *arr a re-importar.",
    ),
}

REASON_LABEL = {
    REASON_COPIED: "Cópia real",
    REASON_ORPHANED_UPGRADE: "Órfão pós-upgrade",
    REASON_SIDECAR_ONLY: "Só arquivo auxiliar",
    REASON_UNKNOWN: "Causa desconhecida",
}

# Reasons safe to offer one-click deletion for: in all three, a working
# copy either still exists elsewhere (COPIED, SIDECAR_ONLY's video file is
# hardlinked) or is expected to no longer matter (ORPHANED_UPGRADE - *arr
# itself already deleted the library side on purpose). REASON_UNKNOWN is
# deliberately excluded - that's exactly the "not sure a backup exists,
# check by hand" case.
DELETABLE_REASONS = {REASON_COPIED, REASON_ORPHANED_UPGRADE, REASON_SIDECAR_ONLY}


def is_download_id_deletable(result, download_id):
    """A whole torrent is only offered for one-click delete if EVERY
    unlinked file found in it has a safe reason - qBittorrent's delete API
    removes the whole torrent's files at once, so a single unknown-reason
    file anywhere in it blocks deletion of the lot, even for its own
    safe-reason siblings."""
    reasons = {u.reason for u in result.unlinked_downloads if u.download_id == download_id}
    if not reasons:
        return False
    return reasons <= DELETABLE_REASONS


@dataclass
class UnlinkedDownload:
    """A completed, *arr-categorized torrent whose data (per a direct
    filesystem check) isn't hardlinked to anything else - found by walking
    the download folder directly, independent of *arr's history log."""
    name: str
    category: str
    download_id: str
    unlinked_bytes: int
    total_bytes: int
    reason: str = REASON_UNKNOWN
    paths: list = field(default_factory=list)


@dataclass
class AuditResult:
    import_findings: list = field(default_factory=list)
    orphan_torrents: list = field(default_factory=list)
    unlinked_downloads: list = field(default_factory=list)
    errors: list = field(default_factory=list)  # (context, message) pairs - non-fatal problems to surface

    def to_dict(self):
        return {
            "import_findings": [asdict(f) for f in self.import_findings],
            "orphan_torrents": [asdict(t) for t in self.orphan_torrents],
            "unlinked_downloads": [asdict(u) for u in self.unlinked_downloads],
            "errors": [list(e) for e in self.errors],
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            import_findings=[ImportFinding(**f) for f in data.get("import_findings", [])],
            orphan_torrents=[OrphanTorrent(**t) for t in data.get("orphan_torrents", [])],
            unlinked_downloads=[UnlinkedDownload(**u) for u in data.get("unlinked_downloads", [])],
            errors=[tuple(e) for e in data.get("errors", [])],
        )

    def wasted_bytes(self):
        """Total confirmed-wasted bytes from BOTH detection paths: the
        direct filesystem scan (unlinked_downloads) and the history-based
        per-import check (status == "copied"). Dedupe by download_id so a
        case both paths independently catch isn't counted twice."""
        swept_ids = {u.download_id for u in self.unlinked_downloads if u.download_id}
        from_scan = sum(u.unlinked_bytes for u in self.unlinked_downloads)
        from_history = sum(
            f.size for f in self.import_findings
            if f.status == "copied" and f.download_id not in swept_ids
        )
        return from_scan + from_history


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
    # Host-side paths (no /hostroot prefix) - what the user can actually go
    # look at on the real machine, as opposed to dropped_local/imported_local
    # which only make sense from inside this tool's own container.
    dropped_host = resolver.to_host_path(event["dropped_path"])
    imported_host = resolver.to_host_path(event["imported_path"])

    base_kwargs = dict(
        service=service_name,
        source_title=event["source_title"],
        date=event["date"],
        dropped_path=event["dropped_path"],
        imported_path=event["imported_path"],
        size=event["size"],
        download_id=event.get("download_id"),
        dropped_host_path=dropped_host,
        imported_host_path=imported_host,
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
            detail=f"arquivo não existe mais na library: {imported_host}",
        )
    if dropped_stat is None:
        return ImportFinding(
            **base_kwargs, status="missing_dropped",
            detail=f"arquivo não existe mais no download: {dropped_host} "
                    "(torrent removido/movido/deletado fora do *arr)",
        )
    if dropped_stat.st_dev != imported_stat.st_dev:
        return ImportFinding(
            **base_kwargs, status="cross_filesystem",
            detail=f"download ({dropped_host}) e library ({imported_host}) estão em "
                    f"filesystems diferentes (dev {dropped_stat.st_dev} vs {imported_stat.st_dev}) - "
                    "hardlink é estruturalmente impossível aqui",
        )
    if dropped_stat.st_ino != imported_stat.st_ino:
        return ImportFinding(
            **base_kwargs, status="copied",
            detail=f"cópia em {dropped_host} e em {imported_host} (mesmo filesystem, inode "
                    f"diferente - virou cópia, não hardlink; desperdiçando ~{event['size']} bytes)",
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


def find_orphan_torrents(torrents, known_download_ids, result):
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


def reclassify_relocated_downloads(result, resolvers_by_service, torrents, qbit_resolver):
    """Radarr/Sonarr history is an immutable log: it records where a file
    was dropped *at import time*, not where it lives now. If the download
    folder gets reorganized afterwards (files moved, not copied - the
    hardlink survives), a stale history path alone would misreport a fine,
    still-linked file as missing. Before finalizing "missing_dropped", check
    qBittorrent's own CURRENT record for that download (matched by hash) -
    it's a live pointer, not a log entry."""
    if not torrents or not qbit_resolver:
        return
    by_hash = {(t.get("hash") or "").upper(): t for t in torrents if t.get("hash")}

    for f in result.import_findings:
        if f.status != "missing_dropped" or not f.download_id:
            continue
        torrent = by_hash.get(f.download_id)
        if torrent is None:
            continue
        resolver = resolvers_by_service.get(f.service)
        if resolver is None:
            continue
        imported_local = resolver.to_local_path(f.imported_path)
        imported_stat = _stat(imported_local) if imported_local else None
        if imported_stat is None:
            continue

        basename = os.path.basename(f.dropped_path)
        content_path = torrent.get("content_path") or ""
        for candidate in (content_path, os.path.join(content_path, basename)):
            current_local = qbit_resolver.to_local_path(candidate)
            current_stat = _stat(current_local) if current_local else None
            if current_stat and current_stat.st_dev == imported_stat.st_dev and current_stat.st_ino == imported_stat.st_ino:
                f.status = "ok"
                f.detail = (
                    f"pasta de download foi reorganizada desde o import (agora em "
                    f"{qbit_resolver.to_host_path(candidate)}), hardlink confirmado no local atual"
                )
                break


def _iter_files(path):
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for name in files:
                yield os.path.join(root, name)
    elif os.path.isfile(path):
        yield path


def scan_download_folder_links(torrents, qbit_resolver, result, known_download_ids):
    """Ground-truth pass: for every completed torrent that *arr's history
    confirms was actually imported at some point, walk its files on disk and
    check nlink directly. nlink<2 means that file's bytes aren't shared with
    the library copy - real wasted space - regardless of whether the
    history-based per-import check still has a live record of it (history
    entries can get pruned over time).

    Scoped by known_download_ids alone (no category filter): category names
    are user-customizable per *arr instance (Sonarr's own suggested default
    is "tv-sonarr", not "sonarr") and a hardcoded guess here previously made
    this pass blind to an entire instance's torrents whenever the category
    didn't match. known_download_ids is already the authoritative "*arr
    actually imported this" signal - a category check on top added nothing
    but a way to be wrong.

    Deliberately excludes torrents *arr never imported (no history record at
    all) - those aren't "wasted", they're either not-yet-imported or
    abandoned downloads with no library counterpart to have linked to; they
    already surface via find_orphan_torrents() instead.

    Also skips any content_path shared by more than one torrent (possible
    with a "no subfolder" save layout, where several torrents' files sit
    directly in the same category folder) - walking it per-torrent would
    misattribute every torrent sharing that path with each other's bytes.

    Reason is determined PER FILE, not per torrent: a season-pack torrent
    can have some episodes correctly linked and others not, all under one
    download_id - aggregating by torrent-wide status previously produced a
    wrong "just a sidecar file" verdict on a real 3.8GB duplicate (two
    unlinked episodes in an otherwise-fine 4-episode pack). A file's own
    extension (not an inferred torrent-wide status) decides "sidecar" now."""
    if not torrents or not qbit_resolver:
        return
    shared_paths = Counter(t.get("content_path") for t in torrents if t.get("content_path"))
    status_by_key = {}
    for f in result.import_findings:
        if f.download_id:
            status_by_key[(f.download_id, os.path.basename(f.dropped_path))] = f.status

    def _reason_for(download_id, basename):
        ext = os.path.splitext(basename)[1].lower()
        if ext in _SIDECAR_EXTENSIONS:
            return REASON_SIDECAR_ONLY
        status = status_by_key.get((download_id, basename))
        if status == "copied":
            return REASON_COPIED
        if status == "superseded":
            return REASON_ORPHANED_UPGRADE
        return REASON_UNKNOWN

    for t in torrents:
        if t.get("progress", 0) < 1:
            continue
        download_id = (t.get("hash") or "").upper()
        if download_id not in known_download_ids:
            continue
        content_path = t.get("content_path") or ""
        if shared_paths.get(content_path, 0) > 1:
            continue
        local = qbit_resolver.to_local_path(content_path)
        host_content_root = qbit_resolver.to_host_path(content_path)
        if not local:
            continue

        total_bytes = 0
        unlinked_by_reason = defaultdict(int)
        paths_by_reason = defaultdict(list)
        for fpath in _iter_files(local):
            st = _stat(fpath)
            if st is None:
                continue
            total_bytes += st.st_size
            if st.st_nlink < 2:
                reason = _reason_for(download_id, os.path.basename(fpath))
                unlinked_by_reason[reason] += st.st_size
                if host_content_root:
                    rel = os.path.relpath(fpath, local)
                    paths_by_reason[reason].append(os.path.normpath(os.path.join(host_content_root, rel)))

        for reason, unlinked_bytes in unlinked_by_reason.items():
            if unlinked_bytes > 0:
                result.unlinked_downloads.append(
                    UnlinkedDownload(
                        name=t.get("name", "?"),
                        category=t.get("category", "?"),
                        download_id=download_id,
                        unlinked_bytes=unlinked_bytes,
                        total_bytes=total_bytes,
                        reason=reason,
                        paths=paths_by_reason.get(reason, [])[:10],
                    )
                )
