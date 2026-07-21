from collections import Counter, defaultdict


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f}{unit}"
        n /= 1024


def render_text(result):
    lines = []
    counts = Counter(f.status for f in result.import_findings)
    total = len(result.import_findings)

    lines.append(f"== {total} imports auditados ==")
    for status in ("ok", "copied", "cross_filesystem", "missing_dropped", "missing_imported", "unresolved", "superseded"):
        if counts.get(status):
            suffix = " (obsoleto, ignorado abaixo)" if status == "superseded" else ""
            lines.append(f"  {status}: {counts[status]}{suffix}")
    lines.append("")

    structural = defaultdict(list)
    for f in result.import_findings:
        if f.status == "cross_filesystem":
            structural[f.service].append(f)
    if structural:
        lines.append("!! PROBLEMA ESTRUTURAL - hardlink impossível (filesystems diferentes) !!")
        for service, findings in structural.items():
            wasted = sum(f.size for f in findings)
            lines.append(
                f"  {service}: {len(findings)} imports afetados, "
                f"~{human_size(wasted)} sendo copiados em vez de linkados"
            )
            lines.append(
                f"    fix: monte download-root e library-root do '{service}' "
                "no mesmo filesystem/disco (mesmo bind mount de origem)"
            )
        lines.append("")

    copied = [f for f in result.import_findings if f.status == "copied"]
    if copied:
        wasted = sum(f.size for f in copied)
        lines.append(f"COPIADO EM VEZ DE LINKADO ({len(copied)}, ~{human_size(wasted)} desperdiçados):")
        for f in copied[:20]:
            lines.append(f"  [{f.service}] {f.source_title}")
        if len(copied) > 20:
            lines.append(f"  ... e mais {len(copied) - 20}")
        lines.append("")

    missing = [f for f in result.import_findings if f.status in ("missing_dropped", "missing_imported")]
    if missing:
        lines.append(f"ARQUIVOS SUMIDOS ({len(missing)}):")
        for f in missing[:20]:
            lines.append(f"  [{f.service}] {f.source_title}: {f.detail}")
        if len(missing) > 20:
            lines.append(f"  ... e mais {len(missing) - 20}")
        lines.append("")

    unresolved = [f for f in result.import_findings if f.status == "unresolved"]
    if unresolved:
        lines.append(f"NÃO CONSEGUI RESOLVER O PATH ({len(unresolved)}) - mount desconhecido:")
        for f in unresolved[:10]:
            lines.append(f"  [{f.service}] {f.detail}")
        if len(unresolved) > 10:
            lines.append(f"  ... e mais {len(unresolved) - 10}")
        lines.append("")

    if result.orphan_torrents:
        wasted = sum(t.size for t in result.orphan_torrents)
        lines.append(
            f"TORRENTS SEM IMPORT CORRESPONDENTE NO HISTÓRICO ({len(result.orphan_torrents)}, "
            f"~{human_size(wasted)}) - pode ser download manual, ou histórico do *arr foi limpo:"
        )
        for t in result.orphan_torrents[:20]:
            lines.append(f"  [{t.state}] {t.name} ({human_size(t.size)})")
        if len(result.orphan_torrents) > 20:
            lines.append(f"  ... e mais {len(result.orphan_torrents) - 20}")
        lines.append("")

    if result.errors:
        lines.append("ERROS (não fatais) durante a auditoria:")
        for context, message in result.errors:
            lines.append(f"  [{context}] {message}")
        lines.append("")

    if not any([structural, copied, missing, unresolved, result.errors]):
        lines.append("Tudo linkado corretamente. Nada a reportar.")

    return "\n".join(lines)
