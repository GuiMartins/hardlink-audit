import html
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


_STATUS_LABEL = {
    "ok": ("OK", "ok"),
    "copied": ("Copiado (desperdiçando espaço)", "bad"),
    "cross_filesystem": ("Filesystems diferentes", "bad"),
    "missing_dropped": ("Torrent sumiu", "warn"),
    "missing_imported": ("Arquivo sumiu da library", "bad"),
    "unresolved": ("Path não resolvido", "warn"),
    "superseded": ("Obsoleto (upgrade posterior)", "muted"),
}


def _esc(value):
    return html.escape(str(value if value is not None else ""))


def _finding_rows(findings):
    rows = []
    for f in findings:
        label, cls = _STATUS_LABEL.get(f.status, (f.status, "warn"))
        rows.append(
            f"<tr><td><span class='badge {cls}'>{_esc(label)}</span></td>"
            f"<td>{_esc(f.service)}</td>"
            f"<td>{_esc(f.source_title)}</td>"
            f"<td>{human_size(f.size)}</td>"
            f"<td class='detail'>{_esc(f.detail)}</td></tr>"
        )
    return "\n".join(rows)


def render_html(result, log_lines, last_run_iso, next_run_iso=None):
    counts = Counter(f.status for f in result.import_findings)
    total = len(result.import_findings)
    bad = [f for f in result.import_findings if f.status in
           ("copied", "cross_filesystem", "missing_dropped", "missing_imported", "unresolved")]
    ok_count = counts.get("ok", 0)

    banner = (
        "<div class='banner ok'>Tudo linkado corretamente.</div>"
        if not bad and not result.errors
        else f"<div class='banner bad'>{len(bad)} problema(s) encontrado(s).</div>"
    )

    cards = "".join(
        f"<div class='card'><div class='n'>{counts.get(s, 0)}</div><div class='l'>{label}</div></div>"
        for s, (label, _cls) in _STATUS_LABEL.items()
        if counts.get(s)
    )

    findings_sorted = sorted(
        result.import_findings,
        key=lambda f: (f.status == "ok", f.status == "superseded", f.date or ""),
    )
    findings_table = (
        "<table><thead><tr><th>Status</th><th>Serviço</th><th>Título</th>"
        "<th>Tamanho</th><th>Detalhe</th></tr></thead><tbody>"
        + _finding_rows(findings_sorted) +
        "</tbody></table>"
        if findings_sorted else "<p class='muted'>Nenhum import auditado ainda.</p>"
    )

    orphans_html = ""
    if result.orphan_torrents:
        wasted = sum(t.size for t in result.orphan_torrents)
        rows = "".join(
            f"<tr><td>{_esc(t.name)}</td><td>{_esc(t.state)}</td><td>{human_size(t.size)}</td></tr>"
            for t in result.orphan_torrents
        )
        orphans_html = f"""
        <h2>Torrents sem import correspondente ({len(result.orphan_torrents)}, ~{human_size(wasted)})</h2>
        <table><thead><tr><th>Nome</th><th>Estado</th><th>Tamanho</th></tr></thead>
        <tbody>{rows}</tbody></table>
        """

    errors_html = ""
    if result.errors:
        rows = "".join(f"<li><b>{_esc(ctx)}</b>: {_esc(msg)}</li>" for ctx, msg in result.errors)
        errors_html = f"<h2>Avisos</h2><ul class='errors'>{rows}</ul>"

    log_html = "<br>".join(_esc(line) for line in log_lines)

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>hardlink-audit</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 0; padding: 2rem;
        background: #0f1115; color: #e6e6e6; }}
@media (prefers-color-scheme: light) {{ body {{ background: #f7f7f8; color: #1a1a1a; }} }}
h1 {{ font-size: 1.4rem; margin-bottom: .2rem; }}
.meta {{ color: #888; font-size: .85rem; margin-bottom: 1.5rem; }}
.banner {{ padding: .8rem 1rem; border-radius: 8px; font-weight: 600; margin-bottom: 1.5rem; }}
.banner.ok {{ background: #1e3a2a; color: #7ee2a8; }}
.banner.bad {{ background: #3a1e1e; color: #ff8a8a; }}
.cards {{ display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: 1.5rem; }}
.card {{ background: rgba(127,127,127,.12); border-radius: 8px; padding: .6rem 1rem; min-width: 90px; }}
.card .n {{ font-size: 1.3rem; font-weight: 700; }}
.card .l {{ font-size: .75rem; color: #999; }}
table {{ width: 100%; border-collapse: collapse; font-size: .85rem; margin-bottom: 1.5rem; }}
th, td {{ text-align: left; padding: .4rem .6rem; border-bottom: 1px solid rgba(127,127,127,.2); }}
td.detail {{ color: #999; }}
.badge {{ padding: .15rem .5rem; border-radius: 999px; font-size: .75rem; font-weight: 600; }}
.badge.ok {{ background: #1e3a2a; color: #7ee2a8; }}
.badge.bad {{ background: #3a1e1e; color: #ff8a8a; }}
.badge.warn {{ background: #3a331e; color: #f0c674; }}
.badge.muted {{ background: rgba(127,127,127,.15); color: #999; }}
.muted {{ color: #888; }}
form {{ display: inline; }}
button {{ background: #3d6bde; color: white; border: none; padding: .5rem 1.1rem;
          border-radius: 6px; font-size: .9rem; cursor: pointer; }}
button:hover {{ background: #4d7bee; }}
.errors li {{ margin-bottom: .3rem; }}
details {{ margin-top: 2rem; color: #888; font-size: .8rem; }}
</style></head>
<body>
<h1>hardlink-audit</h1>
<div class="meta">
  última rodada: {_esc(last_run_iso) or 'nunca'}
  {f' · próxima automática: {_esc(next_run_iso)}' if next_run_iso else ''}
  &nbsp;&nbsp;<form method="post" action="/run"><button type="submit">Rodar agora</button></form>
</div>
{banner}
<div class="cards">{cards}</div>
{errors_html}
<h2>Imports ({total}, {ok_count} ok)</h2>
{findings_table}
{orphans_html}
<details><summary>log de descoberta</summary><p>{log_html}</p></details>
</body></html>"""
