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

    if result.unlinked_downloads:
        wasted = result.wasted_bytes()
        lines.append(
            f"ESPAÇO DESPERDIÇADO (varredura direta): ~{human_size(wasted)} em "
            f"{len(result.unlinked_downloads)} download(s) não linkados"
        )
        for u in sorted(result.unlinked_downloads, key=lambda u: -u.unlinked_bytes)[:20]:
            lines.append(f"  [{u.category}] {u.name}: ~{human_size(u.unlinked_bytes)} sem link")
        if len(result.unlinked_downloads) > 20:
            lines.append(f"  ... e mais {len(result.unlinked_downloads) - 20}")
        lines.append("")

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

    if not any([structural, copied, missing, unresolved, result.unlinked_downloads, result.errors]):
        lines.append("Tudo linkado corretamente. Nada a reportar.")

    return "\n".join(lines)


_STATUS_LABEL = {
    "ok": ("OK", "ok"),
    "copied": ("Copiado", "bad"),
    "cross_filesystem": ("Filesystems diferentes", "bad"),
    "missing_dropped": ("Torrent sumiu", "warn"),
    "missing_imported": ("Arquivo sumiu", "bad"),
    "unresolved": ("Path não resolvido", "warn"),
    "superseded": ("Obsoleto", "muted"),
}

ATTENTION_STATUSES = ("copied", "cross_filesystem", "missing_dropped", "missing_imported", "unresolved")


def _esc(value):
    return html.escape(str(value if value is not None else ""))


def _finding_rows(findings, with_detail=True):
    rows = []
    for f in findings:
        label, cls = _STATUS_LABEL.get(f.status, (f.status, "warn"))
        detail_cell = f"<td class='detail'>{_esc(f.detail)}</td>" if with_detail else ""
        rows.append(
            f"<tr><td><span class='badge {cls}'>{_esc(label)}</span></td>"
            f"<td>{_esc(f.service)}</td>"
            f"<td>{_esc(f.source_title)}</td>"
            f"<td class='num'>{human_size(f.size)}</td>"
            f"{detail_cell}</tr>"
        )
    return "\n".join(rows)


def _compact_table(findings, extra_head="", with_detail=True):
    if not findings:
        return "<p class='muted'>Nenhum.</p>"
    head_detail = "<th>Detalhe</th>" if with_detail else ""
    return (
        f"<table><thead><tr><th>Status</th><th>Serviço</th><th>Título</th>"
        f"<th>Tamanho</th>{head_detail}</tr></thead><tbody>"
        + _finding_rows(findings, with_detail) +
        "</tbody></table>"
    )


def _unlinked_rows(items):
    rows = []
    for u in items:
        rows.append(
            f"<tr><td>{_esc(u.name)}</td><td>{_esc(u.category)}</td>"
            f"<td class='num bad-num'>{human_size(u.unlinked_bytes)}</td>"
            f"<td class='num'>{human_size(u.total_bytes)}</td></tr>"
        )
    return "\n".join(rows)


def render_html(result, log_lines, last_run_iso, next_run_iso=None):
    counts = Counter(f.status for f in result.import_findings)
    total = len(result.import_findings)

    attention = sorted(
        (f for f in result.import_findings if f.status in ATTENTION_STATUSES),
        key=lambda f: f.date or "",
        reverse=True,
    )
    ok_findings = [f for f in result.import_findings if f.status == "ok"]
    superseded_findings = [f for f in result.import_findings if f.status == "superseded"]
    wasted_bytes = result.wasted_bytes()

    problem_count = len(attention) + len(result.unlinked_downloads)
    banner = (
        "<div class='banner ok'>Tudo linkado corretamente. Nenhum espaço desperdiçado encontrado.</div>"
        if not problem_count and not result.errors
        else f"<div class='banner bad'>{problem_count} problema(s) encontrado(s)"
             f"{f' · ~{human_size(wasted_bytes)} desperdiçados' if wasted_bytes else ''}.</div>"
    )

    cards = "".join(
        f"<div class='card'><div class='n'>{counts.get(s, 0)}</div><div class='l'>{label}</div></div>"
        for s, (label, _cls) in _STATUS_LABEL.items()
        if counts.get(s)
    )

    wasted_html = ""
    if result.unlinked_downloads:
        wasted_html = f"""
        <div class="wasted-hero">
          <div class="wasted-n">{human_size(wasted_bytes)}</div>
          <div class="wasted-l">desperdiçados em {len(result.unlinked_downloads)} download(s) não linkados
          (varredura direta do filesystem, não depende do histórico do *arr)</div>
        </div>
        <table><thead><tr><th>Nome</th><th>Categoria</th><th>Sem link</th><th>Tamanho total</th></tr></thead>
        <tbody>{_unlinked_rows(sorted(result.unlinked_downloads, key=lambda u: -u.unlinked_bytes))}</tbody></table>
        """

    attention_html = (
        _compact_table(attention)
        if attention else "<p class='muted'>Nada precisando de atenção.</p>"
    )

    orphans_html = ""
    if result.orphan_torrents:
        wasted = sum(t.size for t in result.orphan_torrents)
        rows = "".join(
            f"<tr><td>{_esc(t.name)}</td><td>{_esc(t.state)}</td><td class='num'>{human_size(t.size)}</td></tr>"
            for t in result.orphan_torrents
        )
        orphans_html = f"""
        <details>
        <summary>Torrents sem import correspondente ({len(result.orphan_torrents)}, ~{human_size(wasted)})</summary>
        <table><thead><tr><th>Nome</th><th>Estado</th><th>Tamanho</th></tr></thead>
        <tbody>{rows}</tbody></table>
        </details>
        """

    errors_html = ""
    if result.errors:
        rows = "".join(f"<li><b>{_esc(ctx)}</b>: {_esc(msg)}</li>" for ctx, msg in result.errors)
        errors_html = f"<h2>Avisos</h2><ul class='errors'>{rows}</ul>"

    ok_html = f"""
    <details>
    <summary>{len(ok_findings)} linkados corretamente</summary>
    {_compact_table(ok_findings, with_detail=False)}
    </details>
    """ if ok_findings else ""

    superseded_html = f"""
    <details>
    <summary>{len(superseded_findings)} obsoletos (substituídos por upgrade de qualidade)</summary>
    {_compact_table(superseded_findings, with_detail=False)}
    </details>
    """ if superseded_findings else ""

    log_html = "<br>".join(_esc(line) for line in log_lines)

    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>hardlink-audit</title>
<style>
:root {{ color-scheme: light dark; }}
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 0; padding: 2rem;
        background: #0f1115; color: #e6e6e6; max-width: 1100px; }}
@media (prefers-color-scheme: light) {{ body {{ background: #f7f7f8; color: #1a1a1a; }} }}
h1 {{ font-size: 1.4rem; margin: 0 0 .2rem; }}
h2 {{ font-size: 1rem; margin: 1.8rem 0 .6rem; color: #aaa; text-transform: uppercase; letter-spacing: .04em; }}
.meta {{ color: #888; font-size: .85rem; margin-bottom: 1.5rem; display: flex; align-items: center; gap: .8rem; flex-wrap: wrap; }}
.banner {{ padding: .8rem 1rem; border-radius: 8px; font-weight: 600; margin-bottom: 1.5rem; }}
.banner.ok {{ background: #1e3a2a; color: #7ee2a8; }}
.banner.bad {{ background: #3a1e1e; color: #ff8a8a; }}
.cards {{ display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: .5rem; }}
.card {{ background: rgba(127,127,127,.1); border: 1px solid rgba(127,127,127,.18);
         border-radius: 10px; padding: .7rem 1.1rem; min-width: 100px; }}
.card .n {{ font-size: 1.4rem; font-weight: 700; line-height: 1.1; }}
.card .l {{ font-size: .72rem; color: #999; margin-top: .15rem; }}
table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
th {{ text-align: left; padding: .5rem .6rem; font-size: .72rem; text-transform: uppercase;
      letter-spacing: .03em; color: #888; border-bottom: 1px solid rgba(127,127,127,.25); }}
td {{ text-align: left; padding: .55rem .6rem; border-bottom: 1px solid rgba(127,127,127,.12);
      vertical-align: top; }}
td.num {{ white-space: nowrap; color: #aaa; }}
td.bad-num {{ color: #ff8a8a; font-weight: 600; }}
.wasted-hero {{ background: rgba(255,138,138,.08); border: 1px solid rgba(255,138,138,.25);
                border-radius: 10px; padding: 1rem 1.2rem; margin-bottom: .8rem; }}
.wasted-hero .wasted-n {{ font-size: 2rem; font-weight: 800; color: #ff8a8a; line-height: 1.1; }}
.wasted-hero .wasted-l {{ font-size: .8rem; color: #999; margin-top: .3rem; }}
td.detail {{ color: #999; font-size: .8rem; }}
tr:last-child td {{ border-bottom: none; }}
.badge {{ display: inline-block; white-space: nowrap; padding: .2rem .6rem; border-radius: 999px;
          font-size: .72rem; font-weight: 600; }}
.badge.ok {{ background: #1e3a2a; color: #7ee2a8; }}
.badge.bad {{ background: #3a1e1e; color: #ff8a8a; }}
.badge.warn {{ background: #3a331e; color: #f0c674; }}
.badge.muted {{ background: rgba(127,127,127,.15); color: #999; }}
.muted {{ color: #888; }}
form {{ display: inline; }}
button {{ background: #3d6bde; color: white; border: none; padding: .5rem 1.1rem;
          border-radius: 6px; font-size: .85rem; cursor: pointer; }}
button:hover {{ background: #4d7bee; }}
.errors li {{ margin-bottom: .3rem; }}
details {{ margin-top: .8rem; }}
details > summary {{ cursor: pointer; color: #999; font-size: .85rem; padding: .4rem 0; user-select: none; }}
details > summary:hover {{ color: #ccc; }}
details table {{ margin-top: .5rem; }}
details.log {{ margin-top: 2.5rem; color: #777; font-size: .8rem; border-top: 1px solid rgba(127,127,127,.15); padding-top: .5rem; }}
</style></head>
<body>
<h1>hardlink-audit</h1>
<div class="meta">
  <span>última rodada: {_esc(last_run_iso) or 'nunca'}</span>
  {f'<span>· próxima automática: {_esc(next_run_iso)}</span>' if next_run_iso else ''}
  <form method="post" action="/run"><button type="submit">Rodar agora</button></form>
</div>
{banner}
<div class="cards">{cards}</div>
{errors_html}
{f'<h2>Espaço desperdiçado</h2>{wasted_html}' if wasted_html else ''}
<h2>Precisa de atenção ({len(attention)})</h2>
{attention_html}
{orphans_html}
{ok_html}
{superseded_html}
<details class="log"><summary>log de descoberta</summary><p>{log_html}</p></details>
</body></html>"""
