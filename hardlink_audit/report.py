import html
from collections import Counter, defaultdict
from datetime import datetime

from .audit import REASON_COPIED, REASON_LABEL, REASON_TEXT, is_download_id_deletable


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f}{unit}"
        n /= 1024


def format_ts(iso_str):
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str)
    except ValueError:
        return iso_str
    return dt.strftime("%d/%m/%Y %H:%M UTC")


def render_text(result):
    lines = []
    counts = Counter(f.status for f in result.import_findings)
    total = len(result.import_findings)

    wasted = result.wasted_bytes()
    if wasted:
        swept_ids = {u.download_id for u in result.unlinked_downloads if u.download_id}
        copied_only = [
            f for f in result.import_findings
            if f.status == "copied" and f.download_id not in swept_ids
        ]
        lines.append(
            f"ESPAÇO DESPERDIÇADO: ~{human_size(wasted)} em "
            f"{len(result.unlinked_downloads) + len(copied_only)} download(s) não linkados"
        )
        for u in sorted(result.unlinked_downloads, key=lambda u: -u.unlinked_bytes)[:20]:
            why, action = REASON_TEXT.get(u.reason, ("", ""))
            lines.append(f"  [{u.category}] {u.name}: ~{human_size(u.unlinked_bytes)} sem link (varredura)")
            lines.append(f"    motivo: {why}")
            lines.append(f"    ação: {action}")
            for p in u.paths:
                lines.append(f"    path: {p}")
        for f in copied_only[:20]:
            why, action = REASON_TEXT[REASON_COPIED]
            lines.append(f"  [{f.service}] {f.source_title}: ~{human_size(f.size)} sem link (histórico)")
            lines.append(f"    motivo: {why}")
            lines.append(f"    ação: {action}")
            for p in (f.dropped_host_path, f.imported_host_path):
                if p:
                    lines.append(f"    path: {p}")
        extra = (len(result.unlinked_downloads) - 20 if len(result.unlinked_downloads) > 20 else 0) + \
                (len(copied_only) - 20 if len(copied_only) > 20 else 0)
        if extra > 0:
            lines.append(f"  ... e mais {extra}")
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

    if result.missing_seeds:
        lines.append(
            f"SEM SEED ({len(result.missing_seeds)}) - arquivo ativo na library, torrent não existe "
            "mais no qBittorrent (só é problema se sua política for seed enquanto quiser o arquivo):"
        )
        for m in sorted(result.missing_seeds, key=lambda m: -m.size)[:20]:
            lines.append(f"  [{m.service}] {m.title} ({human_size(m.size)}): {m.path}")
        if len(result.missing_seeds) > 20:
            lines.append(f"  ... e mais {len(result.missing_seeds) - 20}")
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

    if not any([structural, copied, missing, unresolved, result.unlinked_downloads, result.missing_seeds, result.errors]):
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


def _waste_card(name, subtitle, size_bytes, reason_key, download_id=None, deletable=False, paths=None):
    label = REASON_LABEL.get(reason_key, reason_key)
    why, action = REASON_TEXT.get(reason_key, ("", ""))
    delete_html = ""
    if deletable and download_id:
        confirm_msg = (
            f"Apagar {name} do qBittorrent e os arquivos dele do disco? "
            "Isso NÃO afeta a cópia na library."
        ).replace("'", "\\'")
        delete_html = f"""
        <form method="post" action="/delete/{_esc(download_id)}" class="delete-form"
              onsubmit="return confirm('{_esc(confirm_msg)}');">
          <button type="submit" class="delete-btn">Apagar torrent e arquivos</button>
        </form>
        """
    paths_html = ""
    if paths:
        items = "".join(f"<li>{_esc(p)}</li>" for p in paths)
        paths_html = f"<ul class='waste-paths'>{items}</ul>"
    return f"""
    <div class="waste-item">
      <div class="waste-head">
        <span class="badge {'bad' if reason_key == REASON_COPIED else 'warn'}">{_esc(label)}</span>
        <b>{_esc(name)}</b>
        <span class="waste-sub">{_esc(subtitle)}</span>
        <span class="num bad-num waste-size">{human_size(size_bytes)}</span>
      </div>
      <p class="waste-why">{_esc(why)}</p>
      <p class="waste-action"><b>O que fazer:</b> {_esc(action)}</p>
      {paths_html}
      {delete_html}
    </div>
    """


def render_html(result, log_lines, last_run_iso, next_run_iso=None, running=False):
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

    problem_count = len(attention) + len(result.unlinked_downloads) + len(result.missing_seeds)
    if running:
        banner = "<div class='banner running'><span class='spinner'></span> Rodando agora...</div>"
    elif not problem_count and not result.errors:
        banner = "<div class='banner ok'>Tudo linkado corretamente. Nenhum espaço desperdiçado encontrado.</div>"
    else:
        banner = (
            f"<div class='banner bad'>{problem_count} problema(s) encontrado(s)"
            f"{f' · ~{human_size(wasted_bytes)} desperdiçados' if wasted_bytes else ''}.</div>"
        )

    cards = "".join(
        f"<div class='card'><div class='n'>{counts.get(s, 0)}</div><div class='l'>{label}</div></div>"
        for s, (label, _cls) in _STATUS_LABEL.items()
        if counts.get(s)
    )

    swept_ids = {u.download_id for u in result.unlinked_downloads if u.download_id}
    copied_only = [
        f for f in result.import_findings
        if f.status == "copied" and f.download_id not in swept_ids
    ]

    wasted_html = ""
    if wasted_bytes:
        source_count = len(result.unlinked_downloads) + len(copied_only)
        swept_cards = "".join(
            _waste_card(
                u.name, u.category, u.unlinked_bytes, u.reason,
                download_id=u.download_id,
                deletable=is_download_id_deletable(result, u.download_id),
                paths=u.paths,
            )
            for u in sorted(result.unlinked_downloads, key=lambda u: -u.unlinked_bytes)
        )
        copied_cards = "".join(
            _waste_card(
                f.source_title, f.service, f.size, REASON_COPIED,
                paths=[p for p in (f.dropped_host_path, f.imported_host_path) if p],
            )
            for f in sorted(copied_only, key=lambda f: -f.size)
        )
        wasted_html = f"""
        <div class="wasted-hero">
          <div class="wasted-n">{human_size(wasted_bytes)}</div>
          <div class="wasted-l">desperdiçados em {source_count} download(s) não linkados</div>
        </div>
        {swept_cards}{copied_cards}
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

    missing_seeds_html = ""
    if result.missing_seeds:
        rows = "".join(
            f"<tr><td>{_esc(m.title)}</td><td>{_esc(m.service)}</td>"
            f"<td class='num'>{human_size(m.size)}</td>"
            f"<td class='detail'>{_esc(m.path)}</td></tr>"
            for m in sorted(result.missing_seeds, key=lambda m: -m.size)
        )
        missing_seeds_html = f"""
        <h2>Sem seed ({len(result.missing_seeds)})</h2>
        <p class='muted'>Arquivo ativo na library, mas o torrent de origem não existe mais no qBittorrent -
        só é um problema se sua política for manter o torrent seedando enquanto quiser o arquivo.</p>
        <table><thead><tr><th>Título</th><th>Serviço</th><th>Tamanho</th><th>Path na library</th></tr></thead>
        <tbody>{rows}</tbody></table>
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
<script>
(function() {{
  var saved = localStorage.getItem('theme');
  if (saved) document.documentElement.setAttribute('data-theme', saved);
}})();
</script>
<style>
:root {{ color-scheme: light dark; }}
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 0; padding: 2rem;
        background: #0f1115; color: #e6e6e6; max-width: 1100px; }}
@media (prefers-color-scheme: light) {{
  :root:not([data-theme]) body {{ background: #f7f7f8; color: #1a1a1a; }}
}}
:root[data-theme="light"] body {{ background: #f7f7f8; color: #1a1a1a; }}
:root[data-theme="dark"] body {{ background: #0f1115; color: #e6e6e6; }}
#theme-btn {{ background: transparent; border: 1px solid rgba(127,127,127,.3); color: inherit;
              padding: .4rem .7rem; }}
#theme-btn:hover {{ background: rgba(127,127,127,.15); }}
h1 {{ font-size: 1.4rem; margin: 0 0 .2rem; }}
h2 {{ font-size: 1rem; margin: 1.8rem 0 .6rem; color: #aaa; text-transform: uppercase; letter-spacing: .04em; }}
.meta {{ color: #888; font-size: .85rem; margin-bottom: 1.5rem; display: flex; align-items: center; gap: .8rem; flex-wrap: wrap; }}
.banner {{ padding: .8rem 1rem; border-radius: 8px; font-weight: 600; margin-bottom: 1.5rem;
           display: flex; align-items: center; gap: .6rem; }}
.banner.ok {{ background: #1e3a2a; color: #7ee2a8; }}
.banner.bad {{ background: #3a1e1e; color: #ff8a8a; }}
.banner.running {{ background: #1e2a3a; color: #7eb8f0; }}
.spinner {{ width: 14px; height: 14px; border-radius: 50%; border: 2px solid rgba(126,184,240,.3);
            border-top-color: #7eb8f0; animation: spin .7s linear infinite; flex: none; }}
@keyframes spin {{ to {{ transform: rotate(360deg); }} }}
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
.waste-item {{ background: rgba(127,127,127,.06); border: 1px solid rgba(127,127,127,.15);
               border-radius: 10px; padding: 1.1rem 1.3rem; margin-bottom: 1rem; }}
.waste-head {{ display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; margin-bottom: .7rem; }}
.waste-sub {{ color: #888; font-size: .78rem; }}
.waste-size {{ margin-left: auto; font-size: 1rem; }}
.waste-why {{ margin: 0 0 .6rem; font-size: .85rem; line-height: 1.5; }}
.waste-action {{ margin: 0; color: #999; font-size: .82rem; line-height: 1.5; }}
.waste-paths {{ list-style: none; margin: .7rem 0 0; padding: 0; }}
.waste-paths li {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                    font-size: .74rem; color: #888; background: rgba(127,127,127,.08);
                    border-radius: 4px; padding: .3rem .5rem; margin-top: .3rem;
                    word-break: break-all; }}
.delete-form {{ display: block; margin-top: 1rem; }}
.delete-btn {{ background: #7a2020; font-size: .78rem; padding: .45rem .9rem; }}
.delete-btn:hover {{ background: #9a2828; }}
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
  <span>última rodada: {_esc(format_ts(last_run_iso)) or 'nunca'}</span>
  {f'<span>· próxima automática: {_esc(format_ts(next_run_iso))}</span>' if next_run_iso else ''}
  <form method="post" action="/run" id="run-form">
    <button type="submit" id="run-btn" {"disabled" if running else ""}>{"Rodando..." if running else "Rodar agora"}</button>
  </form>
  <button type="button" id="theme-btn">Tema</button>
</div>
{banner}
<div class="cards">{cards}</div>
{errors_html}
{f'<h2>Espaço desperdiçado</h2>{wasted_html}' if wasted_html else ''}
<h2>Precisa de atenção ({len(attention)})</h2>
{attention_html}
{missing_seeds_html}
{orphans_html}
{ok_html}
{superseded_html}
<details class="log"><summary>log de descoberta</summary><p>{log_html}</p></details>
<script>
document.getElementById('run-form').addEventListener('submit', function() {{
  var btn = document.getElementById('run-btn');
  btn.disabled = true;
  btn.textContent = 'Rodando...';
}});

(function() {{
  var prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
  var themeBtn = document.getElementById('theme-btn');
  function currentTheme() {{
    return document.documentElement.getAttribute('data-theme') || (prefersLight ? 'light' : 'dark');
  }}
  function updateLabel() {{
    themeBtn.textContent = currentTheme() === 'light' ? 'Modo escuro' : 'Modo claro';
  }}
  themeBtn.addEventListener('click', function() {{
    var next = currentTheme() === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateLabel();
  }});
  updateLabel();
}})();
{"""
(function poll() {
  fetch('/api/last-result').then(r => r.json()).then(d => {
    if (d.running) { setTimeout(poll, 2000); } else { location.reload(); }
  }).catch(() => setTimeout(poll, 3000));
})();
""" if running else ""}
</script>
</body></html>"""
