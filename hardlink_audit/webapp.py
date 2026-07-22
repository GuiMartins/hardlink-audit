import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse

from . import audit, report
from .cli import run_audit

DATA_DIR = os.environ.get("DATA_DIR", "/data")
STATE_FILE = os.path.join(DATA_DIR, "last_result.json")
INTERVAL_HOURS = float(os.environ.get("HA_INTERVAL_HOURS", "6"))

app = FastAPI()

_lock = threading.Lock()
_state = {
    "result": audit.AuditResult(),
    "log_lines": [],
    "last_run": None,
    "running": False,
}


def _load_state():
    if os.path.isfile(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            with _lock:
                _state["result"] = audit.AuditResult.from_dict(data["result"])
                _state["log_lines"] = data.get("log_lines", [])
                _state["last_run"] = data.get("last_run")
        except Exception:  # noqa: BLE001 - corrupt/old cache shouldn't crash startup
            pass


def _save_state():
    os.makedirs(DATA_DIR, exist_ok=True)
    with _lock:
        data = {
            "result": _state["result"].to_dict(),
            "log_lines": _state["log_lines"],
            "last_run": _state["last_run"],
        }
    tmp_path = STATE_FILE + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp_path, STATE_FILE)


def _do_run():
    with _lock:
        if _state["running"]:
            return
        _state["running"] = True
    try:
        result, log_lines = run_audit()
        with _lock:
            _state["result"] = result
            _state["log_lines"] = log_lines
            _state["last_run"] = datetime.now(timezone.utc).isoformat()
    finally:
        with _lock:
            _state["running"] = False
        _save_state()


def _scheduler_loop():
    while True:
        time.sleep(INTERVAL_HOURS * 3600)
        _do_run()


@app.on_event("startup")
def on_startup():
    _load_state()
    if _state["last_run"] is None:
        threading.Thread(target=_do_run, daemon=True).start()
    threading.Thread(target=_scheduler_loop, daemon=True).start()


@app.get("/", response_class=HTMLResponse)
def dashboard():
    with _lock:
        result = _state["result"]
        log_lines = list(_state["log_lines"])
        last_run = _state["last_run"]
        running = _state["running"]

    next_run_iso = None
    if last_run:
        try:
            next_run = datetime.fromisoformat(last_run) + timedelta(hours=INTERVAL_HOURS)
            next_run_iso = next_run.isoformat()
        except ValueError:
            pass

    if running:
        log_lines = log_lines + ["(rodando agora...)"]

    return report.render_html(result, log_lines, last_run, next_run_iso)


@app.post("/run")
def trigger_run():
    threading.Thread(target=_do_run, daemon=True).start()
    return RedirectResponse(url="/", status_code=303)


@app.get("/api/last-result")
def api_last_result():
    with _lock:
        return {
            "last_run": _state["last_run"],
            "running": _state["running"],
            **_state["result"].to_dict(),
        }
