"""
Quarry web UI — FastAPI server.

Endpoints:
  GET  /                  Main workbench UI
  GET  /api/events        Recent events (JSON)
  GET  /api/tree          Process tree (JSON)
  GET  /api/iocs          Extracted IOCs (JSON)
  GET  /api/diff          Snapshot diff (JSON)
  GET  /api/status        Session status
  WS   /ws/events         Live event stream
  POST /api/session/stop  Stop the running session

The server holds a reference to the active SessionStore and ETWSession so it can
relay live events and serve pre-computed data.
"""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

if TYPE_CHECKING:
    from quarry.models.session_store import SessionStore
    from quarry.session import AnalysisSession

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR    = Path(__file__).parent / "static"

app = FastAPI(title="Quarry Workbench", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

# Injected by session.py before uvicorn starts
_store:   Optional["SessionStore"]    = None
_session: Optional["AnalysisSession"] = None
_session_meta: dict = {}


def configure(
    store: "SessionStore",
    session: "AnalysisSession",
    meta: dict,
) -> None:
    global _store, _session, _session_meta
    _store   = store
    _session = session
    _session_meta = meta


# ------------------------------------------------------------------
# HTML
# ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    return HTMLResponse((_TEMPLATES_DIR / "index.html").read_text())


# ------------------------------------------------------------------
# REST
# ------------------------------------------------------------------

@app.get("/api/status")
async def api_status() -> JSONResponse:
    return JSONResponse({
        "running":     _session_meta.get("running", False),
        "db_path":     _session_meta.get("db_path", ""),
        "started_at":  _session_meta.get("started_at", 0),
        "event_count": len(_store.recent_events()) if _store else 0,
    })


@app.get("/api/events")
async def api_events(limit: int = 500, event_type: str = "", pid: int = 0) -> JSONResponse:
    if not _store:
        return JSONResponse([])
    evs = _store.recent_events()
    if event_type:
        evs = [e for e in evs if e.event_type == event_type]
    if pid:
        evs = [e for e in evs if e.pid == pid]
    return JSONResponse([e.to_dict() for e in evs[-limit:]])


@app.get("/api/tree")
async def api_tree() -> JSONResponse:
    if not _store:
        return JSONResponse({"roots": []})
    return JSONResponse(_store.process_tree.to_dict())


@app.get("/api/iocs")
async def api_iocs() -> JSONResponse:
    if not _store:
        return JSONResponse({})
    from quarry.analysis.ioc_extractor import extract
    iocs = extract(_store.recent_events())
    return JSONResponse(iocs.to_dict())


@app.get("/api/static")
async def api_static() -> JSONResponse:
    if not _store:
        return JSONResponse(None)
    result = await _store.load_static()
    return JSONResponse(result)


@app.get("/api/diff")
async def api_diff() -> JSONResponse:
    if not _store:
        return JSONResponse({})
    pre  = await _store.load_snapshot("pre")
    post = await _store.load_snapshot("post")
    if not pre or not post:
        return JSONResponse({})
    from quarry.snapshot.diff import diff_snapshots
    return JSONResponse(diff_snapshots(pre, post))


@app.post("/api/session/stop")
async def api_stop() -> JSONResponse:
    if _session:
        _session.request_stop()
    return JSONResponse({"ok": True})


@app.post("/api/session/track/{pid}")
async def api_track(pid: int) -> JSONResponse:
    """Register a PID for child-process hook auto-injection."""
    if _session:
        _session.track_pid(pid)
        return JSONResponse({"ok": True, "pid": pid})
    return JSONResponse({"ok": False, "error": "no active session"}, status_code=409)


# ------------------------------------------------------------------
# WebSocket live stream
# ------------------------------------------------------------------

@app.websocket("/ws/events")
async def ws_events(ws: WebSocket) -> None:
    await ws.accept()
    if not _store:
        await ws.close()
        return

    # Replay recent events first so the page isn't blank on connect
    for ev in _store.recent_events()[-200:]:
        await ws.send_text(ev.to_json())

    queue = _store.subscribe()
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=1.0)
                await ws.send_text(event.to_json())
            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await ws.send_text('{"event_type":"ping"}')
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        _store.unsubscribe(queue)
