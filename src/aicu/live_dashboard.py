"""
Live scan dashboard — real-time web UI for AICU scan progress.

Provides:
- WebSocket streaming of scan events
- Color-coded terminal output with progress bar
- Browser-based dashboard with live updates
- Full payload/response detail on click

Usage:
    aicu scan --api-key sk-... --llm-judge --live

Opens http://localhost:4171 with a real-time dashboard.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any

# Global event queue for dashboard communication
_events: list[dict] = []
_scan_complete = False


def emit_event(event: dict) -> None:
    """Push an event to the live dashboard."""
    event["timestamp"] = time.time()
    _events.append(event)


def get_events_since(index: int) -> list[dict]:
    """Get all events since a given index."""
    return _events[index:]


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AICU Live Scanner</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'JetBrains Mono', 'Fira Code', monospace; background: #0d1117; color: #e6edf3; }
.header { background: #161b22; border-bottom: 1px solid #21262d; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 18px; color: #58a6ff; }
.stats { display: flex; gap: 24px; }
.stat { text-align: center; }
.stat .num { font-size: 24px; font-weight: 700; }
.stat .label { font-size: 11px; color: #8b949e; text-transform: uppercase; }
.confirmed .num { color: #f85149; }
.suspicious .num { color: #d29922; }
.clean .num { color: #3fb950; }
.total .num { color: #58a6ff; }
.progress-bar { height: 3px; background: #21262d; }
.progress-fill { height: 100%; background: #58a6ff; transition: width 0.3s; }
.container { display: flex; height: calc(100vh - 80px); }
.feed { flex: 1; overflow-y: auto; padding: 12px; }
.detail { width: 400px; background: #161b22; border-left: 1px solid #21262d; padding: 16px; overflow-y: auto; display: none; }
.event { padding: 10px 14px; border-radius: 6px; margin-bottom: 6px; cursor: pointer; border-left: 3px solid transparent; font-size: 13px; transition: background 0.15s; }
.event:hover { background: #161b22; }
.event.confirmed { border-left-color: #f85149; background: #1c1012; }
.event.suspicious { border-left-color: #d29922; background: #1c1a10; }
.event.clean { border-left-color: #21262d; }
.event .tag { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px; font-weight: 600; margin-right: 8px; }
.event .tag.confirmed { background: #f85149; color: #fff; }
.event .tag.suspicious { background: #d29922; color: #000; }
.event .tag.clean { background: #21262d; color: #8b949e; }
.event .name { color: #c9d1d9; }
.event .payload-preview { color: #8b949e; font-size: 11px; margin-top: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.event .canary { color: #f85149; font-weight: 700; font-size: 11px; margin-top: 4px; }
.detail h3 { color: #58a6ff; margin-bottom: 12px; font-size: 14px; }
.detail .field { margin-bottom: 12px; }
.detail .field-label { color: #8b949e; font-size: 11px; text-transform: uppercase; margin-bottom: 4px; }
.detail .field-value { color: #e6edf3; font-size: 12px; white-space: pre-wrap; word-break: break-all; background: #0d1117; padding: 8px; border-radius: 4px; max-height: 200px; overflow-y: auto; }
.spinner { display: inline-block; width: 12px; height: 12px; border: 2px solid #21262d; border-top-color: #58a6ff; border-radius: 50%; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="header">
    <h1>AICU <span id="status"><span class="spinner"></span> Scanning...</span></h1>
    <div class="stats">
        <div class="stat total"><div class="num" id="total">0</div><div class="label">Total</div></div>
        <div class="stat confirmed"><div class="num" id="confirmed">0</div><div class="label">Confirmed</div></div>
        <div class="stat suspicious"><div class="num" id="suspicious">0</div><div class="label">Suspicious</div></div>
        <div class="stat clean"><div class="num" id="clean">0</div><div class="label">Clean</div></div>
    </div>
</div>
<div class="progress-bar"><div class="progress-fill" id="progress" style="width:0%"></div></div>
<div class="container">
    <div class="feed" id="feed"></div>
    <div class="detail" id="detail"></div>
</div>
<script>
let eventIndex = 0;
let events = [];
let stats = {total: 0, confirmed: 0, suspicious: 0, clean: 0, expected: 1};

function poll() {
    fetch('/api/events?since=' + eventIndex)
        .then(r => r.json())
        .then(data => {
            data.forEach(handleEvent);
            eventIndex += data.length;
            setTimeout(poll, 500);
        })
        .catch(() => setTimeout(poll, 1000));
}

function handleEvent(evt) {
    events.push(evt);
    if (evt.type === 'scan_start') {
        stats.expected = evt.total_mutations || 1;
    } else if (evt.type === 'result') {
        stats.total++;
        if (evt.outcome === 'confirmed') stats.confirmed++;
        else if (evt.outcome === 'suspicious') stats.suspicious++;
        else stats.clean++;
        addResultToFeed(evt);
    } else if (evt.type === 'scan_complete') {
        document.getElementById('status').textContent = '\\u2705 Complete';
    } else if (evt.type === 'phase') {
        addPhaseToFeed(evt);
    }
    updateStats();
}

function updateStats() {
    document.getElementById('total').textContent = stats.total;
    document.getElementById('confirmed').textContent = stats.confirmed;
    document.getElementById('suspicious').textContent = stats.suspicious;
    document.getElementById('clean').textContent = stats.clean;
    document.getElementById('progress').style.width = Math.min(100, (stats.total / stats.expected) * 100) + '%';
}

function addPhaseToFeed(evt) {
    const feed = document.getElementById('feed');
    const el = document.createElement('div');
    el.style.cssText = 'padding:8px 14px;color:#58a6ff;font-size:12px;font-weight:600;margin-top:8px;';
    el.textContent = evt.message;
    feed.appendChild(el);
    feed.scrollTop = feed.scrollHeight;
}

function addResultToFeed(evt) {
    const feed = document.getElementById('feed');
    const el = document.createElement('div');
    el.className = 'event ' + evt.outcome;
    el.innerHTML = `<span class="tag ${evt.outcome}">${evt.outcome.toUpperCase()}</span><span class="name">[${evt.index}] ${evt.variant_id} ${evt.name}</span>`;
    if (evt.payload_preview) el.innerHTML += `<div class="payload-preview">${escHtml(evt.payload_preview)}</div>`;
    if (evt.canary_leaked) el.innerHTML += `<div class="canary">\\u26a0 CANARY LEAKED</div>`;
    el.onclick = () => showDetail(evt);
    feed.appendChild(el);
    feed.scrollTop = feed.scrollHeight;
}

function showDetail(evt) {
    const d = document.getElementById('detail');
    d.style.display = 'block';
    d.innerHTML = `
        <h3>${evt.variant_id} — ${evt.name}</h3>
        <div class="field"><div class="field-label">Outcome</div><div class="field-value">${evt.outcome} (${evt.confidence})</div></div>
        <div class="field"><div class="field-label">Technique</div><div class="field-value">${evt.transformation_type || 'N/A'}</div></div>
        <div class="field"><div class="field-label">Payload</div><div class="field-value">${escHtml(evt.payload || '')}</div></div>
        <div class="field"><div class="field-label">Response</div><div class="field-value">${escHtml(evt.response || '')}</div></div>
        <div class="field"><div class="field-label">Reason</div><div class="field-value">${escHtml(evt.reason || '')}</div></div>
    `;
}

function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

poll();
</script>
</body>
</html>"""


class DashboardHandler(SimpleHTTPRequestHandler):
    """HTTP handler for the live dashboard."""

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())
        elif self.path.startswith("/api/events"):
            since = 0
            if "since=" in self.path:
                try:
                    since = int(self.path.split("since=")[1])
                except ValueError:
                    since = 0
            events = get_events_since(since)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(events).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress server logs


def start_dashboard(port: int = 4171, open_browser: bool = True) -> HTTPServer:
    """Start the dashboard HTTP server in a background thread.

    ``open_browser`` is best-effort: in headless environments (no display)
    launching a browser is skipped rather than allowed to crash the run.
    """
    server = HTTPServer(("127.0.0.1", port), DashboardHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    if open_browser:
        try:
            webbrowser.open(f"http://localhost:{port}")
        except Exception:
            # No browser / no display (e.g. CI, container). Dashboard still
            # serves at the URL; the user can open it manually.
            pass
    return server


def stop_dashboard(server: HTTPServer) -> None:
    """Stop the dashboard server."""
    server.shutdown()
