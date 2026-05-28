#!/usr/bin/env python3
"""
AICU Web Dashboard

A lightweight web UI for managing scans, viewing results, and browsing findings.

Usage:
    python web_ui.py [--port 8080] [--host 127.0.0.1]

Then open http://127.0.0.1:8080 in your browser.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

RUNS_DIR = Path("runs")
from aicu import PAYLOADS_DIR


def get_runs() -> list[dict]:
    """List all scan runs."""
    if not RUNS_DIR.exists():
        return []
    runs = []
    for d in sorted(RUNS_DIR.iterdir(), reverse=True):
        if d.is_dir() and d.name.startswith("run_"):
            run = {"id": d.name, "path": str(d)}
            baseline = d / "baseline.json"
            if baseline.exists():
                data = json.loads(baseline.read_text(encoding="utf-8"))
                run["timestamp"] = data.get("timestamp", d.name)
                run["status_code"] = data.get("response", data.get("status_code", {}) if isinstance(data.get("status_code"), dict) else {}).get("status_code", "")
            report_html = d / "report.html"
            report_md = d / "report.md"
            run["has_html_report"] = report_html.exists()
            run["has_md_report"] = report_md.exists()
            # Count findings
            for fname in ("results.json", "multi_turn_results.json", "indirect_results.json"):
                fpath = d / fname
                if fpath.exists():
                    try:
                        results = json.loads(fpath.read_text(encoding="utf-8"))
                        confirmed = sum(1 for r in results if r.get("evaluation", r.get("final_evaluation", {})).get("outcome") == "confirmed")
                        suspicious = sum(1 for r in results if r.get("evaluation", r.get("final_evaluation", {})).get("outcome") == "suspicious")
                        run.setdefault("confirmed", 0)
                        run.setdefault("suspicious", 0)
                        run["confirmed"] += confirmed
                        run["suspicious"] += suspicious
                    except (json.JSONDecodeError, KeyError):
                        pass
            runs.append(run)
    return runs


def get_payloads() -> dict[str, int]:
    """Count payloads per file."""
    counts = {}
    if not PAYLOADS_DIR.exists():
        return counts
    for f in PAYLOADS_DIR.glob("*.yaml"):
        try:
            import yaml
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                total = sum(len(v) for v in data.get("payload_sets", data.get("multi_turn_tests", data.get("file_payloads", {}))).values() if isinstance(v, list)) if "payload_sets" in data else len(data.get("multi_turn_tests", data.get("file_payloads", [])))
                counts[f.stem] = total
        except Exception:
            counts[f.stem] = 0
    return counts


def get_run_details(run_id: str) -> dict:
    """Get detailed results for a specific run."""
    run_path = RUNS_DIR / run_id
    if not run_path.exists():
        return {"error": "Run not found"}

    details = {"id": run_id, "results": [], "multi_turn": [], "indirect": []}

    for fname, key in [("results.json", "results"), ("multi_turn_results.json", "multi_turn"), ("indirect_results.json", "indirect")]:
        fpath = run_path / fname
        if fpath.exists():
            try:
                details[key] = json.loads(fpath.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

    return details


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AICU Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1117; color: #e1e4e8; }
.sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 240px; background: #161b22; border-right: 1px solid #21262d; padding: 1.5rem 0; overflow-y: auto; }
.sidebar h1 { font-size: 1.3rem; padding: 0 1.5rem; margin-bottom: 1.5rem; background: linear-gradient(135deg, #58a6ff, #bc8cff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.nav-item { display: block; padding: 0.7rem 1.5rem; color: #8b949e; text-decoration: none; cursor: pointer; transition: all 0.2s; border-left: 3px solid transparent; }
.nav-item:hover { background: #21262d; color: #e1e4e8; }
.nav-item.active { background: #388bfd15; color: #58a6ff; border-left-color: #58a6ff; }
.main { margin-left: 240px; padding: 2rem; }
.header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
.header h2 { font-size: 1.5rem; }
.btn { padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }
.btn:hover { background: #30363d; }
.btn-primary { background: #238636; border-color: #238636; color: #fff; }
.btn-primary:hover { background: #2ea043; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.stat { background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 1.2rem; text-align: center; }
.stat .value { font-size: 2rem; font-weight: 700; }
.stat .label { color: #8b949e; font-size: 0.8rem; text-transform: uppercase; margin-top: 0.3rem; }
.stat.red .value { color: #f85149; }
.stat.yellow .value { color: #d29922; }
.stat.green .value { color: #3fb950; }
.stat.blue .value { color: #58a6ff; }
.card { background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 1.5rem; margin-bottom: 1rem; }
.card h3 { margin-bottom: 0.75rem; font-size: 1.1rem; }
.run-list { list-style: none; }
.run-item { display: flex; justify-content: space-between; align-items: center; padding: 0.8rem 1rem; border-bottom: 1px solid #21262d; cursor: pointer; transition: background 0.2s; }
.run-item:hover { background: #21262d; }
.run-item:last-child { border-bottom: none; }
.badge { padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
.badge-red { background: #f8514920; color: #f85149; }
.badge-yellow { background: #d2992220; color: #d29922; }
.badge-green { background: #3fb95020; color: #3fb950; }
.payload-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; }
.payload-card { background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 1rem; }
.payload-card .name { font-weight: 600; margin-bottom: 0.3rem; }
.payload-card .count { color: #58a6ff; font-size: 1.2rem; font-weight: 700; }
.launch-form { display: grid; gap: 1rem; max-width: 500px; }
.launch-form label { color: #8b949e; font-size: 0.85rem; }
.launch-form input, .launch-form select { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 0.6rem; color: #e1e4e8; font-size: 0.9rem; width: 100%; }
.launch-form input:focus, .launch-form select:focus { outline: none; border-color: #58a6ff; }
.hidden { display: none; }
#toast { position: fixed; bottom: 2rem; right: 2rem; background: #238636; color: #fff; padding: 0.8rem 1.5rem; border-radius: 8px; display: none; z-index: 1000; }
</style>
</head>
<body>
<div class="sidebar">
    <h1>AICU</h1>
    <a class="nav-item active" onclick="showPage('dashboard')">Dashboard</a>
    <a class="nav-item" onclick="showPage('runs')">Scan Runs</a>
    <a class="nav-item" onclick="showPage('payloads')">Payloads</a>
    <a class="nav-item" onclick="showPage('launch')">Launch Scan</a>
    <a class="nav-item" onclick="showPage('generate')">Generate Files</a>
</div>
<div class="main">
    <div id="page-dashboard">
        <div class="header"><h2>Dashboard</h2></div>
        <div class="stats" id="stats"></div>
        <div class="card"><h3>Recent Runs</h3><ul class="run-list" id="recent-runs"></ul></div>
    </div>
    <div id="page-runs" class="hidden">
        <div class="header"><h2>Scan Runs</h2></div>
        <div class="card"><ul class="run-list" id="all-runs"></ul></div>
    </div>
    <div id="page-payloads" class="hidden">
        <div class="header"><h2>Payload Library</h2></div>
        <div class="payload-grid" id="payload-grid"></div>
    </div>
    <div id="page-launch" class="hidden">
        <div class="header"><h2>Launch Scan</h2></div>
        <div class="card">
            <div class="launch-form">
                <div><label>Request File</label><input type="text" id="req-file" value="req.txt" placeholder="Path to raw HTTP request file"></div>
                <div><label>Scan Type</label><select id="scan-type"><option value="scan">Full Scan</option><option value="single-turn">Single-Turn</option><option value="multi-turn">Multi-Turn</option><option value="safety">Safety</option><option value="indirect">Indirect</option></select></div>
                <div><label>Profile</label><select id="profile"><option value="">None</option><option value="openai">OpenAI</option><option value="anthropic">Anthropic</option><option value="azure_openai">Azure OpenAI</option></select></div>
                <button class="btn btn-primary" onclick="launchScan()">Launch Scan</button>
                <div id="scan-output" style="margin-top:1rem; font-family:monospace; font-size:0.8rem; color:#8b949e; white-space:pre-wrap;"></div>
            </div>
        </div>
    </div>
    <div id="page-generate" class="hidden">
        <div class="header"><h2>Generate Attack Files</h2></div>
        <div class="card">
            <div class="launch-form">
                <div><label>Type</label><select id="gen-type"><option value="all">All</option><option value="indirect">Indirect Injection</option><option value="phantom">Phantom (Zero-Width)</option><option value="exfil">Markdown Exfiltration</option></select></div>
                <div><label>Output Directory</label><input type="text" id="gen-output" value="attack_files" placeholder="Output directory"></div>
                <div><label><input type="checkbox" id="gen-adversarial"> Include Adversarial Triggers</label></div>
                <div><label>Perturbations (if adversarial)</label><input type="number" id="gen-perturbations" value="5" min="1" max="50"></div>
                <button class="btn btn-primary" onclick="generateFiles()">Generate</button>
                <div id="gen-output-log" style="margin-top:1rem; font-family:monospace; font-size:0.8rem; color:#8b949e; white-space:pre-wrap;"></div>
            </div>
        </div>
    </div>
</div>
<div id="toast"></div>
<script>
let currentPage = 'dashboard';

function showPage(page) {
    document.querySelectorAll('[id^="page-"]').forEach(p => p.classList.add('hidden'));
    document.getElementById('page-' + page).classList.remove('hidden');
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    event.target.classList.add('active');
    currentPage = page;
    if (page === 'dashboard') loadDashboard();
    if (page === 'runs') loadRuns();
    if (page === 'payloads') loadPayloads();
}

function toast(msg) {
    const t = document.getElementById('toast');
    t.textContent = msg; t.style.display = 'block';
    setTimeout(() => t.style.display = 'none', 3000);
}

async function api(endpoint) {
    const r = await fetch('/api/' + endpoint);
    return r.json();
}

async function loadDashboard() {
    const runs = await api('runs');
    const payloads = await api('payloads');
    const totalPayloads = Object.values(payloads).reduce((a, b) => a + b, 0);
    const totalConfirmed = runs.reduce((a, r) => a + (r.confirmed || 0), 0);
    const totalSuspicious = runs.reduce((a, r) => a + (r.suspicious || 0), 0);

    document.getElementById('stats').innerHTML = `
        <div class="stat blue"><div class="value">${runs.length}</div><div class="label">Total Runs</div></div>
        <div class="stat red"><div class="value">${totalConfirmed}</div><div class="label">Confirmed</div></div>
        <div class="stat yellow"><div class="value">${totalSuspicious}</div><div class="label">Suspicious</div></div>
        <div class="stat green"><div class="value">${totalPayloads}</div><div class="label">Payloads</div></div>
    `;

    document.getElementById('recent-runs').innerHTML = runs.slice(0, 5).map(r => `
        <li class="run-item" onclick="viewRun('${r.id}')">
            <span>${r.id}</span>
            <span>
                ${r.confirmed ? `<span class="badge badge-red">${r.confirmed} confirmed</span>` : ''}
                ${r.suspicious ? `<span class="badge badge-yellow">${r.suspicious} suspicious</span>` : ''}
                ${!r.confirmed && !r.suspicious ? '<span class="badge badge-green">clean</span>' : ''}
            </span>
        </li>
    `).join('');
}

async function loadRuns() {
    const runs = await api('runs');
    document.getElementById('all-runs').innerHTML = runs.map(r => `
        <li class="run-item" onclick="viewRun('${r.id}')">
            <span>${r.id}</span>
            <span>
                ${r.confirmed ? `<span class="badge badge-red">${r.confirmed} confirmed</span>` : ''}
                ${r.suspicious ? `<span class="badge badge-yellow">${r.suspicious} suspicious</span>` : ''}
                ${!r.confirmed && !r.suspicious ? '<span class="badge badge-green">clean</span>' : ''}
                ${r.has_html_report ? ' <a href="/runs/' + r.id + '/report.html" target="_blank" class="btn" style="font-size:0.7rem;padding:0.2rem 0.5rem;">HTML Report</a>' : ''}
            </span>
        </li>
    `).join('') || '<li class="run-item">No runs yet</li>';
}

async function loadPayloads() {
    const payloads = await api('payloads');
    document.getElementById('payload-grid').innerHTML = Object.entries(payloads).map(([name, count]) => `
        <div class="payload-card"><div class="name">${name}</div><div class="count">${count} payloads</div></div>
    `).join('');
}

function viewRun(id) { window.open('/runs/' + id + '/report.html', '_blank'); }

async function launchScan() {
    const reqFile = document.getElementById('req-file').value;
    const scanType = document.getElementById('scan-type').value;
    const profile = document.getElementById('profile').value;
    document.getElementById('scan-output').textContent = 'Launching scan...';
    const r = await fetch('/api/launch', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({request: reqFile, type: scanType, profile: profile})});
    const data = await r.json();
    document.getElementById('scan-output').textContent = data.output || data.error || 'Done';
    toast('Scan complete');
}

async function generateFiles() {
    const type = document.getElementById('gen-type').value;
    const output = document.getElementById('gen-output').value;
    const adversarial = document.getElementById('gen-adversarial').checked;
    const perturbations = document.getElementById('gen-perturbations').value;
    document.getElementById('gen-output-log').textContent = 'Generating...';
    const r = await fetch('/api/generate', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({type, output, adversarial, perturbations: parseInt(perturbations)})});
    const data = await r.json();
    document.getElementById('gen-output-log').textContent = data.output || data.error || 'Done';
    toast('Files generated');
}

loadDashboard();
</script>
</body>
</html>"""


class AICUHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logging

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "":
            self._serve_html(DASHBOARD_HTML)
        elif path == "/api/runs":
            self._serve_json(get_runs())
        elif path == "/api/payloads":
            self._serve_json(get_payloads())
        elif path.startswith("/api/run/"):
            run_id = path.split("/")[-1]
            self._serve_json(get_run_details(run_id))
        elif path.startswith("/runs/"):
            # Serve static files from runs directory
            file_path = Path(path.lstrip("/"))
            if file_path.exists():
                content = file_path.read_bytes()
                ct = "text/html" if path.endswith(".html") else "application/json"
                self._serve_bytes(content, ct)
            else:
                self._serve_404()
        else:
            self._serve_404()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        data = json.loads(body) if body else {}

        if self.path == "/api/launch":
            result = self._launch_scan(data)
            self._serve_json(result)
        elif self.path == "/api/generate":
            result = self._generate_files(data)
            self._serve_json(result)
        else:
            self._serve_404()

    def _launch_scan(self, data: dict) -> dict:
        req_file = data.get("request", "req.txt")
        scan_type = data.get("type", "scan")
        profile = data.get("profile", "")

        cmd = [sys.executable, "main.py", scan_type, "--request", req_file]
        if profile:
            cmd.extend(["--profile", profile])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {"output": result.stdout + result.stderr, "exit_code": result.returncode}
        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out (300s)"}
        except Exception as e:
            return {"error": str(e)}

    def _generate_files(self, data: dict) -> dict:
        gen_type = data.get("type", "all")
        output_dir = data.get("output", "attack_files")
        adversarial = data.get("adversarial", False)
        perturbations = data.get("perturbations", 5)

        cmd = [sys.executable, "generate_attack_files.py", "--type", gen_type, "--output-dir", output_dir]
        if adversarial:
            cmd.extend(["--adversarial", "--perturbations", str(perturbations)])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return {"output": result.stdout + result.stderr}
        except Exception as e:
            return {"error": str(e)}

    def _serve_html(self, html: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _serve_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _serve_bytes(self, data: bytes, content_type: str):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(data)

    def _serve_404(self):
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AICU Web Dashboard")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    server = HTTPServer((args.host, args.port), AICUHandler)
    print(f"[+] AICU Dashboard running at http://{args.host}:{args.port}")
    print("[+] Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Shutting down")
        server.shutdown()


if __name__ == "__main__":
    main()
