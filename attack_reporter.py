"""
Attack Report Generator

Generates an HTML report from attack script results.
Any attack script can call generate_attack_report() with its findings.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def generate_attack_report(
    attack_name: str,
    results: list[dict],
    output_dir: str | Path = "runs",
) -> Path:
    """
    Generate an HTML report from attack results.

    Each result dict should have:
        - id: str
        - name: str
        - status: str ("DISCLOSED", "REFUSED", "NORMAL", "TRIGGERED", etc.)
        - payload: str (the prompt sent)
        - response: str (model's response)
        - strategy: str (optional - adversarial strategy used)
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = out / f"attack_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    # Save JSON
    json_path = run_dir / "results.json"
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    # Classify
    disclosed = [r for r in results if "DISCLOS" in r.get("status", "").upper() or "BYPASS" in r.get("status", "").upper() or "TRIGGERED" in r.get("status", "").upper()]
    refused = [r for r in results if "REFUSED" in r.get("status", "").upper()]
    normal = [r for r in results if r not in disclosed and r not in refused]

    # Build cards
    def build_card(r, severity_class):
        status = _escape(r.get("status", ""))
        name = _escape(r.get("name", ""))
        rid = _escape(r.get("id", ""))
        strategy = _escape(r.get("strategy", "raw"))
        payload = _escape(r.get("payload", "")[:300])
        response = _escape(r.get("response", "")[:500])
        return f'''
        <div class="finding-card {severity_class}">
            <div class="card-header">
                <span class="badge badge-{severity_class}">{status}</span>
                <h3>{rid} — {name}</h3>
            </div>
            <div class="card-meta">Strategy: <code>{strategy}</code></div>
            <details><summary>Payload</summary><pre>{payload}</pre></details>
            <details open><summary>Response</summary><pre>{response}</pre></details>
        </div>'''

    disclosed_html = "\n".join(build_card(r, "high") for r in disclosed) or '<p class="no-findings">None</p>'
    refused_html = "\n".join(build_card(r, "low") for r in refused[:10]) or '<p class="no-findings">None</p>'
    if len(refused) > 10:
        refused_html += f'<p class="no-findings">...and {len(refused) - 10} more refused.</p>'

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AICU Attack Report — {_escape(attack_name)}</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#0f1117; color:#e1e4e8; padding:2rem; }}
h1 {{ font-size:2rem; margin-bottom:0.5rem; background:linear-gradient(135deg,#58a6ff,#bc8cff); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }}
h2 {{ font-size:1.3rem; margin:2rem 0 1rem; padding-bottom:0.5rem; border-bottom:1px solid #21262d; }}
.meta {{ color:#8b949e; margin-bottom:2rem; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:1rem; margin-bottom:2rem; }}
.stat {{ background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.2rem; text-align:center; }}
.stat .value {{ font-size:2rem; font-weight:700; }}
.stat .label {{ color:#8b949e; font-size:0.8rem; text-transform:uppercase; }}
.stat.red .value {{ color:#f85149; }}
.stat.yellow .value {{ color:#d29922; }}
.stat.green .value {{ color:#3fb950; }}
.stat.blue .value {{ color:#58a6ff; }}
.finding-card {{ background:#161b22; border:1px solid #21262d; border-radius:10px; padding:1.5rem; margin-bottom:1rem; border-left:4px solid #30363d; }}
.finding-card.high {{ border-left-color:#f85149; }}
.finding-card.low {{ border-left-color:#3fb950; }}
.card-header {{ display:flex; align-items:center; gap:0.75rem; margin-bottom:0.5rem; }}
.card-header h3 {{ font-size:1rem; }}
.badge {{ padding:0.2rem 0.6rem; border-radius:4px; font-size:0.7rem; font-weight:700; text-transform:uppercase; }}
.badge-high {{ background:#f8514926; color:#f85149; }}
.badge-low {{ background:#3fb95026; color:#3fb950; }}
.card-meta {{ color:#8b949e; font-size:0.85rem; margin-bottom:0.5rem; }}
.card-meta code {{ background:#21262d; padding:0.1rem 0.4rem; border-radius:3px; }}
details {{ margin-top:0.5rem; }}
summary {{ cursor:pointer; color:#58a6ff; font-size:0.85rem; }}
pre {{ background:#0d1117; border:1px solid #21262d; border-radius:6px; padding:1rem; margin-top:0.5rem; font-size:0.8rem; white-space:pre-wrap; word-wrap:break-word; overflow-x:auto; color:#c9d1d9; }}
.no-findings {{ color:#3fb950; font-style:italic; padding:1rem; background:#3fb95010; border-radius:6px; }}
</style>
</head>
<body>
<h1>AICU Attack Report</h1>
<p class="meta">{_escape(attack_name)} — {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

<div class="stats">
    <div class="stat blue"><div class="value">{len(results)}</div><div class="label">Total Tests</div></div>
    <div class="stat red"><div class="value">{len(disclosed)}</div><div class="label">Disclosed</div></div>
    <div class="stat yellow"><div class="value">{len(refused)}</div><div class="label">Refused</div></div>
    <div class="stat green"><div class="value">{len(normal)}</div><div class="label">Normal</div></div>
</div>

<h2>🔴 Findings ({len(disclosed)})</h2>
{disclosed_html}

<h2>❌ Refused ({len(refused)})</h2>
{refused_html}
</body>
</html>'''

    html_path = run_dir / "report.html"
    html_path.write_text(html, encoding="utf-8")

    print(f"[+] Report saved: {html_path}")
    print(f"[+] JSON saved: {json_path}")
    return html_path
