"""
HTML report generator for AICU scan results.
Produces a self-contained, interactive HTML file with filtering and presentation-ready styling.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def _escape_html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _build_finding_card(finding: dict, test_type: str) -> str:
    """Build an HTML card for a single finding showing full payload and response."""
    if test_type == "multi_turn":
        evaluation = finding.get("final_evaluation", {})
    else:
        evaluation = finding.get("evaluation", {})

    outcome = evaluation.get("outcome", "none")
    confidence = evaluation.get("confidence", "low")
    title = _escape_html(evaluation.get("title", "Untitled"))
    reason = _escape_html(evaluation.get("reason", ""))
    test_id = _escape_html(finding.get("test_id", "") or finding.get("variant_id", ""))
    name = _escape_html(finding.get("name", ""))

    severity_class = {
        "confirmed": "severity-high",
        "suspicious": "severity-medium",
    }.get(outcome, "severity-low")

    badge_label = outcome.upper()

    # Extract payload text
    payload_text = ""
    if test_type == "single_turn":
        payload_text = _escape_html(finding.get("payload_text", "") or finding.get("mutation_point_value", "") or "")
    elif test_type == "multi_turn" and "steps" in finding:
        payload_text = _escape_html("\n".join(f"Turn {s.get('step_number', '?')}: {s.get('prompt', '')}" for s in finding.get("steps", [])))

    # Extract model response text
    response_text = _escape_html(finding.get("response_text", "") or finding.get("model_output", "") or "")
    if not response_text and test_type == "multi_turn" and finding.get("steps"):
        last_step = finding["steps"][-1]
        response_text = _escape_html(last_step.get("response_text", ""))

    payload_html = ""
    if payload_text:
        payload_html = f'<div class="payload-section"><strong>Payload Sent:</strong><pre class="payload-text">{payload_text}</pre></div>'

    response_html = ""
    if response_text:
        response_html = f'<div class="response-section"><strong>Model Response:</strong><pre class="response-text">{response_text}</pre></div>'

    meta_html = f'<span class="meta-item">ID: <code>{test_id}</code></span>'
    meta_html += f'<span class="meta-item">{name}</span>'
    meta_html += f'<span class="meta-item">Confidence: {confidence}</span>'

    return f'''
    <div class="finding-card {severity_class}" data-outcome="{outcome}" data-type="{test_type}">
        <div class="card-header">
            <span class="badge badge-{outcome}">{badge_label}</span>
            <h3>{title}</h3>
        </div>
        <div class="card-meta">{meta_html}</div>
        <p class="reason">{reason}</p>
        {payload_html}
        {response_html}
    </div>'''


def generate_html_report(
    run_path: Path,
    single_turn_results: list[dict],
    multi_turn_results: list[dict],
    indirect_results: list[dict],
    safety_results: list[dict] | None = None,
) -> Path:
    """Generate a self-contained interactive HTML report."""
    safety_results = safety_results or []

    # Count findings
    all_results = []
    for r in single_turn_results:
        r["_test_type"] = "single_turn"
        all_results.append(r)
    for r in multi_turn_results:
        r["_test_type"] = "multi_turn"
        all_results.append(r)
    for r in indirect_results:
        r["_test_type"] = "indirect"
        all_results.append(r)
    for r in safety_results:
        r["_test_type"] = "safety"
        all_results.append(r)

    confirmed = []
    suspicious = []
    clean = []

    for r in all_results:
        test_type = r["_test_type"]
        if test_type == "multi_turn":
            outcome = r.get("final_evaluation", {}).get("outcome", "none")
        else:
            outcome = r.get("evaluation", {}).get("outcome", "none")

        if outcome in ("confirmed", "bypassed"):
            confirmed.append(r)
        elif outcome in ("suspicious", "partial"):
            suspicious.append(r)
        else:
            clean.append(r)

    total = len(all_results)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build finding cards
    confirmed_cards = "\n".join(_build_finding_card(f, f["_test_type"]) for f in confirmed)
    suspicious_cards = "\n".join(_build_finding_card(f, f["_test_type"]) for f in suspicious)

    if not confirmed_cards:
        confirmed_cards = '<p class="no-findings">No confirmed findings.</p>'
    if not suspicious_cards:
        suspicious_cards = '<p class="no-findings">No suspicious findings.</p>'

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AICU Scan Report</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1117; color: #e1e4e8; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
header {{ text-align: center; padding: 3rem 0 2rem; border-bottom: 1px solid #21262d; margin-bottom: 2rem; }}
header h1 {{ font-size: 2.5rem; font-weight: 700; background: linear-gradient(135deg, #58a6ff, #bc8cff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
header p {{ color: #8b949e; margin-top: 0.5rem; }}

.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
.stat-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 12px; padding: 1.5rem; text-align: center; }}
.stat-card .number {{ font-size: 2.5rem; font-weight: 700; }}
.stat-card .label {{ color: #8b949e; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 0.05em; }}
.stat-card.critical .number {{ color: #f85149; }}
.stat-card.warning .number {{ color: #d29922; }}
.stat-card.success .number {{ color: #3fb950; }}
.stat-card.info .number {{ color: #58a6ff; }}

.filters {{ display: flex; gap: 0.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
.filter-btn {{ background: #21262d; border: 1px solid #30363d; color: #c9d1d9; padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.85rem; transition: all 0.2s; }}
.filter-btn:hover {{ background: #30363d; }}
.filter-btn.active {{ background: #388bfd26; border-color: #58a6ff; color: #58a6ff; }}

section {{ margin-bottom: 3rem; }}
section h2 {{ font-size: 1.5rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid #21262d; }}

.finding-card {{ background: #161b22; border: 1px solid #21262d; border-radius: 10px; padding: 1.5rem; margin-bottom: 1rem; border-left: 4px solid #30363d; transition: all 0.2s; }}
.finding-card:hover {{ border-color: #58a6ff; transform: translateX(2px); }}
.finding-card.severity-high {{ border-left-color: #f85149; }}
.finding-card.severity-medium {{ border-left-color: #d29922; }}
.finding-card.severity-low {{ border-left-color: #3fb950; }}
.finding-card.hidden {{ display: none; }}

.card-header {{ display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }}
.card-header h3 {{ font-size: 1.1rem; font-weight: 600; }}

.payload-section, .response-section {{ margin-top: 0.75rem; }}
.payload-section strong, .response-section strong {{ color: #8b949e; font-size: 0.85rem; }}
.payload-text, .response-text {{ background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 0.75rem; margin-top: 0.25rem; font-family: monospace; font-size: 0.85rem; white-space: pre-wrap; word-break: break-word; max-height: 300px; overflow-y: auto; }}
.payload-text {{ color: #ff7b72; }}
.response-text {{ color: #a5d6ff; }}

.badge {{ padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }}
.badge-confirmed, .badge-bypassed {{ background: #f8514926; color: #f85149; }}
.badge-suspicious, .badge-partial {{ background: #d2992226; color: #d29922; }}
.badge-none, .badge-refused {{ background: #3fb95026; color: #3fb950; }}

.card-meta {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 0.75rem; font-size: 0.85rem; color: #8b949e; }}
.meta-item code {{ background: #21262d; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.8rem; }}

.reason {{ color: #c9d1d9; margin-bottom: 0.75rem; }}
.evidence {{ background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 1rem; margin-top: 0.75rem; }}
.evidence ul {{ list-style: none; padding: 0; margin-top: 0.5rem; }}
.evidence li {{ padding: 0.25rem 0; }}
.evidence code {{ background: #21262d; padding: 0.2rem 0.5rem; border-radius: 3px; font-size: 0.85rem; color: #f0883e; }}

.steps {{ margin-top: 0.75rem; }}
.steps ol {{ padding-left: 1.5rem; margin-top: 0.5rem; }}
.steps li {{ padding: 0.2rem 0; color: #8b949e; }}

.no-findings {{ color: #3fb950; font-style: italic; padding: 1rem; background: #3fb95010; border-radius: 6px; }}

footer {{ text-align: center; padding: 2rem 0; color: #484f58; border-top: 1px solid #21262d; margin-top: 2rem; font-size: 0.85rem; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>AICU Scan Report</h1>
        <p>Generated: {timestamp}</p>
    </header>

    <div class="summary">
        <div class="stat-card info">
            <div class="number">{total}</div>
            <div class="label">Total Tests</div>
        </div>
        <div class="stat-card critical">
            <div class="number">{len(confirmed)}</div>
            <div class="label">Confirmed</div>
        </div>
        <div class="stat-card warning">
            <div class="number">{len(suspicious)}</div>
            <div class="label">Suspicious</div>
        </div>
        <div class="stat-card success">
            <div class="number">{len(clean)}</div>
            <div class="label">Clean</div>
        </div>
    </div>

    <div class="filters">
        <button class="filter-btn active" onclick="filterCards('all')">All</button>
        <button class="filter-btn" onclick="filterCards('single_turn')">Single-Turn</button>
        <button class="filter-btn" onclick="filterCards('multi_turn')">Multi-Turn</button>
        <button class="filter-btn" onclick="filterCards('indirect')">Indirect</button>
        <button class="filter-btn" onclick="filterCards('safety')">Safety</button>
    </div>

    <section>
        <h2>🔴 Confirmed Findings</h2>
        {confirmed_cards}
    </section>

    <section>
        <h2>🟡 Suspicious Findings</h2>
        {suspicious_cards}
    </section>

    <footer>
        <p>AICU — AI Capability &amp; Vulnerability Scanner | {len(single_turn_results)} single-turn | {len(multi_turn_results)} multi-turn | {len(indirect_results)} indirect | {len(safety_results)} safety</p>
    </footer>
</div>

<script>
function filterCards(type) {{
    document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');

    document.querySelectorAll('.finding-card').forEach(card => {{
        if (type === 'all' || card.dataset.type === type) {{
            card.classList.remove('hidden');
        }} else {{
            card.classList.add('hidden');
        }}
    }});
}}
</script>
</body>
</html>'''

    report_path = run_path / "report.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path
