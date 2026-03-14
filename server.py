#!/usr/bin/env python3
"""
Minimal API serving scraped proxies + UptimeRobot health endpoint.
Runs the scraper in a background thread.
"""

import os
import sys
import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

# ── Config ──────────────────────────────────────────────
PORT = int(os.environ.get("PORT", 10000))
OUTPUT_DIR = "output"
PERSISTENT_JSON = os.path.join(OUTPUT_DIR, "VERIFIED_DETAILED.json")
PERSISTENT_FILE = os.path.join(OUTPUT_DIR, "VERIFIED_PROXIES.txt")
PERSISTENT_ELITE = os.path.join(OUTPUT_DIR, "VERIFIED_ELITE.txt")

BOOT_TIME = time.time()


def read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def uptime_seconds() -> int:
    return int(time.time() - BOOT_TIME)


class ProxyAPIHandler(BaseHTTPRequestHandler):
    """
    Endpoints:
        GET /health          → UptimeRobot ping (200 OK)
        GET /proxies         → all verified proxies (text, one per line)
        GET /proxies/elite   → elite only (text)
        GET /proxies/json    → full detailed JSON
        GET /stats           → quick stats JSON
        GET /                → simple index
    """

    def log_message(self, fmt, *args):
        # silence default logging, keep it clean
        pass

    def _respond(self, code: int, body: str, content_type: str = "text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        path = self.path.rstrip("/")

        # ── Health / UptimeRobot ──
        if path == "/health" or path == "/ping":
            self._respond(200, json.dumps({
                "status": "ok",
                "uptime_seconds": uptime_seconds()
            }), "application/json")
            return

        # ── All proxies (text) ──
        if path == "/proxies":
            data = read_file(PERSISTENT_FILE)
            if not data.strip():
                self._respond(200, "# No proxies yet, scraper still running...\n")
            else:
                self._respond(200, data)
            return

        # ── Elite only (text) ──
        if path == "/proxies/elite":
            data = read_file(PERSISTENT_ELITE)
            if not data.strip():
                self._respond(200, "# No elite proxies yet...\n")
            else:
                self._respond(200, data)
            return

        # ── Full JSON ──
        if path == "/proxies/json":
            data = read_file(PERSISTENT_JSON)
            if not data.strip():
                self._respond(200, "[]", "application/json")
            else:
                self._respond(200, data, "application/json")
            return

        # ── Stats ──
        if path == "/stats":
            all_txt = read_file(PERSISTENT_FILE).strip()
            elite_txt = read_file(PERSISTENT_ELITE).strip()
            total = len(all_txt.splitlines()) if all_txt else 0
            elite = len(elite_txt.splitlines()) if elite_txt else 0
            stats = {
                "total_proxies": total,
                "elite_proxies": elite,
                "uptime_seconds": uptime_seconds(),
            }
            self._respond(200, json.dumps(stats, indent=2), "application/json")
            return

        # ── Index ──
        if path == "" or path == "/":
            html = """<!DOCTYPE html>
<html><head><title>Proxy API</title></head>
<body style="font-family:monospace;background:#111;color:#0f0;padding:2em">
<h1>&#128274; Proxy API</h1>
<ul>
<li><a href="/health" style="color:#0ff">/health</a> - UptimeRobot health check</li>
<li><a href="/proxies" style="color:#0ff">/proxies</a> - All verified proxies (text)</li>
<li><a href="/proxies/elite" style="color:#0ff">/proxies/elite</a> - Elite proxies only</li>
<li><a href="/proxies/json" style="color:#0ff">/proxies/json</a> - Full detailed JSON</li>
<li><a href="/stats" style="color:#0ff">/stats</a> - Quick stats</li>
</ul>
</body></html>"""
            self._respond(200, html, "text/html")
            return

        # ── 404 ──
        self._respond(404, "Not found")


# ── Background scraper ─────────────────────────────────
def run_scraper():
    """Import and run the scraper loop in a background thread."""
    time.sleep(3)  # let the HTTP server start first
    print(f"[scraper] Starting background scraper...")
    try:
        import proxy_scraper
        proxy_scraper.main()
    except Exception as e:
        print(f"[scraper] FATAL: {e}")
        import traceback
        traceback.print_exc()


# ── Main ────────────────────────────────────────────────
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Start scraper in background
    t = threading.Thread(target=run_scraper, daemon=True)
    t.start()

    # Start HTTP server
    server = HTTPServer(("0.0.0.0", PORT), ProxyAPIHandler)
    print(f"[api] Listening on port {PORT}")
    print(f"[api] Endpoints: /health /proxies /proxies/elite /proxies/json /stats")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[api] Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
