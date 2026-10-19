#!/usr/bin/env python3
"""
Out-of-band listener — the exfil-proof channel ("OOB-or-it-didn't-happen").

The target is blind, so the ONLY proof a payload executed is a callback landing
here. Logs every request path+query in memory; GET /__hits returns them as JSON
for the exploits to assert against. Stands in for Burp Collaborator / interactsh
in a self-contained, deterministic form.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("LISTENER_PORT", "18081"))
HITS = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/__hits":
            body = json.dumps(HITS).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        HITS.append(self.path)           # record the callback
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


if __name__ == "__main__":
    print(f"[oob] listener on :{PORT} (GET /__hits for recorded callbacks)")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
