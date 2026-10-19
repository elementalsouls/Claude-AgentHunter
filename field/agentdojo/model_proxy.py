"""Advertise a single Ollama model on /v1/models, forward everything else verbatim.

AgentDojo's VLLM_PARSED path calls _get_local_model_id(port), which takes
data[0]["id"] from /v1/models with no override. Ollama lists every installed
model, so selecting a specific one means controlling that listing. Everything
other than the listing is proxied unchanged, so the agent loop is identical
between models — which is the point: any difference in results is the model,
not the harness.
"""
import http.server, json, os, socketserver, urllib.request

UPSTREAM = os.environ.get("UPSTREAM", "http://127.0.0.1:11434")
MODEL = os.environ.get("PROXY_MODEL", "qwen3-coder:30b")
PORT = int(os.environ.get("PROXY_PORT", "11500"))


class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a): pass

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.rstrip("/").endswith("/v1/models"):
            body = json.dumps({"object": "list", "data": [
                {"id": MODEL, "object": "model", "owned_by": "ollama"}]}).encode()
            return self._send(200, body)
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def _forward(self, method):
        n = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(n) if n else None
        req = urllib.request.Request(UPSTREAM + self.path, data=payload, method=method)
        for k, v in self.headers.items():
            if k.lower() not in ("host", "content-length", "connection"):
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                self._send(r.getcode(), r.read(), r.headers.get("Content-Type", "application/json"))
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read(), e.headers.get("Content-Type", "application/json"))
        except Exception as e:
            self._send(502, json.dumps({"error": str(e)}).encode())


if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    print(f"[proxy] :{PORT} -> {UPSTREAM}, advertising {MODEL}")
    socketserver.ThreadingTCPServer(("127.0.0.1", PORT), H).serve_forever()
