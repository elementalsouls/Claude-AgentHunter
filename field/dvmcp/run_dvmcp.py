"""Launch a DVMCP challenge server on a remapped port (8001/8010 are taken on this box).

Loads the challenge's module and serves its FastMCP app directly, so the repo is
left unmodified.
"""
import importlib.util, sys, uvicorn

path, port = sys.argv[1], int(sys.argv[2])
spec = importlib.util.spec_from_file_location("chal", path)
mod = importlib.util.module_from_spec(spec)
sys.modules["chal"] = mod
spec.loader.exec_module(mod)                      # __name__ != "__main__", so it won't self-serve
# challenges name their FastMCP object differently (mcp, combined_server, ...)
from mcp.server.fastmcp import FastMCP
srv = getattr(mod, "mcp", None) or getattr(mod, "combined_server", None)
if srv is None:
    srv = next(v for v in vars(mod).values() if isinstance(v, FastMCP))
app = srv.sse_app()
uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")
