"""Local TLS server for demoing the live-endpoint scanner (127.0.0.1 only).

  python scripts/demo_tls_server.py            # serves the demo RSA-2048 certificate on 127.0.0.1:8443
  qscan scan --hosts 127.0.0.1:8443
"""
from __future__ import annotations

import http.server
import ssl
import sys
from pathlib import Path

CERTS = Path(__file__).resolve().parent.parent / "demo" / "bharat-finserve" / "edge" / "certs"


def main(port: int = 8443):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERTS / "server.crt", CERTS / "server.key")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    httpd = http.server.HTTPServer(("127.0.0.1", port), http.server.SimpleHTTPRequestHandler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(f"demo TLS server on https://127.0.0.1:{port} (Ctrl+C to stop)")
    httpd.serve_forever()


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 8443)
