import asyncio
import inspect
import json
import socket
import ssl
import subprocess
import sys
import threading
import unittest.mock as um
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import orchestrator as orch

FAKE_CLOUD_KEY = "sk-ant-api03-REALKEYSHOULDNEVERAPPEAR"


def pytest_pyfunc_call(pyfuncitem):
    """Run `async def` tests with asyncio.run, without a pytest-asyncio dependency."""
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        args = {name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames}
        asyncio.run(pyfuncitem.obj(**args))
        return True
    return None


@pytest.fixture(scope="session")
def pki(tmp_path_factory) -> Path:
    """Throwaway CA + server cert (SAN 127.0.0.1) + client cert, valid 1 day."""
    d = tmp_path_factory.mktemp("pki")

    def sh(*a):
        subprocess.run(["openssl", *a], cwd=d, check=True, capture_output=True)

    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
    sh("req", "-x509", *ec, "-keyout", "ca.key", "-out", "ca.crt", "-days", "1", "-subj", "/CN=test CA",
       "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign")
    for name, ext in (("server", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"),
                      ("client", "extendedKeyUsage=clientAuth\n")):
        (d / f"{name}.ext").write_text(ext)
        sh("req", *ec, "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={name}")
        sh("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
           "-days", "1", "-out", f"{name}.crt", "-extfile", f"{name}.ext")
    return d


class _FakeOllama(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/version":
            self._json({"version": "0.12.3"})
        else:
            self._404()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        if self.path == "/api/generate":
            self._json({"response": f"local-answer({body['model']})", "done": True})
        else:
            self._404()

    def _json(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _404(self):
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"404 page not found")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="session")
def ollama_port(pki):
    """Fake Ollama behind mTLS: requires a client certificate signed by the test CA."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FakeOllama)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki / "server.crt", pki / "server.key")
    ctx.load_verify_locations(pki / "ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture(scope="session")
def dead_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class CloudRecorder:
    """Stands in for the Anthropic client and records exactly what would have left the machine."""

    def __init__(self):
        self.sent = []
        self.messages = self

    async def create(self, **kw):
        self.sent.append(kw["messages"][0]["content"])

        class Block:
            type = "text"
            text = "cloud-answer"

        class Msg:
            content = [Block()]

        return Msg()


def write_config(path: Path, cfg: dict) -> Path:
    path.write_text(json.dumps(cfg))
    return path


@pytest.fixture
def audit_file(tmp_path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture
def make(pki, ollama_port, dead_port, audit_file, tmp_path):
    """Build an Orchestrator. M5 is up unless m5_up=False; M970 is always down."""

    def _make(cfg_extra=None, m5_up=True, client_cert=True, cloud=True, workdir=None):
        def ep(port, model):
            e = {"base_url": f"https://127.0.0.1:{port}", "model": model, "ca_file": str(pki / "ca.crt")}
            if client_cert:
                e.update(client_cert=str(pki / "client.crt"), client_key=str(pki / "client.key"))
            return e

        cfg = {"local_endpoints": {"local_m5": ep(ollama_port if m5_up else dead_port, "llama3.3:70b"),
                                   "local_m970": ep(dead_port, "mistral-small")},
               "audit_log_file": str(audit_file), **(cfg_extra or {})}
        if workdir:
            cfg["workdir"] = str(workdir)
        conf = orch.OrchestratorConfig.load(str(write_config(tmp_path / "config.json", cfg)))
        key = orch.Secret(FAKE_CLOUD_KEY) if cloud else None
        with um.patch.dict(sys.modules, {"anthropic": um.MagicMock()}):
            o = orch.Orchestrator(conf, key)
        rec = CloudRecorder()
        if cloud:
            o.providers[orch.ModelProvider.CLAUDE_API].client = rec
        return o, rec

    return _make
