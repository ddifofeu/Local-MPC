"""
Regression suite for the orchestrator's security invariants. Each check replays a
known attack or asserts an invariant.
"""
import asyncio, importlib.util, io, json, logging, os, ssl, stat, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SERVER = Path(__file__).resolve().parent.parent / "orchestrator-mcp-server.py"
OUT = Path(tempfile.mkdtemp(prefix="orch-test-"))


def make_test_pki(d: Path) -> Path:
    """Throwaway CA + server cert (SAN 127.0.0.1) + client cert, valid 1 day."""
    d.mkdir()
    def sh(*a): subprocess.run(["openssl", *a], cwd=d, check=True, capture_output=True)
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


PKI = make_test_pki(OUT / "pki")
spec = importlib.util.spec_from_file_location("orch", SERVER)
orch = importlib.util.module_from_spec(spec); sys.modules["orch"] = orch; spec.loader.exec_module(orch)

# capture stderr logs to scan for leaks
LOGBUF = io.StringIO()
h = logging.StreamHandler(LOGBUF); h.setFormatter(orch._JsonFormatter()); logging.getLogger().addHandler(h)

RESULTS, FAILS = [], []
def check(name, cond, info=""):
    RESULTS.append((name, bool(cond), info))
    if not cond: FAILS.append(name)

# ------------------------------------------------------------------ fake Ollama over mTLS
class Ollama(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/version":
            self._json({"version": "0.12.3"})
        else: self._404()
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = json.loads(self.rfile.read(n))
        if self.path == "/api/generate":
            self._json({"response": f"local-answer({body['model']})", "done": True})
        else: self._404()
    def _json(self, obj):
        b = json.dumps(obj).encode(); self.send_response(200)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def _404(self):
        self.send_response(404); self.end_headers(); self.wfile.write(b"404 page not found")
    def log_message(self, *a): pass

def start_mtls(port):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Ollama)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(PKI / "server.crt", PKI / "server.key")
    ctx.load_verify_locations(PKI / "ca.crt"); ctx.verify_mode = ssl.CERT_REQUIRED
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

class CloudRecorder:
    def __init__(self): self.sent = []; self.messages = self
    async def create(self, **kw):
        self.sent.append(kw["messages"][0]["content"])
        class B: type = "text"; text = "cloud-answer"
        class M: content = [B()]
        return M()

def make(cfg_extra=None, m5_port=18443, m970_port=18444, client_cert=True, cloud=True, workdir=None):
    ep = lambda port, model: {"base_url": f"https://127.0.0.1:{port}", "model": model, "ca_file": str(PKI / "ca.crt"),
                              **({"client_cert": str(PKI / "client.crt"), "client_key": str(PKI / "client.key")} if client_cert else {})}
    cfg = {"local_endpoints": {"local_m5": ep(m5_port, "llama3.3:70b"), "local_m970": ep(m970_port, "mistral-small")},
           "audit_log_file": str(AUDIT), **(cfg_extra or {})}
    if workdir: cfg["workdir"] = workdir
    f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump(cfg, f); f.close()
    conf = orch.OrchestratorConfig.load(f.name)
    key = orch.Secret("sk-ant-api03-REALKEYSHOULDNEVERAPPEAR") if cloud else None
    import unittest.mock as um
    with um.patch.dict(sys.modules, {"anthropic": um.MagicMock()}):
        o = orch.Orchestrator(conf, key)
    rec = CloudRecorder()
    if cloud: o.engine.anthropic = rec
    return o, rec

AUDIT = OUT / "audit.jsonl"

async def main():
    # Only M5 up by default (port 18443); M970 port 18444 is DOWN.
    srv = start_mtls(18443)

    # T1 classifier: every bypass probe must be CRITICAL now
    o, _ = make()
    probes = {
        "english_keyword": "Rotate this password: Hunter2!",
        "french_mdp": "Voici le mot de passe root du serveur : Hunter2!",
        "french_cle": "Vérifie ma clé API Anthropic",
        "raw_anthropic_key": "Why does sk-ant-api03-AbCdEf123 return 401?",
        "raw_aws_key": "AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY fails",
        "private_key_block": "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXk...",
        "zero_width": "My pass​word is Hunter2!",
        "leet": "My p4ssw0rd is Hunter2!",
        "spaced": "p a s s w o r d = Hunter2!",
        "fullwidth": "My ｐａｓｓｗｏｒｄ is Hunter2!",
        "french_sante": "Résume le dossier santé de mon père: diabète type 2",
        "iban": "Pay FR76 3000 6000 0112 3456 7890 189 today",
        "synonym_passphrase": "The passphrase for the vault is correct-horse-battery",
        "jwt": "Decode eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
    }
    table = {}
    for k, p in probes.items():
        r = await o.call("route_task", {"task": p})
        table[k] = (r["data"]["privacy_level"], r["data"]["primary_route"], r["data"]["privacy_reasons"][:2])
    check("T1 all 14 bypass probes now CRITICAL + local", all(v[0] == "critical" and v[1].startswith("local") for v in table.values()), json.dumps(table, ensure_ascii=False))

    # T1b false-positive sanity: benign tasks stay cloud-routable
    benign = {"refactor": "Refactor my 2000-line ML pipeline for performance",
              "blog": "Write a blog post about surfing in winter",
              "news": "What are the latest LLM releases?"}
    bt = {}
    for k, p in benign.items():
        r = await o.call("route_task", {"task": p}); bt[k] = (r["data"]["privacy_level"], r["data"]["primary_route"])
    check("T1b benign tasks still go to cloud", all(v[1] == "claude_api" for v in bt.values()), json.dumps(bt))

    # T2 @private with M5 DOWN: must fail closed, zero cloud
    o, rec = make(m5_port=18999)
    r = await o.call("execute_task", {"task": "Summarise this: DB root pw is Hunter2!", "override": "@private"})
    check("T2 @private + M5 down => error, nothing sent to cloud", r["status"] == "error" and rec.sent == [], json.dumps(r))

    # T3 security task, M5 down => no cloud
    o, rec = make(m5_port=18999)
    r = await o.call("execute_task", {"task": "Audit the security of our VPN config: <paste>"})
    check("T3 security task + locals down => fail closed", r["status"] == "error" and rec.sent == [], json.dumps(r))

    # T3b security task, M5 up => executes locally over mTLS
    o, rec = make()
    r = await o.call("execute_task", {"task": "Audit the security of our VPN config: <paste>"})
    check("T3b security task executes on M5 over mTLS", r["status"] == "success" and r["execution"]["provider"] == "local_m5" and rec.sent == [], json.dumps(r)[:300])

    # T4 HIGH + @claude => refused
    o, rec = make()
    r = await o.call("execute_task", {"task": "Here is our production database schema and internal hostnames: ...", "override": "@claude"})
    check("T4 privacy downgrade by override refused", r.get("code") == "POLICY_VIOLATION" and rec.sent == [], json.dumps(r))
    r = await o.call("execute_task", {"task": "Here is our production database schema and internal hostnames: ..."})
    check("T4b HIGH default => local", r["status"] == "success" and r["execution"]["provider"].startswith("local") and rec.sent == [], json.dumps(r)[:200])

    # T5 history leaks nothing; limit=0 / -1 rejected
    o, _ = make()
    await o.call("route_task", {"task": "my password is Hunter2!"})
    h = await o.call("get_routing_history", {"limit": 10})
    check("T5 history contains no task text", "Hunter2" not in json.dumps(h) and h["status"] == "success", json.dumps(h)[:300])
    r0 = await o.call("get_routing_history", {"limit": 0}); rn = await o.call("get_routing_history", {"limit": -1}); rs = await o.call("get_routing_history", {"limit": "5"})
    check("T5b limit=0/-1/'5' rejected", all(x["code"] == "INVALID_INPUT" for x in (r0, rn, rs)))

    # T6 custom keywords from config are honoured
    o, _ = make({"privacy_keywords": {"critical": ["projet-atlas"]}})
    r = await o.call("route_task", {"task": "Summarise the projet-atlas acquisition memo"})
    check("T6 custom critical keyword honoured", r["data"]["privacy_level"] == "critical", json.dumps(r["data"]))

    # T7 input validation
    o, _ = make()
    cases = {"missing": {}, "list": {"task": ["a"]}, "nul": {"task": "abc\x00def"}, "empty": {"task": "   "},
             "bad_override": {"task": "x", "override": "@root"}, "extra_arg": {"task": "x", "evil": 1}}
    codes = {k: (await o.call("route_task", v)).get("code") for k, v in cases.items()}
    t0 = time.time(); big = await o.call("route_task", {"task": "A" * 50_000_000}); dt = time.time() - t0
    check("T7 malformed inputs => INVALID_INPUT", all(c == "INVALID_INPUT" for c in codes.values()), json.dumps(codes))
    check("T7b 50MB prompt rejected quickly", big.get("code") == "INVALID_INPUT" and dt < 0.5, f"{dt:.3f}s")

    # T8 stubs not routable => no fake success
    o, rec = make()
    r = await o.call("execute_task", {"task": "fix this bug in my loop"})
    check("T8 no fake 'integration ready' success", r["execution"]["provider"] == "claude_api" and "integration ready" not in json.dumps(r), json.dumps(r)[:200])

    # T9 config guards
    def load_raw(d):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False); json.dump(d, f); f.close()
        try: orch.OrchestratorConfig.load(f.name); return "loaded"
        except Exception as e: return type(e).__name__
    check("T9 config with api_keys refused", load_raw({"api_keys": {"anthropic": "sk-ant-x"}}) == "PermissionError")
    check("T9b http:// local endpoint refused", load_raw({"local_endpoints": {"local_m5": {"base_url": "http://m5.lan:8001", "model": "m"}}}) == "ValueError")
    bad = {"kw_string": {"privacy_keywords": {"critical": "foo"}}, "kw_level": {"privacy_keywords": {"secret": ["x"]}},
           "kw_empty": {"privacy_keywords": {"high": [""]}}, "limit_zero": {"limits": {"max_concurrency": 0}},
           "limit_str": {"limits": {"rate_per_minute": "30"}}, "limit_typo": {"limits": {"rate_per_min": 30}}}
    got = {k: load_raw(v) for k, v in bad.items()}
    check("T9c malformed keywords/limits refused at load", all(v == "ValueError" for v in got.values()), json.dumps(got))

    # T10 secret files
    d = Path(tempfile.mkdtemp()); (d / "anthropic_api_key").write_text("sk-ant-api03-FILESECRET\n")
    os.environ["ORCH_SECRETS_DIR"] = str(d)
    os.chmod(d / "anthropic_api_key", 0o644)
    try: orch.load_secret("anthropic_api_key"); perm = "loaded"
    except PermissionError: perm = "refused"
    os.chmod(d / "anthropic_api_key", 0o400)
    s = orch.load_secret("anthropic_api_key")
    os.environ["ANTHROPIC_API_KEY"] = "sk-ant-ENV"
    s_both = orch.load_secret("anthropic_api_key")
    env_left_after_file = "ANTHROPIC_API_KEY" in os.environ
    os.environ["ANTHROPIC_API_KEY"] = "sk-ant-ENV"; os.environ.pop("ORCH_SECRETS_DIR")
    s_env = orch.load_secret("anthropic_api_key")
    check("T10 0644 secret refused, 0400 loaded, repr redacted, env ignored by default",
          perm == "refused" and s.reveal() == "sk-ant-api03-FILESECRET" and "FILESECRET" not in repr(s) + str(s) and s_env is None and "ANTHROPIC_API_KEY" not in os.environ)
    check("T10b env key scrubbed even when the secret file wins",
          s_both.reveal() == "sk-ant-api03-FILESECRET" and not env_left_after_file)

    # T11 mTLS enforced: no client cert => handshake fails => HIGH task fails closed
    o, rec = make(client_cert=False)
    r = await o.call("execute_task", {"task": "internal infrastructure notes"})
    check("T11 without client cert M5 rejects; no cloud fallback", r["status"] == "error" and rec.sent == [], json.dumps(r))

    # T12 rate limit
    o, _ = make({"limits": {"rate_per_minute": 5}})
    codes = [(await o.call("route_task", {"task": "hello"})).get("status") for _ in range(7)]
    check("T12 rate limit kicks in", codes[:5] == ["success"] * 5 and codes[5] == "error", str(codes))

    # T13 file I/O: traversal blocked, output written 0600, content not returned
    wd = Path(tempfile.mkdtemp()); (wd / "in.txt").write_text("mot de passe VPN: Hunter2!")
    o, rec = make(workdir=str(wd))
    tr = await o.call("execute_task", {"input_file": "../../etc/passwd"})
    r = await o.call("execute_task", {"input_file": "in.txt", "output_file": "out.txt"})
    mode = stat.S_IMODE((wd / "out.txt").stat().st_mode) if (wd / "out.txt").exists() else None
    check("T13 traversal blocked; sensitive file processed locally; response not echoed; 0600",
          tr.get("code") == "INVALID_INPUT" and r["status"] == "success" and "response" not in r["execution"]
          and r["execution"]["provider"] == "local_m5" and mode == 0o600 and rec.sent == [], json.dumps(r)[:300])

    # T14 audit log: hash chain verifies, no secrets / prompts anywhere
    lines = AUDIT.read_text().splitlines()
    import hashlib
    ok = True
    for prev, cur in zip(lines, lines[1:]):
        if json.loads(cur)["prev"] != hashlib.sha256(prev.encode()).hexdigest(): ok = False
    blob = AUDIT.read_text() + LOGBUF.getvalue()
    leaks = [s for s in ["Hunter2", "REALKEYSHOULDNEVERAPPEAR", "FILESECRET", "AKIAIOSFODNN7EXAMPLE", "projet-atlas acquisition"] if s in blob]
    check("T14 audit chain intact; no prompt/secret in logs", ok and not leaks, f"{len(lines)} records, leaks={leaks}")
    # tamper detection
    tampered = lines[:]; rec5 = json.loads(tampered[5]); rec5["executed_on"] = "local_m5"; tampered[5] = json.dumps(rec5, sort_keys=True, ensure_ascii=False)
    broken = [i for i, (p, c) in enumerate(zip(tampered, tampered[1:])) if json.loads(c)["prev"] != hashlib.sha256(p.encode()).hexdigest()]
    check("T14b editing one record breaks the chain", broken == [5], f"break detected at {broken}")
    verifier = SERVER.parent / "tools/verify-audit.py"
    forged = OUT / "forged.jsonl"; forged.write_text(AUDIT.read_text() + json.dumps({"event": "decision", "prev": "genesis"}) + "\n")
    rc_ok = subprocess.run([sys.executable, verifier, AUDIT], capture_output=True).returncode
    rc_forged = subprocess.run([sys.executable, verifier, forged], capture_output=True).returncode
    check("T14c verify-audit.py: real log OK, appended 'genesis' record flagged", rc_ok == 0 and rc_forged == 2, f"rc_ok={rc_ok} rc_forged={rc_forged}")

    srv.shutdown()

    # T15 MCP stdio end-to-end (real subprocess, real protocol)
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    cfgf = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump({"audit_log_file": str(Path(tempfile.mkdtemp()) / "a.jsonl")}, cfgf); cfgf.close()
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER), "--config", cfgf.name],
                                   env={"PATH": os.environ["PATH"], "ORCH_SECRETS_DIR": "/nonexistent"})
    async with stdio_client(params) as (rd, wr):
        async with ClientSession(rd, wr) as sess:
            await sess.initialize()
            tools = sorted(t.name for t in (await sess.list_tools()).tools)
            res = await sess.call_tool("route_task", {"task": "mon mot de passe est Hunter2"})
            payload = res.structuredContent or json.loads(res.content[0].text)
    check("T15 MCP stdio: tools listed, CRITICAL w/o local endpoints => NO_ROUTE",
          tools == ["check_resources", "execute_task", "get_routing_history", "route_task"] and payload.get("code") == "NO_ROUTE", f"{tools} {payload}")

    for n, ok, info in RESULTS:
        print(("PASS " if ok else "FAIL ") + n + ("" if ok else f"\n     {info}"))
    print(f"\n{len(RESULTS) - len(FAILS)}/{len(RESULTS)} passed")
    with open(OUT / "results.json", "w") as f:
        json.dump([{"test": n, "pass": ok, "info": info} for n, ok, info in RESULTS], f, indent=1, ensure_ascii=False)
    print(f"details: {OUT / 'results.json'}")

asyncio.run(main())
sys.exit(1 if FAILS else 0)
