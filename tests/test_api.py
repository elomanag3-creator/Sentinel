import os
import tempfile
import unittest

from sentinel.config import Settings
from sentinel.db import Database
from sentinel.models import Finding

try:
    from starlette.testclient import TestClient
    from sentinel.api.app import create_app
except ImportError:           # web extras not installed
    TestClient = None


def seed(path):
    db = Database(path)
    a = db.start_run("audit", "web01", "/", ["ports"])
    db.add_finding(a, Finding("ports", "high", "Port 4444 open", "", "0.0.0.0:4444/tcp"))
    db.add_finding(a, Finding("passwords", "low", "PASS_MAX_DAYS not set"))
    db.log(a, "INFO", "sentinel.audit", "audit started")
    db.finish_run(a)
    b = db.start_run("audit", "web01", "/", ["ports"])
    db.add_finding(b, Finding("passwords", "low", "PASS_MAX_DAYS not set"))
    db.add_finding(b, Finding("ports", "medium", "Port 6379 open", "", "0.0.0.0:6379/tcp"))
    db.finish_run(b)
    d = db.start_run("detect", "web01", "auth.log", ["anomaly"])
    db.add_finding(d, Finding("window", "critical", "Unusual log activity", "<script>alert(1)</script>", "web01",
                              source="anomaly", window_start=db.conn.execute("SELECT datetime('now','-1 hour')").fetchone()[0]
                              .replace(" ", "T") + "+00:00", score=0.9))
    db.finish_run(d)
    db.close()


@unittest.skipIf(TestClient is None, "web extras not installed")
class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "s.db")
        seed(self.db_path)

    def tearDown(self):
        self.tmp.cleanup()

    def client(self, **kw):
        s = Settings(db=self.db_path, model=os.path.join(self.tmp.name, "m.npz"), **kw)
        return TestClient(create_app(s))

    def test_read_endpoints(self):
        c = self.client()
        self.assertEqual(c.get("/api/health").json()["status"], "ok")
        s = c.get("/api/summary").json()
        self.assertEqual(s["hostname"], "web01")
        self.assertEqual(s["latest_audit"]["id"], 2)
        self.assertEqual(s["latest_audit_counts"], {"low": 1, "medium": 1})
        self.assertEqual(s["anomalies_24h"], {"critical": 1})
        self.assertEqual([r["id"] for r in c.get("/api/runs?kind=audit").json()], [2, 1])
        d = c.get("/api/runs/1").json()
        self.assertEqual(d["findings"][0]["title"], "Port 4444 open")          # worst first
        self.assertEqual(c.get("/api/runs/1/logs").json()[0]["message"], "audit started")
        df = c.get("/api/diff?old=1&new=2").json()
        self.assertEqual([f["title"] for f in df["new_findings"]], ["Port 6379 open"])
        self.assertEqual([f["title"] for f in df["resolved"]], ["Port 4444 open"])
        tl = c.get("/api/timeline?hours=24&min_severity=medium").json()
        self.assertTrue(all(r["severity"] in ("medium", "high", "critical") for r in tl))
        self.assertIn("Unusual log activity", [r["title"] for r in tl])

    def test_bad_input_and_missing(self):
        c = self.client()
        self.assertEqual(c.get("/api/runs/999").status_code, 404)
        self.assertEqual(c.get("/api/runs/abc").status_code, 400)
        self.assertEqual(c.get("/api/timeline?hours=-1").status_code, 400)
        self.assertEqual(c.get("/api/timeline?min_severity=bogus").status_code, 400)
        self.assertEqual(c.get("/api/runs?kind=nope").status_code, 400)
        self.assertEqual(c.get("/api/diff?old=1").status_code, 400)

    def test_static_and_security_headers(self):
        c = self.client()
        r = c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("script-src 'self'", r.headers["content-security-policy"])
        self.assertEqual(r.headers["x-frame-options"], "DENY")
        self.assertIn("sentinel", r.text)
        self.assertEqual(c.get("/app.js").status_code, 200)
        self.assertEqual(c.get("/style.css").status_code, 200)
        self.assertEqual(c.get("/api/summary").headers["cache-control"], "no-store")

    def test_token_required_when_configured(self):
        c = self.client(api_token="s3cret")
        self.assertEqual(c.get("/api/health").status_code, 200)
        self.assertTrue(c.get("/api/info").json()["auth_required"])
        self.assertEqual(c.get("/api/summary").status_code, 401)
        self.assertEqual(c.get("/api/summary", headers={"Authorization": "Bearer nope"}).status_code, 401)
        self.assertEqual(c.get("/api/summary", headers={"Authorization": "s3cret"}).status_code, 401)
        self.assertEqual(c.get("/api/summary", headers={"Authorization": "Bearer s3cret"}).status_code, 200)

    def test_config_endpoint_never_leaks_token(self):
        c = self.client(api_token="s3cret")
        r = c.get("/api/config", headers={"Authorization": "Bearer s3cret"})
        self.assertNotIn("s3cret", r.text)
        self.assertEqual(r.json()["settings"]["api_token"], "<set>")

    def test_actions_disabled_without_token(self):
        c = self.client()
        self.assertFalse(c.get("/api/info").json()["actions_enabled"])
        self.assertEqual(c.post("/api/actions/audit").status_code, 403)
        c = self.client(api_token="t", api_actions=False)
        self.assertEqual(c.post("/api/actions/audit", headers={"Authorization": "Bearer t"}).status_code, 403)

    def test_actions_need_auth_and_run(self):
        c = self.client(api_token="t", checks=["permissions"], host_root=self.tmp.name)
        self.assertEqual(c.post("/api/actions/audit").status_code, 401)
        h = {"Authorization": "Bearer t"}
        self.assertEqual(c.post("/api/actions/nope", headers=h).status_code, 404)
        self.assertEqual(c.post("/api/actions/audit", headers=h, json={"checks": ["nope"]}).status_code, 400)
        self.assertEqual(c.post("/api/actions/audit", headers=h, content="not json").status_code, 400)
        r = c.post("/api/actions/audit", headers=h, json={})
        self.assertEqual(r.status_code, 200, r.text)
        rid = r.json()["run_id"]
        self.assertEqual(c.get(f"/api/runs/{rid}", headers=h).json()["run"]["kind"], "audit")
        self.assertEqual(c.post("/api/actions/detect", headers=h).status_code, 400)       # no model trained yet

    def test_busy_returns_409(self):
        from sentinel.db import RUN_LOCK
        import threading
        c = self.client(api_token="t")
        held, release = threading.Event(), threading.Event()

        def hold():
            with RUN_LOCK:
                held.set()
                release.wait(5)
        th = threading.Thread(target=hold)
        th.start()
        held.wait(5)
        try:
            self.assertEqual(c.post("/api/actions/audit", headers={"Authorization": "Bearer t"}).status_code, 409)
        finally:
            release.set()
            th.join()

    def test_host_header_allowlist(self):
        s = Settings(db=self.db_path)
        c = TestClient(create_app(s, allowed_hosts=["localhost", "127.0.0.1"]), base_url="http://evil.example")
        self.assertEqual(c.get("/api/health").status_code, 400)
        c = TestClient(create_app(s, allowed_hosts=["localhost", "127.0.0.1"]), base_url="http://localhost:8080")
        self.assertEqual(c.get("/api/health").status_code, 200)


if __name__ == "__main__":
    unittest.main()
