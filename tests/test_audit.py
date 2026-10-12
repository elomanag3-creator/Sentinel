import tempfile
import unittest

from helpers import bad_root, write
from sentinel.audit import passwords, permissions, ports
from sentinel.audit.runner import run_audit
from sentinel.config import Settings
from sentinel.db import Database
from sentinel.models import Config
from sentinel.registry import CHECKS, load_checks, register


class CheckTests(unittest.TestCase):
    def test_ports_parse(self):
        self.assertEqual(str(ports._parse_addr("0100007F", False)), "127.0.0.1")
        self.assertEqual(str(ports._parse_addr("00000000000000000000000001000000", True)), "::1")

    def test_passwords_on_fake_root(self):
        with tempfile.TemporaryDirectory() as r:
            bad_root(r)
            titles = {f.title for f in passwords.run(Config(host_root=r))}
        for t in ("Extra account with UID 0", "Account has NO password", "Password hashed with MD5-crypt",
                  "SSH root login with password allowed"):
            self.assertIn(t, titles)
        self.assertNotIn("SSH allows empty passwords", titles)       # inside a Match block: ignored

    def test_permissions(self):
        with tempfile.TemporaryDirectory() as r:
            write(r, "/etc/shadow", "x", 0o644)
            fs = permissions.check_path(Config(host_root=r), "/etc/shadow", 0o640, True)
            self.assertEqual([f.severity for f in fs if "permissive" in f.title], ["high"])
            write(r, "/etc/shadow", "x", 0o600)
            self.assertEqual(permissions.check_path(Config(host_root=r), "/etc/shadow", 0o640, True), [])


class RunnerTests(unittest.TestCase):
    def test_run_is_stored_with_logs_and_bad_check_is_isolated(self):
        @register("boom")
        def boom(cfg):
            raise RuntimeError("kaboom")
        try:
            with tempfile.TemporaryDirectory() as r:
                bad_root(r)
                db = Database(":memory:")
                s = Settings(host_root=r, checks=["passwords", "boom"])
                run_id = run_audit(db, s)
                run = db.get_run(run_id)
                self.assertEqual((run["kind"], run["max_severity"]), ("audit", "critical"))
                titles = [f["title"] for f in db.get_findings(run_id)]
                self.assertIn("Check 'boom' failed", titles)           # crash became a finding, run completed
                msgs = [row["message"] for row in db.get_logs(run_id)]
                self.assertIn("audit finished", msgs)
                with self.assertRaisesRegex(ValueError, "unknown check"):
                    run_audit(db, Settings(host_root=r), ["nope"])
        finally:
            CHECKS.pop("boom", None)

    def test_builtins_registered(self):
        self.assertTrue({"ports", "passwords", "packages", "permissions"} <= set(load_checks()))


if __name__ == "__main__":
    unittest.main()
