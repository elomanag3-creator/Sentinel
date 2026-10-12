import os
import sqlite3
import tempfile
import unittest

from sentinel.config import ConfigError, load_settings
from sentinel.db import MIGRATIONS, Database, migrate
from sentinel.models import Finding


class DBTests(unittest.TestCase):
    def test_migrations_apply_once_and_upgrade(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.db")
            Database(path).close()
            Database(path).close()                                   # reopening is a no-op
            con = sqlite3.connect(path)
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], len(MIGRATIONS))
            migrate(con, MIGRATIONS + ["CREATE TABLE extra (a INTEGER);"])   # a future migration
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], len(MIGRATIONS) + 1)
            con.close()
            with self.assertRaises(RuntimeError):                    # DB newer than the code
                migrate(sqlite3.connect(path), MIGRATIONS[:0])

    def test_findings_diff_timeline(self):
        db = Database(":memory:")
        a = db.start_run("audit", "h", "/", ["ports"])
        b = db.start_run("audit", "h", "/", ["ports"])
        db.add_finding(a, Finding("ports", "high", "old", "", "t"))
        db.add_finding(a, Finding("ports", "low", "same", "", "t"))
        db.add_finding(b, Finding("ports", "low", "same", "", "t"))
        db.add_finding(b, Finding("ports", "critical", "new", "", "t"))
        d = db.start_run("detect", "h", "x", ["anomaly"])
        db.add_finding(d, Finding("window", "medium", "odd", "why", "h", source="anomaly",
                                  window_start="2999-01-01T00:00:00+00:00", score=0.7))
        for r in (a, b, d):
            db.finish_run(r)
        self.assertEqual(db.get_run(b)["max_severity"], "critical")
        new, resolved = db.diff(a, b)
        self.assertEqual([r["title"] for r in new], ["new"])
        self.assertEqual([r["title"] for r in resolved], ["old"])
        tl = db.timeline(hours=24 * 365 * 100, min_severity="medium")
        self.assertEqual({r["source"] for r in tl}, {"audit", "anomaly"})
        self.assertEqual(tl[0]["title"], "odd")                      # newest first, anomalies use window start
        with self.assertRaises(sqlite3.IntegrityError):
            db.add_finding(a, Finding("x", "banana", "bad severity"))


class ConfigTests(unittest.TestCase):
    def _toml(self, d, text):
        p = os.path.join(d, "c.toml")
        with open(p, "w") as fh:
            fh.write(text)
        return p

    def test_load_and_env(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._toml(d, '[audit]\nallow_ports=[22,443]\ninterval=60\n[detect]\ncontamination=1\nfiles=["/x"]\n')
            s = load_settings(p)
            self.assertEqual((s.allow_ports, s.audit_interval, s.contamination, s.files), ([22, 443], 60, 1.0, ["/x"]))
            self.assertEqual(s.audit_config().allow_ports, {22, 443})
            os.environ["SENTINEL_DB"] = "/tmp/zzz.db"
            try:
                self.assertEqual(load_settings(p).db, "/tmp/zzz.db")
            finally:
                del os.environ["SENTINEL_DB"]

    def test_errors_are_clear(self):
        with tempfile.TemporaryDirectory() as d:
            for text, msg in (("[audit]\nallow_port=[22]\n", "unknown option"), ("[audit]\ninterval='x'\n", "must be int"),
                              ("[audit\n", "invalid TOML")):
                with self.assertRaisesRegex(ConfigError, msg):
                    load_settings(self._toml(d, text))
        with self.assertRaises(ConfigError):
            load_settings("/nonexistent.toml")


if __name__ == "__main__":
    unittest.main()
