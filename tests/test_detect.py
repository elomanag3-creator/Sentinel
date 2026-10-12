import os
import tempfile
import unittest
from datetime import datetime

import numpy as np

from sentinel.config import Settings
from sentinel.db import Database
from sentinel.detect import runner
from sentinel.detect.demo import write_demo
from sentinel.detect.model import Detector
from sentinel.detect.parser import parse_line, templatize
from sentinel.detect.sources import read_audit_history, read_files
from sentinel.models import Finding


class ParserTests(unittest.TestCase):
    def test_syslog_and_iso(self):
        e = parse_line("Oct  9 06:41:12 web01 sshd[123]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2", datetime(2026, 10, 9))
        self.assertEqual((e.host, e.proc, e.level, e.ips), ("web01", "sshd", "ERROR", ("1.2.3.4",)))
        self.assertEqual(e.template, "sshd: Failed password for invalid user <USER> from <IP> port <N> ssh2")
        self.assertEqual(parse_line("2026-10-09T06:41:12.1+00:00 h cron[9]: ok", None).ts.hour, 6)
        self.assertIsNone(parse_line("garbage", None))

    def test_windows_export_format(self):
        """Lines produced by scripts/win2log.ps1 must parse, and failed logons must count as auth failures."""
        from sentinel.detect.features import AUTH_FAIL
        bad = parse_line("2026-10-12T10:27:01 PC01 winlogon: Failed password for bob from 10.1.2.3 logontype 3 "
                         "(authentication failure)", None)
        self.assertEqual((bad.host, bad.proc, bad.level, bad.ips), ("PC01", "winlogon", "ERROR", ("10.1.2.3",)))
        self.assertTrue(AUTH_FAIL.search(bad.msg))
        good = parse_line("2026-10-12T10:27:02 PC01 winlogon: Accepted logon for bob from - logontype 2", None)
        self.assertEqual(good.level, "INFO")
        self.assertIsNotNone(parse_line("2026-10-12T10:27:03 PC01 useradd: useradd: new account x created by y", None))

    def test_templates_collapse(self):
        self.assertEqual(templatize("sshd", "Failed password for root from 10.0.0.1 port 22 ssh2"),
                         templatize("sshd", "Failed password for alice from 8.8.8.8 port 2200 ssh2"))


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.normal, cls.attack = write_demo(cls.tmp.name)
        cls.det = Detector("time", 300)
        cls.det.fit(read_files([cls.normal]))
        cls.found, _ = cls.det.detect(read_files([cls.attack]))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_attack_is_found(self):
        f = self.found
        self.assertTrue(any(a.kind == "window" and "auth_failures" in a.detail and a.severity in ("high", "critical") for a in f))
        self.assertTrue(any("idle_streak" in a.detail for a in f), "log silence not detected")
        self.assertTrue(any(a.kind == "new_template" and "nc -e" in a.detail and a.severity == "high" for a in f))
        self.assertIn("Out of memory", " ".join(a.detail for a in f))

    def test_model_file_has_no_pickle_and_roundtrips(self):
        path = os.path.join(self.tmp.name, "m.npz")
        self.det.save(path)
        with np.load(path, allow_pickle=False) as z:              # would raise if the file needed pickle
            self.assertEqual(sorted(z.files), ["X", "meta"])
        again, _ = Detector.load(path).detect(read_files([self.attack]))
        self.assertEqual([(a.kind, a.severity, a.start) for a in again], [(a.kind, a.severity, a.start) for a in self.found])

    def test_too_little_data(self):
        with self.assertRaises(ValueError):
            Detector("time", 300).fit(read_files([self.normal])[:30])


class AuditHistoryTests(unittest.TestCase):
    def _runs(self, db, n, incident=False):
        for i in range(n):
            r = db.start_run("audit", "web01", "/", ["ports"])
            for m in ("audit started", "found 2 listening TCP sockets", "audit finished"):
                db.log(r, "INFO", "sentinel.audit", m)
            db.add_finding(r, Finding("passwords", "low", "PASS_MAX_DAYS not set or > 365"))
            if incident and i == n - 1:
                db.add_finding(r, Finding("ports", "high", "Port 4444 listening and not in allow-list", "", "0.0.0.0:4444/tcp"))
            db.finish_run(r)

    def test_new_port_flagged_and_detect_runs_not_reingested(self):
        with tempfile.TemporaryDirectory() as d:
            db, s = Database(":memory:"), Settings(model=os.path.join(d, "a.npz"))
            self._runs(db, 12)
            stats = runner.train(s, db, audit_history=True)
            self.assertEqual(stats["mode"], "group")
            self._runs(db, 1, incident=True)
            run_id, found, nwin, _ = runner.detect(s, db, Detector.load(s.model), audit_history=True)
            self.assertEqual(nwin, 13)
            self.assertTrue(any("Port 4444" in a.detail for a in found))
            stored = [f["title"] for f in db.get_findings(run_id)]
            self.assertIn("Never-seen log pattern", stored)
            self.assertEqual(db.get_run(run_id)["kind"], "detect")
            groups_before = {e.group for e in read_audit_history(db)}
            self.assertNotIn(run_id, groups_before)                  # anomaly runs never become training data

    def test_mode_mismatch_is_explained(self):
        with tempfile.TemporaryDirectory() as d:
            db, s = Database(":memory:"), Settings(model=os.path.join(d, "a.npz"))
            self._runs(db, 12)
            runner.train(s, db, audit_history=True)
            with self.assertRaisesRegex(ValueError, "separate model"):
                runner.detect(s, db, Detector.load(s.model), files=[os.path.join(d, "x.log")])


if __name__ == "__main__":
    unittest.main()
