import contextlib, io, os, tempfile, unittest

from helpers import bad_root
from sentinel.cli import main


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_full_workflow(self):
        with tempfile.TemporaryDirectory() as d:
            db, model, fake = os.path.join(d, "s.db"), os.path.join(d, "m.npz"), os.path.join(d, "root")
            os.makedirs(fake); bad_root(fake)
            base = ["--db", db]

            code, out, _ = run(*base, "audit", "--checks", "passwords", "--host-root", fake, "--fail-on", "high")
            self.assertEqual(code, 2)                                  # critical findings + --fail-on
            self.assertIn("Account has NO password", out)
            self.assertEqual(run(*base, "audit", "--checks", "passwords", "--host-root", fake)[0], 0)

            run(*base, "demo", "--out-dir", d)
            code, out, _ = run(*base, "train", "--file", os.path.join(d, "normal.log"), "--model", model)
            self.assertEqual(code, 0, out)
            code, out, _ = run(*base, "detect", "--file", os.path.join(d, "attack.log"), "--model", model,
                               "--lookback", "30", "--fail-on", "high")
            self.assertEqual(code, 2)
            self.assertIn("auth_failures", out)

            code, out, _ = run(*base, "timeline", "--hours", "48", "--min-severity", "medium")
            self.assertIn("audit/passwords", out)                      # both sources, one timeline
            self.assertIn("anomaly/window", out)
            self.assertIn("detect", run(*base, "history")[1])
            self.assertEqual(run(*base, "show", "999")[0], 1)          # clean error, no traceback

    def test_daemon_once(self):
        with tempfile.TemporaryDirectory() as d:
            fake = os.path.join(d, "root")
            os.makedirs(fake); bad_root(fake)
            cfg = os.path.join(d, "c.toml")
            with open(cfg, "w") as fh:
                fh.write(f'[general]\ndb="{d}/d.db"\nhost_root="{fake}"\n[audit]\nchecks=["passwords"]\n')
            code, _, _ = run("--config", cfg, "daemon", "--once")
            self.assertEqual(code, 0)
            code, out, _ = run("--config", cfg, "history")
            self.assertIn("audit", out)

    def test_bad_config_message(self):
        code, _, err = run("--config", "/nonexistent.toml", "history")
        self.assertEqual(code, 1)
        self.assertIn("config error", err)


if __name__ == "__main__":
    unittest.main()
