"""Listening TCP ports, read from /proc (no root, no nmap needed).

In Docker use `network_mode: host` (and `pid: host` for process names) to see the host's sockets.
"""
import ipaddress
import logging
import os

from ..registry import register
from ..models import Config, Finding

log = logging.getLogger("sentinel.audit.ports")

# port: (service, severity when reachable from the network)
RISKY = {
    21: ("FTP", "high"), 23: ("Telnet", "critical"), 69: ("TFTP", "high"),
    111: ("rpcbind", "medium"), 135: ("MS-RPC", "high"), 139: ("NetBIOS", "high"),
    445: ("SMB", "high"), 512: ("rexec", "critical"), 513: ("rlogin", "critical"),
    514: ("rsh", "critical"), 2049: ("NFS", "medium"), 3306: ("MySQL", "high"),
    3389: ("RDP", "high"), 5432: ("PostgreSQL", "high"), 5900: ("VNC", "high"),
    6379: ("Redis", "high"), 9200: ("Elasticsearch", "high"),
    11211: ("Memcached", "high"), 27017: ("MongoDB", "high"),
}
COMMON = {22: "SSH", 80: "HTTP", 443: "HTTPS"}


def _parse_addr(hexaddr: str, v6: bool):
    raw = bytes.fromhex(hexaddr)
    if v6:  # kernel prints four little-endian 32-bit words
        return ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return ipaddress.IPv4Address(raw[::-1])


def listening_sockets(proc: str = "/proc") -> list:
    out = []
    for name, v6 in (("tcp", False), ("tcp6", True)):
        try:
            fh = open(f"{proc}/net/{name}")
        except OSError:
            continue
        with fh:
            next(fh, None)  # header
            for line in fh:
                p = line.split()
                if len(p) < 10 or p[3] != "0A":  # 0A = LISTEN
                    continue
                addr, port = p[1].split(":")
                out.append({"addr": _parse_addr(addr, v6), "port": int(port, 16), "inode": p[9]})
    return out


def _inode_owners(proc: str = "/proc") -> dict:
    owners = {}
    for pid in filter(str.isdigit, os.listdir(proc)):
        try:
            for fd in os.listdir(f"{proc}/{pid}/fd"):
                target = os.readlink(f"{proc}/{pid}/fd/{fd}")
                if target.startswith("socket:["):
                    with open(f"{proc}/{pid}/comm") as fh:
                        owners[target[8:-1]] = f"{fh.read().strip()} (pid {pid})"
        except OSError:
            continue
    return owners


@register("ports")
def run(cfg: Config) -> list:
    findings, seen = [], set()
    owners = _inode_owners()
    socks = listening_sockets()
    log.info("found %d listening TCP sockets", len(socks))
    for s in socks:
        addr, port = s["addr"], s["port"]
        if addr.is_loopback or (addr, port) in seen or port in cfg.allow_ports:
            continue
        seen.add((addr, port))
        who = owners.get(s["inode"], "process unknown (need root / pid: host)")
        target = f"{addr}:{port}/tcp"
        detail = f"Bound to {addr}; {who}"
        if port in RISKY:
            name, sev = RISKY[port]
            findings.append(Finding("ports", sev, f"{name} (port {port}) reachable from the network", detail, target))
        elif port in COMMON:
            findings.append(Finding("ports", "info", f"{COMMON[port]} (port {port}) listening", detail, target))
        else:
            findings.append(Finding("ports", "low", f"Port {port} listening and not in allow-list", detail, target))
    return findings
