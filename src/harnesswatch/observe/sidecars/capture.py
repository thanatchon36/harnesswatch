"""Capture sidecar for `harnesswatch observe`. Shares the target's network and PID namespaces.

1. Sniffs packet headers on all interfaces (AF_PACKET) and logs three kinds of event to
   net.jsonl: DNS query names, outbound TCP SYNs and outbound UDP/443 (QUIC). No payloads are
   kept. DNS is recognised by destination (port 53 or Docker's 127.0.0.11 resolver), because
   Docker NATs the resolver port before a packet reaches `lo`.
2. Writes the ready marker into the target's filesystem through /proc/1/root. The target's
   entrypoint waits for it, so the harness starts only once the capture is running.
3. Samples /proc every 200 ms and records each new process: command line, uid, seccomp state,
   no_new_privs and namespace ids. These show OS-level sandboxing (bwrap, landlock helpers, ...).

When the target's PID 1 exits, the kernel kills this sidecar too. Every line is flushed as it is
written. Standard library only (needs CAP_NET_RAW and CAP_SYS_PTRACE).
"""

import json
import os
import socket
import struct
import threading
import time

OUT = "/out"
READY = "/proc/1/root/tmp/.hw_ready"
ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
DOCKER_DNS = "127.0.0.11"


def dns_name(payload: bytes) -> str | None:
    """Question name of a DNS query (header 12 bytes, then length-prefixed labels)."""
    if len(payload) < 13 or payload[2] & 0x80:  # QR bit set: a response
        return None
    labels, i = [], 12
    while i < len(payload) and payload[i]:
        size = payload[i]
        if size > 63:
            return None
        labels.append(payload[i + 1 : i + 1 + size].decode("ascii", "replace"))
        i += size + 1
    return ".".join(labels) or None


def sniff(path: str) -> None:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
    with open(path, "w", encoding="utf-8") as out:
        while True:
            packet, addr = sock.recvfrom(65535)
            ifname, pkttype = addr[0], addr[2]
            # loopback packets appear twice (out + in); elsewhere keep outbound only
            if (ifname == "lo") == (pkttype == PACKET_OUTGOING):
                continue
            if len(packet) < 20 or packet[0] >> 4 != 4:
                continue
            ihl = (packet[0] & 0x0F) * 4
            proto = packet[9]
            dst = socket.inet_ntoa(packet[16:20])
            body = packet[ihl:]
            event: dict[str, object] | None = None
            if proto == 17 and len(body) >= 8:
                dport = struct.unpack("!H", body[2:4])[0]
                if dport == 53 or dst == DOCKER_DNS:
                    name = dns_name(body[8:])
                    event = {"kind": "dns", "name": name} if name else None
                elif dport == 443:
                    event = {"kind": "quic", "dst": dst, "port": dport}
            elif proto == 6 and len(body) >= 14:
                dport = struct.unpack("!H", body[2:4])[0]
                flags = body[13]
                if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                    event = {"kind": "syn", "dst": dst, "port": dport}
            if event:
                event["t"] = time.time()
                out.write(json.dumps(event) + "\n")
                out.flush()


def status_fields(pid: str) -> dict[str, str]:
    fields = {}
    with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
        for line in fh:
            key, _, value = line.partition(":")
            if key in {"Name", "PPid", "Uid", "Seccomp", "Seccomp_filters", "NoNewPrivs"}:
                fields[key] = value.strip()
    return fields


def namespaces(pid: str) -> dict[str, str]:
    out = {}
    for ns in ("user", "mnt", "net", "pid"):
        try:
            out[ns] = os.readlink(f"/proc/{pid}/ns/{ns}")
        except OSError:
            out[ns] = ""
    return out


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    threading.Thread(target=sniff, args=(f"{OUT}/net.jsonl",), daemon=True).start()
    time.sleep(0.5)
    own_mnt = os.readlink("/proc/self/ns/mnt")
    seen: set[tuple[str, str]] = set()
    procs = open(f"{OUT}/procs.jsonl", "w", encoding="utf-8")  # noqa: SIM115
    with open(READY, "w", encoding="utf-8") as fh:
        fh.write("1")
    while True:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
                    start = fh.read().rsplit(")", 1)[1].split()[19]
                key = (pid, start)
                if key in seen:
                    continue
                ns = namespaces(pid)
                if ns["mnt"] == own_mnt:
                    seen.add(key)
                    continue
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    cmd = fh.read().replace(b"\0", b" ").decode(errors="replace").strip()
                record = {"pid": int(pid), "t": time.time(), "cmd": cmd[:300], "ns": ns}
                record.update(status_fields(pid))
            except (OSError, IndexError):
                continue
            seen.add(key)
            procs.write(json.dumps(record) + "\n")
            procs.flush()
        time.sleep(0.2)


if __name__ == "__main__":
    main()
