#!/usr/bin/env python3
"""Read-only summary of every BPF-Purkki session in a date range.

Run on the honeypot, fed through stdin (nothing is written there):
    ssh honeypot 'sudo -n python3 - 2026-10-01 2026-10-31' < scripts/session_stats.py > sessions.jsonl

One JSON line per session directory:
    path, date, ip, events, execs, authed, tracked, cmds
and, for authenticated sessions only, "ev": the exec/fork/exit/connect/
file_close events (the process timeline used for attack-flow mapping).

"authed" = the session ran anything besides /usr/sbin/sshd, i.e. the login
succeeded. Sessions from the honeypot's own network (192.168.100.0/24) are skipped.
"""
import json
import sys
from pathlib import Path

ROOT = Path("/home/controller/bpftests/log")
KEEP = {"exec", "fork", "exit", "connect", "file_close"}
INTERNAL = "192.168.100."


def main(first, last):
    for day in sorted(ROOT.iterdir()):
        if not day.is_dir() or not (first <= day.name <= last):
            continue
        for log in sorted(day.glob("*/*/*/log.json")):
            sess = log.parent
            if sess.parent.name.startswith(INTERNAL):
                continue
            rec = {"path": str(sess.relative_to(ROOT)), "date": day.name,
                   "ip": sess.parent.name, "events": 0, "execs": 0,
                   "authed": False, "tracked": 0, "cmds": 0}
            ev = []
            try:
                with log.open(encoding="utf-8", errors="replace") as f:
                    for line in f:
                        try:
                            e = json.loads(line)
                        except ValueError:
                            continue
                        rec["events"] += 1
                        k = e.get("e")
                        if k == "exec":
                            rec["execs"] += 1
                            if e.get("f") != "/usr/sbin/sshd":
                                rec["authed"] = True
                            if str(e.get("k", "")).upper() == "TRACKED":
                                rec["tracked"] += 1
                            v = e.get("v") or []
                            if len(v) >= 3 and v[0] == "bash" and v[1] == "-c":
                                rec["cmds"] += 1
                        if k in KEEP:
                            ev.append(e)
            except OSError:
                rec["error"] = True
            if rec["authed"]:
                rec["ev"] = ev
            sys.stdout.write(json.dumps(rec, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
