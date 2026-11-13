#!/usr/bin/env python3
"""Level 2 attack chains: sessions of the same IP joined into attacks.

An attack = logged-in sessions from one IP where each session starts at
most WINDOW_MIN minutes after the latest end of the sessions before it.
Only attacks with at least one run (executed upload) are kept.

Inputs (CSDA folder): malware-samples_october.json, sessions.jsonl,
samples/, chains/level1/ (run build_level1.py first).
Output: chains/level2/ (README.md, index.csv, summary.json, attacks/, notes/)
Usage:  python3 scripts/build_level2.py [CSDA folder]
"""

import csv
import datetime
import json
import os
import shutil
import sys
from collections import defaultdict

WINDOW_MIN = 60
VALID = {"same-session", "same-ip-same-path"}
ARGV_MAX = 500
LOGDIR = "/home/controller/bpftests/log/"

root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
level1 = os.path.join(root, "chains", "level1")
out = os.path.join(root, "chains", "level2")


def utc(ns):
    if not isinstance(ns, int):
        return "-"
    return datetime.datetime.fromtimestamp(ns / 1e9, datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f")[:-3]


def short(argv):
    s = " ".join(str(a) for a in argv) if isinstance(argv, list) else str(argv)
    return s if len(s) <= ARGV_MAX else s[:ARGV_MAX] + f" …({len(s)} chars)"


def rel_session(log_path):
    p = log_path[len(LOGDIR):] if log_path.startswith(LOGDIR) else log_path
    return p[: -len("/log.json")] if p.endswith("/log.json") else p


def real_path(f):
    f = str(f or "")
    return f.startswith("/") and not f.startswith(("/dev/", "/proc/", "/sys/"))


# ----------------------------------------------------------------- runs
runs = json.load(open(os.path.join(root, "malware-samples_october.json")))["samples"]
run_ips = {r["ip"] for r in runs}
runs_by_session = defaultdict(list)
for r in runs:
    r["_exec_session"] = rel_session(r["exec_log"])
    writer = (rel_session(r["close_log"]) if r.get("close_log") else
              "/".join(r["ondisk"][len(LOGDIR):].split("/")[:4])
              if str(r.get("ondisk") or "").startswith(LOGDIR) else None)
    r["_write_session"] = writer if r.get("link_quality") in VALID else None
    runs_by_session[r["_exec_session"]].append(r)
uploads_by_session = defaultdict(list)
for r in runs:
    if r["_write_session"] and r["_write_session"] != r["_exec_session"]:
        uploads_by_session[r["_write_session"]].append(r)

l1_dir = {}
with open(os.path.join(level1, "index.csv")) as f:
    for row in csv.DictReader(f):
        l1_dir[row["session"]] = row["dir"]

# ------------------------------------- pass 1: session start/end per IP
spans = defaultdict(list)          # ip -> [(start, end, path)]
with open(os.path.join(root, "sessions.jsonl")) as f:
    for line in f:
        s = json.loads(line)
        if s["ip"] not in run_ips or not s.get("authed"):
            continue
        t = [e["t"] for e in (s.get("ev") or []) if isinstance(e.get("t"), int)]
        if t:
            spans[s["ip"]].append((min(t), max(t), s["path"]))

# -------------------------------------------------------- group attacks
attacks = []
for ip, L in spans.items():
    L.sort()
    cur, end = [L[0]], L[0][1]
    groups = []
    for x in L[1:]:
        if (x[0] - end) / 6e10 <= WINDOW_MIN:
            cur.append(x)
            end = max(end, x[1])
        else:
            groups.append(cur)
            cur, end = [x], x[1]
    groups.append(cur)
    for g in groups:
        if any(p in runs_by_session for _, _, p in g):
            attacks.append({"ip": ip, "sessions": g})
attacks.sort(key=lambda a: a["sessions"][0][0])
attack_of = {}
for n, a in enumerate(attacks, 1):
    a["id"] = f"A{n:03d}"
    a["dir"] = f"{a['id']}_{utc(a['sessions'][0][0])[:16].replace('-', '').replace(':', '').replace(' ', 'T')}_{a['ip']}"
    for _, _, p in a["sessions"]:
        attack_of[p] = a

# ------------------------------------------- pass 2: timelines + events
if os.path.exists(out):
    shutil.rmtree(out)
os.makedirs(os.path.join(out, "attacks"))
os.makedirs(os.path.join(out, "notes"))
for a in attacks:
    d = os.path.join(out, "attacks", a["dir"])
    os.makedirs(os.path.join(d, "sessions"))
    os.makedirs(os.path.join(d, "samples"))
    a["lines"] = []
    a["info"] = {}

with open(os.path.join(root, "sessions.jsonl")) as f:
    for line in f:
        s = json.loads(line)
        a = attack_of.get(s["path"])
        if a is None:
            continue
        path = s["path"]
        ev = s.pop("ev", None) or []
        sid = path.split("/")[-1]
        timed = sorted((e for e in ev if isinstance(e.get("t"), int)), key=lambda e: e["t"])
        if path in runs_by_session:
            role = "runs"
        elif path in uploads_by_session:
            role = "upload"
        else:
            role = "other"
        sd = os.path.join(out, "attacks", a["dir"], "sessions")
        if role == "runs":
            name = l1_dir[path]
            os.symlink(os.path.join("..", "..", "..", "..", "level1", "sessions", name),
                       os.path.join(sd, name))
        else:
            name = f"{utc(timed[0]['t'])[:19].replace('-', '').replace(':', '').replace(' ', 'T')}_{s['ip']}_{sid}"
            os.makedirs(os.path.join(sd, name))
            with open(os.path.join(sd, name, "events.jsonl"), "w") as g:
                for e in ev:
                    g.write(json.dumps(e, separators=(",", ":")) + "\n")
        tag = sid
        for e in timed:
            k = e.get("e")
            if k == "exec":
                kind = "RUN*" if e.get("k") == "TRACKED" else "exec"
                txt = f"{kind:5} pid {e['p']}: {short(e.get('v') or [e.get('f')])}"
            elif k == "file_close" and e.get("w") and real_path(e.get("f")):
                txt = f"write pid {e['p']}: {e.get('f')}  ({'copy captured' if e.get('o') else 'no copy'})"
            elif k == "connect" and e.get("a") not in ("0.0.0.0", None):
                txt = f"conn  pid {e['p']}: {e.get('a')}:{e.get('r')}"
            else:
                continue
            a["lines"].append((e["t"], f"{utc(e['t'])}  [{tag}] {txt}"))
        for e in ev:
            if not isinstance(e.get("t"), int):
                a["lines"].append((timed[-1]["t"] if timed else 0,
                                   f"(summary, no time)        [{tag}] {e.get('e')} pid {e.get('p')}: "
                                   f"{e.get('a') or e.get('f')} port {e.get('r', '-')}  x{e.get('count')}"))
        a["info"][path] = {
            "session": path, "folder": f"sessions/{name}", "role": role,
            "start_utc": utc(timed[0]["t"]) if timed else "-",
            "end_utc": utc(timed[-1]["t"]) if timed else "-",
            "commands": s.get("cmds"), "execs": s.get("execs"),
            "runs": len(runs_by_session.get(path, [])),
        }

# ------------------------------------------------------------ write out
index_rows, outside = [], []
for a in attacks:
    d = os.path.join(out, "attacks", a["dir"])
    paths = [p for _, _, p in a["sessions"]]
    a_runs = [r for p in paths for r in runs_by_session.get(p, [])]
    links, shas = [], set()
    for r in sorted(a_runs, key=lambda r: r["exec_ts"]):
        if r.get("sha256") and r.get("link_quality") in VALID:
            shas.add(r["sha256"])
        w = r["_write_session"]
        if w is None:
            where = "file not captured"
        elif w == r["_exec_session"]:
            where = "same session"
        elif w in attack_of and attack_of[w] is a:
            where = "other session in this attack"
        else:
            where = "OUTSIDE this attack"
            outside.append({"attack": a["id"], "run_session": r["_exec_session"],
                            "upload_session": w, "file": r.get("exec_filename"),
                            "upload_attack": attack_of[w]["id"] if w in attack_of else None})
        links.append({"run_time_utc": utc(r["exec_ts"]), "run_session": r["_exec_session"],
                      "pid": r["pid"], "file": r.get("exec_filename"),
                      "sha256": r.get("sha256") if r.get("link_quality") in VALID else None,
                      "uploaded_in_session": w, "uploaded_at_utc": utc(r.get("close_ts")) if w else None,
                      "upload_location": where})
    for sha in sorted(shas):
        os.symlink(os.path.join("..", "..", "..", "..", "..", "samples", sha),
                   os.path.join(d, "samples", sha))
    sess = [a["info"][p] for p in paths]
    start, end = a["sessions"][0][0], max(x[1] for x in a["sessions"])
    roles = defaultdict(int)
    for x in sess:
        roles[x["role"]] += 1
    meta = {"attack": a["id"], "ip": a["ip"], "start_utc": utc(start), "end_utc": utc(end),
            "window_min": WINDOW_MIN, "sessions": sess, "runs": links}
    with open(os.path.join(d, "attack.json"), "w") as g:
        json.dump(meta, g, indent=1)
    with open(os.path.join(d, "timeline.txt"), "w") as g:
        g.write(f"attack {a['id']}  ip {a['ip']}\n{utc(start)} -> {utc(end)} UTC\n"
                f"{len(sess)} sessions: {roles['runs']} with runs, {roles['upload']} upload only, "
                f"{roles['other']} other\n[...] = session id; RUN* = executed upload\n\n")
        for _, l in sorted(a["lines"], key=lambda x: x[0]):
            g.write(l + "\n")
    index_rows.append({
        "attack": a["id"], "dir": a["dir"], "ip": a["ip"],
        "start_utc": utc(start), "end_utc": utc(end),
        "duration_min": round((end - start) / 6e10, 1),
        "sessions": len(sess), "sessions_with_runs": roles["runs"],
        "upload_only_sessions": roles["upload"], "other_sessions": roles["other"],
        "runs": len(a_runs),
        "runs_without_file": sum(1 for x in links if x["upload_location"] == "file not captured"),
        "samples": " ".join(sorted(shas)),
    })

with open(os.path.join(out, "index.csv"), "w", newline="") as g:
    w = csv.DictWriter(g, fieldnames=list(index_rows[0]))
    w.writeheader()
    w.writerows(index_rows)

run_sessions_in = sum(r["sessions_with_runs"] for r in index_rows)
upload_sessions = set(uploads_by_session) - set(runs_by_session)
summary = {
    "window_min": WINDOW_MIN,
    "attacks": len(index_rows),
    "ips": len({r["ip"] for r in index_rows}),
    "sessions": sum(r["sessions"] for r in index_rows),
    "sessions_with_runs": run_sessions_in,
    "upload_only_sessions": sum(r["upload_only_sessions"] for r in index_rows),
    "upload_only_sessions_total": len(upload_sessions),
    "other_sessions": sum(r["other_sessions"] for r in index_rows),
    "runs": sum(r["runs"] for r in index_rows),
    "runs_without_file": sum(r["runs_without_file"] for r in index_rows),
    "attacks_with_1_session": sum(1 for r in index_rows if r["sessions"] == 1),
    "uploads_outside_their_attack": len(outside),
    "outside_details": outside,
}
with open(os.path.join(out, "summary.json"), "w") as g:
    json.dump(summary, g, indent=1)

with open(os.path.join(out, "README.md"), "w") as g:
    g.write(f"""# Level 2 attack chains: sessions of one IP joined into attacks

Built by `scripts/build_level2.py` (run `build_level1.py` first). October
2026, sessions by start time, 192.168.100.0/24 excluded. Times are UTC.

## Rule
An attack = all logged-in sessions from the same IP where each session
starts at most {WINDOW_MIN} minutes after the latest end of the sessions
before it. Only attacks with at least one run (executed upload) are kept.

## Files
- `index.csv`: one row per attack.
- `summary.json`: totals and checks (uploads that fall outside their
  attack are listed under `outside_details`).
- `attacks/<id>_<start>_<ip>/`
  - `timeline.txt`: all sessions of the attack merged in time order.
    `[...]` is the session id. Shows program starts (RUN* = executed
    upload), files written to real paths, outgoing connections, and summary
    events without a timestamp.
  - `attack.json`: the sessions (role: runs / upload / other) and every
    run with where its file was uploaded.
  - `sessions/`: sessions with runs link to their Level 1 folder; upload
    and other sessions have their full `events.jsonl` here.
  - `samples/`: links to the captured files in `samples/`.
- `notes/`: for your own notes.

## Session roles
- runs: an uploaded file was executed (these are the 1,307 Level 1 sessions)
- upload: wrote a file that was executed in another session
- other: logged in but neither of the above (for example only commands)

## Caveats
- One IP is not always one attacker (Tor exits, shared servers). Check the
  content of the timeline, not only the IP.
- Captured files are often incomplete; hashes identify our copy only.
""")

print(json.dumps({k: v for k, v in summary.items() if k != "outside_details"}, indent=1))
