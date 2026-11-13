#!/usr/bin/env python3
"""Level 1 attack chains: one directory per SSH session.

Inputs (CSDA folder):
  malware-samples_october.json   executed uploads (runs) with file links
  sessions.jsonl                 per-session telemetry (ev = events)
  samples/                       captured files, named by sha256

Sessions included: every session with at least one run (1,307).
Sessions that only uploaded a file run elsewhere get no folder; each run
records the session and time its file was uploaded (valid links only:
link_quality same-session / same-ip-same-path). They return at Level 2.

Output: chains/level1/ (README.md, index.csv, sessions/<dir>/, notes/)
Usage:  python3 scripts/build_level1.py [CSDA folder]
"""

import csv
import datetime
import json
import os
import shutil
import sys
from collections import defaultdict

VALID = {"same-session", "same-ip-same-path"}
ARGV_MAX = 500

root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
out = os.path.join(root, "chains", "level1")
LOGDIR = "/home/controller/bpftests/log/"


def rel_session(log_path):
    """honeypot log.json path -> sessions.jsonl 'path' value"""
    p = log_path[len(LOGDIR):] if log_path.startswith(LOGDIR) else log_path
    return p[: -len("/log.json")] if p.endswith("/log.json") else p


def utc(ns):
    if not isinstance(ns, int):
        return "-"
    return datetime.datetime.fromtimestamp(ns / 1e9, datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f")[:-3]


def short(argv):
    s = " ".join(str(a) for a in argv) if isinstance(argv, list) else str(argv)
    return s if len(s) <= ARGV_MAX else s[:ARGV_MAX] + f" …({len(s)} chars, full in events.jsonl)"


# ---------------------------------------------------------------- runs
runs = json.load(open(os.path.join(root, "malware-samples_october.json")))["samples"]
runs_by_session = defaultdict(list)    # sessions.jsonl path -> runs executed there
writes_by_session = defaultdict(list)  # sessions.jsonl path -> runs whose file was written there
for r in runs:
    r["_exec_session"] = rel_session(r["exec_log"])
    runs_by_session[r["_exec_session"]].append(r)
    # relinked runs have close_log null; their writer session is in ondisk
    writer = (rel_session(r["close_log"]) if r.get("close_log") else
              "/".join(r["ondisk"][len(LOGDIR):].split("/")[:4])
              if str(r.get("ondisk") or "").startswith(LOGDIR) else None)
    if r.get("link_quality") in VALID and writer:
        r["_write_session"] = writer
        writes_by_session[r["_write_session"]].append(r)
    else:
        r["_write_session"] = None
wanted = set(runs_by_session)


# ------------------------------------------------------- process trees
def build_processes(ev):
    """Process instances from fork events; handles PID reuse by time."""
    inst = []                      # dicts: pid, start, parent(idx), execs
    latest = {}                    # pid -> instance idx (most recent)
    timed = sorted((e for e in ev if isinstance(e.get("t"), int)), key=lambda e: e["t"])

    def get(pid, t):
        if pid not in latest:
            inst.append({"pid": pid, "start": t, "parent": None, "execs": []})
            latest[pid] = len(inst) - 1
        return latest[pid]

    for e in timed:
        if e.get("e") == "fork" and "c" in e:
            parent = get(e["p"], e["t"])
            inst.append({"pid": e["c"], "start": e["t"], "parent": parent,
                         "forked_after_parent_exec": None, "execs": []})
            latest[e["c"]] = len(inst) - 1
        elif e.get("e") == "exec":
            inst[get(e["p"], e["t"])]["execs"].append(e)
    return inst, latest, timed


def instance_at(inst, pid, t):
    best = None
    for i, x in enumerate(inst):
        if x["pid"] == pid and x["start"] <= t:
            best = i
    return best


def descendants(inst, root_idx, t0):
    """instances forked from root after t0 (its exec), recursively."""
    kids = defaultdict(list)
    for i, x in enumerate(inst):
        if x["parent"] is not None:
            kids[x["parent"]].append(i)
    found, stack = set(), [i for i in kids[root_idx] if inst[i]["start"] >= t0]
    while stack:
        i = stack.pop()
        if i in found:
            continue
        found.add(i)
        stack.extend(kids[i])
    return found


def render_tree(inst, idx, depth, lines, only):
    x = inst[idx]
    label = "; ".join(f"[{utc(e['t'])[11:]}] {short(e.get('v') or [e.get('f')])}"
                      f"{'  (TRACKED)' if e.get('k') == 'TRACKED' else ''}"
                      for e in x["execs"]) or "(no exec seen)"
    lines.append("  " * depth + f"pid {x['pid']}: {label}")
    for i, y in enumerate(inst):
        if y["parent"] == idx and i in only:
            render_tree(inst, i, depth + 1, lines, only)


# ------------------------------------------------------------- output
if os.path.exists(out):
    shutil.rmtree(out)
os.makedirs(os.path.join(out, "sessions"))
os.makedirs(os.path.join(out, "notes"))

index_rows = []
tree_stats = defaultdict(int)
seen_paths = set()

with open(os.path.join(root, "sessions.jsonl")) as f:
    for line in f:
        s = json.loads(line)
        path = s["path"]
        if path not in wanted:
            continue
        seen_paths.add(path)
        ev = s.pop("ev", None) or []
        inst, latest, timed = build_processes(ev)
        start = timed[0]["t"] if timed else None
        end = timed[-1]["t"] if timed else None
        sid = path.split("/")[-1]
        dname = f"{utc(start)[:19].replace('-', '').replace(':', '').replace(' ', 'T')}_{s['ip']}_{sid}"
        d = os.path.join(out, "sessions", dname)
        os.makedirs(os.path.join(d, "samples"))

        # raw events
        with open(os.path.join(d, "events.jsonl"), "w") as g:
            for e in ev:
                g.write(json.dumps(e, separators=(",", ":")) + "\n")

        here = sorted(runs_by_session.get(path, []), key=lambda r: r["exec_ts"])
        written = writes_by_session.get(path, [])

        # sample links
        shas = set()
        for r in here + written:
            if r.get("sha256") and r.get("local_copy") and os.path.exists(os.path.join(root, r["local_copy"])):
                shas.add(r["sha256"])
        for sha in sorted(shas):
            os.symlink(os.path.join("..", "..", "..", "..", "..", "samples", sha),
                       os.path.join(d, "samples", sha))

        # session-local trees from fork events: a run's parent is the most
        # recent earlier run in the same process or in an ancestor process
        tree_lines, run_info = [], []
        for r in here:
            r["_idx"] = instance_at(inst, int(r["pid"]), r["exec_ts"])
        run_at = defaultdict(list)                      # instance idx -> runs
        for r in here:
            if r["_idx"] is not None:
                run_at[r["_idx"]].append(r)
        for r in here:
            r["_parent"] = None
            i, first = r["_idx"], True
            while i is not None and r["_parent"] is None:
                earlier = [x for x in run_at[i] if x is not r and x["exec_ts"] < r["exec_ts"]
                           and (first or x["exec_ts"] < inst[child]["start"])]
                if earlier:
                    r["_parent"] = max(earlier, key=lambda x: x["exec_ts"])
                child, i, first = i, inst[i]["parent"], False
        roots = [r for r in here if r["_parent"] is None]
        root_no = {id(x): n + 1 for n, x in enumerate(roots)}
        local_tree = {}
        for r in here:
            x = r
            while x["_parent"] is not None:
                x = x["_parent"]
            local_tree[id(r)] = f"t{root_no[id(x)]}"
        for r in here:
            role = "ROOT" if r["_parent"] is None else "DESCENDANT"
            check = "agrees" if role == r.get("role") else f"differs (finder: {r.get('role')})"
            tree_stats[f"{role}, finder {check.split(' ')[0]}"] += 1
            if r.get("sha256") and r.get("link_quality") in VALID:
                file_state = f"captured: samples/{r['sha256']}"
            elif r.get("sha256"):
                file_state = "file not captured (finder link points to a file of another IP or path; ignored)"
            else:
                file_state = "file not captured"
            upload = r["_write_session"]
            run_info.append({
                "exec_time_utc": utc(r["exec_ts"]), "pid": r["pid"], "role": role,
                "tree": local_tree[id(r)],
                "parent_run": None if r["_parent"] is None else
                    f"pid {r['_parent']['pid']} {r['_parent'].get('exec_filename')} at {utc(r['_parent']['exec_ts'])}",
                "finder_role": r.get("role"), "finder_tree": r.get("tree"), "finder_role_check": check,
                "exec_filename": r.get("exec_filename"), "args": r.get("args"),
                "sha256": r.get("sha256") if r.get("link_quality") in VALID else None,
                "size": r.get("size") if r.get("link_quality") in VALID else None,
                "link_quality": r.get("link_quality"), "file": file_state,
                "uploaded_in_session": None if upload is None else ("this session" if upload == path else upload),
                "uploaded_at_utc": utc(r.get("close_ts")) if upload else None,
            })
        for r in roots:
            ridx = instance_at(inst, int(r["pid"]), r["exec_ts"])
            tree_lines.append(f"== tree {local_tree[id(r)]}  root pid {r['pid']}  "
                              f"{r.get('exec_filename')}  sha256 {r.get('sha256') if r.get('link_quality') in VALID else '-'}")
            if ridx is None:
                tree_lines.append("  (root process not found in fork/exec events)")
            else:
                render_tree(inst, ridx, 1, tree_lines, descendants(inst, ridx, r["exec_ts"]))
            tree_lines.append("")
        with open(os.path.join(d, "tree.txt"), "w") as g:
            g.write("\n".join(tree_lines) or "(no programs run in this session)\n")

        # files written here that were run (here or elsewhere)
        upl = []
        for r in sorted(written, key=lambda r: r.get("close_ts") or 0):
            upl.append({"close_time_utc": utc(r.get("close_ts")), "filename": r.get("close_filename"),
                        "sha256": r.get("sha256"), "size": r.get("size"),
                        "run_in_session": "this session" if r["_exec_session"] == path else r["_exec_session"],
                        "run_time_utc": utc(r["exec_ts"])})

        # readable timeline: execs, written files, connections, summaries
        tl = []
        for e in timed:
            k = e.get("e")
            if k == "exec":
                tag = "RUN*" if e.get("k") == "TRACKED" else "exec"
                tl.append(f"{utc(e['t'])}  {tag:5} pid {e['p']}: {short(e.get('v') or [e.get('f')])}")
            elif k == "file_close" and e.get("w") and str(e.get("f") or "").startswith("/") \
                    and not str(e.get("f")).startswith(("/dev/", "/proc/", "/sys/")):
                cap = "copy captured" if e.get("o") else "no copy"
                tl.append(f"{utc(e['t'])}  write pid {e['p']}: {e.get('f')}  ({cap})")
            elif k == "connect" and e.get("a") not in ("0.0.0.0", None):
                tl.append(f"{utc(e['t'])}  conn  pid {e['p']}: {e.get('a')}:{e.get('r')}")
        for e in ev:
            if not isinstance(e.get("t"), int):
                tl.append(f"(summary, no time) {e.get('e')} pid {e.get('p')}: "
                          f"{e.get('a') or e.get('f')} port {e.get('r', '-')}  x{e.get('count')}")
        with open(os.path.join(d, "timeline.txt"), "w") as g:
            g.write(f"session {path}\nip {s['ip']}\nstart {utc(start)} UTC\nend   {utc(end)} UTC\n"
                    f"RUN* = executed upload (TRACKED). Full events: events.jsonl\n\n")
            g.write("\n".join(tl) + "\n")

        meta = {"dir": dname, "session": path, "ip": s["ip"],
                "start_utc": utc(start), "end_utc": utc(end),
                "events": s.get("events"), "execs": s.get("execs"), "commands": s.get("cmds"),
                "trimmed_at_midnight": bool(s.get("trimmed")),
                "runs": run_info, "files_written_here_and_run": upl}
        with open(os.path.join(d, "session.json"), "w") as g:
            json.dump(meta, g, indent=1)

        n_conn = sum(1 for e in timed if e.get("e") == "connect" and e.get("a") not in ("0.0.0.0", None))
        n_write = sum(1 for e in timed if e.get("e") == "file_close" and e.get("w")
                      and str(e.get("f") or "").startswith("/")
                      and not str(e.get("f")).startswith(("/dev/", "/proc/", "/sys/")))
        kind = "upload here" if any(r["_write_session"] == path for r in here) else "upload in other session"
        index_rows.append({
            "dir": dname, "ip": s["ip"], "start_utc": utc(start), "end_utc": utc(end), "kind": kind,
            "runs": len(here), "trees": len(roots),
            "runs_without_file": sum(1 for r in run_info if r["file"].startswith("file not captured")),
            "files_written_and_run": len(upl), "commands": s.get("cmds"),
            "files_written": n_write, "connections": n_conn,
            "samples": " ".join(sorted(shas)), "session": path,
        })

missing = wanted - seen_paths
index_rows.sort(key=lambda r: r["start_utc"])
with open(os.path.join(out, "index.csv"), "w", newline="") as g:
    w = csv.DictWriter(g, fieldnames=list(index_rows[0]))
    w.writeheader()
    w.writerows(index_rows)

kinds = defaultdict(int)
for r in index_rows:
    kinds[r["kind"]] += 1
summary = {
    "sessions": len(index_rows), "by_kind": dict(kinds),
    "ips": len({r["ip"] for r in index_rows}),
    "runs": sum(r["runs"] for r in index_rows),
    "trees": sum(r["trees"] for r in index_rows),
    "runs_without_file": sum(r["runs_without_file"] for r in index_rows),
    "role_vs_finder": dict(tree_stats),
    "wanted_but_missing_in_sessions_jsonl": sorted(missing),
}
with open(os.path.join(out, "summary.json"), "w") as g:
    json.dump(summary, g, indent=1)

with open(os.path.join(out, "README.md"), "w") as g:
    g.write(f"""# Level 1 attack chains: one directory per SSH session

Built by `scripts/build_level1.py` from `malware-samples_october.json`,
`sessions.jsonl` and `samples/` (October 2026, sessions by start time,
192.168.100.0/24 excluded). Times are UTC.

## Which sessions
Every session where an uploaded file was executed (a "run"): 1,307.
For each run, `session.json` says where its file was uploaded
(`uploaded_in_session`, `uploaded_at_utc`): this session, or another
session of the same IP. Sessions that only uploaded a file get no folder
here; they are joined in at Level 2. Only valid links are used (same
session, or same IP + same path). Links by file ID to other IPs are ignored.

`index.csv` kind: "upload here" = at least one run's file was uploaded in
this session; "upload in other session" = all files came from elsewhere
(or were not captured).

## Files
- `index.csv`: one row per session.
- `summary.json`: totals.
- `sessions/<start>_<ip>_<session>/`
  - `timeline.txt`: readable: program starts (RUN* = executed upload),
    files written to real paths (not pipes, /dev, /proc, /sys) and whether
    a copy was captured, outgoing connections,
    and summary events without a timestamp.
  - `events.jsonl`: every recorded event of the session, unchanged.
  - `tree.txt`: process tree of each executed upload, built from the
    fork events of this session. A run is a ROOT if no earlier run is in
    its own process or a parent process; otherwise it is a DESCENDANT of
    the most recent such run. Trees are numbered t1, t2, ... per session.
  - `session.json`: runs (file, hash, link quality, where it was uploaded,
    parent check) and files written here that were run.
  - `samples/`: links to the captured files in `../../../../../samples/`.
- `notes/`: for your own notes.

## Caveats
- Captured files are often incomplete (honeypot records at most 16 KB per
  write and drops file data first under load). A hash identifies our copy,
  not the original program.
- `finder_role` / `finder_tree`: the honeypot finder's own labels, kept for
  comparison. The finder groups by PID-based subsession labels, which can
  join runs from different sessions (PID reuse). Our roles use only the
  fork events of the session. A lost fork event would make a child look
  like a ROOT.
- Runs marked "file not captured" stay in the chain.
""")

print(json.dumps(summary, indent=1))
