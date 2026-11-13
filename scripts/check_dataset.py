#!/usr/bin/env python3
"""Check the October dataset: assumptions, consistency, Level 1 and 2.

Usage: python3 scripts/check_dataset.py [CSDA folder]
Prints PASS/FAIL per check and the final numbers. Reads only.
"""

import collections
import csv
import datetime
import glob
import hashlib
import json
import os
import struct
import sys

B = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
LOG = "/home/controller/bpftests/log/"
VALID = {"same-session", "same-ip-same-path"}
LO = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc).timestamp() * 1e9
HI = datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc).timestamp() * 1e9
fails = 0


def check(name, ok, detail=""):
    global fails
    fails += not ok
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))


def rel(p):
    p = p[len(LOG):] if p.startswith(LOG) else p
    return p[:-9] if p.endswith("/log.json") else p


def writer_of(r):
    if r.get("close_log"):
        return rel(r["close_log"])
    if str(r.get("ondisk") or "").startswith(LOG):
        return "/".join(r["ondisk"][len(LOG):].split("/")[:4])
    return None


# ------------------------------------------------------------ load json
d = json.load(open(os.path.join(B, "malware-samples_october.json")))
runs = d["samples"]
for r in runs:
    r["_es"] = rel(r["exec_log"])
    r["_ws"] = writer_of(r)
need = collections.defaultdict(set)
for r in runs:
    need[r["_es"]].add(("exec", r["pid"], r["exec_ts"]))
    if r["_ws"] and r.get("close_ts"):
        need[r["_ws"]].add(("close", r.get("close_filename"), r["close_ts"], r.get("ondisk")))

# ------------------------------------------------ scan sessions.jsonl
sess = {}
exec_paths = {(r["ip"], r["exec_filename"]) for r in runs}
all_writes = collections.defaultdict(list)    # (ip, path) -> [(t, boot)] every write, copy or not
found = {}                       # (session, key) -> boot ns
spread_max = 0.0
bad_start = []
n_lines = 0
with open(os.path.join(B, "sessions.jsonl")) as f:
    for line in f:
        n_lines += 1
        s = json.loads(line)
        p = s["path"]
        ev = s.pop("ev", None) or []
        sess[p] = s
        timed = [e for e in ev if isinstance(e.get("t"), int)]
        if timed:
            t0 = min(e["t"] for e in timed)
            if not (LO <= t0 < HI):
                bad_start.append(p)
            boots = [e["t"] - e["m"] for e in timed if isinstance(e.get("m"), int)]
            if boots:
                spread_max = max(spread_max, (max(boots) - min(boots)) / 1e9)
        for e in timed:
            if e.get("e") == "file_close" and e.get("w") and (s["ip"], e.get("f")) in exec_paths \
                    and isinstance(e.get("m"), int):
                all_writes[(s["ip"], e["f"])].append((e["t"], e["t"] - e["m"]))
        if p in need:
            for e in timed:
                if not isinstance(e.get("m"), int):
                    continue
                if e.get("e") == "exec" and str(e.get("k", "")).upper() == "TRACKED":
                    found[(p, ("exec", str(e["p"]), e["t"]))] = e["t"] - e["m"]
                if e.get("e") == "file_close" and e.get("w") and e.get("o"):
                    found[(p, ("close", e.get("f"), e["t"], e.get("o")))] = e["t"] - e["m"]

print("== assumptions")
# 1 session time from events
check("1 every session starts in October (first event time, not folder name)", not bad_start,
      f"{len(bad_start)} outside")
check("1 sessions.jsonl has one line per session path", len(sess) == n_lines)
# 2 internal range excluded
check("2 no 192.168.100.0/24 in sessions.jsonl or json",
      not any(s["ip"].startswith("192.168.100.") for s in sess.values())
      and not any(r["ip"].startswith("192.168.100.") for r in runs))
check("2 every run is in October", all(LO <= r["exec_ts"] < HI for r in runs))
# 3 never link across IPs
valid = [r for r in runs if r["link_quality"] in VALID]
check("3 every valid link: upload session has the same IP as the run",
      all(sess[r["_ws"]]["ip"] == r["ip"] for r in valid if r["_ws"] in sess)
      and all(r["_ws"] in sess for r in valid))
# 5 same VM run, before the run, same path
diff_boot = [r for r in valid
             if abs(found.get((r["_ws"], ("close", r["close_filename"], r["close_ts"], r["ondisk"])), 0)
                    - found.get((r["_es"], ("exec", str(r["pid"]), r["exec_ts"])), 1e30)) >= 5e9]
check("5 every valid link: upload in the same VM run as the run", not diff_boot, f"{len(diff_boot)} differ")
check("5 every valid link: upload before the run", all(r["close_ts"] <= r["exec_ts"] for r in valid))
check("5 every valid link: same path as the executed file",
      all(r["close_filename"] == r["exec_filename"] for r in valid))
newer = []
for r in valid:
    b = found.get((r["_ws"], ("close", r["close_filename"], r["close_ts"], r["ondisk"])))
    if b is not None and any(r["close_ts"] < t <= r["exec_ts"] and abs(bb - b) < 5e9
                             for t, bb in all_writes[(r["ip"], r["exec_filename"])]):
        newer.append(r)
check("5 every valid link is the last write of the file before the run", not newer, f"{len(newer)} not")
xr = [r for r in runs if r["link_quality"] == "crosses-vm-reset"]
xr_ok = [r for r in xr
         if abs(found.get((r["_ws"], ("close", r["close_filename"], r["close_ts"], r["ondisk"])), 0)
                - found.get((r["_es"], ("exec", str(r["pid"]), r["exec_ts"])), 0)) >= 5e9]
check("5 every crosses-vm-reset link really is in another VM run", len(xr_ok) == len(xr),
      f"{len(xr) - len(xr_ok)} not")
# 6 no session spans a reset
check("6 no session spans a VM reset (boot estimate spread < 5 s)", spread_max < 5,
      f"max spread {spread_max:.2f} s")

print("== json <-> sessions.jsonl")
check("every run's session exists and is logged in",
      all(r["_es"] in sess and sess[r["_es"]]["authed"] for r in runs))
miss = [r for r in runs if (r["_es"], ("exec", str(r["pid"]), r["exec_ts"])) not in found]
check("every run is the same TRACKED exec (pid + time) in the telemetry", not miss, f"{len(miss)} missing")
missw = [r for r in valid if (r["_ws"], ("close", r["close_filename"], r["close_ts"], r["ondisk"])) not in found]
check("every valid link's write exists in the writing session", not missw, f"{len(missw)} missing")
tracked = {p for p, s in sess.items() if s.get("tracked")}
check("sessions with TRACKED execs: telemetry = json", tracked == {r["_es"] for r in runs},
      f"telemetry {len(tracked)}, json {len({r['_es'] for r in runs})}")

print("== json <-> samples/")
files = {n: os.path.join(B, "samples", n) for n in os.listdir(os.path.join(B, "samples"))}
wrong = []
for n, p in files.items():
    h = hashlib.sha256()
    with open(p, "rb") as g:
        for chunk in iter(lambda: g.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != n:
        wrong.append(n)
check(f"all {len(files)} files in samples/ match their SHA-256", not wrong, f"{len(wrong)} mismatch")
ref = set()
for r in runs:
    for x in (r, r.get("finder_link") or {}, r.get("previous_link") or {}):
        if x.get("sha256"):
            ref.add(x["sha256"])
check("every sha256 in the json (incl. old links) is in samples/", ref <= files.keys(),
      f"{len(ref - files.keys())} missing")
check("every file in samples/ is referenced in the json", files.keys() <= ref, f"{len(files.keys() - ref)} not")
check("json sizes match file sizes",
      all(os.path.getsize(files[r["sha256"]]) == r["size"] for r in runs if r.get("sha256")))
q = collections.Counter(r["link_quality"] for r in runs)
vsha = {r["sha256"] for r in valid}
c = d["counts"]
real = {"runs": len(runs), "sessions": len({r["_es"] for r in runs}), "ips": len({r["ip"] for r in runs}),
        "link_quality": dict(q), "unique_sha256_executed_valid_link": len(vsha)}
check("json counts block matches the data", all(c[k] == v for k, v in real.items()),
      str({k: (c[k], v) for k, v in real.items() if c[k] != v}))

print("== Level 1")
L1 = os.path.join(B, "chains", "level1")
l1 = list(csv.DictReader(open(os.path.join(L1, "index.csv"))))
check("level1: one folder per json session", len(l1) == len({r["_es"] for r in runs})
      == len(os.listdir(os.path.join(L1, "sessions"))))
l1runs = []
for row in l1:
    m = json.load(open(os.path.join(L1, "sessions", row["dir"], "session.json")))
    l1runs += m["runs"]
check("level1: total runs = json runs", len(l1runs) == len(runs))
check("level1: every DESCENDANT has a parent run in its session",
      all(x["parent_run"] for x in l1runs if x["role"] == "DESCENDANT"))
check("level1: runs with a file = valid links", sum(1 for x in l1runs if x["sha256"]) == len(valid))
broken = [p for p in glob.glob(os.path.join(L1, "sessions", "*", "samples", "*")) if not os.path.exists(p)]
check("level1: no broken sample links", not broken, f"{len(broken)} broken")

print("== Level 2")
L2 = os.path.join(B, "chains", "level2")
l2 = list(csv.DictReader(open(os.path.join(L2, "index.csv"))))
seen = collections.Counter()
for row in l2:
    m = json.load(open(os.path.join(L2, "attacks", row["dir"], "attack.json")))
    for s in m["sessions"]:
        seen[s["session"]] += 1
check("level2: every session is in at most one attack", max(seen.values()) == 1)
check("level2: every run session is in an attack", {r["_es"] for r in runs} <= set(seen))
check("level2: every valid upload session is in the same attack as its run",
      json.load(open(os.path.join(L2, "summary.json")))["uploads_outside_their_attack"] == 0)
check("level2: total runs = json runs", sum(int(x["runs"]) for x in l2) == len(runs))
broken = [p for p in glob.glob(os.path.join(L2, "attacks", "*", "**"), recursive=True)
          if os.path.islink(p) and not os.path.exists(p)]
check("level2: no broken links", not broken, f"{len(broken)} broken")

print("== Level 3")
L3 = os.path.join(B, "chains", "level3")
l3 = list(csv.DictReader(open(os.path.join(L3, "index.csv"))))
in_camp = collections.Counter()
for row in l3:
    m = json.load(open(os.path.join(L3, "campaigns", row["dir"], "campaign.json")))
    for x in m["attack_list"]:
        in_camp[x["attack"]] += 1
check("level3: every attack is in exactly one campaign",
      set(in_camp) == {x["attack"] for x in l2} and max(in_camp.values()) == 1)
check("level3: totals match level2 (attacks, sessions, runs)",
      sum(int(x["attacks"]) for x in l3) == len(l2)
      and sum(int(x["sessions"]) for x in l3) == sum(int(x["sessions"]) for x in l2)
      and sum(int(x["runs"]) for x in l3) == len(runs))
broken = [p for p in glob.glob(os.path.join(L3, "campaigns", "*", "attacks", "*")) if not os.path.exists(p)]
check("level3: no broken links", not broken, f"{len(broken)} broken")

# 7 completeness of captured ELF files (documented, not a pass/fail)
comp = collections.Counter()
for n in vsha:
    with open(files[n], "rb") as g:
        b = g.read()
    if b[:4] != b"\x7fELF":
        comp["not ELF"] += 1
        continue
    try:
        e = "<" if b[5] == 1 else ">"
        if b[4] == 2:
            phoff, shoff = struct.unpack(e + "QQ", b[32:48])
            phes, phn, shes, shn = struct.unpack(e + "HHHH", b[54:62])
            ends = [struct.unpack(e + "IIQQQQQQ", b[phoff + i * phes: phoff + (i + 1) * phes]) for i in range(phn)]
            need_sz = max([p[2] + p[5] for p in ends] + [shoff + shn * shes if shoff else 0])
        else:
            phoff, shoff = struct.unpack(e + "II", b[28:36])
            phes, phn, shes, shn = struct.unpack(e + "HHHH", b[42:50])
            ends = [struct.unpack(e + "IIIIIIII", b[phoff + i * phes: phoff + (i + 1) * phes]) for i in range(phn)]
            need_sz = max([p[1] + p[4] for p in ends] + [shoff + shn * shes if shoff else 0])
        comp["ELF complete" if len(b) >= need_sz else "ELF incomplete"] += 1
    except struct.error:
        comp["ELF incomplete (header cut)"] += 1

print("\n== numbers")
a = [s for s in sess.values() if s["authed"]]
rows = [
    ("SSH connections (sessions)", len(sess)),
    ("unique IPs", len({s['ip'] for s in sess.values()})),
    ("logged in", f"{len(a)} ({100 * len(a) / len(sess):.1f}%)"),
    ("logged-in IPs", len({s['ip'] for s in a})),
    ("sessions with commands", sum(bool(s.get('cmds')) for s in sess.values())),
    ("sessions with an executed upload", len({r['_es'] for r in runs})),
    ("IPs with an executed upload", len({r['ip'] for r in runs})),
    ("executions (runs)", len(runs)),
    ("  file uploaded in same session", q["same-session"]),
    ("  file uploaded in other session, same IP + VM run", q["same-ip-same-path"]),
    ("  no valid file", len(runs) - len(valid)),
    ("files in samples/", len(files)),
    ("distinct files linked to an execution", len(vsha)),
    ("files in samples/ not linked to an execution", len(files.keys() - vsha)),
    ("linked files by completeness", dict(comp)),
    ("level2 attacks (60 min window)", len(l2)),
    ("level2 sessions in attacks", sum(int(x['sessions']) for x in l2)),
    ("level3 campaigns", len(l3)),
    ("  with runs / upload only / other",
     f"{sum(int(x['sessions_with_runs']) for x in l2)} / {sum(int(x['upload_only_sessions']) for x in l2)}"
     f" / {sum(int(x['other_sessions']) for x in l2)}"),
]
for k, v in rows:
    print(f"   {k:52s} {v}")
print("\nALL CHECKS PASSED" if not fails else f"\n{fails} CHECK(S) FAILED")
