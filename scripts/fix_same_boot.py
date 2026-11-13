#!/usr/bin/env python3
"""Relink runs to uploads from the same VM run (boot) only.

The honeypot VM is reset regularly; uploaded files do not survive a reset.
Boot time of any event = t - m (t = event time, m = guest monotonic ns).

For every run: the file is the latest earlier write (file_close with
written + ondisk copy) of the same path by the same IP in the same boot.
  * unchanged if that is the current valid link
  * relinked (match=relinked-same-boot, old link under previous_link)
  * the last write before the run has no copy: last-write-not-captured
  * no such write: a valid link becomes crosses-vm-reset (write in an
    earlier boot), written-after-run, or weak (different path)
    (link fields kept, as for invalid links); others stay as they are
Every run gets exec_vm_boot_utc.

Usage:
  python3 scripts/fix_same_boot.py plan  [CSDA]   -> writes plan, lists missing copies
  python3 scripts/fix_same_boot.py apply [CSDA]   -> applies plan to the json
"""

import collections
import datetime
import json
import os
import sys

LOG = "/home/controller/bpftests/log/"
VALID = {"same-session", "same-ip-same-path"}
SAME_BOOT_NS = 5e9

mode = sys.argv[1]
root = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else ".")
jpath = os.path.join(root, "malware-samples_october.json")
plan_path = os.path.join(root, "scripts", "fix_same_boot.plan.json")


def rel(p):
    p = p[len(LOG):] if p.startswith(LOG) else p
    return p[:-9] if p.endswith("/log.json") else p


def utc(ns):
    return datetime.datetime.fromtimestamp(ns / 1e9, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def writer_of(r):
    if r.get("close_log"):
        return rel(r["close_log"])
    if str(r.get("ondisk") or "").startswith(LOG):
        return "/".join(r["ondisk"][len(LOG):].split("/")[:4])
    return None


data = json.load(open(jpath))
runs = data["samples"]

if mode == "plan":
    pairs = {(r["ip"], r["exec_filename"]) for r in runs}
    need = collections.defaultdict(set)
    for r in runs:
        need[rel(r["exec_log"])].add(r["exec_ts"])
    closes = collections.defaultdict(list)
    exec_boot = {}
    with open(os.path.join(root, "sessions.jsonl")) as f:
        for line in f:
            s = json.loads(line)
            p, ip = s["path"], s["ip"]
            for e in s.get("ev") or []:
                if not (isinstance(e.get("t"), int) and isinstance(e.get("m"), int)):
                    continue
                # every write counts, with or without a captured copy
                if e.get("e") == "file_close" and e.get("w") and (ip, e.get("f")) in pairs:
                    closes[(ip, e["f"])].append((e["t"], e["t"] - e["m"], e.get("o"), p, e["f"]))
                elif e.get("e") == "exec" and e["t"] in need.get(p, ()):
                    exec_boot[(p, e["t"])] = e["t"] - e["m"]

    known = {}
    for r in runs:
        for x in (r, r.get("finder_link") or {}, r.get("previous_link") or {}):
            if x.get("ondisk") and x.get("sha256"):
                known[x["ondisk"]] = (x["sha256"], x.get("size"))

    plan, missing, trans = [], set(), collections.Counter()
    for i, r in enumerate(runs):
        es = rel(r["exec_log"])
        b = exec_boot.get((es, r["exec_ts"]))
        if b is None:
            raise SystemExit(f"exec boot not found for run {i} {es}")
        cand = [c for c in closes.get((r["ip"], r["exec_filename"]), [])
                if c[0] <= r["exec_ts"] and abs(c[1] - b) < SAME_BOOT_NS]
        step = {"i": i, "exec_boot_ns": b}
        last = max(cand, key=lambda c: c[0]) if cand else None
        if last and last[2] is None:
            # the last write before the run has no copy: the executed version was not captured
            step["action"] = "last-write-not-captured" if r["link_quality"] in VALID else "keep-no-file"
        elif cand:
            t, _, o, ws, fn = last
            lq = "same-session" if ws == es else "same-ip-same-path"
            if r["link_quality"] in VALID and r.get("ondisk") == o and r.get("close_ts") == t:
                step["action"] = "unchanged"
            else:
                step.update(action="relink", close_ts=t, ondisk=o, writer=ws, close_filename=fn, link_quality=lq)
                if o not in known:
                    missing.add(o)
        elif r["link_quality"] not in VALID:
            step["action"] = "keep-no-file"
        elif r["close_ts"] > r["exec_ts"]:
            step["action"] = "written-after-run"
        elif r.get("close_filename") != r["exec_filename"]:
            step["action"] = "weak"
        else:
            step["action"] = "crosses-vm-reset"
        trans[(r["link_quality"], step["action"] if step["action"] != "relink" else "relink->" + step["link_quality"])] += 1
        plan.append(step)
    json.dump({"plan": plan, "missing_copies": sorted(missing),
               "known": {k: list(v) for k, v in known.items()}}, open(plan_path, "w"))
    for (a, b), n in sorted(trans.items()):
        print(f"{n:5}  {a:18} -> {b}")
    print(f"copies to fetch: {len(missing)}")
    for o in sorted(missing):
        print("  ", o)

elif mode == "apply":
    P = json.load(open(plan_path))
    known = {k: tuple(v) for k, v in P["known"].items()}
    fetched_path = os.path.join(root, "scripts", "fix_same_boot.fetched.json")
    if os.path.exists(fetched_path):
        known.update({k: tuple(v) for k, v in json.load(open(fetched_path)).items()})
    for step in P["plan"]:
        r = runs[step["i"]]
        r["exec_vm_boot_utc"] = utc(step["exec_boot_ns"])
        a = step["action"]
        if a == "relink":
            sha, size = known[step["ondisk"]]
            r["previous_link"] = {k: r.get(k) for k in
                                  ("match", "link_quality", "close_session", "close_filename", "close_ts",
                                   "ondisk", "sha256", "size")}
            ws = step["writer"]
            r.update({
                "match": "relinked-same-boot", "link_quality": step["link_quality"],
                "close_ts": step["close_ts"], "close_session": "/".join(ws.split("/")[2:4]),
                "close_filename": step["close_filename"], "ondisk": step["ondisk"],
                "resolved_ondisk": step["ondisk"], "close_log": LOG + ws + "/log.json",
                "sha256": sha, "size": size, "local_copy": f"samples/{sha}", "exists": True,
                "note": "relinked to the latest earlier write of the same path by the same IP in the same "
                        "VM run (boot); previous link under previous_link",
            })
        elif a in ("crosses-vm-reset", "written-after-run", "weak", "last-write-not-captured"):
            r["link_quality"] = a
            r["note"] = {
                "crosses-vm-reset": "the linked write happened in an earlier VM run (before a reset), so it "
                                    "cannot be the executed file",
                "written-after-run": "the linked write happened after the run, so it cannot be the executed file",
                "weak": "the linked write is a different path (file ID reused), so it is not the executed file",
                "last-write-not-captured": "the file was written again after the linked write and before the "
                                           "run; that last write has no captured copy",
            }[a] + ("" if a == "last-write-not-captured" else
                    "; no write of this path by this IP before the run in the same VM run")
    q = collections.Counter(r["link_quality"] for r in runs)
    valid = {r["sha256"] for r in runs if r["link_quality"] in VALID}
    cur = {r["sha256"] for r in runs if r.get("sha256")}
    note = ("; 2026-11-03: links must come from the same VM run (boot = t - m) and be the last write of the "
            "path before the run: runs relinked within the boot (match=relinked-same-boot, old link under "
            "previous_link) or marked crosses-vm-reset / written-after-run / weak / last-write-not-captured")
    if "links must come from the same VM run" not in data["corrections"]:
        data["corrections"] += note
    else:
        data["corrections"] = data["corrections"].split("; 2026-11-03: links must")[0] + note
    data["link_quality"] = ("same-session / same-ip-same-path = file written in the same VM run and supported by "
                            "the data; crosses-vm-reset / written-after-run / last-write-not-captured / weak / invalid = file not used; "
                            "none = no file")
    data["counts"]["link_quality"] = dict(q)
    data["counts"]["unique_sha256_after_correction"] = len(cur)
    data["counts"]["unique_sha256_executed_valid_link"] = len(valid)
    tmp = jpath + ".tmp"
    with open(tmp, "w") as g:
        json.dump(data, g, indent=1)
    os.replace(tmp, jpath)
    print(json.dumps(data["counts"], indent=1))
