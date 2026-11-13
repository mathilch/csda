#!/usr/bin/env python3
"""Look up SHA-256 hashes on VirusTotal (hash only; no file is uploaded).

Usage: python3 scripts/hash_lookup.py [CSDA folder] [--all] [--shas FILE]
  default:     only executed files whose hash is meaningful (complete programs)
  --all:       every file linked to an execution (uses ~910 of the 500/day quota)
  --shas FILE: also look up the hashes listed in FILE (one per line)

Key: ~/.vt_key (never printed). Results are cached in
triage/hash_lookup/vt_cache.json, so reruns do not repeat lookups.
Output: triage/hash_lookup/vt_results.csv (one row per file).
"""

import csv
import datetime
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

args = sys.argv[1:]
extra = set()
if "--shas" in args:
    i = args.index("--shas")
    extra = set(open(args[i + 1]).read().split())
    del args[i:i + 2]
root = os.path.abspath(next((a for a in args if not a.startswith("--")), "."))
ALL = "--all" in args
VALID = {"same-session", "same-ip-same-path"}
INTERVAL = 16                         # free API: 4 requests per minute
out = os.path.join(root, "triage", "hash_lookup")
os.makedirs(out, exist_ok=True)
cache_path = os.path.join(out, "vt_cache.json")
cache = json.load(open(cache_path)) if os.path.exists(cache_path) else {}
key = open(os.path.expanduser("~/.vt_key")).read().strip()


def kind(b):
    """complete / incomplete program, mixed, or beginning missing"""
    if b[:4] != b"\x7fELF":
        return "mixed with other data" if b.find(b"\x7fELF") > 0 else "beginning missing"
    try:
        e = "<" if b[5] == 1 else ">"
        if b[4] == 2:
            phoff, shoff = struct.unpack(e + "QQ", b[32:48])
            phes, phn, shes, shn = struct.unpack(e + "HHHH", b[54:62])
            ph = [struct.unpack(e + "IIQQQQQQ", b[phoff + i * phes: phoff + (i + 1) * phes]) for i in range(phn)]
            need = max([p[2] + p[5] for p in ph] + [shoff + shn * shes if shoff else 0])
        else:
            phoff, shoff = struct.unpack(e + "II", b[28:36])
            phes, phn, shes, shn = struct.unpack(e + "HHHH", b[42:50])
            ph = [struct.unpack(e + "IIIIIIII", b[phoff + i * phes: phoff + (i + 1) * phes]) for i in range(phn)]
            need = max([p[1] + p[4] for p in ph] + [shoff + shn * shes if shoff else 0])
    except struct.error:
        return "incomplete program"
    return "complete program" if len(b) >= need else "incomplete program"


def lookup(sha):
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha}", headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            a = json.load(r)["data"]["attributes"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False}
        raise
    st = a.get("last_analysis_stats", {})
    ts = lambda x: datetime.datetime.fromtimestamp(x, datetime.timezone.utc).strftime("%Y-%m-%d") if x else None
    return {
        "found": True,
        "malicious": st.get("malicious"), "suspicious": st.get("suspicious"),
        "undetected": st.get("undetected"), "engines": sum(st.values()) if st else None,
        "first_submission": ts(a.get("first_submission_date")),
        "last_analysis": ts(a.get("last_analysis_date")),
        "label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        "type": a.get("type_description"), "names": (a.get("names") or [])[:5],
    }


runs = json.load(open(os.path.join(root, "malware-samples_october.json")))["samples"]
files = {}
for r in runs:
    if r["link_quality"] in VALID:
        f = files.setdefault(r["sha256"], {"paths": set(), "runs": 0})
        f["paths"].add(r["exec_filename"])
        f["runs"] += 1

camp = {}
L3 = os.path.join(root, "chains", "level3")
if os.path.exists(os.path.join(L3, "index.csv")):
    for row in csv.DictReader(open(os.path.join(L3, "index.csv"))):
        m = json.load(open(os.path.join(L3, "campaigns", row["dir"], "campaign.json")))
        for s in m["samples"]:
            camp.setdefault(s, set()).add(row["campaign"])

rows, todo = [], []
for sha, f in sorted(files.items()):
    with open(os.path.join(root, "samples", sha), "rb") as g:
        b = g.read()
    k = kind(b)
    rows.append({"sha256": sha, "size": len(b), "kind": k, "runs": f["runs"],
                 "campaigns": " ".join(sorted(camp.get(sha, []))), "paths": " ".join(sorted(f["paths"]))})
    if (ALL or k == "complete program" or sha in extra) and sha not in cache:
        todo.append(sha)

print(f"files: {len(rows)}; to look up now: {len(todo)}; cached: {sum(1 for r in rows if r['sha256'] in cache)}")
for n, sha in enumerate(todo, 1):
    if n > 1:
        time.sleep(INTERVAL)
    cache[sha] = lookup(sha)
    cache[sha]["checked_utc"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M")
    json.dump(cache, open(cache_path, "w"), indent=1)
    print(f"  {n}/{len(todo)} {sha[:12]} found={cache[sha]['found']}")

fields = ["sha256", "size", "kind", "runs", "campaigns", "paths", "vt_status", "malicious", "engines",
          "first_submission", "label", "type", "names", "checked_utc"]
with open(os.path.join(out, "vt_results.csv"), "w", newline="") as g:
    w = csv.DictWriter(g, fieldnames=fields)
    w.writeheader()
    for r in rows:
        c = cache.get(r["sha256"])
        if c is None:
            r["vt_status"] = "not checked" if r["kind"] == "complete program" else "not checkable (copy damaged)"
        else:
            r["vt_status"] = "found" if c["found"] else "not found"
            for k in ("malicious", "engines", "first_submission", "label", "type", "checked_utc"):
                r[k] = c.get(k)
            r["names"] = " | ".join(c.get("names") or [])
        w.writerow(r)
print("written:", os.path.join(out, "vt_results.csv"))
