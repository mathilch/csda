#!/usr/bin/env python3
"""Structural triage, steps 1 and 2.

Step 1: facts per executed file, read from its bytes only: kind (complete,
incomplete, mixed, beginning missing), processor, 32/64-bit, static or
dynamic, UPX, language markers (Go, GCC, Rust).
Step 2: group copies into programs, by content only:
  * same first KEY bytes (after removing foreign data before the ELF header)
  * shorter copies join the program they are the exact beginning of
  * copies without ELF header join the program of the same path that holds
    most of their 256-byte pieces; the rest are grouped among themselves
Every copy is compared piece by piece (the honeypot's 256-byte capture
unit) with the other copies of its program.

Inputs: malware-samples_october.json, samples/, chains/level3/.
Output: triage/structural/ (files.csv, programs.csv, summary.json, README.md)
Usage:  python3 scripts/structural_triage.py [CSDA folder]
"""

import collections
import csv
import hashlib
import itertools
import json
import os
import struct
import sys

KEY = 4096
PIECE = 256           # capture unit of the honeypot
FRAG_MIN = 0.5        # fragment joins a program holding at least this share of its pieces
SAME_MIN = 0.9        # copy counts as the same program if this share of its pieces is in other copies
VALID = {"same-session", "same-ip-same-path"}
MACHINE = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
           2: "SPARC", 43: "SPARC64", 22: "s390", 243: "RISC-V", 258: "LoongArch"}

root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
out = os.path.join(root, "triage", "structural")
os.makedirs(out, exist_ok=True)

runs = json.load(open(os.path.join(root, "malware-samples_october.json")))["samples"]
info = {}
for r in runs:
    if r["link_quality"] in VALID:
        x = info.setdefault(r["sha256"], {"paths": set(), "runs": 0})
        x["paths"].add(r["exec_filename"])
        x["runs"] += 1
camp = collections.defaultdict(set)
L3 = os.path.join(root, "chains", "level3")
for row in csv.DictReader(open(os.path.join(L3, "index.csv"))):
    for s in json.load(open(os.path.join(L3, "campaigns", row["dir"], "campaign.json")))["samples"]:
        camp[s].add(row["campaign"])
vt = {}
vt_csv = os.path.join(root, "triage", "hash_lookup", "vt_results.csv")
if os.path.exists(vt_csv):
    for row in csv.DictReader(open(vt_csv)):
        vt[row["sha256"]] = row


def elf_facts(b):
    """header facts of an ELF image starting at b[0]"""
    f = {"bits": None, "machine": None, "linking": None, "complete": None}
    try:
        e = "<" if b[5] == 1 else ">"
        f["bits"] = 64 if b[4] == 2 else 32
        f["machine"] = MACHINE.get(struct.unpack(e + "H", b[18:20])[0], str(struct.unpack(e + "H", b[18:20])[0]))
        if b[4] == 2:
            phoff, shoff = struct.unpack(e + "QQ", b[32:48])
            phes, phn, shes, shn = struct.unpack(e + "HHHH", b[54:62])
            ph = [struct.unpack(e + "IIQQQQQQ", b[phoff + i * phes: phoff + (i + 1) * phes]) for i in range(phn)]
            types, ends = [p[0] for p in ph], [p[2] + p[5] for p in ph]
        else:
            phoff, shoff = struct.unpack(e + "II", b[28:36])
            phes, phn, shes, shn = struct.unpack(e + "HHHH", b[42:50])
            ph = [struct.unpack(e + "IIIIIIII", b[phoff + i * phes: phoff + (i + 1) * phes]) for i in range(phn)]
            types, ends = [p[0] for p in ph], [p[1] + p[4] for p in ph]
        f["linking"] = "dynamic" if 3 in types else "static"
        need = max(ends + [shoff + shn * shes if shoff else 0])
        f["complete"] = len(b) >= need
    except (struct.error, IndexError, ValueError):
        pass
    return f


def markers(b):
    m = []
    if b"UPX!" in b[:4096]:
        m.append("UPX")
    if b"\xff Go buildinf:" in b or b"Go build ID:" in b or b"runtime.gopanic" in b:
        m.append("Go")
    if b"GCC: (" in b:
        m.append("GCC")
    if b"/rustc/" in b:
        m.append("Rust")
    return m


def body(sha):
    """file content from the ELF header on (foreign data removed); read on demand"""
    with open(os.path.join(root, "samples", sha), "rb") as g:
        raw = g.read()
    return raw[files[sha]["foreign_prefix"]:]


# ------------------------------------------------------------ step 1
files = {}
for sha in sorted(info):
    with open(os.path.join(root, "samples", sha), "rb") as g:
        raw = g.read()
    off = 0 if raw[:4] == b"\x7fELF" else raw.find(b"\x7fELF")
    content = raw[off:] if off >= 0 else raw
    if off < 0:
        kind = "beginning missing"
    elif off > 0:
        kind = "mixed with other data"
    else:
        kind = None
    f = elf_facts(content) if off >= 0 else {"bits": None, "machine": None, "linking": None, "complete": None}
    if kind is None:
        kind = "complete program" if f["complete"] else "incomplete program"
    files[sha] = {"sha256": sha, "size": len(raw), "foreign_prefix": max(off, 0), "kind": kind,
                  "bits": f["bits"], "machine": f["machine"], "linking": f["linking"],
                  "markers": " ".join(markers(content)), "runs": info[sha]["runs"],
                  "campaigns": " ".join(sorted(camp.get(sha, []))),
                  "paths": " ".join(sorted(info[sha]["paths"])),
                  "_head": content[:KEY], "_len": len(content)}
    del raw, content

# ------------------------------------------------------------ step 2
groups = collections.defaultdict(list)
small, frags = [], []
for sha, f in files.items():
    if f["kind"] == "beginning missing":
        frags.append(sha)
    elif f["_len"] >= KEY:
        groups[f["_head"]].append(sha)
    else:
        small.append(sha)
for sha in sorted(small, key=lambda x: -files[x]["_len"]):     # longest first
    b = files[sha]["_head"]
    home = next((k for k in groups if k.startswith(b)), None)
    groups[home if home is not None else b].append(sha)
by_path = collections.defaultdict(set)
for sha, f in files.items():
    for p in info[sha]["paths"]:
        by_path[p].add(sha)


def pieces(sha):
    """fingerprints of the 256-byte pieces of a copy (the honeypot's capture unit)"""
    b = body(sha)
    return {hashlib.blake2b(b[i:i + PIECE], digest_size=8).digest() for i in range(0, len(b) - PIECE + 1, PIECE)}


group_pieces = {}


def pieces_of_group(k):
    if k not in group_pieces:
        u = set()
        for m in groups[k]:
            u |= pieces(m)
        group_pieces[k] = u
    return group_pieces[k]


# fragments (no ELF header): join the program of the same path that holds most
# of their pieces (at least FRAG_MIN); the rest are grouped among themselves
unplaced = []
for sha in frags:
    own = pieces(sha)
    cands = {k for k, members in groups.items()
             for m in members if info[m]["paths"] & info[sha]["paths"]}
    best = max(((len(own & pieces_of_group(k)) / len(own), k) for k in cands), default=(0, None)) if own else (0, None)
    if best[0] >= FRAG_MIN:
        groups[best[1]].append(sha)
        files[sha]["fragment_share"] = best[0]
    else:
        unplaced.append(sha)
parent = {s: s for s in unplaced}


def find(x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x


fp = {s: pieces(s) for s in unplaced}
for x, y in itertools.combinations(unplaced, 2):
    if fp[x] and fp[y] and len(fp[x] & fp[y]) / min(len(fp[x]), len(fp[y])) >= FRAG_MIN:
        parent[find(y)] = find(x)
for s in unplaced:
    groups[b"frag:" + find(s).encode()].append(s)
del fp

programs = []
for n, (k, members) in enumerate(sorted(groups.items(), key=lambda kv: (-len(kv[1]), min(kv[1]))), 1):
    pid = f"P{n:03d}"
    elf = [s for s in members if files[s]["kind"] != "beginning missing"]
    longest = max(elf or members, key=lambda s: files[s]["_len"])
    lb = body(longest)
    cnt = collections.Counter()
    for m in members:
        cnt.update(pieces(m))
    rel = collections.Counter()
    for s in members:
        files[s]["program"] = pid
        own = pieces(s)
        share = sum(1 for x in own if cnt[x] > 1) / len(own) if own else 0.0
        files[s]["pieces_in_other_copies_pct"] = round(100 * share, 1) if len(members) > 1 else ""
        if s == longest:
            r = "longest copy"
        elif files[s]["kind"] == "beginning missing":
            r = "fragment"
        elif lb.startswith(body(s)):
            r = "prefix"
        elif share >= SAME_MIN:
            r = "same program, other gaps"
        else:
            r = "check"
        files[s]["relation"] = r
        rel[r] += 1
    complete = [s for s in members if files[s]["kind"] == "complete program"]
    fl = files[longest]
    programs.append({
        "program": pid, "copies": len(members), "runs": sum(files[s]["runs"] for s in members),
        "machine": fl["machine"], "bits": fl["bits"], "linking": fl["linking"],
        "markers": " ".join(sorted({m for s in members for m in files[s]["markers"].split()})),
        "longest_copy": longest, "longest_size": fl["_len"],
        "complete_copy": complete[0] if complete else "",
        "vt_of_complete_copy": vt.get(complete[0], {}).get("vt_status", "") if complete else "",
        "kinds": "; ".join(f"{k}: {v}" for k, v in sorted(collections.Counter(
            files[s]["kind"] for s in members).items())),
        "copies_vs_longest": "; ".join(f"{k}: {v}" for k, v in sorted(rel.items())),
        "campaigns": " ".join(sorted({c for s in members for c in files[s]["campaigns"].split()})),
        "paths": " ".join(sorted({p for s in members for p in info[s]["paths"]}))[:300],
    })

placed = collections.Counter(s for members in groups.values() for s in members)
assert set(placed) == set(files) and max(placed.values()) == 1, "every file must be in exactly one program"
fields = ["sha256", "program", "relation", "pieces_in_other_copies_pct", "size", "foreign_prefix", "kind", "bits", "machine", "linking",
          "markers", "runs", "campaigns", "paths"]
with open(os.path.join(out, "files.csv"), "w", newline="") as g:
    w = csv.DictWriter(g, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for sha in sorted(files, key=lambda s: (files[s]["program"], s)):
        w.writerow(files[sha])
with open(os.path.join(out, "programs.csv"), "w", newline="") as g:
    w = csv.DictWriter(g, fieldnames=list(programs[0]))
    w.writeheader()
    w.writerows(programs)

rel_all = collections.Counter(f["relation"].split(" ")[0] for f in files.values())
summary = {
    "files": len(files), "programs": len(programs),
    "programs_with_more_than_1_copy": sum(1 for p in programs if p["copies"] > 1),
    "programs_with_a_complete_copy": sum(1 for p in programs if p["complete_copy"]),
    "fragments_placed_in_a_program_with_header": len(frags) - len(unplaced),
    "fragments_grouped_without_header": len(unplaced),
    "copies_vs_longest": dict(rel_all),
    "kinds": dict(collections.Counter(f["kind"] for f in files.values())),
    "machines": dict(collections.Counter(f["machine"] for f in files.values())),
    "linking": dict(collections.Counter(f["linking"] for f in files.values())),
    "markers": dict(collections.Counter(f["markers"] or "none" for f in files.values())),
}
with open(os.path.join(out, "summary.json"), "w") as g:
    json.dump(summary, g, indent=1)
with open(os.path.join(out, "README.md"), "w") as g:
    g.write(f"""# Structural triage (steps 1 and 2)

Built by `scripts/structural_triage.py`. Covers the files linked to an
execution (valid links in `malware-samples_october.json`). Content only;
campaigns and paths are listed for comparison, not used for grouping
(except to narrow the search for fragments, see below).

## Step 1: files.csv
One row per file: size, foreign data before the ELF header
(`foreign_prefix`), kind, processor, 32/64-bit, static/dynamic, markers
(UPX = UPX header in the first 4 KB; Go = Go build info/ID or Go runtime
names; GCC = GCC comment; Rust = rustc paths), runs, campaigns, paths.
Facts of mixed copies are read from the ELF header after the foreign data.

## Step 2: programs.csv
Copies with the same first {KEY} bytes (after removing foreign data) are one
program. Shorter copies join the program they are the exact beginning of.
The honeypot rebuilds files from {PIECE}-byte pieces, so copies are compared
piece by piece (8-byte fingerprints of each {PIECE}-byte piece).
Copies without an ELF header (beginning missing) join the program of the
same executed path that holds at least {int(FRAG_MIN*100)}% of their pieces; the others are
grouped among themselves by the same rule.

`relation`: `longest copy`; `prefix` = exact beginning of the longest copy;
`same program, other gaps` = at least {int(SAME_MIN*100)}% of its pieces are also in other copies;
`fragment` = no ELF header; `check` = fewer shared pieces (possible
different program). `pieces_in_other_copies_pct` gives the share.
""")
print(json.dumps(summary, indent=1))
