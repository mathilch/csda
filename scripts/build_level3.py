#!/usr/bin/env python3
"""Level 3 attack chains: attacks from different IPs joined into campaigns.

Behaviour only (no file contents). Two attacks are linked if they share
  1. an SSH key (in a command), or
  2. a distinctive executed path (fixed file name, not a random one), or
  3. most of their commands: at least SHARE_MIN of the smaller attack's
     commands (at least MIN_CMDS) also appear in the other attack.
A campaign = all attacks linked directly or through other attacks.

Normalisation:
  * a word used by only one attack is a variable value -> <v>
    (random file names, passwords, ...)
  * /home/<user>/ -> ~/
  * login noise is ignored: the motd run-parts script run by sshd at login,
    sftp-server and scp (upload method)

Inputs: chains/level2/ (run build_level1.py and build_level2.py first).
Output: chains/level3/ (README.md, index.csv, summary.json, campaigns/, notes/)
Usage:  python3 scripts/build_level3.py [CSDA folder]
"""

import collections
import csv
import itertools
import json
import os
import re
import shutil
import sys

SHARE_MIN = 0.8
MIN_CMDS = 3

root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
L2 = os.path.join(root, "chains", "level2")
out = os.path.join(root, "chains", "level3")

TOK = re.compile(r"[A-Za-z0-9_.\-]+")
KEY = re.compile(r"(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+)\s+(AAAA[A-Za-z0-9+/=]{60,})")
NOISE = re.compile(r"run-parts --lsbsysinit /etc/update-motd\.d|^/usr/lib/openssh/sftp-server$|^scp ")


def home(p):
    return re.sub(r"^/home/[^/]+/", "~/", p)


# --------------------------------------------------------- features
rows = list(csv.DictReader(open(os.path.join(L2, "index.csv"))))
att = {}
for row in rows:
    meta = json.load(open(os.path.join(L2, "attacks", row["dir"], "attack.json")))
    cmds, keys, net = [], set(), collections.Counter()
    for s in meta["sessions"]:
        with open(os.path.join(L2, "attacks", row["dir"], s["folder"], "events.jsonl")) as f:
            for line in f:
                e = json.loads(line)
                if e.get("e") == "exec":
                    v = e.get("v") or []
                    if len(v) >= 3 and os.path.basename(str(v[0])) in ("bash", "sh") and v[1] == "-c":
                        cmds.append(str(v[2]))
                    keys.update(KEY.findall(" ".join(map(str, v))))
                elif e.get("e") == "connect" and isinstance(e.get("t"), int):
                    a = str(e.get("a"))
                    if a not in ("0.0.0.0", "None") and not a.startswith(("127.", "192.168.100.")) \
                            and e.get("r") != 22:
                        net[f"{a}:{e.get('r')}"] += 1
    att[row["attack"]] = {"row": row, "ip": row["ip"], "cmds": cmds, "keys": keys, "net": set(net),
                          "paths": {r["file"] for r in meta["runs"]}}

use = collections.defaultdict(set)
for aid, x in att.items():
    for c in x["cmds"] + list(x["paths"]):
        for t in TOK.findall(c):
            use[t].add(aid)


def norm(s):
    return TOK.sub(lambda m: m.group(0) if len(use[m.group(0)]) > 1 else "<v>", s)


for x in att.values():
    x["ncmds"] = {norm(c) for c in x["cmds"] if not NOISE.search(c)}
    x["npaths"] = {home(norm(p)) for p in x["paths"]}

# ------------------------------------------------------------ links
parent = {a: a for a in att}


def find(a):
    while parent[a] != a:
        parent[a] = parent[parent[a]]
        a = parent[a]
    return a


links = collections.defaultdict(list)          # (a, b) -> reasons
groups = collections.defaultdict(set)
for a, x in att.items():
    for k in x["keys"]:
        groups[("SSH key", k[:24] + "…")].add(a)
    for p in x["npaths"]:
        if not p.rsplit("/", 1)[-1].startswith("<v>"):
            groups[("path", p)].add(a)
for (kind, value), members in groups.items():
    members = sorted(members)
    for b in members[1:]:
        if find(b) != find(members[0]):
            links[(members[0], b)].append(f"{kind}: {value}")
        parent[find(b)] = find(members[0])
cmd_links = 0
for a, b in itertools.combinations(sorted(att), 2):
    ca, cb = att[a]["ncmds"], att[b]["ncmds"]
    m = min(len(ca), len(cb))
    if m >= MIN_CMDS and len(ca & cb) / m >= SHARE_MIN and find(a) != find(b):
        links[(a, b)].append(f"commands: {len(ca & cb)}/{m} of the smaller attack's commands shared")
        parent[find(b)] = find(a)
        cmd_links += 1

camp = collections.defaultdict(list)
for a in att:
    camp[find(a)].append(a)
camps = sorted(camp.values(), key=lambda g: (-len(g), min(g)))

# ----------------------------------------------------------- output
if os.path.exists(out):
    shutil.rmtree(out)
os.makedirs(os.path.join(out, "campaigns"))
os.makedirs(os.path.join(out, "notes"))
index = []
for n, g in enumerate(camps, 1):
    g.sort()
    cid = f"C{n:02d}"
    paths = collections.Counter(p for a in g for p in att[a]["npaths"])
    fixed = [p for p, _ in paths.most_common() if not p.rsplit("/", 1)[-1].startswith("<v>")]
    label = " + ".join(list(dict.fromkeys(os.path.basename(p) for p in fixed))[:2]) or next(iter(paths))
    dname = f"{cid}_{re.sub(r'[^A-Za-z0-9._+-]', '_', label)[:40]}"
    d = os.path.join(out, "campaigns", dname)
    os.makedirs(os.path.join(d, "attacks"))
    for a in g:
        r = att[a]["row"]
        os.symlink(os.path.join("..", "..", "..", "..", "level2", "attacks", r["dir"]),
                   os.path.join(d, "attacks", r["dir"]))
    ips = sorted({att[a]["ip"] for a in g})
    starts = sorted(att[a]["row"]["start_utc"] for a in g)
    ends = sorted(att[a]["row"]["end_utc"] for a in g)
    cmds = collections.Counter(c for a in g for c in att[a]["ncmds"])
    keys = collections.Counter(k for a in g for k in att[a]["keys"])
    net = collections.Counter(t for a in g for t in att[a]["net"])
    shas = sorted({s for a in g for s in att[a]["row"]["samples"].split()})
    inner = [{"attacks": [a, b], "reasons": why} for (a, b), why in links.items()
             if find(a) == find(g[0])]
    meta = {
        "campaign": cid, "label_from_paths": label,
        "attacks": len(g), "ips": len(ips), "ip_list": ips,
        "first_start_utc": starts[0], "last_end_utc": ends[-1],
        "sessions": sum(int(att[a]["row"]["sessions"]) for a in g),
        "runs": sum(int(att[a]["row"]["runs"]) for a in g),
        "runs_without_file": sum(int(att[a]["row"]["runs_without_file"]) for a in g),
        "executed_paths": [{"path": p, "attacks": k} for p, k in paths.most_common()],
        "ssh_keys": [{"key": k, "attacks": c} for k, c in keys.most_common()],
        "commands_in_at_least_half_of_attacks": [{"command": c, "attacks": k}
                                                 for c, k in cmds.most_common() if k >= len(g) / 2],
        "network_targets_in_at_least_half_of_attacks": [{"target": t, "attacks": k}
                                                        for t, k in net.most_common() if k >= len(g) / 2],
        "samples": shas,
        "links": inner,
        "attack_list": [{"attack": a, "dir": att[a]["row"]["dir"], "ip": att[a]["ip"],
                         "start_utc": att[a]["row"]["start_utc"]} for a in g],
    }
    with open(os.path.join(d, "campaign.json"), "w") as f:
        json.dump(meta, f, indent=1)
    index.append({"campaign": cid, "dir": dname, "label_from_paths": label, "attacks": len(g),
                  "ips": len(ips), "first_start_utc": starts[0], "last_end_utc": ends[-1],
                  "sessions": meta["sessions"], "runs": meta["runs"],
                  "runs_without_file": meta["runs_without_file"], "samples": len(shas),
                  "ssh_keys": len(keys), "linked_by": "; ".join(sorted({w.split(':')[0] for l in inner
                                                                       for w in l["reasons"]})) or "-"})

with open(os.path.join(out, "index.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(index[0]))
    w.writeheader()
    w.writerows(index)
summary = {"share_min": SHARE_MIN, "min_cmds": MIN_CMDS, "attacks": len(att), "campaigns": len(camps),
           "campaigns_with_1_attack": sum(1 for g in camps if len(g) == 1),
           "links_by_command_rule": cmd_links,
           "ips_in_more_than_one_campaign": {ip: sorted(r["campaign"] for r in index
                                                        if ip in json.load(open(os.path.join(
                                                            out, "campaigns", r["dir"], "campaign.json")))["ip_list"])
                                             for ip in {x["ip"] for x in att.values()}
                                             if sum(1 for g in camps if ip in {att[a]["ip"] for a in g}) > 1}}
with open(os.path.join(out, "summary.json"), "w") as f:
    json.dump(summary, f, indent=1)

with open(os.path.join(out, "README.md"), "w") as f:
    f.write(f"""# Level 3 attack chains: attacks joined into campaigns

Built by `scripts/build_level3.py` from `chains/level2/` (run
`build_level1.py` and `build_level2.py` first). Behaviour only: file
contents are compared later, in the sample triage.

## Rules
Two attacks are linked if they share
1. an SSH key (in a command), or
2. a distinctive executed path: a fixed file name such as `/dev/shm/retea`
   or `~/.dhpcd`; random names such as `/var/tmp/<v>` do not count, or
3. most of their commands: at least {int(SHARE_MIN * 100)}% of the smaller attack's commands
   (at least {MIN_CMDS}) also appear in the other attack.
A campaign = all attacks linked directly or through other attacks.

Normalisation: a word used by only one attack is a variable value and is
written `<v>`; `/home/<user>/` is written `~/`; login noise (the motd
run-parts script started by sshd at login, sftp-server, scp) is ignored.
Network targets (not port 22) are listed for information only, not used
as links: most targets are scan noise and some are generic services.

## Files
- `index.csv`: one row per campaign. `label_from_paths` is only a label
  taken from the executed paths, not a family name.
- `summary.json`: totals; IPs that appear in more than one campaign.
- `campaigns/<id>_<label>/`
  - `campaign.json`: attacks, IPs, time span, executed paths, SSH keys,
    commands and network targets used in at least half of its attacks, the
    samples, and which link joined which attacks.
  - `attacks/`: links to the Level 2 attack folders.
- `notes/`: for your own notes.
""")

print(json.dumps(summary, indent=1))
for r in index:
    print(f"{r['campaign']} {r['attacks']:4} attacks {r['ips']:3} IPs  {r['label_from_paths']:35} linked by: {r['linked_by']}")
