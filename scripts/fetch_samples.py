#!/usr/bin/env python3
"""Copy captured files ("ondisk" copies) from the honeypot into samples/.

Read-only on the honeypot: the wanted paths go to `tar` over stdin and the
archive streams back over SSH; nothing is written there. Locally, every file
is hashed and stored as samples/<sha256> (mode 0644, never executable). Names
inside the archive are never used as local paths.

How the October data was collected (all read-only, run from the CSDA folder):
  1. Executions:  ssh honeypot 'sudo -n python3 - /home/controller/bpftests/log --json' \\
                      < scripts/find-malware-samples.py > finder_all.json
     (the honeypot developers' own finder, unchanged copy), filtered to
     October -> malware-samples_october.json, links fixed by fix_same_boot.py
  2. Sessions:    ssh honeypot 'sudo -n python3 - 2026-10-01 2026-10-31' \\
                      < scripts/session_stats.py > sessions.jsonl
  3. Files:       this script

Usage:
  python3 -I scripts/fetch_samples.py plan   [--root CSDA] [--paths FILE]
      list copies that are referenced but not yet in samples/ (no SSH)
  python3 -I scripts/fetch_samples.py fetch  [--root CSDA] [--paths FILE]
      fetch those copies
  python3 -I scripts/fetch_samples.py verify [--root CSDA]
      sha256 every referenced copy on the honeypot and compare it with the json

Default paths: every "ondisk" in malware-samples_october.json. --paths takes a
text file (one honeypot path per line) or fix_same_boot.plan.json
("missing_copies"). Fetched files are recorded in scripts/fetch_samples.fetched.json
as {ondisk: [sha256, size]}.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tarfile

HOST = "honeypot"
TAR = "sudo -n nice tar --null --ignore-failed-read -T - -cf -"
SHA = "sudo -n nice xargs -0 -r sha256sum --"

ap = argparse.ArgumentParser()
ap.add_argument("mode", choices=["plan", "fetch", "verify"])
ap.add_argument("--root", default=".")
ap.add_argument("--paths")
args = ap.parse_args()

root = os.path.abspath(args.root)
samples = os.path.join(root, "samples")
record_path = os.path.join(root, "scripts", "fetch_samples.fetched.json")
runs = json.load(open(os.path.join(root, "malware-samples_october.json")))["samples"]

# expected sha256 per honeypot path, as recorded in the json
expected = {r["ondisk"]: r.get("sha256") for r in runs if r.get("ondisk")}

if args.paths:
    if args.paths.endswith(".json"):
        wanted = json.load(open(args.paths))["missing_copies"]
    else:
        wanted = [line.strip() for line in open(args.paths) if line.strip()]
else:
    wanted = sorted(expected)
have = set(os.listdir(samples))
missing = sorted({p for p in wanted if not (expected.get(p) and expected[p] in have)})


def nul(paths):
    return "".join(p + "\0" for p in paths).encode()


if args.mode == "plan":
    print(f"referenced copies: {len(set(wanted))}, already in samples/: {len(set(wanted)) - len(missing)}, "
          f"to fetch: {len(missing)}")
    for p in missing:
        print("  ", p)

elif args.mode == "fetch":
    if not missing:
        sys.exit("nothing to fetch")
    record = json.load(open(record_path)) if os.path.exists(record_path) else {}
    proc = subprocess.Popen(["ssh", HOST, TAR], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    proc.stdin.write(nul(missing))
    proc.stdin.close()
    got, new, mismatch = {}, 0, []
    with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
        for m in tar:
            if not m.isreg():
                continue
            src = tar.extractfile(m)
            tmp = os.path.join(samples, ".part")
            h, size = hashlib.sha256(), 0
            with open(tmp, "wb") as out:
                while chunk := src.read(1 << 20):
                    h.update(chunk)
                    out.write(chunk)
                    size += len(chunk)
            sha = h.hexdigest()
            dst = os.path.join(samples, sha)
            if os.path.exists(dst):
                os.remove(tmp)
            else:
                os.chmod(tmp, 0o644)
                os.replace(tmp, dst)
                new += 1
            path = "/" + m.name               # tar strips the leading "/"
            got[path] = [sha, size]
            if expected.get(path) and expected[path] != sha:
                mismatch.append(path)
    err = proc.stderr.read().decode(errors="replace")
    proc.wait()
    record.update(got)
    json.dump(record, open(record_path, "w"), indent=1, sort_keys=True)
    print(f"asked {len(missing)}, received {len(got)}, new files in samples/: {new}")
    for p in sorted(set(missing) - set(got)):
        print("   not received:", p)
    for p in mismatch:
        print("   sha256 differs from the json:", p)
    for line in err.splitlines():
        if "Removing leading" not in line:
            print("  ", line)

else:  # verify
    paths = sorted(set(wanted))
    out = subprocess.run(["ssh", HOST, SHA], input=nul(paths), capture_output=True, check=False)
    remote = {}
    for line in out.stdout.decode(errors="replace").splitlines():
        sha, _, path = line.partition("  ")
        remote[path] = sha
    same = sum(1 for p in paths if remote.get(p) and remote[p] == expected.get(p))
    gone = [p for p in paths if p not in remote]
    differ = [p for p in paths if p in remote and remote[p] != expected.get(p)]
    local = sum(1 for p in paths if expected.get(p) in have)
    print(f"referenced copies: {len(paths)}, same sha256 on honeypot: {same}, differ: {len(differ)}, "
          f"missing on honeypot: {len(gone)}, local copy present: {local}")
    for p in differ:
        print("   differs:", p)
    for p in gone:
        print("   missing:", p)
