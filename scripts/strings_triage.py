#!/usr/bin/env python3
"""Strings and keyword triage of the executed files, per program.

Static only: files are read, never run. UPX-packed files can only be
unpacked when the copy is complete (upx -d, a static decompression);
for packed copies that are cut off, the strings are compressed and are
not read (the few readable runs in compressed data are random matches).

Per copy, the part after the foreign prefix (data from another file in
front of the ELF header, see structural triage) is the program; the
prefix is scanned separately and reported as "other file".

Extracted (printable runs of at least MIN_LEN bytes):
  url, ipv4, domain (URL hosts and stand-alone names), monero wallet,
  ssh key, discord webhook, path, keyword (names of tools, families and
  services from KEYWORDS), go version (from the Go build info).
Every ipv4 is compared with the connect targets in the telemetry, and
every ssh key with the keys used in the commands (chains/level3).

Inputs:  triage/structural/files.csv, samples/, chains/level3/, sessions.jsonl
Output:  triage/strings/ (README.md, programs.csv, iocs.csv, summary.json,
         unpacked/ = unpacked complete UPX copies)
Usage:   python3 scripts/strings_triage.py [CSDA folder]
"""

import collections
import csv
import json
import os
import re
import shutil
import subprocess
import sys

MIN_LEN = 6
root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
out = os.path.join(root, "triage", "strings")

KEYWORDS = ["xmrig", "supportxmr", "nicehash", "moneropool", "monerohash", "f2pool", "xmrpool", "c3pool",
            "hashvault", "nanopool", "minexmr", "herominers", "randomx", "stratum", "pastebin", "discord",
            "telegram", "ipify", "ifconfig.me", "icanhazip", "ipinfo", "diicot", "retea", "mirai", "gafgyt",
            "kaiten", "tsunami", "shellbot", "kinsing", "teamtnt", "masscan", "zmap", "sshpass", "fritzfrog"]
TLD = ("com|net|org|io|ru|cn|xyz|top|cc|info|biz|pw|su|de|eu|me|online|site|club|tk|ro|us|uk|nl|fr|"
       "dev|app|live|pro|ws|co")
STR = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
URL = re.compile(r"(?:https?|ftp|stratum\+(?:tcp|ssl|tls))://[^\s\"'<>]{4,}")
IP = re.compile(r"(?<![0-9.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{2,5})?(?![0-9.])")
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9-]*[a-z][a-z0-9-]*\.(?:%s)" % TLD)
# Go/ELF names that look like domains, and Go strings glued together
NOT_DOMAIN = re.compile(r"^(?:runtime|reflect|unicode|valid|data|godebugs|itab|textproto)\.|relang\.org$|[a-z0-9-]{30}")
SPLIT = re.compile(r"[\s\"'=,;:/()<>\[\]{}]+")
WALLET = re.compile(r"(?<![1-9A-Za-z])[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}(?![1-9A-Za-z])")
SSHKEY = re.compile(r"(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+) (AAAA[A-Za-z0-9+/=]{60,})")
WEBHOOK = re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{20,}")
PATH = re.compile(r"(?<![A-Za-z0-9._-])(?:/tmp|/var/tmp|/dev/shm|/etc|/root|/usr|/bin|/sbin|/lib|/opt|/home|/run)"
                  r"/[A-Za-z0-9._/-]{2,}")
KW = re.compile(r"(?<![A-Za-z0-9])(?:%s)(?![A-Za-z])" % "|".join(re.escape(k) for k in KEYWORDS), re.I)
# well-known sites and library references: listed, but marked
GENERIC_DOMAIN = {"go.dev", "golang.org", "github.com", "www.github.com", "www.google.com", "www.bing.com",
                  "www.example.com", "www.wikipedia.org", "www.reddit.com", "gcc.gnu.org", "bugs.launchpad.net",
                  "upx.sf.net", "xmrig.com"}
# dotted numbers starting with 0-2 that are object IDs (certificates) or versions, not addresses
OID_LIKE = re.compile(r"^(?:1\.[0-3]\.|2\.5\.)")
# addresses every program may use: not counted as a match with the telemetry
GENERIC_IP = re.compile(r"^(?:0\.0\.0\.0|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|1\.1\.1\.1$|1\.0\.0\.1$|"
                        r"8\.8\.8\.8$|8\.8\.4\.4$|9\.9\.9\.9$|255\.255\.255\.255$)")


def go_version(b):
    """Go version from the build info header (Go 1.18+ inline format)."""
    i = b.find(b"\xff Go buildinf:")
    if i < 0 or len(b) < i + 40:
        return None
    if not b[i + 15] & 2:
        return "old format"
    n, sh, j = 0, 0, i + 32
    while j < len(b):
        n |= (b[j] & 0x7f) << sh
        j += 1
        if b[j - 1] < 0x80:
            break
        sh += 7
    v = b[j:j + n].decode("latin1")
    return v if v.startswith("go") or v == "unknown" else None


def scan(b):
    """IOC values in the printable runs of b: {(kind, value)}"""
    found = set()
    for m in STR.finditer(b):
        s = m.group().decode()
        for u in URL.findall(s):
            found.add(("url", u))
            host = re.sub(r"^[a-z+]+://", "", u).split("/")[0].split(":")[0].lower()
            if DOMAIN.fullmatch(host) and not NOT_DOMAIN.match(host):
                found.add(("domain", host))
        found.update(("ipv4", x) for x in IP.findall(s))
        found.update(("domain", t.lower()) for t in SPLIT.split(s)
                     if DOMAIN.fullmatch(t.lower()) and not NOT_DOMAIN.match(t.lower()))
        found.update(("monero wallet", x) for x in WALLET.findall(s))
        found.update(("ssh key", x) for x in SSHKEY.findall(s))
        found.update(("discord webhook", x) for x in WEBHOOK.findall(s))
        found.update(("path", x.rstrip("/.")) for x in PATH.findall(s))
        found.update(("keyword", k.group().lower()) for k in KW.finditer(s))
    return found


# ------------------------------------------------- telemetry (streamed)
files = list(csv.DictReader(open(os.path.join(root, "triage", "structural", "files.csv"))))
ip_camp = collections.defaultdict(set)
cmd_keys = collections.defaultdict(set)
L3 = os.path.join(root, "chains", "level3")
for row in csv.DictReader(open(os.path.join(L3, "index.csv"))):
    m = json.load(open(os.path.join(L3, "campaigns", row["dir"], "campaign.json")))
    for ip in m["ip_list"]:
        ip_camp[ip].add(row["campaign"])
    for k in m["ssh_keys"]:
        cmd_keys[k["key"]].add(row["campaign"])
connect = collections.defaultdict(set)         # target address -> campaigns of the IPs that connected
with open(os.path.join(root, "sessions.jsonl")) as f:
    for line in f:
        if '"connect"' not in line:
            continue
        s = json.loads(line)
        for e in s.get("ev") or []:
            if e.get("e") == "connect" and isinstance(e.get("t"), int):
                connect[str(e.get("a"))].update(ip_camp.get(s["ip"], {"no campaign"}))
        del s

# ------------------------------------------------------------ samples
if os.path.exists(out):
    shutil.rmtree(out)
os.makedirs(os.path.join(out, "unpacked"))
prog = collections.defaultdict(lambda: {"copies": 0, "read": 0, "packed_cut": 0, "unpacked": 0, "campaigns": set(),
                                        "go": collections.Counter(), "strings": 0})
hits = collections.defaultdict(lambda: collections.Counter())    # (program, source) -> Counter((kind, value))
for r in files:
    p = prog[r["program"]]
    p["copies"] += 1
    p["campaigns"].update(r["campaigns"].split())
    with open(os.path.join(root, "samples", r["sha256"]), "rb") as g:
        b = g.read()
    pre = int(r["foreign_prefix"] or 0)
    if pre:
        hits[(r["program"], "other file")].update(scan(b[:pre]))
    body = b[pre:]
    del b
    if "UPX" in r["markers"].split():
        if r["kind"] != "complete program":
            p["packed_cut"] += 1
            continue
        packed = os.path.join(out, "unpacked", r["sha256"] + ".upx")
        with open(packed, "wb") as g:
            g.write(body)
        dst = os.path.join(out, "unpacked", r["sha256"])
        res = subprocess.run(["upx", "-q", "-d", "-o", dst, packed], capture_output=True, text=True)
        os.remove(packed)
        if res.returncode != 0:
            p["packed_cut"] += 1
            continue
        p["unpacked"] += 1
        with open(dst, "rb") as g:
            body = g.read()
    p["read"] += 1
    p["strings"] = max(p["strings"], sum(1 for _ in STR.finditer(body)))
    v = go_version(body)
    if v:
        p["go"][v] += 1
    src = "fragment (no ELF header)" if r["kind"] == "beginning missing" else "program"
    hits[(r["program"], src)].update(scan(body))
    del body

# ------------------------------------------------------------- output
ioc_rows = []
for (pid, source), c in sorted(hits.items()):
    for (kind, value), n in sorted(c.items()):
        note, tel = "", ""
        if kind == "ipv4" and GENERIC_IP.match(value.split(":")[0]):
            note = "generic address"
        elif kind == "ipv4" and OID_LIKE.match(value):
            note = "not an address (object ID)"
        elif kind == "domain" and value in GENERIC_DOMAIN:
            note = "generic site"
        elif kind == "ipv4":
            tel = " ".join(sorted(connect.get(value.split(":")[0], ())))
        elif kind == "ssh key":
            tel = " ".join(sorted(cmd_keys.get(value, ())))
        ioc_rows.append({"program": pid, "campaigns": " ".join(sorted(prog[pid]["campaigns"])), "source": source,
                         "kind": kind, "value": value, "copies": n, "note": note, "in_telemetry": tel})
with open(os.path.join(out, "iocs.csv"), "w", newline="") as g:
    w = csv.DictWriter(g, fieldnames=list(ioc_rows[0]))
    w.writeheader()
    w.writerows(ioc_rows)

KINDS = ["url", "ipv4", "domain", "monero wallet", "ssh key", "discord webhook", "path", "keyword"]
prog_rows = []
for pid in sorted(prog):
    p = prog[pid]
    c = hits.get((pid, "program"), collections.Counter()) + hits.get((pid, "fragment (no ELF header)"),
                                                                      collections.Counter())
    row = {"program": pid, "campaigns": " ".join(sorted(p["campaigns"])), "copies": p["copies"],
           "copies_read": p["read"], "unpacked": p["unpacked"], "packed_and_cut": p["packed_cut"],
           "max_strings": p["strings"], "go_version": " ".join(sorted(p["go"]))}
    for k in KINDS:
        row[k] = len({v for (kind, v) in c if kind == k})
    row["keywords"] = " ".join(sorted({v for (kind, v) in c if kind == "keyword"}))
    row["ips_in_telemetry"] = " ".join(sorted({r["value"] for r in ioc_rows if r["program"] == pid
                                               and r["kind"] == "ipv4" and r["in_telemetry"]}))
    prog_rows.append(row)
with open(os.path.join(out, "programs.csv"), "w", newline="") as g:
    w = csv.DictWriter(g, fieldnames=list(prog_rows[0]))
    w.writeheader()
    w.writerows(prog_rows)

summary = {
    "files": len(files), "programs": len(prog),
    "copies_read": sum(p["read"] for p in prog.values()),
    "copies_unpacked": sum(p["unpacked"] for p in prog.values()),
    "copies_packed_and_cut": sum(p["packed_cut"] for p in prog.values()),
    "programs_read": sum(1 for p in prog.values() if p["read"]),
    "programs_not_read": sorted(k for k, p in prog.items() if not p["read"]),
    "ioc_values_by_kind_program": dict(collections.Counter(r["kind"] for r in ioc_rows if r["source"] == "program")),
    "ioc_values_by_kind_fragment": dict(collections.Counter(r["kind"] for r in ioc_rows
                                                            if r["source"] == "fragment (no ELF header)")),
    "ioc_values_by_kind_other_file": dict(collections.Counter(r["kind"] for r in ioc_rows
                                                              if r["source"] == "other file")),
    "ips_also_in_telemetry": sorted({(r["program"], r["value"], r["in_telemetry"]) for r in ioc_rows
                                     if r["kind"] == "ipv4" and r["in_telemetry"]}),
    "ssh_keys_also_in_commands": sorted({(r["program"], r["source"], r["value"][:24] + "…", r["in_telemetry"])
                                         for r in ioc_rows if r["kind"] == "ssh key" and r["in_telemetry"]}),
}
with open(os.path.join(out, "summary.json"), "w") as g:
    json.dump(summary, g, indent=1)

with open(os.path.join(out, "README.md"), "w") as g:
    g.write(f"""# Strings and keyword triage

Built by `scripts/strings_triage.py` from `triage/structural/files.csv`,
`samples/`, `chains/level3/` and `sessions.jsonl`. Static only.

## Method
- Printable runs of at least {MIN_LEN} bytes, per copy; results joined per
  program (copies of a program are cut in different places).
- The foreign prefix of a copy (data from another file in front of the ELF
  header) is scanned separately: `source = other file`. Copies without
  an ELF header are `source = fragment (no ELF header)`: they may also be
  data of another file.
- UPX-packed copies: complete copies are unpacked with `upx -d` (static) and
  the unpacked file is scanned (kept in `unpacked/`). Packed copies that
  are cut off are not read: their content is compressed.
- Kinds: url, ipv4, domain (URL hosts and stand-alone names), monero
  wallet, ssh key, discord webhook, path, keyword (names of tools, families
  and services: {", ".join(KEYWORDS)}).
- `note` / `in_telemetry`: for an ipv4, the campaigns whose IPs connected to that
  address in the telemetry; for an ssh key, the campaigns that used the key
  in a command. Local, private and public DNS addresses (0.0.0.0, 127.x,
  private ranges, 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 255.255.255.255) are marked
  `generic address` and not compared; certificate object IDs such as
  2.5.4.6 or 1.3.101.110 are marked `not an address (object ID)`;
  well-known sites and library references are marked `generic site`.
  Keywords only count as a whole word (any case).

## Limits
- Go programs store strings without separators, so a value can have text
  of the next string glued to its end (for example a URL). Check values by
  hand before using them.
- Obfuscated programs (for example Go programs built with garble) keep
  their strings encrypted; they are not found here.

## Files
- `programs.csv`: one row per program: copies read, unpacked, packed and
  cut, Go version, number of values per kind, keywords, IPs also seen in
  the telemetry.
- `iocs.csv`: one row per program, source and value, with the number of
  copies that contain it.
- `summary.json`: totals.
""")
print(json.dumps(summary, indent=1))
