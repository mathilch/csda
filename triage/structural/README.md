# Structural triage (steps 1 and 2)

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
Copies with the same first 4096 bytes (after removing foreign data) are one
program. Shorter copies join the program they are the exact beginning of.
The honeypot rebuilds files from 256-byte pieces, so copies are compared
piece by piece (8-byte fingerprints of each 256-byte piece).
Copies without an ELF header (beginning missing) join the program of the
same executed path that holds at least 50% of their pieces; the others are
grouped among themselves by the same rule.

`relation`: `longest copy`; `prefix` = exact beginning of the longest copy;
`same program, other gaps` = at least 90% of its pieces are also in other copies;
`fragment` = no ELF header; `check` = fewer shared pieces (possible
different program). `pieces_in_other_copies_pct` gives the share.
