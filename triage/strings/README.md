# Strings and keyword triage

Built by `scripts/strings_triage.py` from `triage/structural/files.csv`,
`samples/`, `chains/level3/` and `sessions.jsonl`. Static only.

## Method
- Printable runs of at least 6 bytes, per copy; results joined per
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
  and services: xmrig, supportxmr, nicehash, moneropool, monerohash, f2pool, xmrpool, c3pool, hashvault, nanopool, minexmr, herominers, randomx, stratum, pastebin, discord, telegram, ipify, ifconfig.me, icanhazip, ipinfo, diicot, retea, mirai, gafgyt, kaiten, tsunami, shellbot, kinsing, teamtnt, masscan, zmap, sshpass, fritzfrog).
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
