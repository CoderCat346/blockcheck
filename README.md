# blockcheck

Find out whether a domain is **actually** blocked — and which layer is doing it.

`dig` says NXDOMAIN? That could be a filter, or the name could simply not exist.
`curl` times out? That could be SNI filtering, an IP block, or a dead host.
`blockcheck` runs four independent probes — DNS, CNAME, TCP/TLS and HTTP — and
reports the path the traffic actually takes, so you know whether you are looking
at a resolver policy, a transparent proxy, a block page, or a site that is just
down.

```
$ blockcheck google-analytics.com
google-analytics.com  BLOCKED  [domain]
  path      dns: filtered  tcp: open  tls: ok
  reason    10.0.0.1 [A,AAAA]: answers sinkhole address 0.0.0.0
  reason    public resolver 1.1.1.1 answers NOERROR 0.0.0.0 but DoH says
            NOERROR 172.217.26.36: port 53 is intercepted on-path
  reason    DoH (cloudflare) confirms the name is live: 172.217.26.36
  reason    direct IP connectivity still works: DNS-only block, reachable via
            DoH or a different resolver
  truth     doh (cloudflare) -> 172.217.26.36, 2404:6800:4002:828::2004
  ! local    10.0.0.1       A    NOERROR 0.0.0.0                 361 ms  sinkhole
  ! local    10.0.0.1       AAAA NOERROR ::                      341 ms  sinkhole
    control  1.1.1.1        A    NOERROR 0.0.0.0                 335 ms  sinkhole
    doh      cloudflare     A    NOERROR 172.217.26.36           343 ms  ok
  cname     -
  tls       172.217.26.36:443  ok  TLSv1.3  cert=*.google-analytics.com  ...
```

Single file, standard library only. It ships its own DNS client, so it works on
boxes where `dig`, `host` and `nslookup` are not installed.

## What it checks

| Layer | Probes | Detects |
|---|---|---|
| **dns** | system resolver(s), 1.1.1.1 / 8.8.8.8 / 9.9.9.9, DoH (Cloudflare, Google), and the zone's own authoritative servers (`--auth`) | `NXDOMAIN`, `SERVFAIL`, `REFUSED`, `NODATA`/RPZ, sinkhole `0.0.0.0` / `::` / loopback, rewrite to a private address, silent drop, and on-path port-53 interception |
| **cname** | the full CNAME chain from whichever resolver has the cleanest answer | cross-domain hops, known ad/analytics vendors (Adobe, Salesforce, Criteo, OneTrust, …), first-party CNAME cloaking, and CNAME targets that are themselves filtered — the usual reason a site hangs for 30 s |
| **tcp/tls** | connect + handshake per address, with the real SNI | IP/port block vs SNI-based reset vs MITM/block portal (certificate for a different name, even when self-signed) vs expired cert vs dead host. A baseline probe separates "blocked" from "this uplink has no 443 at all" |
| **http** | the block page, when TLS fails or DNS answers with a block-page IP | fingerprints FortiGuard, Umbrella, AdGuard, Sophos, Zscaler, … by server header, title and body markers |

IPv6 addresses are skipped when the network cannot reach them, NAT64-synthesised
`AAAA` records are labelled as such, and DNSSEC `AD` is shown when the resolver
sets it.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/CoderCat346/blockcheck/main/blockcheck \
  -o ~/.local/bin/blockcheck
chmod +x ~/.local/bin/blockcheck
```

Or from a clone:

```sh
git clone https://github.com/CoderCat346/blockcheck.git
ln -s "$PWD/blockcheck/blockcheck" ~/.local/bin/blockcheck
```

Requirements: Python 3.8+. `curl` enables the DoH, block-page and `--asn`
checks; `openssl` is used to decode certificates when verification fails. Both
are optional — the tool degrades gracefully without them.

## Usage

```sh
blockcheck example.com                     # full report
blockcheck '*.doubleclick.net'             # wildcard rule
blockcheck -f domains.txt --json > out.json
blockcheck ads.example.com -r 192.168.1.1:53 --timeout 3
blockcheck example.com -v --auth --asn     # every answer, authoritative NS, ASN
blockcheck '*.example.com' --samples 5 --seed 1 --brief
```

Targets can be domains, URLs (`https://site/path` — scheme and path are
stripped), `host:port`, or `*.wildcard`. `-` reads them from stdin, `-f` from a
file (blank lines and `#` comments ignored).

## Reading the output

```
path      dns: filtered  tcp: open  tls: ok  ipv6: unreachable
```

The `path` line is the summary: what each layer did. Then one line per reason,
the ground truth used for comparison, every resolver answer, the CNAME chain,
the TLS results per address, and any block page found.

`!` marks a *local* answer that is blocking. `control` and `doh` rows are shown
for reference and never carry the mark.

| Verdict | Meaning | Exit |
|---|---|---|
| `BLOCKED` | at least one layer filters this name | 2 |
| `ALLOWED` | resolves and connects normally | 0 |
| `PARTIAL` | wildcard: the apex is filtered but some subdomains still resolve | 3 |
| `UNKNOWN` | nothing conclusive — usually the name does not exist | 3 |
| `ERROR` | the target was not a valid domain | 1 |

With several targets the exit code is the worst one. `--quiet` prints nothing and
only sets the code.

## Wildcards

`*.example.com` checks the apex in full, then `--samples` random labels under it:

- **BLOCKED** — every sample that resolves is filtered as well.
- **PARTIAL** — a sample still resolves: a real hole in the rule (the leak is named).
- If the zone publishes no wildcard address records, it says so instead of
  inventing a leak. `--seed` makes the samples reproducible.

## Options

| Option | Default | |
|---|---|---|
| `-f, --file` | | read targets from a file |
| `-r, --resolver` | `/etc/resolv.conf` | resolver to test, `ip[:port]`, repeatable |
| `--control` | `1.1.1.1 8.8.8.8 9.9.9.9` | public resolvers used as ground truth |
| `-t, --timeout` | `4` | per-probe timeout in seconds |
| `--retries` | `1` | DNS retries per server |
| `--port` | `443` | TLS port to probe |
| `--http-port` | `80` | port used to fetch a block page |
| `--max-ips` | `3` | addresses probed per name |
| `--samples` | `3` | random subdomains per wildcard |
| `--seed` | | reproducible wildcard samples |
| `--no-doh` | | skip DoH ground truth |
| `--doh-provider` | both | `cloudflare` or `google` |
| `--dnssec` | off | set the EDNS0 DO bit |
| `--no-tls` | | DNS-only check (fast) |
| `--no-http` | | never fetch block pages |
| `--no-chain-check` | | do not test whether CNAME targets are blocked |
| `--auth` | | also query the zone's authoritative nameservers |
| `--asn` | | prefix/ASN lookup for resolved addresses |
| `-v, --verbose` | | show every resolver answer |
| `--brief` | | summary table only |
| `--json` | | machine-readable output |
| `--quiet` | | no output, exit code only |
| `--no-color` | | disable ANSI colour (also honours `NO_COLOR`) |

## JSON

```json
{
  "tool": "blockcheck",
  "version": "1.0",
  "targets": [{
    "target": "google-analytics.com",
    "verdict": "BLOCKED",
    "paths": { "dns": "filtered", "tcp": "open", "tls": "ok" },
    "reasons": ["10.0.0.1 [A,AAAA]: answers sinkhole address 0.0.0.0"],
    "truth": { "source": "doh", "ips": ["172.217.26.36"] },
    "local": [{ "server": "10.0.0.1", "rcode": 0, "class": "sinkhole" }],
    "cloaking": { "chain": [], "vendor": null },
    "tls": [{ "ip": "172.217.26.36", "status": "ok", "tls": "TLSv1.3" }]
  }],
  "summary": { "total": 1, "blocked": 1, "allowed": 0 }
}
```

## Recipes

```sh
# nightly check of the blocklist, alert on anything that leaks
blockcheck -f blocked.txt --quiet || omalauncher notify "blocklist" "something is not blocked"

# is my resolver the problem, or the uplink?
blockcheck example.com -r 192.168.1.1
blockcheck example.com -r 1.1.1.1

# what does the zone itself say? (bypasses every recursive resolver)
blockcheck example.com --auth -v

# find first-party CNAME cloaking in a list of sites
blockcheck -f sites.txt --json | jq -r '.targets[] | select(.cloaking.vendor) |
  "\(.target) -> \(.cloaking.tracker) (\(.cloaking.vendor))"'

# which of these are filtered only at DNS?
blockcheck -f domains.txt --json |
  jq -r '.targets[] | select(.paths.dns=="filtered" and .paths.tls=="ok") | .target'
```

## How the verdict is decided

For each record type the tool picks a **truth** answer, in order of how hard it is
to intercept: DoH, then a public resolver, then the local one. A local answer is
`BLOCKED` when it is NXDOMAIN/SERVFAIL/REFUSED/NODATA, a sinkhole or block-page
address, a private address where the truth is public, or no answer at all while
the truth has one. Transport is judged separately: TCP failure to every address
counts as a block only if a baseline probe shows the uplink can reach 443 at all;
a TCP connect followed by a TLS failure is reported as SNI filtering; a
certificate for another name is reported as MITM/portal.

That separation is the point: `dns: filtered  tls: ok` means a resolver policy
you can bypass, while `dns: ok  tls: sni-filtered` means the block is on the wire
and a different resolver will not help.

## Caveats

- Port 53 is frequently intercepted on-path, so a "clean" public resolver can
  still return the filtered answer. DoH is the default ground truth for exactly
  that reason; `--no-doh` weakens the comparison.
- Some middleboxes drop DNS queries that set the EDNS0 DO bit. That is why
  DNSSEC is opt-in (`--dnssec`) rather than always on.
- Block-page detection is heuristic: it looks for vendor names and wording in the
  page plus the status code, and labels it "looks like a block page".
- `--auth` needs the zone's nameservers to be reachable on port 53/udp.
- Only IPv4 is probed when the network has no working IPv6 path.

## Tests

Offline — two mock resolvers on loopback, no network needed:

```sh
python3 tests/test_classification.py
```

Covers every DNS classification path, sinkhole vs truth handling, CNAME
cloaking vs a legitimate CDN edge, target normalisation, eTLD+1, IP
classification and certificate name matching.

## License

MIT — see [LICENSE](LICENSE).
