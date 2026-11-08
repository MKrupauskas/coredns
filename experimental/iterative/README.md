# Iterative resolver embedding experiment

**Lab only. Not a proposed default CoreDNS plugin or production resolver.**

This isolated Go module runs CoreDNS with an opt-in `iterative_lab` terminal
handler. It embeds the pinned SDNS EDNS, answer cache and validating iterative
resolver pipeline in the same process. There is no libunbound, cgo dependency,
external resolver process, or public recursive forwarding configuration.

The purpose is to test whether reusing SDNS is a practical route to the request
in coredns/coredns#2216. No default plugin list, generated files, or parent
module dependencies are changed. The module pins CoreDNS to the parent source
revision rather than depending on uncommitted parent changes.

## Build and run

From this directory, with Go 1.27:

```sh
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o coredns-iterative-linux ./cmd/coredns-iterative
CGO_ENABLED=0 go build -o coredns-iterative ./cmd/coredns-iterative
mkdir -p /tmp/coredns-iterative-state
./coredns-iterative -conf Corefile.example
```

The example binds to 127.0.0.1:1053. The adapter also rejects non-loopback
clients itself, before cache lookup. It supports one instance per process and
rejects subsequent setup/reload attempts. Restart the process to change
configuration. Its small binary registers only `bind`, `errors`, `log` and this
handler (plus CoreDNS's built-in infrastructure). It does not register the
CoreDNS `cache`, `forward`, or `reload` plugins. This avoids introducing a second
answer cache or a forwarding fallback into the experiment.

The TOML file has exactly three fields: `directory`, `roots`, and `anchors`.
Unknown fields are rejected. Roots must be literal IPv4 addresses on port 53.
Anchors must parse as root IN SEP DNSKEYs; this parser check does **not** establish
their authenticity. The sample key 38696 was retrieved over HTTPS from IANA's
root-anchors.xml on 2026-11-08; its S/MIME signature was not independently
verified in this experiment. Establish seed trust through your approved process.
The directory holds SDNS trust-anchor state and must be writable. An Internet
connection permitting outbound UDP and TCP port 53 is required for public lookups.

## Implemented boundaries

* Loopback-only recursion, one IN question, QUERY opcode, RD required; reject
  transfers and ANY. Unknown configuration cannot silently enable forwarding.
* At most 64 admitted client requests, with immediate REFUSED on overload and
  a five-second request deadline. No adapter-side waiting queue or detached
  timeout goroutine.
* SDNS validation is always enabled. Its request-tree work policy is explicitly
  `enforce`, with 64 outbound and 64 internal queries, depth 24, 1-second
  upstream timeout, and 64 engine concurrency slots. Normalized crypto limits
  are 4 DNSKEY candidates, 8 checks per RRset, 32 signature checks, 32 DS
  digests, 32 NSEC3 hashes and 32 concurrent crypto operations. These are lab
  choices, not capacity recommendations; independent upkeep has separate work.
* One SDNS answer cache/store is shared with internal DNSSEC/NS/alias queries
  through SDNS's own auto-wiring. It carries delegation lease and validated
  denial metadata which would be lost by a naive dns.Msg-only cache wrapper.
* Request and response ownership is copied; the adapter clears AA, restores
  client ID/RD/CD, sets RA, and truncates UDP replies to 512 or the advertised
  size capped at 1232. It propagates socket write failures.

## Known gaps that block adoption

* SDNS startup/pipeline/metrics are process-global. Resolver pruning,
  enrichment and periodic work lack a complete instance-scoped cancellation
  lifecycle. `Stop` only closes its TCP pool. Reload, multiple instances and
  clean failed-start cleanup are not solved here.
* `CacheSize=4096` is **not a process memory bound**. Delegation and glue caches
  have independent fixed capacities (262144 each); failure/proof caches,
  connection pools and background work add their own budgets. A configurable
  aggregate byte budget and per-authority fairness need review.
* SDNS's positive cache has a five-second minimum for some responses. That
  conflicts with the proposal's strict authoritative TTL ceiling for unsigned
  short/zero-TTL answers. Signed and negative TTL ceiling tests do not resolve
  this gap. Do not infer cache conformance from these results.
* Root priming, trust-anchor persistence/rollover, client CD/DO/AD combinations,
  all referral edge cases, IPv6-only authorities and authoritative transport
  recovery have not been independently certified through this adapter.
* There is no enterprise client ACL configuration, outbound destination policy,
  production metrics contract, benchmark, fuzz campaign, or deployment test.
  Public recursion can be induced to contact attacker-chosen authorities;
  network egress restrictions remain a required part of the future design.
* A pure Go static build proves packaging feasibility, not protocol correctness
  or performance at Uber scale.

See [DESIGN.md](DESIGN.md) for the proposed upstream approach and acceptance gates,
and [VALIDATION.md](VALIDATION.md) for exactly what was exercised.
