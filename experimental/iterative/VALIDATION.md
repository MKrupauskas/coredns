# Validation record — 2026-11-08

Environment: macOS arm64, Go 1.27.3 (official archive SHA-256 checked).
CoreDNS baseline: `603b99c1880fd95d5ff7f72aa3e5c18812314abb`.
SDNS baseline: `2226f31b50fd1f146f452165acdcd7520213ea8f`.

## Adapter checks

`go test -race -count=1 ./...` passed. Default tests are local and do not
construct the real resolver. The public-network test is skipped unless enabled.

Covered: refusing remote clients, malformed/multiple questions and non-QUERY
messages; RD=0, CHAOS, transfer and ANY rejection; immediate overload rejection;
parent cancellation and bounded deadline; admission-slot release; request and
response copying; AA/RD/RA/CD/ID handling; UDP truncation versus TCP responses;
socket write errors; missing anchors, unknown keys, attempts to enable
forwarding/disable validation, hostname root hints and nonstandard root ports.

`go vet ./...` passed.

## Actual engine through the adapter

An explicit public-network smoke test passed with the race detector:

```sh
mkdir -p /tmp/coredns-iterative-state
ITERATIVE_LIVE_CONFIG=example.toml go test -race -run TestLiveValidatingAdapter -count=1 -v
```

This constructs the real plugin using its Corefile setup, runs its actual SDNS
pipeline, checks two successful validated `cloudflare.com` queries, checks
SERVFAIL with AD clear for `dnssec-failed.org`, and rejects a second setup.
Public-domain behavior can change; this is an opt-in smoke test, not a stable
fixture or conformance certificate. It writes trust-anchor state.

A separate native binary was started with Corefile.example and queried over
UDP at 127.0.0.1:1053. Observed client timings were:

| Query | Result | AD | Answers | Client elapsed |
| --- | --- | --- | --- | --- |
| cloudflare.com A, first | NOERROR | true | 3 | 83.8 ms |
| cloudflare.com A, repeat | NOERROR | true | 3 | 0.48 ms |
| dnssec-failed.org A | SERVFAIL | false | 0 | 720.6 ms |

These timings are one smoke run, not a performance comparison or scale result.
Logs showed the bogus domain failing its parent DS/DNSKEY check. The process
was stopped after the smoke test.

## Selected upstream engine tests

At the pinned SDNS checkout, this passed under the race detector:

```sh
go test -race -json ./middleware/resolver ./middleware/cache ./internal/dnsutil \
  -run 'Test(Hermetic|.*RecursionWork|AdmissionOnlyShortens|DenialAdmittedAtItsOwnLifetime|ZeroLifetimeDenial|SignedAnswerKeepsItsCeiling|SignedReferralNeverOutlives)' \
  -count=1 -timeout=90s
```

The JSON record contained 69 successful test/subtest events, no failures:
39 in resolver and 30 in cache. The dnsutil package had no tests matching this
selection. Cases include a signed local hierarchy, secure/bogus/wrong-DS
answers, insecure delegations, NSEC3 denials/opt-out, missing denial coverage,
resolution recovery, request work accounting, negative/zero-TTL admission and
signature/delegation cache ceilings. These are **upstream engine** tests with
its own fixtures and seams, not adapter end-to-end conformance tests.

## Packaging

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o coredns-iterative-linux ./cmd/coredns-iterative
file coredns-iterative-linux
```

Passed. `file` identified an x86-64 Linux ELF executable, **statically linked**.
The Linux binary was not executed on a Linux host in this experiment. The
native CGO-disabled macOS binary was executed for the UDP smoke test.

## Not established

No complete RFC/conformance suite, independent validator audit, full engine
test suite, fuzzing campaign, reload leak testing, Linux runtime test,
IPv6-only delegation test, deterministic signed adapter hierarchy, enterprise
load benchmark or canary deployment was completed. The five-second positive
TTL floor and aggregate memory/lifecycle gaps remain. See DESIGN.md for gates.
