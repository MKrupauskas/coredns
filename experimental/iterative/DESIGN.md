# A practical route to opt-in native recursion

Research snapshot: 2026-11-08. This is a proposal for discussion, not maintainer
approval or a production recommendation.

## Issue strategy and first step

Revive the discussion on [#2216](https://github.com/coredns/coredns/issues/2216)
with a concise design and this experiment. Do not open another broad feature
request immediately. The issue is closed, unlocked, labelled external, and was
closed in 2019 after work stalled. Its last comment in 2021 asks whether the
author still wants an official plugin. Closure is not evidence that the
functionality was implemented or rejected on principle.

The useful maintainer signals are specific:

* [Design request](https://github.com/coredns/coredns/issues/2216#issuecomment-431517790):
  explain the resolution loop, its termination, cache behavior and TTLs.
* [External plugin first](https://github.com/coredns/coredns/issues/2216#issuecomment-431973042),
  followed by [possible later default shipping](https://github.com/coredns/coredns/issues/2216#issuecomment-446356783).
* [Review and ownership](https://github.com/coredns/coredns/issues/2216#issuecomment-431419594)
  need to be settled before incorporation.

The older [#27](https://github.com/coredns/coredns/issues/27) was deferred for
workload/priorities. [#5402](https://github.com/coredns/coredns/issues/5402)
confirms forwarding versus recursion and mentions wrapping domainr/dnsr as an
external plugin. Neither supplies a modern validating engine acceptance plan.
Searches of CoreDNS issue/PR titles and bodies for recursive, resolver and
iterative did not identify a newer dedicated replacement; search is not proof
that no related work exists. The published [CoreDNS setup manual](https://coredns.io/manual/installation/)
still describes external libunbound integration rather than native Go recursion.

**First maintainer-facing step:** ask whether an independently maintained
external plugin backed by an embeddable validating engine, with explicit
conformance gates, is still the preferred path. Present this evidence and ask
about ownership and cache placement. If maintainers want current tracking,
open one narrowly titled design issue referencing #2216; leave the historical
thread as context. No new issue or comment has been posted by this experiment.

## Candidate assessment

| Candidate | What the evidence supports | Decision |
| --- | --- | --- |
| [SDNS](https://github.com/semihalev/sdns) | MIT Go server; validating iteration, denial handling, work accounting and rich cache metadata. The originally proposed engine in #2216. Inspected at `2226f31b50fd1f146f452165acdcd7520213ea8f`. | Best reuse candidate to investigate, conditional on extraction/lifecycle and cache fixes. Prototype it rather than rewrite its validator. |
| [nsmithuk/resolver](https://github.com/nsmithuk/resolver) | Convenient Go API and DNSSEC package, but README explicitly calls it alpha and unsuitable for security-critical reliance. Inspected at `a1d51ff98c12823fad5e9190d4791ca8abe058c7`. | Useful comparison, not an enterprise default. |
| [domainr/dnsr](https://github.com/domainr/dnsr) | Small iterative API, context support and claimed Domainr production use; TTL expiry is an option. No DNSSEC validator found in the inspected Go source. | Does not supply the required validation boundary. Production use for its purpose does not fill that gap. |
| [ZDNS](https://github.com/zmap/zdns) | Maintained Go measurement toolkit with iterative lookup and local DNSSEC validation, using its own DNS fork and result model. | Real candidate, but requires API/cache/serving adaptation and a separate resource/conformance review. Useful differential client; not assumed a drop-in server engine. |
| [Labyrinth](https://github.com/labyrinthdns/labyrinth) | MIT Go server advertises validation, caching, work controls and many serving/UI features. README and repository surface inspected, not a deep security audit. | Secondary extraction candidate; do not infer maturity from a long feature list. |
| [CoreDNS recursor external plugin](https://coredns.io/explugins/recursor/) | Documented aliases and configured upstream resolvers. | Its name does not establish root-to-authority iteration or DNSSEC validation. |
| [RouteDNS](https://github.com/folbricht/routedns) / Go `net.Resolver` | Stub/proxy/routing facilities; the latter delegates to configured recursive servers. | Not a validating iterative engine for this purpose. |
| [miekg/dns](https://github.com/miekg/dns) | Wire messages, transport and DNSSEC primitives. | Necessary building blocks, not a complete cache/validator/iterator. |
| [libunbound plugin](https://coredns.io/explugins/unbound/) | Mature resolver integration through C. | Reasonable operational baseline, but improving its wrapper does not satisfy the requested pure Go packaging goal. |

This is a selection for an experiment, not a claim that all alternatives were
audited or SDNS has passed independent conformance. Reimplementing DNSSEC from
scratch would enlarge the hardest review surface without solving maintenance.

## Target architecture

Use a separately maintained engine module with an instance-owned resolver and
`Resolve(ctx, question, policy)` / `Close()` lifecycle. Construct and validate
an instance before exposing it to CoreDNS; drain/cancel on reload or shutdown.
No global registry, fatal exits, implicit listeners, system resolver fallback,
or uncancellable initialization. Keep logging, metrics, policy and transport
injected. A thin external CoreDNS plugin owns client policy and protocol
translation. Only consider inclusion in the standard static binary after the
external plugin has operational evidence and named maintainers. Shipping the
code by default and enabling recursion at runtime are separate decisions.

For the eventual user experience, propose `iterative` as an explicit terminal
Corefile directive. Public recursion requires explicit client CIDRs; default
deny/loopback. Keep internal authoritative zones in more specific server blocks,
and isolate internal/public cache and validation policy. Configuration should
offer vetted defaults rather than an entire second server configuration.

### Resolver loop and termination

1. Validate client question and policy; check the appropriately partitioned
   validated answer/failure cache. Coalesce identical misses with a bounded
   waiter count; one waiter's cancellation must not cancel unrelated waiters.
2. Start at the longest still-valid cached delegation, or primed root hints.
   Send RD=0, use QNAME minimization with bounded compatibility fallback.
3. Admit referrals only for an advancing zone cut ancestral to the question.
   Validate delegation state; accept only relevant in-bailiwick glue for listed
   NS names. Resolve missing/out-of-bailiwick NS addresses through bounded
   subqueries. Never promote unrelated additional data to trusted answers.
4. Try a bounded selection of reachable authorities; validate response source,
   ID and question, retry truncated UDP over TCP under the same request budget.
   Share deadlines/work accounting across aliases, NS address queries, DS,
   DNSKEY, retries, parallel attempts and DNSSEC proof work.
5. Follow bounded CNAME/DNAME chains and detect repeated states. Finish only
   with a validated positive answer, authenticated negative answer, proven
   insecure answer, explicit policy rejection or failure. Exhaustion/deadline/
   bogus validation returns SERVFAIL (with bounded EDE where appropriate),
   never an unchecked answer disguised as success.

Bound total queries, recursion/alias depth, per-authority attempts, outstanding
requests/sockets, queued work and waiters, bytes retained and processed, DNSKEY
candidates, signatures, DS digests and NSEC3 work. Have both per-request and
global crypto/concurrency gates. Use circuit breaking and bounded failure
caching without letting one failed authority consume all capacity. Enforce
destination policy on every address discovered from DNS, not just seed hints;
otherwise untrusted delegations can drive traffic to internal services.

### DNSSEC semantics

Validate regardless of whether clients request DNSSEC records with DO. DO is
about response records; it is not permission to skip validation. Track secure,
insecure, bogus and indeterminate internally; never trust an upstream AD bit.
Respect CD semantics with isolated cache provenance and only assert AD when
the returned data actually meets the local validation and client flag rules.
Test mixed-security aliases and negative responses, not just signed A answers.

Validation includes root-to-child DS/DNSKEY transitions, supported algorithm
and digest policy, wildcard expansion, NSEC/NSEC3 denial and opt-out, missing
proofs, revoked keys, signature windows, and bounded crypto work. Validate
policy against current DNSSEC algorithm requirements during implementation.

Seed current authenticated root trust anchors; support durable RFC 5011 state
with atomic persistence and safe restart/read-only behavior. [IANA](https://www.iana.org/dnssec/files)
reports KSK 38696 signing since 2026-10-11. An old-key-only seed is not a safe
late-2026 default. Clock validity and trust-state errors need explicit startup
and observability behavior; an ordinary configuration reload must not reset
hold-down timers.

### Cache contract

The engine owns delegation, glue, DNSKEY/DS, authenticated denial and failure
state. Prefer one engine-owned answer cache initially, since SDNS requires
provenance/delegation leases not carried in a plain dns.Msg. Do not silently
layer CoreDNS cache on it. If answer caching is moved outward later, define and
test a metadata contract before changing ownership.

RRsets expire no later than authoritative TTL. Zero TTL is transaction-only;
no minimum TTL may extend unsigned data. Validated lifetime is also capped by
RRSIG TTL, original TTL and signature expiration. Age TTLs on copies; never
share mutable messages across requests. Negative lifetime follows RFC 2308
SOA TTL/MINIMUM, with separate NXDOMAIN and NODATA keys and no unsupported
negative caching without SOA. Bind cached answers to the delegation/validation
provenance that justified them. Partition unchecked/CD and validated data,
classes, views, trust/policy epochs and ECS scopes if ECS is ever introduced.
Keep ECS disabled initially. Cap failures according to RFC 9520; overload or
request-local budget failures must not poison global answer state. Stale
serving and aggressive denial reuse should be deferred until independently
tested, with signature and delegation bounds intact.

### Large deployments

Recursion removes dependence on public-recursive per-source quotas; it does
not guarantee unlimited scalability. Authoritative servers also limit traffic.
Start with anonymized workload/QPS, cache-hit and unique-name measurements,
tail latency and failure budgets. Plan egress capacity, NAT/conntrack/source-port
entropy, UDP/TCP reachability, IPv6 behavior, per-site caches and cold-start
storms. Measure random-subdomain abuse and partial-authority outages, not only
warm repeated names. Monitor work per miss, cache bytes, budget rejections,
validation outcomes, inflight queries and per-authority circuit state, using
bounded metric labels. Do not put queried names in metric labels.

## Acceptance stages

1. Maintainers agree on external plugin scope, ownership, cache contract and
   engine extraction direction. This approval is still pending.
2. Engine instance lifecycle and strict TTL/resource policies are fixed and
   covered by deterministic signed root/TLD/child fixtures. Add a transport
   injection seam so these fixtures exercise the **actual adapter** offline.
3. Run the RFC 1034/1035, 2181, 2308, 4033–4035, 5155, 5452, 6891, 7766,
   8020, 8198 (if enabled), 8482, 8767 (if enabled), 8914, 9156 and 9520
   applicable cases. Map test cases to requirements and capture exceptions.
   Include malformed messages, bailiwick poisoning, lame/referral loops,
   missing glue, DS-at-parent, mixed-security aliases, wildcard denials,
   DNSSEC downgrade, signature/key/hash exhaustion and rollover/restart.
4. Differential tests against pinned Unbound and BIND/Knot versions; use
   controlled authoritative fixtures, not agreement as a substitute for RFC
   assertions. Fuzz message/referral/proof handling; race and leak tests with
   cancellation, startup failures and repeated reloads. Confirm CGO-disabled
   Linux builds and transport behavior on supported platforms.
5. Reproducible load tests at an agreed workload, then isolated shadow traffic,
   a limited canary with SLO/rollback criteria, and sustained external-plugin
   operation. Only then discuss bundling by default. None of stages 2–5 is
   complete in this prototype.
