# recursive

## Name

*recursive* - resolves names iteratively from the authoritative name servers.

## Description

The *recursive* plugin makes CoreDNS a recursive resolver. It does not forward queries to an upstream
resolver such as 8.8.8.8. It starts at the root servers and follows referrals (root, then TLD, then the
zone's authoritative servers) until it gets an answer, the same way Unbound or BIND do.

In large deployments the volume of internet-bound lookups can exceed the rate limits of public
resolvers, which then answer with SERVFAIL or drop queries. Resolving iteratively spreads the load over
the authoritative servers of each zone, so no single third party sees all of the traffic.

The plugin keeps a cache of delegations (the name servers and addresses of each zone it has learned
about). After the first lookup in a zone, later lookups go straight to that zone's servers. Concurrent
queries for the same name and type share a single resolution.

*recursive* does not cache answers itself. Put the *cache* plugin in front of it, as in the examples
below.

The plugin:

* follows CNAME chains, resolving targets in other zones from scratch;
* resolves the addresses of name servers that are delegated without glue;
* retries over TCP when a response is truncated;
* tries other name servers when one times out or answers with SERVFAIL, REFUSED or a lame referral;
* only accepts glue and answer records for names within the zone of the server that sent them
  (the bailiwick check), and never sends queries to unspecified, multicast or loopback addresses
  that it learns from referrals;
* limits the work done for one client query: at most 100 upstream queries, 16 referrals per name,
  12 CNAME hops and 6 levels of nested name server lookups. If a query exceeds these limits, it is
  answered with SERVFAIL.

Answers keep the response code of the authoritative server (NOERROR or NXDOMAIN). Negative answers
include the zone's SOA record so they can be cached. Responses never have the AA bit set.

The plugin does not perform DNSSEC validation, and it does not return DNSSEC records unless they are
asked for explicitly.

## Syntax

~~~ txt
recursive [FROM...] {
    except IGNORED_NAMES...
    roots ADDRESS...
    timeout DURATION
    ipv6
}
~~~

* **FROM...** are the zones to resolve recursively. Queries for other names go to the next plugin.
  Defaults to the zones of the server block.
* `except` is a space-separated list of domains to exclude from recursive resolution. Queries for
  these names go to the next plugin.
* `roots` replaces the built-in root hints with **ADDRESS...**, a list of IP addresses with an
  optional port, for example `192.0.2.1` or `[2001:db8::1]:5353`. This is useful with a private root,
  or with a local copy of the root zone (RFC 8806).
* `timeout` is the time to wait for a response from one authoritative server before trying another.
  The default is 2s. The whole resolution of a client query is limited to 10s.
* `ipv6` also uses the IPv6 addresses of the root servers and of the name servers learned from
  referrals. By default only IPv4 is used, so that hosts without IPv6 connectivity do not wait for
  timeouts.

## Metrics

If monitoring is enabled (via the *prometheus* plugin) then the following metrics are exported:

* `coredns_recursive_upstream_queries_total{rcode}` - queries sent to authoritative servers, by
  response code; `rcode` is `error` when no response was received.
* `coredns_recursive_delegation_cache_total{result}` - lookups in the delegation cache; `result` is
  `hit` or `miss`.
* `coredns_recursive_resolution_failures_total` - client queries answered with SERVFAIL because the
  name could not be resolved.

## Examples

Resolve everything recursively and cache the answers:

~~~ corefile
. {
    cache
    recursive
}
~~~

Forward an internal domain to the corporate resolvers and resolve everything else recursively. The
*forward* plugin comes before *recursive* in the plugin chain, so it handles `corp.example.com`:

~~~ corefile
. {
    errors
    cache 30
    forward corp.example.com 10.0.0.53
    recursive
}
~~~

Use a local root server instead of the built-in root hints:

~~~ corefile
. {
    cache
    recursive . {
        roots 127.0.0.1:5300
    }
}
~~~

## See Also

The *forward* plugin forwards queries to an upstream recursive resolver.

## Bugs

There is no DNSSEC validation, QNAME minimisation (RFC 9156) or tracking of the response times
of name servers.
