package recursive

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin/pkg/cache"
	"github.com/coredns/coredns/plugin/pkg/singleflight"

	"github.com/miekg/dns"
)

const (
	defaultTimeout = 2 * time.Second  // per query sent to an authoritative server
	resolveTimeout = 10 * time.Second // per client query, including all upstream queries
	udpSize        = 1232             // EDNS0 buffer size, see https://www.dnsflagday.net/2020/

	maxReferrals   = 16  // referrals followed for a single name
	maxCNAMEs      = 12  // CNAME (and DNAME synthesized CNAME) hops
	maxDepth       = 6   // nesting of name server address lookups for glueless delegations
	maxQueries     = 100 // upstream queries for one client query, including nested lookups
	maxServerTries = 6   // servers tried for one step before giving up

	minDelegationTTL = 5 * time.Second
	maxDelegationTTL = 24 * time.Hour
	delegationCache  = 10000
)

var (
	errBudget         = errors.New("query budget exhausted")
	errNoServers      = errors.New("no usable name servers")
	errTooManyCNAMEs  = errors.New("CNAME chain too long")
	errTooDeep        = errors.New("name server lookups nested too deeply")
	errTooManyReferal = errors.New("too many referrals")
	errMismatch       = errors.New("response does not match the question")
)

// result is the outcome of resolving a name. It is shared between all callers waiting on the
// same resolution, so it must not be modified.
type result struct {
	rcode  int
	answer []dns.RR
	ns     []dns.RR // SOA for negative answers
}

// delegation is a set of name server addresses for a zone, learned from a referral.
type delegation struct {
	zone    string
	servers []string // host:port
	expires time.Time
}

// resolver performs iterative resolution, starting at the root servers and following referrals
// down to the authoritative servers for a name.
type resolver struct {
	roots   []string // host:port
	port    string   // port used for name servers learned from referrals
	timeout time.Duration
	ipv6    bool

	// allowLoopback permits sending queries to loopback addresses learned from referrals. It is
	// only set in tests: in production a referral to 127.0.0.1 is a misconfiguration or an attack.
	allowLoopback bool

	deleg *cache.Cache[*delegation]
	group singleflight.Group
	now   func() time.Time
}

func newResolver() *resolver {
	r := &resolver{
		port:    "53",
		timeout: defaultTimeout,
		deleg:   cache.New[*delegation](delegationCache),
		now:     time.Now,
	}
	r.setRoots(false)
	return r
}

// setRoots sets the root servers from the built-in root hints.
func (r *resolver) setRoots(ipv6 bool) {
	r.roots = r.roots[:0]
	for _, h := range rootHints {
		r.roots = append(r.roots, net.JoinHostPort(h.v4, "53"))
		if ipv6 {
			r.roots = append(r.roots, net.JoinHostPort(h.v6, "53"))
		}
	}
}

// budget limits the work done for a single client query. The resolution of one client query is
// sequential, so it does not need to be safe for concurrent use.
type budget struct{ queries int }

func (b *budget) spend() error {
	if b.queries <= 0 {
		return errBudget
	}
	b.queries--
	return nil
}

// Resolve resolves qname/qtype. Concurrent calls for the same question share one resolution.
func (r *resolver) Resolve(ctx context.Context, qname string, qtype uint16) (*result, error) {
	qname = strings.ToLower(dns.Fqdn(qname))
	key := cache.Hash([]byte(fmt.Sprintf("%s/%d", qname, qtype)))

	v, err := r.group.Do(key, func() (any, error) {
		// The resolution is shared with other callers, so it must not be cancelled when the
		// first caller goes away.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), resolveTimeout)
		defer cancel()
		return r.resolve(ctx, qname, qtype, &budget{queries: maxQueries}, 0)
	})
	if err != nil {
		return nil, err
	}
	return v.(*result), nil
}

// resolve resolves qname/qtype, following CNAMEs.
func (r *resolver) resolve(ctx context.Context, qname string, qtype uint16, b *budget, depth int) (*result, error) {
	if depth > maxDepth {
		return nil, errTooDeep
	}

	res := &result{rcode: dns.RcodeSuccess}
	name := qname
	for range maxCNAMEs {
		msg, zone, err := r.iterate(ctx, name, qtype, b, depth)
		if err != nil {
			return nil, err
		}

		rrs, target, found := followChain(msg.Answer, name, qtype, zone)
		res.answer = append(res.answer, rrs...)
		if found {
			return res, nil
		}
		if target != name {
			// The chain leaves data this server can vouch for; resolve the rest from scratch.
			name = target
			continue
		}

		// No data for name: NXDOMAIN or NODATA. Keep the SOA so the answer can be cached.
		res.rcode = msg.Rcode
		res.ns = soa(msg.Ns, zone, name)
		return res, nil
	}
	return nil, errTooManyCNAMEs
}

// iterate sends qname/qtype to the closest known name servers and follows referrals until it gets
// an answer or a negative response. It returns that response and the zone of the server that sent it.
func (r *resolver) iterate(ctx context.Context, qname string, qtype uint16, b *budget, depth int) (*dns.Msg, string, error) {
	zone, servers := r.closest(qname, qtype)
	for range maxReferrals {
		msg, err := r.queryAny(ctx, servers, qname, qtype, zone, b)
		if err != nil {
			if zone != "." && !errors.Is(err, errBudget) {
				// Forget the delegation, so the next query learns it again from the parent zone
				// instead of failing until it expires.
				r.deleg.Remove(cache.Hash([]byte(zone)))
			}
			return nil, "", fmt.Errorf("querying %s servers for %s/%s: %w", zone, qname, dns.TypeToString[qtype], err)
		}

		child, nsNames, ttl := referral(msg, zone, qname)
		if child == "" || len(msg.Answer) > 0 || msg.Rcode != dns.RcodeSuccess {
			return msg, zone, nil
		}

		addrs, glueTTL := r.glue(msg.Extra, nsNames, zone)
		ttl = min(ttl, glueTTL)
		if len(addrs) == 0 {
			addrs, err = r.lookupServers(ctx, nsNames, b, depth)
			if err != nil {
				return nil, "", fmt.Errorf("resolving name servers for %s: %w", child, err)
			}
		}
		r.store(child, addrs, ttl)
		zone, servers = child, addrs
	}
	return nil, "", errTooManyReferal
}

// closest returns the deepest cached zone above qname and its servers, falling back to the roots.
func (r *resolver) closest(qname string, qtype uint16) (string, []string) {
	name := qname
	if qtype == dns.TypeDS && name != "." {
		// DS records live in the parent zone.
		name = parent(name)
	}
	now := r.now()
	for {
		if d, ok := r.deleg.Get(cache.Hash([]byte(name))); ok && d.zone == name && now.Before(d.expires) {
			delegationCacheCount.WithLabelValues("hit").Inc()
			return d.zone, d.servers
		}
		if name == "." {
			break
		}
		name = parent(name)
	}
	delegationCacheCount.WithLabelValues("miss").Inc()
	return ".", r.roots
}

func (r *resolver) store(zone string, servers []string, ttl time.Duration) {
	ttl = max(min(ttl, maxDelegationTTL), minDelegationTTL)
	r.deleg.Add(cache.Hash([]byte(zone)), &delegation{zone: zone, servers: servers, expires: r.now().Add(ttl)})
}

// lookupServers resolves the addresses of name servers for a delegation that came without glue.
// One name server with addresses is enough: resolving all of them would multiply the work for
// every glueless delegation.
func (r *resolver) lookupServers(ctx context.Context, nsNames []string, b *budget, depth int) ([]string, error) {
	types := []uint16{dns.TypeA}
	if r.ipv6 {
		types = append(types, dns.TypeAAAA)
	}

	lastErr := errNoServers
	for _, i := range rand.Perm(len(nsNames)) { // #nosec G404 -- non-cryptographic RNG by design (server selection only).
		var addrs []string
		for _, t := range types {
			res, err := r.resolve(ctx, nsNames[i], t, b, depth+1)
			if err != nil {
				lastErr = err
				if errors.Is(err, errBudget) || ctx.Err() != nil {
					return nil, err
				}
				continue
			}
			for _, rr := range res.answer {
				if a := r.addr(rr); a != "" {
					addrs = append(addrs, a)
				}
			}
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
	}
	return nil, lastErr
}

// glue returns the addresses in extra for the name servers in nsNames. Glue is only accepted for
// names within zone, the zone of the server that sent it, so a server can't inject addresses for
// names it is not responsible for.
func (r *resolver) glue(extra []dns.RR, nsNames []string, zone string) ([]string, time.Duration) {
	var addrs []string
	ttl := maxDelegationTTL
	for _, rr := range extra {
		name := rr.Header().Name
		if !dns.IsSubDomain(zone, name) || !containsFold(nsNames, name) {
			continue
		}
		if a := r.addr(rr); a != "" {
			addrs = append(addrs, a)
			ttl = min(ttl, time.Duration(rr.Header().Ttl)*time.Second)
		}
	}
	return addrs, ttl
}

// addr returns the host:port for an A or AAAA record, or "" if it should not be used.
func (r *resolver) addr(rr dns.RR) string {
	var ip net.IP
	switch rr := rr.(type) {
	case *dns.A:
		ip = rr.A
	case *dns.AAAA:
		if !r.ipv6 {
			return ""
		}
		ip = rr.AAAA
	default:
		return ""
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return ""
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() || (a.IsLoopback() && !r.allowLoopback) {
		return ""
	}
	return net.JoinHostPort(a.String(), r.port)
}

// queryAny sends the question to servers, in random order, until one gives a usable response.
func (r *resolver) queryAny(ctx context.Context, servers []string, qname string, qtype uint16, zone string, b *budget) (*dns.Msg, error) {
	lastErr := errNoServers
	for n, i := range rand.Perm(len(servers)) { // #nosec G404 -- non-cryptographic RNG by design (server selection only).
		if n >= maxServerTries {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := b.spend(); err != nil {
			return nil, err
		}
		msg, err := r.exchange(ctx, servers[i], qname, qtype)
		if err != nil {
			upstreamQueryCount.WithLabelValues("error").Inc()
			lastErr = err
			continue
		}
		upstreamQueryCount.WithLabelValues(dns.RcodeToString[msg.Rcode]).Inc()
		if !usable(msg, zone, qname) {
			lastErr = fmt.Errorf("unusable response from %s: %s", servers[i], dns.RcodeToString[msg.Rcode])
			continue
		}
		return msg, nil
	}
	return nil, lastErr
}

// exchange sends one non-recursive query over UDP, retrying over TCP if the response is truncated.
func (r *resolver) exchange(ctx context.Context, server, qname string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = false
	m.SetEdns0(udpSize, false)

	c := &dns.Client{Net: "udp", Timeout: r.timeout, UDPSize: udpSize}
	resp, _, err := c.ExchangeContext(ctx, m, server)
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.ExchangeContext(ctx, m, server)
	}
	if err != nil {
		return nil, err
	}
	if len(resp.Question) != 1 || !strings.EqualFold(resp.Question[0].Name, qname) || resp.Question[0].Qtype != qtype {
		return nil, errMismatch
	}
	return resp, nil
}

// usable reports whether msg is a response we can act on: an answer, a negative answer or a
// referral further down the tree. Anything else (SERVFAIL, REFUSED, lame or upward referrals)
// means another server should be tried.
func usable(msg *dns.Msg, zone, qname string) bool {
	switch msg.Rcode {
	case dns.RcodeNameError:
		return true
	case dns.RcodeSuccess:
	default:
		return false
	}
	if len(msg.Answer) > 0 || msg.Authoritative {
		return true
	}
	if child, _, _ := referral(msg, zone, qname); child != "" {
		return true
	}
	for _, rr := range msg.Ns {
		if rr.Header().Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}

// referral returns the child zone, its name servers and their TTL if msg delegates qname to a
// zone below zone.
func referral(msg *dns.Msg, zone, qname string) (string, []string, time.Duration) {
	var (
		child string
		names []string
		ttl   = maxDelegationTTL
	)
	for _, rr := range msg.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		owner := strings.ToLower(ns.Hdr.Name)
		if child == "" {
			if owner == zone || !dns.IsSubDomain(zone, owner) || !dns.IsSubDomain(owner, qname) {
				continue
			}
			child = owner
		}
		if owner != child {
			continue
		}
		names = append(names, strings.ToLower(ns.Ns))
		ttl = min(ttl, time.Duration(ns.Hdr.Ttl)*time.Second)
	}
	return child, names, ttl
}

// followChain collects the records for name and qtype from rrs, following CNAMEs. Only records
// within zone are used. It returns the records, the name at the end of the chain, and whether
// records of qtype were found for it.
func followChain(rrs []dns.RR, name string, qtype uint16, zone string) ([]dns.RR, string, bool) {
	var out []dns.RR
	for range maxCNAMEs {
		var (
			found bool
			next  string
		)
		for _, rr := range rrs {
			h := rr.Header()
			if h.Class != dns.ClassINET || !strings.EqualFold(h.Name, name) || !dns.IsSubDomain(zone, h.Name) {
				continue
			}
			switch {
			case h.Rrtype == qtype || qtype == dns.TypeANY:
				out = append(out, rr)
				found = true
			case h.Rrtype == dns.TypeCNAME && next == "":
				out = append(out, rr)
				next = strings.ToLower(rr.(*dns.CNAME).Target)
			}
		}
		if found || next == "" {
			return out, name, found
		}
		name = next
	}
	return out, name, false
}

// soa returns the SOA records from ns that may be used for a negative answer for name.
func soa(ns []dns.RR, zone, name string) []dns.RR {
	var out []dns.RR
	for _, rr := range ns {
		h := rr.Header()
		if h.Rrtype == dns.TypeSOA && dns.IsSubDomain(zone, h.Name) && dns.IsSubDomain(h.Name, name) {
			out = append(out, rr)
		}
	}
	return out
}

func parent(name string) string {
	off, end := dns.NextLabel(name, 0)
	if end {
		return "."
	}
	return name[off:]
}

func containsFold(names []string, name string) bool {
	for _, n := range names {
		if strings.EqualFold(n, name) {
			return true
		}
	}
	return false
}
