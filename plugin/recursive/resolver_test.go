package recursive

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// hierarchy is a fake DNS tree served on several loopback addresses that share one port:
//
//	127.0.0.1  root        delegates com. and net. to 127.0.0.2
//	127.0.0.2  com., net.  delegates example.com. (with glue), example.net. (with glue) and
//	                       glueless.com. (to ns.example.net., without glue)
//	127.0.0.3  example.com., example.net.
//	127.0.0.4  glueless.com.
//	127.0.0.5  a broken root server that refuses everything
type hierarchy struct {
	port    string
	servers []*dns.Server

	mu      sync.Mutex
	queries map[string]int // by server IP
}

func soaRR(zone string) dns.RR {
	return test.SOA(zone + " 300 IN SOA ns.invalid. hostmaster.invalid. 1 7200 1800 86400 300")
}

func (h *hierarchy) serve(w dns.ResponseWriter, r *dns.Msg) {
	ip, _, _ := net.SplitHostPort(w.LocalAddr().String())
	h.mu.Lock()
	h.queries[ip]++
	h.mu.Unlock()

	m := new(dns.Msg)
	m.SetReply(r)
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	is := func(zone string) bool { return dns.IsSubDomain(zone, name) }

	switch ip {
	case "127.0.0.1":
		switch {
		case is("com."):
			m.Ns = []dns.RR{test.NS("com. 3600 IN NS a.gtld.com.")}
			m.Extra = []dns.RR{test.A("a.gtld.com. 3600 IN A 127.0.0.2")}
		case is("net."):
			m.Ns = []dns.RR{test.NS("net. 3600 IN NS a.gtld.net.")}
			m.Extra = []dns.RR{test.A("a.gtld.net. 3600 IN A 127.0.0.2")}
		default:
			m.Authoritative = true
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{soaRR(".")}
		}
	case "127.0.0.2":
		switch {
		case is("example.com."):
			m.Ns = []dns.RR{test.NS("example.com. 3600 IN NS ns1.example.com.")}
			m.Extra = []dns.RR{
				test.A("ns1.example.com. 3600 IN A 127.0.0.3"),
				// Out of bailiwick glue must be ignored.
				test.A("www.victim.org. 3600 IN A 192.0.2.66"),
			}
		case is("example.net."):
			m.Ns = []dns.RR{test.NS("example.net. 3600 IN NS ns.example.net.")}
			m.Extra = []dns.RR{test.A("ns.example.net. 3600 IN A 127.0.0.3")}
		case is("glueless.com."):
			m.Ns = []dns.RR{test.NS("glueless.com. 3600 IN NS ns.example.net.")}
		default:
			m.Authoritative = true
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{soaRR("com.")}
		}
	case "127.0.0.3":
		m.Authoritative = true
		switch {
		case name == "www.example.com." && q.Qtype == dns.TypeA:
			m.Answer = []dns.RR{test.A("www.example.com. 300 IN A 192.0.2.1")}
		case name == "www.example.com.":
			m.Ns = []dns.RR{soaRR("example.com.")}
		case name == "alias.example.com.":
			m.Answer = []dns.RR{
				test.CNAME("alias.example.com. 300 IN CNAME www.example.com."),
				test.A("www.example.com. 300 IN A 192.0.2.1"),
			}
		case name == "ext.example.com.":
			m.Answer = []dns.RR{
				test.CNAME("ext.example.com. 300 IN CNAME www.glueless.com."),
				// Not this server's data: must be ignored and resolved from glueless.com.
				test.A("www.glueless.com. 300 IN A 192.0.2.66"),
			}
		case name == "big.example.com." && w.LocalAddr().Network() == "udp":
			m.Truncated = true
		case name == "big.example.com.":
			m.Answer = []dns.RR{test.TXT(`big.example.com. 300 IN TXT "tcp"`)}
		case name == "ns.example.net.":
			m.Answer = []dns.RR{test.A("ns.example.net. 300 IN A 127.0.0.4")}
		case is("example.net."):
			m.Ns = []dns.RR{soaRR("example.net.")}
		default:
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{soaRR("example.com.")}
		}
	case "127.0.0.4":
		m.Authoritative = true
		if name == "www.glueless.com." {
			m.Answer = []dns.RR{test.A("www.glueless.com. 300 IN A 192.0.2.2")}
		} else {
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{soaRR("glueless.com.")}
		}
	default:
		m.Rcode = dns.RcodeRefused
	}
	w.WriteMsg(m)
}

func newHierarchy(t *testing.T) *hierarchy {
	t.Helper()
	ips := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"}
	h := &hierarchy{queries: map[string]int{}}

	for range 5 {
		h.close()
		h.servers = nil
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, h.port, _ = net.SplitHostPort(pc.LocalAddr().String())
		pc.Close()

		ok := true
		for _, ip := range ips {
			addr := net.JoinHostPort(ip, h.port)
			pc, err := net.ListenPacket("udp", addr)
			if err != nil {
				ok = false
				break
			}
			l, err := net.Listen("tcp", addr)
			if err != nil {
				pc.Close()
				ok = false
				break
			}
			handler := dns.HandlerFunc(h.serve)
			h.servers = append(h.servers,
				&dns.Server{PacketConn: pc, Handler: handler},
				&dns.Server{Listener: l, Handler: handler})
		}
		if ok {
			break
		}
	}
	if len(h.servers) != 2*len(ips) {
		h.close()
		t.Skip("can not listen on 127.0.0.2-5; loopback aliases are not available")
	}

	for _, s := range h.servers {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go s.ActivateAndServe()
		<-started
	}
	t.Cleanup(h.close)
	return h
}

func (h *hierarchy) close() {
	for _, s := range h.servers {
		s.Shutdown()
	}
}

func (h *hierarchy) count(ip string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.queries[ip]
}

func (h *hierarchy) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	clear(h.queries)
}

func (h *hierarchy) resolver() *resolver {
	r := newResolver()
	r.port = h.port
	r.allowLoopback = true
	r.roots = []string{net.JoinHostPort("127.0.0.1", h.port), net.JoinHostPort("127.0.0.5", h.port)}
	return r
}

func TestResolve(t *testing.T) {
	h := newHierarchy(t)

	tests := []struct {
		name   string
		qtype  uint16
		rcode  int
		answer []string
		ns     []string
	}{
		{"www.example.com.", dns.TypeA, dns.RcodeSuccess, []string{"www.example.com.\t300\tIN\tA\t192.0.2.1"}, nil},
		{"WWW.Example.COM.", dns.TypeA, dns.RcodeSuccess, []string{"www.example.com.\t300\tIN\tA\t192.0.2.1"}, nil},
		{"www.example.com.", dns.TypeAAAA, dns.RcodeSuccess, nil, []string{"example.com."}},
		{"nope.example.com.", dns.TypeA, dns.RcodeNameError, nil, []string{"example.com."}},
		{"nope.org.", dns.TypeA, dns.RcodeNameError, nil, []string{"."}},
		{"alias.example.com.", dns.TypeA, dns.RcodeSuccess, []string{
			"alias.example.com.\t300\tIN\tCNAME\twww.example.com.",
			"www.example.com.\t300\tIN\tA\t192.0.2.1",
		}, nil},
		// Glueless delegation; the out of zone A record in the CNAME response is not trusted.
		{"ext.example.com.", dns.TypeA, dns.RcodeSuccess, []string{
			"ext.example.com.\t300\tIN\tCNAME\twww.glueless.com.",
			"www.glueless.com.\t300\tIN\tA\t192.0.2.2",
		}, nil},
		{"big.example.com.", dns.TypeTXT, dns.RcodeSuccess, []string{"big.example.com.\t300\tIN\tTXT\t\"tcp\""}, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name+"/"+dns.TypeToString[tc.qtype], func(t *testing.T) {
			r := h.resolver()
			res, err := r.Resolve(context.Background(), tc.name, tc.qtype)
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if res.rcode != tc.rcode {
				t.Errorf("expected rcode %s, got %s", dns.RcodeToString[tc.rcode], dns.RcodeToString[res.rcode])
			}
			if len(res.answer) != len(tc.answer) {
				t.Fatalf("expected %d answers, got %v", len(tc.answer), res.answer)
			}
			for i, rr := range res.answer {
				if rr.String() != tc.answer[i] {
					t.Errorf("expected answer %q, got %q", tc.answer[i], rr.String())
				}
			}
			if len(res.ns) != len(tc.ns) {
				t.Fatalf("expected %d SOA records, got %v", len(tc.ns), res.ns)
			}
			for i, rr := range res.ns {
				if rr.Header().Name != tc.ns[i] || rr.Header().Rrtype != dns.TypeSOA {
					t.Errorf("expected SOA for %s, got %s", tc.ns[i], rr)
				}
			}
		})
	}
}

func TestResolveUsesDelegationCache(t *testing.T) {
	h := newHierarchy(t)
	r := h.resolver()

	if _, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if h.count("127.0.0.1") == 0 || h.count("127.0.0.2") == 0 {
		t.Fatalf("expected the first query to start at the root, got %v", h.queries)
	}

	h.reset()
	if _, err := r.Resolve(context.Background(), "nope.example.com.", dns.TypeA); err != nil {
		t.Fatal(err)
	}
	if h.count("127.0.0.1") != 0 || h.count("127.0.0.2") != 0 || h.count("127.0.0.5") != 0 || h.count("127.0.0.3") != 1 {
		t.Errorf("expected a single query to the example.com. server, got %v", h.queries)
	}
}

func TestResolveNoUsableServers(t *testing.T) {
	h := newHierarchy(t)
	r := h.resolver()
	r.roots = []string{net.JoinHostPort("127.0.0.5", h.port)}

	if _, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA); err == nil {
		t.Fatal("expected an error when all root servers refuse")
	}
}

func TestRecursiveServeDNS(t *testing.T) {
	h := newHierarchy(t)
	rc := New()
	rc.r = h.resolver()
	rc.ignored = []string{"internal.example.com."}
	rc.Next = test.NextHandler(dns.RcodeRefused, nil)

	m := new(dns.Msg)
	m.SetQuestion("WWW.example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, err := rc.ServeDNS(context.Background(), rec, m); err != nil {
		t.Fatal(err)
	}
	if !rec.Msg.RecursionAvailable || rec.Msg.Authoritative {
		t.Errorf("expected RA and no AA, got %v", rec.Msg.MsgHdr)
	}
	if len(rec.Msg.Answer) != 1 || rec.Msg.Answer[0].Header().Name != "WWW.example.com." {
		t.Errorf("expected one answer for WWW.example.com., got %v", rec.Msg.Answer)
	}

	m.SetQuestion("host.internal.example.com.", dns.TypeA)
	rec = dnstest.NewRecorder(&test.ResponseWriter{})
	if code, _ := rc.ServeDNS(context.Background(), rec, m); code != dns.RcodeRefused {
		t.Errorf("expected excepted names to go to the next plugin, got %s", dns.RcodeToString[code])
	}
}

func TestReferral(t *testing.T) {
	m := new(dns.Msg)
	m.Ns = []dns.RR{
		test.NS("org. 3600 IN NS ns.org."), // not below qname's path
		test.NS("example.com. 600 IN NS a.example.com."),
		test.NS("example.com. 300 IN NS B.example.com."),
	}
	child, names, ttl := referral(m, "com.", "www.example.com.")
	if child != "example.com." || len(names) != 2 || names[1] != "b.example.com." || ttl.Seconds() != 300 {
		t.Errorf("unexpected referral %q %v %s", child, names, ttl)
	}

	// An upward referral is not a referral.
	m.Ns = []dns.RR{test.NS(". 3600 IN NS a.root-servers.net.")}
	if child, _, _ := referral(m, "com.", "www.example.com."); child != "" {
		t.Errorf("expected no referral, got %q", child)
	}
}

func TestAddr(t *testing.T) {
	r := newResolver()
	tests := []struct {
		rr   dns.RR
		want string
	}{
		{test.A("a. 1 IN A 192.0.2.1"), "192.0.2.1:53"},
		{test.A("a. 1 IN A 127.0.0.1"), ""},
		{test.A("a. 1 IN A 0.0.0.0"), ""},
		{test.AAAA("a. 1 IN AAAA 2001:db8::1"), ""}, // IPv6 disabled
	}
	for _, tc := range tests {
		if got := r.addr(tc.rr); got != tc.want {
			t.Errorf("addr(%s) = %q, want %q", tc.rr, got, tc.want)
		}
	}
	r.ipv6 = true
	if got := r.addr(test.AAAA("a. 1 IN AAAA 2001:db8::1")); got != "[2001:db8::1]:53" {
		t.Errorf("unexpected IPv6 address %q", got)
	}
}

func TestResolveForgetsFailingDelegation(t *testing.T) {
	h := newHierarchy(t)
	r := h.resolver()

	// A cached delegation whose only server refuses everything.
	r.store("example.com.", []string{net.JoinHostPort("127.0.0.5", h.port)}, time.Hour)
	if _, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA); err == nil {
		t.Fatal("expected an error from the broken delegation")
	}
	res, err := r.Resolve(context.Background(), "www.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("expected the delegation to be learned again, got %s", err)
	}
	if len(res.answer) != 1 {
		t.Errorf("expected one answer, got %v", res.answer)
	}
}
