package iterative

import (
	"context"
	"os"
	"testing"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
)

// Explicit opt-in: this contacts real root/authoritative servers and writes
// RFC 5011 state to the configured directory. It is a smoke test, not a
// deterministic DNSSEC conformance test.
func TestLiveValidatingAdapter(t *testing.T) {
	path := os.Getenv("ITERATIVE_LIVE_CONFIG")
	if path == "" {
		t.Skip("set ITERATIVE_LIVE_CONFIG for public-network smoke test")
	}
	c := caddy.NewTestController("dns", name+" "+path)
	if err := setup(c); err != nil {
		t.Fatal(err)
	}
	plugins := dnsserver.GetConfig(c).Plugin
	h := plugins[len(plugins)-1](nil)
	for _, tc := range []struct {
		domain string
		code   int
		ad     bool
	}{
		{"cloudflare.com.", dns.RcodeSuccess, true},
		{"cloudflare.com.", dns.RcodeSuccess, true},
		{"dnssec-failed.org.", dns.RcodeServerFailure, false},
	} {
		q := request()
		q.SetQuestion(tc.domain, dns.TypeA)
		q.SetEdns0(1232, true)
		w := loopback()
		code, err := h.ServeDNS(context.Background(), w, q)
		if err != nil || code != tc.code || w.msg.AuthenticatedData != tc.ad {
			t.Fatalf("%s: code=%d err=%v reply=%v", tc.domain, code, err, w.msg)
		}
	}
	if err := setup(caddy.NewTestController("dns", name+" "+path)); err == nil {
		t.Fatal("second setup accepted")
	}
}
