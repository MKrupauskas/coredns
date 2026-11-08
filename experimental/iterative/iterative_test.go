package iterative

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type queryFunc func(context.Context, *dns.Msg) (*dns.Msg, error)

func (f queryFunc) Query(c context.Context, m *dns.Msg) (*dns.Msg, error) { return f(c, m) }

type writer struct {
	addr net.Addr
	msg  *dns.Msg
	err  error
}

func (w *writer) LocalAddr() net.Addr         { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1053} }
func (w *writer) RemoteAddr() net.Addr        { return w.addr }
func (w *writer) WriteMsg(m *dns.Msg) error   { w.msg = m; return w.err }
func (w *writer) Write(b []byte) (int, error) { return len(b), w.err }
func (w *writer) Close() error                { return nil }
func (w *writer) TsigStatus() error           { return nil }
func (w *writer) TsigTimersOnly(bool)         {}
func (w *writer) Hijack()                     {}
func request() *dns.Msg                       { q := new(dns.Msg); q.SetQuestion("www.example.", dns.TypeA); return q }
func loopback() *writer                       { return &writer{addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}} }

func TestAdmission(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*dns.Msg, *writer)
		code   int
	}{
		{"remote", func(_ *dns.Msg, w *writer) { w.addr = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3} }, dns.RcodeRefused},
		{"empty", func(q *dns.Msg, _ *writer) { q.Question = nil }, dns.RcodeFormatError},
		{"multiple", func(q *dns.Msg, _ *writer) { q.Question = append(q.Question, q.Question[0]) }, dns.RcodeFormatError},
		{"update", func(q *dns.Msg, _ *writer) { q.Opcode = dns.OpcodeUpdate }, dns.RcodeFormatError},
		{"response", func(q *dns.Msg, _ *writer) { q.Response = true }, dns.RcodeFormatError},
		{"rd0", func(q *dns.Msg, _ *writer) { q.RecursionDesired = false }, dns.RcodeRefused},
		{"chaos", func(q *dns.Msg, _ *writer) { q.Question[0].Qclass = dns.ClassCHAOS }, dns.RcodeRefused},
		{"axfr", func(q *dns.Msg, _ *writer) { q.Question[0].Qtype = dns.TypeAXFR }, dns.RcodeRefused},
		{"ixfr", func(q *dns.Msg, _ *writer) { q.Question[0].Qtype = dns.TypeIXFR }, dns.RcodeRefused},
		{"any", func(q *dns.Msg, _ *writer) { q.Question[0].Qtype = dns.TypeANY }, dns.RcodeRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{slots: make(chan struct{}, 1), query: queryFunc(func(context.Context, *dns.Msg) (*dns.Msg, error) { t.Fatal("engine reached"); return nil, nil })}
			q, w := request(), loopback()
			tc.mutate(q, w)
			code, err := h.ServeDNS(context.Background(), w, q)
			if err != nil || code != tc.code || w.msg.Rcode != tc.code {
				t.Fatalf("code=%d err=%v reply=%v", code, err, w.msg)
			}
		})
	}
}

func TestOverloadAndCancellation(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	h := &Handler{slots: make(chan struct{}, 1), query: queryFunc(func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
		if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > 5*time.Second {
			t.Error("missing bounded deadline")
		}
		close(entered)
		<-release
		return new(dns.Msg).SetReply(q), nil
	})}
	done := make(chan struct{})
	go func() { defer close(done); h.ServeDNS(context.Background(), loopback(), request()) }()
	<-entered
	w := loopback()
	code, _ := h.ServeDNS(context.Background(), w, request())
	if code != dns.RcodeRefused {
		t.Fatal(code)
	}
	close(release)
	<-done
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, _ = h.ServeDNS(ctx, loopback(), request())
	if code != dns.RcodeServerFailure {
		t.Fatal(code)
	}
	if len(h.slots) != 0 {
		t.Fatal("slot leaked")
	}
}

func TestCopiesFlagsTransportAndWriteError(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		t.Run(map[bool]string{false: "udp", true: "tcp"}[tcp], func(t *testing.T) {
			q := request()
			q.CheckingDisabled = true
			original := q.String()
			result := new(dns.Msg).SetReply(q)
			result.Authoritative = true
			for i := 0; i < 30; i++ {
				rr, _ := dns.NewRR("www.example. 60 IN TXT \"" + strings.Repeat("x", 100) + "\"")
				result.Answer = append(result.Answer, rr)
			}
			h := &Handler{slots: make(chan struct{}, 1), query: queryFunc(func(_ context.Context, in *dns.Msg) (*dns.Msg, error) {
				in.Question[0].Name = "mutated."
				return result, nil
			})}
			w := loopback()
			if tcp {
				w.addr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3}
			}
			w.err = errors.New("write failed")
			_, err := h.ServeDNS(context.Background(), w, q)
			if !errors.Is(err, w.err) || q.String() != original || !result.Authoritative || len(result.Answer) != 30 {
				t.Fatal("ownership or write failure")
			}
			if w.msg.Authoritative || !w.msg.RecursionAvailable || !w.msg.CheckingDisabled || w.msg.Id != q.Id {
				t.Fatal("flags")
			}
			if !tcp && (!w.msg.Truncated || w.msg.Len() > 512) {
				t.Fatal("UDP oversized")
			}
			if tcp && w.msg.Truncated {
				t.Fatal("TCP truncated")
			}
		})
	}
}

func TestConfigurationFailsClosed(t *testing.T) {
	anchor := ". 3600 IN DNSKEY 257 3 8 AwEAAQ==" // Parser fixture only, never trusted on a network.
	valid := "directory = \"" + t.TempDir() + "\"\nroots = [\"198.41.0.4:53\"]\nanchors = [\"" + anchor + "\"]\n"
	for _, tc := range []struct {
		name, body string
		ok         bool
	}{
		{"valid", valid, true},
		{"no anchors", "directory=\"x\"\nroots=[\"198.41.0.4:53\"]", false},
		{"forwarding", valid + "forwarderservers=[\"8.8.8.8:53\"]", false},
		{"disable dnssec", valid + "dnssec=\"off\"", false},
		{"hostname", strings.ReplaceAll(valid, "198.41.0.4:53", "root.example:53"), false},
		{"bad port", strings.ReplaceAll(valid, ":53", ":5353"), false},
		{"non root", strings.ReplaceAll(valid, ". 3600", "example. 3600"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "cfg.toml")
			if err := os.WriteFile(p, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := load(p)
			if (err == nil) != tc.ok {
				t.Fatalf("%v", err)
			}
			if err == nil && (cfg.DNSSEC != "on" || cfg.RecursionFirewall.Mode != "enforce" || cfg.RecursionFirewall.MaxOutboundQueries != 64) {
				t.Fatal("policy")
			}
		})
	}
}
