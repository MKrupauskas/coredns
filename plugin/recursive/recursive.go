// Package recursive implements a recursive resolver. Instead of forwarding queries to an upstream
// resolver it starts at the root servers and follows referrals down to the authoritative servers.
package recursive

import (
	"context"
	"strings"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

var log = clog.NewWithPlugin("recursive")

// Recursive is a plugin that resolves queries iteratively from the authoritative name servers.
type Recursive struct {
	Next plugin.Handler

	from    []string
	ignored []string
	r       *resolver
}

// New returns a Recursive that resolves all names using the built-in root hints.
func New() *Recursive {
	return &Recursive{from: []string{"."}, r: newResolver()}
}

// ServeDNS implements the plugin.Handler interface.
func (rc *Recursive) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	if !rc.match(state) || state.QClass() != dns.ClassINET {
		return plugin.NextOrFailure(rc.Name(), rc.Next, ctx, w, r)
	}

	res, err := rc.r.Resolve(ctx, state.QName(), state.QType())
	if err != nil {
		resolutionFailureCount.Inc()
		log.Debugf("Failed to resolve %s/%s: %s", state.QName(), state.Type(), err)
		return dns.RcodeServerFailure, err
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.RecursionAvailable = true
	m.Rcode = res.rcode
	// The result is shared with other queries for the same name; later plugins (cache,
	// loadbalance, rewrite, ...) may modify the records, so hand out copies.
	m.Answer = copyRRs(res.answer)
	m.Ns = copyRRs(res.ns)
	// Answer with the name as asked: the shared resolution is done on the lower cased name.
	for _, rr := range m.Answer {
		if strings.EqualFold(rr.Header().Name, state.QName()) {
			rr.Header().Name = state.QName()
		}
	}
	state.SizeAndDo(m)

	w.WriteMsg(m)
	return dns.RcodeSuccess, nil
}

// Name implements the plugin.Handler interface.
func (rc *Recursive) Name() string { return "recursive" }

func (rc *Recursive) match(state request.Request) bool {
	name := state.Name()
	if plugin.Zones(rc.from).Matches(name) == "" {
		return false
	}
	for _, ignore := range rc.ignored {
		if plugin.Name(ignore).Matches(name) {
			return false
		}
	}
	return true
}

func copyRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		out[i] = dns.Copy(rr)
	}
	return out
}
