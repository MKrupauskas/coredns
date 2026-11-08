// Package iterative is a lab-only CoreDNS adapter for the SDNS resolver.
package iterative

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/edns"
	"github.com/semihalev/sdns/middleware/resolver"
)

const name = "iterative_lab"

var startup struct {
	sync.Mutex
	used bool
}

func init() {
	plugin.Register(name, setup)
	// A terminal directive only in the standalone experimental binary.
	dnsserver.Directives = append(dnsserver.Directives, name)
}

type settings struct {
	Directory string   `toml:"directory"`
	Roots     []string `toml:"roots"`
	Anchors   []string `toml:"anchors"`
}

func load(path string) (*config.Config, error) {
	var s settings
	md, err := toml.DecodeFile(path, &s)
	if err != nil {
		return nil, err
	}
	if len(md.Undecoded()) != 0 {
		return nil, fmt.Errorf("unknown settings: %v", md.Undecoded())
	}
	if s.Directory == "" || len(s.Roots) == 0 || len(s.Anchors) == 0 {
		return nil, fmt.Errorf("directory, roots and anchors are required")
	}
	for _, root := range s.Roots {
		host, port, err := net.SplitHostPort(root)
		if err != nil || net.ParseIP(host) == nil || port != "53" {
			return nil, fmt.Errorf("root must be a literal IP on port 53: %q", root)
		}
		if net.ParseIP(host).To4() == nil {
			return nil, fmt.Errorf("lab adapter currently requires IPv4 root hints")
		}
	}
	for _, anchor := range s.Anchors {
		rr, err := dns.NewRR(anchor)
		if err != nil {
			return nil, fmt.Errorf("invalid anchor: %w", err)
		}
		key, ok := rr.(*dns.DNSKEY)
		if !ok || key.Hdr.Name != "." || key.Hdr.Class != dns.ClassINET || key.Protocol != 3 || key.Flags != 257 {
			return nil, fmt.Errorf("anchor must be a root IN SEP DNSKEY")
		}
	}
	cfg := &config.Config{
		Directory: s.Directory, RootServers: s.Roots, RootKeys: s.Anchors, DNSSEC: "on",
		Maxdepth: 24, MaxConcurrentQueries: 64, CacheSize: 4096, Expire: 300,
		Timeout: config.Duration{Duration: time.Second}, QueryTimeout: config.Duration{Duration: 5 * time.Second},
	}
	cfg.RecursionFirewall.Mode = config.RecursionFirewallModeEnforce
	cfg.RecursionFirewall.Normalize()
	cfg.RecursionFirewall.MaxOutboundQueries = 64
	cfg.RecursionFirewall.MaxInternalQueries = 64
	return cfg, cfg.RecursionFirewall.Validate()
}

func setup(c *caddy.Controller) error {
	var path string
	for c.Next() {
		args := c.RemainingArgs()
		if len(args) != 1 || path != "" {
			return plugin.Error(name, c.ArgErr())
		}
		path = args[0]
		if c.NextBlock() {
			return plugin.Error(name, c.ArgErr())
		}
	}
	cfg, err := load(path)
	if err != nil {
		return plugin.Error(name, err)
	}
	startup.Lock()
	defer startup.Unlock()
	if startup.used {
		return plugin.Error(name, fmt.Errorf("one instance per process; reload is unsupported"))
	}
	startup.used = true
	middleware.Register("edns", func(cfg *config.Config) middleware.Handler { return edns.New(cfg) })
	middleware.Register("cache", func(cfg *config.Config) middleware.Handler { return answercache.New(cfg) })
	middleware.Register("resolver", func(cfg *config.Config) middleware.Handler { return resolver.New(cfg) })
	middleware.Setup(cfg)
	h := &Handler{query: middleware.NewPipelineQueryer(middleware.GlobalPipeline()), slots: make(chan struct{}, 64)}
	dnsserver.GetConfig(c).AddPlugin(func(_ plugin.Handler) plugin.Handler { return h })
	return nil
}

// Handler admits loopback clients before touching the resolver/cache. Each
// accepted request uses SDNS's own pipeline and request-tree work ledger.
type Handler struct {
	query middleware.Queryer
	slots chan struct{}
}

func (*Handler) Name() string { return name }
func (h *Handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
	reply := func(code int) (int, error) { m := new(dns.Msg); m.SetRcode(req, code); return code, w.WriteMsg(m) }
	host, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return reply(dns.RcodeRefused)
	}
	if req.Opcode != dns.OpcodeQuery || req.Response || len(req.Question) != 1 {
		return reply(dns.RcodeFormatError)
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET || q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR || q.Qtype == dns.TypeANY || !req.RecursionDesired {
		return reply(dns.RcodeRefused)
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		return reply(dns.RcodeRefused)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return reply(dns.RcodeServerFailure)
	}
	result, err := h.query.Query(ctx, req.Copy())
	if err != nil || result == nil || ctx.Err() != nil {
		return reply(dns.RcodeServerFailure)
	}
	result = result.Copy()
	result.Id = req.Id
	result.Authoritative = false
	result.RecursionDesired = req.RecursionDesired
	result.RecursionAvailable = true
	result.CheckingDisabled = req.CheckingDisabled
	if _, tcp := w.RemoteAddr().(*net.TCPAddr); !tcp {
		size := uint16(512)
		if opt := req.IsEdns0(); opt != nil {
			size = opt.UDPSize()
			if size < 512 {
				size = 512
			}
			if size > 1232 {
				size = 1232
			}
		}
		result.Truncate(int(size))
	}
	return result.Rcode, w.WriteMsg(result)
}
