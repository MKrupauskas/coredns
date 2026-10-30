package recursive

import (
	"fmt"
	"net"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("recursive", setup) }

func setup(c *caddy.Controller) error {
	rc, err := parse(c)
	if err != nil {
		return plugin.Error("recursive", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		rc.Next = next
		return rc
	})

	return nil
}

func parse(c *caddy.Controller) (*Recursive, error) {
	rc := New()

	i := 0
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++

		if from := plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys); len(from) > 0 {
			rc.from = from
		}

		var roots []string
		for c.NextBlock() {
			switch c.Val() {
			case "except":
				ignore := c.RemainingArgs()
				if len(ignore) == 0 {
					return nil, c.ArgErr()
				}
				for _, name := range ignore {
					rc.ignored = append(rc.ignored, plugin.Host(name).NormalizeExact()...)
				}
			case "roots":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return nil, c.ArgErr()
				}
				for _, a := range args {
					addr, err := hostPort(a)
					if err != nil {
						return nil, c.Errf("invalid root server address %q: %s", a, err)
					}
					roots = append(roots, addr)
				}
			case "timeout":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				d, err := time.ParseDuration(c.Val())
				if err != nil {
					return nil, c.Errf("invalid timeout %q: %s", c.Val(), err)
				}
				if d <= 0 {
					return nil, c.Errf("timeout must be positive: %s", d)
				}
				rc.r.timeout = d
			case "ipv6":
				if c.NextArg() {
					return nil, c.ArgErr()
				}
				rc.r.ipv6 = true
			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}

		if len(roots) > 0 {
			rc.r.roots = roots
		} else {
			rc.r.setRoots(rc.r.ipv6)
		}
	}
	return rc, nil
}

// hostPort returns addr as host:port, adding port 53 when no port is given.
func hostPort(addr string) (string, error) {
	if ip := net.ParseIP(addr); ip != nil {
		return net.JoinHostPort(addr, "53"), nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("not an IP address: %q", host)
	}
	return net.JoinHostPort(host, port), nil
}
