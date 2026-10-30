package recursive

import (
	"slices"
	"testing"
	"time"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		from      []string
		ignored   []string
		roots     []string
		timeout   time.Duration
		ipv6      bool
	}{
		{"recursive", false, []string{"."}, nil, nil, defaultTimeout, false},
		{"recursive example.org example.net", false, []string{"example.org.", "example.net."}, nil, nil, defaultTimeout, false},
		{`recursive . {
			except internal.example.com corp
			roots 192.0.2.1 192.0.2.2:5353 [2001:db8::1]:53
			timeout 500ms
			ipv6
		}`, false, []string{"."}, []string{"internal.example.com.", "corp."}, []string{"192.0.2.1:53", "192.0.2.2:5353", "[2001:db8::1]:53"}, 500 * time.Millisecond, true},
		{"recursive {\nexcept\n}", true, nil, nil, nil, 0, false},
		{"recursive {\nroots a.root-servers.net\n}", true, nil, nil, nil, 0, false},
		{"recursive {\ntimeout -1s\n}", true, nil, nil, nil, 0, false},
		{"recursive {\nipv6 yes\n}", true, nil, nil, nil, 0, false},
		{"recursive {\nfoo\n}", true, nil, nil, nil, 0, false},
		{"recursive\nrecursive", true, nil, nil, nil, 0, false},
	}

	for i, tc := range tests {
		c := caddy.NewTestController("dns", tc.input)
		rc, err := parse(c)
		if tc.shouldErr {
			if err == nil {
				t.Errorf("test %d: expected error for %q", i, tc.input)
			}
			continue
		}
		if err != nil {
			t.Fatalf("test %d: unexpected error: %s", i, err)
		}
		if !slices.Equal(rc.from, tc.from) {
			t.Errorf("test %d: expected from %v, got %v", i, tc.from, rc.from)
		}
		if !slices.Equal(rc.ignored, tc.ignored) {
			t.Errorf("test %d: expected except %v, got %v", i, tc.ignored, rc.ignored)
		}
		if tc.roots != nil && !slices.Equal(rc.r.roots, tc.roots) {
			t.Errorf("test %d: expected roots %v, got %v", i, tc.roots, rc.r.roots)
		}
		if tc.roots == nil && len(rc.r.roots) != len(rootHints) {
			t.Errorf("test %d: expected %d root hints, got %d", i, len(rootHints), len(rc.r.roots))
		}
		if rc.r.timeout != tc.timeout {
			t.Errorf("test %d: expected timeout %s, got %s", i, tc.timeout, rc.r.timeout)
		}
		if rc.r.ipv6 != tc.ipv6 {
			t.Errorf("test %d: expected ipv6 %t, got %t", i, tc.ipv6, rc.r.ipv6)
		}
	}
}

func TestSetupIPv6RootHints(t *testing.T) {
	rc, err := parse(caddy.NewTestController("dns", "recursive {\nipv6\n}"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.r.roots) != 2*len(rootHints) {
		t.Errorf("expected IPv4 and IPv6 root hints, got %v", rc.r.roots)
	}
}
