package recursive

// rootHints are the addresses of the root name servers, as published by IANA in
// https://www.internic.net/domain/named.root. They are only used to bootstrap
// resolution and change very rarely.
var rootHints = []struct{ v4, v6 string }{
	{"198.41.0.4", "2001:503:ba3e::2:30"},   // a.root-servers.net
	{"170.247.170.2", "2801:1b8:10::b"},     // b.root-servers.net
	{"192.33.4.12", "2001:500:2::c"},        // c.root-servers.net
	{"199.7.91.13", "2001:500:2d::d"},       // d.root-servers.net
	{"192.203.230.10", "2001:500:a8::e"},    // e.root-servers.net
	{"192.5.5.241", "2001:500:2f::f"},       // f.root-servers.net
	{"192.112.36.4", "2001:500:12::d0d"},    // g.root-servers.net
	{"198.97.190.53", "2001:500:1::53"},     // h.root-servers.net
	{"192.36.148.17", "2001:7fe::53"},       // i.root-servers.net
	{"192.58.128.30", "2001:503:c27::2:30"}, // j.root-servers.net
	{"193.0.14.129", "2001:7fd::1"},         // k.root-servers.net
	{"199.7.83.42", "2001:500:9f::42"},      // l.root-servers.net
	{"202.12.27.33", "2001:dc3::35"},        // m.root-servers.net
}
