// SPDX-License-Identifier: Apache-2.0
package dnsfilter

import (
	"regexp"
	"testing"

	"github.com/miekg/dns"
)

func TestFiltersFilter(t *testing.T) {
	t.Run("empty filters returns true", func(t *testing.T) {
		if got := (Filters{}).Filter(); !got {
			t.Fatalf("expected true, got false")
		}
	})

	t.Run("all true returns true", func(t *testing.T) {
		filters := Filters{AlwaysTrue, AlwaysTrue}
		if got := filters.Filter(); !got {
			t.Fatalf("expected true, got false")
		}
	})

	t.Run("contains false returns false", func(t *testing.T) {
		filters := Filters{AlwaysTrue, AlwaysFalse, AlwaysTrue}
		if got := filters.Filter(); got {
			t.Fatalf("expected false, got true")
		}
	})
}

func TestFilterCombinators(t *testing.T) {
	m := &dns.Msg{}

	t.Run("and", func(t *testing.T) {
		if got := Filter(AlwaysTrue).And(Filter(AlwaysTrue))(m); !got {
			t.Fatalf("expected true, got false")
		}
		if got := Filter(AlwaysTrue).And(Filter(AlwaysFalse))(m); got {
			t.Fatalf("expected false, got true")
		}
	})

	t.Run("or", func(t *testing.T) {
		if got := Filter(AlwaysFalse).Or(Filter(AlwaysTrue))(m); !got {
			t.Fatalf("expected true, got false")
		}
		if got := Filter(AlwaysFalse).Or(Filter(AlwaysFalse))(m); got {
			t.Fatalf("expected false, got true")
		}
	})

	t.Run("not", func(t *testing.T) {
		if got := Filter(AlwaysTrue).Not()(m); got {
			t.Fatalf("expected false, got true")
		}
		if got := Filter(AlwaysFalse).Not()(m); !got {
			t.Fatalf("expected true, got false")
		}
	})
}

func TestQueryAndResponse(t *testing.T) {
	query := &dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeQuery, Response: false}}
	response := &dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeQuery, Response: true}}
	nonQuery := &dns.Msg{MsgHdr: dns.MsgHdr{Opcode: dns.OpcodeNotify, Response: true}}

	if !IsQuery(query) {
		t.Fatalf("expected query to be true")
	}
	if IsQuery(nonQuery) {
		t.Fatalf("expected non-query to be false")
	}

	if !IsResponse(response) {
		t.Fatalf("expected response to be true")
	}
	if IsResponse(query) {
		t.Fatalf("expected query to be false as response")
	}
	if IsResponse(nonQuery) {
		t.Fatalf("expected non-query response to be false")
	}
}

func TestSectionPresence(t *testing.T) {
	msg := &dns.Msg{}
	if HasQuestion(msg) || HasAnswer(msg) || HasAuthority(msg) || HasAdditional(msg) {
		t.Fatalf("expected all section checks to be false")
	}

	msg.Question = []dns.Question{{Name: "example.org.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	msg.Answer = []dns.RR{&dns.A{}}
	msg.Ns = []dns.RR{&dns.NS{}}
	msg.Extra = []dns.RR{&dns.OPT{}}

	if !HasQuestion(msg) || !HasAnswer(msg) || !HasAuthority(msg) || !HasAdditional(msg) {
		t.Fatalf("expected all section checks to be true")
	}
}

func TestHeaderFlags(t *testing.T) {
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{
		Authoritative:      true,
		Truncated:          true,
		RecursionDesired:   true,
		RecursionAvailable: true,
		AuthenticatedData:  true,
		CheckingDisabled:   true,
	}}

	if !IsAA(msg) || !IsTC(msg) || !IsRD(msg) || !IsRA(msg) || !IsAD(msg) || !IsSecure(msg) || !IsCD(msg) {
		t.Fatalf("expected all positive flag checks to be true")
	}
	if IsInsecure(msg) {
		t.Fatalf("expected IsInsecure to be false")
	}

	msg.AuthenticatedData = false
	if IsSecure(msg) {
		t.Fatalf("expected IsSecure to be false")
	}
	if !IsInsecure(msg) {
		t.Fatalf("expected IsInsecure to be true")
	}
}

func TestEDNS0Filters(t *testing.T) {
	msg := &dns.Msg{}
	if IsEDNS0(msg) {
		t.Fatalf("expected IsEDNS0 false without OPT")
	}
	if IsDO(msg) {
		t.Fatalf("expected IsDO false without OPT")
	}
	if IsEDNS0WithOption(dns.EDNS0NSID)(msg) {
		t.Fatalf("expected option check false without OPT")
	}

	msg.SetEdns0(1232, true)
	if !IsEDNS0(msg) {
		t.Fatalf("expected IsEDNS0 true with OPT")
	}
	if !IsDO(msg) {
		t.Fatalf("expected IsDO true when DO bit set")
	}

	edns := msg.IsEdns0()
	edns.Option = append(edns.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID, Nsid: "abc"})

	if !IsEDNS0WithOption(dns.EDNS0NSID)(msg) {
		t.Fatalf("expected option check true for matching code")
	}
	if IsEDNS0WithOption(dns.EDNS0SUBNET)(msg) {
		t.Fatalf("expected option check false for non-matching code")
	}
}

func TestMatchFilters(t *testing.T) {
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Question: []dns.Question{{
			Name:   "www.example.org.",
			Qtype:  dns.TypeAAAA,
			Qclass: dns.ClassINET,
		}},
	}
	empty := &dns.Msg{}

	if !MatchQType(dns.TypeAAAA)(msg) {
		t.Fatalf("expected MatchQType true")
	}
	if MatchQType(dns.TypeA)(msg) {
		t.Fatalf("expected MatchQType false")
	}
	if MatchQType(dns.TypeAAAA)(empty) {
		t.Fatalf("expected MatchQType false without question")
	}

	if !MatchQClass(dns.ClassINET)(msg) {
		t.Fatalf("expected MatchQClass true")
	}
	if MatchQClass(dns.ClassCHAOS)(msg) {
		t.Fatalf("expected MatchQClass false")
	}
	if MatchQClass(dns.ClassINET)(empty) {
		t.Fatalf("expected MatchQClass false without question")
	}

	if !MatchRCode(dns.RcodeSuccess)(msg) {
		t.Fatalf("expected MatchRCode true")
	}
	if MatchRCode(dns.RcodeNameError)(msg) {
		t.Fatalf("expected MatchRCode false")
	}

	if !MatchQName("www.example.org.")(msg) {
		t.Fatalf("expected MatchQName true")
	}
	if MatchQName("example.org.")(msg) {
		t.Fatalf("expected MatchQName false")
	}
	if MatchQName("www.example.org.")(empty) {
		t.Fatalf("expected MatchQName false without question")
	}

	if !MatchQnameSubdomain("example.org.")(msg) {
		t.Fatalf("expected MatchQnameSubdomain true")
	}
	if MatchQnameSubdomain("example.com.")(msg) {
		t.Fatalf("expected MatchQnameSubdomain false")
	}
	if MatchQnameSubdomain("example.org.")(empty) {
		t.Fatalf("expected MatchQnameSubdomain false without question")
	}

	pattern := regexp.MustCompile(`^www\.example\.org\.$`)
	if !MatchQnameRegexp(pattern)(msg) {
		t.Fatalf("expected MatchQnameRegexp true")
	}
	if MatchQnameRegexp(regexp.MustCompile(`^api\.example\.org\.$`))(msg) {
		t.Fatalf("expected MatchQnameRegexp false")
	}
	if MatchQnameRegexp(pattern)(empty) {
		t.Fatalf("expected MatchQnameRegexp false without question")
	}
}
