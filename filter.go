// SPDX-License-Identifier: Apache-2.0
package dnsfilter

import (
	"regexp"

	"github.com/miekg/dns"
)

type Filters []Filter

func (fs Filters) Filter() bool {
	for _, f := range fs {
		if !f(nil) {
			return false
		}
	}
	return true
}

type Filter func(*dns.Msg) bool

// And returns a new Filter that combines the original Filter with another Filter using a logical AND operation. When applied to a DNS message, the resulting Filter will return true only if both the original Filter and the provided Filter return true for that message. This allows for creating more specific filters by combining multiple conditions that must be satisfied for a message to pass through the filter.
func (f Filter) And(g Filter) Filter {
	return func(m *dns.Msg) bool {
		return f(m) && g(m)
	}
}

// Or returns a new Filter that combines the original Filter with another Filter using a logical OR operation. When applied to a DNS message, the resulting Filter will return true if either the original Filter or the provided Filter returns true for that message. This allows for flexible filter combinations where multiple conditions can be satisfied for a message to pass through the filter.
func (f Filter) Or(g Filter) Filter {
	return func(m *dns.Msg) bool {
		return f(m) || g(m)
	}
}

// Not returns a new Filter that negates the result of the original Filter. When applied to a DNS message, the resulting Filter will return true if the original Filter returns false, and vice versa. This can be useful for creating complementary filters or for excluding certain conditions from a filter chain.
func (f Filter) Not() Filter {
	return func(m *dns.Msg) bool {
		return !f(m)
	}
}

// AlwaysTrue is a filter function that always returns true, regardless of the input DNS message. It can be used as a default filter or as a base for creating more complex filters by combining it with other filter functions using logical operations (AND, OR, NOT).
func AlwaysTrue(_ *dns.Msg) bool {
	return true
}

// AlwaysFalse is a filter function that always returns false, regardless of the input DNS message. It can be used as a default filter or as a base for creating more complex filters by combining it with other filter functions using logical operations (AND, OR, NOT).
func AlwaysFalse(_ *dns.Msg) bool {
	return false
}

// IsQuery checks if the DNS message is a query by verifying that the Opcode in the message header is set to Query.
func IsQuery(m *dns.Msg) bool {
	return m.Opcode == dns.OpcodeQuery
}

// IsResponse checks if the DNS message is a response by verifying that the Opcode is Query and the Response bit is set in the message header.
func IsResponse(m *dns.Msg) bool {
	return m.Opcode == dns.OpcodeQuery && m.Response
}

// HasQuestion checks if the DNS message has any questions in the question section, which may indicate that it is a query or contains queries.
func HasQuestion(m *dns.Msg) bool {
	return len(m.Question) > 0
}

// HasAnswer checks if the DNS message has any records in the answer section, which may indicate that there are answers included in the message.
func HasAnswer(m *dns.Msg) bool {
	return len(m.Answer) > 0
}

// HasAuthority checks if the DNS message has any records in the authority section, which may indicate that there are authoritative name servers included in the message.
func HasAuthority(m *dns.Msg) bool {
	return len(m.Ns) > 0
}

// HasAdditional checks if the DNS message has any records in the additional section, which may indicate that there are extra records included in the message.
func HasAdditional(m *dns.Msg) bool {
	return len(m.Extra) > 0
}

// IsAA checks if the AA (Authoritative Answer) bit is set in the DNS message header, which may indicate that the response is authoritative.
func IsAA(m *dns.Msg) bool {
	return m.Authoritative
}

// IsTC checks if the TC (Truncated) bit is set in the DNS message header, which may indicate that the message was truncated and that the client should retry over TCP.
func IsTC(m *dns.Msg) bool {
	return m.Truncated
}

// IsRD checks if the RD (Recursion Desired) bit is set in the DNS message header, which may indicate that the client is requesting recursive query processing.
func IsRD(m *dns.Msg) bool {
	return m.RecursionDesired
}

// IsRA checks if the RA (Recursion Available) bit is set in the DNS message header, which may indicate that the server can perform recursive queries.
func IsRA(m *dns.Msg) bool {
	return m.RecursionAvailable
}

// IsAD checks if the AD (Authenticated Data) bit is set in the DNS message header, which may indicate that the data is authenticated.
func IsAD(m *dns.Msg) bool {
	return m.AuthenticatedData
}

// IsSecure checks if the DNS message is authenticated, which may indicate that it is secure.
func IsSecure(m *dns.Msg) bool {
	return m.AuthenticatedData
}

// IsInsecure checks if the DNS message is not authenticated, which may indicate that it is not secure.
func IsInsecure(m *dns.Msg) bool {
	return !m.AuthenticatedData
}

// IsCD checks if the CD (Checking Disabled) bit is set in the DNS message header.
func IsCD(m *dns.Msg) bool {
	return m.CheckingDisabled
}

// IsEDNS0 checks if the DNS message has an EDNS0 OPT record in the additional section.
func IsEDNS0(m *dns.Msg) bool {
	return m.IsEdns0() != nil
}

// IsDO checks if the DNS message has the DO (DNSSEC OK) bit set in the EDNS0 options.
func IsDO(m *dns.Msg) bool {
	edns0 := m.IsEdns0()
	if edns0 == nil {
		return false
	}
	return edns0.Do()
}

// IsEDNS0WithOption checks if the DNS message has an EDNS0 OPT record with a specific option code in the additional section.
func IsEDNS0WithOption(code uint16) func(m *dns.Msg) bool {
	return func(m *dns.Msg) bool {
		edns0 := m.IsEdns0()
		if edns0 == nil {
			return false
		}
		for _, option := range edns0.Option {
			if option.Option() == code {
				return true
			}
		}
		return false
	}
}

// MatchQType checks if the question type in the DNS message matches the specified type, which may indicate the type of query (e.g., A, AAAA, MX).
func MatchQType(qtype uint16) func(m *dns.Msg) bool {
	return func(m *dns.Msg) bool {
		if len(m.Question) == 0 {
			return false
		}
		return m.Question[0].Qtype == qtype
	}
}

// MatchQClass checks if the question class in the DNS message matches the specified class, which may indicate the type of query (e.g., IN for Internet).
func MatchQClass(qclass uint16) func(m *dns.Msg) bool {
	return func(m *dns.Msg) bool {
		if len(m.Question) == 0 {
			return false
		}
		return m.Question[0].Qclass == qclass
	}
}

// IsRcode checks if the Rcode (Response Code) in the DNS message header matches the specified code, which may indicate the type of response or error.
func MatchRCode(rcode int) func(m *dns.Msg) bool {
	return func(m *dns.Msg) bool {
		return m.Rcode == rcode
	}
}

// MatchQName checks if the question name in the DNS message matches the specified name.
func MatchQName(name string) func(m *dns.Msg) bool {
	return func(m *dns.Msg) bool {
		if len(m.Question) == 0 {
			return false
		}
		return m.Question[0].Name == name
	}
}

// IsQnameSubdomain checks if the question name in the DNS message is a subdomain of the specified parent domain.
func MatchQnameSubdomain(parent string) func(m *dns.Msg) bool {
	return func(m *dns.Msg) bool {
		if len(m.Question) == 0 {
			return false
		}
		return dns.IsSubDomain(parent, m.Question[0].Name)
	}
}

// MatchQnameRegexp checks if the question name in the DNS message matches the specified regular expression pattern.
func MatchQnameRegexp(pattern *regexp.Regexp) func(m *dns.Msg) bool {
	return func(m *dns.Msg) bool {
		if len(m.Question) == 0 {
			return false
		}
		return pattern.MatchString(m.Question[0].Name)
	}
}
