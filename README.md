# dnsfilter

[![CI](https://github.com/mimuret/dnsfilter/actions/workflows/ci.yml/badge.svg)](https://github.com/mimuret/dnsfilter/actions/workflows/ci.yml)
![Coverage](https://raw.githubusercontent.com/mimuret/dnsfilter/main/docs/coverage.svg)

`dnsfilter` is a Go library for composing simple predicate-based filters on
`*dns.Msg` from [`github.com/miekg/dns`](https://github.com/miekg/dns).

## Installation

```bash
go get github.com/mimuret/dnsfilter
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/mimuret/dnsfilter"
)

func main() {
	msg := &dns.Msg{}
	msg.SetQuestion("www.example.org.", dns.TypeA)
	msg.Opcode = dns.OpcodeQuery

	// Allow only messages that are query, have question,
	// and match the specified QName.
	f := dnsfilter.Filter(dnsfilter.IsQuery).
		And(dnsfilter.Filter(dnsfilter.HasQuestion)).
		And(dnsfilter.Filter(dnsfilter.MatchQName("www.example.org.")))

	fmt.Println(f(msg)) // true
}
```

## Main API

### Types

- `type Filter func(*dns.Msg) bool`
- `type Filters []Filter`

### Combinators

- `Filter.And(Filter) Filter`
- `Filter.Or(Filter) Filter`
- `Filter.Not() Filter`
- `Filters.Filter() bool`

### Common Filters

- Always true/false: `AlwaysTrue`, `AlwaysFalse`
- Message kind: `IsQuery`, `IsResponse`
- Section presence: `HasQuestion`, `HasAnswer`, `HasAuthority`, `HasAdditional`
- Header flags: `IsAA`, `IsTC`, `IsRD`, `IsRA`, `IsAD`, `IsSecure`, `IsInsecure`, `IsCD`
- EDNS0 related: `IsEDNS0`, `IsDO`, `IsEDNS0WithOption`
- Matchers: `MatchQType`, `MatchQClass`, `MatchRCode`, `MatchQName`, `MatchQnameSubdomain`, `MatchQnameRegexp`

## Test

```bash
go test ./...
```

## License

Apache License 2.0. See [LICENSE](./LICENSE).
