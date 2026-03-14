# dnsfilter

[![CI](https://github.com/mimuret/dnsfilter/actions/workflows/ci.yml/badge.svg)](https://github.com/mimuret/dnsfilter/actions/workflows/ci.yml)
![Coverage](https://raw.githubusercontent.com/mimuret/dnsfilter/main/docs/coverage.svg)

`dnsfilter` は [`github.com/miekg/dns`](https://github.com/miekg/dns) の `*dns.Msg` に対して、
シンプルに条件判定を組み合わせるための Go ライブラリです。

## インストール

```bash
go get github.com/mimuret/dnsfilter
```

## 使い方

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

	// Query かつ Question があり、QName が一致するものだけ通す
	f := dnsfilter.Filter(dnsfilter.IsQuery).
		And(dnsfilter.Filter(dnsfilter.HasQuestion)).
		And(dnsfilter.Filter(dnsfilter.MatchQName("www.example.org.")))

	fmt.Println(f(msg)) // true
}
```

## 主な API

### 型

- `type Filter func(*dns.Msg) bool`
- `type Filters []Filter`

### 合成

- `Filter.And(Filter) Filter`
- `Filter.Or(Filter) Filter`
- `Filter.Not() Filter`
- `Filters.Filter() bool`

### 代表的なフィルタ

- 常に真偽を返す: `AlwaysTrue`, `AlwaysFalse`
- メッセージ種別: `IsQuery`, `IsResponse`
- セクション有無: `HasQuestion`, `HasAnswer`, `HasAuthority`, `HasAdditional`
- ヘッダフラグ: `IsAA`, `IsTC`, `IsRD`, `IsRA`, `IsAD`, `IsSecure`, `IsInsecure`, `IsCD`
- EDNS0 関連: `IsEDNS0`, `IsDO`, `IsEDNS0WIthOption`
- マッチ系: `MatchQType`, `MatchQClass`, `MatchRCode`, `MatchQName`, `MatchQnameSubdomain`, `MatchQnameRegexp`

## テスト

```bash
go test ./...
```

## ライセンス

Apache License 2.0。詳細は [LICENSE](./LICENSE) を参照してください。
