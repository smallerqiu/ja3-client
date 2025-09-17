module github.com/smallerqiu/ja3-client

go 1.24.1

toolchain go1.24.7

require (
	github.com/smallerqiu/utls v1.1.1
	github.com/tam7t/hpkp v0.0.0-20160821193359-2b70b4024ed5
	golang.org/x/net v0.38.0
)

require (
	github.com/andybalholm/brotli v1.1.1
	github.com/dgraph-io/ristretto v0.2.0
	github.com/klauspost/compress v1.17.11
	golang.org/x/crypto v0.36.0
	golang.org/x/sys v0.31.0
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cloudflare/circl v1.5.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	golang.org/x/text v0.23.0 // indirect
)

replace github.com/smallerqiu/utls => ../ja3-utls
