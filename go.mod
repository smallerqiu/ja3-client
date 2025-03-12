module github.com/smallerqiu/ja3-client

go 1.23.4

require (
	// github.com/smallerqiu/fhttp v1.0.1
	github.com/smallerqiu/utls v1.0.9
	github.com/tam7t/hpkp v0.0.0-20160821193359-2b70b4024ed5
	golang.org/x/net v0.35.0
)

require (
	github.com/andybalholm/brotli v1.0.6
	github.com/klauspost/compress v1.17.4
	github.com/smallerqiu/fhttp v1.0.1
)

require (
	github.com/cloudflare/circl v1.5.0 // indirect
	golang.org/x/crypto v0.33.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
)

// github.com/smallerqiu/fhttp => ../fhttp
replace github.com/smallerqiu/utls => ../utls
