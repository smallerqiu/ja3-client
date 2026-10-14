module github.com/smallerqiu/ja3-client

go 1.26.0

require (
	github.com/smallerqiu/utls v1.2.1
	golang.org/x/net v0.61.0
)

require (
	github.com/andybalholm/brotli v1.2.6
	github.com/klauspost/compress v1.20.3
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/cloudflare/circl v1.6.5 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/smallerqiu/utls => ../ja3-utls
