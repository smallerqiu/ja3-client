module github.com/smallerqiu/ja3-client/cffi

go 1.26.0

// The shared library is built from this repo, not from a published tag.
// Pinning github.com/smallerqiu/ja3-client to a released version meant every
// .so/.dll/.dylib shipped the old library code while the repo moved on.
// cffi is a main module that is never imported by anyone, so a local replace
// here is safe (unlike in the root go.mod, where it would be ignored by
// consumers).
require github.com/smallerqiu/ja3-client v1.2.4

require (
	github.com/andybalholm/brotli v1.2.6 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/klauspost/compress v1.20.3 // indirect
	github.com/smallerqiu/utls v1.2.1 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
)

replace github.com/smallerqiu/ja3-client => ../
