module github.com/shui1iao/Kat

go 1.26.9

require (
	golang.org/x/crypto v0.57.0
	lukechampine.com/blake3 v1.4.1
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pires/go-proxyproto v0.11.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/text v0.42.0 // indirect
)

require (
	github.com/coder/websocket v1.8.14
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f
	golang.org/x/net v0.60.0
	golang.org/x/sys v0.48.0 // indirect
)

replace github.com/xtls/reality => ./third_party/reality
