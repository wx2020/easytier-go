module github.com/EasyTier/EasyTier/go

go 1.25.0

require (
	github.com/flynn/noise v1.1.0
	github.com/gorilla/websocket v1.5.3
	github.com/pelletier/go-toml/v2 v2.2.4
	golang.org/x/crypto v0.54.0
	golang.org/x/sys v0.47.0
)

require github.com/klauspost/compress v1.17.11

require google.golang.org/protobuf v1.36.12

require (
	github.com/EasyTier/EasyTier/go/ffi v0.0.0-00010101000000-000000000000 // indirect
	github.com/EasyTier/EasyTier/go/jni v0.0.0-00010101000000-000000000000 // indirect
	github.com/EasyTier/EasyTier/go/platform v0.0.0-00010101000000-000000000000 // indirect
	github.com/EasyTier/EasyTier/go/uptime v0.0.0-00010101000000-000000000000 // indirect
	github.com/EasyTier/EasyTier/go/web v0.0.0-00010101000000-000000000000 // indirect
	github.com/mattn/go-sqlite3 v1.14.50 // indirect
	github.com/quic-go/quic-go v0.61.0 // indirect
	golang.org/x/net v0.56.0 // indirect
)

replace github.com/EasyTier/EasyTier/go/platform => ./platform

replace github.com/EasyTier/EasyTier/go/web => ./web

replace github.com/EasyTier/EasyTier/go/uptime => ./uptime

replace github.com/EasyTier/EasyTier/go/ffi => ./ffi

replace github.com/EasyTier/EasyTier/go/jni => ./jni
