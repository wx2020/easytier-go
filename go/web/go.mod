module github.com/EasyTier/EasyTier/go/web

go 1.24.0

require (
	github.com/EasyTier/EasyTier/go v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.36.0
)

require (
	github.com/flynn/noise v1.1.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	golang.org/x/sys v0.31.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/EasyTier/EasyTier/go => ../
