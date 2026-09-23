# EasyTier GUI

Modern, lightweight desktop GUI client for EasyTier, powered by **Vue 3** frontend and **Wails v2 (Go)** backend.

## Architecture

- **Frontend**: Vue 3 + TypeScript + Vite + PrimeVue in `easytier-gui/`.
- **Backend / Host**: Pure Go Wails v2 desktop application in `go/gui/`.
  - Directly interfaces with `go/internal/gui/backend.go`.
  - Zero Rust / C++ toolchain dependencies.
  - Generates an ~8 MB self-contained binary in 3 seconds.

## Build From Source

### Prerequisites

- **Node.js**: >= 20.x with `pnpm`
- **Go**: >= 1.24

### 1. Build Frontend Assets

```bash
cd easytier-gui
pnpm install
pnpm build
```

This generates production assets in `easytier-gui/dist`.

### 2. Build Desktop Executable

```bash
cd ../go/gui

# Run unit tests
go test -v .

# Compile standalone executable (Windows: .exe, Linux: binary)
go build -ldflags "-s -w" -o easytier-gui.exe .
```

The resulting `easytier-gui` binary contains all embedded frontend assets (`//go:embed all:dist`) and runs out-of-the-box.
