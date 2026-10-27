# luci-app-easytier

OpenWrt LuCI console for the **EasyTier Go** core, modelled on
`luci-app-singbox` from the MU300 tree.

## Features

- Dashboard: service state, PID, uptime, network name, overlay IPv4, TUN
  device, core version, autostart state, TUN RX/TX.
- Peer table: peer ID, hostname, overlay IPv4, version, latency, next hop,
  cost (from the Go OSPF self-descriptions).
- Route table: OSPF converged destination/next-hop/cost.
- Start / stop / restart and enable / disable autostart.
- Basic config form: network name/secret, hostname, overlay IPv4, listeners,
  peers, MTU and no-tun. Saving validates the TOML with
  `easytier-core --check-config` and restarts the service.
- Recent logs from `logread` (procd stdout/stderr).

## Layout

```
luci-app-easytier/
├── Makefile                         # luci.mk feed template
├── build.ps1                        # standalone Windows PowerShell builder
├── build.sh                         # standalone IPK + plain-file builder
├── control/{control,postinst,postrm}
├── root/
│   ├── etc/init.d/easytier          # procd service
│   ├── usr/share/luci/menu.d/luci-app-easytier.json
│   ├── www/cgi-bin/easytier-api     # shell CGI backend
│   ├── www/luci-static/resources/view/easytier/dashboard_v3.js
│   └── root/config/easytier/config.toml
└── bin/                             # build output (ipk, tarball, binaries)
```

## Build

**Windows (PowerShell):**
```powershell
.\build.ps1
```

**Linux / macOS / Git Bash:**
```bash
./build.sh
```

This builds `easytier-core`/`easytier-cli` with
`CGO_ENABLED=0 GOOS=linux GOARCH=arm64` and emits:

- `bin/luci-app-easytier_1.0.1-1_aarch64_generic.ipk` (standard opkg systems)
- `bin/luci-app-easytier-files-1.0.1.tar.gz` (plain-file deploy)
- `bin/easytier-core`, `bin/easytier-cli`

## Deploy on the F50 (apk-based OpenWrt 25.12)

The F50 has `apk` and no `opkg`, so use the plain-file payload:

```sh
# from the host
scp bin/luci-app-easytier-files-1.0.1.tar.gz root@192.168.0.1:/tmp/
ssh root@192.168.0.1 '
  tar -xzf /tmp/luci-app-easytier-files-1.0.1.tar.gz -C /
  chmod 755 /usr/bin/easytier-core /usr/bin/easytier-cli \
            /usr/bin/easytier-cgroup-exec \
            /etc/init.d/easytier /www/cgi-bin/easytier-api
  chmod 600 /root/config/easytier/config.toml
  /etc/init.d/easytier enable
  /etc/init.d/easytier start
  rm -f /tmp/luci-indexcache* /tmp/luci-modulecache*
'
```

The `chmod` step is required: tarballs built under Windows Git Bash do not
preserve the executable bit, so an extracted binary may otherwise be `0644`.

> The F50 at `192.168.0.1` was deployed this way because it runs apk-tools and
> has no `opkg`. See `docs/LUCI_EASYTIER_F50.md` for the full transcript.

Then open **网络 → EasyTier 组网** in LuCI, or query the CGI directly:

```sh
curl -s 'http://127.0.0.1/cgi-bin/easytier-api?action=status' | jq .
```

## Notes

- The service runs `/usr/bin/easytier-core --config-file
  /root/config/easytier/config.toml --rpc-portal 127.0.0.1:15888`.
- Config is root-only (`0600`); backups are written next to it on every save.
- The Go core requires `CAP_NET_ADMIN`/root; the procd service runs as root.
- The Go CLI management `peer`/`route` JSON is used by the dashboard; the
  plain-text CLI table is intentionally not parsed.
