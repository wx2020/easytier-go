// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package service

import (
	"strings"
	"testing"
)

var testOptions = Options{
	Name: "easytier",
	Exec: "/opt/easytier/easytier-core",
	Args: []string{"-c", "/etc/easytier/config.toml", "--node-name", "edge node"},
}

func TestRenderersTemplates(t *testing.T) {
	tests := []struct {
		name   string
		render func(Options) (string, error)
		want   string
	}{
		{
			name:   "systemd",
			render: RenderSystemd,
			want:   "[Unit]\nDescription=\"easytier\"\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=\"/opt/easytier/easytier-core\" \"-c\" \"/etc/easytier/config.toml\" \"--node-name\" \"edge node\"\nRestart=always\nRestartSec=1s\n\n[Install]\nWantedBy=multi-user.target\n",
		},
		{
			name:   "openrc",
			render: RenderOpenRC,
			want:   "#!/sbin/openrc-run\n\nname='easytier'\ndescription='easytier'\ncommand='/opt/easytier/easytier-core'\npidfile=\"/run/${RC_SVCNAME}.pid\"\n\nstart() {\n\tebegin \"Starting ${RC_SVCNAME}\"\n\tstart-stop-daemon --start --background --make-pidfile --pidfile \"$pidfile\" --exec \"$command\" -- '-c' '/etc/easytier/config.toml' '--node-name' 'edge node'\n\teend $?\n}\n\nstop() {\n\tebegin \"Stopping ${RC_SVCNAME}\"\n\tstart-stop-daemon --stop --pidfile \"$pidfile\" --retry TERM/5/KILL/5\n\teend $?\n}\n",
		},
		{
			name:   "launchd",
			render: RenderLaunchd,
			want:   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>easytier</string>\n\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>/opt/easytier/easytier-core</string>\n\t\t<string>-c</string>\n\t\t<string>/etc/easytier/config.toml</string>\n\t\t<string>--node-name</string>\n\t\t<string>edge node</string>\n\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>KeepAlive</key>\n\t<true/>\n</dict>\n</plist>\n",
		},
		{
			name:   "freebsd rc.d",
			render: RenderFreeBSDRCD,
			want:   "#!/bin/sh\n#\n# PROVIDE: easytier\n# REQUIRE: LOGIN FILESYSTEMS NETWORKING\n# KEYWORD: shutdown\n\n. /etc/rc.subr\n\nname='easytier'\nrcvar=\"${RC_SVCNAME}_enable\"\ncommand='/opt/easytier/easytier-core'\npidfile=\"/var/run/${RC_SVCNAME}.pid\"\n\nload_rc_config \"${RC_SVCNAME}\"\n\nstart_cmd=service_start\nservice_start() {\n\t/usr/sbin/daemon -c -S -T \"$name\" -p \"$pidfile\" \"$command\" '-c' '/etc/easytier/config.toml' '--node-name' 'edge node'\n}\n\nstop_cmd=service_stop\nservice_stop() {\n\tif [ -r \"$pidfile\" ]; then\n\t\tkill -TERM \"$(cat \"$pidfile\")\"\n\tfi\n}\n\nrun_rc_command \"$1\"\n",
		},
		{
			name:   "windows command line",
			render: RenderWindowsCommandLine,
			want:   "\"/opt/easytier/easytier-core\" \"-c\" \"/etc/easytier/config.toml\" \"--node-name\" \"edge node\"",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.render(testOptions)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Errorf("rendered template mismatch (-want +got):\nwant: %q\n got: %q", test.want, got)
			}
		})
	}
}

func TestRenderersEscapeInjectionSensitiveInput(t *testing.T) {
	options := Options{
		Name: "bad\n[Service]\nExecStart=/tmp/evil",
		Exec: "/usr/bin/worker; touch /tmp/pwned",
		Args: []string{"$(touch /tmp/pwned)", `quote"and\\slash`, "' ; rm -rf /", "<&>"},
	}

	systemd, err := RenderSystemd(options)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(systemd, "\nExecStart=/tmp/evil") || !strings.Contains(systemd, `\n[Service]\nExecStart=/tmp/evil`) {
		t.Fatalf("systemd input escaped incorrectly: %q", systemd)
	}

	openrc, err := RenderOpenRC(options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(openrc, `'"'"' ; rm -rf /'`) || !strings.Contains(openrc, "'$(touch /tmp/pwned)'") {
		t.Fatalf("OpenRC arguments are not shell quoted: %q", openrc)
	}

	rcd, err := RenderFreeBSDRCD(options)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rcd, "\nExecStart=/tmp/evil") || !strings.Contains(rcd, "# PROVIDE: bad\\n[Service]\\nExecStart=/tmp/evil") {
		t.Fatalf("rc.d name escaped incorrectly: %q", rcd)
	}

	launchd, err := RenderLaunchd(options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(launchd, "&lt;&amp;&gt;") {
		t.Fatalf("launchd XML text is not escaped: %q", launchd)
	}

	windows, err := RenderWindowsCommandLine(options)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(windows, `"quote\"and\\slash"`) {
		t.Fatalf("Windows argument is not escaped: %q", windows)
	}
}

func TestOptionsValidate(t *testing.T) {
	for _, options := range []Options{{}, {Name: "name"}, {Exec: "command"}, {Name: "name\x00", Exec: "command"}, {Name: "name", Exec: "command", Args: []string{"\x01"}}} {
		if err := options.Validate(); err == nil {
			t.Errorf("Validate(%+v) succeeded", options)
		}
	}
}

func TestSystemdControls(t *testing.T) {
	unit, err := RenderSystemd(Options{Name: "test", Exec: "/bin/test", DisableAutostart: true, DisableRestartOnFailure: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(unit, "[Install]") || !strings.Contains(unit, "Restart=no\n") {
		t.Fatalf("systemd controls not applied: %q", unit)
	}
}
