// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ValidateService checks that service options can be represented safely.
func ValidateService(cfg ServiceConfig) error {
	if cfg.Name == "" {
		return errors.New("service name is required")
	}
	if cfg.Exec == "" {
		return errors.New("service executable is required")
	}
	for _, v := range append([]string{cfg.Name, cfg.Exec}, cfg.Args...) {
		if !utf8.ValidString(v) {
			return errors.New("service options must be valid UTF-8")
		}
		for _, r := range v {
			if r == 0 || (r < 0x20 && r != '\t' && r != '\n' && r != '\r') {
				return errors.New("service options cannot contain invalid XML characters")
			}
		}
	}
	return nil
}

// RenderSystemd returns a systemd unit file.
func RenderSystemd(cfg ServiceConfig) (string, error) {
	if err := ValidateService(cfg); err != nil {
		return "", err
	}
	argv := append([]string{cfg.Exec}, cfg.Args...)
	var b strings.Builder
	b.WriteString("[Unit]\nDescription=")
	b.WriteString(systemdQuote(cfg.Name))
	if cfg.Description != "" {
		b.WriteString("\nDescription=")
		b.WriteString(systemdQuote(cfg.Description))
	}
	b.WriteString("\nAfter=network.target\n\n[Service]\nType=simple\n")
	if cfg.WorkDir != "" {
		b.WriteString("WorkingDirectory=")
		b.WriteString(systemdQuote(cfg.WorkDir))
		b.WriteString("\n")
	}
	b.WriteString("ExecStart=")
	for i, v := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(systemdQuote(v))
	}
	if cfg.DisableRestartOnFailure {
		b.WriteString("\nRestart=no\n")
	} else {
		b.WriteString("\nRestart=always\nRestartSec=1s\n")
	}
	b.WriteString("LimitNOFILE=infinity\n")
	if !cfg.DisableAutostart {
		b.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	}
	return b.String(), nil
}

// RenderOpenRC returns an OpenRC runscript.
func RenderOpenRC(cfg ServiceConfig) (string, error) {
	if err := ValidateService(cfg); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#!/sbin/openrc-run\n\nname=%s\ndescription=%s\ncommand=%s\npidfile=\"/run/${RC_SVCNAME}.pid\"\n\n", shellQuote(cfg.Name), shellQuote(cfg.Name), shellQuote(cfg.Exec))
	b.WriteString("start() {\n\tebegin \"Starting ${RC_SVCNAME}\"\n\tstart-stop-daemon --start --background --make-pidfile --pidfile \"$pidfile\" --exec \"$command\" --")
	writeShellArgv(&b, cfg.Args)
	b.WriteString("\n\teend $?\n}\n\nstop() {\n\tebegin \"Stopping ${RC_SVCNAME}\"\n\tstart-stop-daemon --stop --pidfile \"$pidfile\" --retry TERM/5/KILL/5\n\teend $?\n}\n")
	return b.String(), nil
}

// RenderLaunchd returns a launchd plist.
func RenderLaunchd(cfg ServiceConfig) (string, error) {
	if err := ValidateService(cfg); err != nil {
		return "", err
	}
	argv := append([]string{cfg.Exec}, cfg.Args...)
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>")
	b.WriteString(xmlText(cfg.Name))
	b.WriteString("</string>\n\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, v := range argv {
		b.WriteString("\t\t<string>")
		b.WriteString(xmlText(v))
		b.WriteString("</string>\n")
	}
	b.WriteString("\t</array>\n\t<key>RunAtLoad</key>\n\t<")
	if cfg.DisableAutostart {
		b.WriteString("false")
	} else {
		b.WriteString("true")
	}
	b.WriteString("/>\n\t<key>KeepAlive</key>\n\t<")
	if cfg.DisableRestartOnFailure {
		b.WriteString("false")
	} else {
		b.WriteString("true")
	}
	b.WriteString("/>\n")
	if cfg.WorkDir != "" {
		b.WriteString("\t<key>WorkingDirectory</key>\n\t<string>")
		b.WriteString(xmlText(cfg.WorkDir))
		b.WriteString("</string>\n")
	}
	b.WriteString("</dict>\n</plist>\n")
	return b.String(), nil
}

// RenderFreeBSDRCD returns a FreeBSD rc.d script.
func RenderFreeBSDRCD(cfg ServiceConfig) (string, error) {
	if err := ValidateService(cfg); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "#!/bin/sh\n#\n# PROVIDE: %s\n# REQUIRE: LOGIN FILESYSTEMS NETWORKING\n# KEYWORD: shutdown\n\n. /etc/rc.subr\n\nname=%s\nrcvar=\"${RC_SVCNAME}_enable\"\ncommand=%s\npidfile=\"/var/run/${RC_SVCNAME}.pid\"\n\nload_rc_config \"${RC_SVCNAME}\"\n\n", commentText(cfg.Name), shellQuote(cfg.Name), shellQuote(cfg.Exec))
	b.WriteString("start_cmd=service_start\nservice_start() {\n\t/usr/sbin/daemon -c -S -T \"$name\" -p \"$pidfile\" \"$command\"")
	writeShellArgv(&b, cfg.Args)
	b.WriteString("\n}\n\nstop_cmd=service_stop\nservice_stop() {\n\tif [ -r \"$pidfile\" ]; then\n\t\tkill -TERM \"$(cat \"$pidfile\")\"\n\tfi\n}\n\nrun_rc_command \"$1\"\n")
	return b.String(), nil
}

func writeShellArgv(dst *strings.Builder, args []string) {
	for _, a := range args {
		dst.WriteByte(' ')
		dst.WriteString(shellQuote(a))
	}
}

func shellQuote(v string) string {
	v = strings.NewReplacer("\r", "\\r", "\n", "\\n").Replace(v)
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
}

func systemdQuote(v string) string {
	var q strings.Builder
	q.WriteByte('"')
	for _, r := range v {
		switch r {
		case '%':
			q.WriteString("%%")
		case '\\':
			q.WriteString("\\\\")
		case '"':
			q.WriteString("\\\"")
		case '\n':
			q.WriteString("\\n")
		case '\r':
			q.WriteString("\\r")
		case '\t':
			q.WriteString("\\t")
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&q, "\\x%02X", r)
			} else {
				q.WriteRune(r)
			}
		}
	}
	q.WriteByte('"')
	return q.String()
}

func xmlText(v string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#13;", "\n", "&#10;", "\t", "&#9;")
	return r.Replace(v)
}

func commentText(v string) string {
	return strings.NewReplacer("\r", "\\r", "\n", "\\n").Replace(v)
}
