// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package service renders service-manager configuration without installing it.
package service

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Options describes the process launched by a service manager. Args is already
// split into argv elements; it is never parsed as a shell command.
type Options struct {
	Name                    string
	Exec                    string
	Args                    []string
	DisableAutostart        bool
	DisableRestartOnFailure bool
}

// Validate checks that options can be represented safely by every renderer.
func (o Options) Validate() error {
	if o.Name == "" {
		return errors.New("service name is required")
	}
	if o.Exec == "" {
		return errors.New("service executable is required")
	}
	for _, value := range append([]string{o.Name, o.Exec}, o.Args...) {
		if !utf8.ValidString(value) {
			return errors.New("service options must be valid UTF-8")
		}
		for _, r := range value {
			if r == 0 || (r < 0x20 && r != '\t' && r != '\n' && r != '\r') {
				return errors.New("service options cannot contain invalid XML characters")
			}
		}
	}
	return nil
}

// RenderSystemd returns a systemd unit file.
func RenderSystemd(options Options) (string, error) {
	if err := options.Validate(); err != nil {
		return "", err
	}

	argv := append([]string{options.Exec}, options.Args...)
	var unit strings.Builder
	unit.WriteString("[Unit]\nDescription=")
	unit.WriteString(systemdQuote(options.Name))
	unit.WriteString("\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=")
	for i, value := range argv {
		if i > 0 {
			unit.WriteByte(' ')
		}
		unit.WriteString(systemdQuote(value))
	}
	if options.DisableRestartOnFailure {
		unit.WriteString("\nRestart=no\n")
	} else {
		unit.WriteString("\nRestart=always\nRestartSec=1s\n")
	}
	if !options.DisableAutostart {
		unit.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	}
	return unit.String(), nil
}

// RenderOpenRC returns an OpenRC runscript.
func RenderOpenRC(options Options) (string, error) {
	if err := options.Validate(); err != nil {
		return "", err
	}

	var script strings.Builder
	fmt.Fprintf(&script, "#!/sbin/openrc-run\n\nname=%s\ndescription=%s\ncommand=%s\npidfile=\"/run/${RC_SVCNAME}.pid\"\n\n", shellQuote(options.Name), shellQuote(options.Name), shellQuote(options.Exec))
	script.WriteString("start() {\n\tebegin \"Starting ${RC_SVCNAME}\"\n\tstart-stop-daemon --start --background --make-pidfile --pidfile \"$pidfile\" --exec \"$command\" --")
	writeShellArgv(&script, options.Args)
	script.WriteString("\n\teend $?\n}\n\nstop() {\n\tebegin \"Stopping ${RC_SVCNAME}\"\n\tstart-stop-daemon --stop --pidfile \"$pidfile\" --retry TERM/5/KILL/5\n\teend $?\n}\n")
	return script.String(), nil
}

// RenderLaunchd returns a launchd plist.
func RenderLaunchd(options Options) (string, error) {
	if err := options.Validate(); err != nil {
		return "", err
	}

	argv := append([]string{options.Exec}, options.Args...)
	var plist strings.Builder
	plist.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>")
	plist.WriteString(xmlText(options.Name))
	plist.WriteString("</string>\n\t<key>ProgramArguments</key>\n\t<array>\n")
	for _, value := range argv {
		plist.WriteString("\t\t<string>")
		plist.WriteString(xmlText(value))
		plist.WriteString("</string>\n")
	}
	plist.WriteString("\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>KeepAlive</key>\n\t<true/>\n</dict>\n</plist>\n")
	return plist.String(), nil
}

// RenderFreeBSDRCD returns a FreeBSD rc.d script.
func RenderFreeBSDRCD(options Options) (string, error) {
	if err := options.Validate(); err != nil {
		return "", err
	}

	var script strings.Builder
	fmt.Fprintf(&script, "#!/bin/sh\n#\n# PROVIDE: %s\n# REQUIRE: LOGIN FILESYSTEMS NETWORKING\n# KEYWORD: shutdown\n\n. /etc/rc.subr\n\nname=%s\nrcvar=\"${RC_SVCNAME}_enable\"\ncommand=%s\npidfile=\"/var/run/${RC_SVCNAME}.pid\"\n\nload_rc_config \"${RC_SVCNAME}\"\n\n", commentText(options.Name), shellQuote(options.Name), shellQuote(options.Exec))
	script.WriteString("start_cmd=service_start\nservice_start() {\n\t/usr/sbin/daemon -c -S -T \"$name\" -p \"$pidfile\" \"$command\"")
	writeShellArgv(&script, options.Args)
	script.WriteString("\n}\n\nstop_cmd=service_stop\nservice_stop() {\n\tif [ -r \"$pidfile\" ]; then\n\t\tkill -TERM \"$(cat \"$pidfile\")\"\n\tfi\n}\n\nrun_rc_command \"$1\"\n")
	return script.String(), nil
}

// RenderWindowsCommandLine returns a CreateProcess-compatible command line.
func RenderWindowsCommandLine(options Options) (string, error) {
	if err := options.Validate(); err != nil {
		return "", err
	}

	argv := append([]string{options.Exec}, options.Args...)
	quoted := make([]string, len(argv))
	for i, value := range argv {
		quoted[i] = windowsQuote(value)
	}
	return strings.Join(quoted, " "), nil
}

func writeShellArgv(dst *strings.Builder, args []string) {
	for _, arg := range args {
		dst.WriteByte(' ')
		dst.WriteString(shellQuote(arg))
	}
}

func shellQuote(value string) string {
	// Newlines are not valid service metadata. Rendering them literally would
	// create misleading unit/script lines, so preserve a visible safe form.
	value = strings.NewReplacer("\r", "\\r", "\n", "\\n").Replace(value)
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func systemdQuote(value string) string {
	var quoted strings.Builder
	quoted.WriteByte('"')
	for _, r := range value {
		switch r {
		case '%':
			quoted.WriteString("%%")
		case '\\':
			quoted.WriteString("\\\\")
		case '"':
			quoted.WriteString("\\\"")
		case '\n':
			quoted.WriteString("\\n")
		case '\r':
			quoted.WriteString("\\r")
		case '\t':
			quoted.WriteString("\\t")
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&quoted, "\\x%02X", r)
			} else {
				quoted.WriteRune(r)
			}
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}

func windowsQuote(value string) string {
	var quoted strings.Builder
	quoted.WriteByte('"')
	backslashes := 0
	for _, r := range value {
		switch r {
		case '\\':
			backslashes++
		case '"':
			quoted.WriteString(strings.Repeat("\\", backslashes*2+1))
			quoted.WriteByte('"')
			backslashes = 0
		default:
			quoted.WriteString(strings.Repeat("\\", backslashes))
			quoted.WriteRune(r)
			backslashes = 0
		}
	}
	quoted.WriteString(strings.Repeat("\\", backslashes*2))
	quoted.WriteByte('"')
	return quoted.String()
}

func xmlText(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\r", "&#13;", "\n", "&#10;", "\t", "&#9;")
	return replacer.Replace(value)
}

func commentText(value string) string {
	return strings.NewReplacer("\r", "\\r", "\n", "\\n").Replace(value)
}
