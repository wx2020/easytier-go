// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only
package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <version> <out>\n", os.Args[0])
		os.Exit(2)
	}
	ver := strings.TrimPrefix(os.Args[1], "v")
	ver = "v" + ver
	out := os.Args[2]

	// Reproduce platform.DefaultMagiskModule & BuildMagiskZip deterministically
	// without requiring go/platform workspace (GOWORK=off friendly).
	moduleID := "easytier_magisk"
	prop := fmt.Sprintf("id=%s\nname=EasyTier_Magisk\nversion=%s\nversionCode=1\nauthor=EasyTier\ndescription=easytier magisk module @EasyTier(https://github.com/EasyTier/EasyTier)\nupdateJson=https://raw.githubusercontent.com/EasyTier/EasyTier/refs/heads/main/easytier-contrib/easytier-magisk/magisk_update.json\nminMagisk=23000\n", moduleID, ver)
	scripts := map[string]string{
		"module.prop":                prop,
		"service.sh":                 "#!/data/adb/magisk/busybox sh\nMODDIR=${0%/*}\nwhile [ \"$(getprop sys.boot_completed)\" != \"1\" ]; do sleep 5; done\n${MODDIR}/easytier_core.sh &\n${MODDIR}/hotspot_iprule.sh add &\n",
		"customize.sh":               "SKIPMOUNT=false\nPROPFILE=true\nPOSTFSDATA=true\nLATESTARTSERVICE=true\nset_perm_recursive $MODPATH 0 0 0777 0777\n",
		"action.sh":                  "#!/system/bin/sh\n# hotspot toggle\necho toggle > /data/adb/modules/" + moduleID + "/enable_IP_rule\n",
		"uninstall.sh":               "#!/system/bin/sh\nrm -rf /data/adb/modules/" + moduleID + "\n",
		"easytier_core.sh":           "#!/system/bin/sh\nMODDIR=${0%/*}\nCONFIG_FILE=${MODDIR}/config/config.toml\n",
		"hotspot_iprule.sh":          "#!/system/bin/sh\nMODDIR=${0%/*}\nACTION=$1\niptables -t nat -N ET_NAT 2>/dev/null\n",
		"config/config.toml":         "# easytier config\n",
		"config/command_args_sample": "--hostname example\n",
		"META-INF/com/google/android/update-binary":  "# updater\n",
		"META-INF/com/google/android/updater-script": "# dummy\n",
		"system/bin/easytier-core":                   "binary placeholder\n",
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Deterministic order: sort keys
	keys := make([]string, 0, len(scripts))
	for k := range scripts {
		keys = append(keys, k)
	}
	// simple sort
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, name := range keys {
		w, err := zw.Create(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if _, err := w.Write([]byte(scripts[name])); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := zw.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	data := buf.Bytes()
	// Validate contains required entries
	required := []string{"module.prop", "service.sh", "customize.sh", "META-INF/com/google/android/update-binary"}
	found := make(map[string]bool)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, f := range zr.File {
		found[f.Name] = true
	}
	for _, r := range required {
		if !found[r] {
			fmt.Fprintf(os.Stderr, "missing %q\n", r)
			os.Exit(1)
		}
	}
	if err := os.WriteFile(out, data, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("magisk %d bytes -> %s\n", len(data), out)
}
