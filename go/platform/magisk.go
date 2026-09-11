// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package platform

import (
	"archive/zip"
	"bytes"
	"fmt"
	"strings"
)

// MagiskModule describes the Magisk module layout (NTV-04).
// Mirrors easytier-contrib/easytier-magisk/*.
type MagiskModule struct {
	ID          string
	Name        string
	Version     string
	VersionCode string
	Author      string
	Description string
	MinMagisk   string
}

func DefaultMagiskModule() MagiskModule {
	return MagiskModule{
		ID:          "easytier_magisk",
		Name:        "EasyTier_Magisk",
		Version:     "v2.6.4",
		VersionCode: "1",
		Author:      "EasyTier",
		Description: "easytier magisk module @EasyTier(https://github.com/EasyTier/EasyTier)",
		MinMagisk:   "23000",
	}
}

func (m MagiskModule) Validate() error {
	if strings.TrimSpace(m.ID) == "" {
		return fmt.Errorf("%w: magisk module id required", ErrInvalidConfig)
	}
	if strings.TrimSpace(m.Version) == "" {
		return fmt.Errorf("%w: magisk version required", ErrInvalidConfig)
	}
	return nil
}

func (m MagiskModule) RenderModuleProp() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "id=%s\n", m.ID)
	fmt.Fprintf(&b, "name=%s\n", m.Name)
	fmt.Fprintf(&b, "version=%s\n", m.Version)
	fmt.Fprintf(&b, "versionCode=%s\n", m.VersionCode)
	fmt.Fprintf(&b, "author=%s\n", m.Author)
	fmt.Fprintf(&b, "description=%s\n", m.Description)
	fmt.Fprintf(&b, "updateJson=https://raw.githubusercontent.com/EasyTier/EasyTier/refs/heads/main/easytier-contrib/easytier-magisk/magisk_update.json\n")
	if m.MinMagisk != "" {
		fmt.Fprintf(&b, "minMagisk=%s\n", m.MinMagisk)
	}
	return b.String(), nil
}

// PlanMagiskInstall returns dry-run plan for installing the Magisk module.
func PlanMagiskInstall(module MagiskModule) (Plan, error) {
	if err := module.Validate(); err != nil {
		return Plan{}, err
	}
	plan := newPlan("android")
	prop, _ := module.RenderModuleProp()
	plan.Add("render module.prop", []string{"module.prop", strings.TrimSpace(prop[:30])}, false, nil)
	plan.Add("install Magisk module", []string{"magisk", "--install-module", module.ID}, true, []string{"magisk", "--remove-module", module.ID})
	plan.Add("ensure TUN device", []string{"sh", "mkdir -p /dev/net && ln -sf /dev/tun /dev/net/tun"}, true, []string{"rm -f /dev/net/tun"})
	plan.Add("start easytier_core.sh watchdog", []string{"sh", "/data/adb/modules/" + module.ID + "/service.sh"}, true, []string{"pkill -f easytier-core"})
	plan.Add("start hotspot_iprule.sh", []string{"sh", "/data/adb/modules/" + module.ID + "/hotspot_iprule.sh", "add"}, true, []string{"sh", "/data/adb/modules/" + module.ID + "/hotspot_iprule.sh", "del"})
	plan.Warnings = append(plan.Warnings, "requires Magisk 23+, root, and reboot to activate")
	return plan, nil
}

// MagiskScripts returns the expected script files for the module (for zip validation).
func MagiskScripts(moduleID string) map[string]string {
	return map[string]string{
		"module.prop":                "# generated",
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
		"system/bin/easytier-core":                   "binary placeholder",
	}
}

// BuildMagiskZip builds an in-memory zip for the module (dry-run, for tests).
func BuildMagiskZip(module MagiskModule) ([]byte, error) {
	if err := module.Validate(); err != nil {
		return nil, err
	}
	prop, err := module.RenderModuleProp()
	if err != nil {
		return nil, err
	}
	scripts := MagiskScripts(module.ID)
	scripts["module.prop"] = prop

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range scripts {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ValidateMagiskZip checks that a built zip contains required entries.
func ValidateMagiskZip(data []byte, moduleID string) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: empty zip", ErrInvalidConfig)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("%w: invalid zip: %v", ErrInvalidConfig, err)
	}
	required := []string{"module.prop", "service.sh", "customize.sh", "META-INF/com/google/android/update-binary"}
	found := make(map[string]bool)
	for _, f := range zr.File {
		found[f.Name] = true
	}
	for _, r := range required {
		if !found[r] {
			return fmt.Errorf("%w: missing %q in magisk zip", ErrInvalidConfig, r)
		}
	}
	// Check module.prop contains id
	for _, f := range zr.File {
		if f.Name == "module.prop" {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			buf := new(bytes.Buffer)
			_, _ = buf.ReadFrom(rc)
			rc.Close()
			if !strings.Contains(buf.String(), "id="+moduleID) {
				return fmt.Errorf("%w: module.prop missing id=%s", ErrInvalidConfig, moduleID)
			}
		}
	}
	return nil
}

// PlanMagiskUninstall returns cleanup plan.
func PlanMagiskUninstall(moduleID string) Plan {
	plan := newPlan("android")
	plan.Add("stop easytier-core", []string{"pkill", "-f", "easytier-core"}, true, nil)
	plan.Add("flush hotspot NAT rules", []string{"sh", "/data/adb/modules/" + moduleID + "/hotspot_iprule.sh", "del"}, true, nil)
	plan.Add("remove module directory", []string{"rm", "-rf", "/data/adb/modules/" + moduleID}, true, nil)
	plan.Add("remove TUN symlink if created", []string{"rm", "-f", "/dev/net/tun"}, true, nil)
	return plan
}
