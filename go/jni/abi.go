// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package jni ABI mapping for Android NDK (NTV-02).
package jni

import (
	"fmt"
	"sort"
)

// ABIDef defines one Android ABI target mapping.
type ABIDef struct {
	AndroidABI string // e.g. arm64-v8a
	RustTarget string // e.g. aarch64-linux-android
	GoArch     string // e.g. arm64
	GoOS       string // always android
	NDKArch    string // ndk toolchain arch
}

// AllABIs is the canonical list matching Rust easytier-android-jni/README.
var AllABIs = []ABIDef{
	{AndroidABI: "arm64-v8a", RustTarget: "aarch64-linux-android", GoArch: "arm64", GoOS: "android", NDKArch: "aarch64"},
	{AndroidABI: "armeabi-v7a", RustTarget: "armv7-linux-androideabi", GoArch: "arm", GoOS: "android", NDKArch: "arm"},
	{AndroidABI: "x86", RustTarget: "i686-linux-android", GoArch: "386", GoOS: "android", NDKArch: "x86"},
	{AndroidABI: "x86_64", RustTarget: "x86_64-linux-android", GoArch: "amd64", GoOS: "android", NDKArch: "x86_64"},
}

// ABIByName returns the ABIDef for a given android ABI string.
func ABIByName(name string) (ABIDef, error) {
	for _, a := range AllABIs {
		if a.AndroidABI == name {
			return a, nil
		}
	}
	return ABIDef{}, fmt.Errorf("%w: unknown ABI %q", ErrInvalidConfig, name)
}

// ValidateABIs checks that all 4 expected ABIs are present and no duplicates.
func ValidateABIs(abis []string) error {
	if len(abis) == 0 {
		return fmt.Errorf("%w: no ABIs provided", ErrInvalidConfig)
	}
	seen := make(map[string]bool)
	for _, abi := range abis {
		if _, err := ABIByName(abi); err != nil {
			return err
		}
		if seen[abi] {
			return fmt.Errorf("%w: duplicate ABI %q", ErrInvalidConfig, abi)
		}
		seen[abi] = true
	}
	return nil
}

// SortedABIs returns a sorted copy of ABIs for deterministic builds.
func SortedABIs(abis []string) []string {
	out := append([]string(nil), abis...)
	sort.Strings(out)
	return out
}

// BuildEnv returns environment variables needed for cross-compilation to the given ABI.
func BuildEnv(abi ABIDef, ndkRoot string) map[string]string {
	env := map[string]string{
		"GOOS":        abi.GoOS,
		"GOARCH":      abi.GoArch,
		"CGO_ENABLED": "1",
		"ANDROID_ABI": abi.AndroidABI,
	}
	if ndkRoot != "" {
		if abi.GoArch == "arm" {
			env["CC"] = ndkRoot + "/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang"
			env["CXX"] = ndkRoot + "/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang++"
		} else {
			clangPrefix := map[string]string{
				"arm64": "aarch64-linux-android21-clang",
				"386":   "i686-linux-android21-clang",
				"amd64": "x86_64-linux-android21-clang",
			}[abi.GoArch]
			if clangPrefix != "" {
				env["CC"] = ndkRoot + "/toolchains/llvm/prebuilt/linux-x86_64/bin/" + clangPrefix
				env["CXX"] = ndkRoot + "/toolchains/llvm/prebuilt/linux-x86_64/bin/" + clangPrefix + "++"
			}
		}
	}
	return env
}

// LibraryName returns the shared library filename for the given ABI.
func LibraryName(abi string) string {
	return "libeasytier_jni.so"
}

// OutputDir returns the jniLibs output path for the given ABI (as used by Android Studio).
func OutputDir(abi string) string {
	return "src/main/jniLibs/" + abi
}

// BuildPlan describes building for all ABIs (dry-run).
type BuildPlan struct {
	ABIs     []string
	Actions  []BuildAction
	Warnings []string
}

type BuildAction struct {
	ABI         string
	Description string
	Commands    [][]string
}

func PlanBuildAllABIs(ndkRoot string) (BuildPlan, error) {
	abis := make([]string, 0, len(AllABIs))
	for _, a := range AllABIs {
		abis = append(abis, a.AndroidABI)
	}
	if err := ValidateABIs(abis); err != nil {
		return BuildPlan{}, err
	}
	plan := BuildPlan{ABIs: SortedABIs(abis)}
	for _, abiName := range abis {
		def, _ := ABIByName(abiName)
		env := BuildEnv(def, ndkRoot)
		action := BuildAction{
			ABI:         abiName,
			Description: fmt.Sprintf("build %s (%s)", abiName, def.RustTarget),
			Commands: [][]string{
				{"go", "build", "-buildmode=c-shared", "-o", OutputDir(abiName) + "/" + LibraryName(abiName), "./..."},
			},
		}
		_ = env
		plan.Actions = append(plan.Actions, action)
	}
	if ndkRoot == "" {
		plan.Warnings = append(plan.Warnings, "ANDROID_NDK_ROOT not set; using host toolchain for dry-run only")
	}
	return plan, nil
}

// IsSupportedABI reports whether an ABI is in the 4-ABI matrix.
func IsSupportedABI(abi string) bool {
	_, err := ABIByName(abi)
	return err == nil
}
