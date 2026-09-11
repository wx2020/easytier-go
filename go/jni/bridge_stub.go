//go:build !cgo

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package jni

// CGOEnabled reports whether this build uses cgo bridge.
func CGOEnabled() bool { return false }

// Stub JNI exports for non-cgo builds (host tests).
// These are not real JNI symbols, but keep API surface testable without cgo.

func Java_com_easytier_jni_EasyTierJNI_setTunFdStub(instName string, fd int) int {
	return SetTunFd(instName, fd)
}

func Java_com_easytier_jni_EasyTierJNI_parseConfigStub(config string) int {
	return ParseConfig(config)
}

func Java_com_easytier_jni_EasyTierJNI_runNetworkInstanceStub(config string) int {
	return RunNetworkInstance(config)
}

func Java_com_easytier_jni_EasyTierJNI_retainNetworkInstanceStub(names []string) int {
	return RetainNetworkInstance(names)
}

func Java_com_easytier_jni_EasyTierJNI_collectNetworkInfosStub() string {
	return CollectNetworkInfos()
}

func Java_com_easytier_jni_EasyTierJNI_getLastErrorStub() string {
	return GetLastError()
}
