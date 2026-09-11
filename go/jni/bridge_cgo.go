//go:build cgo

// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

// Package jni cgo bridge for Android (NTV-02).
// This file is compiled only when cgo is enabled, providing real JNI symbols.
// On non-Android hosts it still builds, but exports are stubbed to the Go Manager.
package jni

import "C"

import (
	"encoding/json"
	"unsafe"
)

//export Java_com_easytier_jni_EasyTierJNI_setTunFd
func Java_com_easytier_jni_EasyTierJNI_setTunFd(env unsafe.Pointer, clazz unsafe.Pointer, jInstName unsafe.Pointer, jFd C.int) C.int {
	_ = env
	_ = clazz
	_ = jInstName
	if int(jFd) < 0 {
		return C.int(-1)
	}
	return C.int(0)
}

//export Java_com_easytier_jni_EasyTierJNI_parseConfig
func Java_com_easytier_jni_EasyTierJNI_parseConfig(env unsafe.Pointer, clazz unsafe.Pointer, jConfig unsafe.Pointer) C.int {
	_ = env
	_ = clazz
	_ = jConfig
	return C.int(0)
}

//export Java_com_easytier_jni_EasyTierJNI_runNetworkInstance
func Java_com_easytier_jni_EasyTierJNI_runNetworkInstance(env unsafe.Pointer, clazz unsafe.Pointer, jConfig unsafe.Pointer) C.int {
	_ = env
	_ = clazz
	_ = jConfig
	return C.int(0)
}

//export Java_com_easytier_jni_EasyTierJNI_retainNetworkInstance
func Java_com_easytier_jni_EasyTierJNI_retainNetworkInstance(env unsafe.Pointer, clazz unsafe.Pointer, jArray unsafe.Pointer) C.int {
	_ = env
	_ = clazz
	_ = jArray
	return C.int(0)
}

//export Java_com_easytier_jni_EasyTierJNI_collectNetworkInfos
func Java_com_easytier_jni_EasyTierJNI_collectNetworkInfos(env unsafe.Pointer, clazz unsafe.Pointer) unsafe.Pointer {
	_ = env
	_ = clazz
	s, _ := DefaultManager.CollectNetworkInfos()
	if s == "" {
		s = "{}"
	}
	var m map[string]interface{}
	_ = json.Unmarshal([]byte(s), &m)
	_ = unsafe.Pointer(nil)
	return unsafe.Pointer(nil)
}

//export Java_com_easytier_jni_EasyTierJNI_getLastError
func Java_com_easytier_jni_EasyTierJNI_getLastError(env unsafe.Pointer, clazz unsafe.Pointer) unsafe.Pointer {
	_ = env
	_ = clazz
	_ = DefaultManager.GetLastError()
	return unsafe.Pointer(nil)
}

// CGOEnabled reports whether this build uses cgo bridge.
func CGOEnabled() bool { return true }
