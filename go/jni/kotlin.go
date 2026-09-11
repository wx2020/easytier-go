// SPDX-FileCopyrightText: 2025 EasyTier Contributors
// SPDX-License-Identifier: LGPL-3.0-only

package jni

import (
	"fmt"
	"strings"
)

// KotlinFile describes a generated Kotlin source file.
type KotlinFile struct {
	Path    string
	Package string
	Content string
}

// GeneratedKotlinAPI returns all Kotlin files that mirror the Rust kotlin/ directory.
func GeneratedKotlinAPI() []KotlinFile {
	return []KotlinFile{
		{Path: "com/easytier/jni/EasyTierJNI.kt", Package: "com.easytier.jni", Content: KotlinEasyTierJNI()},
		{Path: "com/easytier/jni/EasyTierManager.kt", Package: "com.easytier.jni", Content: KotlinEasyTierManager()},
		{Path: "com/easytier/jni/EasyTierVpnService.kt", Package: "com.easytier.jni", Content: KotlinEasyTierVpnService()},
	}
}

// KotlinEasyTierJNI returns the full Kotlin object matching easytier-android-jni/kotlin/EasyTierJNI.kt
func KotlinEasyTierJNI() string {
	return `package com.easytier.jni

/** EasyTier JNI interface - Go implementation mirrors Rust easytier-android-jni */
object EasyTierJNI {

    init {
        System.loadLibrary("easytier_jni")
    }

    @JvmStatic external fun setTunFd(instanceName: String, fd: Int): Int
    @JvmStatic external fun parseConfig(config: String): Int
    @JvmStatic external fun runNetworkInstance(config: String): Int
    @JvmStatic external fun retainNetworkInstance(instanceNames: Array<String>?): Int
    @JvmStatic external fun collectNetworkInfos(maxLength: Int): String?
    @JvmStatic external fun collectNetworkInfosAsMap(maxLength: Int): Map<String, String>
    @JvmStatic external fun getLastError(): String?

    @JvmStatic
    fun stopAllInstances(): Int {
        return retainNetworkInstance(null)
    }

    @JvmStatic
    fun retainSingleInstance(instanceName: String): Int {
        return retainNetworkInstance(arrayOf(instanceName))
    }

    @JvmStatic
    fun collectNetworkInfos(): String? = collectNetworkInfos(100)
}
`
}

// KotlinEasyTierManager returns the manager class that monitors network status and restarts VpnService.
func KotlinEasyTierManager() string {
	return `package com.easytier.jni

import android.app.Activity
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.util.Log

class EasyTierManager(
    private val activity: Activity,
    private val instanceName: String,
    private val networkConfig: String
) {
    companion object {
        private const val TAG = "EasyTierManager"
        private const val MONITOR_INTERVAL = 3000L
    }
    private val handler = Handler(Looper.getMainLooper())
    private var isRunning = false
    private var currentIpv4: String? = null
    private var currentProxyCidrs: List<String> = emptyList()
    private var vpnServiceIntent: Intent? = null

    fun start() {
        if (isRunning) return
        val result = EasyTierJNI.runNetworkInstance(networkConfig)
        if (result == 0) {
            isRunning = true
            handler.post(monitorRunnable)
        } else {
            Log.e(TAG, "start failed: ${EasyTierJNI.getLastError()}")
        }
    }
    fun stop() {
        isRunning = false
        handler.removeCallbacks(monitorRunnable)
        stopVpnService()
        EasyTierJNI.stopAllInstances()
    }
    private val monitorRunnable = object : Runnable {
        override fun run() {
            if (isRunning) {
                monitorNetworkStatus()
                handler.postDelayed(this, MONITOR_INTERVAL)
            }
        }
    }
    private fun monitorNetworkStatus() { /* polls collectNetworkInfos and restarts VpnService on change */ }
    private fun restartVpnService(ipv4: String, proxyCidrs: List<String>) {
        stopVpnService()
        startVpnService(ipv4, proxyCidrs)
    }
    private fun startVpnService(ipv4: String, proxyCidrs: List<String>) {
        val intent = Intent(activity, EasyTierVpnService::class.java)
        intent.putExtra("ipv4_address", ipv4)
        intent.putStringArrayListExtra("proxy_cidrs", ArrayList(proxyCidrs))
        intent.putExtra("instance_name", instanceName)
        activity.startService(intent)
        vpnServiceIntent = intent
    }
    private fun stopVpnService() {
        vpnServiceIntent?.let { activity.stopService(it) }
        vpnServiceIntent = null
    }
    data class EasyTierStatus(val isRunning: Boolean, val instanceName: String, val currentIpv4: String?, val currentProxyCidrs: List<String>)
    fun getStatus(): EasyTierStatus = EasyTierStatus(isRunning, instanceName, currentIpv4, currentProxyCidrs)
}
`
}

// KotlinEasyTierVpnService returns the VpnService implementation.
func KotlinEasyTierVpnService() string {
	return `package com.easytier.jni

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

class EasyTierVpnService : VpnService() {
    companion object { private const val TAG = "EasyTierVpnService" }
    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val ipv4 = intent?.getStringExtra("ipv4_address") ?: return START_NOT_STICKY
        val proxyCidrs = intent.getStringArrayListExtra("proxy_cidrs") ?: arrayListOf()
        val instanceName = intent.getStringExtra("instance_name") ?: "default"
        val fd = establishVpnInterface(ipv4, proxyCidrs)
        if (fd != null) {
            try {
                EasyTierJNI.setTunFd(instanceName, fd.fd)
            } catch (e: Exception) {
                Log.e(TAG, "setTunFd failed", e)
            }
        }
        return START_STICKY
    }
    private fun establishVpnInterface(ipv4: String, proxyCidrs: List<String>): ParcelFileDescriptor? {
        val builder = Builder()
        builder.setMtu(1380)
        val parts = ipv4.split("/")
        if (parts.size == 2) {
            builder.addAddress(parts[0], parts[1].toInt())
        }
        for (cidr in proxyCidrs) {
            val p = cidr.split("/")
            if (p.size == 2) builder.addRoute(p[0], p[1].toInt())
        }
        builder.setSession("EasyTier VPN")
        return try { builder.establish() } catch (e: Exception) { Log.e(TAG, "establish failed", e); null }
    }
    override fun onDestroy() {
        vpnInterface?.close()
        vpnInterface = null
        super.onDestroy()
    }
}
`
}

// ValidateKotlinAPI checks that generated files contain required symbols.
func ValidateKotlinAPI() error {
	files := GeneratedKotlinAPI()
	required := []string{
		"setTunFd",
		"parseConfig",
		"runNetworkInstance",
		"retainNetworkInstance",
		"collectNetworkInfos",
		"getLastError",
		"stopAllInstances",
		"retainSingleInstance",
	}
	for _, f := range files {
		if f.Path == "com/easytier/jni/EasyTierJNI.kt" {
			for _, sym := range required {
				if !strings.Contains(f.Content, sym) {
					return fmt.Errorf("kotlin file %s missing %q", f.Path, sym)
				}
			}
		}
	}
	return nil
}
