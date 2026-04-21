package com.netscope.sdk

internal object NetScopeNative {
    init { System.loadLibrary("netscope") }
    external fun nativeInit(): Int
}
