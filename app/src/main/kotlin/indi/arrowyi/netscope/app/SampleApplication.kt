package indi.arrowyi.netscope.app

import android.app.Application
import android.util.Log
import indi.arrowyi.netscope.sdk.NetScope

class SampleApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        NetScope.init(this)
        NetScope.setLogInterval(30)
        NetScope.setOnFlowEnd { stats ->
            Log.d("NetScope-App", "Flow ended: ${stats.key} ↑${stats.txBytesInterval} ↓${stats.rxBytesInterval}")
        }
    }
}
