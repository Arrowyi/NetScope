package indi.arrowyi.netscope.app

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import indi.arrowyi.netscope.sdk.NetScope
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request

class MainActivity : AppCompatActivity() {
    private val scope = MainScope()
    // Use the Builder path so the NetScope Gradle plugin's build-time
    // instrumentation fires on .build(). Note: `OkHttpClient()` no-arg
    // constructor bypasses the Builder and is therefore NOT instrumented
    // (see README "Known Limitations").
    private val client = OkHttpClient.Builder().build()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<Button>(R.id.btnFetch).setOnClickListener {
            scope.launch(Dispatchers.IO) {
                listOf(
                    "https://httpbin.org/get",
                    "https://www.google.com",
                    "https://api.github.com"
                ).forEach { url ->
                    runCatching {
                        client.newCall(Request.Builder().url(url).build()).execute().close()
                    }
                }
                withContext(Dispatchers.Main) { refreshStats() }
            }
        }

        findViewById<Button>(R.id.btnClear).setOnClickListener {
            NetScope.clearStats()
            refreshStats()
        }

        refreshStats()
    }

    private fun refreshStats() {
        val sb = StringBuilder()
        NetScope.getApiStats().forEach { s ->
            sb.appendLine(s.key)
            sb.appendLine("  ↑${fmtBytes(s.txBytesTotal)}  ↓${fmtBytes(s.rxBytesTotal)}  conn=${s.connCountTotal}")
        }
        findViewById<TextView>(R.id.tvStats).text = sb.toString().ifEmpty { "No traffic yet" }
    }

    private fun fmtBytes(b: Long) = when {
        b >= 1_048_576 -> "%.1f MB".format(b / 1_048_576.0)
        b >= 1_024     -> "%.1f KB".format(b / 1_024.0)
        else           -> "$b B"
    }

    override fun onDestroy() { super.onDestroy(); scope.cancel() }
}
