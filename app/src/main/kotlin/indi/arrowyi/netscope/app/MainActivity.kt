package indi.arrowyi.netscope.app

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import indi.arrowyi.sdk.NetScope
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request

class MainActivity : AppCompatActivity() {
    private val scope = MainScope()
    private val client = OkHttpClient()

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
        NetScope.getDomainStats().forEach { s ->
            sb.appendLine("${s.domain}")
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
