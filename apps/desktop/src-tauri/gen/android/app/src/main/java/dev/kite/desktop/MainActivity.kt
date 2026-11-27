package dev.kite.desktop

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.util.Log
import androidx.activity.enableEdgeToEdge
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

class MainActivity : TauriActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    enableEdgeToEdge()
    super.onCreate(savedInstanceState)
    if (savedInstanceState == null) handleSharedContent(intent)
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    handleSharedContent(intent)
  }

  /**
   * Android shares `content://` URIs that the Rust side cannot open. Copy the
   * payload into the app data dir and let the frontend pick a recipient.
   */
  private fun handleSharedContent(intent: Intent?) {
    if (intent == null) return
    if (intent.action != Intent.ACTION_SEND && intent.action != Intent.ACTION_SEND_MULTIPLE) return

    val batch = "${System.currentTimeMillis()}-${UUID.randomUUID()}"
    val directory = File(applicationContext.dataDir, "incoming_share/$batch")
    if (!directory.mkdirs()) return

    val files = JSONArray()
    fun copy(uri: Uri?) {
      uri ?: return
      val name = displayName(uri)?.substringAfterLast('/')?.substringAfterLast('\\')
        ?.takeIf { it.isNotBlank() && it != "." && it != ".." } ?: "shared-file"
      val target = File(directory, "file-${files.length()}")
      try {
        contentResolver.openInputStream(uri).use { input ->
          if (input == null) return
          target.outputStream().use { output -> input.copyTo(output) }
        }
        files.put(JSONObject().put("path", target.absolutePath).put("name", name))
      } catch (_: Exception) {
        target.delete()
        // Ignore unreadable shares; the user can retry from the source app.
      }
    }

    if (intent.action == Intent.ACTION_SEND) {
      @Suppress("DEPRECATION")
      copy(intent.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri)
    } else {
      @Suppress("DEPRECATION")
      intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.forEach { copy(it) }
    }

    val text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
      ?: intent.getStringExtra(Intent.EXTRA_TEXT)
      ?: intent.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString()
    Log.i("KiteShare", "action=${intent.action} files=${files.length()} text=${text?.length ?: -1}")
    if (files.length() == 0 && text.isNullOrBlank()) {
      directory.deleteRecursively()
      return
    }

    val payload = JSONObject().put("files", files)
    if (!text.isNullOrBlank()) payload.put("text", text)
    try {
      val temp = File(directory, "share.tmp")
      temp.writeText(payload.toString())
      if (!temp.renameTo(File(directory, "share.json"))) directory.deleteRecursively()
    } catch (error: Exception) {
      Log.w("KiteShare", "Could not queue share", error)
      directory.deleteRecursively()
    }
  }

  private fun displayName(uri: Uri): String? {
    if (uri.scheme == "file") return uri.lastPathSegment
    return try {
      contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
        if (!cursor.moveToFirst()) return@use null
        val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (index >= 0) cursor.getString(index) else null
      }
    } catch (_: Exception) {
      null
    }
  }
}
