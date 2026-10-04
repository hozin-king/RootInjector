package com.hozinking.rootinjector

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.File

class MainActivity : AppCompatActivity() {

    private lateinit var tvLog: TextView
    private lateinit var tvRootStatus: TextView
    private lateinit var tvPid: TextView
    private lateinit var tvSo: TextView
    private lateinit var etPackage: EditText
    private lateinit var etAddr: EditText
    private lateinit var etValue: EditText
    private lateinit var etSearch: EditText
    private lateinit var spType: Spinner
    private lateinit var spSearchType: Spinner

    private var pid: String = ""
    private var soPath: String = ""
    private var injectorBin: File? = null
    private var hasRoot = false

    private val PICK_SO = 1001
    private val TYPES = arrayOf("i32", "u32", "f32", "i64", "f64", "str")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvLog = findViewById(R.id.tvLog)
        tvRootStatus = findViewById(R.id.tvRootStatus)
        tvPid = findViewById(R.id.tvPid)
        tvSo = findViewById(R.id.tvSo)
        etPackage = findViewById(R.id.etPackage)
        etAddr = findViewById(R.id.etAddr)
        etValue = findViewById(R.id.etValue)
        etSearch = findViewById(R.id.etSearch)
        spType = findViewById(R.id.spType)
        spSearchType = findViewById(R.id.spSearchType)
        tvLog.movementMethod = ScrollingMovementMethod()

        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, TYPES)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spType.adapter = adapter
        spSearchType.adapter = adapter

        findViewById<Button>(R.id.btnPid).setOnClickListener { ambilPid() }
        findViewById<Button>(R.id.btnPickSo).setOnClickListener { pilihSo() }
        findViewById<Button>(R.id.btnInject).setOnClickListener { inject() }
        findViewById<Button>(R.id.btnRead).setOnClickListener { bacaMemori() }
        findViewById<Button>(R.id.btnWrite).setOnClickListener { tulisMemori() }
        findViewById<Button>(R.id.btnSearch).setOnClickListener { cariMemori() }

        thread { initRoot() }
    }

    // ---------- root & binary ----------

    private fun log(msg: String) {
        runOnUiThread {
            tvLog.append(msg + "\n")
            val lm = tvLog.layout
            if (lm != null) {
                val scroll = lm.getLineTop(tvLog.lineCount) - tvLog.height
                if (scroll > 0) tvLog.scrollTo(0, scroll)
            }
        }
    }

    private fun thread(fn: () -> Unit) {
        Thread(fn).start()
    }

    private fun initRoot() {
        val id = shell("id")
        hasRoot = id.contains("uid=0")
        runOnUiThread {
            tvRootStatus.text = if (hasRoot) "✓ Root TERDETEKSI" else "✗ TIDAK ada root — app tidak bisa dipakai"
        }
        log("$ su -c id\n$id")
        if (!hasRoot) return

        // Coba matikan SELinux enforcing (best effort, bantu ptrace)
        shell("setenforce 0")

        // Ekstrak binary injector dari assets
        try {
            val out = File(filesDir, "injector")
            if (!out.exists() || out.length() == 0L) {
                assets.open("injector").use { inp ->
                    out.outputStream().use { oup -> inp.copyTo(oup) }
                }
            }
            shell("chmod 755 ${out.absolutePath}")
            injectorBin = out
            val v = shell("${out.absolutePath}")
            log("injector siap: ${out.absolutePath}\n$v".take(300))
        } catch (e: Exception) {
            log("GAGAL ekstrak injector: ${e.message}")
        }
    }

    /** Jalankan perintah sebagai root, kembalikan stdout+stderr. */
    private fun shell(cmd: String): String {
        return try {
            val p = ProcessBuilder("su", "-c", cmd)
                .redirectErrorStream(true)
                .start()
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor()
            out.trim()
        } catch (e: Exception) {
            "ERROR: ${e.message}"
        }
    }

    private fun inj(vararg args: String): String {
        val bin = injectorBin?.absolutePath ?: return "injector belum siap"
        return shell("$bin ${args.joinToString(" ")}")
    }

    // ---------- inject ----------

    private fun ambilPid() {
        val pkg = etPackage.text.toString().trim()
        if (pkg.isEmpty()) { toast("Isi package dulu"); return }
        thread {
            val out = inj("pidof", pkg)
            log("$ pidof $pkg\n$out")
            val first = out.lines().firstOrNull { it.matches(Regex("\\d+")) }
            if (first != null) {
                pid = first
                runOnUiThread { tvPid.text = "PID: $pid" }
            } else {
                runOnUiThread { toast("Proses tidak ketemu — pastikan gamenya sedang jalan") }
            }
        }
    }

    private fun pilihSo() {
        val i = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            type = "*/*"
            addCategory(Intent.CATEGORY_OPENABLE)
        }
        startActivityForResult(i, PICK_SO)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == PICK_SO && resultCode == Activity.RESULT_OK) {
            val uri = data?.data ?: return
            thread {
                try {
                    val out = File(filesDir, "payload.so")
                    contentResolver.openInputStream(uri)?.use { inp ->
                        out.outputStream().use { oup -> inp.copyTo(oup) }
                    }
                    soPath = out.absolutePath
                    runOnUiThread { tvSo.text = ".so: ${out.name} (${out.length()} byte)" }
                    log("payload disalin ke $soPath")
                } catch (e: Exception) {
                    log("GAGAL salin .so: ${e.message}")
                }
            }
        }
    }

    private fun inject() {
        if (!hasRoot) { toast("Butuh root"); return }
        if (pid.isEmpty()) { toast("Ambil PID dulu"); return }
        if (soPath.isEmpty()) { toast("Pilih file .so dulu"); return }
        thread {
            log("$ inject $pid $soPath ...")
            val out = inj("inject", pid, soPath)
            log(out)
            runOnUiThread {
                if (out.startsWith("OK")) toast("Inject BERHASIL")
                else toast("Inject GAGAL — lihat log")
            }
        }
    }

    // ---------- memori ----------

    private fun bacaMemori() {
        val addr = etAddr.text.toString().trim()
        if (pid.isEmpty() || addr.isEmpty()) { toast("PID & alamat wajib diisi"); return }
        val tipe = spType.selectedItem.toString()
        thread {
            val len = when (tipe) { "i64", "f64" -> 8; "str" -> 64; else -> 4 }
            val out = inj("readmem", pid, addr, len.toString())
            log("$ readmem $addr ($tipe)\n$out")
            if (!out.startsWith("GAGAL") && !out.startsWith("ERROR")) {
                runOnUiThread { etValue.setText(decodeHex(out.trim(), tipe)) }
            }
        }
    }

    private fun tulisMemori() {
        val addr = etAddr.text.toString().trim()
        val value = etValue.text.toString()
        if (pid.isEmpty() || addr.isEmpty() || value.isEmpty()) { toast("PID, alamat & nilai wajib diisi"); return }
        val tipe = spType.selectedItem.toString()
        val hex = encodeValue(value, tipe)
        if (hex == null) { toast("Nilai tidak valid untuk tipe $tipe"); return }
        thread {
            val out = inj("writemem", pid, addr, hex)
            log("$ writemem $addr = $value ($tipe)\n$out")
        }
    }

    private fun cariMemori() {
        val value = etSearch.text.toString()
        if (pid.isEmpty() || value.isEmpty()) { toast("PID & nilai wajib diisi"); return }
        val tipe = spSearchType.selectedItem.toString()
        thread {
            log("$ search $value ($tipe) ... bisa agak lama")
            val out = inj("search", pid, tipe, "'$value'")
            log(out.take(4000))
        }
    }

    // ---------- konversi ----------

    private fun decodeHex(hex: String, tipe: String): String {
        return try {
            val b = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val bb = java.nio.ByteBuffer.wrap(b).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            when (tipe) {
                "f32" -> bb.float.toString()
                "i64" -> bb.long.toString()
                "f64" -> bb.double.toString()
                "str" -> String(b).trim { it <= ' ' || it == '\u0000' }
                else -> bb.int.toString()
            }
        } catch (e: Exception) { hex }
    }

    private fun encodeValue(value: String, tipe: String): String? {
        return try {
            val bb = java.nio.ByteBuffer.allocate(8).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            when (tipe) {
                "f32" -> bb.putFloat(value.toFloat())
                "i64" -> bb.putLong(value.toLong())
                "f64" -> bb.putDouble(value.toDouble())
                "str" -> return value.toByteArray().joinToString("") { "%02x".format(it) }
                else -> bb.putInt(value.toInt())
            }
            val n = when (tipe) { "i64", "f64" -> 8; else -> 4 }
            bb.array().take(n).joinToString("") { "%02x".format(it) }
        } catch (e: Exception) { null }
    }

    private fun toast(msg: String) {
        runOnUiThread { Toast.makeText(this, msg, Toast.LENGTH_SHORT).show() }
    }
}
