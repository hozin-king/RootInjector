# Root Injector

Aplikasi Android mandiri untuk inject library `.so` ke proses game + baca/tulis/cari nilai di memori — mirip cara kerja GameGuardian, tapi fokus ke inject & memory tools. **Dibuat terpisah dari Sketchware Pro biar aman.**

## Syarat

- HP **sudah root** (Magisk / KernelSU) — tanpa root aplikasi tidak bisa apa-apa.
- HP **64-bit (arm64)** — binary native hanya dikompilasi untuk arm64-v8a.
- Aplikasi target **64-bit**. Game 32-bit tidak didukung.

## Cara pakai

1. Buka aplikasi, pastikan status "✓ Root TERDETEKSI".
2. **Inject**: isi package target (mis. `com.kiloo.subwaysurf`) → *Ambil PID* (game harus sedang jalan) → *Pilih file .so* (payload mod kamu) → *INJECT!*
3. **Baca/Tulis memori**: isi alamat (hex), pilih tipe (`i32/u32/f32/i64/f64/str`), isi nilai → *Baca* / *Tulis*.
4. **Cari nilai**: isi nilai + tipe → *Cari*. Hasil berupa daftar alamat (maks 200).

## Cara kerja

- Aplikasi mengekstrak binary native `injector` dari assets lalu menjalankannya via `su -c`.
- `inject`: ptrace attach → cari alamat `dlopen`/`mmap` di libc target → alokasi buffer via remote `mmap` → tulis path `.so` → panggil remote `dlopen(path, RTLD_NOW)` → detach.
- `readmem`/`writemem`: via `process_vm_readv`/`process_vm_writev` (sebagai root).
- `search`: scan region memori `rw` di `/proc/<pid>/maps`, cocokkan pola byte (little-endian).

## Batasan jujur

- Game dengan **anti-cheat** bisa menggagalkan inject atau mendeteksi modifikasi.
- Beberapa ROM butuh `setenforce 0` (aplikasi mencoba otomatis, best-effort).
- File `.so` payload **kamu sediakan sendiri** — aplikasi ini hanya injector-nya.
- Search memori game besar bisa lambat (scan per 1MB).

## Build

CI (GitHub Actions) otomatis: compile `native/injector.cpp` pakai NDK r26d (clang arm64) → masukkan ke `app/src/main/assets/injector` → build debug APK → upload sebagai artifact `rootinjector-apk`.

Build lokal butuh Android NDK, lalu:
```
aarch64-linux-android21-clang++ -O2 -fPIE -pie -o app/src/main/assets/injector native/injector.cpp
./gradlew assembleDebug
```
