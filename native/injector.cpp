// injector — root helper untuk RootInjector (arm64 / aarch64 only).
// Dijalankan sebagai root:  su -c /path/injector <perintah>
// Perintah:
//   pidof <package>                 -> PID (atau kosong)
//   inject <pid> <so_path>          -> handle dlopen (hex) / GAGAL
//   readmem <pid> <addr_hex> <len>   -> hex bytes ke stdout
//   writemem <pid> <addr_hex> <hex>  -> OK <nbytes> / GAGAL
//   search <pid> <tipe> <nilai>     -> daftar alamat hex (maks 200)
//       tipe: i32 u32 f32 i64 f64 str
//   maps <pid>                      -> dump /proc/<pid>/maps
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/mman.h>

// ---------- util ----------

static unsigned long long get_libc_base(pid_t pid) {
    // base address dari segmen r-xp libc.so di /proc/<pid>/maps
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[1024];
    unsigned long long base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
            base = strtoull(line, NULL, 16);
            break;
        }
    }
    fclose(f);
    return base;
}

static unsigned long long get_local_libc_base(void) {
    Dl_info info;
    if (dladdr((void *)get_libc_base, &info) && info.dli_fbase)
        return (unsigned long long)info.dli_fbase;
    // fallback: cari di maps sendiri
    return get_libc_base(getpid());
}

// alamat fungsi di proses target = base libc target + offset lokal
static unsigned long long remote_func(pid_t pid, void *local_func) {
    unsigned long long local_base = get_local_libc_base();
    unsigned long long remote_base = get_libc_base(pid);
    if (!local_base || !remote_base) return 0;
    unsigned long long off = (unsigned long long)local_func - local_base;
    return remote_base + off;
}

// ---------- remote call via ptrace (aarch64) ----------

static int wait_stopped(pid_t pid) {
    int status;
    for (int i = 0; i < 50; i++) {
        pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid && WIFSTOPPED(status)) return 0;
        if (w == pid) return -1;
        usleep(20000);
    }
    return -1;
}

// Panggil func(arg0..arg5) di proses target. Return = x0 setelah fungsi return.
static unsigned long long remote_call(pid_t pid, unsigned long long func,
                                      unsigned long long a0, unsigned long long a1,
                                      unsigned long long a2, unsigned long long a3,
                                      unsigned long long a4, unsigned long long a5) {
    struct user_regs_struct orig, regs;
    struct iovec iov;
    int status = 0;
    unsigned long long ret = 0;
    iov.iov_base = &orig;
    iov.iov_len = sizeof(orig);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0) return 0;
    memcpy(&regs, &orig, sizeof(regs));

    regs.regs[0] = a0; regs.regs[1] = a1; regs.regs[2] = a2;
    regs.regs[3] = a3; regs.regs[4] = a4; regs.regs[5] = a5;
    regs.pc = func;
    regs.regs[30] = 0;                 // lr = 0 -> ret memicu SIGSEGV
    regs.sp = orig.sp & ~15ULL;        // stack 16-byte aligned

    iov.iov_base = &regs;
    if (ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0) return 0;
    if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) goto restore;

    waitpid(pid, &status, 0);          // tunggu SIGSEGV saat ret ke 0
    if (!WIFSTOPPED(status)) goto restore;

    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) != 0) goto restore;
    ret = regs.regs[0];

restore:
    iov.iov_base = &orig;              // kembalikan register asli
    iov.iov_len = sizeof(orig);
    ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov);
    if (!WIFSTOPPED(status)) return 0;
    return ret;
}

// ---------- perintah ----------

static int cmd_pidof(const char *pkg) {
    DIR *d = opendir("/proc");
    if (!d) { printf("GAGAL buka /proc\n"); return 1; }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char path[96];
        snprintf(path, sizeof(path), "/proc/%s/cmdline", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char cmd[512];
        size_t n = fread(cmd, 1, sizeof(cmd) - 1, f);
        fclose(f);
        if (n == 0) continue;
        cmd[n] = 0;
        if (strcmp(cmd, pkg) == 0) {
            printf("%s\n", e->d_name);
            closedir(d);
            return 0;
        }
    }
    closedir(d);
    printf("TIDAK_KETEMU\n");
    return 0;
}

static ssize_t vm_read(pid_t pid, unsigned long long addr, void *buf, size_t len) {
    struct iovec local = { buf, len };
    struct iovec remote = { (void *)addr, len };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static ssize_t vm_write(pid_t pid, unsigned long long addr, const void *buf, size_t len) {
    struct iovec local = { (void *)buf, len };
    struct iovec remote = { (void *)addr, len };
    return process_vm_writev(pid, &local, 1, &remote, 1, 0);
}

static int cmd_readmem(pid_t pid, unsigned long long addr, size_t len) {
    if (len == 0 || len > 65536) { printf("GAGAL len\n"); return 1; }
    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) return 1;
    ssize_t r = vm_read(pid, addr, buf, len);
    if (r <= 0) { printf("GAGAL read: %s\n", strerror(errno)); free(buf); return 1; }
    for (ssize_t i = 0; i < r; i++) printf("%02x", buf[i]);
    printf("\n");
    free(buf);
    return 0;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int cmd_writemem(pid_t pid, unsigned long long addr, const char *hex) {
    size_t hlen = strlen(hex);
    if (hlen == 0 || hlen % 2) { printf("GAGAL hex ganjil\n"); return 1; }
    size_t len = hlen / 2;
    unsigned char *buf = (unsigned char *)malloc(len);
    for (size_t i = 0; i < len; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) { printf("GAGAL hex\n"); free(buf); return 1; }
        buf[i] = (hi << 4) | lo;
    }
    ssize_t w = vm_write(pid, addr, buf, len);
    free(buf);
    if (w <= 0) { printf("GAGAL write: %s\n", strerror(errno)); return 1; }
    printf("OK %zd\n", w);
    return 0;
}

// cari nilai di semua region rw (anon/heap), hasil maks 200 alamat
static int cmd_search(pid_t pid, const char *type, const char *value) {
    unsigned char needle[64];
    size_t nlen = 0;
    if (!strcmp(type, "i32") || !strcmp(type, "u32")) {
        int32_t v = (int32_t)strtol(value, NULL, 0);
        memcpy(needle, &v, 4); nlen = 4;
    } else if (!strcmp(type, "f32")) {
        float v = strtof(value, NULL);
        memcpy(needle, &v, 4); nlen = 4;
    } else if (!strcmp(type, "i64")) {
        int64_t v = strtoll(value, NULL, 0);
        memcpy(needle, &v, 8); nlen = 8;
    } else if (!strcmp(type, "f64")) {
        double v = strtod(value, NULL);
        memcpy(needle, &v, 8); nlen = 8;
    } else if (!strcmp(type, "str")) {
        nlen = strlen(value);
        if (nlen == 0 || nlen > sizeof(needle)) { printf("GAGAL\n"); return 1; }
        memcpy(needle, value, nlen);
    } else { printf("GAGAL tipe\n"); return 1; }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) { printf("GAGAL maps\n"); return 1; }

    const size_t CHUNK = 1 << 20; // 1MB
    unsigned char *buf = (unsigned char *)malloc(CHUNK + 64);
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f) && found < 200) {
        unsigned long long start, end;
        char perms[8];
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3) continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue;   // butuh rw
        if (strstr(line, "/system/") || strstr(line, "/apex/")) continue; // skip system
        unsigned long long size = end - start;
        if (size == 0 || size > (1ULL << 32)) continue;
        for (unsigned long long off = 0; off < size && found < 200; ) {
            size_t want = size - off > CHUNK ? CHUNK : (size_t)(size - off);
            // overlap agar pola di perbatasan chunk tidak terlewat
            ssize_t r = vm_read(pid, start + off, buf, want + (nlen - 1 > 64 ? 64 : nlen - 1));
            if (r <= (ssize_t)nlen) break;
            for (ssize_t i = 0; i + (ssize_t)nlen <= r && found < 200; i++) {
                if (memcmp(buf + i, needle, nlen) == 0) {
                    printf("0x%llx\n", start + off + i);
                    found++;
                    i += nlen - 1;
                }
            }
            if ((size_t)r < want) break;
            off += want;
        }
    }
    free(buf);
    fclose(f);
    printf("SELESAI %d\n", found);
    return 0;
}

static int cmd_maps(pid_t pid) {
    char path[64], buf[4096];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("GAGAL\n"); return 1; }
    ssize_t r;
    while ((r = read(fd, buf, sizeof(buf))) > 0) fwrite(buf, 1, r, stdout);
    close(fd);
    return 0;
}

static int cmd_inject(pid_t pid, const char *so_path) {
    if (access(so_path, R_OK) != 0) { printf("GAGAL so tidak bisa dibaca\n"); return 1; }

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
        printf("GAGAL attach: %s\n", strerror(errno));
        return 1;
    }
    if (wait_stopped(pid) != 0) {
        printf("GAGAL wait\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }

    unsigned long long p_mmap = remote_func(pid, (void *)mmap);
    unsigned long long p_dlopen = remote_func(pid, (void *)dlopen);
    if (!p_mmap || !p_dlopen) {
        printf("GAGAL resolve\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }

    // alokasi buffer r/w di target
    unsigned long long buf = remote_call(pid, p_mmap, 0, 8192,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, (unsigned long long)-1, 0);
    if (!buf || buf == (unsigned long long)-1) {
        printf("GAGAL mmap\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }

    size_t plen = strlen(so_path) + 1;
    if (plen > 4096) plen = 4096;
    if (vm_write(pid, buf, so_path, plen) != (ssize_t)plen) {
        printf("GAGAL tulis path\n");
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 1;
    }

    unsigned long long handle = remote_call(pid, p_dlopen, buf, RTLD_NOW | RTLD_LOCAL, 0, 0, 0, 0);
    // bebaskan buffer
    unsigned long long p_munmap = remote_func(pid, (void *)munmap);
    if (p_munmap) remote_call(pid, p_munmap, buf, 8192, 0, 0, 0, 0);

    ptrace(PTRACE_DETACH, pid, 0, 0);
    if (!handle) {
        printf("GAGAL dlopen (handle 0)\n");
        return 1;
    }
    printf("OK handle=0x%llx\n", handle);
    return 0;
}

// ---------- main ----------

static void usage(void) {
    printf("pakai: injector <perintah> [arg...]\n"
           "  pidof <package>\n"
           "  inject <pid> <so_path>\n"
           "  readmem <pid> <addr_hex> <len>\n"
           "  writemem <pid> <addr_hex> <hexbytes>\n"
           "  search <pid> <i32|u32|f32|i64|f64|str> <nilai>\n"
           "  maps <pid>\n");
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    if (!strcmp(argv[1], "pidof") && argc == 3) return cmd_pidof(argv[2]);
    if (!strcmp(argv[1], "inject") && argc == 4) return cmd_inject(atoi(argv[2]), argv[3]);
    if (!strcmp(argv[1], "readmem") && argc == 5)
        return cmd_readmem(atoi(argv[2]), strtoull(argv[3], NULL, 16), atoi(argv[4]));
    if (!strcmp(argv[1], "writemem") && argc == 5)
        return cmd_writemem(atoi(argv[2]), strtoull(argv[3], NULL, 16), argv[4]);
    if (!strcmp(argv[1], "search") && argc == 5)
        return cmd_search(atoi(argv[2]), argv[3], argv[4]);
    if (!strcmp(argv[1], "maps") && argc == 3) return cmd_maps(atoi(argv[2]));
    usage();
    return 1;
}
