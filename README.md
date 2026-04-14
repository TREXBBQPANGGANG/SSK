# 🔐 SEED Labs 2.0 — Hands-On Security Reports

> **Laporan Praktikum Keamanan Sistem & Jaringan**
> SEED Labs pada Ubuntu 20.04 (Docker/UTM — Apple Silicon)

---

## 👤 Informasi Mahasiswa

| Field | Detail |
|---|---|
| **Nama** | Muhammad Tamim Nugraha |
| **NRP** | 5024231060 |
| **Institusi** | Institut Teknologi Sepuluh Nopember (ITS) |
| **Program Studi** | Teknik Komputer 2023 |
| **Lingkungan Lab** | SEED Ubuntu 20.04 (Docker/UTM on Apple Silicon) |
| **Referensi Utama** | [SEED Labs 2.0 — Hands on Security](https://www.handsonsecurity.net/resources.html) |

---

## 📊 Status Laporan

| Kode | Topik | File | Status |
|---|---|---|---|
| R1 | Software Security Attack | [r1-software-attack.md](r1-software-attack.md) | ✅ Selesai |
| R2 | Buffer Overflow & Shellcode | [r2-buffer-overflow.md](r2-buffer-overflow.md) | ✅ Selesai |
| R3 | OS-Level Attacks | [r3-os-attacks.md](r3-os-attacks.md) | ✅ Selesai |
| R4 | Web Security Attacks | [r4-web-attacks.md](r4-web-attacks.md) | ✅ Selesai |
| R5 | Network Security | r5-network-security.md | ⏳ Proses |
| R6 | Firewall & IDS | r6-firewall-ids.md | ⏳ Proses |
| R7 | Kriptografi | r7-kriptografi.md | ⏳ Proses |

---

## 🗂️ Struktur Repositori

```
proyek-final/
├── README.md                    # Dokumen utama (file ini)
├── r1-software-attack.md        # Set-UID, Env Variables, Format String
├── r2-buffer-overflow.md        # Stack Overflow & Shellcode
├── r3-os-attacks.md             # Race Condition, Dirty COW, Shellshock
├── r4-web-attacks.md            # SQLi, XSS, CSRF, Clickjacking
├── r5-network-security.md       # (Akan datang)
├── r6-firewall-ids.md           # (Akan datang)
├── r7-kriptografi.md            # (Akan datang)
└── images/                      # Screenshot bukti eksploitasi
```

---

## 🛠️ Persiapan Lingkungan

### Prasyarat

```bash
# Clone SEED Labs environment (Docker-based)
git clone https://github.com/seed-labs/seed-labs.git
cd seed-labs

# Pastikan Docker sudah terinstal dan berjalan
docker --version
docker-compose --version

# Untuk UTM pada Apple Silicon — gunakan image Ubuntu 20.04 ARM
# atau jalankan melalui Rosetta emulation
```

### Konfigurasi Keamanan untuk Lab

```bash
# Nonaktifkan ASLR (Address Space Layout Randomization)
sudo sysctl -w kernel.randomize_va_space=0

# Verifikasi
cat /proc/sys/kernel/randomize_va_space
# Output yang diharapkan: 0
```

---

## 📚 Referensi

1. Du, W. (2019). *Computer & Internet Security: A Hands-on Approach (2nd Edition)*. ISBN: 978-1733003926.
2. SEED Labs Official: [https://seedsecuritylabs.org/](https://seedsecuritylabs.org/)
3. SEED Labs Resources: [https://www.handsonsecurity.net/resources.html](https://www.handsonsecurity.net/resources.html)
4. CVE Database: [https://cve.mitre.org/](https://cve.mitre.org/)

---

## ⚖️ Disclaimer

> Seluruh eksperimen dalam repositori ini dilakukan **hanya untuk tujuan edukasi** di dalam lingkungan lab terisolasi (SEED Labs VM/Docker). Penggunaan teknik-teknik yang dibahas di luar konteks edukasi adalah **ilegal dan tidak etis**. Penulis dan institusi tidak bertanggung jawab atas penyalahgunaan materi ini.

---

<p align="center">
  <strong>Muhammad Tamim Nugraha</strong> — 5024231060<br>
  Teknik Komputer 2023 · Institut Teknologi Sepuluh Nopember
</p>
