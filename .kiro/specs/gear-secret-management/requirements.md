# Requirements Document

## Introduction

Gear adalah tool manajemen secret sederhana yang terinspirasi dari HashiCorp Vault. Gear menyediakan penyimpanan secret terenkripsi dengan AES-256-GCM (envelope encryption), kontrol akses berbasis token, policy per-path, dan audit log. Stack teknis: Go backend (`net/http`, SQLite), Vue web UI, single binary deployment. Fase 1 berfokus pada MVP lokal dengan TLS wajib, autentikasi token, dan CRUD secret melalui REST API dan Web UI dasar.

## Glossary

- **Gear**: Nama produk/codename untuk tool secret management ini.
- **Secret**: Nilai sensitif (password, API key, token, sertifikat) yang disimpan dalam sistem.
- **Path**: Identifier hierarkis untuk secret, mirip filesystem (contoh: `app/db/password`).
- **Master_Key**: Kunci enkripsi utama yang meng-enkripsi DEK; disimpan terpisah dari database sebagai file dengan permission `chmod 600`.
- **DEK**: Data Encryption Key — kunci enkripsi per-secret yang di-generate secara acak menggunakan `crypto/rand` dan dienkripsi oleh Master Key sebelum disimpan di database.
- **Token**: String acak berkecukupan entropi (di-generate via `crypto/rand`) yang digunakan sebagai kredensial akses API; disimpan sebagai hash SHA-256 di database.
- **Policy**: Aturan yang mendefinisikan izin akses (read, write, delete) untuk token pada pola path tertentu.
- **Audit_Log**: Catatan setiap percobaan akses yang mencakup token, path, aksi, timestamp, dan hasil (sukses/gagal).
- **Admin**: Satu-satunya akun pengguna di Fase 1 yang memiliki akses penuh ke semua fitur.
- **Backend**: Komponen Go yang menjalankan logika API, autentikasi, enkripsi, dan akses data.
- **Web_UI**: Dashboard Vue untuk mengelola secret, token, policy, dan melihat audit log.
- **CLI**: Antarmuka baris perintah untuk perintah `gear init`.
- **TTL**: Time To Live — durasi validitas token sebelum kadaluarsa.
- **Nonce**: Nilai acak yang digunakan satu kali per operasi AES-GCM, di-generate via `crypto/rand`.
- **Envelope_Encryption**: Pola enkripsi di mana DEK mengenkripsi data dan Master Key mengenkripsi DEK.
- **SQLite**: Database file-based tempat menyimpan secret terenkripsi, DEK terenkripsi, token (hash), policy, dan audit log.

---

## Requirements

### Requirement 1: Inisialisasi Sistem (gear init)

**User Story:** Sebagai admin, saya ingin menjalankan satu perintah inisialisasi sehingga sistem siap digunakan dengan Master Key dan akun admin yang telah dibuat sekaligus tanpa state yang tidak konsisten.

#### Acceptance Criteria

1. WHEN `gear init` dijalankan pada sistem yang belum diinisialisasi, THE CLI SHALL generate Master Key baru menggunakan `crypto/rand` dan menyimpannya ke file lokal dengan permission `chmod 600`.
2. WHEN `gear init` dijalankan, THE CLI SHALL membuat akun admin pertama secara interaktif — meminta password dari terminal tanpa memunculkannya di layar (tidak lewat argumen CLI).
3. WHEN admin tidak memasukkan password selama `gear init`, THE CLI SHALL generate password acak menggunakan `crypto/rand`, menampilkannya sekali di terminal, dan menyimpan hash password menggunakan bcrypt atau argon2 ke database.
4. WHEN `gear init` dijalankan pada sistem yang sudah diinisialisasi, THE CLI SHALL menolak eksekusi dan menampilkan pesan error yang jelas tanpa menimpa data yang sudah ada.
5. THE CLI SHALL menyelesaikan proses `gear init` secara atomik — Master Key dan akun admin keduanya berhasil dibuat, atau keduanya tidak dibuat (tidak ada state setengah jadi); sistem melaporkan sukses hanya ketika kedua komponen berhasil dibuat sepenuhnya.
6. WHEN `gear init` berhasil selesai, THE CLI SHALL menampilkan instruksi langkah selanjutnya kepada admin, termasuk peringatan untuk menyimpan password admin di tempat yang aman.

---

### Requirement 2: Penyimpanan Secret Terenkripsi (Envelope Encryption)

**User Story:** Sebagai admin, saya ingin secret disimpan dengan enkripsi yang kuat sehingga isi database tidak dapat dibaca tanpa Master Key.

#### Acceptance Criteria

1. WHEN secret baru disimpan, THE Backend SHALL generate DEK unik menggunakan `crypto/rand` untuk setiap secret.
2. WHEN secret disimpan, THE Backend SHALL mengenkripsi nilai secret menggunakan DEK dengan algoritma AES-256-GCM.
3. WHEN secret disimpan, THE Backend SHALL generate Nonce secara acak menggunakan `crypto/rand` untuk setiap operasi AES-GCM, dan Nonce tersebut tidak pernah digunakan ulang untuk kunci yang sama.
4. WHEN secret disimpan, THE Backend SHALL mengenkripsi DEK menggunakan Master Key dengan AES-256-GCM sebelum menyimpannya ke SQLite.
5. THE Backend SHALL menyimpan DEK terenkripsi berdampingan dengan ciphertext secret di SQLite — tidak pernah menyimpan DEK plaintext atau secret plaintext ke storage.
6. WHEN secret dibaca, THE Backend SHALL mendekripsi DEK menggunakan Master Key, kemudian mendekripsi secret menggunakan DEK yang sudah didekripsi.
7. THE Backend SHALL memastikan inspeksi langsung file SQLite tidak memperlihatkan secret dalam bentuk plaintext.
8. THE SQLite schema SHALL menyediakan kolom `version` pada tabel secret sejak awal untuk mengakomodasi versioning di masa depan tanpa migrasi struktural besar.

---

### Requirement 3: Autentikasi Admin

**User Story:** Sebagai admin, saya ingin login ke dashboard dan API dengan password sehingga hanya saya yang dapat mengelola sistem.

#### Acceptance Criteria

1. WHEN admin mengirimkan username dan password ke `POST /v1/auth/login`, THE Backend SHALL memverifikasi password menggunakan bcrypt atau argon2 terhadap hash yang tersimpan di database.
2. WHEN verifikasi password berhasil, THE Backend SHALL mengembalikan token sesi yang valid dengan TTL yang dikonfigurasi.
3. WHEN verifikasi password gagal, THE Backend SHALL mengembalikan HTTP 401 tanpa mengungkapkan informasi detail penyebab kegagalan dan tanpa men-generate token apapun.
4. WHEN endpoint `POST /v1/auth/login` menerima lebih dari jumlah percobaan yang dikonfigurasi dalam jendela waktu tertentu dari satu IP, THE Backend SHALL menolak permintaan berikutnya dengan HTTP 429 (rate limiting) hingga jendela waktu berakhir.
5. THE Backend SHALL tidak pernah mencatat atau mengembalikan password admin dalam bentuk plaintext di log, response body, atau error message.

---

### Requirement 4: Manajemen Token Akses

**User Story:** Sebagai admin, saya ingin membuat dan mencabut token akses sehingga aplikasi atau pipeline CI/CD dapat mengakses secret dengan kredensial yang dapat dikelola.

#### Acceptance Criteria

1. WHEN admin membuat token baru via `POST /v1/token`, THE Backend SHALL generate token string berkecukupan entropi menggunakan `crypto/rand`.
2. WHEN token dibuat, THE Backend SHALL menyimpan hash SHA-256 dari token ke database — bukan nilai token plaintext.
3. WHEN token dibuat, THE Backend SHALL mengembalikan nilai token plaintext kepada admin sekali saja pada saat pembuatan — token tidak dapat diambil kembali setelah itu.
4. WHEN token dibuat, THE Backend SHALL menyimpan TTL yang dikonfigurasi dan menandai token sebagai kadaluarsa secara otomatis setelah TTL berakhir.
5. WHEN admin merevoke token via `DELETE /v1/token/{id}`, THE Backend SHALL segera menandai token sebagai tidak valid sehingga token tersebut tidak dapat digunakan untuk request berikutnya.
6. WHEN sebuah request menggunakan token yang sudah kadaluarsa, dicabut, tidak ada, atau berformat tidak valid, THE Backend SHALL menolak request dengan HTTP 401.
7. THE Backend SHALL mendukung pembuatan multiple token (lebih dari satu token aktif secara bersamaan) untuk memungkinkan penggunaan berbeda per aplikasi atau pipeline.

---

### Requirement 5: Policy Akses Per-Path

**User Story:** Sebagai admin, saya ingin mengatur izin akses per-path untuk setiap token sehingga prinsip least-privilege dapat diterapkan.

#### Acceptance Criteria

1. WHEN admin membuat policy, THE Backend SHALL memungkinkan penetapan izin `read`, `write`, dan/atau `delete` untuk pola path tertentu pada token tertentu.
2. WHEN token melakukan request terhadap path, THE Backend SHALL mengevaluasi policy yang melekat pada token tersebut sebelum memproses request.
3. WHEN token tidak memiliki izin yang diperlukan untuk aksi yang diminta pada path yang diminta, THE Backend SHALL menolak request dengan HTTP 403.
4. WHEN token memiliki izin yang diperlukan, THE Backend SHALL memproses request dan melanjutkan ke logika bisnis.
5. THE Backend SHALL mendukung wildcard pada pola path dalam policy (contoh: `app/*` mencakup semua path di bawah `app/`).
6. WHEN path secret mengandung karakter yang berpotensi menyebabkan path traversal, THE Backend SHALL selalu menolak request dengan HTTP 400 dan memastikan validasi input ketat dijalankan sebagai bagian dari proses penolakan tersebut.

---

### Requirement 6: CRUD Secret via REST API

**User Story:** Sebagai aplikasi atau pipeline CI/CD, saya ingin membaca, menulis, dan menghapus secret via REST API sehingga secret dapat diintegrasikan ke workflow otomatis.

#### Acceptance Criteria

1. WHEN request `PUT /v1/secret/{path}` diterima dengan token valid dan izin write, THE Backend SHALL menyimpan atau memperbarui secret di path yang ditentukan menggunakan envelope encryption (upsert — create dan update memakai endpoint yang sama).
2. WHEN request `GET /v1/secret/{path}` diterima dengan token valid dan izin read, THE Backend SHALL mendekripsi dan mengembalikan nilai secret di path yang ditentukan.
3. WHEN request `DELETE /v1/secret/{path}` diterima dengan token valid dan izin delete, THE Backend SHALL menghapus secret beserta DEK-nya dari database.
4. WHEN request `GET /v1/list/{prefix}` diterima dengan token valid dan izin read, THE Backend SHALL mengembalikan daftar path secret di bawah prefix yang ditentukan tanpa mendekripsi nilainya, atau mengembalikan HTTP 404 jika tidak ada secret di bawah prefix tersebut.
5. WHEN path yang diminta tidak ditemukan untuk operasi read atau delete, THE Backend SHALL mengembalikan HTTP 404.
6. WHEN request masuk tanpa token atau dengan token yang tidak valid, THE Backend SHALL mengembalikan HTTP 401 untuk semua endpoint `/v1/secret/*` dan `/v1/list/*`.

---

### Requirement 7: Audit Log

**User Story:** Sebagai admin, saya ingin melihat riwayat semua percobaan akses secret sehingga saya dapat mendeteksi akses yang tidak sah atau mencurigakan.

#### Acceptance Criteria

1. WHEN setiap request ke endpoint secret diproses (berhasil maupun gagal), THE Backend SHALL mencatat entri ke Audit_Log yang berisi: token identifier, path yang diakses, aksi yang dilakukan, timestamp, dan hasil (sukses atau gagal dengan kode error).
2. THE Backend SHALL tidak pernah mencatat nilai secret dalam plaintext di Audit_Log, termasuk tidak mencatat nilai secret atau credential apapun saat terjadi kegagalan autentikasi.
3. WHEN admin mengakses `GET /v1/audit`, THE Backend SHALL mengembalikan daftar entri Audit_Log yang dapat difilter berdasarkan token, path, rentang waktu, atau hasil.
4. THE Backend SHALL mencatat 100% percobaan akses — tidak ada request yang lolos tanpa dicatat, termasuk request yang ditolak karena autentikasi atau otorisasi gagal.
5. WHEN pencatatan Audit_Log gagal untuk suatu request ke endpoint secret, THE Backend SHALL menolak request tersebut untuk memastikan tidak ada akses yang berlangsung tanpa tercatat.
6. WHEN percobaan autentikasi gagal di `POST /v1/auth/login`, THE Backend SHALL mencatat entri ke Audit_Log tanpa menyertakan password yang dimasukkan.

---

### Requirement 8: Web UI Dasar (Vue)

**User Story:** Sebagai admin, saya ingin mengelola secret, token, dan policy melalui antarmuka web sehingga saya tidak harus menggunakan raw API calls untuk operasi sehari-hari.

#### Acceptance Criteria

1. WHEN admin mengakses halaman login Web_UI dan memasukkan kredensial yang valid, THE Web_UI SHALL mengautentikasi admin dan menampilkan dashboard utama.
2. WHEN admin berhasil login, THE Web_UI SHALL menyimpan token sesi dan menyertakannya di setiap request API berikutnya.
3. WHEN admin membuka halaman browse secrets, THE Web_UI SHALL menampilkan daftar path secret secara hierarkis menggunakan `GET /v1/list/{prefix}`.
4. WHEN admin membuka detail secret, THE Web_UI SHALL menampilkan nilai secret yang sudah didekripsi menggunakan `GET /v1/secret/{path}`.
5. WHEN admin membuat, memperbarui, atau menghapus secret melalui form Web_UI, THE Web_UI SHALL memanggil endpoint API yang sesuai dan menampilkan feedback hasil operasi.
6. WHEN admin membuka halaman manajemen token, THE Web_UI SHALL menampilkan daftar token aktif dan memungkinkan pembuatan token baru serta revokasi token yang ada.
7. WHEN token sesi admin kadaluarsa, THE Web_UI SHALL mengarahkan admin kembali ke halaman login secara langsung — bahkan saat admin sedang idle tanpa melakukan aksi apapun.
8. WHEN admin membuka halaman audit log, THE Web_UI SHALL menampilkan tabel riwayat akses dengan kemampuan filter.

---

### Requirement 9: Keamanan Transport (TLS)

**User Story:** Sebagai admin, saya ingin semua komunikasi antara client dan backend dilindungi TLS sehingga data dalam transit tidak dapat disadap.

#### Acceptance Criteria

1. THE Backend SHALL menolak semua koneksi HTTP non-TLS dan hanya menerima koneksi HTTPS.
2. WHEN Backend dikonfigurasi tanpa sertifikat TLS yang valid, THE Backend SHALL tidak dapat dimulai dan menampilkan pesan error yang jelas.
3. WHERE sertifikat TLS yang digunakan adalah self-signed (untuk lingkungan development), THE Backend SHALL berfungsi normal dengan konfigurasi yang sesuai.
4. THE Web_UI SHALL menggunakan HTTPS untuk semua request API ke Backend.

---

### Requirement 10: Validasi Input & Keamanan Path

**User Story:** Sebagai admin, saya ingin sistem memvalidasi semua input sehingga serangan path traversal dan injeksi tidak dapat dilakukan.

#### Acceptance Criteria

1. WHEN path secret yang diterima mengandung komponen `..`, `/./`, karakter null, atau pola traversal lainnya, THE Backend SHALL menolak request dengan HTTP 400 dan mencatat percobaan pelanggaran keamanan tersebut beserta detailnya ke Audit_Log untuk keperluan monitoring.
2. WHEN path secret yang diterima mengandung karakter yang tidak diizinkan (selain huruf, angka, `/`, `-`, `_`, `.`), THE Backend SHALL menolak request dengan HTTP 400.
3. THE Backend SHALL memvalidasi panjang maksimum path secret sebelum memproses request.
4. WHEN request body mengandung field yang tidak diharapkan atau format yang salah, THE Backend SHALL menolak request dengan HTTP 400 dan pesan error deskriptif.

---
