# Product Overview

## Purpose

Gear adalah tool manajemen secret sederhana yang terinspirasi dari HashiCorp Vault. Gear menyimpan secret (password, API key, token, sertifikat) secara terenkripsi kuat sehingga isi database tidak dapat dibaca tanpa Master Key. Fokus produk adalah keamanan yang benar secara default (secure by default), kemudahan deployment (single binary), dan kesederhanaan operasional.

## Target Users

- **Admin / Operator infrastruktur** yang perlu menyimpan dan mendistribusikan secret aplikasi secara aman.
- **Aplikasi / service** yang mengambil secret melalui REST API menggunakan access token.
- **Tim kecil** yang menginginkan manajemen secret ringan tanpa kompleksitas Vault penuh.

## Key Features

- **Envelope Encryption** — Setiap secret dienkripsi dengan DEK unik (AES-256-GCM), dan DEK dienkripsi oleh Master Key. Plaintext tidak pernah disimpan ke storage.
- **Inisialisasi atomik (`gear init`)** — Generate Master Key (`chmod 600`) dan akun admin dalam satu operasi yang konsisten (all-or-nothing).
- **Autentikasi berbasis token** — Access token di-generate via `crypto/rand`, disimpan sebagai hash SHA-256, mendukung TTL/expiry dan revocation.
- **Policy per-path** — Kontrol akses granular (read/write/delete) terhadap pola path secret, dengan dukungan wildcard (`app/*`).
- **Audit log append-only** — Setiap percobaan akses dicatat (token, path, aksi, hasil, IP, timestamp) dan dapat difilter/paginasi.
- **HTTPS wajib** — Server mengharuskan TLS; request HTTP di-redirect ke HTTPS.
- **Rate limiting** — Perlindungan brute-force pada endpoint login.

## Business Objectives

- Menyediakan penyimpanan secret yang aman dengan friksi operasional minimal.
- Menjamin secret tidak dapat dipulihkan dari inspeksi langsung file database.
- Menegakkan least-privilege melalui token + policy per-path.
- Menyediakan jejak audit yang lengkap untuk kebutuhan compliance dan investigasi.

## Design Principles

- **Secure by default** — TLS wajib, permission `master.key` diverifikasi ketat (0600), tidak ada penyimpanan plaintext.
- **Fail closed** — Kegagalan evaluasi policy atau autentikasi menolak akses, bukan mengizinkannya.
- **Kesederhanaan** — Single binary, SQLite sebagai storage, tanpa dependensi eksternal berat.
