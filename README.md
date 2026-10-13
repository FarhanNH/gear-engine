# Gear

Gear adalah tool manajemen secret sederhana yang terinspirasi dari HashiCorp Vault. Gear menyimpan secret (password, API key, token, sertifikat) secara terenkripsi kuat menggunakan **envelope encryption** (AES-256-GCM), dengan kontrol akses berbasis token, policy per-path, dan audit log. Dikemas sebagai single binary Go dengan storage SQLite.

## Fitur

- **Envelope Encryption** — DEK unik per-secret (AES-256-GCM); DEK dienkripsi oleh Master Key. Plaintext tidak pernah tersimpan.
- **Inisialisasi atomik** — `gear init` menyiapkan Master Key (`chmod 600`) dan akun admin dalam satu langkah konsisten.
- **Autentikasi token** — Token di-generate via `crypto/rand`, disimpan sebagai hash SHA-256, mendukung expiry (TTL) dan revocation.
- **Policy per-path** — Izin `read` / `write` / `delete` granular per pola path, mendukung wildcard (`app/*`).
- **Audit log** — Append-only, mencatat token, path, aksi, hasil, IP, dan timestamp; dapat difilter dan dipaginasi.
- **HTTPS wajib** — TLS diwajibkan; request HTTP di-redirect ke HTTPS.
- **Rate limiting** — Perlindungan brute-force pada endpoint login.

## Persyaratan

- Go 1.22+
- Sertifikat & private key TLS (untuk menjalankan server)
- **uv** (Python package manager) — untuk graphify

## Graphify — Knowledge Graph

Project ini menggunakan [graphify](https://github.com/Graphify-Labs/graphify) untuk membangun knowledge graph kodebase, sehingga AI coding assistant dapat memahami struktur project lebih efisien.

### Install graphify (sekali per mesin)

```bash
# Install uv (jika belum ada)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install graphify CLI
uv tool install graphifyy

# Register skill ke AI assistant
graphify install
```

### Update graphify-out (setiap ada perubahan kode)

```bash
graphify . --code-only
```

Output tersimpan di `graphify-out/` (sudah di-ignore oleh git). Jalankan ulang perintah ini setiap kali ada perubahan signifikan pada kode agar knowledge graph tetap akurat.

## Build

```bash
make build      # menghasilkan bin/gear
```

## Quick Start

### 1. Inisialisasi sistem

```bash
./bin/gear init
```

Perintah ini akan:
- Meng-generate Master Key dan menyimpannya ke `./master.key` (permission `0600`).
- Membuat akun admin (meminta password dari terminal; jika kosong, password acak akan di-generate dan ditampilkan sekali).

> **PERINGATAN:** Kehilangan `master.key` membuat SELURUH secret tidak dapat dipulihkan. Simpan dengan aman.

### 2. Jalankan server

Set variabel environment TLS yang wajib, lalu jalankan:

```bash
export GEAR_TLS_CERT=/path/to/cert.pem
export GEAR_TLS_KEY=/path/to/key.pem
./bin/gear serve
```

Server HTTPS default mendengarkan di `:8443`, dan HTTP redirect di `:8080`.

## Konfigurasi

Konfigurasi dibaca dari environment variables:

| Env Var | Default | Keterangan |
|---|---|---|
| `GEAR_DB_PATH` | `./gear.db` | Path file database SQLite |
| `GEAR_MASTER_KEY_PATH` | `./master.key` | Path file Master Key |
| `GEAR_TLS_CERT` | *(wajib)* | Path TLS certificate |
| `GEAR_TLS_KEY` | *(wajib)* | Path TLS private key |
| `GEAR_LISTEN_ADDR` | `:8443` | Alamat listener HTTPS |
| `GEAR_HTTP_ADDR` | `:8080` | Alamat listener HTTP (redirect-only) |
| `GEAR_CORS_ORIGIN` | *(kosong)* | Daftar origin CORS (comma-separated) |
| `GEAR_RATE_LIMIT_MAX` | `10` | Maks percobaan login per window per IP |
| `GEAR_RATE_LIMIT_WINDOW` | `5m` | Durasi sliding window rate limit |
| `GEAR_SESSION_TTL` | `12h` | TTL default session token admin |

## API

Semua endpoint berada di bawah prefix `/v1`. Kecuali login, semua endpoint memerlukan autentikasi via header `Authorization`. Response error selalu berbentuk `{"error": "<message>"}`.

### Auth

| Method | Path | Keterangan |
|---|---|---|
| `POST` | `/v1/auth/login` | Login admin (rate-limited) |
| `POST` | `/v1/auth/logout` | Logout (butuh auth) |

### Secret

| Method | Path | Keterangan |
|---|---|---|
| `PUT` | `/v1/secret/{path}` | Simpan secret. Body: `{"value": "..."}`. Response `204` |
| `GET` | `/v1/secret/{path}` | Ambil secret. Response `{"path": "...", "value": "..."}` |
| `DELETE` | `/v1/secret/{path}` | Hapus secret. Response `204` |
| `GET` | `/v1/list/{prefix}` | List path secret di bawah prefix. Response `{"paths": [...]}` |

### Token

| Method | Path | Keterangan |
|---|---|---|
| `POST` | `/v1/token` | Buat access token |
| `GET` | `/v1/token` | List token |
| `DELETE` | `/v1/token/{id}` | Revoke token |

### Policy

| Method | Path | Keterangan |
|---|---|---|
| `POST` | `/v1/policy` | Buat policy |
| `GET` | `/v1/policy` | List policy |
| `DELETE` | `/v1/policy/{id}` | Hapus policy |

### Audit

| Method | Path | Keterangan |
|---|---|---|
| `GET` | `/v1/audit` | Ambil audit log (filter & paginasi) |

Mapping HTTP method → action policy: `GET` → `read`, `PUT` → `write`, `DELETE` → `delete`.

## Arsitektur

```
main → cli → server (router + middleware) → handler → service → database
                                                          ↓
                                                    crypto / model / validate
```

| Direktori | Tanggung jawab |
|---|---|
| `cmd/gear` | Entry point & dispatch subcommand |
| `internal/cli` | Implementasi `init` dan `serve` |
| `internal/config` | Loading & validasi konfigurasi env |
| `internal/crypto` | AES-256-GCM, keygen, password hashing |
| `internal/database` | Koneksi SQLite + migrations |
| `internal/handler` | HTTP handler per-domain |
| `internal/middleware` | Auth, audit, CORS, rate limit, TLS |
| `internal/model` | Struct domain |
| `internal/server` | Setup router chi & graceful shutdown |
| `internal/service` | Business logic inti |
| `internal/validate` | Validasi path secret |

## Keamanan

- **Envelope encryption** memastikan inspeksi langsung file SQLite tidak memperlihatkan secret plaintext.
- **`master.key` harus `chmod 600`** — server berhenti fatal jika permission tidak tepat.
- **TLS wajib** dengan konfigurasi yang di-harden.
- **Fail closed** — kegagalan evaluasi policy atau autentikasi menolak akses.
- Token disimpan sebagai hash SHA-256; password admin di-hash (bcrypt/argon2id).

## Development

```bash
make build       # Compile binary ke bin/gear
make test        # Jalankan semua test
make test-race   # Jalankan test dengan race detector
make lint        # Lint (golangci-lint / go vet)
make clean       # Hapus artifact build
```

Konvensi test:
- `*_test.go` — unit test
- `*_pbt_test.go` — property-based test (gopter)
- `*_integration_test.go` — integration test

## Status

Fase 1 (MVP): TLS wajib, autentikasi token, CRUD secret via REST API. Kolom `version` pada tabel secret sudah disiapkan untuk versioning di masa depan.
