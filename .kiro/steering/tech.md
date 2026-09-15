# Technology Stack

## Language & Runtime

- **Go 1.22** — Bahasa utama untuk seluruh backend dan CLI.
- Module path: `github.com/gear/engine`.

## Core Libraries

- **`net/http`** — HTTP/HTTPS server (standard library).
- **`github.com/go-chi/chi/v5`** — Router dan middleware (RequestID, RealIP, Logger, Recoverer).
- **`modernc.org/sqlite`** — Driver SQLite pure-Go (tanpa CGO), untuk portabilitas single-binary.
- **`golang.org/x/crypto`** — Primitives kriptografi (password hashing).
- **`golang.org/x/term`** — Membaca password dari terminal tanpa echo saat `gear init`.
- **`github.com/leanovate/gopter`** — Property-based testing.

## Cryptography

- **AES-256-GCM** untuk envelope encryption (via `crypto/aes` + `crypto/cipher`).
- **`crypto/rand`** untuk semua nilai acak: Master Key, DEK, Nonce (12-byte), token, password generate.
- **Envelope encryption**: DEK unik per-secret mengenkripsi value; Master Key mengenkripsi DEK.
- **SHA-256** untuk hashing access token (hex-encoded).
- **bcrypt / argon2id** untuk hashing password admin.
- Kunci AES harus tepat **32 byte**; fungsi crypto memvalidasi panjang kunci.

## Storage

- **SQLite** file-based (mode WAL, `foreign_keys = ON`).
- Skema diinisialisasi via migration SQL (`internal/database/migrations/`).
- Timestamp disimpan sebagai Unix integer.
- Tabel: `admins`, `secrets`, `tokens`, `policies`, `audit_log`.

## Security Constraints

- **TLS wajib** — Server tidak berjalan tanpa cert & key valid (`GEAR_TLS_CERT`, `GEAR_TLS_KEY`).
- **`master.key` harus `chmod 600`** — Server fatal-exit jika permission tidak tepat 0600.
- **Tidak ada plaintext di storage** — DEK dan secret selalu tersimpan dalam bentuk terenkripsi.
- **Fail closed** — Kegagalan policy/auth menolak akses.
- HTTP plain hanya untuk redirect ke HTTPS.

## Configuration

Konfigurasi dimuat dari environment variables (lihat `internal/config/config.go`):

| Env Var | Default | Keterangan |
|---|---|---|
| `GEAR_DB_PATH` | `./gear.db` | Path file database SQLite |
| `GEAR_MASTER_KEY_PATH` | `./master.key` | Path file Master Key |
| `GEAR_TLS_CERT` | *(required)* | Path TLS certificate |
| `GEAR_TLS_KEY` | *(required)* | Path TLS private key |
| `GEAR_LISTEN_ADDR` | `:8443` | Alamat listener HTTPS |
| `GEAR_HTTP_ADDR` | `:8080` | Alamat listener HTTP (redirect-only) |
| `GEAR_CORS_ORIGIN` | *(kosong)* | Daftar origin CORS (comma-separated) |
| `GEAR_RATE_LIMIT_MAX` | `10` | Maks percobaan login per window per IP |
| `GEAR_RATE_LIMIT_WINDOW` | `5m` | Durasi sliding window rate limit |
| `GEAR_SESSION_TTL` | `12h` | TTL default untuk session token admin |

## Build & Development Commands

Gunakan `Makefile` di root project:

```bash
make build       # Compile binary ke bin/gear
make test        # Jalankan semua test (go test -count=1 ./...)
make test-race   # Jalankan test dengan race detector
make lint        # golangci-lint jika tersedia, fallback ke go vet
make clean       # Hapus artifact build
```

## Testing Conventions

- Unit test: `*_test.go` di package yang sama.
- Property-based test: `*_pbt_test.go` menggunakan `gopter`.
- Integration test: `*_integration_test.go` (mis. TLS, audit middleware).
- Selalu jalankan `make test` (atau `make test-race` untuk kode konkuren) sebelum menyelesaikan perubahan.

## Constraints (Environment)

- Mesin dengan RAM terbatas — hindari command shell paralel dan proses berlebih.
- Utamakan tool baca/tulis file daripada perintah shell untuk operasi file.
