# Project Structure

## Layout Direktori

```
gear-engine/
├── Makefile                      # Build, test, lint, clean
├── go.mod / go.sum               # Module: github.com/gear/engine
├── cmd/
│   └── gear/
│       └── main.go               # Entry point; dispatch subcommand (init, serve)
└── internal/                     # Kode privat aplikasi (tidak diekspor sebagai library)
    ├── cli/                      # Implementasi subcommand CLI (RunInit, RunServe)
    ├── config/                   # Loading & validasi konfigurasi dari env
    ├── crypto/                   # AES-256-GCM, keygen, password hash, utils
    ├── database/                 # Koneksi SQLite + migrations/
    │   └── migrations/           # File SQL skema (001_init.sql, ...)
    ├── handler/                  # HTTP handler per-domain (auth, secret, token, policy, audit)
    ├── middleware/               # Middleware: auth, audit, cors, ratelimit, tls
    ├── model/                    # Struct domain (Secret, Token, Policy, AuditEntry, Admin)
    ├── server/                   # Setup server, routing chi, graceful shutdown
    ├── service/                  # Business logic per-domain (secret, token, policy, audit)
    └── validate/                 # Validasi path secret (traversal, karakter, panjang)
```

## Arsitektur Layer

Aliran request mengikuti layering yang tegas:

```
main → cli → server (router + middleware) → handler → service → database
                                                          ↓
                                                    crypto / model / validate
```

- **cmd/gear** — Hanya parsing argumen dan dispatch ke `internal/cli`.
- **cli** — Orkestrasi command level tinggi (`init`, `serve`).
- **server** — Membangun `chi.Router`, memasang middleware stack, wiring service & handler, menjalankan HTTPS + graceful shutdown.
- **handler** — Decode request, panggil service, encode response JSON. Tidak berisi business logic berat.
- **service** — Business logic inti (envelope encryption, evaluasi policy, audit). Berinteraksi dengan `*sql.DB`.
- **middleware** — Concern lintas-request: autentikasi, audit, CORS, rate limit, TLS redirect/config.
- **model** — Struct data murni tanpa logic.
- **crypto / validate** — Utility murni, mudah dites secara terisolasi.

## Konvensi Penamaan

- **Package**: huruf kecil, satu kata, sesuai nama direktori (`handler`, `service`, `crypto`).
- **File**: snake/lowercase per-domain (`secret.go`, `token.go`, `policy.go`, `audit.go`).
- **Test**:
  - `*_test.go` — unit test.
  - `*_pbt_test.go` — property-based test (gopter).
  - `*_integration_test.go` — integration test.
- **Konstruktor**: `New<Nama>` (mis. `NewSecretService`, `NewAuthHandler`).
- **Env var**: prefix `GEAR_` uppercase (mis. `GEAR_DB_PATH`).
- **Interface service**: `<Domain>Service` (mis. `SecretService`, `TokenService`).

## Import Patterns

- Import internal selalu dengan path penuh module: `github.com/gear/engine/internal/<pkg>`.
- Package `crypto` internal diberi alias `gearCrypto` saat mengimpor untuk menghindari bentrok dengan stdlib `crypto` (lihat `internal/cli/init.go`).
- Alias chi middleware sebagai `chimiddleware` untuk membedakan dari `internal/middleware`.
- Urutan import: stdlib → third-party → internal (dipisah baris kosong).

## Konvensi Routing (chi)

Semua route API di bawah prefix `/v1`. Middleware stack (luar → dalam):

1. `RequestID` → `RealIP` → `TLSRedirect` → `CORS` → `Logger` → `Recoverer` (global)
2. `AuditMiddleware` (semua `/v1/*`)
3. Per-route: `RateLimit` (login), `PathValidation` (secret/list), `Auth`, `Policy`.

Mapping HTTP method → action policy: `GET`→`read`, `PUT`→`write`, `DELETE`→`delete`.

## Prinsip

- Semua kode aplikasi berada di `internal/` agar tidak menjadi API publik.
- Business logic tinggal di `service`, bukan di `handler`.
- Struct domain tinggal di `model`, bebas dependensi.
- Error dibungkus dengan konteks menggunakan `fmt.Errorf("...: %w", err)`.
- Response error HTTP selalu JSON: `{"error": "<message>"}`.
