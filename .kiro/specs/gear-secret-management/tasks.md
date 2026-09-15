# Implementation Plan: Gear Secret Management

## Overview

Implementasi dua project terpisah: `gear-engine` (Go backend) dan `gear-ui` (Vue 3 SPA). Implementasi dilakukan incremental — dimulai dari setup project, domain model, crypto layer, kemudian API dan UI. Setiap komponen divalidasi lewat unit test dan property-based test sebelum integrasi.

---

## Tasks

- [x] 1. Setup gear-engine — Go module, struktur direktori, Makefile
  - [x] 1.1 Inisialisasi Go module dan struktur direktori gear-engine
    - Buat `gear-engine/go.mod` dengan module path `github.com/gear/engine`
    - Buat semua direktori: `cmd/gear/`, `internal/cli/`, `internal/config/`, `internal/crypto/`, `internal/database/migrations/`, `internal/middleware/`, `internal/handler/`, `internal/service/`, `internal/model/`, `internal/validate/`, `internal/server/`
    - Buat `cmd/gear/main.go` sebagai entry point yang meng-route subcommand `init` dan `serve`
    - _Requirements: 1.1, 9.1_
  - [x] 1.2 Buat Makefile untuk gear-engine
    - Target: `build`, `test`, `test-race`, `lint`, `clean`
    - Target `test` menjalankan `go test ./...` dengan flag `-count=1`
    - _Requirements: 1.1_

- [x] 2. Setup gear-ui — Vite + Vue 3 + Pinia + vue-router
  - [x] 2.1 Inisialisasi project gear-ui dengan Vite + Vue 3 + TypeScript
    - Jalankan scaffolding Vite template `vue-ts` untuk `gear-ui/`
    - Install dependencies: `vue-router@4`, `pinia`, dan `@vueuse/core`
    - Buat struktur direktori: `src/views/`, `src/components/`, `src/api/`, `src/store/`, `src/router/`
    - Buat `.env.example` dengan isi `VITE_API_BASE_URL=https://localhost:8443`
    - Tambahkan `.env.local` ke `.gitignore`
    - _Requirements: 8.1, 8.2, 9.4_
  - [x] 2.2 Setup vite.config.ts dengan proxy dan environment variable
    - Konfigurasi `vite.config.ts` untuk membaca `VITE_API_BASE_URL`
    - Tambahkan tipe TypeScript untuk env vars di `env.d.ts` (atau `vite-env.d.ts`)
    - _Requirements: 8.2, 9.4_

- [x] 3. Database schema dan migrations
  - [x] 3.1 Buat file migrations 001_init.sql dengan 5 tabel
    - Tulis DDL untuk tabel: `admins`, `secrets`, `tokens`, `policies`, `audit_log`
    - Sertakan `PRAGMA journal_mode = WAL` dan `PRAGMA foreign_keys = ON`
    - Buat index: `idx_secrets_path`, `idx_tokens_hash`, `idx_policies_token`, `idx_audit_timestamp`, `idx_audit_token`, `idx_audit_path`
    - Kolom `secrets.version` harus ada sejak DDL awal
    - _Requirements: 2.5, 2.8_
  - [x] 3.2 Implementasi database/db.go — open, migrate, close
    - Tulis `internal/database/db.go` dengan fungsi `Open(path string) (*sql.DB, error)` yang membuka SQLite via `modernc.org/sqlite` dan menjalankan embedded migration SQL
    - Tambahkan dependency `modernc.org/sqlite` ke go.mod
    - Fungsi `Close(*sql.DB) error` untuk graceful shutdown
    - _Requirements: 2.5, 2.7_

- [x] 4. Model structs Go
  - [x] 4.1 Definisikan semua model struct di internal/model/model.go
    - Tulis struct: `Secret`, `Token`, `Policy`, `AuditEntry`, `AuditFilter`, `Admin`
    - Pastikan field sesuai dengan skema SQLite (termasuk pointer untuk nullable field)
    - _Requirements: 2.5, 4.2, 5.1, 7.1_

- [x] 5. Crypto module — AES-256-GCM, GenerateKey, GenerateToken, HashToken, password hashing
  - [x] 5.1 Implementasi internal/crypto/aes.go — AES-256-GCM encrypt/decrypt
    - Fungsi `Encrypt(plaintext, key []byte) (ciphertext, nonce []byte, err error)`
    - Fungsi `Decrypt(ciphertext, nonce, key []byte) ([]byte, error)`
    - Fungsi `GenerateKey() ([]byte, error)` — 32 bytes via `crypto/rand`
    - Key harus tepat 32 bytes; return error jika tidak
    - _Requirements: 2.1, 2.2, 2.3, 2.4_
  - [x] 5.2 Implementasi internal/crypto/keygen.go — token generation dan hashing
    - Fungsi `GenerateToken() (string, error)` — 32 bytes entropy, hex-encoded (64 chars)
    - Fungsi `HashToken(plaintext string) string` — SHA-256 hex string
    - _Requirements: 4.1, 4.2_
  - [x] 5.3 Implementasi internal/crypto/password.go — bcrypt/argon2 hash dan verify
    - Fungsi `HashPassword(password string) (string, error)` menggunakan bcrypt (cost ≥ 12) atau argon2id
    - Fungsi `VerifyPassword(hash, password string) error`
    - _Requirements: 1.2, 1.3, 3.1_
  - [x] 5.4 Tulis unit tests untuk crypto module
    - Test `Encrypt`/`Decrypt` round-trip, key size enforcement, nonce uniqueness
    - Test `GenerateToken` format (64 hex chars), `HashToken` deterministic
    - Test `HashPassword`/`VerifyPassword` round-trip dan rejection kasus salah
    - _Requirements: 2.1, 2.2, 2.3, 4.1, 4.2_
  - [x] 5.5 Tulis property-based test untuk crypto module (gopter, min 200 iterasi)
    - **Property 1: Encrypt-Decrypt Round Trip** — `∀ plaintext ∈ []byte, key ∈ []byte(32): Decrypt(Encrypt(plaintext, key)) == plaintext`
    - **Validates: Requirements 2.2, 2.6**
    - **Property 2: Nonce Uniqueness** — `∀ plaintext, key: nonce₁ ≠ nonce₂ untuk dua panggilan Encrypt berturut-turut`
    - **Validates: Requirements 2.3**
    - **Property 3: Ciphertext Berbeda dari Plaintext** — `∀ plaintext ≠ []: ciphertext ≠ plaintext`
    - **Validates: Requirements 2.2, 2.7**
    - **Property 4: Decrypt Gagal jika Ciphertext Dimodifikasi** — `∀ ciphertext: modifikasi satu byte menyebabkan error`
    - **Validates: Requirements 2.2, 2.6**
    - **Property 5: GenerateToken Selalu Menghasilkan 64 Karakter Hex** — `∀ panggilan: len(token) == 64 && isHex(token)`
    - **Validates: Requirements 4.1**
    - **Property 6: HashToken Deterministik** — `∀ input: HashToken(s) == HashToken(s)`
    - **Validates: Requirements 4.2**
    - Gunakan `gopter` dengan min 200 iterasi per property
    - _Requirements: 2.1-2.6, 4.1, 4.2_

- [x] 6. Path validation module
  - [x] 6.1 Implementasi internal/validate/path.go
    - Fungsi `ValidatePath(path string) error` dengan error sentinel: `ErrPathTooLong`, `ErrPathTraversal`, `ErrInvalidPathChars`
    - Regex allowed: `^[a-zA-Z0-9/_\-\.]+$`; max length 512 chars
    - Deteksi: `..`, `/./`, null byte (`\x00`), leading `/`
    - _Requirements: 5.6, 10.1, 10.2, 10.3_
  - [x] 6.2 Tulis unit tests untuk validate/path.go
    - Test accept: path valid dengan berbagai kombinasi karakter legal
    - Test reject: `..`, `/./`, null byte, leading `/`, karakter non-ASCII, panjang > 512
    - _Requirements: 10.1, 10.2, 10.3_
  - [x] 6.3 Tulis property-based test untuk path validation (gopter, min 200 iterasi)
    - **Property 7: Valid Path Selalu Diterima** — `∀ path ∈ [a-zA-Z0-9/_\-.]{1,512}: ValidatePath(path) == nil`
    - **Validates: Requirements 10.1, 10.2, 10.3**
    - **Property 8: Path dengan Traversal Selalu Ditolak** — `∀ path yang mengandung ".." atau "/./"`: `ValidatePath(path) == ErrPathTraversal`
    - **Validates: Requirements 10.1**
    - **Property 9: Path Terlalu Panjang Selalu Ditolak** — `∀ path dengan len > 512: ValidatePath(path) == ErrPathTooLong`
    - **Validates: Requirements 10.3**
    - _Requirements: 10.1, 10.2, 10.3_

- [x] 7. Service layer
  - [x] 7.1 Implementasi internal/service/secret.go — SecretService
    - Interface dan implementasi: `Put`, `Get`, `Delete`, `List`
    - `Put`: generate DEK, encrypt value, encrypt DEK dengan Master Key, upsert ke DB
    - `Get`: decrypt DEK dengan Master Key, decrypt value dengan DEK; zero-out DEK setelah pakai
    - `Delete`: hapus row + DEK dari DB
    - `List`: query paths dengan LIKE prefix%; return `[]string`
    - _Requirements: 2.1-2.7, 6.1-6.5_
  - [x] 7.2 Tulis unit tests untuk SecretService
    - Test Put-Get round trip, Delete, List dengan prefix
    - Test Get untuk path tidak ada (404), Delete path tidak ada
    - Mock DB dan crypto
    - _Requirements: 2.1-2.7, 6.1-6.5_
  - [x] 7.3 Tulis property-based test untuk SecretService (gopter, min 200 iterasi)
    - **Property 10: Put-Get Round Trip** — `∀ path valid, value: Get(path) == value setelah Put(path, value)`
    - **Validates: Requirements 2.6, 6.1, 6.2**
    - **Property 11: Delete Idempoten** — `∀ path: Delete setelah Delete mengembalikan 404`
    - **Validates: Requirements 6.3, 6.5**
    - **Property 12: List Prefix Konsisten** — `∀ prefix: semua path dalam hasil List memiliki prefix yang diminta`
    - **Validates: Requirements 6.4**
    - _Requirements: 2.1-2.7, 6.1-6.5_
  - [x] 7.4 Implementasi internal/service/token.go — TokenService
    - Interface dan implementasi: `Create`, `Revoke`, `Validate`, `List`
    - `Create`: generate token via `GenerateToken()`, hash dengan `HashToken()`, simpan ke DB dengan TTL
    - `Validate`: hash input, query DB, cek revoked dan expiry
    - `Revoke`: set `revoked=1` di DB
    - _Requirements: 4.1-4.7_
  - [x] 7.5 Tulis unit tests untuk TokenService
    - Test Create mengembalikan plaintext token dan ID
    - Test Validate token valid, expired, revoked, tidak ada
    - Test Revoke → Validate mengembalikan 401
    - _Requirements: 4.1-4.7_
  - [x] 7.6 Tulis property-based test untuk TokenService (gopter, min 200 iterasi)
    - **Property 13: Token yang Baru Dibuat Selalu Valid** — `∀ name, ttl > 0: Validate(Create(name, ttl).plaintext) == valid`
    - **Validates: Requirements 4.1, 4.2, 4.3**
    - **Property 14: Token yang Di-Revoke Selalu Invalid** — `∀ token: Validate setelah Revoke == error`
    - **Validates: Requirements 4.5, 4.6**
    - _Requirements: 4.1-4.7_
  - [x] 7.7 Implementasi internal/service/policy.go — PolicyService
    - Interface dan implementasi: `Create`, `Delete`, `Evaluate`
    - `Evaluate`: query policies untuk tokenID, match path terhadap pattern (support `*` wildcard di akhir), cek permission bit
    - _Requirements: 5.1-5.6_
  - [x] 7.8 Tulis unit tests untuk PolicyService
    - Test exact match, wildcard match `app/*`, no-match
    - Test `Evaluate` dengan berbagai kombinasi permission (read, write, delete)
    - _Requirements: 5.1-5.6_
  - [x] 7.9 Tulis property-based test untuk PolicyService (gopter, min 200 iterasi)
    - **Property 15: Policy Wildcard Konsisten** — `∀ prefix, path yang memiliki prefix: Evaluate dengan pattern "prefix/*" == allowed`
    - **Validates: Requirements 5.5**
    - **Property 16: Policy Tanpa Match Selalu Denied** — `∀ tokenID tanpa policy untuk path: Evaluate == false`
    - **Validates: Requirements 5.2, 5.3**
    - _Requirements: 5.1-5.6_
  - [x] 7.10 Implementasi internal/service/audit.go — AuditService
    - Interface dan implementasi: `Log`, `Query`
    - `Log`: INSERT ke audit_log; TIDAK mencatat nilai secret atau credential plaintext
    - `Query`: SELECT dengan filter berdasarkan `AuditFilter` (token_id, path, since, until, result, limit, offset)
    - _Requirements: 7.1-7.6_
  - [x] 7.11 Tulis unit tests untuk AuditService
    - Test Log menyimpan entry dengan benar
    - Test Query dengan berbagai kombinasi filter
    - Verifikasi nilai secret tidak tersimpan dalam entry
    - _Requirements: 7.1-7.4, 7.6_

- [x] 8. Middleware stack
  - [x] 8.1 Implementasi internal/middleware/auth.go — token authentication
    - Extract `Authorization: Bearer {token}` dari header
    - Hash token dengan SHA-256, query DB, cek revoked dan TTL
    - Set `tokenID` ke context request untuk dipakai downstream
    - Skip untuk `POST /v1/auth/login`
    - Return HTTP 401 jika token invalid/expired/revoked
    - _Requirements: 3.2, 4.6, 9.1_
  - [x] 8.2 Implementasi internal/middleware/audit.go — audit log middleware
    - Wrap `ResponseWriter` untuk intercept status code
    - Tulis pre-request log (access attempt) SEBELUM memanggil next handler
    - Jika pre-request `Log()` gagal → return HTTP 500, JANGAN teruskan ke handler
    - _Requirements: 7.1, 7.4, 7.5_
  - [x] 8.3 Implementasi internal/middleware/cors.go — CORS handler
    - Validasi `Origin` header terhadap whitelist dari `GEAR_CORS_ORIGIN`
    - Handle pre-flight `OPTIONS` request tanpa memanggil handler
    - Set CORS headers hanya untuk origin yang diizinkan
    - _Requirements: 8.2, 9.1_
  - [x] 8.4 Implementasi internal/middleware/ratelimit.go — IP-based sliding window
    - In-memory rate limiter per IP untuk `POST /v1/auth/login`
    - Default: max 10 attempts per 5 menit per IP (konfigurasi via env var)
    - Response 429 dengan header `Retry-After: {seconds}`
    - Baca `X-Forwarded-For` / `X-Real-IP` dengan validasi trusted proxy
    - _Requirements: 3.4_
  - [x] 8.5 Implementasi internal/middleware/tls.go — TLS enforcement
    - HTTP listener hanya untuk redirect 301 ke HTTPS
    - TLS config: `MinVersion TLS 1.2`, cipher suites yang kuat, curve preferences
    - Fatal log + `os.Exit(1)` jika sertifikat TLS tidak valid saat startup
    - _Requirements: 9.1, 9.2, 9.3_
  - [x] 8.6 Tulis unit tests untuk middleware
    - Test AuthMiddleware: valid token pass, invalid/expired/revoked token → 401
    - Test RateLimitMiddleware: exceed limit → 429, window reset
    - Test CORSMiddleware: allowed origin → headers set, disallowed origin → no headers
    - Test AuditMiddleware: audit fail → 500, tidak meneruskan ke handler
    - _Requirements: 3.4, 4.6, 7.5, 9.1_

- [x] 9. internal/config/config.go
  - [x] 9.1 Implementasi config.go — load dari environment variables
    - Struct `Config` dengan field: `DBPath`, `MasterKeyPath`, `TLSCert`, `TLSKey`, `ListenAddr`, `HTTPAddr`, `CORSOrigins []string`, `RateLimitMax`, `RateLimitWindow`, `SessionTTL`
    - Fungsi `Load() (*Config, error)` membaca env vars dengan nilai default
    - Validasi: `GEAR_TLS_CERT` dan `GEAR_TLS_KEY` wajib ada; error jika kosong
    - _Requirements: 9.1, 9.2_

- [x] 10. gear init CLI — atomik: Master Key + admin
  - [x] 10.1 Implementasi internal/cli/init.go — perintah gear init
    - Cek apakah sistem sudah diinisialisasi (DB sudah ada, tabel admins sudah ada row) → tolak dengan error jelas
    - Generate Master Key (32 bytes, `crypto/rand`), tulis ke `master.key.tmp` dengan `chmod 600`
    - Minta password admin dari terminal (tanpa echo) via `golang.org/x/term`; jika kosong, generate password acak dan tampilkan sekali
    - Hash password dengan `HashPassword()`, INSERT ke tabel admins dalam transaksi DB
    - Jika INSERT berhasil → `os.Rename("master.key.tmp", "master.key")`
    - Jika INSERT gagal → hapus `master.key.tmp`, rollback transaksi
    - Tampilkan instruksi next steps dan peringatan simpan password
    - _Requirements: 1.1-1.6_
  - [x] 10.2 Tulis integration test untuk atomisitas gear init
    - Test sukses: Master Key dan admin keduanya terbuat
    - Test failure: simulasi DB failure → verifikasi `master.key.tmp` dihapus dan tidak ada row admin
    - Test idempoten: jalankan `gear init` dua kali → error pada run kedua, state tidak berubah
    - _Requirements: 1.4, 1.5_

- [x] 11. REST API handlers
  - [x] 11.1 Implementasi internal/handler/auth.go
    - `POST /v1/auth/login`: validasi JSON body, verify password via service, return token + `expires_at`; return 401 tanpa detail jika gagal
    - `POST /v1/auth/logout`: revoke session token
    - Tidak pernah mencatat password di log
    - _Requirements: 3.1, 3.2, 3.3, 3.5, 7.6_
  - [x] 11.2 Implementasi internal/handler/secret.go
    - `PUT /v1/secret/{path}`: validasi path, validasi JSON body, call `SecretService.Put()`, return 204
    - `GET /v1/secret/{path}`: call `SecretService.Get()`, return 200 + JSON
    - `DELETE /v1/secret/{path}`: call `SecretService.Delete()`, return 204 atau 404
    - `GET /v1/list/{prefix}`: call `SecretService.List()`, return 200 + paths atau 404
    - _Requirements: 6.1-6.6_
  - [x] 11.3 Implementasi internal/handler/token.go
    - `POST /v1/token`: parse TTL dari string (contoh: `"720h"`), call `TokenService.Create()`, return 201 dengan plaintext token (sekali saja)
    - `GET /v1/token`: call `TokenService.List()`, return 200 tanpa plaintext token
    - `DELETE /v1/token/{id}`: call `TokenService.Revoke()`, return 204 atau 404
    - _Requirements: 4.1-4.7_
  - [x] 11.4 Implementasi internal/handler/policy.go
    - `POST /v1/policy`: parse permissions array, call `PolicyService.Create()`, return 201
    - `GET /v1/policy`: optional filter `?token_id=`, call `PolicyService` list, return 200
    - `DELETE /v1/policy/{id}`: call `PolicyService.Delete()`, return 204 atau 404
    - _Requirements: 5.1-5.5_
  - [x] 11.5 Implementasi internal/handler/audit.go
    - `GET /v1/audit`: parse query params (token_id, path, since, until, result, limit, offset), call `AuditService.Query()`, return 200 + entries + pagination metadata
    - _Requirements: 7.3_
  - [x] 11.6 Tulis unit tests untuk semua handlers
    - Test setiap handler dengan mock services
    - Test error cases: 400, 401, 403, 404, 500
    - Test format response JSON
    - _Requirements: 3.1-3.5, 4.1-4.7, 5.1-5.5, 6.1-6.6, 7.3_

- [x] 12. HTTP server setup dan route registration
  - [x] 12.1 Implementasi internal/server/server.go
    - Setup chi router dengan middleware stack sesuai urutan: `RequestID`, `RealIP`, `TLSRedirect`, `CORS`, `Logger`, `Recoverer`, `RateLimit` (hanya `/auth/login`), `PathValidation` (hanya `/v1/secret/*` dan `/v1/list/*`), `Auth` (semua `/v1/*` kecuali login), `Policy` (secret/list), `Audit` (semua `/v1/*`)
    - Register semua routes ke handler masing-masing
    - Graceful shutdown: tangkap `SIGINT`/`SIGTERM`, tunggu request aktif selesai
    - Verifikasi `master.key` file permission `0600` saat startup; fatal jika tidak
    - _Requirements: 9.1, 9.2, 9.3_

- [x] 13. Checkpoint — Gear Engine selesai, semua tests pass
  - Pastikan semua unit test dan property-based test gear-engine lulus. Jalankan `cd gear-engine && go test ./...`. Tanya user jika ada pertanyaan sebelum melanjutkan ke gear-ui.

- [x] 14. Vue API client + Pinia auth store
  - [x] 14.1 Implementasi src/api/client.ts — fetch wrapper
    - Fungsi `apiFetch(path, options)` yang inject `Authorization: Bearer {token}` dari Pinia store
    - Base URL dari `import.meta.env.VITE_API_BASE_URL`
    - Intercept response 401 → call `authStore.logout()` + redirect ke `/login`
    - Intercept response 403 → tampilkan toast "Forbidden"
    - Typed helper functions: `getSecret`, `putSecret`, `deleteSecret`, `listSecrets`, `createToken`, `revokeToken`, `listTokens`, `createPolicy`, `deletePolicy`, `listPolicies`, `getAuditLog`
    - _Requirements: 8.2, 8.3, 8.4, 8.5, 8.6, 9.4_
  - [x] 14.2 Implementasi src/store/auth.ts — Pinia auth store
    - State: `token: string | null`, `expiresAt: number | null`
    - Action `login(username, password)`: call `POST /v1/auth/login`, simpan token + expiry ke store (dan localStorage untuk persistensi tab)
    - Action `logout()`: hapus state + localStorage, redirect ke `/login`
    - Action `checkExpiry()`: bandingkan `Date.now()` dengan `expiresAt`; jika kadaluarsa → `logout()`
    - `setInterval` setiap 30 detik untuk memanggil `checkExpiry()` secara otomatis
    - _Requirements: 8.1, 8.2, 8.7_
  - [x] 14.3 Implementasi src/router/index.ts — vue-router + navigation guard
    - Routes: `/login`, `/` (redirect ke `/secrets`), `/secrets`, `/secrets/:path`, `/tokens`, `/policies`, `/audit`
    - Navigation guard: jika `!authStore.token` → redirect ke `/login`
    - _Requirements: 8.1, 8.7_

- [x] 15. Vue views dan components
  - [x] 15.1 Implementasi src/views/Login.vue
    - Form username + password, button login
    - Call `authStore.login()`, tampilkan error message jika gagal
    - Redirect ke `/secrets` setelah login berhasil
    - _Requirements: 8.1, 8.2_
  - [x] 15.2 Implementasi src/components/SecretTree.vue — recursive tree component
    - Props: `paths: string[]`
    - Render tree hierarkis dari flat path list (group by prefix separator `/`)
    - Emit `select(path)` saat path leaf diklik
    - _Requirements: 8.3_
  - [x] 15.3 Implementasi src/views/Secrets.vue — browse secrets
    - Load paths via `GET /v1/list/{prefix}` (root prefix awal: `""`)
    - Gunakan `SecretTree` component untuk display
    - Navigasi ke `/secrets/:path` saat item dipilih
    - _Requirements: 8.3_
  - [x] 15.4 Implementasi src/views/SecretDetail.vue — tampil/edit/hapus secret
    - Load secret via `GET /v1/secret/:path`
    - Form edit value → `PUT /v1/secret/:path`
    - Tombol delete → `DELETE /v1/secret/:path` dengan konfirmasi
    - Feedback sukses/gagal setiap operasi
    - _Requirements: 8.4, 8.5_
  - [x] 15.5 Implementasi src/components/TokenCard.vue
    - Props: `token: Token` (nama, expires_at, revoked status, created_at)
    - Tampilkan info token (masked value); one-time display plaintext pada create baru (via emit atau slot)
    - Tombol revoke dengan konfirmasi
    - _Requirements: 8.6_
  - [x] 15.6 Implementasi src/views/Tokens.vue — manajemen token
    - Load tokens via `GET /v1/token`
    - Form buat token baru (nama + TTL): call `POST /v1/token`, tampilkan plaintext token sekali dengan pesan "Simpan sekarang, tidak bisa dilihat lagi"
    - Render daftar token dengan `TokenCard`
    - _Requirements: 4.3, 8.6_
  - [x] 15.7 Implementasi src/views/Policies.vue — manajemen policy
    - Load policies via `GET /v1/policy`
    - Form buat policy: pilih token (dari list), input path pattern, checkbox read/write/delete
    - Call `POST /v1/policy`, tampilkan feedback
    - Tombol hapus policy
    - _Requirements: 5.1, 8.5_
  - [x] 15.8 Implementasi src/components/AuditTable.vue — filterable table
    - Props: `entries: AuditEntry[]`, `total: number`, `limit: number`, `offset: number`
    - Render tabel dengan kolom: token_name, path, action, result, ip_address, timestamp
    - Emit `filter-change(params)` dan `page-change(offset)` saat filter atau paginasi berubah
    - _Requirements: 7.3, 8.8_
  - [x] 15.9 Implementasi src/views/AuditLog.vue — halaman audit log
    - Load entries via `GET /v1/audit` dengan filter params
    - Filter controls: token_id, path, since/until date picker, result dropdown
    - Paginasi
    - Gunakan `AuditTable` component
    - _Requirements: 7.3, 8.8_

- [x] 16. Checkpoint — gear-ui selesai, semua komponen terintegrasi
  - Pastikan gear-ui build tanpa error: `cd gear-ui && npm run build`. Tanya user jika ada pertanyaan sebelum integrasi test.

- [x] 17. Integration tests
  - [x] 17.1 Tulis integration test: TLS enforcement
    - Test bahwa server menolak plain HTTP dan hanya menerima HTTPS
    - Test bahwa server gagal start tanpa TLS cert yang valid
    - _Requirements: 9.1, 9.2_
  - [x] 17.2 Tulis integration test: audit fail-safe
    - Simulasi `AuditService.Log()` yang selalu error
    - Verifikasi bahwa handler mengembalikan HTTP 500 dan TIDAK memproses request
    - Verifikasi bahwa tidak ada data yang berubah di DB saat audit gagal
    - _Requirements: 7.5_
  - [x] 17.3 Tulis property-based test untuk audit completeness (gopter, min 200 iterasi)
    - **Property 17: Setiap Request Menghasilkan Satu Audit Entry** — `∀ request valid ke /v1/secret/*: len(AuditLog) bertambah tepat 1`
    - **Validates: Requirements 7.4**
    - **Property 18: Audit Entry Tidak Mengandung Secret Value** — `∀ entry di audit_log: entry.path tidak berisi nilai secret yang di-PUT`
    - **Validates: Requirements 7.2**
    - _Requirements: 7.1-7.5_
  - [x] 17.4 Tulis property-based test untuk envelope encryption (gopter, min 200 iterasi)
    - **Property 19: Database Tanpa Master Key Tidak Dapat Membaca Secret** — `∀ secret: decrypt tanpa Master Key menghasilkan error`
    - **Validates: Requirements 2.4, 2.7**
    - **Property 20: Setiap Secret Memiliki DEK Unik** — `∀ secret₁ ≠ secret₂: DEK₁ ≠ DEK₂`
    - **Validates: Requirements 2.1**
    - _Requirements: 2.1, 2.4, 2.7_

- [x] 18. Final checkpoint — semua tests pass
  - Pastikan semua test lulus: `cd gear-engine && go test ./...` dan `cd gear-ui && npm run type-check`. Tanya user jika ada pertanyaan.

---

## Notes

- Task bertanda `*` bersifat opsional dan dapat dilewati untuk MVP lebih cepat
- Property-based test menggunakan library `gopter` (Go) dengan minimum 200 iterasi per property
- Properties 1–20 sesuai urutan di design document bagian "Correctness Properties"
- Setiap task mereferensikan requirement spesifik untuk traceability
- `gear-engine` dan `gear-ui` adalah project terpisah — tidak ada file sharing atau embed
- DEK harus di-zero-out dari memory setelah setiap operasi enkripsi/dekripsi (lihat design)
- Master Key file permission harus `0600`; server tidak akan start jika berbeda
- Token plaintext HANYA dikembalikan satu kali saat pembuatan — tidak pernah disimpan di DB

---

## Task Dependency Graph

```json
{
  "waves": [
    {
      "id": 0,
      "tasks": ["1.1", "1.2", "2.1", "2.2"]
    },
    {
      "id": 1,
      "tasks": ["3.1", "4.1", "9.1"]
    },
    {
      "id": 2,
      "tasks": ["3.2", "5.1", "5.2", "5.3"]
    },
    {
      "id": 3,
      "tasks": ["5.4", "5.5", "6.1"]
    },
    {
      "id": 4,
      "tasks": ["6.2", "6.3", "7.1", "7.4", "7.7", "7.10"]
    },
    {
      "id": 5,
      "tasks": ["7.2", "7.3", "7.5", "7.6", "7.8", "7.9", "7.11"]
    },
    {
      "id": 6,
      "tasks": ["8.1", "8.2", "8.3", "8.4", "8.5"]
    },
    {
      "id": 7,
      "tasks": ["8.6", "10.1", "11.1", "11.2", "11.3", "11.4", "11.5"]
    },
    {
      "id": 8,
      "tasks": ["10.2", "11.6", "12.1"]
    },
    {
      "id": 9,
      "tasks": ["14.1", "14.2", "14.3"]
    },
    {
      "id": 10,
      "tasks": ["15.1", "15.2", "15.5", "15.8"]
    },
    {
      "id": 11,
      "tasks": ["15.3", "15.4", "15.6", "15.7", "15.9"]
    },
    {
      "id": 12,
      "tasks": ["17.1", "17.2"]
    },
    {
      "id": 13,
      "tasks": ["17.3", "17.4"]
    }
  ]
}
```
