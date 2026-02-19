# 🔒 WireGuard Manager

REST API untuk mengelola WireGuard peers di **Mikrotik RouterOS** — tanpa library eksternal ROS, murni low-level TCP/TLS Node.js.

Mendukung **banyak router sekaligus** (S0, S1, S2, ..., tidak ada batas), koneksi **TLS dengan cipher suite modern**, dan verifikasi **SHA-256 fingerprint** untuk proteksi MITM.

---

## Fitur

- Multi-server dinamis — tambah router sebanyak apapun via env vars
- Koneksi TLS (port 8729) sebagai default, plain TCP (8728) sebagai fallback
- Verifikasi TLS fingerprint SHA-256 — aman meski router pakai self-signed cert
- Cipher suite modern: TLS 1.3 prioritas, TLS 1.2 ECDHE sebagai fallback
- Generate WireGuard keypair (Curve25519) murni di Node.js, tidak butuh binary `wg`
- Auto-suggest nama peer & IP berikutnya yang kosong
- QR code config WireGuard siap scan
- Cache peers 5 detik agar list terasa snappy
- Connection pool per router dengan auto-reconnect
- Partial TCP buffer carry-over (tidak ada data yang di-drop)
- Request queue FIFO — aman untuk concurrent write

---

## Struktur Project

```
.
├── server.js               # Express API — semua route
├── get-fingerprint.js      # Utility: ambil TLS fingerprint router → fingerprints.txt
├── .env.example            # Template konfigurasi
├── package.json
└── src/
    ├── config.js           # Dynamic server loader dari env vars
    ├── mikrotik.js         # Low-level RouterOS API protocol (TCP/TLS)
    ├── crypto.js           # WireGuard keypair generator (tweetnacl)
    └── generator.js        # Auto-generate nama peer & IP
```

---

## Instalasi

```bash
git clone https://github.com/Azda45/crispy-waffle.git
cd crispy-waffle
npm install
cp .env.example .env
```

Edit `.env` sesuai konfigurasi router kamu, lalu jalankan:

```bash
npm start        # production
npm run dev      # development (auto-restart on file change)
```

---

## Konfigurasi

Semua konfigurasi via environment variables di file `.env`.

### App

| Variable | Default | Keterangan                              |
| -------- | ------- | --------------------------------------- |
| `PORT`   | `3000`  | Port HTTP server                        |
| `DEBUG`  | `false` | Log detail TLS handshake & ROS protocol |

### WireGuard Client Defaults

Nilai ini dipakai saat generate config/QR code untuk client.

| Variable         | Default            | Keterangan                           |
| ---------------- | ------------------ | ------------------------------------ |
| `IPV4_CIDR`      | `32`               | Prefix length IPv4 client            |
| `IPV6_CIDR`      | `128`              | Prefix length IPv6 client            |
| `WG_DNS`         | `1.1.1.1, 1.0.0.1` | DNS server                           |
| `WG_ALLOWED_IPS` | `0.0.0.0/0, ::/0`  | Allowed IPs (full tunnel by default) |
| `WG_KEEPALIVE`   | `25`               | PersistentKeepalive (detik)          |

### RouterOS Connection

| Variable          | Default | Keterangan                         |
| ----------------- | ------- | ---------------------------------- |
| `ROS_TIMEOUT`     | `15`    | Timeout koneksi per router (detik) |
| `ROS_MAX_RETRIES` | `3`     | Jumlah retry kalau koneksi gagal   |
| `ROS_RETRY_DELAY` | `1000`  | Jeda antar retry (ms)              |

### Server (Dynamic — S0, S1, S2, ..., SN)

Tambah router sebanyak yang dibutuhkan. Loader scan dari `S0_HOST`, `S1_HOST`, dst. dan **berhenti di index pertama yang HOST-nya kosong** — jadi jangan ada gap.

> ⚠️ Kalau `S0` dan `S2` ada tapi `S1` kosong, maka `S2` dan seterusnya **diabaikan**.

| Variable               | Default       | Keterangan                                                |
| ---------------------- | ------------- | --------------------------------------------------------- |
| `S{N}_HOST`            | —             | **WAJIB.** IP / hostname router                           |
| `S{N}_USER`            | —             | **WAJIB.** Username RouterOS                              |
| `S{N}_PASSWORD`        | —             | **WAJIB.** Password RouterOS                              |
| `S{N}_NAME`            | `Router-N`    | Nama tampilan                                             |
| `S{N}_PORT`            | `8729`        | Port API RouterOS                                         |
| `S{N}_TLS`             | auto          | `true`/`false`. Auto-detect dari port: 8729→TLS, 8728→TCP |
| `S{N}_TLS_FINGERPRINT` | —             | SHA-256 fingerprint cert (sangat disarankan)              |
| `S{N}_TLS_CA`          | —             | Path ke PEM CA cert (kalau pakai internal CA)             |
| `S{N}_WG_INTERFACE`    | `wireguard1`  | Nama interface WireGuard di router                        |
| `S{N}_WG_PORT`         | `51820`       | Port UDP WireGuard                                        |
| `S{N}_IPV4_PREFIX`     | `10.10.N.`    | Prefix subnet IPv4 peers                                  |
| `S{N}_IPV6_PREFIX`     | `fd00:10:N::` | Prefix subnet IPv6 peers                                  |

**Port RouterOS:**

- `8729` — API-SSL (**TLS**, direkomendasikan)
- `8728` — API (plain TCP, tidak terenkripsi, hindari di produksi)

**Contoh 4 router:**

```env
S0_NAME=Jakarta-01
S0_HOST=10.0.0.1
S0_USER=admin
S0_PASSWORD=rahasia
S0_PORT=8729
S0_TLS_FINGERPRINT=AA:BB:CC:DD:...

S1_NAME=Jakarta-02
S1_HOST=10.0.0.2
S1_USER=admin
S1_PASSWORD=rahasia
S1_PORT=8729
S1_TLS_FINGERPRINT=EE:FF:11:22:...

S2_NAME=Surabaya-01
S2_HOST=10.0.1.1
S2_USER=admin
S2_PASSWORD=rahasia
S2_PORT=8729

S3_NAME=Bandung-01
S3_HOST=10.0.2.1
S3_USER=admin
S3_PASSWORD=rahasia
S3_PORT=8729
```

---

## TLS Fingerprint

RouterOS menggunakan **self-signed certificate**. Tanpa fingerprint, koneksi TLS tetap terenkripsi tapi rentan MITM. Dengan fingerprint, koneksi akan ditolak kalau cert tidak cocok.

### Cara ambil fingerprint

**Pakai script bawaan** (direkomendasikan):

```bash
node get-fingerprint.js
```

Script membaca semua server dari `.env`, koneksi ke masing-masing, lalu menyimpan hasilnya ke **`fingerprints.txt`** — bukan di console.

```
┌─ S0 Jakarta-01 — 10.0.0.1:8729
│  Subject   : MikroTik (self-signed)
│  SHA-256   : AA:BB:CC:DD:EE:FF:...
└─ .env line :
   S0_TLS_FINGERPRINT=AA:BB:CC:DD:EE:FF:...
```

Tinggal copy baris `S0_TLS_FINGERPRINT=...` dari `fingerprints.txt` ke `.env`.

**Manual pakai OpenSSL:**

```bash
openssl s_client -connect <host>:8729 </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout
```

**Satu host tanpa .env:**

```bash
node get-fingerprint.js 192.168.1.1
node get-fingerprint.js 192.168.1.1 8729
```

---

## API Reference

Base URL: `http://localhost:3000`

Semua response berformat JSON dengan field `success: boolean`.

---

### `GET /api/servers`

List semua server yang aktif.

**Response:**

```json
{
  "success": true,
  "servers": [
    { "id": 0, "name": "Jakarta-01", "host": "10.0.0.1", "tls": true },
    { "id": 1, "name": "Jakarta-02", "host": "10.0.0.2", "tls": true }
  ]
}
```

---

### `GET /api/:server/peers`

List semua WireGuard peers di server `N`.

```bash
GET /api/0/peers
```

**Response:**

```json
{
  "success": true,
  "server": { "id": 0, "name": "Jakarta-01", "host": "10.0.0.1" },
  "peers": [
    {
      ".id": "*1",
      "name": "Swift-Phoenix-42",
      "ipv4": "10.10.0.2",
      "ipv6": "fd00:10:0::2",
      "enabled": true,
      "privkey": "base64...",
      "public-key": "base64...",
      "allowed-address": "10.10.0.2/32,fd00:10:0::2/128"
    }
  ]
}
```

> `privkey` hanya ada untuk peer yang dibuat via API ini. Peer yang dibuat manual di Winbox/WebFig akan `null` — QR code tidak bisa digenerate.

---

### `GET /api/:server/suggest`

Auto-generate nama peer unik + IPv4 & IPv6 kosong berikutnya.

```bash
GET /api/0/suggest
```

**Response:**

```json
{
  "success": true,
  "name": "Frost-Jaguar-73",
  "ipv4": "10.10.0.5",
  "ipv6": "fd00:10:0::5"
}
```

---

### `POST /api/:server/peers`

Tambah peer baru. Keypair di-generate otomatis.

```bash
POST /api/0/peers
Content-Type: application/json

{
  "name": "Frost-Jaguar-73",
  "ipv4": "10.10.0.5",
  "ipv6": "fd00:10:0::5"
}
```

**Response `201`:**

```json
{
  "success": true,
  "peer": {
    ".id": "*5",
    "name": "Frost-Jaguar-73",
    "ipv4": "10.10.0.5",
    "ipv6": "fd00:10:0::5",
    "enabled": true,
    "privkey": "base64...",
    "public-key": "base64..."
  }
}
```

**Error `409`** — kalau IP sudah dipakai:

```json
{ "success": false, "error": "IPv4 10.10.0.5 sudah dipakai peer lain" }
```

---

### `PATCH /api/:server/peers/:id/toggle`

Enable / disable peer.

```bash
PATCH /api/0/peers/*5/toggle
Content-Type: application/json

{ "enabled": true }
```

- `enabled: true` → peer saat ini **aktif** → akan di-**disable**
- `enabled: false` → peer saat ini **nonaktif** → akan di-**enable**

**Response:**

```json
{ "success": true, "disabled": true }
```

---

### `DELETE /api/:server/peers/:id`

Hapus peer permanen dari router.

```bash
DELETE /api/0/peers/*5
```

**Response:**

```json
{ "success": true }
```

---

### `POST /api/:server/peers/:id/qrcode`

Generate QR code config WireGuard siap scan + teks `.conf`.

```bash
POST /api/0/peers/*5/qrcode
Content-Type: application/json

{
  "privkey": "base64...",
  "ipv4": "10.10.0.5",
  "ipv6": "fd00:10:0::5"
}
```

**Response:**

```json
{
  "success": true,
  "qrcode": "data:image/png;base64,...",
  "configText": "[Interface]\nPrivateKey = ...\n..."
}
```

`configText` berisi file `.conf` lengkap yang bisa disimpan langsung.

---

## Error Responses

Semua error mengembalikan `success: false` dengan field `error`.

| Status | Keterangan                                      |
| ------ | ----------------------------------------------- |
| `400`  | Field wajib kosong / input tidak valid          |
| `404`  | Server ID tidak ditemukan / endpoint tidak ada  |
| `409`  | IP conflict — sudah dipakai peer lain           |
| `500`  | Error koneksi ke router / internal server error |

---

## Private Key & Keamanan

Private key peer disimpan di field **comment** RouterOS sebagai JSON:

```json
{ "privkey": "base64...", "created_at": "2026-01-01T00:00:00.000Z" }
```

Siapa pun yang bisa akses konfigurasi router bisa membaca private key semua peer. Ini trade-off desain untuk tetap stateless (tidak butuh database).

**Rekomendasi produksi:**

- Aktifkan TLS (`S{N}_TLS=true`, port 8729)
- Set `S{N}_TLS_FINGERPRINT` untuk proteksi MITM
- Batasi akses API RouterOS hanya dari IP internal

---

## Tech Stack

|                   |                                             |
| ----------------- | ------------------------------------------- |
| Runtime           | Node.js ≥ 18                                |
| Framework         | Express 4                                   |
| RouterOS Protocol | Low-level TCP/TLS (murni Node.js built-ins) |
| WireGuard Crypto  | tweetnacl (Curve25519)                      |
| QR Code           | qrcode                                      |
| Config            | dotenv                                      |

Tidak ada library eksternal untuk komunikasi RouterOS — semua diimplementasi dari scratch mengikuti [RouterOS API spec](https://help.mikrotik.com/docs/display/ROS/API).

---

## License

MIT
