"use strict";

const net = require("net");
const tls = require("tls");
const crypto = require("crypto");
const config = require("./config");

// ═══════════════════════════════════════════════════════════════════════════════
//  RouterOS API Wire Protocol — low-level encoder / decoder
//  Ref: https://help.mikrotik.com/docs/display/ROS/API
//
//  Framing:
//    sentence  = word* NUL
//    word      = length_prefix  utf8_bytes
//    length_prefix (variable-length, big-endian):
//      0xxxxxxx                          — 1 byte,  len 0x00–0x7F
//      10xxxxxx xxxxxxxx                 — 2 bytes, len 0x80–0x3FFF
//      110xxxxx xxxxxxxx xxxxxxxx        — 3 bytes, len 0x4000–0x1FFFFF
//      1110xxxx xxxxxxxx xxxxxxxx xxxxxxxx — 4 bytes, len 0x200000–0xFFFFFFF
//      11110000 xxxxxxxx*4               — 5 bytes, len ≥ 0x10000000 (rare)
//    NUL = single 0x00 byte (= 1-byte length encoding for len=0)
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Encoder ──────────────────────────────────────────────────────────────────

function encodeLength(len) {
  if (len < 0x80) return Buffer.from([len]);

  if (len < 0x4000)
    return Buffer.from([((len >> 8) & 0x3f) | 0x80, len & 0xff]);

  if (len < 0x200000)
    return Buffer.from([
      ((len >> 16) & 0x1f) | 0xc0,
      (len >> 8) & 0xff,
      len & 0xff,
    ]);

  if (len < 0x10000000)
    return Buffer.from([
      ((len >> 24) & 0x0f) | 0xe0,
      (len >> 16) & 0xff,
      (len >> 8) & 0xff,
      len & 0xff,
    ]);

  // 5-byte — len ≥ 0x10000000 (sangat jarang tapi harus handle)
  return Buffer.from([
    0xf0,
    (len >> 24) & 0xff,
    (len >> 16) & 0xff,
    (len >> 8) & 0xff,
    len & 0xff,
  ]);
}

/** Encode satu word → length_prefix + utf8_bytes */
function encodeWord(word) {
  const body = Buffer.from(word, "utf8");
  return Buffer.concat([encodeLength(body.length), body]);
}

/** Encode satu sentence → word* + NUL(0x00) */
function encodeSentence(words) {
  const parts = words.map(encodeWord);
  parts.push(Buffer.from([0x00]));
  return Buffer.concat(parts);
}

// ─── Decoder ──────────────────────────────────────────────────────────────────

/**
 * Decode raw bytes dari socket menjadi array of sentences.
 *
 * Kembalikan { sentences, remaining } supaya bytes yang belum membentuk
 * sentence lengkap (partial TCP chunk) bisa di-carry-over ke chunk berikutnya.
 * Tanpa ini, partial packet langsung di-drop → response korup / hilang.
 *
 * @param  {Buffer} buf
 * @returns {{ sentences: string[][], remaining: Buffer }}
 */
function decodePackets(buf) {
  const sentences = [];
  let i = 0;

  outer: while (i < buf.length) {
    const sentence = [];

    while (true) {
      // Butuh minimal 1 byte untuk baca length prefix
      if (i >= buf.length) break outer;

      const b0 = buf[i];
      let len, skip;

      if ((b0 & 0xf0) === 0xf0) {
        // 5-byte
        if (i + 5 > buf.length) break outer;
        len =
          buf[i + 1] * 0x1000000 +
          (buf[i + 2] << 16) +
          (buf[i + 3] << 8) +
          buf[i + 4];
        // Gunakan perkalian untuk bit ke-31 agar tidak sign-extend di JS
        skip = 5;
      } else if ((b0 & 0xe0) === 0xe0) {
        // 4-byte
        if (i + 4 > buf.length) break outer;
        len =
          (b0 & 0x0f) * 0x1000000 +
          (buf[i + 1] << 16) +
          (buf[i + 2] << 8) +
          buf[i + 3];
        skip = 4;
      } else if ((b0 & 0xc0) === 0xc0) {
        // 3-byte
        if (i + 3 > buf.length) break outer;
        len = ((b0 & 0x1f) << 16) + (buf[i + 1] << 8) + buf[i + 2];
        skip = 3;
      } else if ((b0 & 0x80) === 0x80) {
        // 2-byte
        if (i + 2 > buf.length) break outer;
        len = ((b0 & 0x3f) << 8) + buf[i + 1];
        skip = 2;
      } else {
        // 1-byte
        len = b0;
        skip = 1;
      }

      // len == 0 → end-of-sentence (NUL word)
      if (len === 0) {
        i += skip;
        sentences.push(sentence);
        break; // lanjut ke sentence berikutnya
      }

      // Pastikan seluruh body word sudah ada di buffer
      if (i + skip + len > buf.length) break outer;

      i += skip;
      sentence.push(buf.subarray(i, i + len).toString("utf8"));
      i += len;
    }
  }

  return { sentences, remaining: buf.subarray(i) };
}

// ═══════════════════════════════════════════════════════════════════════════════
//  TLS context — dibangun sekali, di-reuse
//  Urutan preferensi cipher mengutamakan TLS 1.3 (node ≥ 12) lalu TLS 1.2.
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Buat TLS context dengan cipher suite modern.
 * RouterOS menggunakan self-signed cert, jadi rejectUnauthorized=false.
 * Kita verifikasi via fingerprint SHA-256 kalau dikonfigurasi.
 *
 * @param {object}  opts
 * @param {string}  [opts.caFingerprint]   SHA-256 hex fingerprint cert router (opsional tapi disarankan)
 * @param {string}  [opts.caCert]          PEM CA cert (opsional)
 * @returns {tls.SecureContext}
 */
function buildTlsContext({ caFingerprint, caCert } = {}) {
  const ctxOpts = {
    // TLS 1.3 sebagai minimum kalau router mendukung (RouterOS 7.x)
    // Fallback ke TLS 1.2 untuk RouterOS 6.x yang belum support TLS 1.3
    minVersion: "TLSv1.2",

    // Cipher suite modern — TLS 1.3 AEADs + TLS 1.2 forward-secret ECDHE
    // sesuai rekomendasi Mozilla "Intermediate" 2024
    ciphers: [
      // TLS 1.3 (Node secara otomatis pakai ini kalau didukung kedua pihak)
      "TLS_AES_256_GCM_SHA384",
      "TLS_AES_128_GCM_SHA256",
      "TLS_CHACHA20_POLY1305_SHA256",
      // TLS 1.2 ECDHE + AESGCM / CHACHA20
      "ECDHE-ECDSA-AES256-GCM-SHA384",
      "ECDHE-RSA-AES256-GCM-SHA384",
      "ECDHE-ECDSA-CHACHA20-POLY1305",
      "ECDHE-RSA-CHACHA20-POLY1305",
      "ECDHE-ECDSA-AES128-GCM-SHA256",
      "ECDHE-RSA-AES128-GCM-SHA256",
    ].join(":"),

    // Hanya verifikasi cert kalau CA / fingerprint dikonfigurasi
    rejectUnauthorized: !!(caCert || caFingerprint),
  };

  if (caCert) ctxOpts.ca = caCert;

  return tls.createSecureContext(ctxOpts);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  rosConnect — buat TCP/TLS socket ke RouterOS dan login
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * @typedef {object} RosApi
 * @property {(words: string[]) => Promise<object[]>} write
 * @property {() => void}                             close
 * @property {(() => void) | null}                    _onClose
 */

/**
 * Buat koneksi ke RouterOS API, login, dan return RosApi object.
 *
 * Mode koneksi (diurutkan dari paling aman):
 *   1. TLS + fingerprint verification  ← paling aman, pakai ini kalau bisa
 *   2. TLS tanpa verifikasi cert        ← enkripsi tapi rentan MITM
 *   3. Plain TCP                        ← tidak direkomendasikan di produksi
 *
 * Fixes vs versi asli:
 *   • Partial TCP chunk carry-over (tidak di-drop lagi)
 *   • TLS didukung dengan cipher suite modern
 *   • Concurrent write() aman (request queue FIFO)
 *   • Error post-login tidak crash (reject queue item atau log)
 *   • api object tidak reference sebelum declared
 *   • destroyAll() idempotent (tidak reject dua kali)
 *
 * @param {object}  opts
 * @param {string}  opts.host
 * @param {number}  opts.port
 * @param {string}  opts.user
 * @param {string}  opts.password
 * @param {boolean} [opts.useTls=true]       — default TLS
 * @param {number}  [opts.timeout=15]        — detik
 * @param {string}  [opts.caFingerprint]     — SHA-256 hex fingerprint (opsional)
 * @param {string}  [opts.caCert]            — PEM CA cert (opsional)
 * @returns {Promise<RosApi>}
 */
function rosConnect({
  host,
  port,
  user,
  password,
  useTls = true,
  timeout = 15,
  caFingerprint,
  caCert,
}) {
  return new Promise((resolve, reject) => {
    let sock;

    if (useTls) {
      const secureContext = buildTlsContext({ caFingerprint, caCert });
      sock = tls.connect({
        host,
        port,
        secureContext,
        // rejectUnauthorized dihandle di dalam secureContext,
        // tapi kita override di sini supaya sesuai
        rejectUnauthorized: !!(caCert || caFingerprint),
        servername: host, // SNI
        checkServerIdentity: caFingerprint
          ? (hostname, cert) => {
              // Verifikasi fingerprint SHA-256
              const der = cert.raw;
              const fp = crypto.createHash("sha256").update(der).digest("hex");
              const want = caFingerprint.replace(/[:\s]/g, "").toLowerCase();
              if (fp !== want) {
                return new Error(
                  `TLS fingerprint mismatch: got ${fp}, want ${want}`,
                );
              }
              // return undefined = OK
            }
          : undefined,
      });
    } else {
      sock = net.createConnection({ host, port });
    }

    sock.setTimeout(timeout * 1000);

    let buf = Buffer.alloc(0);
    let loggedIn = false;
    let destroyed = false;

    // ── Request queue (FIFO) ──────────────────────────────────────────────────
    /** @type {{ resolve: Function, reject: Function, accumulator: string[][] }[]} */
    const queue = [];

    function destroyAll(err) {
      if (destroyed) return;
      destroyed = true;
      try {
        sock.destroy();
      } catch (_) {}
      for (const item of queue) {
        try {
          item.reject(err);
        } catch (_) {}
      }
      queue.length = 0;
    }

    // ── Data handler ──────────────────────────────────────────────────────────
    sock.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const { sentences, remaining } = decodePackets(buf);
      buf = remaining; // carry-over bytes belum lengkap

      for (const sentence of sentences) {
        if (!sentence.length) continue;
        const type = sentence[0];

        // ── Fase login ──────────────────────────────────────────────────────
        if (!loggedIn) {
          if (type === "!done") {
            loggedIn = true;
            resolve(api);
          } else if (type === "!trap" || type === "!fatal") {
            const msg =
              sentence.find((w) => w.startsWith("=message="))?.slice(9) ??
              "Login failed";
            const err = new Error(msg);
            reject(err);
            destroyAll(err);
          }
          continue;
        }

        // ── Fase normal ─────────────────────────────────────────────────────
        if (!queue.length) {
          if (config.app.debug)
            console.warn(
              "[ROS] Unexpected sentence tanpa active request:",
              sentence,
            );
          continue;
        }

        const current = queue[0];
        current.accumulator.push(sentence);

        if (["!done", "!empty", "!trap", "!fatal"].includes(type)) {
          queue.shift();

          if (type === "!trap" || type === "!fatal") {
            const msg =
              current.accumulator
                .flat()
                .find((w) => w?.startsWith("=message="))
                ?.slice(9) ?? "RouterOS error";
            current.reject(new Error(msg));
          } else {
            // Parse setiap baris !re → plain object
            const rows = current.accumulator
              .filter((s) => s[0] === "!re")
              .map((s) => {
                const obj = {};
                for (const w of s.slice(1)) {
                  const eq = w.indexOf("=", 1);
                  if (eq > 0) obj[w.slice(1, eq)] = w.slice(eq + 1);
                }
                return obj;
              });
            current.resolve(rows);
          }
        }
      }
    });

    // ── Kirim login setelah socket siap ──────────────────────────────────────
    function sendLogin() {
      sock.write(
        encodeSentence(["/login", `=name=${user}`, `=password=${password}`]),
      );
    }

    if (useTls) {
      // TLS: tunggu TLS handshake selesai (secureConnect)
      sock.on("secureConnect", () => {
        if (config.app.debug) {
          const proto = sock.getProtocol?.() ?? "unknown";
          const cipher = sock.getCipher?.()?.name ?? "unknown";
          console.log(
            `[ROS TLS] ${host} — protocol: ${proto}, cipher: ${cipher}`,
          );
        }
        sendLogin();
      });
    } else {
      sock.on("connect", sendLogin);
    }

    sock.on("timeout", () => {
      const err = new Error(`Connection timeout ke ${host}:${port}`);
      if (!loggedIn) reject(err);
      destroyAll(err);
    });

    sock.on("error", (err) => {
      if (!loggedIn) reject(err);
      else destroyAll(err);
    });

    sock.on("close", () => {
      // Panggil hook cleanup pool (diset oleh MikrotikService)
      try {
        api._onClose?.();
      } catch (_) {}
      if (queue.length) destroyAll(new Error("Connection closed unexpectedly"));
    });

    // ── API object ────────────────────────────────────────────────────────────
    const api = {
      /**
       * Kirim sentence ke RouterOS dan tunggu respons.
       * Aman dipanggil secara concurrent (queue FIFO).
       *
       * @param   {string[]}          words
       * @returns {Promise<object[]>}
       */
      write(words) {
        return new Promise((res, rej) => {
          if (destroyed) {
            rej(new Error("Connection already closed"));
            return;
          }
          queue.push({ resolve: res, reject: rej, accumulator: [] });
          sock.write(encodeSentence(words));
        });
      },

      close() {
        destroyAll(new Error("Closed by caller"));
      },

      /** Diisi MikrotikService.connect() untuk auto-cleanup pool. */
      _onClose: null,
    };
    // api sudah fully constructed sebelum sendLogin() dipanggil,
    // jadi tidak ada temporal dead zone issue
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Connection pool & peers cache
// ═══════════════════════════════════════════════════════════════════════════════

/** @type {Record<string, RosApi>} */
const pool = {};

/** @type {Record<string, { data: object[], ts: number }>} */
const cache = {};

const CACHE_TTL = 5_000; // ms

// ═══════════════════════════════════════════════════════════════════════════════
//  MikrotikService
// ═══════════════════════════════════════════════════════════════════════════════

class MikrotikService {
  /**
   * @param {number} serverId — index server dari config.servers (0, 1, …)
   */
  constructor(serverId = 0) {
    const srv = config.servers.find((s) => s.id === Number(serverId));
    if (!srv) throw new Error(`Server ID ${serverId} tidak ditemukan`);
    this.srv = srv;
    this.poolKey = `srv_${srv.id}`;
    this.cacheKey = `peers_${srv.id}`;
  }

  // ── Koneksi ───────────────────────────────────────────────────────────────

  /**
   * Ambil koneksi aktif dari pool, atau buat koneksi baru.
   * Retry otomatis sesuai config.routeros.maxRetries.
   *
   * @param {number} attempt
   * @returns {Promise<RosApi>}
   */
  async connect(attempt = 1) {
    if (pool[this.poolKey]) return pool[this.poolKey];

    const {
      host,
      port,
      user,
      password,
      tls: useTls,
      caFingerprint,
      caCert,
    } = this.srv;
    const proto = useTls ? "TLS" : "TCP";
    console.log(
      `[Mikrotik] Connecting to ${host}:${port} via ${proto} (attempt ${attempt})…`,
    );

    try {
      const api = await rosConnect({
        host,
        port,
        user,
        password,
        useTls,
        caFingerprint,
        caCert,
        timeout: config.routeros.timeout,
      });

      // Hook: hapus dari pool otomatis saat koneksi mati
      api._onClose = () => {
        if (pool[this.poolKey] === api) {
          delete pool[this.poolKey];
          console.log(
            `[Mikrotik] Koneksi ${this.poolKey} (${host}) closed → dihapus dari pool`,
          );
        }
      };

      pool[this.poolKey] = api;
      console.log(`[Mikrotik] ✓ Connected to ${host}:${port} via ${proto}`);
      return api;
    } catch (err) {
      delete pool[this.poolKey];
      console.error(
        `[Mikrotik] Gagal (${attempt}/${config.routeros.maxRetries}): ${err.message}`,
      );

      if (attempt < config.routeros.maxRetries) {
        await sleep(config.routeros.retryDelay);
        return this.connect(attempt + 1);
      }

      throw new Error(`Gagal konek ke router ${host}: ${err.message}`);
    }
  }

  /** Tutup koneksi dan hapus dari pool. */
  disconnect() {
    const api = pool[this.poolKey];
    if (api) {
      api.close();
      delete pool[this.poolKey];
    }
  }

  // ── Cache ─────────────────────────────────────────────────────────────────

  invalidateCache() {
    delete cache[this.cacheKey];
  }

  // ── Peers ─────────────────────────────────────────────────────────────────

  /**
   * Ambil semua WireGuard peers untuk server ini.
   *
   * @param  {boolean} forceRefresh — bypass TTL cache
   * @returns {Promise<object[]>}
   */
  async getPeers(forceRefresh = false) {
    const hit = cache[this.cacheKey];
    if (!forceRefresh && hit && Date.now() - hit.ts < CACHE_TTL)
      return hit.data;

    const api = await this.connect();
    const peers = await api.write([
      "/interface/wireguard/peers/print",
      `?interface=${this.srv.wgInterface}`,
    ]);

    const result = peers.map((p) => this._parsePeer(p));
    cache[this.cacheKey] = { data: result, ts: Date.now() };
    return result;
  }

  /**
   * Normalisasi satu peer dari RouterOS ke format standar aplikasi.
   * @private
   */
  _parsePeer(peer) {
    const name = peer.name || "Unknown";

    // Private key disimpan di comment sebagai JSON saat peer dibuat via API ini.
    // Peer yang dibuat manual (Winbox/WebFig) tidak punya privkey → QR tidak bisa digenerate.
    let privkey = null;
    try {
      const parsed = JSON.parse(peer.comment || "{}");
      privkey = parsed.privkey ?? null;
    } catch {
      // bukan JSON — peer manual, skip
    }

    const addrs = (peer["allowed-address"] || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    const ipv4 = addrs.find((a) => a.includes("."))?.split("/")[0] ?? "-";
    const ipv6 = addrs.find((a) => a.includes(":"))?.split("/")[0] ?? "-";
    const enabled = peer.disabled !== "true" && peer.disabled !== true;

    return { ...peer, name, privkey, ipv4, ipv6, enabled };
  }

  /**
   * Ambil public key interface WireGuard di sisi server.
   * @returns {Promise<string>}
   */
  async getServerPublicKey() {
    const api = await this.connect();
    const result = await api.write([
      "/interface/wireguard/print",
      `?name=${this.srv.wgInterface}`,
    ]);

    if (!result?.length)
      throw new Error(
        `Interface '${this.srv.wgInterface}' tidak ditemukan di router`,
      );

    return result[0]["public-key"];
  }

  /**
   * Tambah WireGuard peer baru.
   *
   * @param {object} data
   * @param {string} data.name
   * @param {string} data.ipv4
   * @param {string} data.ipv6
   * @param {string} data.publicKey
   * @param {string} data.privateKey
   */
  async addPeer({ name, ipv4, ipv6, publicKey, privateKey }) {
    if (!name?.trim()) throw new Error("Nama peer wajib diisi");
    if (!ipv4?.trim()) throw new Error("IPv4 wajib diisi");
    if (!ipv6?.trim()) throw new Error("IPv6 wajib diisi");
    if (!publicKey?.trim()) throw new Error("Public key wajib diisi");

    const v4 = ipv4.trim();
    const v6 = ipv6.trim();

    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(v4))
      throw new Error(`IPv4 tidak valid: ${v4}`);
    if (!v6.includes(":")) throw new Error(`IPv6 tidak valid: ${v6}`);

    const comment = JSON.stringify({
      privkey: privateKey,
      created_at: new Date().toISOString(),
    });

    const api = await this.connect();
    await api.write([
      "/interface/wireguard/peers/add",
      `=interface=${this.srv.wgInterface}`,
      `=name=${name.trim()}`,
      `=public-key=${publicKey.trim()}`,
      `=allowed-address=${v4}/32,${v6}/128`,
      `=comment=${comment}`,
    ]);

    this.invalidateCache();
  }

  /**
   * Enable / disable peer.
   *
   * @param {string}  id            — RouterOS .id (e.g. "*1")
   * @param {boolean} shouldDisable — true = disable, false = enable
   */
  async togglePeer(id, shouldDisable) {
    if (!id) throw new Error("Peer ID tidak boleh kosong");
    const api = await this.connect();
    await api.write([
      "/interface/wireguard/peers/set",
      `=.id=${id}`,
      `=disabled=${shouldDisable ? "yes" : "no"}`,
    ]);
    this.invalidateCache();
  }

  /**
   * Hapus peer dari router.
   *
   * @param {string} id — RouterOS .id
   */
  async removePeer(id) {
    if (!id) throw new Error("Peer ID tidak boleh kosong");
    const api = await this.connect();
    await api.write(["/interface/wireguard/peers/remove", `=.id=${id}`]);
    this.invalidateCache();
  }
}

// ─── Helper ───────────────────────────────────────────────────────────────────
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

module.exports = MikrotikService;
