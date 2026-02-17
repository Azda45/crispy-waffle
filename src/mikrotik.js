const net = require("net");
const config = require("./config");

// ─── Low-level RouterOS API encoder/decoder ───────────────────────────────

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
  return Buffer.from([
    ((len >> 24) & 0x0f) | 0xe0,
    (len >> 16) & 0xff,
    (len >> 8) & 0xff,
    len & 0xff,
  ]);
}

function encodeWord(word) {
  const wordBuf = Buffer.from(word, "utf8");
  return Buffer.concat([encodeLength(wordBuf.length), wordBuf]);
}

function encodeSentence(words) {
  return Buffer.concat([...words.map(encodeWord), Buffer.from([0x00])]);
}

function decodePackets(buffer) {
  const sentences = [];
  let i = 0;
  while (i < buffer.length) {
    const sentence = [];
    while (i < buffer.length) {
      let len, skip;
      const b = buffer[i];
      if ((b & 0xe0) === 0xe0) {
        len =
          ((b & 0x0f) << 24) |
          (buffer[i + 1] << 16) |
          (buffer[i + 2] << 8) |
          buffer[i + 3];
        skip = 4;
      } else if ((b & 0xc0) === 0xc0) {
        len = ((b & 0x1f) << 16) | (buffer[i + 1] << 8) | buffer[i + 2];
        skip = 3;
      } else if ((b & 0x80) === 0x80) {
        len = ((b & 0x3f) << 8) | buffer[i + 1];
        skip = 2;
      } else {
        len = b;
        skip = 1;
      }
      i += skip;
      if (len === 0) {
        sentences.push(sentence);
        break;
      }
      sentence.push(buffer.slice(i, i + len).toString("utf8"));
      i += len;
    }
  }
  return sentences;
}

function rosConnect(host, port, user, password, timeout = 15) {
  return new Promise((resolve, reject) => {
    const sock = new net.Socket();
    sock.setTimeout(timeout * 1000);

    let buf = Buffer.alloc(0);
    let loggedIn = false;
    let pendingResolve = null;
    let pendingReject = null;
    let pendingData = [];

    sock.connect(port, host, () => {
      sock.write(
        encodeSentence(["/login", `=name=${user}`, `=password=${password}`]),
      );
    });

    sock.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const sentences = decodePackets(buf);
      buf = Buffer.alloc(0);

      for (const sentence of sentences) {
        if (!sentence.length) continue;
        const type = sentence[0];

        if (!loggedIn) {
          if (type === "!done") {
            loggedIn = true;
            resolve(api);
          } else if (type === "!trap" || type === "!fatal") {
            const msg =
              sentence.find((w) => w.startsWith("=message="))?.slice(9) ||
              "Login failed";
            reject(new Error(msg));
            sock.destroy();
          }
          continue;
        }

        pendingData.push(sentence);

        if (["!done", "!empty", "!trap", "!fatal"].includes(type)) {
          const res = pendingResolve;
          const rej = pendingReject;
          const data = [...pendingData];
          pendingResolve = null;
          pendingReject = null;
          pendingData = [];

          if (!res) continue;

          if (type === "!trap" || type === "!fatal") {
            const msg =
              data
                .flat()
                .find((w) => w?.startsWith("=message="))
                ?.slice(9) || "RouterOS error";
            rej(new Error(msg));
          } else {
            const rows = data
              .filter((s) => s[0] === "!re")
              .map((s) => {
                const obj = {};
                s.slice(1).forEach((w) => {
                  const eq = w.indexOf("=", 1);
                  if (eq > 0) obj[w.slice(1, eq)] = w.slice(eq + 1);
                });
                return obj;
              });
            res(rows);
          }
        }
      }
    });

    sock.on("timeout", () => {
      reject(new Error("Connection timeout"));
      sock.destroy();
    });
    sock.on("error", (err) => {
      if (!loggedIn) reject(err);
    });
    sock.on("close", () => {
      // Hapus dari pool kalau koneksi mati
      for (const key of Object.keys(pool)) {
        if (pool[key] === api) {
          delete pool[key];
          console.log(`[Mikrotik] Koneksi ${key} closed, dihapus dari pool`);
        }
      }
      if (pendingReject) {
        pendingReject(new Error("Connection closed unexpectedly"));
        pendingReject = null;
        pendingResolve = null;
      }
    });

    const api = {
      write(words) {
        return new Promise((res, rej) => {
          pendingResolve = res;
          pendingReject = rej;
          pendingData = [];
          sock.write(encodeSentence(words));
        });
      },
      close() {
        sock.destroy();
      },
    };
  });
}

// ─── Singleton connection pool ────────────────────────────────────────────
const pool = {};

// ─── Peers cache (TTL 5 detik) — biar refresh berasa instant ─────────────
const cache = {};
const CACHE_TTL = 5000; // ms

class MikrotikService {
  constructor(serverId = 0) {
    this.serverConfig =
      config.servers.find((s) => s.id == serverId) || config.servers[0];
    this.poolKey = `srv_${this.serverConfig.id}`;
    this.cacheKey = `peers_${this.serverConfig.id}`;
  }

  async connect(attempt = 1) {
    if (pool[this.poolKey]) return pool[this.poolKey];

    try {
      console.log(`[Mikrotik] Connecting to ${this.serverConfig.host}...`);
      const api = await rosConnect(
        this.serverConfig.host,
        this.serverConfig.port,
        this.serverConfig.user,
        this.serverConfig.password,
        config.routeros.timeout,
      );
      pool[this.poolKey] = api;
      console.log("[Mikrotik] Connected!");
      return api;
    } catch (error) {
      delete pool[this.poolKey];
      console.error(
        `[Mikrotik] Failed (Attempt ${attempt}/${config.routeros.maxRetries}): ${error.message}`,
      );
      if (attempt < config.routeros.maxRetries) {
        await new Promise((r) => setTimeout(r, config.routeros.retryDelay));
        return this.connect(attempt + 1);
      }
      throw new Error(`Gagal konek ke router: ${error.message}`);
    }
  }

  invalidateCache() {
    delete cache[this.cacheKey];
  }

  async getPeers(forceRefresh = false) {
    // Serve dari cache kalau masih fresh
    const cached = cache[this.cacheKey];
    if (!forceRefresh && cached && Date.now() - cached.ts < CACHE_TTL) {
      return cached.data;
    }

    const api = await this.connect();
    const peers = await api.write([
      "/interface/wireguard/peers/print",
      `?interface=${this.serverConfig.wgInterface}`,
    ]);

    const result = peers.map((peer) => {
      // Nama langsung dari field 'name' RouterOS — sama persis seperti di Winbox/WebFig
      const name = peer.name || "Unknown";

      // Comment hanya berisi privkey untuk generate QR
      let privkey = null;
      try {
        const parsed = JSON.parse(peer.comment || "{}");
        privkey = parsed.privkey || null;
      } catch (e) {
        // Peer dibuat manual (comment bukan JSON) — privkey null, QR tidak bisa digenerate
      }

      const addrs = (peer["allowed-address"] || "")
        .split(",")
        .map((s) => s.trim());
      const ipv4 = addrs.find((a) => a.includes("."))?.split("/")[0] || "-";
      const ipv6 = addrs.find((a) => a.includes(":"))?.split("/")[0] || "-";

      return { ...peer, name, privkey, ipv4, ipv6 };
    });

    // Simpan ke cache
    cache[this.cacheKey] = { data: result, ts: Date.now() };
    return result;
  }

  async getServerPublicKey() {
    const api = await this.connect();
    const result = await api.write([
      "/interface/wireguard/print",
      `?name=${this.serverConfig.wgInterface}`,
    ]);
    if (!result || result.length === 0)
      throw new Error(
        `Interface '${this.serverConfig.wgInterface}' tidak ditemukan`,
      );
    return result[0]["public-key"];
  }

  async addPeer(data) {
    if (!data.name?.trim()) throw new Error("Nama peer wajib diisi");
    if (!data.ipv4?.trim()) throw new Error("IPv4 wajib diisi");
    if (!data.ipv6?.trim()) throw new Error("IPv6 wajib diisi");

    const ipv4 = data.ipv4.trim();
    const ipv6 = data.ipv6.trim();

    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ipv4))
      throw new Error(`IPv4 tidak valid: ${ipv4}`);
    if (!ipv6.includes(":")) throw new Error(`IPv6 tidak valid: ${ipv6}`);

    const api = await this.connect();
    // name disimpan di field =name RouterOS (terlihat di Winbox/WebFig)
    // comment hanya untuk privkey agar bisa generate QR code
    const commentJSON = JSON.stringify({
      privkey: data.privateKey,
      created_at: new Date().toISOString(),
    });

    await api.write([
      "/interface/wireguard/peers/add",
      `=interface=${this.serverConfig.wgInterface}`,
      `=name=${data.name.trim()}`,
      `=public-key=${data.publicKey}`,
      `=allowed-address=${ipv4}/32,${ipv6}/128`,
      `=comment=${commentJSON}`,
    ]);

    this.invalidateCache(); // cache stale setelah add
  }

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

  async removePeer(id) {
    if (!id) throw new Error("Peer ID tidak boleh kosong");
    const api = await this.connect();
    await api.write(["/interface/wireguard/peers/remove", `=.id=${id}`]);
    this.invalidateCache();
  }
}

module.exports = MikrotikService;
