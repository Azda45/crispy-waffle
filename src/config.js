"use strict";

require("dotenv").config();

// ═══════════════════════════════════════════════════════════════════════════════
//  Dynamic server loader
//
//  Server dikonfigurasi via env vars dengan prefix S0_, S1_, S2_, ..., SN_.
//  Loader scan mulai dari S0_ dan berhenti di index pertama yang tidak punya
//  S{N}_HOST — jadi tidak ada "gap" yang diperbolehkan.
//
//  Tidak ada batas maksimum server — tambah sebanyak yang dibutuhkan.
//
//  Contoh 5 server: S0_HOST, S1_HOST, S2_HOST, S3_HOST, S4_HOST
//  Kalau S2_HOST kosong tapi S3_HOST ada → S3 dan seterusnya diabaikan.
// ═══════════════════════════════════════════════════════════════════════════════

function buildServer(index) {
  const P = `S${index}`; // prefix, e.g. "S0"
  const host = process.env[`${P}_HOST`]?.trim() || null;

  // Tidak ada HOST → stop scan
  if (!host) return null;

  const user = process.env[`${P}_USER`]?.trim() || null;
  const password = process.env[`${P}_PASSWORD`]?.trim() || null;

  if (!user || !password) {
    console.warn(
      `[Config] ⚠  Server ${index} (${host}): S${index}_USER atau S${index}_PASSWORD kosong — dilewati`,
    );
    return null;
  }

  const tlsEnv = process.env[`${P}_TLS`];
  const port = parseInt(process.env[`${P}_PORT`]) || 8729;

  // Auto-detect TLS dari port kalau S{N}_TLS tidak di-set eksplisit
  // 8729 = RouterOS API-SSL (default TLS), 8728 = RouterOS API (plain)
  const useTls = tlsEnv !== undefined ? tlsEnv === "true" : port === 8729;

  return {
    id: index,
    name: process.env[`${P}_NAME`]?.trim() || `Router-${index}`,
    host,
    user,
    password,
    port,
    tls: useTls,
    caFingerprint: process.env[`${P}_TLS_FINGERPRINT`]?.trim() || null,
    caCert: process.env[`${P}_TLS_CA`]?.trim() || null,
    wgInterface: process.env[`${P}_WG_INTERFACE`]?.trim() || "wireguard1",
    wgPort: parseInt(process.env[`${P}_WG_PORT`]) || 51820,
    ipv4Prefix: process.env[`${P}_IPV4_PREFIX`]?.trim() || `10.10.${index}.`,
    ipv6Prefix: process.env[`${P}_IPV6_PREFIX`]?.trim() || `fd00:10:${index}::`,
  };
}

// ─── Scan S0, S1, S2, … sampai HOST kosong ────────────────────────────────────

const servers = [];

for (let i = 0; ; i++) {
  // Kalau tidak ada HOST sama sekali untuk index ini → stop
  if (!process.env[`S${i}_HOST`]?.trim()) break;

  const srv = buildServer(i);
  if (srv) servers.push(srv);
  // srv null (user/pass kosong) → skip tapi lanjut scan berikutnya
}

// ─── Validasi minimal 1 server ────────────────────────────────────────────────

if (!servers.length) {
  console.error(`
[Config] ❌ Tidak ada server yang terkonfigurasi.

Minimal butuh satu server dengan env vars berikut:
  S0_HOST=192.168.1.1
  S0_USER=admin
  S0_PASSWORD=secret
  S0_PORT=8729       (opsional, default 8729/TLS)
  S0_TLS=true        (opsional, auto-detect dari port)

Tambah S1_, S2_, dst. untuk server berikutnya.
`);
  process.exit(1);
}

// ─── Log ringkasan server yang aktif ──────────────────────────────────────────

console.log(`[Config] ${servers.length} server terkonfigurasi:`);
for (const s of servers) {
  const proto = s.tls
    ? `TLS:${s.port}${s.caFingerprint ? " + fingerprint✓" : " (no cert verify⚠)"}`
    : `TCP:${s.port} ⚠ (plaintext)`;
  console.log(
    `         [${s.id}] "${s.name}" → ${s.host} via ${proto}  WG: ${s.wgInterface}`,
  );
}

// ═══════════════════════════════════════════════════════════════════════════════
//  Exports
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = {
  app: {
    port: parseInt(process.env.PORT) || 3000,
    debug: process.env.DEBUG === "true",
  },

  routeros: {
    timeout: parseInt(process.env.ROS_TIMEOUT) || 15, // detik
    maxRetries: parseInt(process.env.ROS_MAX_RETRIES) || 3,
    retryDelay: parseInt(process.env.ROS_RETRY_DELAY) || 1000, // ms
  },

  wireguard: {
    dns: process.env.WG_DNS || "1.1.1.1, 1.0.0.1",
    allowedIps: process.env.WG_ALLOWED_IPS || "0.0.0.0/0, ::/0",
    persistentKeepalive: parseInt(process.env.WG_KEEPALIVE) || 25,
    ipv4Cidr: parseInt(process.env.IPV4_CIDR) || 32,
    ipv6Cidr: parseInt(process.env.IPV6_CIDR) || 128,
  },

  servers,
};
