#!/usr/bin/env node
"use strict";

/**
 * get-fingerprint.js
 *
 * Koneksi TLS ke semua server di .env, ambil SHA-256 fingerprint cert,
 * lalu simpan hasilnya ke fingerprints.txt (bukan di-print ke console).
 *
 * Usage:
 *   node get-fingerprint.js                   # scan semua server dari .env
 *   node get-fingerprint.js 192.168.1.1       # host manual, port default 8729
 *   node get-fingerprint.js 192.168.1.1 8729  # host + port manual
 *
 * Output:
 *   fingerprints.txt  — hasil fingerprint semua server, siap copy ke .env
 */

require("dotenv").config();

const tls = require("tls");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const OUT_FILE = path.resolve("fingerprints.txt");

// ─── Ambil fingerprint dari satu host:port ────────────────────────────────────

function getFingerprint(host, port = 8729) {
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port, rejectUnauthorized: false }, () => {
      const cert = sock.getPeerCertificate(true);
      sock.destroy();

      if (!cert?.raw) {
        reject(new Error("Tidak ada certificate dari server"));
        return;
      }

      const fp = crypto
        .createHash("sha256")
        .update(cert.raw)
        .digest("hex")
        .match(/.{2}/g)
        .join(":")
        .toUpperCase();

      resolve({
        fingerprint: fp,
        subject: cert.subject?.CN || cert.subject?.O || "(unknown)",
        issuer: cert.issuer?.CN || cert.issuer?.O || "(unknown)",
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        selfSigned: cert.subject?.CN === cert.issuer?.CN,
      });
    });

    sock.setTimeout(10_000);
    sock.on("timeout", () => {
      sock.destroy();
      reject(new Error("Connection timeout"));
    });
    sock.on("error", (err) => reject(err));
  });
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);

  // ── Kumpulkan target ────────────────────────────────────────────────────────
  let targets = [];

  if (args.length >= 1) {
    // Mode manual: node get-fingerprint.js <host> [port]
    targets.push({
      index: null,
      name: "Manual",
      host: args[0],
      port: parseInt(args[1]) || 8729,
      envKey: null,
    });
  } else {
    // Mode .env: scan S0_HOST, S1_HOST, S2_HOST, ... sampai kosong
    for (let i = 0; ; i++) {
      const host = process.env[`S${i}_HOST`]?.trim();
      if (!host) break;

      const port = parseInt(process.env[`S${i}_PORT`]) || 8729;
      const tlsEnv = process.env[`S${i}_TLS`];
      const useTls = tlsEnv !== undefined ? tlsEnv === "true" : port === 8729;

      if (!useTls) {
        targets.push({
          index: i,
          name: process.env[`S${i}_NAME`] || `Router-${i}`,
          host,
          port,
          skip: true,
        });
        continue;
      }

      targets.push({
        index: i,
        name: process.env[`S${i}_NAME`]?.trim() || `Router-${i}`,
        host,
        port,
        envKey: `S${i}_TLS_FINGERPRINT`,
        skip: false,
      });
    }

    if (!targets.length) {
      console.error("❌  Tidak ada server di .env");
      console.error("    Gunakan: node get-fingerprint.js <host> [port]");
      process.exit(1);
    }
  }

  // ── Proses semua target ─────────────────────────────────────────────────────
  const lines = []; // isi fingerprints.txt
  const timestamp = new Date().toISOString();

  lines.push("# ════════════════════════════════════════════════════════════");
  lines.push("# WireGuard Manager — TLS Fingerprints");
  lines.push(`# Generated : ${timestamp}`);
  lines.push(`# Servers   : ${targets.length}`);
  lines.push("# ════════════════════════════════════════════════════════════");
  lines.push("");

  let successCount = 0;
  let failCount = 0;

  for (const t of targets) {
    console.log(`[${t.index ?? "-"}] ${t.name} (${t.host}:${t.port})...`);

    // Server ini non-TLS, skip
    if (t.skip) {
      console.log(`     SKIP — TLS tidak aktif`);
      lines.push(
        `# [SKIP] S${t.index} "${t.name}" (${t.host}:${t.port}) — TLS tidak aktif`,
      );
      lines.push("");
      continue;
    }

    try {
      const r = await getFingerprint(t.host, t.port);
      successCount++;

      console.log(`     ✓ ${r.fingerprint}`);

      const selfSign = r.selfSigned ? " (self-signed)" : "";

      lines.push(
        `# ── ${t.index !== null ? `S${t.index}` : "Manual"} — ${t.name}${selfSign}`,
      );
      lines.push(`# Host      : ${t.host}:${t.port}`);
      lines.push(`# Subject   : ${r.subject}`);
      lines.push(`# Issuer    : ${r.issuer}`);
      lines.push(`# Valid     : ${r.validFrom}  →  ${r.validTo}`);
      lines.push(`# SHA-256   : ${r.fingerprint}`);
      lines.push(`#`);
      // Baris env langsung bisa di-copy ke .env
      if (t.envKey) {
        lines.push(`${t.envKey}=${r.fingerprint}`);
      } else {
        lines.push(`# S?_TLS_FINGERPRINT=${r.fingerprint}`);
      }
      lines.push("");
    } catch (err) {
      failCount++;
      console.log(`     ✗ GAGAL — ${err.message}`);

      lines.push(
        `# ── ${t.index !== null ? `S${t.index}` : "Manual"} — ${t.name}`,
      );
      lines.push(`# Host      : ${t.host}:${t.port}`);
      lines.push(`# ERROR     : ${err.message}`);
      if (t.envKey) {
        lines.push(`# ${t.envKey}=<GAGAL — isi manual>`);
      }
      lines.push("");
    }
  }

  // ── Summary ─────────────────────────────────────────────────────────────────
  lines.push("# ════════════════════════════════════════════════════════════");
  lines.push(`# Total: ${successCount} berhasil, ${failCount} gagal`);
  lines.push("# ════════════════════════════════════════════════════════════");

  // ── Tulis file ───────────────────────────────────────────────────────────────
  fs.writeFileSync(OUT_FILE, lines.join("\n") + "\n", "utf8");

  console.log("");
  console.log(`✅  Hasil disimpan ke: ${OUT_FILE}`);
  if (failCount > 0)
    console.log(`⚠   ${failCount} server gagal — periksa koneksi / port.`);
}

main().catch((err) => {
  console.error("Fatal:", err.message);
  process.exit(1);
});
