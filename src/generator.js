"use strict";

// ─── Name generator ───────────────────────────────────────────────────────────

const ADJECTIVES = [
  "Swift",
  "Clever",
  "Mighty",
  "Noble",
  "Brave",
  "Silent",
  "Golden",
  "Storm",
  "Lunar",
  "Solar",
  "Cyber",
  "Neon",
  "Frost",
  "Blaze",
  "Echo",
  "Shadow",
  "Mystic",
  "Royal",
  "Cosmic",
  "Arctic",
];

const NOUNS = [
  "Phoenix",
  "Dragon",
  "Tiger",
  "Eagle",
  "Wolf",
  "Falcon",
  "Raven",
  "Lion",
  "Bear",
  "Hawk",
  "Lynx",
  "Puma",
  "Cobra",
  "Viper",
  "Panther",
  "Jaguar",
  "Orca",
  "Shark",
  "Rhino",
  "Bison",
];

// Total kombinasi = 20 * 20 * 90 = 36.000 — lebih dari cukup

/**
 * Generate nama peer unik yang belum ada di existingNames.
 * Format: Adjective-Noun-NN  (e.g. "Swift-Phoenix-42")
 *
 * @param  {string[]} existingNames
 * @returns {string}
 */
function generateName(existingNames = []) {
  const existing = new Set(existingNames.map((n) => n?.toLowerCase().trim()));

  for (let attempt = 0; attempt < 500; attempt++) {
    const adj = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
    const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
    const num = String(Math.floor(Math.random() * 90) + 10); // 10–99
    const name = `${adj}-${noun}-${num}`;
    if (!existing.has(name.toLowerCase())) return name;
  }

  // Fallback: timestamp agar nama selalu unik
  return `Peer-${Date.now()}`;
}

// ─── IP generator ─────────────────────────────────────────────────────────────

/**
 * Parse last octet IPv4 dari string IP (tanpa prefix length).
 * "10.10.10.5"  → 5
 * "10.10.10.5/32" → 5
 *
 * @param  {string} ip
 * @returns {number|null}
 */
function parseLastOctetV4(ip) {
  if (!ip || ip === "-") return null;
  const clean = ip.trim().split("/")[0];
  const parts = clean.split(".");
  const last = parseInt(parts[3], 10);
  return isNaN(last) ? null : last;
}

/**
 * Parse last hex segment dari IPv6 compressed address.
 * "fd00:10:10::5"  → 5
 * "fd00:10:10::1f" → 31
 *
 * @param  {string} ip
 * @returns {number|null}
 */
function parseLastSegmentV6(ip) {
  if (!ip || ip === "-") return null;
  const clean = ip.trim().split("/")[0];
  const idx = clean.lastIndexOf(":");
  if (idx < 0) return null;
  const last = parseInt(clean.slice(idx + 1), 16);
  return isNaN(last) ? null : last;
}

/**
 * Cari host ID bebas berikutnya (range 2–253) yang tidak dipakai
 * baik di IPv4 maupun IPv6 secara bersamaan.
 *
 * IPv6 di-generate dalam hex (e.g. "fd00:10:10::1a" untuk host 26).
 *
 * @param  {object[]} peers
 * @param  {string}   ipv4Prefix  — e.g. "10.10.10."
 * @param  {string}   ipv6Prefix  — e.g. "fd00:10:10::"
 * @returns {{ ipv4: string, ipv6: string }}
 */
function findNextFreeIP(peers, ipv4Prefix, ipv6Prefix) {
  const usedV4 = new Set();
  const usedV6 = new Set();

  for (const peer of peers) {
    const v4 = parseLastOctetV4(peer.ipv4);
    const v6 = parseLastSegmentV6(peer.ipv6);
    if (v4 !== null) usedV4.add(v4);
    if (v6 !== null) usedV6.add(v6);
  }

  for (let host = 2; host <= 253; host++) {
    if (!usedV4.has(host) && !usedV6.has(host)) {
      return {
        ipv4: `${ipv4Prefix}${host}`,
        ipv6: `${ipv6Prefix}${host.toString(16)}`,
      };
    }
  }

  throw new Error("Tidak ada IP kosong tersisa (host 2–253 semua terpakai)");
}

/**
 * Cek apakah IPv4 atau IPv6 sudah dipakai peer lain.
 * Prefix length (/32, /128) diabaikan saat perbandingan.
 *
 * @param  {object[]} peers
 * @param  {string}   ipv4
 * @param  {string}   ipv6
 * @returns {{ taken: boolean, which?: string, ip?: string }}
 */
function isIPTaken(peers, ipv4, ipv6) {
  const norm = (ip) => (ip || "").trim().split("/")[0].toLowerCase();
  const chkV4 = norm(ipv4);
  const chkV6 = norm(ipv6);

  for (const peer of peers) {
    if (norm(peer.ipv4) === chkV4)
      return { taken: true, which: "IPv4", ip: ipv4 };
    if (norm(peer.ipv6) === chkV6)
      return { taken: true, which: "IPv6", ip: ipv6 };
  }
  return { taken: false };
}

module.exports = { generateName, findNextFreeIP, isIPTaken };
