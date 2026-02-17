// ─── Name generator ──────────────────────────────────────────────────────

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

function generateName(existingNames = []) {
  const existing = new Set(existingNames.map((n) => n?.toLowerCase()));
  let attempts = 0;
  while (attempts < 100) {
    const adj = ADJECTIVES[Math.floor(Math.random() * ADJECTIVES.length)];
    const noun = NOUNS[Math.floor(Math.random() * NOUNS.length)];
    const number = Math.floor(Math.random() * 90) + 10; // 2 digit random number
    const name = `${adj}-${noun}-${number}`;
    if (!existing.has(name.toLowerCase())) return name;
    attempts++;
  }
  return `Peer${Math.floor(Math.random() * 9000) + 1000}`;
}

// ─── IP generator ─────────────────────────────────────────────────────────

function parseLastOctetV4(ip) {
  const parts = ip.trim().split(".");
  return parseInt(parts[3]) || 0;
}

function parseLastSegmentV6(ip) {
  const trimmed = ip.trim();
  const afterDoubleColon = trimmed.split("::")[1];
  if (!afterDoubleColon) return 0;
  const segments = afterDoubleColon.split(":");
  return parseInt(segments[segments.length - 1], 16) || 0;
}

function findNextFreeIP(peers, ipv4Prefix, ipv6Prefix) {
  const usedV4 = new Set();
  const usedV6 = new Set();
  for (const peer of peers) {
    if (peer.ipv4 && peer.ipv4 !== "-") usedV4.add(parseLastOctetV4(peer.ipv4));
    if (peer.ipv6 && peer.ipv6 !== "-")
      usedV6.add(parseLastSegmentV6(peer.ipv6));
  }
  for (let host = 2; host <= 253; host++) {
    if (!usedV4.has(host) && !usedV6.has(host)) {
      return {
        ipv4: `${ipv4Prefix}${host}`,
        ipv6: `${ipv6Prefix}${host}`,
      };
    }
  }
  throw new Error("Tidak ada IP kosong tersisa (host 2-253 semua terpakai)");
}

function isIPTaken(peers, ipv4, ipv6) {
  for (const peer of peers) {
    if (peer.ipv4 === ipv4) return { taken: true, which: "IPv4", ip: ipv4 };
    if (peer.ipv6 === ipv6) return { taken: true, which: "IPv6", ip: ipv6 };
  }
  return { taken: false };
}

module.exports = { generateName, findNextFreeIP, isIPTaken };
