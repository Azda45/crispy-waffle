"use strict";

const express = require("express");
const QRCode = require("qrcode");
const config = require("./src/config");
const MikrotikService = require("./src/mikrotik");
const { generateKeypair } = require("./src/crypto");
const { generateName, findNextFreeIP, isIPTaken } = require("./src/generator");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Resolve :server URL param → server ID yang valid.
 * Throw 404 kalau tidak ditemukan agar error handler menanganinya dengan benar.
 */
function resolveServer(raw) {
  const id = parseInt(raw, 10);
  const srv = config.servers.find((s) => s.id === id);
  if (!srv) {
    const available = config.servers.map((s) => s.id).join(", ");
    const err = new Error(
      `Server ID ${raw} tidak ditemukan. Server tersedia: ${available}`,
    );
    err.status = 404;
    throw err;
  }
  return id;
}

/**
 * Wrapper untuk async route handler agar promise rejection
 * diteruskan ke Express error handler (diperlukan di Express 4).
 */
const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

// ─── GET /api/servers ─────────────────────────────────────────────────────────
app.get("/api/servers", (_req, res) => {
  res.json({
    success: true,
    servers: config.servers.map((s) => ({
      id: s.id,
      name: s.name,
      host: s.host,
      tls: s.tls,
    })),
  });
});

// ─── GET /api/:server/peers ───────────────────────────────────────────────────
app.get(
  "/api/:server/peers",
  wrap(async (req, res) => {
    const serverId = resolveServer(req.params.server);
    const svc = new MikrotikService(serverId);
    const peers = await svc.getPeers();
    const srv = config.servers.find((s) => s.id === serverId);
    res.json({
      success: true,
      peers,
      server: { id: srv.id, name: srv.name, host: srv.host },
    });
  }),
);

// ─── GET /api/:server/suggest ─────────────────────────────────────────────────
app.get(
  "/api/:server/suggest",
  wrap(async (req, res) => {
    const serverId = resolveServer(req.params.server);
    const svc = new MikrotikService(serverId);
    const peers = await svc.getPeers();
    const srv = config.servers.find((s) => s.id === serverId);

    const name = generateName(peers.map((p) => p.name).filter(Boolean));
    const { ipv4, ipv6 } = findNextFreeIP(
      peers,
      srv.ipv4Prefix,
      srv.ipv6Prefix,
    );

    res.json({ success: true, name, ipv4, ipv6 });
  }),
);

// ─── POST /api/:server/peers ──────────────────────────────────────────────────
app.post(
  "/api/:server/peers",
  wrap(async (req, res) => {
    const serverId = resolveServer(req.params.server);
    const { name, ipv4, ipv6 } = req.body;

    if (!name?.trim())
      return res
        .status(400)
        .json({ success: false, error: "Nama peer wajib diisi" });
    if (!ipv4?.trim())
      return res
        .status(400)
        .json({ success: false, error: "IPv4 wajib diisi" });
    if (!ipv6?.trim())
      return res
        .status(400)
        .json({ success: false, error: "IPv6 wajib diisi" });

    const svc = new MikrotikService(serverId);
    const peers = await svc.getPeers(true); // force refresh sebelum cek konflik

    const conflict = isIPTaken(peers, ipv4.trim(), ipv6.trim());
    if (conflict.taken)
      return res.status(409).json({
        success: false,
        error: `${conflict.which} ${conflict.ip} sudah dipakai peer lain`,
      });

    const keys = generateKeypair();
    await svc.addPeer({
      name: name.trim(),
      ipv4: ipv4.trim(),
      ipv6: ipv6.trim(),
      ...keys,
    });

    // Ambil data peer yang baru saja ditambahkan
    const fresh = await svc.getPeers(true);
    const added =
      fresh.find(
        (p) =>
          p.name === name.trim() &&
          (p.ipv4 === ipv4.trim() || p.ipv6 === ipv6.trim()),
      ) ?? null;

    res.status(201).json({ success: true, peer: added });
  }),
);

// ─── PATCH /api/:server/peers/:id/toggle ─────────────────────────────────────
app.patch(
  "/api/:server/peers/:id/toggle",
  wrap(async (req, res) => {
    const serverId = resolveServer(req.params.server);
    const { id } = req.params;
    const { enabled } = req.body;

    if (!id)
      return res
        .status(400)
        .json({ success: false, error: "Peer ID wajib diisi" });

    // enabled=true  → peer saat ini aktif → kita DISABLE
    // enabled=false → peer saat ini nonaktif → kita ENABLE
    const shouldDisable = enabled === true || enabled === "true";

    const svc = new MikrotikService(serverId);
    await svc.togglePeer(id, shouldDisable);
    res.json({ success: true, disabled: shouldDisable });
  }),
);

// ─── DELETE /api/:server/peers/:id ───────────────────────────────────────────
app.delete(
  "/api/:server/peers/:id",
  wrap(async (req, res) => {
    const serverId = resolveServer(req.params.server);
    const { id } = req.params;

    if (!id)
      return res
        .status(400)
        .json({ success: false, error: "Peer ID wajib diisi" });

    const svc = new MikrotikService(serverId);
    await svc.removePeer(id);
    res.json({ success: true });
  }),
);

// ─── POST /api/:server/peers/:id/qrcode ──────────────────────────────────────
app.post(
  "/api/:server/peers/:id/qrcode",
  wrap(async (req, res) => {
    const serverId = resolveServer(req.params.server);
    const { privkey, ipv4, ipv6 } = req.body;

    if (!privkey?.trim())
      return res
        .status(400)
        .json({ success: false, error: "privkey wajib diisi" });
    if (!ipv4?.trim())
      return res
        .status(400)
        .json({ success: false, error: "IPv4 wajib diisi" });
    if (!ipv6?.trim())
      return res
        .status(400)
        .json({ success: false, error: "IPv6 wajib diisi" });

    const svc = new MikrotikService(serverId);
    const serverPubKey = await svc.getServerPublicKey();
    const { wireguard } = config;
    const srv = config.servers.find((s) => s.id === serverId);

    const wgConfig = [
      "[Interface]",
      `PrivateKey = ${privkey.trim()}`,
      `Address = ${ipv4.trim()}/${wireguard.ipv4Cidr}, ${ipv6.trim()}/${wireguard.ipv6Cidr}`,
      `DNS = ${wireguard.dns}`,
      "",
      "[Peer]",
      `PublicKey = ${serverPubKey}`,
      `Endpoint = ${srv.host}:${srv.wgPort}`,
      `AllowedIPs = ${wireguard.allowedIps}`,
      `PersistentKeepalive = ${wireguard.persistentKeepalive}`,
    ].join("\n");

    const qrcode = await QRCode.toDataURL(wgConfig);
    res.json({ success: true, qrcode, configText: wgConfig });
  }),
);

// ─── 404 ─────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, error: "Endpoint tidak ditemukan" });
});

// ─── Global error handler ─────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  if (status >= 500) console.error("[Error]", err.stack ?? err.message);
  res.status(status).json({ success: false, error: err.message });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(config.app.port, () => {
  console.log(
    `\n✅  WG Manager API running → http://localhost:${config.app.port}`,
  );
  console.log(
    `    Servers aktif: ${config.servers.map((s) => `${s.name} (${s.host})`).join(", ")}`,
  );
});
