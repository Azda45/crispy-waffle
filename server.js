const express = require("express");
const bodyParser = require("body-parser");
const QRCode = require("qrcode");
const config = require("./src/config");
const MikrotikService = require("./src/mikrotik");
const { generateKeypair } = require("./src/crypto");
const { generateName, findNextFreeIP, isIPTaken } = require("./src/generator");

const app = express();

app.set("view engine", "ejs");
app.set("views", "./views");
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// ─── Dashboard ────────────────────────────────────────────────────────────
app.get("/", async (req, res) => {
  try {
    const service = new MikrotikService(0);
    const peers = await service.getPeers();
    res.render("index", { peers, server: config.servers[0], error: null });
  } catch (err) {
    console.error("[Route /]", err.message);
    res.render("index", {
      peers: [],
      server: config.servers[0],
      error: err.message,
    });
  }
});

// ─── Suggest nama + IP kosong ─────────────────────────────────────────────
// Dipanggil saat modal Add dibuka — biar tidak perlu isi manual
app.get("/suggest", async (req, res) => {
  try {
    const service = new MikrotikService(0);
    const peers = await service.getPeers(); // ambil dari cache kalau masih fresh
    const srv = config.servers[0];

    const existingNames = peers.map((p) => p.name).filter(Boolean);
    const name = generateName(existingNames);
    const { ipv4, ipv6 } = findNextFreeIP(
      peers,
      srv.ipv4Prefix,
      srv.ipv6Prefix,
    );

    res.json({ success: true, name, ipv4, ipv6 });
  } catch (err) {
    console.error("[Route /suggest]", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Add Peer ─────────────────────────────────────────────────────────────
app.post("/add", async (req, res) => {
  const { name, ipv4, ipv6 } = req.body;

  if (!name?.trim())
    return res
      .status(400)
      .json({ success: false, error: "Nama peer wajib diisi" });
  if (!ipv4?.trim())
    return res.status(400).json({ success: false, error: "IPv4 wajib diisi" });
  if (!ipv6?.trim())
    return res.status(400).json({ success: false, error: "IPv6 wajib diisi" });

  try {
    const service = new MikrotikService(0);
    const peers = await service.getPeers(true); // force refresh untuk cek duplikat akurat

    const conflict = isIPTaken(peers, ipv4.trim(), ipv6.trim());
    if (conflict.taken) {
      return res.status(409).json({
        success: false,
        error: `${conflict.which} ${conflict.ip} sudah dipakai peer lain`,
      });
    }

    const keys = generateKeypair();
    await service.addPeer({ ...req.body, ...keys });
    res.json({ success: true });
  } catch (err) {
    console.error("[Route /add]", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Toggle Peer ──────────────────────────────────────────────────────────
app.post("/toggle", async (req, res) => {
  const { id, enabled } = req.body;
  if (!id)
    return res.status(400).json({ success: false, error: "id wajib diisi" });

  try {
    const service = new MikrotikService(0);
    // 'enabled' from the client means the peer is currently active.
    // The toggle action is therefore to disable it.
    const shouldDisable = enabled === true || enabled === "true";
    await service.togglePeer(id, shouldDisable);
    res.json({ success: true });
  } catch (err) {
    console.error("[Route /toggle]", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Delete Peer ──────────────────────────────────────────────────────────
app.post("/delete", async (req, res) => {
  const { id } = req.body;
  if (!id)
    return res.status(400).json({ success: false, error: "id wajib diisi" });

  try {
    const service = new MikrotikService(0);
    await service.removePeer(id);
    res.json({ success: true });
  } catch (err) {
    console.error("[Route /delete]", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── QR Code ──────────────────────────────────────────────────────────────
app.post("/qrcode", async (req, res) => {
  const { privkey, ipv4, ipv6 } = req.body;

  if (!privkey?.trim())
    return res
      .status(400)
      .json({ success: false, error: "privkey wajib diisi" });
  if (!ipv4?.trim())
    return res.status(400).json({ success: false, error: "IPv4 wajib diisi" });
  if (!ipv6?.trim())
    return res.status(400).json({ success: false, error: "IPv6 wajib diisi" });

  try {
    const service = new MikrotikService(0);
    const serverPubKey = await service.getServerPublicKey();
    const { wireguard } = config;

    const wgConfig = [
      `[Interface]`,
      `PrivateKey = ${privkey.trim()}`,
      `Address = ${ipv4.trim()}/${wireguard.ipv4Cidr}, ${ipv6.trim()}/${wireguard.ipv6Cidr}`,
      `DNS = ${wireguard.dns}`,
      ``,
      `[Peer]`,
      `PublicKey = ${serverPubKey}`,
      `Endpoint = ${config.servers[0].host}:${config.servers[0].wgPort}`,
      `AllowedIPs = ${wireguard.allowedIps}`,
      `PersistentKeepalive = ${wireguard.persistentKeepalive}`,
    ].join("\n");

    const qr = await QRCode.toDataURL(wgConfig);
    res.json({ success: true, qrcode: qr, configText: wgConfig });
  } catch (err) {
    console.error("[Route /qrcode]", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(config.app.port, () =>
  console.log(`Server running at http://localhost:${config.app.port}`),
);
