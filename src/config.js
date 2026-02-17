require("dotenv").config();

module.exports = {
  app: {
    port: parseInt(process.env.PORT) || 3000,
    debug: process.env.DEBUG === "true",
  },
  routeros: {
    timeout: 15,
    maxRetries: 3,
    retryDelay: 1000,
  },
  wireguard: {
    dns: "1.1.1.1, 1.0.0.1",
    allowedIps: "0.0.0.0/0, ::/0",
    persistentKeepalive: 25,
    ipv4Cidr: parseInt(process.env.IPV4_CIDR || 32),
    ipv6Cidr: parseInt(process.env.IPV6_CIDR || 128),
  },
  servers: [
    {
      id: 0,
      name: process.env.S0_NAME || "Main Router",
      host: process.env.S0_HOST,
      user: process.env.S0_USER,
      password: process.env.S0_PASSWORD,
      port: parseInt(process.env.S0_PORT) || 8728,
      tls: process.env.S0_TLS === "true", // FIX: boolean, bukan string
      wgInterface: process.env.S0_WG_INTERFACE || "wireguard1",
      wgPort: parseInt(process.env.S0_WG_PORT) || 51820,
      ipv4Prefix: process.env.S0_IPV4_PREFIX || "10.10.10.",
      ipv6Prefix: process.env.S0_IPV6_PREFIX || "fd00:10:10::",
    },
    {
      id: 1,
      name: process.env.S1_NAME || "Secondary Router",
      host: process.env.S1_HOST,
      user: process.env.S1_USER,
      password: process.env.S1_PASSWORD,
      port: parseInt(process.env.S1_PORT) || 8728,
      tls: process.env.S1_TLS === "true", // FIX: boolean, bukan string
      wgInterface: process.env.S1_WG_INTERFACE || "wireguard1",
      wgPort: parseInt(process.env.S1_WG_PORT) || 51820,
      ipv4Prefix: process.env.S1_IPV4_PREFIX || "10.10.11.",
      ipv6Prefix: process.env.S1_IPV6_PREFIX || "fd00:10:11::",
    },
  ],
};
