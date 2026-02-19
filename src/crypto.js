"use strict";

const nacl = require("tweetnacl");
const naclUtil = require("tweetnacl-util");

/**
 * Generate WireGuard keypair (Curve25519) sepenuhnya di Node.js.
 * Tidak butuh binary `wg` terinstall.
 *
 * @returns {{ privateKey: string, publicKey: string }} base64-encoded
 */
function generateKeypair() {
  const keyPair = nacl.box.keyPair();
  return {
    privateKey: naclUtil.encodeBase64(keyPair.secretKey),
    publicKey: naclUtil.encodeBase64(keyPair.publicKey),
  };
}

module.exports = { generateKeypair };
