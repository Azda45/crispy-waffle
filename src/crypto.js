const nacl = require("tweetnacl");
const naclUtil = require("tweetnacl-util");

const generateKeypair = () => {
  const keyPair = nacl.box.keyPair();
  return {
    privateKey: naclUtil.encodeBase64(keyPair.secretKey),
    publicKey: naclUtil.encodeBase64(keyPair.publicKey),
  };
};

module.exports = { generateKeypair };
