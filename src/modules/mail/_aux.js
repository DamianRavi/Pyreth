//import crypto from 'crypto-js'
/*
function sha512(msg) {
  return crypto.createHash("sha512").update(msg).digest();
}

function aes256CbcEncrypt(iv, key, plaintext) {
  var cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(plaintext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function aes256CbcDecrypt(iv, key, ciphertext) {
  var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(ciphertext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function hmacSha256(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest();
}

function isValidPrivateKey(privateKey) {
  if(privateKey.length !== 32 || !isScalar(privateKey)){
    return false;
  }
  return privateKey.compare(ZERO32) > 0 && // > 0
  privateKey.compare(EC_GROUP_ORDER) < 0; // < G
}

export function encrypt = (publicKeyTo, msg, opts) {
  opts = opts || {};
  // Tmp variable to save context from flat promises;
  var ephemPublicKey;
  return new promise(function(resolve) {
    var ephemPrivateKey = opts.ephemPrivateKey || crypto.randomBytes(32);
    // There is a very unlikely possibility that it is not a valid key
    while(!isValidPrivateKey(ephemPrivateKey))
    {
      ephemPrivateKey = opts.ephemPrivateKey || crypto.randomBytes(32);
    }
    ephemPublicKey = getPublic(ephemPrivateKey);
    resolve(derive(ephemPrivateKey, publicKeyTo));
  }).then(function(Px) {
    var hash = sha512(Px);
    var iv = opts.iv || crypto.randomBytes(16);
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var ciphertext = aes256CbcEncrypt(iv, encryptionKey, msg);
    var dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
    var mac = Buffer.from(hmacSha256(macKey, dataToMac));
    return {
      iv: iv,
      ephemPublicKey: ephemPublicKey,
      ciphertext: ciphertext,
      mac: mac,
    };
  });
};

export function decrypt = (privateKey, opts) {
  return derive(privateKey, opts.ephemPublicKey).then(function(Px) {
    assert(isValidPrivateKey(privateKey), "Bad private key");
    var hash = sha512(Px);
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var dataToMac = Buffer.concat([
      opts.iv,
      opts.ephemPublicKey,
      opts.ciphertext
    ]);
    var realMac = hmacSha256(macKey, dataToMac);
    assert(equalConstTime(opts.mac, realMac), "Bad MAC"); return aes256CbcDecrypt(opts.iv, encryptionKey, opts.ciphertext);
  });
};
*/
