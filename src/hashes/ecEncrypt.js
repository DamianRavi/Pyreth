import crypto from "crypto-js";
import { randomBytes } from "@noble/hashes/utils";
//import * as secp256k1 from '@noble/secp256k1'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha512 } from '@noble/hashes/sha512'
import { Buffer } from 'buffer';

const EC_GROUP_ORDER = Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex');
const ZERO32 = Buffer.alloc(32, 0);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

function isScalar (x) {
  return Buffer.isBuffer(x) && x.length === 32;
}

function equalConstTime(b1, b2) {
  if (b1.length !== b2.length) {
    return false;
  }
  var res = 0;
  for (var i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i];  // jshint ignore:line
  }
  return res === 0;
}

function isValidPrivateKey(privateKey) {
  if (!isScalar(privateKey))
  {
    return false;
  }
  return privateKey.compare(ZERO32) > 0 && // > 0
  privateKey.compare(EC_GROUP_ORDER) < 0; // < G
}

function hmacSha256(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest();
}
/*
function sha512(msg) {
  return crypto.createHash("sha512").update(msg).digest();
}*/

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

function uint8ArrayToHexString(uint8Array) {
	let hexString = '0x';
	for (const e of uint8Array) {
		const hex = e.toString(16);
		hexString += hex.length === 1 ? `0${hex}` : hex;
	}
	return hexString;
}

function getPublic(privateKey) {
  //assert(privateKey.length === 32, "Bad private key");
  //assert(isValidPrivateKey(privateKey), "Bad private key");
  //var compressed = secp256k1.publicKeyCreate(privateKey);
  return secp256k1.getPublicKey(privateKey, false);
};

const derive = (privateKeyA, publicKeyB) => {
  return new Promise(function(resolve) {
    //assert(privateKeyA.length === 32, "Bad private key");
    //assert(isValidPrivateKey(privateKeyA), "Bad private key");
    //resolve(ecdh.derive(privateKeyA, publicKeyB));
    console.log(privateKeyA, publicKeyB)
    resolve(secp256k1.getSharedSecret(privateKeyA, publicKeyB))
  });
};

export const encrypt = (publicKeyTo, msg, opts) => {
  opts = opts || {};
  // Tmp variable to save context from flat promises;
  var ephemPublicKey;
  return new Promise(function(resolve) {
    //secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey())
    var ephemPrivateKey = opts.ephemPrivateKey || secp256k1.utils.randomPrivateKey()//Buffer.from(randomBytes(32));

    if(!isUint8Array(publicKeyTo)){
      if(publicKeyTo.substr(0, 2) != "0x"){
        publicKeyTo = "0x" + publicKeyTo
      }
      publicKeyTo = hexToUint8Array(publicKeyTo)
    }
    //publicKeyTo = getPublic("70edafb40309e63fb3054f60b32790a5e85defc4620fbaed14a44af06fbaead2")
    /*
    if(!isValidPrivateKey(ephemPrivateKey)){
      console.log("INVALID KEY")
      return "INVALID KEY"
    }
    while(!isValidPrivateKey(ephemPrivateKey)) {
      ephemPrivateKey = opts.ephemPrivateKey || secp256k1.utils.randomPrivateKey()//Buffer.from(randomBytes(32));
    }*/
    ephemPublicKey = getPublic(ephemPrivateKey);
    resolve(derive(ephemPrivateKey, publicKeyTo));
  }).then(function(Px) {
    var hash = sha512(Px);
    var iv = opts.iv || Buffer.from(randomBytes(16));
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var ciphertext = aes256CbcEncrypt(iv, encryptionKey, msg);
    var dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
    let mac = hmacSha256(macKey, dataToMac);
    return { iv: iv, ephemPublicKey: ephemPublicKey, ciphertext: ciphertext, mac: mac };
  });
};

export const decrypt = (privateKey, opts) => {
  privateKey = privateKey.substr(-64)
  return derive(privateKey, opts.ephemPublicKey).then(function(Px) {
    assert(privateKey.length === 64, "Bad private key");
    //assert(isValidPrivateKey(privateKey), "Bad private key");
    var hash = sha512(Px);
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var dataToMac = Buffer.concat([ opts.iv, opts.ephemPublicKey, opts.ciphertext]);
    var realMac = hmacSha256(macKey, dataToMac);
    assert(equalConstTime(opts.mac, realMac), "Bad MAC"); return aes256CbcDecrypt(opts.iv, encryptionKey, opts.ciphertext).toString();
  });
};
