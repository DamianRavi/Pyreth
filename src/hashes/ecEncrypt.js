import crypto from "crypto-js";
import { randomBytes } from "@noble/hashes/utils";
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha512 } from '@noble/hashes/sha512'
import { Buffer } from 'buffer';
import { hexToUint8Array } from '../converter.js'

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

function aes256CbcEncrypt(iv, key, plaintext) {
  key = crypto.enc.Hex.parse(key.toString('hex'));
  iv = crypto.enc.Hex.parse(iv.toString('hex'));

  var encrypted = crypto.AES.encrypt(plaintext, key, { mode: crypto.mode.CBC, iv: iv }); //, padding: crypto.pad.Pkcs7
  return encrypted.ciphertext.toString(crypto.enc.Base64)
}

function aes256CbcDecrypt(iv, key, ciphertext) {
  key = crypto.enc.Hex.parse(key.toString('hex'));
  iv = crypto.enc.Hex.parse(iv.toString('hex'));

  var decrypted = crypto.AES.decrypt(ciphertext, key, { mode: crypto.mode.CBC, iv: iv }).toString(crypto.enc.Utf8)
  return decrypted;
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
  return secp256k1.getPublicKey(privateKey, false);
};

const derive = (privateKeyA, publicKeyB) => {
  return new Promise(function(resolve) {
    resolve(secp256k1.getSharedSecret(privateKeyA, publicKeyB))
  });
};

export const encrypt = (publicKeyTo, msg, opts) => {
  opts = opts || {};

  var ephemPublicKey;
  return new Promise(function(resolve) {
    var ephemPrivateKey = opts.ephemPrivateKey || secp256k1.utils.randomPrivateKey()//Buffer.from(randomBytes(32));
    if(publicKeyTo?.constructor?.name !== 'Uint8Array'){
      if(publicKeyTo.substr(0, 2) == "0x"){
        publicKeyTo = publicKeyTo.slice(2)
      }
    }
    /*
    if(!isValidPrivateKey(ephemPrivateKey)){
      return "INVALID KEY"
    }
    while(!isValidPrivateKey(ephemPrivateKey)) {
      ephemPrivateKey = opts.ephemPrivateKey || secp256k1.utils.randomPrivateKey()//Buffer.from(randomBytes(32));
    }*/

    ephemPublicKey = getPublic(ephemPrivateKey);

    var bufferKey = Buffer.from(publicKeyTo, "hex")
    if(bufferKey.length < 65){
      var prefix = Buffer.from([0x04])
      bufferKey = Buffer.concat([prefix, bufferKey]);
    }

    resolve(derive(ephemPrivateKey, bufferKey));
  }).then(function(Px) {
    var hash = sha512(Px);
    var iv = opts.iv || Buffer.from(randomBytes(16));
    var encryptionKey = Buffer.from(hash.slice(0, 32));
    var macKey = crypto.enc.Utf8.parse(Buffer.from(hash.slice(32))); //to hex

    var ciphertext = aes256CbcEncrypt(iv, encryptionKey, msg);
    iv = Buffer.from(iv)

    var dataToMac = Buffer.concat([ iv, ephemPublicKey, Buffer.from(ciphertext, 'base64') ]);
    let mac = crypto.HmacSHA256(dataToMac, macKey).toString(crypto.enc.Base64)
    return { iv: iv.toString("base64"), ephemPublicKey: Buffer.from(ephemPublicKey).toString('base64'), ciphertext: ciphertext, mac: mac };
  });
};

export const decrypt = (privateKey, opts) => {
  privateKey = privateKey.substr(-64)

  var ciphertext = opts.ciphertext;
  opts.iv = Buffer.from(opts.iv, 'base64');
  opts.ephemPublicKey = Buffer.from(opts.ephemPublicKey, 'base64');
  opts.ciphertext = Buffer.from(opts.ciphertext, 'base64');

  return derive(privateKey, Buffer.from(opts.ephemPublicKey).toString("hex")).then(function(Px) {
    assert(privateKey.length === 64, "Bad private key");
    var hash = sha512(Px);
    var encryptionKey = Buffer.from(hash.slice(0, 32));
    var macKey = crypto.enc.Utf8.parse(Buffer.from(hash.slice(32))); //to hex
    var dataToMac = Buffer.concat([opts.iv, opts.ephemPublicKey, opts.ciphertext]);
    var realMac = crypto.HmacSHA256(dataToMac, macKey).toString(crypto.enc.Base64);
    assert(equalConstTime(opts.mac, realMac), "Bad MAC");
    return aes256CbcDecrypt(opts.iv, encryptionKey, ciphertext).toString();
  });
};
