import TransactionFactory from './modules/eth/accounts/TransactionFactory.js'
import { randomBytes as _randomBytes } from '@noble/hashes/utils';
import {secp256k1} from '@noble/curves/secp256k1'
import { PrivateKeyLengthError, InvalidPrivateKeyError } from './errors.js'
import { bytesToHex, bytesToUint8Array, uint8ArrayToBigInt, utf8ToBytes, uint8ArrayToHexString, hexToUint8Array, hexToNumber, toChecksumAddress, utf8ToHex, hexToBytes, uint8ArrayConcat, numberToHex } from './converter.js'
import { isUint8Array, isHexStrict, ensureIfUint8Array, isNullish } from './validator.js'
import { sha3Raw } from './hashes.js'
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { scrypt as scryptSync } from '@noble/hashes/scrypt'
import { decrypt as createDecipheriv, encrypt as createCipheriv } from './hashes/aes.js';
import { encode, decode } from './hashes/ss58.js'
import { blake2b } from '@noble/hashes/blake2b';
import { blake2s } from '@noble/hashes/blake2s';
import { base58 } from '@scure/base';

export const randomHex = (bytesLength) => bytesToHex( _randomBytes(new Uint8Array(bytesLength)) );

export const randomBytes = (bytesLength) => _randomBytes(new Uint8Array(bytesLength));

export const createSS58 = (pubKey) => {
  return encode(pubKey.replace("0x", ""))
}

export const uuidV4 = () => {
  return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, c =>
    (c ^ _randomBytes(1)[0] & 15 >> c / 4).toString(16)
  );
}

export const parseAndValidatePrivateKey = (data, ignoreLength) => {
	let privateKeyUint8Array;
	if (!ignoreLength && typeof data === 'string' && isHexStrict(data) && data.length !== 66) {
		throw new Error("Invalid Private Key Length");
	}

	try {
		privateKeyUint8Array = isUint8Array(data) ? (data ) : bytesToUint8Array(data);
	} catch {
		throw new Error("Invalid Private Key");
	}

	if (!ignoreLength && privateKeyUint8Array.byteLength !== 32) {
		throw new Error("Invalid Private Key Length");
	}

	return privateKeyUint8Array;
};

export const checkAddressCheckSum = (data) => {
  if (!/^(0x)?[0-9a-f]{40}$/i.test(data)) return false;
	const address = data.slice(2);
	const updatedData = utf8ToBytes(address.toLowerCase());
	const addressHash = uint8ArrayToHexString(keccak256(ensureIfUint8Array(updatedData))).slice(2);

	for (let i = 0; i < 40; i += 1) {
		if ( (parseInt(addressHash[i], 16) > 7 && address[i].toUpperCase() !== address[i]) || (parseInt(addressHash[i], 16) <= 7 && address[i].toLowerCase() !== address[i]) ) {
			return false;
		}
	}
	return true;
}

function calculateSigRecovery(v, chainId) {
	if (BigInt(v) === BigInt(0) || BigInt(v) === BigInt(1)) return v;

	if (chainId === undefined) {
		return BigInt(v) - BigInt(27);
	}
	return BigInt(v) - (BigInt(chainId) * BigInt(2) + BigInt(35));//BigInt(v).minus(BigInt(chainId).times(2).plus(35))//(BigInt(chainId) * BigInt(2) + BigInt(35));
}

function isValidSigRecovery(recovery) {
	return recovery === BigInt(0) || recovery === BigInt(1);
}

/**
 * ECDSA public key recovery from signature.
 * NOTE: Accepts `v === 0 | v === 1` for EIP1559 transactions
 * @returns Recovered public key
 */
export const ecrecover = function ( msgHash, v, r, s, chainId ) {
	const recovery = calculateSigRecovery(v, chainId);
	if (recovery.toString() != "0" && recovery.toString() != "1") {
		throw new Error('Invalid signature v value');
	}
	const senderPubKey = new secp256k1.Signature(uint8ArrayToBigInt(r), uint8ArrayToBigInt(s)).addRecoveryBit(Number(recovery)).recoverPublicKey(bytesToHex(msgHash).replace("0x", "")).toRawBytes(false);
	return Buffer.from(senderPubKey).toString('hex');
};

export const checkMaxInitCodeSize = (common, length) => {
	const maxInitCodeSize = common.param('vm', 'maxInitCodeSize');
	if (maxInitCodeSize && BigInt(length) > maxInitCodeSize) {
		throw new Error(
			`the initcode size of this transaction is too large: it is ${length} while the max is ${common.param(
				'vm',
				'maxInitCodeSize',
			)}`,
		);
	}
};

/**********************************************************/

export const create = () => {
  const privateKey = secp256k1.utils.randomPrivateKey();
  return privateKeyToAccount(`${bytesToHex(privateKey)}`);
}

export const privateKeyToAccount = (privateKey, ignoreLength) => {
  const privateKeyUint8Array = parseAndValidatePrivateKey(privateKey, ignoreLength);

  return {
    address: privateKeyToAddress(privateKeyUint8Array),
    ss58Address: createSS58(privateKeyToPublicKey(privateKey)),
    privateKey: bytesToHex(privateKeyUint8Array),
    publicKey: privateKeyToPublicKey(privateKey, false),
    signTransaction: (_tx) => {
      throw new Error('Do not have network access to sign the transaction');
    },
    sign: (data) => sign(typeof data === 'string' ? data : JSON.stringify(data), privateKeyUint8Array),
    encrypt: async (password, options) => encrypt(privateKeyUint8Array, password, options),
  };
}

export const privateKeyToAddress = (privateKey) => {
  const privateKeyUint8Array = parseAndValidatePrivateKey(privateKey);
  const publicKey = secp256k1.getPublicKey(privateKeyUint8Array, false);

  const publicKeyHash = sha3Raw(publicKey.slice(1));
  const address = publicKeyHash.slice(-40);

  return toChecksumAddress(`0x${address}`);
}

export const privateKeyToPublicKey = (privateKey, isCompressed) => {
  const privateKeyUint8Array = parseAndValidatePrivateKey(privateKey);
  return `0x${bytesToHex(secp256k1.getPublicKey(privateKeyUint8Array, isCompressed)).slice(4)}`; // 0x and removing compression byte
}

export const decrypt = async (keystore, password, nonStrict) => {
  const json = typeof keystore === 'object' ? keystore : (JSON.parse(nonStrict ? keystore.toLowerCase() : keystore));
  //validator.validateJSONSchema(keyStoreSchema, json);

  if (json.version !== 3) throw new KeyStoreVersionError();

  const uint8ArrayPassword = typeof password === 'string' ? hexToBytes(utf8ToHex(password)) : password;
  //validator.validate(['bytes'], [uint8ArrayPassword]);

  let derivedKey;
  if (json.crypto.kdf === 'scrypt') {
    const kdfparams = json.crypto.kdfparams;
    const uint8ArraySalt = typeof kdfparams.salt === 'string' ? hexToBytes(kdfparams.salt) : kdfparams.salt;
    derivedKey = scryptSync( uint8ArrayPassword, uint8ArraySalt, {N: kdfparams.n, p: kdfparams.p, r: kdfparams.r, dklen: kdfparams.dklen} );
  } else if (json.crypto.kdf === 'pbkdf2') {
    const kdfparams = json.crypto.kdfparams;

    const uint8ArraySalt = typeof kdfparams.salt === 'string' ? hexToBytes(kdfparams.salt) : kdfparams.salt;

    derivedKey = pbkdf2Sync( uint8ArrayPassword, uint8ArraySalt,
      kdfparams.c,
      kdfparams.dklen,
      'sha256',
    );
  } else {
    throw new InvalidKdfError();
  }

  const ciphertext = hexToBytes(json.crypto.ciphertext);
  const mac = sha3Raw(uint8ArrayConcat(derivedKey.slice(16, 32), ciphertext)).replace('0x', '');

  if (mac !== json.crypto.mac) {
    throw new KeyDerivationError();
  }

  const seed = await createDecipheriv( hexToBytes(json.crypto.ciphertext), derivedKey.slice(0, 16), hexToBytes(json.crypto.cipherparams.iv) );

  return privateKeyToAccount(seed);
};

export const encrypt = async (privateKey,	password,	options = undefined) => {
  const privateKeyUint8Array = parseAndValidatePrivateKey(privateKey);

    // if given salt or iv is a string, convert it to a Uint8Array
    let salt;
    if (options?.salt) {
      salt = typeof options.salt === 'string' ? hexToBytes(options.salt) : options.salt;
    } else {
      salt = randomBytes(32);
    }

    if (!(isString(password) || isUint8Array(password))) {
      throw new InvalidPasswordError();
    }

    const uint8ArrayPassword =
      typeof password === 'string' ? hexToBytes(utf8ToHex(password)) : password;

    let initializationVector;
    if (options?.iv) {
      initializationVector = typeof options.iv === 'string' ? hexToBytes(options.iv) : options.iv;
      if (initializationVector.length !== 16) {
        throw new IVLengthError();
      }
    } else {
      initializationVector = randomBytes(16);
    }

    const kdf = options?.kdf ?? 'scrypt';

    let derivedKey;
    let kdfparams;

    // derive key from key derivation function
    if (kdf === 'pbkdf2') {
      kdfparams = {
        dklen: options?.dklen ?? 32,
        salt: bytesToHex(salt).replace('0x', ''),
        c: options?.c ?? 262144,
        prf: 'hmac-sha256',
      };

      if (kdfparams.c < 1000) {
        // error when c < 1000, pbkdf2 is less secure with less iterations
        throw new PBKDF2IterationsError();
      }
      derivedKey = pbkdf2Sync(uint8ArrayPassword, salt, kdfparams.c, kdfparams.dklen, 'sha256');
    } else if (kdf === 'scrypt') {
      kdfparams = {
        n: options?.n ?? 8192,
        r: options?.r ?? 8,
        p: options?.p ?? 1,
        dklen: options?.dklen ?? 32,
        salt: bytesToHex(salt).replace('0x', ''),
      };
      derivedKey = scryptSync(
        uint8ArrayPassword,
        salt,
        kdfparams.n,
        kdfparams.p,
        kdfparams.r,
        kdfparams.dklen,
      );
    } else {
      throw new InvalidKdfError();
    }

    const cipher = await createCipheriv( privateKeyUint8Array, derivedKey.slice(0, 16), initializationVector, 'aes-128-ctr' );

    const ciphertext = bytesToHex(cipher).slice(2);

    const mac = sha3Raw(uint8ArrayConcat(derivedKey.slice(16, 32), cipher)).replace('0x', '');
    return {
      version: 3,
      id: uuidV4(),
      address: privateKeyToAddress(privateKeyUint8Array).toLowerCase().replace('0x', ''),
      crypto: {
        ciphertext,
        cipherparams: { iv: bytesToHex(initializationVector).replace('0x', '') },
        cipher: 'aes-128-ctr',
        kdf,
        kdfparams,
        mac,
      },
    };
}

export const hashMessage = (message) => {
  const messageHex = isHexStrict(message) ? message : utf8ToHex(message);
  const messageBytes = hexToBytes(messageHex);
  const preamble = hexToBytes( utf8ToHex(`\x19Ethereum Signed Message:\n${messageBytes.byteLength}`) );
  const ethMessage = uint8ArrayConcat(preamble, messageBytes);
  return sha3Raw(ethMessage); // using keccak in web3-utils.sha3Raw instead of SHA3 (NIST Standard) as both are different
}

export const recover = (data,	signatureOrV, prefixedOrR, s, prefixed) => {
  if (typeof data === 'object') {
    const signatureStr = `${data.r}${data.s.slice(2)}${data.v.slice(2)}`;
    return recover(data.messageHash, signatureStr, prefixedOrR);
  }
  if (typeof signatureOrV === 'string' && typeof prefixedOrR === 'string' && !isNullish(s)) {
    const signatureStr = `${prefixedOrR}${s.slice(2)}${signatureOrV.slice(2)}`;
    return recover(data, signatureStr, prefixed);
  }

  if (isNullish(signatureOrV)) throw new InvalidSignatureError('signature string undefined');

  const V_INDEX = 130; // r = first 32 bytes, s = second 32 bytes, v = last byte of signature
  const hashedMessage = prefixedOrR ? data : hashMessage(data);

  let v = parseInt(signatureOrV.substring(V_INDEX), 16); // 0x + r + s + v
  if (v > 26) {
    v -= 27;
  }

  const ecPublicKey = secp256k1.Signature.fromCompact(signatureOrV.slice(2, V_INDEX)).addRecoveryBit(v).recoverPublicKey(hashedMessage.replace('0x', '')).toRawBytes(false);

  const publicHash = sha3Raw(ecPublicKey.subarray(1));

  const address = toChecksumAddress(`0x${publicHash.slice(-40)}`);

  return address;
}

export const recoverTransaction = (rawTransaction) => {
  if (isNullish(rawTransaction)) throw new UndefinedRawTransactionError();

  const tx = TransactionFactory.fromSerializedData(hexToBytes(rawTransaction));
  return toChecksumAddress(tx.getSenderAddress());
}

export const sign = (data, privateKey) => {
  const privateKeyUint8Array = parseAndValidatePrivateKey(privateKey);
  const hash = hashMessage(data);

  const signature = secp256k1.sign(hash.substring(2), privateKeyUint8Array);
  const signatureBytes = signature.toCompactRawBytes();
  const r = signature.r.toString(16).padStart(64, '0');
  const s = signature.s.toString(16).padStart(64, '0');
  const v = signature.recovery + 27;

  return {
    message: data,
    messageHash: hash,
    v: numberToHex(v),
    r: `0x${r}`,
    s: `0x${s}`,
    signature: `${bytesToHex(signatureBytes)}${v.toString(16)}`,
  };
}

export const signTransaction = (transaction, privateKey) => {
  transaction = TransactionFactory.fromTxData(transaction);
  //console.log("hashedTX", bytesToHex(transaction.getMessageToSign()) )
  //const signedTx = sign(bytesToHex(transaction.getMessageToSign()), hexToBytes(privateKey));
  transaction.sign(bytesToHex(hexToBytes(privateKey)));

  if (isNullish(transaction.v) || isNullish(transaction.r) || isNullish(transaction.s))
    throw new Error('Signer Error');

  const validationErrors = transaction.validate(true);
  if (validationErrors.length > 0) {
    let errorString = 'Signer Error ';
    for (const validationError of validationErrors) {
      errorString += `${errorString} ${validationError}.`;
    }
    throw new Error(errorString);
  }

  const rawTx = bytesToHex(transaction.serialize());
  const txHash = sha3Raw(rawTx); // using keccak in web3-utils.sha3Raw instead of SHA3 (NIST Standard) as both are different
  return {
    messageHash: transaction.getMessageToSign(),
    v: `0x${transaction.v.toString(16)}`,
    r: `${transaction.r.toString(16).padStart(64, '0')}`,
    s: `${transaction.s.toString(16).padStart(64, '0')}`,
    rawTransaction: rawTx,
    transactionHash: bytesToHex(txHash),
  };
}
