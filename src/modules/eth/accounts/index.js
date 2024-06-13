import { isUint8Array, isHexStrict, isNullish, isString } from '../../../validator.js'
import { bytesToHex, hexToBytes, numberToHex, toChecksumAddress, toUint8Array, utf8ToHex, uint8ArrayConcat, uint8ArrayToBigInt, hexToUint8Array } from '../../../converter.js'
import { assertIsUint8Array, bigIntToUint8Array, bigIntToHex, bigIntToUnpaddedUint8Array } from './utils.js'
import { KeyStoreVersionError, PBKDF2IterationsError, TransactionSigningError, UndefinedRawTransactionError, InvalidPasswordError, IVLengthError, InvalidSignatureError, InvalidKdfError, KeyDerivationError } from '../../../errors.js'
import { create as _create, decrypt as _decrypt, encrypt as _encrypt, sign as _sign, recoverTransaction as _recoverTransaction, signTransaction as _signTransaction,
				 hashMessage as _hashMessage,
				 privateKeyToAccount as _privateKeyToAccount, privateKeyToAddress as _privateKeyToAddress, privateKeyToPublicKey as _privateKeyToPublicKey, recover as _recover,
				 parseAndValidatePrivateKey as _parseAndValidatePrivateKey, randomBytes, uuidV4, createSS58 } from '../../../encoders.js'
import { sha3Raw } from '../../../hashes.js'
import { scrypt as scryptSync } from '@noble/hashes/scrypt'
import { pbkdf2 as pbkdf2Sync } from '@noble/hashes/pbkdf2';
import TransactionFactory from './TransactionFactory.js'
import {Transaction} from './LegacyTransaction.js'

const keyStoreSchema = {
	type: 'object',
	required: ['crypto', 'id', 'version', 'address'],
	properties: {
		crypto: {
			type: 'object',
			required: ['cipher', 'ciphertext', 'cipherparams', 'kdf', 'kdfparams', 'mac'],
			properties: {
				cipher: { type: 'string' },
				ciphertext: { type: 'string' },
				cipherparams: { type: 'object' },
				kdf: { type: 'string' },
				kdfparams: { type: 'object' },
				salt: { type: 'string' },
				mac: { type: 'string' },
			},
		},
		id: { type: 'string' },
		version: { type: 'number' },
		address: { type: 'string' },
	},
};

function calculateSigRecovery(v, chainId) {
	if (v === 0 || v === 1) return v;

	if (chainId === undefined) {
		return v - 27;
	}
	return v - (chainId * 2 + 35);
}

function isValidSigRecovery(recovery) {
	return recovery === 0 || recovery === 1;
}



export class Accounts{
	constructor(wallet){
		this.wallet = wallet;
		this.Transaction = Transaction
	}

	create = () => _create();

	parseAndValidatePrivateKey = (privateKey) => _parseAndValidatePrivateKey(privateKey);

	decrypt = async (keystore, password, nonStrict) => await _decrypt(keystore, password, nonStrict)

	encrypt = async (privateKey,	password,	options = undefined) => await _encrypt(privateKey,	password,	options)

	hashMessage = (message) => _hashMessage(message)

	privateKeyToAccount = (privateKey, ignoreLength) => _privateKeyToAccount(privateKey, ignoreLength);
	privateKeyToAddress = (privateKey) => _privateKeyToAddress(privateKey);
	privateKeyToPublicKey = (privateKey, isCompressed) => _privateKeyToPublicKey(privateKey, isCompressed);

	recover = (data,	signatureOrV, prefixedOrR, s, prefixed) => _recover(data,	signatureOrV, prefixedOrR, s, prefixed)

	recoverTransaction = (rawTransaction) => _recoverTransaction(rawTransaction)

	sign = (data, privateKey) => _sign(data, privateKey);

	signTransaction = (transaction, privateKey) => _signTransaction(transaction, privateKey);
	/*
	class Transaction {
		constructor(){
			this.data = data;
			this.txOptions = txOptions;
		}

		return TransactionFactory.fromTxData(this.data, this.txOptions)
	}*/

	//data, txOptions
	//Transaction = Transaction


}
