import * as RLP from './rlp.js';
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { bytesToHex, bigIntToHex, hexToBytes, toUint8Array, uint8ArrayConcat, uint8ArrayToBigInt, bytesToUint8Array, numberToHex } from '../../../converter.js';
import { isHexStrict, isUint8Array } from '../../../validator.js';
//import { validateNoLeadingZeroes } from 'web3-validator';
import {secp256k1} from '@noble/curves/secp256k1'
import { ecrecover } from '../../../encoders.js'
import { bigIntToUnpaddedUint8Array, assertIsUint8Array, unpadUint8Array, checkMaxInitCodeSize } from './utils.js'
export const MAX_UINT64 = BigInt('0xffffffffffffffff');
export const MAX_INTEGER = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
export const SECP256K1_ORDER = BigInt(secp256k1.CURVE.n);
export const SECP256K1_ORDER_DIV_2 = SECP256K1_ORDER / BigInt(2);

const Capability = {
	EIP155ReplayProtection: 155,
	EIP1559FeeMarket: 1559,
	EIP2718TypedTransaction: 2718,
	EIP2930AccessLists: 2930,
}

const TRANSACTION_TYPE = 0;

function meetsEIP155(_v, chainId) {
	const v = Number(_v);
	const chainIdDoubled = Number(chainId) * 2;
	return v === chainIdDoubled + 35 || v === chainIdDoubled + 36;
}

/**
 * An Ethereum non-typed (legacy) transaction
 */
// eslint-disable-next-line no-use-before-define
export class Transaction {

 static fromTxData(txData, opts = {}) {
		return new Transaction(txData, opts);
	}

 static fromValuesArray(values, opts = {}) {
		if (values.length !== 6 && values.length !== 9) {
			throw new Error('Invalid transaction. Only expecting 6 values (for unsigned tx) or 9 values (for signed tx).');
		}

		const [nonce, gasPrice, gasLimit, to, value, data, v, r, s] = values;

		//validateNoLeadingZeroes({ nonce, gasPrice, gasLimit, value, v, r, s });

		return new Transaction( { nonce, gasPrice, gasLimit, to, value, data, v, r, s }, opts )
	}

	static fromSerializedTx(serialized, opts = {}) {
		 const values = RLP.decode(serialized);
		 if (!Array.isArray(values)) {
			 throw new Error('Invalid serialized tx input. Must be array');
		 }

		 return this.fromValuesArray(values, opts);
	 }


	constructor(txData, opts = {}) {
		this.type = 0; //WARNING
		const { nonce, gasLimit, to, value, data, v, r, s, type } = txData;
		const { chainId, accessList, maxFeePerGas, maxPriorityFeePerGas, gasPrice } = txData;
		this._type = 0;

		if(!chainId){
			this.chainId = 1;
		}

		this.txOptions = opts;
		const toB = toUint8Array(to === '' ? '0x' : to);
		const vB = toUint8Array(v === '' ? '0x' : v);
		const rB = toUint8Array(r === '' ? '0x' : r);
		const sB = toUint8Array(s === '' ? '0x' : s);

		this.nonce = uint8ArrayToBigInt(toUint8Array(nonce === '' ? '0x' : nonce));
		this.gasLimit = uint8ArrayToBigInt(toUint8Array(gasLimit === '' ? '0x' : gasLimit));
		this.gasPrice = uint8ArrayToBigInt(toUint8Array(gasPrice === '' ? '0x' : gasPrice));
		this.to = toB.length > 0 ? toB : undefined;
		this.value = uint8ArrayToBigInt(toUint8Array(value === '' ? '0x' : value));
		this.data = toUint8Array(data === '' ? '0x' : data);

		this.v = v ? bytesToHex(v) : v//vB.length > 0 ? uint8ArrayToBigInt(vB) : undefined;
		this.r = r ? bytesToHex(r) : r//rB.length > 0 ? uint8ArrayToBigInt(rB) : undefined;
		this.s = s ? bytesToHex(s) : s//sB.length > 0 ? uint8ArrayToBigInt(sB) : undefined;

		this._validateCannotExceedMaxInteger({ value: this.value});
		this._validateCannotExceedMaxInteger({ gasLimit: this.gasLimit }, 64);
		this._validateCannotExceedMaxInteger({ nonce: this.nonce }, 64, true);

		const createContract = this.to === undefined || this.to === null;
		const allowUnlimitedInitCodeSize = opts.allowUnlimitedInitCodeSize ?? false;
/*
		if(typeof txData == "string"){
			this.chainId = 0; //CHANGE THIS
			this.gasPrice = uint8ArrayToBigInt( toUint8Array(txData.gasPrice === '' ? '0x' : txData.gasPrice) );

			if (this.gasPrice * this.gasLimit > MAX_INTEGER) {
				const msg = this._errorMsg('gas limit * gasPrice cannot exceed MAX_INTEGER (2^256-1)');
				throw new Error(msg);
			}
			this._validateCannotExceedMaxInteger({ gasPrice: this.gasPrice });
			this._validateNotArray(txData);
		}
		else if(typeof txData == "object"){

		}
		else if(typeof txData == "array"){

		}
*/
		this.activeCapabilities = [1559, 2718, 2930];
		this.activeCapabilities.push(Capability.EIP155ReplayProtection);

		const freeze = opts?.freeze ?? true;
		if (freeze) {
			//Object.freeze(this);
		}
	}

 	getSenderAddress() {
		return this.publicToAddress(this.getSenderPublicKey());
	}

	publicToAddress(_pubKey, sanitize = false) {
			let pubKey = _pubKey;
			assertIsUint8Array(pubKey);
			if (sanitize && pubKey.length !== 64) {
					pubKey = secp256k1.ProjectivePoint.fromHex(pubKey).toRawBytes(false).slice(1);
			}
			if (pubKey.length !== 64) {
					throw new Error('Expected pubKey to be of length 64');
			}
			return bytesToHex(keccak256(pubKey).slice(-20));
	}

 raw() {
		return [
			bigIntToUnpaddedUint8Array(this.nonce),
			bigIntToUnpaddedUint8Array(this.gasPrice),
			bigIntToUnpaddedUint8Array(this.gasLimit),
			this.to !== undefined ? this.to : Uint8Array.from([]),
			bigIntToUnpaddedUint8Array(this.value),
			this.data,
			this.v !== undefined ? bigIntToUnpaddedUint8Array(this.v) : Uint8Array.from([]),
			this.r !== undefined ? bigIntToUnpaddedUint8Array(BigInt(this.r)) : Uint8Array.from([]),
			this.s !== undefined ? bigIntToUnpaddedUint8Array(BigInt(this.s)) : Uint8Array.from([]),
		];
	}

 serialize() {
		return RLP.encode(this.raw());
	}

	supports(capability) {
		return this.activeCapabilities.includes(capability);
	}

	_getMessageToSign() {
		const values = [
			bigIntToUnpaddedUint8Array(this.nonce),
			bigIntToUnpaddedUint8Array(this.gasPrice), //--------------
			bigIntToUnpaddedUint8Array(this.gasLimit),
			this.to !== undefined ? this.to : Uint8Array.from([]), //-------------------
			bigIntToUnpaddedUint8Array(this.value),
			this.data,
		];

		if (this.supports(Capability.EIP155ReplayProtection)) {
			values.push(toUint8Array(this.chainId));
			values.push(unpadUint8Array(toUint8Array(0)));
			values.push(unpadUint8Array(toUint8Array(0)));
		}

		return values;
	}


 getMessageToSign(hashMessage = true) {
		const message = this._getMessageToSign();
		if (hashMessage) {
			return keccak256(RLP.encode(message));
		}
		return message;
	}

	parseAndValidatePrivateKey(data, ignoreLength) {
		let privateKeyUint8Array;
		if (!ignoreLength && typeof data === 'string' && isHexStrict(data) && data.length !== 66) {
			throw new Error("Invalid Private Key Length");
		}

		try {
			privateKeyUint8Array = isUint8Array(data) ? (data) : bytesToUint8Array(data);
		} catch {
			throw new Error("Invalid Private Key");
		}

		if (!ignoreLength && privateKeyUint8Array.byteLength !== 32) {
			throw new Error("Invalid Private Key Length");
		}

		return privateKeyUint8Array;
	};

	sign(privateKey) {
		const privateKeyUint8Array = this.parseAndValidatePrivateKey(privateKey);
		const hash = this.getMessageToSign(true)
		//const hash = hashMessage(data);
		const signature = secp256k1.sign(hash, privateKeyUint8Array);
		const signatureBytes = signature.toCompactRawBytes();
		this.r = "0x" + signature.r.toString(16).padStart(64, '0');
		this.s = "0x" + signature.s.toString(16).padStart(64, '0');
		this.v = (this.chainId === undefined ? BigInt(signature.recovery) + BigInt(27) : BigInt(signature.recovery) + BigInt(35) + (BigInt(this.chainId) * BigInt(2)));

		return {
			message: this.getMessageToSign(false),
			messageHash: hash,
			v: numberToHex(this.v),
			r: `0x${this.r}`,
			s: `0x${this.s}`,
			signature: `${bytesToHex(signatureBytes)}${this.v.toString(16)}`,
		};
	};

 getDataFee() {
		throw new Error("getDataFee is unimplemeted");
	}

 getUpfrontCost() {
		return this.gasLimit * this.gasPrice + this.value;
	}

 isSigned() {
		const { v, r, s } = this;
		if (v === undefined || r === undefined || s === undefined) {
			return false;
		}
		return true;
	}

 hash() {
		if (!this.isSigned()) {
			const msg = this._errorMsg('Cannot call hash method if transaction is not signed');
			throw new Error(msg);
		}

		if (Object.isFrozen(this)) {
			if (!this.cache.hash) {
				this.cache.hash = keccak256(RLP.encode(this.raw()));
			}
			return this.cache.hash;
		}

		return keccak256(RLP.encode(this.raw()));
	}

	getMessageToVerifySignature() {
		if (!this.isSigned()) {
			const msg = this._errorMsg('This transaction is not signed');
			throw new Error(msg);
		}
		const message = this._getMessageToSign();
		return bytesToHex(keccak256(RLP.encode(message)));
	}

	_validateHighS() {
		const { s } = this;
		if (s !== undefined && uint8ArrayToBigInt(hexToBytes(s)) > SECP256K1_ORDER_DIV_2) {
			const msg = this._errorMsg(
				'Invalid Signature: s-values greater than secp256k1n/2 are considered invalid',
			);
			throw new Error(msg);
		}
	}

	getSenderPublicKey() {
		const msgHash = this.getMessageToVerifySignature();
		const { v, r, s } = this;
		this._validateHighS();
		try {
			return ecrecover( msgHash, BigInt(v), bigIntToUnpaddedUint8Array(BigInt(r)), bigIntToUnpaddedUint8Array(BigInt(s)), this.chainId)
		} catch (e) {
			const msg = this._errorMsg('Invalid Signature');
			throw new Error(msg);
		}
	}

 _processSignature(_v, r, s) {
		let v = _v;
		if (this.supports(Capability.EIP155ReplayProtection)) {
			v += this.chainId * BigInt(2) + BigInt(8);
		}

		const opts = { ...this.txOptions };

		return Transaction.fromTxData(
			{
				nonce: this.nonce,
				gasPrice: this.gasPrice,
				gasLimit: this.gasLimit,
				to: this.to,
				value: this.value,
				data: this.data,
				v,
				r: uint8ArrayToBigInt(r),
				s: uint8ArrayToBigInt(s),
			},
			opts);
	}

 toJSON() {
		return {
			nonce: bigIntToHex(this.nonce),
			gasPrice: bigIntToHex(this.gasPrice),
			gasLimit: bigIntToHex(this.gasLimit),
			to: this.to !== undefined ? this.to.toString() : undefined,
			value: bigIntToHex(this.value),
			data: bytesToHex(this.data),
			v: this.v !== undefined ? bigIntToHex(this.v) : undefined,
			r: this.r !== undefined ? bigIntToHex(this.r) : undefined,
			s: this.s !== undefined ? bigIntToHex(this.s) : undefined,
		};
	}

	verifySignature() {
			try {
				// Main signature verification is done in `getSenderPublicKey()`
				const publicKey = this.getSenderPublicKey();
				return unpadUint8Array(publicKey).length !== 0;
			}
			catch (e) {
				return false;
			}
	}

	validate(stringError = false) {
			const errors = [];
			//if (this.getBaseFee() > this.gasLimit) {
			//		errors.push(`gasLimit is too low. given ${this.gasLimit}, need at least ${this.getBaseFee()}`);
			//}

			if (this.isSigned() && !this.verifySignature()) {
					errors.push('Invalid Signature');
			}
			return stringError ? errors : errors.length === 0;
	}

	_validateCannotExceedMaxInteger(values, bits = 256, cannotEqual = false) {
		for (const [key, value] of Object.entries(values)) {
			switch (bits) {
				case 64:
					if (cannotEqual) {
						if (value !== undefined && values.value && BigInt(values.value) >= (MAX_UINT64)){
							const msg = this._errorMsg(`${key} cannot equal or exceed MAX_UINT64 (2^64-1), given ${value}`);
							throw new Error(msg);
						}
					} else if (value !== undefined && values.value && BigInt(values.value) > (MAX_UINT64)){
						const msg = this._errorMsg(`${key} cannot exceed MAX_UINT64 (2^64-1), given ${value}`);
						throw new Error(msg);
					}
					break;
				case 256:
					if (cannotEqual) {
						if (value !== undefined && values.value && BigInt(values.value) >= MAX_INTEGER){
							const msg = this._errorMsg(`${key} cannot equal or exceed MAX_INTEGER (2^256-1), given ${value}`);
							throw new Error(msg);
						}
					} else if (value !== undefined && values.value && BigInt(values.value) > (MAX_INTEGER)){
						const msg = this._errorMsg(`${key} cannot exceed MAX_INTEGER (2^256-1), given ${value}`);
						throw new Error(msg);
					}
					break;
				default: {
					const msg = this._errorMsg('unimplemented bits value');
					throw new Error(msg);
				}
			}
		}
	}

	_validateNotArray(values) {
		const txDataKeys = [ 'nonce', 'gasPrice', 'gasLimit', 'to', 'value', 'data', 'v', 'r', 's', 'type', 'baseFee', 'maxFeePerGas', 'chainId' ];
		for (const [key, value] of Object.entries(values)) {
			if (txDataKeys.includes(key)) {
				if (Array.isArray(value)) {
					throw new Error(`${key} cannot be an array`);
				}
			}
		}
	}

	_getSharedErrorPostfix() {
		let hash = '';
		try {
			hash = this.isSigned() ? bytesToHex(this.hash()) : 'not available (unsigned)';
		} catch (e) {
			hash = 'error';
		}
		let isSigned = '';
		try {
			isSigned = this.isSigned().toString();
		} catch (e) {
			hash = 'error';
		}
		let postfix = `tx type=${this.type} hash=${hash} nonce=${this.nonce} value=${this.value} `;
		postfix += `signed=${isSigned}`;// hf=${hf}`;

		return postfix;
	}

	errorStr() {
		let errorStr = this._getSharedErrorPostfix();
		errorStr += ` gasPrice=${this.gasPrice}`;
		return errorStr;
	}

 _errorMsg(msg) {
		return `${msg} (${this.errorStr()})`;
	}
}
