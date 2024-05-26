import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1'
import { validateNoLeadingZeroes, uint8ArrayEquals } from '../../../validator.js';
import * as RLP from './rlp.js';
import { bytesToHex, bigIntToHex, hexToBytes, toUint8Array, uint8ArrayConcat, uint8ArrayToBigInt } from '../../../converter.js';
import { ecrecover } from '../../../encoders.js'
import { bigIntToUnpaddedUint8Array, assertIsUint8Array, unpadUint8Array, checkMaxInitCodeSize } from './utils.js'
import { getAccessListData, getAccessListJSON, getDataFeeEIP2930, verifyAccessList } from './utils.js';
export const MAX_UINT64 = BigInt('0xffffffffffffffff');
export const MAX_INTEGER = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
export const SECP256K1_ORDER = BigInt(secp256k1.CURVE.n);
export const SECP256K1_ORDER_DIV_2 = SECP256K1_ORDER / BigInt(2);

const TRANSACTION_TYPE = 2;
const TRANSACTION_TYPE_UINT8ARRAY = hexToBytes(TRANSACTION_TYPE.toString(16).padStart(2, '0'));

const Capability = {
	EIP155ReplayProtection: 155,
	EIP1559FeeMarket: 1559,
	EIP2718TypedTransaction: 2718,
	EIP2930AccessLists: 2930,
}

const DEFAULT_HARDFORK = 'london'

const DEFAULT_CHAIN_DATA = {
  name: 'Moonbeam',
  networkId: 0,
  chainId: 0,
  baseChain: "GLMR",
  hardfork: DEFAULT_HARDFORK
}


export class FeeMarketEIP1559Transaction {

	static fromTxData(txData, opts = {}) {
		return new FeeMarketEIP1559Transaction(txData, opts);
	}

	fromSerializedTx(serialized, opts = {}) {
		if (!uint8ArrayEquals(serialized.subarray(0, 1), TRANSACTION_TYPE_UINT8ARRAY)) {
			throw new Error(`Invalid serialized tx input: not an EIP-1559 transaction (wrong tx type, expected: ${TRANSACTION_TYPE}, received: ${bytesToHex(serialized.subarray(0, 1))}`);
		}
		const values = RLP.decode(serialized.subarray(1));

		if (!Array.isArray(values)) {
			throw new Error('Invalid serialized tx input: must be array');
		}
		//return FeeMarketEIP1559Transaction.fromValuesArray(values, opts);
		return this.fromValuesArray(values, opts);
	}

	constructor(txData, opts = {}) {
    txData.type = 2; //WARNING

    const { nonce, gasLimit, to, value, data, v, r, s, type } = txData;
    const { chainId, accessList, maxFeePerGas, maxPriorityFeePerGas, gasPrice } = txData;
		this._type = 2;

		this.txOptions = opts;

		const toB = toUint8Array(to === '' ? '0x' : to);
		const vB = toUint8Array(v === '' ? '0x' : v);
		const rB = toUint8Array(r === '' ? '0x' : r);
		const sB = toUint8Array(s === '' ? '0x' : s);

		this.nonce = uint8ArrayToBigInt(toUint8Array(nonce === '' ? '0x' : nonce));
		this.gasLimit = uint8ArrayToBigInt(toUint8Array(gasLimit === '' ? '0x' : gasLimit));
		this.to = toB.length > 0 ? toB : undefined;
		this.value = uint8ArrayToBigInt(toUint8Array(value === '' ? '0x' : value));
		this.data = toUint8Array(data === '' ? '0x' : data);

		this.v = vB.length > 0 ? uint8ArrayToBigInt(vB) : undefined;
		this.r = rB.length > 0 ? uint8ArrayToBigInt(rB) : undefined;
		this.s = sB.length > 0 ? uint8ArrayToBigInt(sB) : undefined;

		this._validateCannotExceedMaxInteger({ value: this.value, r: this.r, s: this.s });
		this._validateCannotExceedMaxInteger({ gasLimit: this.gasLimit }, 64);
		this._validateCannotExceedMaxInteger({ nonce: this.nonce }, 64, true);

		const createContract = this.to === undefined || this.to === null;
		const allowUnlimitedInitCodeSize = opts.allowUnlimitedInitCodeSize ?? false;

		//if (createContract && !allowUnlimitedInitCodeSize) {
			//checkMaxInitCodeSize(common, this.data.length);
		//}

		//if (!this.common.isActivatedEIP(1559)) {
			//throw new Error('EIP-1559 not enabled on Common');
		//}
		this.activeCapabilities = [1559, 2718, 2930];
		this.activeCapabilities.push(Capability.EIP155ReplayProtection);

		// Populate the access list fields
		const accessListData = getAccessListData(accessList ?? []);
		this.accessList = accessListData.accessList;
		this.AccessListJSON = accessListData.AccessListJSON;
		// Verify the access list format.
		verifyAccessList(this.accessList);

		this.maxFeePerGas = uint8ArrayToBigInt( toUint8Array(maxFeePerGas === '' ? '0x' : maxFeePerGas) );
		this.maxPriorityFeePerGas = uint8ArrayToBigInt( toUint8Array(maxPriorityFeePerGas === '' ? '0x' : maxPriorityFeePerGas) );

		//this._validateCannotExceedMaxInteger({maxFeePerGas: this.maxFeePerGas,maxPriorityFeePerGas: this.maxPriorityFeePerGas});

		this._validateNotArray(txData);

		if (this.gasLimit * this.maxFeePerGas > MAX_INTEGER) {
			const msg = this._errorMsg('gasLimit * maxFeePerGas cannot exceed MAX_INTEGER (2^256-1)');
			throw new Error(msg);
		}

		if (this.maxFeePerGas < this.maxPriorityFeePerGas) {
			const msg = this._errorMsg('maxFeePerGas cannot be less than maxPriorityFeePerGas (The total must be the larger of the two)');
			throw new Error(msg);
		}

		this._validateYParity();
		this._validateHighS();

		const freeze = opts?.freeze ?? true;
		if (freeze) {
			Object.freeze(this);
		}
	}

	static getDataFee() {
		throw new Error("getDataFee is unimplemeted");
	}

	static getUpfrontCost(baseFee = 0) {
		const prio = this.maxPriorityFeePerGas;
		const maxBase = this.maxFeePerGas - baseFee;
		const inclusionFeePerGas = prio < maxBase ? prio : maxBase;
		const gasPrice = inclusionFeePerGas + baseFee;
		return this.gasLimit * gasPrice + this.value;
	}

	static raw() {
		return [
			bigIntToUnpaddedUint8Array(this.chainId),
			bigIntToUnpaddedUint8Array(this.nonce),
			bigIntToUnpaddedUint8Array(this.maxPriorityFeePerGas),
			bigIntToUnpaddedUint8Array(this.maxFeePerGas),
			bigIntToUnpaddedUint8Array(this.gasLimit),
			this.to !== undefined ? this.to.buf : Uint8Array.from([]),
			bigIntToUnpaddedUint8Array(this.value),
			this.data,
			this.accessList,
			this.v !== undefined ? bigIntToUnpaddedUint8Array(this.v) : Uint8Array.from([]),
			this.r !== undefined ? bigIntToUnpaddedUint8Array(this.r) : Uint8Array.from([]),
			this.s !== undefined ? bigIntToUnpaddedUint8Array(this.s) : Uint8Array.from([]),
		];
	}

	static serialize() {
		const base = this.raw();
		return uint8ArrayConcat(TRANSACTION_TYPE_UINT8ARRAY, RLP.encode(base));
	}

	static getMessageToSign(hashMessage = true) {
		const base = this.raw().slice(0, 9);
		const message = uint8ArrayConcat(TRANSACTION_TYPE_UINT8ARRAY, RLP.encode(base));
		if (hashMessage) {
			return keccak256(message);
		}
		return message;
	}

	static hash() {
		if (!this.isSigned()) {
			const msg = this._errorMsg('Cannot call hash method if transaction is not signed');
			throw new Error(msg);
		}

		if (Object.isFrozen(this)) {
			if (!this.cache.hash) {
				this.cache.hash = keccak256(this.serialize());
			}
			return this.cache.hash;
		}

		return keccak256(this.serialize());
	}

	static getMessageToVerifySignature() {
		return this.getMessageToSign();
	}

	getSenderPublicKey() {
		if (!this.isSigned()) {
			const msg = this._errorMsg('Cannot call this method if transaction is not signed');
			throw new Error(msg);
		}

		const msgHash = this.getMessageToVerifySignature();
		const { v, r, s } = this;

		this._validateHighS();

		try {
			return ecrecover( msgHash, v + 27, bigIntToUnpaddedUint8Array(r), bigIntToUnpaddedUint8Array(s) );
		} catch (e) {
			const msg = this._errorMsg('Invalid Signature');
			throw new Error(msg);
		}
	}

	static _processSignature(v, r, s) {
		const opts = { ...this.txOptions };

		return FeeMarketEIP1559Transaction.fromTxData(
			{
				chainId: this.chainId,
				nonce: this.nonce,
				maxPriorityFeePerGas: this.maxPriorityFeePerGas,
				maxFeePerGas: this.maxFeePerGas,
				gasLimit: this.gasLimit,
				to: this.to,
				value: this.value,
				data: this.data,
				accessList: this.accessList,
				v: v - 27,
				r: uint8ArrayToBigInt(r),
				s: uint8ArrayToBigInt(s),
			},
			opts,
		);
	}

	static toJSON() {
		const accessListJSON = getAccessListJSON(this.accessList);
		return {
			chainId: bigIntToHex(this.chainId),
			nonce: bigIntToHex(this.nonce),
			maxPriorityFeePerGas: bigIntToHex(this.maxPriorityFeePerGas),
			maxFeePerGas: bigIntToHex(this.maxFeePerGas),
			gasLimit: bigIntToHex(this.gasLimit),
			to: this.to !== undefined ? this.to.toString() : undefined,
			value: bigIntToHex(this.value),
			data: bytesToHex(this.data),
			accessList: accessListJSON,
			v: this.v !== undefined ? bigIntToHex(this.v) : undefined,
			r: this.r !== undefined ? bigIntToHex(this.r) : undefined,
			s: this.s !== undefined ? bigIntToHex(this.s) : undefined,
		};
	}

  static supports(capability) {
    return this.activeCapabilities.includes(capability);
  }

   //Checks if the transaction has the minimum amount of gas required (DataFee + TxFee + Creation Fee).
  static validate(stringError = false) {
    const errors = [];

    if (this.getBaseFee() > this.gasLimit) {
      errors.push(`gasLimit is too low. given ${this.gasLimit}, need at least ${this.getBaseFee()}`,);
    }

    if (this.isSigned() && !this.verifySignature()) {
      errors.push('Invalid Signature');
    }

    return stringError ? errors : errors.length === 0;
  }

  static _validateYParity() {
    const { v } = this;
    if (v !== undefined && v !== 0 && v !== 1) {
      const msg = this._errorMsg('The y-parity of the transaction should either be 0 or 1');
      throw new Error(msg);
    }
  }

  static _validateHighS() {
    const { s } = this;
    if (s !== undefined && s > SECP256K1_ORDER_DIV_2) {
      const msg = this._errorMsg(
        'Invalid Signature: s-values greater than secp256k1n/2 are considered invalid',
      );
      throw new Error(msg);
    }
  }

  static getBaseFee() {
		throw new Error("getBaseFee is unimplemeted");
  }

  static _getDataFee() {
    throw new Error("_getDataFee is unimplemeted");
  }

  static toCreationAddress() {
    return this.to === undefined || this.to.buf.length === 0;
  }

  static isSigned() {
    const { v, r, s } = this;
    if (v === undefined || r === undefined || s === undefined) {
      return false;
    }
    return true;
  }

  static verifySignature() {
    try {
      const publicKey = this.getSenderPublicKey();
      return unpadUint8Array(publicKey).length !== 0;
    } catch (e) {
      return false;
    }
  }

  static publicToAddress(_pubKey, sanitize = false) {
    let pubKey = _pubKey;
    assertIsUint8Array(pubKey);
    if (sanitize && pubKey.length !== 64) {
      pubKey = secp256k1.ProjectivePoint.fromHex(pubKey).toRawBytes(false).slice(1);
    }
    if (pubKey.length !== 64) {
      throw new Error('Expected pubKey to be of length 64');
    }
    // Only take the lower 160bits of the hash
    return keccak256(pubKey).slice(-20);
  }

  static getSenderAddress() {
    return this.publicToAddress(this.getSenderPublicKey());
  }

  static sign(privateKey) {
    if (privateKey.length !== 32) {
      const msg = this._errorMsg('Private key must be 32 bytes in length.');
      throw new Error(msg);
    }

    // Hack for the constellation that we have got a legacy tx after spuriousDragon with a non-EIP155 conforming signature
    // and want to recreate a signature (where EIP155 should be applied)
    // Leaving this hack lets the legacy.spec.ts -> sign(), verifySignature() test fail
    // 2021-06-23
    let hackApplied = false;
    if (this.type === 0 && !this.supports(Capability.EIP155ReplayProtection)) {
      this.activeCapabilities.push(Capability.EIP155ReplayProtection);
      hackApplied = true;
    }

    const msgHash = this.getMessageToSign(true);
    const { v, r, s } = this._ecsign(msgHash, privateKey);
    const tx = this._processSignature(v, r, s);

    // Hack part 2
    if (hackApplied) {
      const index = this.activeCapabilities.indexOf(Capability.EIP155ReplayProtection);
      if (index > -1) {
        this.activeCapabilities.splice(index, 1);
      }
    }

    return tx;
  }

  _validateCannotExceedMaxInteger(values, bits = 256, cannotEqual = false) {
    for (const [key, value] of Object.entries(values)) {
      switch (bits) {
        case 64:
          if (cannotEqual) {
            if (value !== undefined && value >= MAX_UINT64) {
              const msg = this._errorMsg(`${key} cannot equal or exceed MAX_UINT64 (2^64-1), given ${value}`);
              throw new Error(msg);
            }
          } else if (value !== undefined && value > MAX_UINT64) {
            const msg = this._errorMsg(`${key} cannot exceed MAX_UINT64 (2^64-1), given ${value}`);
            throw new Error(msg);
          }
          break;
        case 256:
          if (cannotEqual) {
            if (value !== undefined && value >= MAX_INTEGER) {
              const msg = this._errorMsg(`${key} cannot equal or exceed MAX_INTEGER (2^256-1), given ${value}`);
              throw new Error(msg);
            }
          } else if (value !== undefined && value > MAX_INTEGER) {
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

  static _validateNotArray(values) {
    const txDataKeys = [ 'nonce', 'gasPrice', 'gasLimit', 'to', 'value', 'data', 'v', 'r', 's', 'type', 'baseFee', 'maxFeePerGas', 'chainId' ];
    for (const [key, value] of Object.entries(values)) {
      if (txDataKeys.includes(key)) {
        if (Array.isArray(value)) {
          throw new Error(`${key} cannot be an array`);
        }
      }
    }
  }

  static _getSharedErrorPostfix() {
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
		/*
    let hf = '';
    try {
      hf = this.common.hardfork();
    } catch (e) {
      hf = 'error';
    }
		*/
    let postfix = `tx type=${this.type} hash=${hash} nonce=${this.nonce} value=${this.value} `;
    postfix += `signed=${isSigned}`;// hf=${hf}`;

    return postfix;
  }

  static _ecsign(msgHash, privateKey, chainId) {
    const signature = secp256k1.sign(msgHash, privateKey);
    const signatureBytes = signature.toCompactRawBytes();

    const r = signatureBytes.subarray(0, 32);
    const s = signatureBytes.subarray(32, 64);
    const v = chainId === undefined ? (signature.recovery + 27) : (signature.recovery + 35) + (chainId) * (2);

    return { r, s, v };
  }

	static errorStr() {
		let errorStr = this._getSharedErrorPostfix();
		errorStr += ` maxFeePerGas=${this.maxFeePerGas} maxPriorityFeePerGas=${this.maxPriorityFeePerGas}`;
		return errorStr;
	}

	static _errorMsg(msg) {
		return `${msg} (${this.errorStr()})`;
	}

}
