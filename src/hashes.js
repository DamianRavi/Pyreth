import { encodePacked } from './hashes/solidityPack.js';
import { SHA3_EMPTY_BYTES } from './enums.js'
import { isHexStrict, isUint8Array } from './validator.js'
import { bytesToHex, hexToBytes, utf8ToBytes } from './converter.js'
import { InvalidAddressError } from './errors.js'
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';

export const sha3Raw = (data) => {
	if (typeof data === 'string') {
		if (data.startsWith('0x') && isHexStrict(data)) {
			data = hexToBytes(data);
		} else {
			data = utf8ToBytes(data);
		}
	}
  !isUint8Array(data) ?? new InvalidAddressError(data);
	return bytesToHex(keccak256(data));
}

export const sha3 = (data) => {
  const hash = sha3Raw(data);
	return hash === SHA3_EMPTY_BYTES ? undefined : hash;
}

export const soliditySha3Raw = (data) => {
  sha3Raw(encodePacked(data))
}

export const soliditySha3 = (data) => {
  sha3(encodePacked(data))
}
