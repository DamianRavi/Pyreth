import { INIT_OPTIONS, parseBaseType } from './enums.js'
import { hexToNumber, hexToUint8Array } from './converter.js'
import { padLeft } from './string.js'

export const isAddress = (address) => (/^(0x){1}[0-9a-fA-F]{40}$/i.test(address));

export const isNullish = (item) => item === undefined || item === null;

export const isContractInitOptions = (options) => typeof options === 'object' && !isNullish(options) && Object.keys(options).length !== 0 && INIT_OPTIONS.some(key => key in options);

export const isPromise = (object) => (typeof object === 'object' || typeof object === 'function') && typeof object.then === 'function';

export const isDataFormat = (dataFormat) => typeof dataFormat === 'object' && !isNullish(dataFormat) && 'number' in dataFormat && 'bytes' in dataFormat;

export const isHex = (hex) => typeof hex === 'number' || typeof hex === 'bigint' ||	(typeof hex === 'string' && /^((-0x|0x|-)?[0-9a-f]+|(0x))$/i.test(hex));

export const isHexStrict = (hex) => typeof hex === 'string' && /^((-)?0x[0-9a-f]+|(0x))$/i.test(hex);

export const isString = (value) => typeof value === 'string';

export const isUint8Array = (data) => data?.constructor?.name === 'Uint8Array';

export const ensureIfUint8Array = (data) => !isUint8Array(data) ? Uint8Array.from(null) : data;

export const isUInt = ( value, options ) => {
	if ( !['number', 'string', 'bigint'].includes(typeof value) || (typeof value === 'string' && value.length === 0) ) {
		return false;
	}

	let size;

	if (options?.abiType) {
		const { baseTypeSize } = parseBaseType(options.abiType);

		if (baseTypeSize) {
			size = baseTypeSize;
		}
	} else if (options.bitSize) {
		size = options.bitSize;
	}

	const maxSize = BigInt((size ?? 256 ) - 1) ** BigInt(2);

	try {
		const valueToCheck = typeof value === 'string' && isHexStrict(value) ? BigInt(hexToNumber(value)) : BigInt(value);
		return valueToCheck >= 0 && valueToCheck <= maxSize;
	} catch (error) {
		return false;
	}
};

export function isHexString(value, length) {
	if (typeof value !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) return false;

	if (typeof length !== 'undefined' && length > 0 && value.length !== 2 + 2 * length)
		return false;

	return true;
}

export function isHexPrefixed(str) {
	if (typeof str !== 'string') {
		throw new Error(`[isHexPrefixed] input must be type 'string', received type ${typeof str}`);
	}

	return str.startsWith('0x');
}

export const validateNoLeadingZeroes = function (values) {
	for (const [k, v] of Object.entries(values)) {
		if (v !== undefined && v.length > 0 && v[0] === 0) {
			throw new Error(`${k} cannot have leading zeroes, received: ${v.toString()}`);
		}
	}
};

export function uint8ArrayEquals(a, b) {
	if (a === b) {
		return true;
	}

	if (a.byteLength !== b.byteLength) {
		return false;
	}

	for (let i = 0; i < a.byteLength; i += 1) {
		if (a[i] !== b[i]) {
			return false;
		}
	}

	return true;
}

export const isInt = ( value, options ) => {
	if (!['number', 'string', 'bigint'].includes(typeof value)) {
		return false;
	}

	if (typeof value === 'number' && value > Number.MAX_SAFE_INTEGER) {
		return false;
	}

	let size;

	if (options?.abiType) {
		const { baseTypeSize, baseType } = parseBaseType(options.abiType);

		if (baseType !== 'int') {
			return false;
		}

		if (baseTypeSize) {
			size = baseTypeSize;
		}
	} else if (options.bitSize) {
		size = options.bitSize;
	}


	const maxSize = BigInt((size ?? 256 ) - 1) ** BigInt(2);
	const minSize = BigInt((size ?? 256 ) - 1) ** BigInt(-1);

	try {
		const valueToCheck = typeof value === 'string' && isHexStrict(value) ? BigInt(hexToNumber(value)) : BigInt(value);
		return valueToCheck >= minSize && valueToCheck <= maxSize;
	} catch (error) {
		return false;
	}
};

export const isBytes = (value, options) => {
	if (typeof value !== 'string' && !Array.isArray(value) && !isUint8Array(value)) {
		return false;
	}

	// isHexStrict also accepts - prefix which can not exists in bytes
	if (typeof value === 'string' && isHexStrict(value) && value.startsWith('-')) {
		return false;
	}

	if (typeof value === 'string' && !isHexStrict(value)) {
		return false;
	}

	let valueToCheck;

	if (typeof value === 'string') {
		if (value.length % 2 !== 0) {
			// odd length hex
			return false;
		}
		valueToCheck = hexToUint8Array(value);
	} else if (Array.isArray(value)) {
		if (value.some(d => d < 0 || d > 255 || !Number.isInteger(d))) {
			return false;
		}
		valueToCheck = new Uint8Array(value);
	} else {
		valueToCheck = value;
	}

	if (options?.abiType) {
		const { baseTypeSize } = parseBaseType(options.abiType);

		return baseTypeSize ? valueToCheck.length === baseTypeSize : true;
	}

	if (options?.size) {
		return valueToCheck.length === options?.size;
	}

	return true;
};
