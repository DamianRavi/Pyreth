import { hexToNumber } from '../converter.js'
import { isHexStrict } from '../validator.js'

export const VALID_ETH_BASE_TYPES = ['bool', 'int', 'uint', 'bytes', 'string', 'address', 'tuple'];

export const parseBaseType = (type) => {
	// Remove all empty spaces to avoid any parsing issue.
	let strippedType = type.replace(/ /, '');
	let baseTypeSize;
	let isArray;
	let arraySizes = [];

	if (type.includes('[')) {
		strippedType = strippedType.slice(0, strippedType.indexOf('['));
		arraySizes = [...type.matchAll(/(?:\[(\d*)\])/g)].map(match => parseInt(match[1], 10)).map(size => (Number.isNaN(size) ? -1 : size));
		isArray = arraySizes.length > 0;
	}

	if (VALID_ETH_BASE_TYPES.includes(strippedType)) {
		return { baseType: strippedType, isArray, baseTypeSize, arraySizes };
	}

	if (strippedType.startsWith('int')) {
		baseTypeSize = parseInt(strippedType.substring(3), 10);
		strippedType = 'int';
	} else if (strippedType.startsWith('uint')) {
		baseTypeSize = parseInt(type.substring(4), 10);
		strippedType = 'uint';
	} else if (strippedType.startsWith('bytes')) {
		baseTypeSize = parseInt(strippedType.substring(5), 10);
		strippedType = 'bytes';
	} else {
		return { baseType: undefined, isArray: false, baseTypeSize: undefined, arraySizes };
	}

	return { baseType: strippedType, isArray, baseTypeSize, arraySizes };
};

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
	}
  catch (error) {
		return false;
	}
};

export const isInt = (value, options) => {
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
	}
  else if (options.bitSize) {
		size = options.bitSize;
	}

	const maxSize = BigInt((size ?? 256 ) - 1) ** BigInt(2);
	const minSize = BigInt((size ?? 256 ) - 1) ** BigInt(-1);

	try {
		const valueToCheck = typeof value === 'string' && isHexStrict(value) ? BigInt(hexToNumber(value)) : BigInt(value);
		return valueToCheck >= minSize && valueToCheck <= maxSize;
	}
  catch (error) {
		return false;
	}
};

export const isNumber = (value) => {
	if (isInt(value)) {
		return true;
	}

	// It would be a decimal number
	if ( typeof value === 'string' && /[0-9.]/.test(value) && value.indexOf('.') === value.lastIndexOf('.') ) {
		return true;
	}

	if (typeof value === 'number') {
		return true;
	}

	return false;
};
