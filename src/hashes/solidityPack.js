import { utf8ToHex, toTwosComplement, toNumber, hexToNumber, numberToHex } from '../converter.js'
import { leftPad, rightPad } from '../string.js'
import { isAddress, isHex, isHexStrict } from '../validator.js'
import { isInt, isUInt } from './types.js'
import { InvalidStringError, InvalidBooleanError, InvalidAddressError, InvalidBytesError, InvalidLargeValueError, InvalidUnsignedIntegerError, InvalidSizeError, HexProcessingError } from '../errors.js'

const elementaryName = (name) => {
	if (name.startsWith('int[')) {
		return `int256${name.slice(3)}`;
	}
	if (name === 'int') {
		return 'int256';
	}
	if (name.startsWith('uint[')) {
		return `uint256'${name.slice(4)}`;
	}
	if (name === 'uint') {
		return 'uint256';
	}
	return name;
};

const bitLength = (value) => {
	const updatedVal = value.toString(2);
	return updatedVal.length;
};

const parseTypeN = (value, typeLength) => {
	const typesize = /^(\d+).*$/.exec(value.slice(typeLength));
	return typesize ? parseInt(typesize[1], 10) : 0;
};

export const toHex = ( value, returnType ) => {
	if (typeof value === 'string' && isAddress(value)) {
		return returnType ? 'address' : `0x${value.toLowerCase().replace(/^0x/i, '')}`;
	}

	if (typeof value === 'boolean') {
		// eslint-disable-next-line no-nested-ternary
		return returnType ? 'bool' : value ? '0x01' : '0x00';
	}

	if (typeof value === 'number') {
		// eslint-disable-next-line no-nested-ternary
		return returnType ? (value < 0 ? 'int256' : 'uint256') : numberToHex(value);
	}

	if (typeof value === 'bigint') {
		return returnType ? 'bigint' : numberToHex(value);
	}

	if (typeof value === 'object' && !!value) {
		return returnType ? 'string' : utf8ToHex(JSON.stringify(value));
	}

	if (typeof value === 'string') {
		if (value.startsWith('-0x') || value.startsWith('-0X')) {
			return returnType ? 'int256' : numberToHex(value);
		}

		if (isHexStrict(value)) {
			return returnType ? 'bytes' : value;
		}
		if (isHex(value) && !isInt(value) && !isUInt(value)) {
			return returnType ? 'bytes' : `0x${value}`;
		}
		if (isHex(value) && !isInt(value) && isUInt(value)) {
			return returnType ? 'uint' : numberToHex(value);
		}

		if (!Number.isFinite(value)) {
			return returnType ? 'string' : utf8ToHex(value);
		}
	}

	throw new HexProcessingError(value);
};

const getType = (arg) => {
	if (Array.isArray(arg)) {
		throw new Error('Autodetection of array types is not supported.');
	}

	let type;
	let value;
	// if type is given
	if (
		typeof arg === 'object' &&
		('t' in arg || 'type' in arg) &&
		('v' in arg || 'value' in arg)
	) {
		type = 't' in arg ? arg.t : arg.type;
		value = 'v' in arg ? arg.v : arg.value;

		type = type.toLowerCase() === 'bigint' ? 'int' : type;
	} else if (typeof arg === 'bigint') {
		return ['int', arg];
	}
	// otherwise try to guess the type
	else {
		type = toHex(arg, true);
		value = toHex(arg);

		if (!type.startsWith('int') && !type.startsWith('uint')) {
			type = 'bytes';
		}
	}

	if (
		(type.startsWith('int') || type.startsWith('uint')) &&
		typeof value === 'string' &&
		!/^(-)?0x/i.test(value)
	) {
		value = BigInt(value);
	}
	return [type, value];
};

const solidityPack = (type, val) => {
	const value = val.toString();
	if (type === 'string') {
		if (typeof val === 'string') return utf8ToHex(val);
		throw new InvalidStringError(val);
	}
	if (type === 'bool' || type === 'boolean') {
		if (typeof val === 'boolean') return val ? '01' : '00';
		throw new InvalidBooleanError(val);
	}

	if (type === 'address') {
		if (!isAddress(value)) {
			throw new InvalidAddressError(value);
		}
		return value;
	}
	const name = elementaryName(type);
	if (type.startsWith('uint')) {
		const size = parseTypeN(name, 'uint'.length);

		if (size % 8 || size < 8 || size > 256) {
			throw new InvalidSizeError(value);
		}
		const num = toNumber(value);
		if (bitLength(num) > size) {
			throw new InvalidLargeValueError(value);
		}
		if (num < BigInt(0)) {
			throw new InvalidUnsignedIntegerError(value);
		}

		return size ? leftPad(num.toString(16), (size / 8) * 2) : num.toString(16);
	}

	if (type.startsWith('int')) {
		const size = parseTypeN(name, 'int'.length);
		if (size % 8 || size < 8 || size > 256) {
			throw new InvalidSizeError(type);
		}

		const num = toNumber(value);
		if (bitLength(num) > size) {
			throw new InvalidLargeValueError(value);
		}
		if (num < BigInt(0)) {
			return toTwosComplement(num.toString(), (size / 8) * 2);
		}
		return size ? leftPad(num.toString(16), size / 4) : num.toString(16);
	}

	if (name === 'bytes') {
		if (value.replace(/^0x/i, '').length % 2 !== 0) {
			throw new InvalidBytesError(value);
		}
		return value;
	}

	if (type.startsWith('bytes')) {
		if (value.replace(/^0x/i, '').length % 2 !== 0) {
			throw new InvalidBytesError(value);
		}

		const size = parseTypeN(type, 'bytes'.length);

		if (!size || size < 1 || size > 64 || size < value.replace(/^0x/i, '').length / 2) {
			throw new InvalidBytesError(value);
		}

		return rightPad(value, size * 2);
	}
	return '';
};

export const processSolidityEncodePackedArgs = (arg) => {
	const [type, val] = getType(arg);

	// array case
	if (Array.isArray(val)) {
		// go through each element of the array and use map function to create new hexarg list
		const hexArg = val.map((v) => solidityPack(type, v).replace('0x', ''));
		return hexArg.join('');
	}

	const hexArg = solidityPack(type, val);
	return hexArg.replace('0x', '');
};

/**
 * Encode packed arguments to a hexstring
 */
export const encodePacked = (...values) => {
	const hexArgs = values.map(processSolidityEncodePackedArgs);
	return `0x${hexArgs.join('').toLowerCase()}`;
};
