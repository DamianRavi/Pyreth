import { utf8ToBytes, hexToUtf8, bytesToUint8Array, bytesToHex, uint8ArrayToBigInt, uint8ArrayConcat, bigIntToUint8Array, hexToUint8Array, uint8ArrayToHexString, toNumber } from '../../../converter.js'
import { isBytes, isAddress, isHexStrict } from '../../../validator.js'
import { toChecksumAddress } from '../../../converter.js'
import { Buffer } from 'buffer'
const MAX_STATIC_BYTES_COUNT = 32;
const ADDRESS_BYTES_COUNT = 20;
const WORD_SIZE = 32;
const ADDRESS_OFFSET = WORD_SIZE - ADDRESS_BYTES_COUNT;

export const numberLimits = new Map();

let base = 256; // 2 ^ 8 = 256
for (let i = 8; i <= 256; i += 8) {
	numberLimits.set(`uint${i}`, { min: 0, max: base - 1 });
	numberLimits.set(`int${i}`, { min: -base / 2, max: base / 2 - 1 });
	base *= 256;
}

numberLimits.set(`int`, numberLimits.get('int256'));
numberLimits.set(`uint`, numberLimits.get('uint256'));


export const toBool = (value) => {
	if (typeof value === 'boolean') {
		return value;
	}

	if (typeof value === 'number' && (value === 0 || value === 1)) {
		return Boolean(value);
	}

	if (typeof value === 'bigint' && (value === BigInt(0) || value === BigInt(1))) {
		return Boolean(value);
	}

	if (
		typeof value === 'string' &&
		!isHexStrict(value) &&
		(value === '1' || value === '0' || value === 'false' || value === 'true')
	) {
		if (value === 'true') {
			return true;
		}
		if (value === 'false') {
			return false;
		}
		return Boolean(Number(value));
	}

	if (typeof value === 'string' && isHexStrict(value) && (value === '0x1' || value === '0x0')) {
		return Boolean(toNumber(value));
	}

	throw new Error(value);
};

export function encodeParamFromAbiParameter(param, value) {
	if (param.type === 'string') {
		return encodeString(param, value);
	}
	if (param.type === 'bool') {
		return encodeBoolean(param, value);
	}
	if (param.type === 'address') {
		return encodeAddress(param, value);
	}
	if (param.type === 'tuple') {
		return encodeTuple(param, value);
	}
	if (param.type.endsWith(']')) {
		return encodeArray(param, value);
	}
	if (param.type.startsWith('bytes')) {
		return encodeBytes(param, value);
	}
	if (param.type.startsWith('uint') || param.type.startsWith('int')) {
		return encodeNumber(param, value);
	}
	throw new Error('Unsupported', {
		param,
		value,
	});
}

export function decodeParamFromAbiParameter(param, bytes) {
	if (param.type === 'string') {
		return decodeString(param, bytes);
	}
	if (param.type === 'bool') {
		return decodeBool(param, bytes);
	}
	if (param.type === 'address') {
		return decodeAddress(param, bytes);
	}
	if (param.type === 'tuple') {
		return decodeTuple(param, bytes);
	}
	if (param.type.endsWith(']')) {
		return decodeArray(param, bytes);
	}
	if (param.type.startsWith('bytes')) {
		return decodeBytes(param, bytes);
	}
	if (param.type.startsWith('uint') || param.type.startsWith('int')) {
		return decodeNumber(param, bytes);
	}
	throw new Error('Unsupported', { param, bytes });
}



export function extractArrayType(param) {
	const arrayParenthesisStart = param.type.lastIndexOf('[');
	const arrayParamType = param.type.substring(0, arrayParenthesisStart);
	const sizeString = param.type.substring(arrayParenthesisStart);
	let size = -1;
	if (sizeString !== '[]') {
		size = Number(sizeString.slice(1, -1));
		// eslint-disable-next-line no-restricted-globals
		if (isNaN(size)) {
			throw new Error('Invalid fixed array size', { size: sizeString });
		}
	}
	return {
		param: { type: arrayParamType, name: '', components: param.components },
		size,
	};
}

export function isDynamic(param) {
	if (param.type === 'string' || param.type === 'bytes' || param.type.endsWith('[]')) return true;
	if (param.type === 'tuple') {
		return param.components?.some(isDynamic) ?? false;
	}
	if (param.type.endsWith(']')) {
		return isDynamic(extractArrayType(param).param);
	}
	return false;
}





function alloc(size = 0) {
	if (Buffer?.alloc !== undefined) {
		const buf = Buffer.alloc(size);
		return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
	}

	return new Uint8Array(size);
}



export function encodeBoolean(param, input) {
	let value;
	try {
		value = toBool(input);
	} catch (e) {
		throw new Error('provided input is not valid boolean value', { type: param.type, value: input, name: param.name});
	}

	return encodeNumber({ type: 'uint8', name: '' }, Number(value));
}

export function decodeBool(_param, bytes) {
	const numberResult = decodeNumber({ type: 'uint8', name: '' }, bytes);
	if (numberResult.result > 1 || numberResult.result < 0) {
		throw new Error('Invalid boolean value encoded', { boolBytes: bytes.subarray(0, WORD_SIZE), numberResult });
	}
	return { result: numberResult.result === BigInt(1), encoded: numberResult.encoded, consumed: WORD_SIZE };
}





export function encodeString(_param, input) {
	if (typeof input !== 'string') {
		throw new Error('invalid input, should be string', { input });
	}
	const bytes = utf8ToBytes(input);
	return encodeBytes({ type: 'bytes', name: '' }, bytes);
}

export function decodeString(_param, bytes) {
	const r = decodeBytes({ type: 'bytes', name: '' }, bytes);
	return { result: hexToUtf8(r.result), encoded: r.encoded, consumed: r.consumed };
}

export function encodeBytes(param, input) {
	// hack for odd length hex strings
	if (typeof input === 'string' && input.length % 2 !== 0) {
		// eslint-disable-next-line no-param-reassign
		input += '0';
	}
	if (!isBytes(input)) {
		throw new Error('provided input is not valid bytes value', { type: param.type, value: input, name: param.name });
	}
	const bytes = bytesToUint8Array(input);
	const [, size] = param.type.split('bytes');
	// fixed size
	if (size) {
		if (Number(size) > MAX_STATIC_BYTES_COUNT || Number(size) < 1) {
			throw new Error( 'invalid bytes type. Static byte type can have between 1 and 32 bytes', { type: param.type } );
		}
		if (Number(size) < bytes.length) {
			throw new Error('provided input size is different than type size', { type: param.type, value: input, name: param.name });
		}
		const encoded = alloc(WORD_SIZE);
		encoded.set(bytes);
		return { dynamic: false, encoded };
	}

	const partsLength = Math.ceil(bytes.length / WORD_SIZE);
	// one word for length of data + WORD for each part of actual data
	const encoded = alloc(WORD_SIZE + partsLength * WORD_SIZE);

	encoded.set(encodeNumber({ type: 'uint32', name: '' }, bytes.length).encoded);
	encoded.set(bytes, WORD_SIZE);
	return { dynamic: true, encoded };
}

export function decodeBytes(param, bytes) {
	const [, sizeString] = param.type.split('bytes');
	let size = Number(sizeString);
	let remainingBytes = bytes;
	let partsCount = 1;
	let consumed = 0;
	if (!size) {
		// dynamic bytes
		const result = decodeNumber({ type: 'uint32', name: '' }, remainingBytes);
		size = Number(result.result);
		consumed += result.consumed;
		remainingBytes = result.encoded;
		partsCount = Math.ceil(size / WORD_SIZE);
	}
	if (size > bytes.length) {
		throw new Error('there is not enough data to decode', { type: param.type, encoded: bytes, size });
	}

	return { result: bytesToHex(remainingBytes.subarray(0, size)), encoded: remainingBytes.subarray(partsCount * WORD_SIZE), consumed: consumed + partsCount * WORD_SIZE };
}

export function encodeNumber(param, input) {
	let value;
	try {
		value = BigInt(input);
	} catch (e) {
		throw new Error('provided input is not number value', { type: param.type, value: input, name: param.name });
	}
	const limit = numberLimits.get(param.type);
	if (!limit) {
		throw new Error('provided abi contains invalid number datatype', { type: param.type });
	}
	if (value < limit.min) {
		throw new Error('provided input is less then minimum for given type', { type: param.type, value: input, name: param.name, minimum: limit.min.toString() });
	}
	if (value > limit.max) {
		throw new Error('provided input is greater then maximum for given type', { type: param.type, value: input, name: param.name, maximum: limit.max.toString() });
	}
	return { dynamic: false, encoded: bigIntToUint8Array(value) };
}

export function decodeNumber(param, bytes) {
	if (bytes.length < WORD_SIZE) {
		throw new Error('Not enough bytes left to decode', { param, bytesLeft: bytes.length });
	}
	const boolBytes = bytes.subarray(0, WORD_SIZE);
	const limit = numberLimits.get(param.type);
	if (!limit) {
		throw new Error('provided abi contains invalid number datatype', { type: param.type });
	}
	const numberResult = uint8ArrayToBigInt(boolBytes, limit.max);

	if (numberResult < limit.min) {
		throw new Error('decoded value is less then minimum for given type', { type: param.type, value: numberResult, name: param.name, minimum: limit.min.toString() });
	}
	if (numberResult > limit.max) {
		throw new Error('decoded value is greater then maximum for given type', { type: param.type, value: numberResult, name: param.name, maximum: limit.max.toString() });
	}
	return { result: numberResult.toString(), encoded: bytes.subarray(WORD_SIZE), consumed: WORD_SIZE }; // !!! changed to string not BN
}


export function encodeAddress(param, input) {
	if (typeof input !== 'string') {
		throw new Error('address type expects string as input type', { value: input, name: param.name, type: param.type });
	}
	let address = input.toLowerCase();
	if (!address.startsWith('0x')) {
		address = `0x${address}`;
	}
	if (!isAddress(address)) {
		throw new Error('provided input is not valid address', { value: input, name: param.name, type: param.type });
	}
	const addressBytes = hexToUint8Array(address);
	const encoded = alloc(WORD_SIZE);
	encoded.set(addressBytes, ADDRESS_OFFSET);
	return { dynamic: false, encoded };
}

export function decodeAddress(_param, bytes) {
	const addressBytes = bytes.subarray(ADDRESS_OFFSET, WORD_SIZE);
	if (addressBytes.length !== ADDRESS_BYTES_COUNT) {
		throw new Error('Invalid decoding input, not enough bytes to decode address', { bytes });
	}
	const result = uint8ArrayToHexString(addressBytes);

	return { result: toChecksumAddress(result), encoded: bytes.subarray(WORD_SIZE), consumed: WORD_SIZE };
}

export function encodeArray(param, values) {
	if (!Array.isArray(values)) {
		throw new Error('Expected value to be array', { abi: param, values });
	}
	const { size, param: arrayItemParam } = extractArrayType(param);
	const encodedParams = values.map(v => encodeParamFromAbiParameter(arrayItemParam, v));
	const dynamic = size === -1;
	const dynamicItems = encodedParams.length > 0 && encodedParams[0].dynamic;
	if (!dynamic && values.length !== size) {
		throw new Error("Given arguments count doesn't match array length", { arrayLength: size, argumentsLength: values.length });
	}
	if (dynamic || dynamicItems) {
		const encodingResult = encodeDynamicParams(encodedParams);
		if (dynamic) {
			const encodedLength = encodeNumber( { type: 'uint256', name: '' }, encodedParams.length ).encoded;
			return { dynamic: true, encoded: encodedParams.length > 0 ? uint8ArrayConcat(encodedLength, encodingResult) : encodedLength };
		}
		return { dynamic: true, encoded: encodingResult };
	}

	return { dynamic: false, encoded: uint8ArrayConcat(...encodedParams.map(p => p.encoded)) };
}

export function decodeArray(param, bytes){
	// eslint-disable-next-line prefer-const
	let { size, param: arrayItemParam } = extractArrayType(param);
	const dynamic = size === -1;

	let consumed = 0;
	const result = [];
	let remaining = bytes;
	// dynamic array, we need to decode length
	if (dynamic) {
		const lengthResult = decodeNumber({ type: 'uint32', name: '' }, bytes);
		size = Number(lengthResult.result);
		consumed = lengthResult.consumed;
		remaining = lengthResult.encoded;
	}
	const hasDynamicChild = isDynamic(arrayItemParam);
	if (hasDynamicChild) {
		// known length but dynamic child, each child is actually head element with encoded offset
		for (let i = 0; i < size; i += 1) {
			const offsetResult = decodeNumber(
				{ type: 'uint32', name: '' },
				remaining.subarray(i * WORD_SIZE),
			);
			consumed += offsetResult.consumed;
			const decodedChildResult = decodeParamFromAbiParameter(
				arrayItemParam,
				remaining.subarray(Number(offsetResult.result)),
			);
			consumed += decodedChildResult.consumed;
			result.push(decodedChildResult.result);
		}
		return { result, encoded: remaining.subarray(consumed), consumed };
	}

	for (let i = 0; i < size; i += 1) {
		// decode static params
		const decodedChildResult = decodeParamFromAbiParameter( arrayItemParam, bytes.subarray(consumed) );
		consumed += decodedChildResult.consumed;
		result.push(decodedChildResult.result);
	}
	return { result, encoded: bytes.subarray(consumed), consumed };
}

export function encodeTuple(param, input) {
	let dynamic = false;
	if (!Array.isArray(input) && typeof input !== 'object') {
		throw new Error('param must be either Array or Object', {param, input});
	}
	const narrowedInput = input;
	const encoded = [];
	for (let i = 0; i < (param.components?.length ?? 0); i += 1) {
		const paramComponent = param.components[i];
		let result;
		if (Array.isArray(narrowedInput)) {
			if (i >= narrowedInput.length) {
				throw new Error('input param length missmatch', {param, input});
			}
			result = encodeParamFromAbiParameter(paramComponent, narrowedInput[i]);
		} else {
			const paramInput = narrowedInput[paramComponent.name ?? ''];
			if (paramInput === undefined || paramInput === null) {
				throw new Error('missing input defined in abi', { param, input, paramName: paramComponent.name });
			}
			result = encodeParamFromAbiParameter(paramComponent, paramInput);
		}
		if (result.dynamic) {
			dynamic = true;
		}
		encoded.push(result);
	}

	if (dynamic) {
		return { dynamic: true, encoded: encodeDynamicParams(encoded) };
	}
	return { dynamic: false, encoded: uint8ArrayConcat(...encoded.map(e => e.encoded)) };
}

export function decodeTuple(param, bytes) {
	const result = { __length__: 0 };
	let consumed = 0;

	if (!param.components) {
		return { result, encoded: bytes, consumed };
	}

	let dynamicConsumed = 0;
	for (const [index, childParam] of param.components.entries()) {
		let decodedResult;
		if (isDynamic(childParam)) {
			const offsetResult = decodeNumber( { type: 'uint32', name: '' }, bytes.subarray(consumed) );
			decodedResult = decodeParamFromAbiParameter( childParam, bytes.subarray(Number(offsetResult.result)) );
			consumed += offsetResult.consumed;
			dynamicConsumed += decodedResult.consumed;
		} else {
			decodedResult = decodeParamFromAbiParameter(childParam, bytes.subarray(consumed));
			consumed += decodedResult.consumed;
		}
		result.__length__ += 1;
		result[index] = decodedResult.result;
		if (childParam.name && childParam.name !== '') {
			result[childParam.name] = decodedResult.result;
		}
	}
	return { encoded: bytes.subarray(consumed + dynamicConsumed), result, consumed: consumed + dynamicConsumed };
}

export function encodeDynamicParams(encodedParams) {
	let staticSize = 0;
	let dynamicSize = 0;
	const staticParams = [];
	const dynamicParams = [];
	// figure out static size
	for (const encodedParam of encodedParams) {
		if (encodedParam.dynamic) {
			staticSize += WORD_SIZE;
		} else {
			staticSize += encodedParam.encoded.length;
		}
	}

	for (const encodedParam of encodedParams) {
		if (encodedParam.dynamic) {
			staticParams.push(
				encodeNumber({ type: 'uint256', name: '' }, staticSize + dynamicSize),
			);
			dynamicParams.push(encodedParam);
			dynamicSize += encodedParam.encoded.length;
		} else {
			staticParams.push(encodedParam);
		}
	}
	return uint8ArrayConcat( ...staticParams.map(p => p.encoded), ...dynamicParams.map(p => p.encoded) );
}
