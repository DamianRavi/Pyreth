import { parseAbiParameter } from './abitype.js'; //AbiParameter as ExternalAbiParameter,
import { sha3Raw } from '../../../hashes.js'
import { rightPad, leftPad } from '../../../string.js'
import { isNullish, isUint8Array } from '../../../validator.js'
import { toHex, uint8ArrayConcat, uint8ArrayToHexString, hexToUint8Array, bigIntToUint8Array, uint8ArrayToBigInt } from '../../../converter.js'
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { encodeNumber, decodeNumber, encodeParamFromAbiParameter, decodeParamFromAbiParameter, encodeTuple, decodeTuple, encodeDynamicParams } from './utils.js'
const WORD_SIZE = 32;

const STATIC_TYPES = ['bool', 'string', 'int', 'uint', 'address', 'fixed', 'ufixed'];

const _decodeParameter = (inputType, clonedTopic) => inputType === 'string' ? clonedTopic : decodeParameter(inputType, clonedTopic);

const TYPE_REGEX = /^\w+/;
const paramTypeBytes = /^bytes([0-9]*)$/;
const paramTypeBytesArray = /^bytes([0-9]*)\[\]$/;
const paramTypeNumber = /^(u?int)([0-9]*)$/;
const paramTypeNumberArray = /^(u?int)([0-9]*)\[\]$/;

const getTypeHash = (typedData, type) => keccak256(encodeType(typedData, type));
const getStructHash = (	typedData, type, data ) => keccak256(encodeData(typedData, type, data));
const ARRAY_REGEX = /^(.*)\[([0-9]*?)]$/;


const getDependencies = ( typedData, type, dependencies = []) => {
	const match = type.match(TYPE_REGEX);
	const actualType = match[0];
	if (dependencies.includes(actualType)) {
		return dependencies;
	}

	if (!typedData.types[actualType]) {
		return dependencies;
	}

	return [
		actualType,
		...typedData.types[actualType].reduce(
			(previous, _type) => [
				...previous,
				...getDependencies(typedData, _type.type, previous).filter(
					dependency => !previous.includes(dependency),
				),
			],
			[],
		),
	];
};


const encodeType = (typedData, type) => {
	const [primary, ...dependencies] = getDependencies(typedData, type);
	// eslint-disable-next-line @typescript-eslint/require-array-sort-compare
	const types = [primary, ...dependencies.sort()];

	return types
		.map(
			dependency =>
				// eslint-disable-next-line @typescript-eslint/restrict-template-expressions
				`${dependency}(${typedData.types[dependency].map(
					_type => `${_type.type} ${_type.name}`,
				)})`,
		)
		.join('');
};


const encodeData = (typedData, type, data) => {
	const [types, values] = typedData.types[type].reduce(
		([_types, _values], field) => {
			if (isNullish(data[field.name]) || isNullish(data[field.name])) {
				throw new Error(`Cannot encode data: missing data for '${field.name}'`, { data, field});
			}

			const value = data[field.name];
			const [_type, encodedValue] = encodeValue(typedData, field.type, value);

			return [
				[..._types, _type],
				[..._values, encodedValue],
			];
		},
		[['bytes32'], [getTypeHash(typedData, type)]],
	);

	return encodeParameters(types, values);
};

const encodeValue = ( typedData, type, data ) => {
	const match = type.match(ARRAY_REGEX);

	// Checks for array types
	if (match) {
		const arrayType = match[1];
		const length = Number(match[2]) || undefined;

		if (!Array.isArray(data)) {
			throw new Error('Cannot encode data: value is not of array type', { data });
		}

		if (length && data.length !== length) {
			throw new Error( `Cannot encode data: expected length of ${length}, but got ${data.length}`, { data } );
		}

		const encodedData = data.map(item => encodeValue(typedData, arrayType, item));
		const types = encodedData.map(item => item[0]);
		const values = encodedData.map(item => item[1]);

		return ['bytes32', keccak256(encodeParameters(types, values))];
	}

	if (typedData.types[type]) {
		return ['bytes32', getStructHash(typedData, type, data)];
	}

	// Strings and arbitrary byte arrays are hashed to bytes32
	if (type === 'string') {
		return ['bytes32', keccak256(data)];
	}

	if (type === 'bytes') {
		return ['bytes32', keccak256(data)];
	}

	return [type, data];
};

function inferParamsAbi(params) {
	const abi = [];
	params.forEach(param => {
		if (Array.isArray(param)) {
			const inferredParams = inferParamsAbi(param);
			abi.push({ type: 'tuple', components: inferredParams, name: '' });
		} else {
			abi.push({ type: toHex(param, true) });
		}
	});
	return abi;
}

export function convertExternalAbiParameter(abiParam) {
	return { ...abiParam, name: abiParam.name ?? '', components: abiParam.components?.map(c => convertExternalAbiParameter(c)) };
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


function isAbiParameter(param) {
	return (!isNullish(param) && typeof param === 'object' && !isNullish(param.type) && typeof param.type === 'string');
}


function toAbiParams(abi) {
	return abi.map(input => {
		if (isAbiParameter(input)) {
			return input;
		}
		if (typeof input === 'string') {
			return convertExternalAbiParameter(parseAbiParameter(input.replace(/tuple/, '')));
		}

		if (isSimplifiedStructFormat(input)) {
			const structName = Object.keys(input)[0];
			const structInfo = mapStructNameAndType(structName);
			structInfo.name = structInfo.name ?? '';
			return {
				...structInfo,
				components: mapStructToCoderFormat(
					input[structName],
				),
			};
		}
		throw new Error('Invalid abi');
	});
}

export const jsonInterfaceMethodToString = (json) => {
	if (isAbiErrorFragment(json) || isAbiEventFragment(json) || isAbiFunctionFragment(json)) {
		if (json.name?.includes('(')) {
			return json.name;
		}
		return `${json.name ?? ''}(${flattenTypes(false, json.inputs ?? []).join(',')})`;
	}
	return `(${flattenTypes(false, json.inputs ?? []).join(',')})`;
};

export const decodeContractErrorData = (errorsAbi, error) => {
	if (error?.data) {
		let errorName
		let errorSignature
		let errorArgs
		try {
			const errorSha = error.data.slice(0, 10);
			const errorAbi = errorsAbi.find(abi => encodeErrorSignature(abi).substr(0, errorSha.length) === errorSha);

			if (errorAbi?.inputs) {
				errorName = errorAbi.name;
				errorSignature = jsonInterfaceMethodToString(errorAbi);
				// decode abi.inputs according to EIP-838
				errorArgs = decodeParameters([...errorAbi.inputs], error.data.substring(10));
			}
		} catch (err) {
			console.error(err);
		}
		if (errorName) {
			error.setDecodedProperties(errorName, errorSignature, errorArgs);
		}
	}
};

export const decodeLog = ( inputs, data, topics ) => {
	const clonedTopics = Array.isArray(topics) ? topics : [topics];
	const indexedInputs = {};
	const nonIndexedInputs = {};

	for (const [i, input] of inputs.entries()) {
		if (input.indexed) {
			indexedInputs[i] = input;
		} else {
			nonIndexedInputs[i] = input;
		}
	}

	const decodedNonIndexedInputs = data ? decodeParametersWith(Object.values(nonIndexedInputs), data, true) : { __length__: 0 };

	// If topics are more than indexed inputs, that means first topic is the event signature
	const offset = clonedTopics.length - Object.keys(indexedInputs).length;

	const decodedIndexedInputs = Object.values(indexedInputs).map((input, index) =>
		STATIC_TYPES.some(s => input.type.substr(0, s.length) === s) ? _decodeParameter(input.type, clonedTopics[index + offset]) : clonedTopics[index + offset]);

	const returnValues = { __length__: 0 };

	let indexedCounter = 0;
	let nonIndexedCounter = 0;

	for (const [i, res] of inputs.entries()) {
		returnValues[i] = res.type === 'string' ? '' : undefined;

		if (indexedInputs[i]) {
			returnValues[i] = decodedIndexedInputs[indexedCounter];
			indexedCounter += 1;
		}

		if (nonIndexedInputs[i]) {
			returnValues[i] = decodedNonIndexedInputs[String(nonIndexedCounter)];
			nonIndexedCounter += 1;
		}

		if (res.name) {
			returnValues[res.name] = returnValues[i];
		}

		returnValues.__length__ += 1;
	}

	return returnValues;
};

export const decodeParameter = (abi, bytes) => {
  return(decodeParameters([abi], bytes)['0'])
}

export const decodeParameters = (abi, bytes) => {
	const abiParams = toAbiParams(abi);
	const bytesArray = hexToUint8Array(bytes);
	return decodeTuple({ type: 'tuple', name: '', components: abiParams }, bytesArray).result;
}

export const decodeParametersWith = ( abis, bytes, loose) => {
	try {
		if (abis.length > 0 && (!bytes || bytes === '0x' || bytes === '0X')) {
			throw new Error(
				"Returned values aren't valid, did it run Out of Gas? " +
					'You might also see this error if you are not using the ' +
					'correct ABI for the contract you are retrieving data from, ' +
					'requesting data from a block number that does not exist, ' +
					'or querying a node which is not fully synced.',
			);
		}
		return decodeParameters(abis, `0x${bytes.replace(/0x/i, '')}`, loose);
	} catch (err) {
		throw new Error(`Parameter decoding error: ${err.message}`, {internalErr: err});
	}
};

export const encodeErrorSignature = (functionName) => {
	if (typeof functionName !== 'string' && !isAbiErrorFragment(functionName)) {
		throw new Error('Invalid parameter value in encodeErrorSignature');
	}

	let name;

	if (functionName && (typeof functionName === 'function' || typeof functionName === 'object')) {
		name = jsonInterfaceMethodToString(functionName);
	} else {
		name = functionName;
	}

	return sha3Raw(name);
};

export const encodeEventSignature = (functionName) => {
	if (typeof functionName !== 'string' && !isAbiEventFragment(functionName)) {
		throw new Error('Invalid parameter value in encodeEventSignature');
	}

	if (functionName && (typeof functionName === 'function' || typeof functionName === 'object')) {
		functionName = jsonInterfaceMethodToString(functionName);
	}

	return sha3Raw(functionName);
}

export const encodeFunctionCall = ( jsonInterface, params ) => {
	if (!isAbiFunctionFragment(jsonInterface)) {
		throw new Error('Invalid parameter value in encodeFunctionCall');
	}
	return `${encodeFunctionSignature(jsonInterface)}${encodeParameters( jsonInterface.inputs ?? [], params ?? [] ).replace('0x', '')}`;
}

export const encodeFunctionSignature = (functionName) => {
	if (typeof functionName !== 'string' && !isAbiFunctionFragment(functionName)) {
		throw new Error('Invalid parameter value in encodeFunctionSignature');
	}

	let name;

	if (functionName && (typeof functionName === 'function' || typeof functionName === 'object')) {
		name = jsonInterfaceMethodToString(functionName);
	} else {
		name = functionName;
	}

	return sha3Raw(name).slice(0, 10);
};

export const encodeParameter = (abi, param) => {
  return(encodeParameters([abi], [param]))
}

export const encodeParameters = (abi, params) => {
  if (abi?.length !== params.length) {
    throw new Error('Invalid number of values received for given ABI', { expected: abi?.length, received: params.length });
  }
  const abiParams = toAbiParams(abi);
  return uint8ArrayToHexString( encodeTuple({ type: 'tuple', name: '', components: abiParams }, params).encoded );
}

export const flattenTypes = ( includeTuple, puts ) => {
	const types = [];

	puts.forEach(param => {
		if (typeof param.components === 'object') {
			if (!param.type.substr(0, 5) === 'tuple') {
				throw new Error(`Invalid value given "${param.type}". Error: components found but type is not tuple.`);
			}
			const arrayBracket = param.type.indexOf('[');
			const suffix = arrayBracket >= 0 ? param.type.substring(arrayBracket) : '';
			const result = flattenTypes(includeTuple, param.components);

			if (Array.isArray(result) && includeTuple) {
				types.push(`tuple(${result.join(',')})${suffix}`);
			} else if (!includeTuple) {
				types.push(`(${result.join(',')})${suffix}`);
			} else {
				types.push(`(${result.join()})`);
			}
		} else {
			types.push(param.type);
		}
	});

	return types;
};

export const formatOddHexstrings = (param) => isOddHexstring(param) ? `0x0${param.substring(2)}` : param;

export const formatParam = (type, _param) => {
	// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment

	// clone if _param is an object
	const param = typeof _param === 'object' && !Array.isArray(_param) ? { ..._param } : _param;

	// Format BN to string
	if (param instanceof BigInt || typeof param === 'bigint') {
		return param.toString(10);
	}

	if (paramTypeBytesArray.exec(type) || paramTypeNumberArray.exec(type)) {
		const paramClone = [...param];
		return paramClone.map(p => formatParam(type.replace('[]', ''), p));
	}

	// Format correct width for u?int[0-9]*
	let match = paramTypeNumber.exec(type);
	if (match) {
		const size = parseInt(match[2] ? match[2] : '256', 10);
		if (size / 8 < param.length) {
			// pad to correct bit width
			return leftPad(param, size);
		}
	}

	// Format correct length for bytes[0-9]+
	match = paramTypeBytes.exec(type);
	if (match) {
		const hexParam = isUint8Array(param) ? toHex(param) : param;

		// format to correct length
		const size = parseInt(match[1], 10);
		if (size) {
			let maxSize = size * 2;

			if (param.substr(0, 2) === '0x') {
				maxSize += 2;
			}
			// pad to correct length
			const paddedParam = hexParam.length < maxSize ? rightPad(param, size * 2) : hexParam;
			return formatOddHexstrings(paddedParam);
		}

		return formatOddHexstrings(hexParam);
	}
	return param;
};

export const getEncodedEip712Data = (typedData, hash) => {
	const EIP_191_PREFIX = '1901';
	const message = `0x${EIP_191_PREFIX}${getStructHash( typedData, 'EIP712Domain', typedData.domain ).substring(2)}${getStructHash(typedData, typedData.primaryType, typedData.message).substring(2)}`;

	if (hash) {
		return keccak256(message);
	}

	return message;
};

export function inferTypesAndEncodeParameters(params) {
	try {
		const abiParams = inferParamsAbi(params);
		return uint8ArrayToHexString( encodeTuple({ type: 'tuple', name: '', components: abiParams }, params).encoded );
	} catch (e) {
		// throws If the inferred params type caused an error
		throw new Error('Could not infer types from given params', {params});
	}
}

export const isAbiConstructorFragment = (item) =>
	!isNullish(item) &&
	typeof item === 'object' &&
	!isNullish(item.type) &&
	item.type === 'constructor';

export const isAbiErrorFragment = (item)  =>
	!isNullish(item) &&
	typeof item === 'object' &&
	!isNullish(item.type) &&
	item.type === 'error';

export const isAbiEventFragment = (item) =>
	!isNullish(item) &&
	typeof item === 'object' &&
	!isNullish(item.type) &&
	item.type === 'event';

export const isAbiFragment = (item) =>
	!isNullish(item) &&
	typeof item === 'object' &&
	!isNullish(item.type) &&
	['function', 'event', 'constructor', 'error'].includes(item.type);

export const isAbiFunctionFragment = (item) =>
	!isNullish(item) &&
	typeof item === 'object' &&
	!isNullish(item.type) &&
	item.type === 'function';

export const isOddHexstring = (param) =>
	typeof param === 'string' && /^(-)?0x[0-9a-f]*$/i.test(param) && param.length % 2 === 1;

export const isSimplifiedStructFormat = (type) =>
	typeof type === 'object' && typeof type.components === 'undefined' && typeof type.name === 'undefined';

export const mapStructNameAndType = (structName) =>
	structName.includes('[]') ? { type: 'tuple[]', name: structName.slice(0, -2) } : { type: 'tuple', name: structName };

export const mapStructToCoderFormat = (struct) => {
	const components = [];

	for (const key of Object.keys(struct)) {
		const item = struct[key];

		if (typeof item === 'object') {
			components.push({ ...mapStructNameAndType(key), components: mapStructToCoderFormat(item)});
		} else {
			components.push({name: key, type: struct[key]});
		}
	}
	return components;
};

export const mapTypes = (types) => {
	const mappedTypes = [];

	for (const type of types) {
		let modifiedType = type;

		// Clone object
		if (typeof type === 'object') {
			modifiedType = { ...type };
		}

		// Remap `function` type params to bytes24 since Ethers does not
		// recognize former type. Solidity docs say `Function` is a bytes24
		// encoding the contract address followed by the function selector hash.
		if (typeof type === 'object' && type.type === 'function') {
			modifiedType = { ...type, type: 'bytes24' };
		}

		if (isSimplifiedStructFormat(modifiedType)) {
			const structName = Object.keys(modifiedType)[0];

			mappedTypes.push({ ...mapStructNameAndType(structName), components: mapStructToCoderFormat(modifiedType[structName]) });
		} else {
			mappedTypes.push(modifiedType);
		}
	}

	return mappedTypes;
};

export {encodeDynamicParams}
