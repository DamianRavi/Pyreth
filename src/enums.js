export const SHA3_EMPTY_BYTES = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
export const unitTypes = ['address', 'bool', 'string', 'bytes', 'bigint',
'int256', 'int128', 'int64', 'int32', 'int16', 'int8', 'int4', 'int2', 'int',
'uint256', 'uint128', 'uint64', 'uint32', 'uint16', 'uint8', 'uint4', 'uint2', 'uint'];
export const charCodeMap = { zero: 48, nine: 57, A: 65, F: 70, a: 97, f: 102 }

export const ETHER_UNITS = {
	noether: BigInt(0),
	wei: BigInt(1),
	kwei: BigInt(1000),
	Kwei: BigInt(1000),
	babbage: BigInt(1000),
	femtoether: BigInt(1000),
	mwei: BigInt(1000000),
	Mwei: BigInt(1000000),
	lovelace: BigInt(1000000),
	picoether: BigInt(1000000),
	gwei: BigInt(1000000000),
	Gwei: BigInt(1000000000),
	shannon: BigInt(1000000000),
	nanoether: BigInt(1000000000),
	nano: BigInt(1000000000),
	szabo: BigInt(1000000000000),
	microether: BigInt(1000000000000),
	micro: BigInt(1000000000000),
	finney: BigInt(1000000000000000),
	milliether: BigInt(1000000000000000),
	milli: BigInt(1000000000000000),
	ether: BigInt('1000000000000000000'),
	kether: BigInt('1000000000000000000000'),
	grand: BigInt('1000000000000000000000'),
	mether: BigInt('1000000000000000000000000'),
	gether: BigInt('1000000000000000000000000000'),
	tether: BigInt('1000000000000000000000000000000'),
};

export const INIT_OPTIONS = [ 'input', 'data', 'from', 'gas', 'gasPrice', 'gasLimit', 'address', 'jsonInterface', 'syncWithContext', 'dataInputFill']

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

/*
export const parseBaseType = <T = typeof VALID_ETH_BASE_TYPES[number]>(
	type: string,
): {
	baseType?: T;
	baseTypeSize: number | undefined;
	arraySizes: number[];
	isArray: boolean;
} => {
	// Remove all empty spaces to avoid any parsing issue.
	let strippedType = type.replace(/ /, '');
	let baseTypeSize: number | undefined;
	let isArray = false;
	let arraySizes: number[] = [];

	if (type.includes('[')) {
		// Extract the array type
		strippedType = strippedType.slice(0, strippedType.indexOf('['));
		// Extract array indexes
		arraySizes = [...type.matchAll(/(?:\[(\d*)\])/g)]
			.map(match => parseInt(match[1], 10))
			.map(size => (Number.isNaN(size) ? -1 : size));

		isArray = arraySizes.length > 0;
	}

	if (VALID_ETH_BASE_TYPES.includes(strippedType)) {
		return { baseType: strippedType as unknown as T, isArray, baseTypeSize, arraySizes };
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

	return { baseType: strippedType as unknown as T, isArray, baseTypeSize, arraySizes };
};
*/
