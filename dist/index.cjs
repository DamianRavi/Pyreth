'use strict';

var utils = require('@noble/hashes/utils');
var sha3$1 = require('@noble/hashes/sha3');
var buffer = require('buffer');
var secp256k1 = require('@noble/curves/secp256k1');
var scrypt = require('@noble/hashes/scrypt');
require('@noble/hashes/crypto');
var crypto = require('crypto-js');
var assert$1 = require('assert');
var base58 = require('bs58');
var blake2b = require('blake2b');
require('@noble/hashes/blake2b');
require('@noble/hashes/blake2s');
require('@scure/base');
require('@noble/hashes/pbkdf2');
var sha512 = require('@noble/hashes/sha512');

class BaseError extends Error {

  constructor(shortMessage, args = {}) {
    const details =
      args.cause instanceof BaseError
        ? args.cause.details
        : args.cause?.message
        ? args.cause.message
        : args.details;
    const docsPath =
      args.cause instanceof BaseError
        ? args.cause.docsPath || args.docsPath
        : args.docsPath;
    const message = [
      shortMessage || 'An error occurred.',
      '',
      ...(args.metaMessages ? [...args.metaMessages, ''] : []),
      ...(docsPath ? [`Docs: https://abitype.dev${docsPath}`] : []),
      ...(details ? [`Details: ${details}`] : []),
      `Version: abitype@1.0.2`,
    ].join('\n');

    super(message);

    if (args.cause) this.cause = args.cause;
    this.details = details;
    this.docsPath = docsPath;
    this.metaMessages = args.metaMessages;
    this.shortMessage = shortMessage;
  }
}

class UnknownTypeError extends BaseError {
    constructor({ type }) {
        super('Unknown type.', {
            metaMessages: [
                `Type "${type}" is not a valid ABI type. Perhaps you forgot to include a struct signature?`,
            ],
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'UnknownTypeError'
        });
    }
}
class UnknownSolidityTypeError extends BaseError {
    constructor({ type }) {
        super('Unknown type.', {
            metaMessages: [`Type "${type}" is not a valid ABI type.`],
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'UnknownSolidityTypeError'
        });
    }
}
class InvalidParenthesisError extends BaseError {
    constructor({ current, depth }) {
        super('Unbalanced parentheses.', {
            metaMessages: [
                `"${current.trim()}" has too many ${depth > 0 ? 'opening' : 'closing'} parentheses.`,
            ],
            details: `Depth "${depth}"`,
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'InvalidParenthesisError'
        });
    }
}

class CircularReferenceError extends BaseError {
    constructor({ type }) {
        super('Circular reference detected.', {
            metaMessages: [`Struct "${type}" is a circular reference.`],
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'CircularReferenceError'
        });
    }
}

let InvalidSignatureError$1 = class InvalidSignatureError extends BaseError {
    constructor({ signature, type, }) {
        super(`Invalid ${type} signature.`, {
            details: signature,
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'InvalidSignatureError'
        });
    }
};
class InvalidStructSignatureError extends BaseError {
    constructor({ signature }) {
        super('Invalid struct signature.', {
            details: signature,
            metaMessages: ['No properties exist.'],
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'InvalidStructSignatureError'
        });
    }
}
class InvalidAbiParameterError extends BaseError {
    constructor({ param }) {
        super('Failed to parse ABI parameter.', {
            details: `parseAbiParameter(${JSON.stringify(param, null, 2)})`,
            docsPath: '/api/human#parseabiparameter-1',
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'InvalidAbiParameterError'
        });
    }
}
class InvalidParameterError extends BaseError {
    constructor({ param }) {
        super('Invalid ABI parameter.', {
            details: param,
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'InvalidParameterError'
        });
    }
}
class SolidityProtectedKeywordError extends BaseError {
    constructor({ param, name }) {
        super('Invalid ABI parameter.', {
            details: param,
            metaMessages: [
                `"${name}" is a protected Solidity keyword. More info: https://docs.soliditylang.org/en/latest/cheatsheet.html`,
            ],
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'SolidityProtectedKeywordError'
        });
    }
}
class InvalidModifierError extends BaseError {
    constructor({ param, type, modifier, }) {
        super('Invalid ABI parameter.', {
            details: param,
            metaMessages: [
                `Modifier "${modifier}" not allowed${type ? ` in "${type}" type` : ''}.`,
            ],
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'InvalidModifierError'
        });
    }
}
class InvalidFunctionModifierError extends BaseError {
    constructor({ param, type, modifier, }) {
        super('Invalid ABI parameter.', {
            details: param,
            metaMessages: [
                `Modifier "${modifier}" not allowed${type ? ` in "${type}" type` : ''}.`,
                `Data location can only be specified for array, struct, or mapping types, but "${modifier}" was given.`,
            ],
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'InvalidFunctionModifierError'
        });
    }
}
class InvalidAbiTypeParameterError extends BaseError {
    constructor({ abiParameter, }) {
        super('Invalid ABI parameter.', {
            details: JSON.stringify(abiParameter, null, 2),
            metaMessages: ['ABI parameter type is invalid.'],
        });
        Object.defineProperty(this, "name", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 'InvalidAbiTypeParameterError'
        });
    }
}

function getParameterCacheKey(param, type) {
    if (type)
        return `${type}:${param}`;
    return param;
}

const parameterCache = new Map([
    ['address', { type: 'address' }],
    ['bool', { type: 'bool' }],
    ['bytes', { type: 'bytes' }],
    ['bytes32', { type: 'bytes32' }],
    ['int', { type: 'int256' }],
    ['int256', { type: 'int256' }],
    ['string', { type: 'string' }],
    ['uint', { type: 'uint256' }],
    ['uint8', { type: 'uint8' }],
    ['uint16', { type: 'uint16' }],
    ['uint24', { type: 'uint24' }],
    ['uint32', { type: 'uint32' }],
    ['uint64', { type: 'uint64' }],
    ['uint96', { type: 'uint96' }],
    ['uint112', { type: 'uint112' }],
    ['uint160', { type: 'uint160' }],
    ['uint192', { type: 'uint192' }],
    ['uint256', { type: 'uint256' }],
    ['address owner', { type: 'address', name: 'owner' }],
    ['address to', { type: 'address', name: 'to' }],
    ['bool approved', { type: 'bool', name: 'approved' }],
    ['bytes _data', { type: 'bytes', name: '_data' }],
    ['bytes data', { type: 'bytes', name: 'data' }],
    ['bytes signature', { type: 'bytes', name: 'signature' }],
    ['bytes32 hash', { type: 'bytes32', name: 'hash' }],
    ['bytes32 r', { type: 'bytes32', name: 'r' }],
    ['bytes32 root', { type: 'bytes32', name: 'root' }],
    ['bytes32 s', { type: 'bytes32', name: 's' }],
    ['string name', { type: 'string', name: 'name' }],
    ['string symbol', { type: 'string', name: 'symbol' }],
    ['string tokenURI', { type: 'string', name: 'tokenURI' }],
    ['uint tokenId', { type: 'uint256', name: 'tokenId' }],
    ['uint8 v', { type: 'uint8', name: 'v' }],
    ['uint256 balance', { type: 'uint256', name: 'balance' }],
    ['uint256 tokenId', { type: 'uint256', name: 'tokenId' }],
    ['uint256 value', { type: 'uint256', name: 'value' }],
    [
        'event:address indexed from',
        { type: 'address', name: 'from', indexed: true },
    ],
    ['event:address indexed to', { type: 'address', name: 'to', indexed: true }],
    [
        'event:uint indexed tokenId',
        { type: 'uint256', name: 'tokenId', indexed: true },
    ],
    [
        'event:uint256 indexed tokenId',
        { type: 'uint256', name: 'tokenId', indexed: true },
    ],
]);

function execTyped(regex, string) {
    const match = regex.exec(string);
    return match?.groups;
}
const bytesRegex = /^bytes([1-9]|1[0-9]|2[0-9]|3[0-2])?$/;
const integerRegex = /^u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?$/;
const isTupleRegex = /^\(.+?\).*?$/;

function parseAbiParameter(param) {
    let abiParameter;
    if (typeof param === 'string')
        abiParameter = parseAbiParameter_(param, { modifiers });
    else {
        const structs = parseStructs(param);
        const length = param.length;
        for (let i = 0; i < length; i++) {
            const signature = param[i];
            if (isStructSignature(signature))
                continue;
            abiParameter = parseAbiParameter_(signature, { modifiers, structs });
            break;
        }
    }
    if (!abiParameter)
        throw new InvalidAbiParameterError({ param });
    return abiParameter;
}


function parseStructs(signatures) {
    // Create "shallow" version of each struct (and filter out non-structs or invalid structs)
    const shallowStructs = {};
    const signaturesLength = signatures.length;
    for (let i = 0; i < signaturesLength; i++) {
        const signature = signatures[i];
        if (!isStructSignature(signature))
            continue;
        const match = execStructSignature(signature);
        if (!match)
            throw new InvalidSignatureError$1({ signature, type: 'struct' });
        const properties = match.properties.split(';');
        const components = [];
        const propertiesLength = properties.length;
        for (let k = 0; k < propertiesLength; k++) {
            const property = properties[k];
            const trimmed = property.trim();
            if (!trimmed)
                continue;
            const abiParameter = parseAbiParameter(trimmed);
            components.push(abiParameter);
        }
        if (!components.length)
            throw new InvalidStructSignatureError({ signature });
        shallowStructs[match.name] = components;
    }
    // Resolve nested structs inside each parameter
    const resolvedStructs = {};
    const entries = Object.entries(shallowStructs);
    const entriesLength = entries.length;
    for (let i = 0; i < entriesLength; i++) {
        const [name, parameters] = entries[i];
        resolvedStructs[name] = resolveStructs(parameters, shallowStructs);
    }
    return resolvedStructs;
}
const typeWithoutTupleRegex = /^(?<type>[a-zA-Z$_][a-zA-Z0-9$_]*)(?<array>(?:\[\d*?\])+?)?$/;
function resolveStructs(abiParameters, structs, ancestors = new Set()) {
    const components = [];
    const length = abiParameters.length;
    for (let i = 0; i < length; i++) {
        const abiParameter = abiParameters[i];
        const isTuple = isTupleRegex.test(abiParameter.type);
        if (isTuple)
            components.push(abiParameter);
        else {
            const match = execTyped(typeWithoutTupleRegex, abiParameter.type);
            if (!match?.type)
                throw new InvalidAbiTypeParameterError({ abiParameter });
            const { array, type } = match;
            if (type in structs) {
                if (ancestors.has(type))
                    throw new CircularReferenceError({ type });
                components.push({
                    ...abiParameter,
                    type: `tuple${array ?? ''}`,
                    components: resolveStructs(structs[type] ?? [], structs, new Set([...ancestors, type])),
                });
            }
            else {
                if (isSolidityType(type))
                    components.push(abiParameter);
                else
                    throw new UnknownTypeError({ type });
            }
        }
    }
    return components;
}




const abiParameterWithoutTupleRegex = /^(?<type>[a-zA-Z$_][a-zA-Z0-9$_]*)(?<array>(?:\[\d*?\])+?)?(?:\s(?<modifier>calldata|indexed|memory|storage{1}))?(?:\s(?<name>[a-zA-Z$_][a-zA-Z0-9$_]*))?$/;
const abiParameterWithTupleRegex = /^\((?<type>.+?)\)(?<array>(?:\[\d*?\])+?)?(?:\s(?<modifier>calldata|indexed|memory|storage{1}))?(?:\s(?<name>[a-zA-Z$_][a-zA-Z0-9$_]*))?$/;
const dynamicIntegerRegex = /^u?int$/;
function parseAbiParameter_(param, options) {
    // optional namespace cache by `type`
    const parameterCacheKey = getParameterCacheKey(param, options?.type);
    if (parameterCache.has(parameterCacheKey))
        return parameterCache.get(parameterCacheKey);
    const isTuple = isTupleRegex.test(param);
    const match = execTyped(isTuple ? abiParameterWithTupleRegex : abiParameterWithoutTupleRegex, param);
    if (!match)
        throw new InvalidParameterError({ param });
    if (match.name && isSolidityKeyword(match.name))
        throw new SolidityProtectedKeywordError({ param, name: match.name });
    const name = match.name ? { name: match.name } : {};
    const indexed = match.modifier === 'indexed' ? { indexed: true } : {};
    const structs = options?.structs ?? {};
    let type;
    let components = {};
    if (isTuple) {
        type = 'tuple';
        const params = splitParameters(match.type);
        const components_ = [];
        const length = params.length;
        for (let i = 0; i < length; i++) {
            // remove `modifiers` from `options` to prevent from being added to tuple components
            components_.push(parseAbiParameter(params[i]));
        }
        components = { components: components_ };
    }
    else if (match.type in structs) {
        type = 'tuple';
        components = { components: structs[match.type] };
    }
    else if (dynamicIntegerRegex.test(match.type)) {
        type = `${match.type}256`;
    }
    else {
        type = match.type;
        if (!(options?.type === 'struct') && !isSolidityType(type))
            throw new UnknownSolidityTypeError({ type });
    }
    if (match.modifier) {
        // Check if modifier exists, but is not allowed (e.g. `indexed` in `functionModifiers`)
        if (!options?.modifiers?.has?.(match.modifier))
            throw new InvalidModifierError({
                param,
                type: options?.type,
                modifier: match.modifier,
            });
        // Check if resolved `type` is valid if there is a function modifier
        if (functionModifiers.has(match.modifier) &&
            !isValidDataLocation(type, !!match.array))
            throw new InvalidFunctionModifierError({
                param,
                type: options?.type,
                modifier: match.modifier,
            });
    }
    const abiParameter = {
        type: `${type}${match.array ?? ''}`,
        ...name,
        ...indexed,
        ...components,
    };
    parameterCache.set(parameterCacheKey, abiParameter);
    return abiParameter;
}

function splitParameters(params, result = [], current = '', depth = 0) {
    const length = params.trim().length;
    for (let i = 0; i < length; i++) {
        const char = params[i];
        const tail = params.slice(i + 1);
        switch (char) {
            case ',':
                return depth === 0
                    ? splitParameters(tail, [...result, current.trim()])
                    : splitParameters(tail, result, `${current}${char}`, depth);
            case '(':
                return splitParameters(tail, result, `${current}${char}`, depth + 1);
            case ')':
                return splitParameters(tail, result, `${current}${char}`, depth - 1);
            default:
                return splitParameters(tail, result, `${current}${char}`, depth);
        }
    }
    if (current === '')
        return result;
    if (depth !== 0)
        throw new InvalidParenthesisError({ current, depth });
    result.push(current.trim());
    return result;
}

function isSolidityType(type) {
    return (type === 'address' ||
        type === 'bool' ||
        type === 'function' ||
        type === 'string' ||
        bytesRegex.test(type) ||
        integerRegex.test(type));
}
const protectedKeywordsRegex = /^(?:after|alias|anonymous|apply|auto|byte|calldata|case|catch|constant|copyof|default|defined|error|event|external|false|final|function|immutable|implements|in|indexed|inline|internal|let|mapping|match|memory|mutable|null|of|override|partial|private|promise|public|pure|reference|relocatable|return|returns|sizeof|static|storage|struct|super|supports|switch|this|true|try|typedef|typeof|var|view|virtual)$/;

function isSolidityKeyword(name) {
    return (name === 'address' ||
        name === 'bool' ||
        name === 'function' ||
        name === 'string' ||
        name === 'tuple' ||
        bytesRegex.test(name) ||
        integerRegex.test(name) ||
        protectedKeywordsRegex.test(name));
}

function isValidDataLocation(type, isArray) {
    return isArray || type === 'bytes' || type === 'string' || type === 'tuple';
}
// https://regexr.com/7gmp3
const structSignatureRegex = /^struct (?<name>[a-zA-Z$_][a-zA-Z0-9$_]*) \{(?<properties>.*?)\}$/;
function isStructSignature(signature) {
    return structSignatureRegex.test(signature);
}
function execStructSignature(signature) {
    return execTyped(structSignatureRegex, signature);
}
const modifiers = new Set([ 'memory', 'indexed', 'storage', 'calldata']);
const functionModifiers = new Set([ 'calldata', 'memory', 'storage']);

// Utils error codes
const ERR_INVALID_STRING = 1001;
const ERR_INVALID_BYTES = 1002;
const ERR_INVALID_ADDRESS = 1005;
const ERR_INVALID_HEX = 1006;
const ERR_INVALID_TYPE = 1007;
const ERR_INVALID_BOOLEAN = 1008;
const ERR_INVALID_UNSIGNED_INTEGER = 1009;
const ERR_INVALID_SIZE = 1010;
const ERR_INVALID_LARGE_VALUE = 1011;
const ERR_INVALID_NIBBLE_WIDTH = 1014;


const ValidationError = (msg) => {
  throw new Error(msg);
};

const InvalidAddressError = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_STRING,
    message: `Invalid value given "${value}". Error: invalid ethereum address.`,
    cause: "this.cause"
  };
  return errObj
};

const InvalidStringError = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_ADDRESS,
    message: `Invalid value given "${value}". Error: invalid string.`,
    cause: "this.cause"
  };
  return errObj
};

const InvalidNumberError = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_ADDRESS,
    message: `Invalid value given "${value}". Error: invalid number.`,
    cause: "this.cause"
  };
  return errObj
};

const InvalidBooleanError = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_BOOLEAN,
    message: `Invalid value given "${value}". Error: invalid boolean.`,
    cause: "this.cause"
  };
  return errObj
};

const InvalidBytesError = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_BYTES,
    message: `Invalid value given "${value}". Error: invalid bytes.`,
    cause: "this.cause"
  };
  return errObj
};

const InvalidSizeError = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_SIZE,
    message: `Invalid value given "${value}". Error: invalid size.`,
    cause: "this.cause"
  };
  return errObj
};

const InvalidLargeValueError = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_LARGE_VALUE,
    message: `Invalid value given "${value}". Error: invalid large value.`,
    cause: "this.cause"
  };
  return errObj
};

const InvalidUnsignedIntegerError = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_UNSIGNED_INTEGER,
    message: `Invalid value given "${value}". Error: invalid unsigned integer.`,
    cause: "this.cause"
  };
  return errObj
};

const NibbleWidthError = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_NIBBLE_WIDTH,
    message: `Invalid value given "${value}". Error: value greater than the nibble width.`,
    cause: "this.cause"
  };
  return errObj
};

const HexProcessingError = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_HEX,
    message: `Invalid value given "${value}". Error: hex processing error.`,
    cause: "this.cause"
  };
  return errObj
};

const TypeError$1 = (value) => {
  var errObj = {
    name: "this.name",
    code: ERR_INVALID_TYPE,
    message: `Invalid value given "${value}". Error: invalid type.`,
    cause: "this.cause"
  };
  return errObj
};

const SHA3_EMPTY_BYTES = '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470';
const charCodeMap = { zero: 48, nine: 57, A: 65, F: 70, a: 97, f: 102 };

const ETHER_UNITS = {
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

const INIT_OPTIONS = [ 'input', 'data', 'from', 'gas', 'gasPrice', 'gasLimit', 'address', 'jsonInterface', 'syncWithContext', 'dataInputFill'];

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

const numberToHex$2 = (value) => {
  return("0x" + Number(value).toString(16))
};

const padLeft = (value, characterAmount, sign = "0") => {
  if (typeof value === 'string' && !isHexStrict(value)) {
    return value.padStart(characterAmount, sign);
  }
  const hex = typeof value === 'string' && isHexStrict(value) ? value : numberToHex$2(value);
  const [prefix, hexValue] = hex.startsWith('-') ? ['-0x', hex.slice(3)] : ['0x', hex.slice(2)];
  return `${prefix}${hexValue.padStart(characterAmount, sign)}`;
};

const leftPad = (value, characterAmount, sign) => padLeft(value, characterAmount, sign);

const padRight = (value, characterAmount, sign = "0") => {
  if (typeof value === 'string' && !isHexStrict(value)) {
		return value.padEnd(characterAmount, sign);
	}
	//validator.validate(['int'], [value]);
	const hexString = typeof value === 'string' && isHexStrict(value) ? value : numberToHex$2(value);
	const prefixLength = hexString.startsWith('-') ? 3 : 2;
	return hexString.padEnd(characterAmount + prefixLength, sign);
};

const rightPad = (value, characterAmount, sign) => padRight(value, characterAmount, sign);

const isAddress = (address) => (/^(0x){1}[0-9a-fA-F]{40}$/i.test(address));

const isNullish = (item) => item === undefined || item === null;

const isContractInitOptions = (options) => typeof options === 'object' && !isNullish(options) && Object.keys(options).length !== 0 && INIT_OPTIONS.some(key => key in options);

const isPromise = (object) => (typeof object === 'object' || typeof object === 'function') && typeof object.then === 'function';

const isDataFormat = (dataFormat) => typeof dataFormat === 'object' && !isNullish(dataFormat) && 'number' in dataFormat && 'bytes' in dataFormat;

const isHex = (hex) => typeof hex === 'number' || typeof hex === 'bigint' ||	(typeof hex === 'string' && /^((-0x|0x|-)?[0-9a-f]+|(0x))$/i.test(hex));

const isHexStrict = (hex) => typeof hex === 'string' && /^((-)?0x[0-9a-f]+|(0x))$/i.test(hex);

const isUint8Array = (data) => data?.constructor?.name === 'Uint8Array';

const ensureIfUint8Array = (data) => !isUint8Array(data) ? Uint8Array.from(null) : data;

const isUInt$1 = ( value, options ) => {
	if ( !['number', 'string', 'bigint'].includes(typeof value) || (typeof value === 'string' && value.length === 0) ) {
		return false;
	}

	if (options.bitSize) ;

	const maxSize = BigInt((256 ) - 1) ** BigInt(2);

	try {
		const valueToCheck = typeof value === 'string' && isHexStrict(value) ? BigInt(hexToNumber(value)) : BigInt(value);
		return valueToCheck >= 0 && valueToCheck <= maxSize;
	} catch (error) {
		return false;
	}
};

function isHexString(value, length) {
	if (typeof value !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) return false;

	return true;
}

function isHexPrefixed$1(str) {
	if (typeof str !== 'string') {
		throw new Error(`[isHexPrefixed] input must be type 'string', received type ${typeof str}`);
	}

	return str.startsWith('0x');
}

function uint8ArrayEquals(a, b) {
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

const isInt$1 = ( value, options ) => {
	if (!['number', 'string', 'bigint'].includes(typeof value)) {
		return false;
	}

	if (typeof value === 'number' && value > Number.MAX_SAFE_INTEGER) {
		return false;
	}

	if (options.bitSize) ;


	const maxSize = BigInt((256 ) - 1) ** BigInt(2);
	const minSize = BigInt((256 ) - 1) ** BigInt(-1);

	try {
		const valueToCheck = typeof value === 'string' && isHexStrict(value) ? BigInt(hexToNumber(value)) : BigInt(value);
		return valueToCheck >= minSize && valueToCheck <= maxSize;
	} catch (error) {
		return false;
	}
};

const isBytes$1 = (value, options) => {
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

	if (typeof value === 'string') {
		if (value.length % 2 !== 0) {
			// odd length hex
			return false;
		}
		hexToUint8Array(value);
	} else if (Array.isArray(value)) {
		if (value.some(d => d < 0 || d > 255 || !Number.isInteger(d))) {
			return false;
		}
	} else ;

	return true;
};

const WORD_SIZE$1 = 32;
const mask = BigInt(1) << BigInt(256);

function charCodeToBase16(char) {
  if (char >= charCodeMap.zero && char <= charCodeMap.nine)
    return char - charCodeMap.zero
  if (char >= charCodeMap.A && char <= charCodeMap.F)
    return char - (charCodeMap.A - 10)
  if (char >= charCodeMap.a && char <= charCodeMap.f)
    return char - (charCodeMap.a - 10)
  return undefined
}

const numberToHex$1 = (value) => {
	if ((typeof value === 'number' || typeof value === 'bigint') && value < 0) {
		return `-0x${value.toString(16).slice(1)}`;
	}

	if ((typeof value === 'number' || typeof value === 'bigint') && value >= 0) {
		return `0x${value.toString(16)}`;
	}

	if (typeof value === 'string' && isHexStrict(value)) {
		const [negative, hex] = value.substr(0, 1) === '-' ? [true, value.slice(1)] : [false, value];
		const hexValue = hex.split(/^(-)?0(x|X)/).slice(-1)[0];
		return `${negative ? '-' : ''}0x${hexValue.replace(/^0+/, '').toLowerCase()}`;
	}

	if (typeof value === 'string' && !isHexStrict(value)) {
		return numberToHex$1(BigInt(value));
	}

	throw new InvalidNumberError(value);
};

const asciiToHex = (str) => {
  if (typeof data !== 'string') {
		throw new Error("Invalid ascii string.");
	}
	let hexString = '';
	for (let i = 0; i < str.length; i += 1) {
		const hexCharCode = str.charCodeAt(i).toString(16);
		hexString += hexCharCode.length % 2 !== 0 ? `0${hexCharCode}` : hexCharCode;
	}
	return `0x${hexString}`;
};

const bytesToHex$1 = (bytes) => uint8ArrayToHexString(bytesToUint8Array(bytes));

const bytesToUint8Array = (data) => {
	if (isUint8Array(data)) {
		return data;
	}
	if (Array.isArray(data)) {
		return new Uint8Array(data);
	}
	if (typeof data === 'string') {
		return hexToUint8Array(data);
	}
	throw new Error("Invalid bytes " + data);
};

const bytesToUtf8 = (data) => {
  if (!(data instanceof Uint8Array)) {
    throw new TypeError$1(`bytesToUtf8 expected Uint8Array, got ${typeof data}`);
  }
  return new TextDecoder().decode(data);
};

const convert = () => "1";

const convertScalarValue = () => "1";

const fromAscii = asciiToHex;

const fromTwosComplement = (value, nibbleWidth = 64) => {
	const val = toNumber(value);
	if (val < 0) return val;
	const largestBit = Math.ceil(Math.log(Number(val)) / Math.log(2));
	if (largestBit > nibbleWidth * 4)
		throw new NibbleWidthError(`value: "${value}", nibbleWidth: "${nibbleWidth}"`);

	if (nibbleWidth * 4 !== largestBit) return val;
	const complement = BigInt(2) ** BigInt(nibbleWidth * 4);
	return toNumber(BigInt(val) - complement);
};

const utf8ToHex = (str) => {
  typeof str === "string" || ValidationError(`Invalid String ${typeof str} ${JSON.stringify(str)}`); //toHex(str, true)
	let strWithoutNullCharacter = str.replace(/^(?:\u0000)/, '');
	strWithoutNullCharacter = strWithoutNullCharacter.replace(/(?:\u0000)$/, '');
	return bytesToHex$1(new TextEncoder().encode(strWithoutNullCharacter));
};

const getStorageSlotNumForLongString = (mainSlotNumber) => sha3( `0x${(typeof mainSlotNumber === 'number' ? mainSlotNumber.toString() : mainSlotNumber ).padStart(64, '0')}`,);

const hexToBytes$1 = (bytes) => (typeof bytes === 'string' && bytes.slice(0, 2).toLowerCase() !== '0x') ? bytesToUint8Array(`0x${bytes}`) : bytesToUint8Array(bytes);

const hexToUtf8 = (hex) => bytesToUtf8(hexToBytes$1(hex));
//decodeURIComponent(hex.replace(/\s+/g, '').replace(/[0-9a-f]{2}/g, '%$&'));

const hexToString = hexToUtf8;

const hexToUint8Array = (hex) => {
	let offset = 0;
	if (hex.substr(0, 1) === '0' && (hex[1] === 'x' || hex[1] === 'X')) {
		offset = 2;
	}
	if (hex.length % 2 !== 0) {
    //hex = hex.slice(0, 2) + "0" + hex.slice(2)
		throw new Error(`hex string has odd length: ${hex}`); //deprecated
	}
	const length = (hex.length - offset) / 2;
	const bytes = new Uint8Array(length);
	for (let index = 0, j = offset; index < length; index+=1) {
	  const nibbleLeft = charCodeToBase16(hex.charCodeAt(j++));
	  const nibbleRight = charCodeToBase16(hex.charCodeAt(j++));
	  if (nibbleLeft === undefined || nibbleRight === undefined) {
		   throw new Error(`Invalid byte sequence ("${hex[j - 2]}${ hex[j - 1] }" in "${hex}").` )
	  }
	  bytes[index] = nibbleLeft * 16 + nibbleRight;
	}
	return bytes
};

const hexToAscii = (value) => {
  var hex = '';
  for (var i = 0, l = value.length; i < l; i++) {
    var hexx = Number(value.charCodeAt(i)).toString(16);
    hex += (hexx.length > 1 && hexx || '0' + hexx);
  }
  return hex;
};

const toAscii = hexToAscii;

const toBigInt = (value) => {
	if (typeof value === 'number') {
		return BigInt(value);
	}
	if (typeof value === 'bigint') {
		return value;
	}
	if (typeof value === 'string' && isHex(value)) {
		return value.substr(0, 1 ) === '-' ? -BigInt(value.substring(1)) : BigInt(value);
	}

	throw new InvalidNumberError(value);
};

const toBool$1 = (value) => {
	if (typeof value === 'boolean') {
		return value;
	}

	if (typeof value === 'number' && (value === 0 || value === 1)) {
		return Boolean(value);
	}

	if (typeof value === 'bigint' && (value === BigInt(0) || value === BigInt(1))) {
		return Boolean(value);
	}

	if ( typeof value === 'string' && !isHexStrict(value) && (value === '1' || value === '0' || value === 'false' || value === 'true') ) {
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
	throw new InvalidBooleanError(value);
};

const hexToNumber = (value) => {
  return(parseInt(value, 16))
};

const toDecimal = hexToNumber;

const toUtf8 = (input) => {
	if (typeof input === 'string') {
		return hexToUtf8(input);
	}
	return bytesToUtf8(input);
};

const hexToNumberString = (value) => {
  return(parseInt(value, 16).toString())
};

const toNumber = (value) => {
	if (typeof value === 'number') {
		return value;
	}
	if (typeof value === 'bigint') {
		return value >= Number.MIN_SAFE_INTEGER && value <= Number.MAX_SAFE_INTEGER ? Number(value) : value;
	}
	if (typeof value === 'string' && isHexStrict(value)) {
		return hexToNumber(value);
	}

	try {
		return toNumber(BigInt(value));
	} catch {
		throw new InvalidNumberError(value);
	}
};

const toWei = (parsedNumber, unit = "ether") => {
  if(!ETHER_UNITS[unit]){
    throw new Error("Invalid Unit")
  }
  parsedNumber = parsedNumber.toString();
  var denomination = BigInt(ETHER_UNITS[unit]);
  const [integer, fraction] = parsedNumber.split('.').concat('');

  const value = BigInt(`${integer}${fraction}`);
  const updatedValue = value * denomination;
  const decimals = fraction.length;
  if (decimals === 0) {
    return updatedValue.toString();
  }
  return updatedValue.toString().slice(0, -decimals);
};

const fromWei = (number, unit = "ether") => {
  if(!ETHER_UNITS[unit]){
    throw new Error("Invalid Unit")
  }
  var denomination = BigInt(ETHER_UNITS[unit]);

  const value = String(toNumber(number));
  const numberOfZerosInDenomination = denomination.toString().length - 1;

  if (numberOfZerosInDenomination <= 0) {
    return value.toString();
  }

  const zeroPaddedValue = value.padStart(numberOfZerosInDenomination, '0');
  const integer = zeroPaddedValue.slice(0, -numberOfZerosInDenomination);
  const fraction = zeroPaddedValue.slice(-numberOfZerosInDenomination).replace(/\.?0+$/, '');

  if (integer === '') {
    return `0.${fraction}`;
  }

  if (fraction === '') {
    return integer;
  }
  const updatedValue = `${integer}.${fraction}`;
  return updatedValue.slice(0, integer.length + numberOfZerosInDenomination + 1);
};

const toChecksumAddress = (address) => {
  if (!isAddress(address)) {
		throw new Error("Invalid address: " + address);
	}

	const lowerCaseAddress = address.toLowerCase().replace(/^0x/i, '');
	const hash = uint8ArrayToHexString( sha3$1.keccak_256( ensureIfUint8Array(utils.utf8ToBytes(lowerCaseAddress))) );

	if ( !hash || hash === SHA3_EMPTY_BYTES )
		return ''; // // EIP-1052 if hash is equal to c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470, keccak was given empty data

	let checksumAddress = '0x';
	const addressHash = hash.replace(/^0x/i, '');

	for (let i = 0; i < lowerCaseAddress.length; i += 1) {
		if (parseInt(addressHash[i], 16) > 7) {
			checksumAddress += lowerCaseAddress[i].toUpperCase();
		} else {
			checksumAddress += lowerCaseAddress[i];
		}
	}
	return checksumAddress;
};

const toTwosComplement = (value, nibbleWidth = 64) => {
  //const val = Number(value);
	const val = toNumber(value);
	if (val >= 0) return padLeft(toHex$1(val), nibbleWidth);

	const largestBit = BigInt.pow(2, nibbleWidth * 4);
	if (-val >= largestBit) {
		throw new NibbleWidthError(`value: ${value}, nibbleWidth: ${nibbleWidth}`);
	}
	const updatedVal = BigInt(val);
	const complement = updatedVal + largestBit;

	return padLeft(numberToHex$1(complement), nibbleWidth);
};

const uint8ArrayToHexString = (uint8Array) => {
	let hexString = '0x';
	for (const e of uint8Array) {
		const hex = e.toString(16);
		hexString += hex.length === 1 ? `0${hex}` : hex;
	}
	return hexString;
};

const stripHexPrefix$1 = (str) => {
	if (typeof str !== 'string')
		throw new Error(`[stripHexPrefix] input must be type 'string', received ${typeof str}`);

	return isHexPrefixed$1(str) ? str.slice(2) : str;
};

function padToEven$1(value) {
	let a = value;
	if (typeof a !== 'string') {
		throw new Error(`[padToEven] value must be type 'string', received ${typeof a}`);
	}
	if (a.length % 2) a = `0${a}`;
	return a;
}

const bigIntToHex = (num) => `0x${num.toString(16)}`;

const toUint8Array = function (v) {
	if (v === null || v === undefined) {
		return new Uint8Array();
	}

	if (v instanceof Uint8Array) {
		return v;
	}

	if (v?.constructor?.name === 'Uint8Array') {
		return Uint8Array.from(v);
	}

	if (Array.isArray(v)) {
		return Uint8Array.from(v);
	}

	if (typeof v === 'string') {
		if (!isHexString(v)) {
			throw new Error(
				`Cannot convert string to Uint8Array. only supports 0x-prefixed hex strings and this string was given: ${v}`,
			);
		}
		return hexToBytes$1(padToEven$1(stripHexPrefix$1(v)));
	}

	if (typeof v === 'number') {
		return toUint8Array(numberToHex$1(v));
	}

	if (typeof v === 'bigint') {
		if (v < 0) {
			throw new Error(`Cannot convert negative bigint to Uint8Array. Given: ${v}`);
		}
		let n = v.toString(16);
		if (n.length % 2) n = `0${n}`;
		return toUint8Array(`0x${n}`);
	}

	if (v.toArray) {
		return Uint8Array.from(v.toArray());
	}

	throw new Error('invalid type');
};

function uint8ArrayToBigInt(buf) {
	const hex = bytesToHex$1(buf);
	if (hex === '0x') {
		return BigInt(0);
	}
	return BigInt(hex);
}

function bigIntToUint8Array$1(value, byteLength = WORD_SIZE$1) {
  let hexValue = (value < 0 ? (mask + value).toString(16) : value.toString(16));
  hexValue = padLeft(hexValue, byteLength * 2);
	return hexToUint8Array(hexValue);
}

function uint8ArrayConcat(...parts) {
	const length = parts.reduce((prev, part) => {
		const agg = prev + part.length;
		return agg;
	}, 0);
	const result = new Uint8Array(length);
	let offset = 0;
	for (const part of parts) {
		result.set(part, offset);
		offset += part.length;
	}
	return result;
}

const toHex$1 = (value, returnType) => {
  if(returnType){
    if(typeof value == 'number'){
      return (value < 0 ? 'int256' : 'uint256')
    }
    return typeof value;
  }

  if (typeof value === 'string' && isAddress(value)) {
		return returnType ? 'address' : `0x${value.toLowerCase().replace(/^0x/i, '')}`;
	}
  if (typeof value === 'boolean') {
		return value ? '0x01' : '0x00';
	}
  if (typeof value === 'bigint' || typeof value === 'number') {
		return numberToHex$1(value);
	}
  if(Array.isArray(value)){
    uint8ArrayToHexString(bytesToUint8Array(value));
  }
  if(value instanceof Uint8Array){
    uint8ArrayToHexString(value);
  }
  if (typeof value === 'object' && !!value) {
    return utf8ToHex(JSON.stringify(value));
  }

  if (typeof value === 'string') {
    if (value.substr(0, 3) === '-0x' || value.substr(0, 3) === '-0X') {
      return returnType ? 'int256' : numberToHex$1(value);
    }
    if (isHexStrict(value)) {
      return returnType ? 'bytes' : value;
    }
    if (isHex(value) && !isInt$1(value) && !isUInt$1(value)) {
      return returnType ? 'bytes' : `0x${value}`;
    }
    if (isHex(value) && !isInt$1(value) && isUInt$1(value)) {
      return returnType ? 'uint' : numberToHex$1(value);
    }
    if (!Number.isFinite(value)) {
      return returnType ? 'string' : utf8ToHex(value);
    }
  }

  throw new HexProcessingError(value);
};

const isUInt = ( value, options ) => {
	if ( !['number', 'string', 'bigint'].includes(typeof value) || (typeof value === 'string' && value.length === 0) ) {
		return false;
	}
	if (options.bitSize) ;
	const maxSize = BigInt((256 ) - 1) ** BigInt(2);

	try {
		const valueToCheck = typeof value === 'string' && isHexStrict(value) ? BigInt(hexToNumber(value)) : BigInt(value);
		return valueToCheck >= 0 && valueToCheck <= maxSize;
	}
  catch (error) {
		return false;
	}
};

const isInt = (value, options) => {
	if (!['number', 'string', 'bigint'].includes(typeof value)) {
		return false;
	}

	if (typeof value === 'number' && value > Number.MAX_SAFE_INTEGER) {
		return false;
	}

	if (options.bitSize) ;

	const maxSize = BigInt((256 ) - 1) ** BigInt(2);
	const minSize = BigInt((256 ) - 1) ** BigInt(-1);

	try {
		const valueToCheck = typeof value === 'string' && isHexStrict(value) ? BigInt(hexToNumber(value)) : BigInt(value);
		return valueToCheck >= minSize && valueToCheck <= maxSize;
	}
  catch (error) {
		return false;
	}
};

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

const toHex = ( value, returnType ) => {
	if (typeof value === 'string' && isAddress(value)) {
		return returnType ? 'address' : `0x${value.toLowerCase().replace(/^0x/i, '')}`;
	}

	if (typeof value === 'boolean') {
		// eslint-disable-next-line no-nested-ternary
		return returnType ? 'bool' : value ? '0x01' : '0x00';
	}

	if (typeof value === 'number') {
		// eslint-disable-next-line no-nested-ternary
		return returnType ? (value < 0 ? 'int256' : 'uint256') : numberToHex$1(value);
	}

	if (typeof value === 'bigint') {
		return returnType ? 'bigint' : numberToHex$1(value);
	}

	if (typeof value === 'object' && !!value) {
		return returnType ? 'string' : utf8ToHex(JSON.stringify(value));
	}

	if (typeof value === 'string') {
		if (value.startsWith('-0x') || value.startsWith('-0X')) {
			return returnType ? 'int256' : numberToHex$1(value);
		}

		if (isHexStrict(value)) {
			return returnType ? 'bytes' : value;
		}
		if (isHex(value) && !isInt(value) && !isUInt(value)) {
			return returnType ? 'bytes' : `0x${value}`;
		}
		if (isHex(value) && !isInt(value) && isUInt(value)) {
			return returnType ? 'uint' : numberToHex$1(value);
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

const processSolidityEncodePackedArgs = (arg) => {
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
const encodePacked = (...values) => {
	const hexArgs = values.map(processSolidityEncodePackedArgs);
	return `0x${hexArgs.join('').toLowerCase()}`;
};

const sha3Raw = (data) => {
	if (typeof data === 'string') {
		if (data.startsWith('0x') && isHexStrict(data)) {
			data = hexToBytes$1(data);
		} else {
			data = utils.utf8ToBytes(data);
		}
	}
  !isUint8Array(data) ?? new InvalidAddressError(data);
	return bytesToHex$1(sha3$1.keccak_256(data));
};

const sha3 = (data) => {
  const hash = sha3Raw(data);
	return hash === SHA3_EMPTY_BYTES ? undefined : hash;
};

const soliditySha3Raw = (data) => {
  sha3Raw(encodePacked(data));
};

const soliditySha3 = (data) => {
  sha3(encodePacked(data));
};

const MAX_STATIC_BYTES_COUNT = 32;
const ADDRESS_BYTES_COUNT = 20;
const WORD_SIZE = 32;
const ADDRESS_OFFSET = WORD_SIZE - ADDRESS_BYTES_COUNT;

const numberLimits = new Map();

let base = 256; // 2 ^ 8 = 256
for (let i = 8; i <= 256; i += 8) {
	numberLimits.set(`uint${i}`, { min: 0, max: base - 1 });
	numberLimits.set(`int${i}`, { min: -base / 2, max: base / 2 - 1 });
	base *= 256;
}

numberLimits.set(`int`, numberLimits.get('int256'));
numberLimits.set(`uint`, numberLimits.get('uint256'));


const toBool = (value) => {
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

function encodeParamFromAbiParameter(param, value) {
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

function decodeParamFromAbiParameter(param, bytes) {
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



function extractArrayType$1(param) {
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

function isDynamic$1(param) {
	if (param.type === 'string' || param.type === 'bytes' || param.type.endsWith('[]')) return true;
	if (param.type === 'tuple') {
		return param.components?.some(isDynamic$1) ?? false;
	}
	if (param.type.endsWith(']')) {
		return isDynamic$1(extractArrayType$1(param).param);
	}
	return false;
}





function alloc(size = 0) {
	if (buffer.Buffer?.alloc !== undefined) {
		const buf = buffer.Buffer.alloc(size);
		return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
	}

	return new Uint8Array(size);
}



function encodeBoolean(param, input) {
	let value;
	try {
		value = toBool(input);
	} catch (e) {
		throw new Error('provided input is not valid boolean value', { type: param.type, value: input, name: param.name});
	}

	return encodeNumber({ type: 'uint8', name: '' }, Number(value));
}

function decodeBool(_param, bytes) {
	const numberResult = decodeNumber({ type: 'uint8', name: '' }, bytes);
	if (numberResult.result > 1 || numberResult.result < 0) {
		throw new Error('Invalid boolean value encoded', { boolBytes: bytes.subarray(0, WORD_SIZE), numberResult });
	}
	return { result: numberResult.result === BigInt(1), encoded: numberResult.encoded, consumed: WORD_SIZE };
}





function encodeString(_param, input) {
	if (typeof input !== 'string') {
		throw new Error('invalid input, should be string', { input });
	}
	const bytes = utils.utf8ToBytes(input);
	return encodeBytes({ type: 'bytes', name: '' }, bytes);
}

function decodeString(_param, bytes) {
	const r = decodeBytes({ type: 'bytes', name: '' }, bytes);
	return { result: hexToUtf8(r.result), encoded: r.encoded, consumed: r.consumed };
}

function encodeBytes(param, input) {
	// hack for odd length hex strings
	if (typeof input === 'string' && input.length % 2 !== 0) {
		// eslint-disable-next-line no-param-reassign
		input += '0';
	}
	if (!isBytes$1(input)) {
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

function decodeBytes(param, bytes) {
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

	return { result: bytesToHex$1(remainingBytes.subarray(0, size)), encoded: remainingBytes.subarray(partsCount * WORD_SIZE), consumed: consumed + partsCount * WORD_SIZE };
}

function encodeNumber(param, input) {
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
	return { dynamic: false, encoded: bigIntToUint8Array$1(value) };
}

function decodeNumber(param, bytes) {
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


function encodeAddress(param, input) {
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

function decodeAddress(_param, bytes) {
	const addressBytes = bytes.subarray(ADDRESS_OFFSET, WORD_SIZE);
	if (addressBytes.length !== ADDRESS_BYTES_COUNT) {
		throw new Error('Invalid decoding input, not enough bytes to decode address', { bytes });
	}
	const result = uint8ArrayToHexString(addressBytes);

	return { result: toChecksumAddress(result), encoded: bytes.subarray(WORD_SIZE), consumed: WORD_SIZE };
}

function encodeArray(param, values) {
	if (!Array.isArray(values)) {
		throw new Error('Expected value to be array', { abi: param, values });
	}
	const { size, param: arrayItemParam } = extractArrayType$1(param);
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

function decodeArray(param, bytes){
	// eslint-disable-next-line prefer-const
	let { size, param: arrayItemParam } = extractArrayType$1(param);
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
	const hasDynamicChild = isDynamic$1(arrayItemParam);
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

function encodeTuple(param, input) {
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

function decodeTuple(param, bytes) {
	const result = { __length__: 0 };
	let consumed = 0;

	if (!param.components) {
		return { result, encoded: bytes, consumed };
	}

	let dynamicConsumed = 0;
	for (const [index, childParam] of param.components.entries()) {
		let decodedResult;
		if (isDynamic$1(childParam)) {
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

function encodeDynamicParams(encodedParams) {
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

const STATIC_TYPES = ['bool', 'string', 'int', 'uint', 'address', 'fixed', 'ufixed'];

const _decodeParameter = (inputType, clonedTopic) => inputType === 'string' ? clonedTopic : decodeParameter(inputType, clonedTopic);

const TYPE_REGEX = /^\w+/;
const paramTypeBytes = /^bytes([0-9]*)$/;
const paramTypeBytesArray = /^bytes([0-9]*)\[\]$/;
const paramTypeNumber = /^(u?int)([0-9]*)$/;
const paramTypeNumberArray = /^(u?int)([0-9]*)\[\]$/;

const getTypeHash = (typedData, type) => sha3$1.keccak_256(encodeType(typedData, type));
const getStructHash = (	typedData, type, data ) => sha3$1.keccak_256(encodeData(typedData, type, data));
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

		return ['bytes32', sha3$1.keccak_256(encodeParameters(types, values))];
	}

	if (typedData.types[type]) {
		return ['bytes32', getStructHash(typedData, type, data)];
	}

	// Strings and arbitrary byte arrays are hashed to bytes32
	if (type === 'string') {
		return ['bytes32', sha3$1.keccak_256(data)];
	}

	if (type === 'bytes') {
		return ['bytes32', sha3$1.keccak_256(data)];
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
			abi.push({ type: toHex$1(param, true) });
		}
	});
	return abi;
}

function convertExternalAbiParameter(abiParam) {
	return { ...abiParam, name: abiParam.name ?? '', components: abiParam.components?.map(c => convertExternalAbiParameter(c)) };
}

function extractArrayType(param) {
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

function isDynamic(param) {
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

const jsonInterfaceMethodToString = (json) => {
	if (isAbiErrorFragment(json) || isAbiEventFragment(json) || isAbiFunctionFragment(json)) {
		if (json.name?.includes('(')) {
			return json.name;
		}
		return `${json.name ?? ''}(${flattenTypes(false, json.inputs ?? []).join(',')})`;
	}
	return `(${flattenTypes(false, json.inputs ?? []).join(',')})`;
};

const decodeContractErrorData = (errorsAbi, error) => {
	if (error?.data) {
		let errorName;
		let errorSignature;
		let errorArgs;
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

const decodeLog = ( inputs, data, topics ) => {
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

const decodeParameter = (abi, bytes) => {
  return(decodeParameters([abi], bytes)['0'])
};

const decodeParameters = (abi, bytes) => {
	const abiParams = toAbiParams(abi);
	const bytesArray = hexToUint8Array(bytes);
	return decodeTuple({ type: 'tuple', name: '', components: abiParams }, bytesArray).result;
};

const decodeParametersWith = ( abis, bytes, loose) => {
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

const encodeErrorSignature = (functionName) => {
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

const encodeEventSignature = (functionName) => {
	if (typeof functionName !== 'string' && !isAbiEventFragment(functionName)) {
		throw new Error('Invalid parameter value in encodeEventSignature');
	}

	if (functionName && (typeof functionName === 'function' || typeof functionName === 'object')) {
		functionName = jsonInterfaceMethodToString(functionName);
	}

	return sha3Raw(functionName);
};

const encodeFunctionCall = ( jsonInterface, params ) => {
	if (!isAbiFunctionFragment(jsonInterface)) {
		throw new Error('Invalid parameter value in encodeFunctionCall');
	}
	return `${encodeFunctionSignature(jsonInterface)}${encodeParameters( jsonInterface.inputs ?? [], params ?? [] ).replace('0x', '')}`;
};

const encodeFunctionSignature = (functionName) => {
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

const encodeParameter = (abi, param) => {
  return(encodeParameters([abi], [param]))
};

const encodeParameters = (abi, params) => {
  if (abi?.length !== params.length) {
    throw new Error('Invalid number of values received for given ABI', { expected: abi?.length, received: params.length });
  }
  const abiParams = toAbiParams(abi);
  return uint8ArrayToHexString( encodeTuple({ type: 'tuple', name: '', components: abiParams }, params).encoded );
};

const flattenTypes = ( includeTuple, puts ) => {
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

const formatOddHexstrings = (param) => isOddHexstring(param) ? `0x0${param.substring(2)}` : param;

const formatParam = (type, _param) => {
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
		const hexParam = isUint8Array(param) ? toHex$1(param) : param;

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

const getEncodedEip712Data = (typedData, hash) => {
	const EIP_191_PREFIX = '1901';
	const message = `0x${EIP_191_PREFIX}${getStructHash( typedData, 'EIP712Domain', typedData.domain ).substring(2)}${getStructHash(typedData, typedData.primaryType, typedData.message).substring(2)}`;

	if (hash) {
		return sha3$1.keccak_256(message);
	}

	return message;
};

function inferTypesAndEncodeParameters(params) {
	try {
		const abiParams = inferParamsAbi(params);
		return uint8ArrayToHexString( encodeTuple({ type: 'tuple', name: '', components: abiParams }, params).encoded );
	} catch (e) {
		// throws If the inferred params type caused an error
		throw new Error('Could not infer types from given params', {params});
	}
}

const isAbiConstructorFragment = (item) =>
	!isNullish(item) &&
	typeof item === 'object' &&
	!isNullish(item.type) &&
	item.type === 'constructor';

const isAbiErrorFragment = (item)  =>
	!isNullish(item) &&
	typeof item === 'object' &&
	!isNullish(item.type) &&
	item.type === 'error';

const isAbiEventFragment = (item) =>
	!isNullish(item) &&
	typeof item === 'object' &&
	!isNullish(item.type) &&
	item.type === 'event';

const isAbiFragment = (item) =>
	!isNullish(item) &&
	typeof item === 'object' &&
	!isNullish(item.type) &&
	['function', 'event', 'constructor', 'error'].includes(item.type);

const isAbiFunctionFragment = (item) =>
	!isNullish(item) &&
	typeof item === 'object' &&
	!isNullish(item.type) &&
	item.type === 'function';

const isOddHexstring = (param) =>
	typeof param === 'string' && /^(-)?0x[0-9a-f]*$/i.test(param) && param.length % 2 === 1;

const isSimplifiedStructFormat = (type) =>
	typeof type === 'object' && typeof type.components === 'undefined' && typeof type.name === 'undefined';

const mapStructNameAndType = (structName) =>
	structName.includes('[]') ? { type: 'tuple[]', name: structName.slice(0, -2) } : { type: 'tuple', name: structName };

const mapStructToCoderFormat = (struct) => {
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

const mapTypes = (types) => {
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

var Abi = /*#__PURE__*/Object.freeze({
  __proto__: null,
  convertExternalAbiParameter: convertExternalAbiParameter,
  decodeContractErrorData: decodeContractErrorData,
  decodeLog: decodeLog,
  decodeParameter: decodeParameter,
  decodeParameters: decodeParameters,
  decodeParametersWith: decodeParametersWith,
  encodeDynamicParams: encodeDynamicParams,
  encodeErrorSignature: encodeErrorSignature,
  encodeEventSignature: encodeEventSignature,
  encodeFunctionCall: encodeFunctionCall,
  encodeFunctionSignature: encodeFunctionSignature,
  encodeParameter: encodeParameter,
  encodeParameters: encodeParameters,
  extractArrayType: extractArrayType,
  flattenTypes: flattenTypes,
  formatOddHexstrings: formatOddHexstrings,
  formatParam: formatParam,
  getEncodedEip712Data: getEncodedEip712Data,
  inferTypesAndEncodeParameters: inferTypesAndEncodeParameters,
  isAbiConstructorFragment: isAbiConstructorFragment,
  isAbiErrorFragment: isAbiErrorFragment,
  isAbiEventFragment: isAbiEventFragment,
  isAbiFragment: isAbiFragment,
  isAbiFunctionFragment: isAbiFunctionFragment,
  isDynamic: isDynamic,
  isOddHexstring: isOddHexstring,
  isSimplifiedStructFormat: isSimplifiedStructFormat,
  jsonInterfaceMethodToString: jsonInterfaceMethodToString,
  mapStructNameAndType: mapStructNameAndType,
  mapStructToCoderFormat: mapStructToCoderFormat,
  mapTypes: mapTypes
});

function encode$1(input) {
  if (Array.isArray(input)) {
    const output = [];
    for (let i = 0; i < input.length; i++) {
      output.push(encode$1(input[i]));
    }
    const buf = concatBytes$1(...output);
    return concatBytes$1(encodeLength(buf.length, 192), buf)
  }
  const inputBuf = toBytes(input);
  if (inputBuf.length === 1 && inputBuf[0] < 128) {
    return inputBuf
  }
  return concatBytes$1(encodeLength(inputBuf.length, 128), inputBuf)
}

function safeSlice(input, start, end) {
  if (end > input.length) {
    throw new Error('invalid RLP (safeSlice): end slice of Uint8Array out-of-bounds')
  }
  return input.slice(start, end)
}

function decodeLength(v) {
  if (v[0] === 0 && v[1] === 0) {
    throw new Error('invalid RLP: extra zeros')
  }

  return parseHexByte(bytesToHex(v))
}

function encodeLength(len, offset) {
  if (len < 56) {
    return Uint8Array.from([len + offset])
  }
  const hexLength = numberToHex(len);
  const lLength = hexLength.length / 2;
  const firstByte = numberToHex(offset + 55 + lLength);
  return Uint8Array.from(hexToBytes(firstByte + hexLength))
}

function decode(input, stream = false) {
  if (!input || input.length === 0) {
    return Uint8Array.from([])
  }

  const inputBytes = toBytes(input);
  const decoded = _decode(inputBytes);

  if (stream) {
    return decoded
  }
  if (decoded.remainder.length !== 0) {
    throw new Error('invalid RLP: remainder must be zero')
  }

  return decoded.data
}

/** Decode an input with RLP */
function _decode(input) {
  let length, llength, data, innerRemainder, d;
  const decoded = [];
  const firstByte = input[0];

  if (firstByte <= 0x7f) {
    // a single byte whose value is in the [0x00, 0x7f] range, that byte is its own RLP encoding.
    return {
      data: input.slice(0, 1),
      remainder: input.slice(1),
    }
  } else if (firstByte <= 0xb7) {
    // string is 0-55 bytes long. A single byte with value 0x80 plus the length of the string followed by the string
    // The range of the first byte is [0x80, 0xb7]
    length = firstByte - 0x7f;

    // set 0x80 null to 0
    if (firstByte === 0x80) {
      data = Uint8Array.from([]);
    } else {
      data = safeSlice(input, 1, length);
    }

    if (length === 2 && data[0] < 0x80) {
      throw new Error('invalid RLP encoding: invalid prefix, single byte < 0x80 are not prefixed')
    }

    return {
      data: data,
      remainder: input.slice(length),
    }
  } else if (firstByte <= 0xbf) {
    // string is greater than 55 bytes long. A single byte with the value (0xb7 plus the length of the length),
    // followed by the length, followed by the string
    llength = firstByte - 0xb6;
    if (input.length - 1 < llength) {
      throw new Error('invalid RLP: not enough bytes for string length')
    }
    length = decodeLength(safeSlice(input, 1, llength));
    if (length <= 55) {
      throw new Error('invalid RLP: expected string length to be greater than 55')
    }
    data = safeSlice(input, llength, length + llength);

    return {
      data: data,
      remainder: input.slice(length + llength),
    }
  } else if (firstByte <= 0xf7) {
    // a list between  0-55 bytes long
    length = firstByte - 0xbf;
    innerRemainder = safeSlice(input, 1, length);
    while (innerRemainder.length) {
      d = _decode(innerRemainder);
      decoded.push(d.data);
      innerRemainder = d.remainder;
    }

    return {
      data: decoded,
      remainder: input.slice(length),
    }
  } else {
    // a list  over 55 bytes long
    llength = firstByte - 0xf6;
    length = decodeLength(safeSlice(input, 1, llength));
    if (length < 56) {
      throw new Error('invalid RLP: encoded list too short')
    }
    const totalLength = llength + length;
    if (totalLength > input.length) {
      throw new Error('invalid RLP: total length is larger than the data')
    }

    innerRemainder = safeSlice(input, llength, totalLength);

    while (innerRemainder.length) {
      d = _decode(innerRemainder);
      decoded.push(d.data);
      innerRemainder = d.remainder;
    }

    return { data: decoded, remainder: input.slice(totalLength) }
  }
}

const cachedHexes = Array.from({ length: 256 }, (_v, i) => i.toString(16).padStart(2, '0'));
function bytesToHex(uint8a) {
  // Pre-caching chars with `cachedHexes` speeds this up 6x
  let hex = '';
  for (let i = 0; i < uint8a.length; i++) {
    hex += cachedHexes[uint8a[i]];
  }
  return hex
}

function parseHexByte(hexByte) {
  if (hexByte.length !== 2) throw new Error('Invalid byte sequence')
  const byte = Number.parseInt(hexByte, 16);
  if (Number.isNaN(byte)) throw new Error('Invalid byte sequence')
  return byte
}

// Caching slows it down 2-3x
function hexToBytes(hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('hexToBytes: expected string, got ' + typeof hex)
  }
  if (hex.length % 2) throw new Error('hexToBytes: received invalid unpadded hex')
  const array = new Uint8Array(hex.length / 2);
  for (let i = 0; i < array.length; i++) {
    const j = i * 2;
    array[i] = parseHexByte(hex.slice(j, j + 2));
  }
  return array
}

/** Concatenates two Uint8Arrays into one. */
function concatBytes$1(...arrays) {
  if (arrays.length === 1) return arrays[0]
  const length = arrays.reduce((a, arr) => a + arr.length, 0);
  const result = new Uint8Array(length);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const arr = arrays[i];
    result.set(arr, pad);
    pad += arr.length;
  }
  return result
}

function utf8ToBytes(utf) {
  return new TextEncoder().encode(utf)
}

/** Transform an integer into its hexadecimal value */
function numberToHex(integer) {
  if (integer < 0) {
    throw new Error('Invalid integer as argument, must be unsigned!')
  }
  const hex = integer.toString(16);
  return hex.length % 2 ? `0${hex}` : hex
}

/** Pad a string to be even */
function padToEven(a) {
  return a.length % 2 ? `0${a}` : a
}

/** Check if a string is prefixed by 0x */
function isHexPrefixed(str) {
  return str.length >= 2 && str[0] === '0' && str[1] === 'x'
}

/** Removes 0x from a given String */
function stripHexPrefix(str) {
  if (typeof str !== 'string') {
    return str
  }
  return isHexPrefixed(str) ? str.slice(2) : str
}

/** Transform anything into a Uint8Array */
function toBytes(v) {
  if (v instanceof Uint8Array) {
    return v
  }
  if (typeof v === 'string') {
    if (isHexPrefixed(v)) {
      return hexToBytes(padToEven(stripHexPrefix(v)))
    }
    return utf8ToBytes(v)
  }
  if (typeof v === 'number' || typeof v === 'bigint') {
    if (!v) {
      return Uint8Array.from([])
    }
    return hexToBytes(numberToHex(v))
  }
  if (v === null || v === undefined) {
    return Uint8Array.from([])
  }
  throw new Error('toBytes: received unsupported type ' + typeof v)
}

function assertIsUint8Array(input) {
	if (!isUint8Array(input)) {
		const msg = `This method only supports Uint8Array but input was: ${input}`;
		throw new Error(msg);
	}
}

function stripZeros(a) {
	let first = a[0];
	while (a.length > 0 && first.toString() === '0') {
		a = a.slice(1);
		first = a[0];
	}
	return a;
}

const unpadUint8Array = function (a) {
	assertIsUint8Array(a);
	return stripZeros(a);
};

function bigIntToUnpaddedUint8Array(value) {
	return unpadUint8Array(bigIntToUint8Array(value));
}

function bigIntToUint8Array(num) {
	return toUint8Array(`0x${num.toString(16)}`);
}

const zeros = function (bytes) {
	return new Uint8Array(bytes).fill(0);
};

const setLength = function (msg, length, right) {
	const buf = zeros(length);
	if (msg.length < length) {
		buf.set(msg, length - msg.length);
		return buf;
	}
	return msg.subarray(-length);
};

const setLengthLeft = function (msg, length) {
	assertIsUint8Array(msg);
	return setLength(msg, length);
};

function isAccessListUint8Array(input) {
	if (input.length === 0) {
		return true;
	}
	const firstItem = input[0];
	if (Array.isArray(firstItem)) {
		return true;
	}
	return false;
}

function isAccessList(input) {
	return !isAccessListUint8Array(input); // This is exactly the same method, except the output is negated.
}

const getAccessListData = (accessList) => {
	let AccessListJSON;
	let uint8arrayAccessList;
	if (isAccessList(accessList)) {
		AccessListJSON = accessList;
		const newAccessList = [];
		// eslint-disable-next-line @typescript-eslint/prefer-for-of
		for (let i = 0; i < accessList.length; i += 1) {
			const item = accessList[i];
			const addressBytes = toUint8Array(item.address);
			const storageItems = [];
			// eslint-disable-next-line @typescript-eslint/prefer-for-of
			for (let index = 0; index < item.storageKeys.length; index += 1) {
				storageItems.push(toUint8Array(item.storageKeys[index]));
			}
			newAccessList.push([addressBytes, storageItems]);
		}
		uint8arrayAccessList = newAccessList;
	} else {
		uint8arrayAccessList = accessList ?? [];
		// build the JSON
		const json = [];
		// eslint-disable-next-line @typescript-eslint/prefer-for-of
		for (let i = 0; i < uint8arrayAccessList.length; i += 1) {
			const data = uint8arrayAccessList[i];
			const address = bytesToHex$1(data[0]);
			const storageKeys = [];
			// eslint-disable-next-line @typescript-eslint/prefer-for-of
			for (let item = 0; item < data[1].length; item += 1) {
				storageKeys.push(bytesToHex$1(data[1][item]));
			}
			const jsonItem = {address, storageKeys};
			json.push(jsonItem);
		}
		AccessListJSON = json;
	}

	return {AccessListJSON, accessList: uint8arrayAccessList };
};

const verifyAccessList = (accessList) => {
	// eslint-disable-next-line @typescript-eslint/prefer-for-of
	for (let key = 0; key < accessList.length; key += 1) {
		const accessListItem = accessList[key];
		const address = accessListItem[0];
		const storageSlots = accessListItem[1];
		// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/consistent-type-assertions
		if ((accessListItem)[2] !== undefined) {
			throw new Error(
				'Access list item cannot have 3 elements. It can only have an address, and an array of storage slots.',
			);
		}
		if (address.length !== 20) {
			throw new Error('Invalid EIP-2930 transaction: address length should be 20 bytes');
		}
		// eslint-disable-next-line @typescript-eslint/prefer-for-of
		for (let storageSlot = 0; storageSlot < storageSlots.length; storageSlot += 1) {
			if (storageSlots[storageSlot].length !== 32) {
				throw new Error(
					'Invalid EIP-2930 transaction: storage slot length should be 32 bytes',
				);
			}
		}
	}
};

const getAccessListJSON = (accessList) => {
	const accessListJSON = [];
	for (let index = 0; index < accessList.length; index += 1) {
		const item = accessList[index];
		const JSONItem = {address: bytesToHex$1(setLengthLeft(new Uint8Array([item[0], 20]))), storageKeys: []};
		const storageSlots = item && item[1];
		for (let slot = 0; slot < storageSlots.length; slot += 1) {
			const storageSlot = storageSlots[slot];
			JSONItem.storageKeys.push(bytesToHex$1(setLengthLeft(storageSlot, 32)));
		}
		accessListJSON.push(JSONItem);
	}
	return accessListJSON;
};

const MAX_UINT64$1 = BigInt('0xffffffffffffffff');
const MAX_INTEGER$1 = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
const SECP256K1_ORDER$1 = BigInt(secp256k1.secp256k1.CURVE.n);
const SECP256K1_ORDER_DIV_2$1 = SECP256K1_ORDER$1 / BigInt(2);

const TRANSACTION_TYPE = 2;
const TRANSACTION_TYPE_UINT8ARRAY = hexToBytes$1(TRANSACTION_TYPE.toString(16).padStart(2, '0'));

const Capability$1 = {
	EIP155ReplayProtection: 155,
	EIP1559FeeMarket: 1559,
	EIP2718TypedTransaction: 2718,
	EIP2930AccessLists: 2930,
};


class FeeMarketEIP1559Transaction {

	static fromTxData(txData, opts = {}) {
		return new FeeMarketEIP1559Transaction(txData, opts);
	}

	fromSerializedTx(serialized, opts = {}) {
		if (!uint8ArrayEquals(serialized.subarray(0, 1), TRANSACTION_TYPE_UINT8ARRAY)) {
			throw new Error(`Invalid serialized tx input: not an EIP-1559 transaction (wrong tx type, expected: ${TRANSACTION_TYPE}, received: ${bytesToHex$1(serialized.subarray(0, 1))}`);
		}
		const values = decode(serialized.subarray(1));

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

		this.to === undefined || this.to === null;
		opts.allowUnlimitedInitCodeSize ?? false;

		//if (createContract && !allowUnlimitedInitCodeSize) {
			//checkMaxInitCodeSize(common, this.data.length);
		//}

		//if (!this.common.isActivatedEIP(1559)) {
			//throw new Error('EIP-1559 not enabled on Common');
		//}
		this.activeCapabilities = [1559, 2718, 2930];
		this.activeCapabilities.push(Capability$1.EIP155ReplayProtection);

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

		if (this.gasLimit * this.maxFeePerGas > MAX_INTEGER$1) {
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
		return uint8ArrayConcat(TRANSACTION_TYPE_UINT8ARRAY, encode$1(base));
	}

	static getMessageToSign(hashMessage = true) {
		const base = this.raw().slice(0, 9);
		const message = uint8ArrayConcat(TRANSACTION_TYPE_UINT8ARRAY, encode$1(base));
		if (hashMessage) {
			return sha3$1.keccak_256(message);
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
				this.cache.hash = sha3$1.keccak_256(this.serialize());
			}
			return this.cache.hash;
		}

		return sha3$1.keccak_256(this.serialize());
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
			data: bytesToHex$1(this.data),
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
    if (s !== undefined && s > SECP256K1_ORDER_DIV_2$1) {
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
      pubKey = secp256k1.secp256k1.ProjectivePoint.fromHex(pubKey).toRawBytes(false).slice(1);
    }
    if (pubKey.length !== 64) {
      throw new Error('Expected pubKey to be of length 64');
    }
    // Only take the lower 160bits of the hash
    return sha3$1.keccak_256(pubKey).slice(-20);
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
    if (this.type === 0 && !this.supports(Capability$1.EIP155ReplayProtection)) {
      this.activeCapabilities.push(Capability$1.EIP155ReplayProtection);
      hackApplied = true;
    }

    const msgHash = this.getMessageToSign(true);
    const { v, r, s } = this._ecsign(msgHash, privateKey);
    const tx = this._processSignature(v, r, s);

    // Hack part 2
    if (hackApplied) {
      const index = this.activeCapabilities.indexOf(Capability$1.EIP155ReplayProtection);
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
            if (value !== undefined && value >= MAX_UINT64$1) {
              const msg = this._errorMsg(`${key} cannot equal or exceed MAX_UINT64 (2^64-1), given ${value}`);
              throw new Error(msg);
            }
          } else if (value !== undefined && value > MAX_UINT64$1) {
            const msg = this._errorMsg(`${key} cannot exceed MAX_UINT64 (2^64-1), given ${value}`);
            throw new Error(msg);
          }
          break;
        case 256:
          if (cannotEqual) {
            if (value !== undefined && value >= MAX_INTEGER$1) {
              const msg = this._errorMsg(`${key} cannot equal or exceed MAX_INTEGER (2^256-1), given ${value}`);
              throw new Error(msg);
            }
          } else if (value !== undefined && value > MAX_INTEGER$1) {
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
      hash = this.isSigned() ? bytesToHex$1(this.hash()) : 'not available (unsigned)';
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
    const signature = secp256k1.secp256k1.sign(msgHash, privateKey);
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

const MAX_UINT64 = BigInt('0xffffffffffffffff');
const MAX_INTEGER = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
const SECP256K1_ORDER = BigInt(secp256k1.secp256k1.CURVE.n);
const SECP256K1_ORDER_DIV_2 = SECP256K1_ORDER / BigInt(2);

const Capability = {
	EIP155ReplayProtection: 155,
	EIP1559FeeMarket: 1559,
	EIP2718TypedTransaction: 2718,
	EIP2930AccessLists: 2930,
};

/**
 * An Ethereum non-typed (legacy) transaction
 */
// eslint-disable-next-line no-use-before-define
class Transaction {

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
		 const values = decode(serialized);
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
		toUint8Array(v === '' ? '0x' : v);
		toUint8Array(r === '' ? '0x' : r);
		toUint8Array(s === '' ? '0x' : s);

		this.nonce = uint8ArrayToBigInt(toUint8Array(nonce === '' ? '0x' : nonce));
		this.gasLimit = uint8ArrayToBigInt(toUint8Array(gasLimit === '' ? '0x' : gasLimit));
		this.gasPrice = uint8ArrayToBigInt(toUint8Array(gasPrice === '' ? '0x' : gasPrice));
		this.to = toB.length > 0 ? toB : undefined;
		this.value = uint8ArrayToBigInt(toUint8Array(value === '' ? '0x' : value));
		this.data = toUint8Array(data === '' ? '0x' : data);

		this.v = v ? bytesToHex$1(v) : v;//vB.length > 0 ? uint8ArrayToBigInt(vB) : undefined;
		this.r = r ? bytesToHex$1(r) : r;//rB.length > 0 ? uint8ArrayToBigInt(rB) : undefined;
		this.s = s ? bytesToHex$1(s) : s;//sB.length > 0 ? uint8ArrayToBigInt(sB) : undefined;

		this._validateCannotExceedMaxInteger({ value: this.value});
		this._validateCannotExceedMaxInteger({ gasLimit: this.gasLimit }, 64);
		this._validateCannotExceedMaxInteger({ nonce: this.nonce }, 64, true);

		this.to === undefined || this.to === null;
		opts.allowUnlimitedInitCodeSize ?? false;
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

		opts?.freeze ?? true;
	}

 	getSenderAddress() {
		return this.publicToAddress(this.getSenderPublicKey());
	}

	publicToAddress(_pubKey, sanitize = false) {
			let pubKey = _pubKey;
			assertIsUint8Array(pubKey);
			if (sanitize && pubKey.length !== 64) {
					pubKey = secp256k1.secp256k1.ProjectivePoint.fromHex(pubKey).toRawBytes(false).slice(1);
			}
			if (pubKey.length !== 64) {
					throw new Error('Expected pubKey to be of length 64');
			}
			return bytesToHex$1(sha3$1.keccak_256(pubKey).slice(-20));
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
		return encode$1(this.raw());
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
			return sha3$1.keccak_256(encode$1(message));
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

		const hash = this.getMessageToSign(true);
		//const hash = hashMessage(data);
		const signature = secp256k1.secp256k1.sign(hash, privateKeyUint8Array);
		const signatureBytes = signature.toCompactRawBytes();
		this.r = "0x" + signature.r.toString(16).padStart(64, '0');
		this.s = "0x" + signature.s.toString(16).padStart(64, '0');
		this.v = (this.chainId === undefined ? BigInt(signature.recovery) + BigInt(27) : BigInt(signature.recovery) + BigInt(35) + (BigInt(this.chainId) * BigInt(2)));

		return {
			message: this.getMessageToSign(false),
			messageHash: hash,
			v: numberToHex$1(this.v),
			r: `0x${this.r}`,
			s: `0x${this.s}`,
			signature: `${bytesToHex$1(signatureBytes)}${this.v.toString(16)}`,
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
				this.cache.hash = sha3$1.keccak_256(encode$1(this.raw()));
			}
			return this.cache.hash;
		}

		return sha3$1.keccak_256(encode$1(this.raw()));
	}

	getMessageToVerifySignature() {
		if (!this.isSigned()) {
			const msg = this._errorMsg('This transaction is not signed');
			throw new Error(msg);
		}
		const message = this._getMessageToSign();
		return bytesToHex$1(sha3$1.keccak_256(encode$1(message)));
	}

	_validateHighS() {
		const { s } = this;
		if (s !== undefined && uint8ArrayToBigInt(hexToBytes$1(s)) > SECP256K1_ORDER_DIV_2) {
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
			data: bytesToHex$1(this.data),
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
			hash = this.isSigned() ? bytesToHex$1(this.hash()) : 'not available (unsigned)';
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

	errorStr() {
		let errorStr = this._getSharedErrorPostfix();
		errorStr += ` gasPrice=${this.gasPrice}`;
		return errorStr;
	}

 _errorMsg(msg) {
		return `${msg} (${this.errorStr()})`;
	}
}

class TransactionFactory {

	static typeToInt(txType) {
		return Number(uint8ArrayToBigInt(toUint8Array(txType)));
	}

	static fromTxData(txData, txOptions = {}) { //FIX THIS
		if (!('type' in txData) || txData.type === undefined) {
			return Transaction.fromTxData(txData, txOptions);
		}
		const txType = TransactionFactory.typeToInt(txData.type);
		if (txType === 0) {
			return Transaction.fromTxData(txData, txOptions);
		}
		if (txType === 1) {
			throw new Error(`Tx instantiation with type ${txType} not supported`);
			//return AccessListEIP2930Transaction.fromTxData(txData, txOptions);
		}
		if (txType === 2) {
			return FeeMarketEIP1559Transaction.fromTxData(txData, txOptions);
		}


	}

	static fromSerializedData(data, txOptions = {}) {
		if (data[0] <= 0x7f) {
			switch (data[0]) {
				case 1:
					//return AccessListEIP2930Transaction.fromSerializedTx(data, txOptions);
				case 2:
					return FeeMarketEIP1559Transaction.fromSerializedTx(data, txOptions);
				default: {
					throw new Error(`TypedTransaction with ID ${data[0]} unknown`);
				}
			}
		}
		else {
			return Transaction.fromSerializedTx(data, txOptions);
		}
	}

	static fromBlockBodyData(data, txOptions) {
		if (isUint8Array(data)) {
			return this.fromSerializedData(data , txOptions);
		}
		throw new Error('Cannot decode transaction: unknown type input');
	}
}

function isBytes(a) {
  return (
    a instanceof Uint8Array ||
    (a != null && typeof a === 'object' && a.constructor.name === 'Uint8Array')
  );
}

function abytes(b, ...lengths) {
  if (!isBytes(b)) throw new Error('Uint8Array expected');
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error(`Uint8Array expected of length ${lengths}, not of length=${b.length}`);
}

function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}

function equalsBytes(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function validateOpt(key, iv, mode) {
  if (!mode.startsWith("aes-")) {
    throw new Error(`AES submodule doesn't support mode ${mode}`);
  }
  if (iv.length !== 16) {
    throw new Error("AES: wrong IV length");
  }
  if (
    (mode.startsWith("aes-128") && key.length !== 16) ||
    (mode.startsWith("aes-256") && key.length !== 32)
  ) {
    throw new Error("AES: wrong key length");
  }
}

async function getBrowserKey(mode, key, iv) {
  if (!crypto.web) {
    throw new Error("Browser crypto not available.");
  }
  let keyMode;
  if (["aes-128-cbc", "aes-256-cbc"].includes(mode)) {
    keyMode = "cbc";
  }
  if (["aes-128-ctr", "aes-256-ctr"].includes(mode)) {
    keyMode = "ctr";
  }
  if (!keyMode) {
    throw new Error("AES: unsupported mode");
  }
  const wKey = await crypto.web.subtle.importKey(
    "raw",
    key,
    { name: `AES-${keyMode.toUpperCase()}`, length: key.length * 8 },
    true,
    ["encrypt", "decrypt"]
  );
  // node.js uses whole 128 bit as a counter, without nonce, instead of 64 bit
  // recommended by NIST SP800-38A
  return [wKey, { name: `aes-${keyMode}`, iv, counter: iv, length: 128 }];
}

async function encrypt$2( msg, key, iv, mode = "aes-128-ctr", pkcs7PaddingEnabled = true) {
  validateOpt(key, iv, mode);
  if (crypto.web) {
    const [wKey, wOpt] = await getBrowserKey(mode, key, iv);
    const cipher = await crypto.web.subtle.encrypt(wOpt, wKey, msg);
    // Remove PKCS7 padding on cbc mode by stripping end of message
    let res = new Uint8Array(cipher);
    if (!pkcs7PaddingEnabled && wOpt.name === "aes-cbc" && !(msg.length % 16)) {
      res = res.slice(0, -16);
    }
    return res;
  } else if (crypto.node) {
    const cipher = crypto.node.createCipheriv(mode, key, iv);
    cipher.setAutoPadding(pkcs7PaddingEnabled);
    return concatBytes(cipher.update(msg), cipher.final());
  } else {
    throw new Error("The environment doesn't have AES module");
  }
}

async function getPadding(cypherText, key, iv, mode) {
  const lastBlock = cypherText.slice(-16);
  for (let i = 0; i < 16; i++) {
    // Undo xor of iv and fill with lastBlock ^ padding (16)
    lastBlock[i] ^= iv[i] ^ 16;
  }
  const res = await encrypt$2(lastBlock, key, iv, mode);
  return res.slice(0, 16);
}

async function decrypt$2(cypherText, key, iv, mode = "aes-128-ctr", pkcs7PaddingEnabled = true) {
  validateOpt(key, iv, mode);
  if (crypto.web) {
    const [wKey, wOpt] = await getBrowserKey(mode, key, iv);
    // Add empty padding so Chrome will correctly decrypt message
    if (!pkcs7PaddingEnabled && wOpt.name === "aes-cbc") {
      const padding = await getPadding(cypherText, key, iv, mode);
      cypherText = concatBytes(cypherText, padding);
    }
    const msg = await crypto.web.subtle.decrypt(wOpt, wKey, cypherText);
    const msgBytes = new Uint8Array(msg);
    // Safari always ignores padding (if no padding -> broken message)
    if (wOpt.name === "aes-cbc") {
      const encrypted = await encrypt$2(msgBytes, key, iv, mode);
      if (!equalsBytes(encrypted, cypherText)) {
        throw new Error("AES: wrong padding");
      }
    }
    return msgBytes;
  } else if (crypto) {
    const decipher = crypto.createDecipheriv(mode, key, iv);
    decipher.setAutoPadding(pkcs7PaddingEnabled);
    return concatBytes(decipher.update(cypherText), decipher.final());
  } else {
    throw new Error("The environment doesn't have AES module");
  }
}

const HASH_PREFIX = buffer.Buffer.from('SS58PRE');
const HASH_BUF = buffer.Buffer.alloc(64);

function encode(address) {
    const prefix = 0;
    const bytes = hexToUint8Array(address);

    assert$1(Number.isInteger(prefix) && prefix >= 0 && prefix < 16384, 'invalid prefix');
    let len = bytes.length;
    let hashLen;
    switch(len) {
        case 1:
        case 2:
        case 4:
        case 8:
            hashLen = 1;
            break
        case 32:
        case 33:
            hashLen = 2;
            break
        default:
            assert$1(false, 'invalid address length');
    }
    let buf;
    let offset;
    {
        buf = buffer.Buffer.allocUnsafe(1 + hashLen + len);
        buf[0] = prefix;
        offset = 1;
    }
    buf.set(bytes, offset);
    computeHash(buf, hashLen);
    for (let i = 0; i < hashLen; i++) {
        buf[offset + len + i] = HASH_BUF[i];
    }
    return base58.encode(buf)
}


function computeHash(buf, len) {
    let hash = blake2b(64);
    hash.update(HASH_PREFIX);
    hash.update(buf.subarray(0, buf.length - len));
    hash.digest(HASH_BUF);
}

const randomHex = (bytesLength) => bytesToHex$1( utils.randomBytes(new Uint8Array(bytesLength)) );

const randomBytes = (bytesLength) => utils.randomBytes(new Uint8Array(bytesLength));

const createSS58 = (pubKey) => {
  return encode(pubKey.replace("0x", ""))
};

const uuidV4 = () => {
  return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, c =>
    (c ^ utils.randomBytes(1)[0] & 15 >> c / 4).toString(16)
  );
};

const parseAndValidatePrivateKey = (data, ignoreLength) => {
	let privateKeyUint8Array;
	if (!ignoreLength && typeof data === 'string' && isHexStrict(data) && data.length !== 66) {
		throw new Error("Invalid Private Key Length");
	}

	try {
		privateKeyUint8Array = isUint8Array(data) ? (data ) : bytesToUint8Array(data);
	} catch {
		throw new Error("Invalid Private Key");
	}

	if (!ignoreLength && privateKeyUint8Array.byteLength !== 32) {
		throw new Error("Invalid Private Key Length");
	}

	return privateKeyUint8Array;
};

const checkAddressCheckSum = (data) => {
  if (!/^(0x)?[0-9a-f]{40}$/i.test(data)) return false;
	const address = data.slice(2);
	const updatedData = utils.utf8ToBytes(address.toLowerCase());
	const addressHash = uint8ArrayToHexString(sha3$1.keccak_256(ensureIfUint8Array(updatedData))).slice(2);

	for (let i = 0; i < 40; i += 1) {
		if ( (parseInt(addressHash[i], 16) > 7 && address[i].toUpperCase() !== address[i]) || (parseInt(addressHash[i], 16) <= 7 && address[i].toLowerCase() !== address[i]) ) {
			return false;
		}
	}
	return true;
};

function calculateSigRecovery(v, chainId) {
	if (BigInt(v) === BigInt(0) || BigInt(v) === BigInt(1)) return v;

	if (chainId === undefined) {
		return BigInt(v) - BigInt(27);
	}
	return BigInt(v) - (BigInt(chainId) * BigInt(2) + BigInt(35));//BigInt(v).minus(BigInt(chainId).times(2).plus(35))//(BigInt(chainId) * BigInt(2) + BigInt(35));
}

/**
 * ECDSA public key recovery from signature.
 * NOTE: Accepts `v === 0 | v === 1` for EIP1559 transactions
 * @returns Recovered public key
 */
const ecrecover = function ( msgHash, v, r, s, chainId ) {
	const recovery = calculateSigRecovery(v, chainId);
	if (recovery.toString() != "0" && recovery.toString() != "1") {
		throw new Error('Invalid signature v value');
	}
	const senderPubKey = new secp256k1.secp256k1.Signature(uint8ArrayToBigInt(r), uint8ArrayToBigInt(s)).addRecoveryBit(Number(recovery)).recoverPublicKey(bytesToHex$1(msgHash).replace("0x", "")).toRawBytes(false);
	return Buffer.from(senderPubKey).toString('hex');
};

/**********************************************************/

const create = () => {
  const privateKey = secp256k1.secp256k1.utils.randomPrivateKey();
  return privateKeyToAccount(`${bytesToHex$1(privateKey)}`);
};

const privateKeyToAccount = (privateKey, ignoreLength) => {
  const privateKeyUint8Array = parseAndValidatePrivateKey(privateKey, ignoreLength);

  return {
    address: privateKeyToAddress(privateKeyUint8Array),
    ss58Address: createSS58(privateKeyToPublicKey(privateKey)),
    privateKey: bytesToHex$1(privateKeyUint8Array),
    publicKey: privateKeyToPublicKey(privateKey, false),
    signTransaction: (_tx) => {
      throw new Error('Do not have network access to sign the transaction');
    },
    sign: (data) => sign$1(typeof data === 'string' ? data : JSON.stringify(data), privateKeyUint8Array),
    encrypt: async (password, options) => encrypt$1(privateKeyUint8Array, password, options),
  };
};

const privateKeyToAddress = (privateKey) => {
  const privateKeyUint8Array = parseAndValidatePrivateKey(privateKey);
  const publicKey = secp256k1.secp256k1.getPublicKey(privateKeyUint8Array, false);

  const publicKeyHash = sha3Raw(publicKey.slice(1));
  const address = publicKeyHash.slice(-40);

  return toChecksumAddress(`0x${address}`);
};

const privateKeyToPublicKey = (privateKey, isCompressed) => {
  const privateKeyUint8Array = parseAndValidatePrivateKey(privateKey);
  return `0x${bytesToHex$1(secp256k1.secp256k1.getPublicKey(privateKeyUint8Array, isCompressed)).slice(4)}`; // 0x and removing compression byte
};

const decrypt$1 = async (keystore, password, nonStrict) => {
  const json = typeof keystore === 'object' ? keystore : (JSON.parse(nonStrict ? keystore.toLowerCase() : keystore));
  //validator.validateJSONSchema(keyStoreSchema, json);

  if (json.version !== 3) throw new KeyStoreVersionError();

  const uint8ArrayPassword = typeof password === 'string' ? hexToBytes$1(utf8ToHex(password)) : password;
  //validator.validate(['bytes'], [uint8ArrayPassword]);

  let derivedKey;
  if (json.crypto.kdf === 'scrypt') {
    const kdfparams = json.crypto.kdfparams;
    const uint8ArraySalt = typeof kdfparams.salt === 'string' ? hexToBytes$1(kdfparams.salt) : kdfparams.salt;
    derivedKey = scrypt.scrypt( uint8ArrayPassword, uint8ArraySalt, {N: kdfparams.n, p: kdfparams.p, r: kdfparams.r, dklen: kdfparams.dklen} );
  } else if (json.crypto.kdf === 'pbkdf2') {
    const kdfparams = json.crypto.kdfparams;

    const uint8ArraySalt = typeof kdfparams.salt === 'string' ? hexToBytes$1(kdfparams.salt) : kdfparams.salt;

    derivedKey = pbkdf2Sync( uint8ArrayPassword, uint8ArraySalt,
      kdfparams.c,
      kdfparams.dklen,
      'sha256',
    );
  } else {
    throw new InvalidKdfError();
  }

  const ciphertext = hexToBytes$1(json.crypto.ciphertext);
  const mac = sha3Raw(uint8ArrayConcat(derivedKey.slice(16, 32), ciphertext)).replace('0x', '');

  if (mac !== json.crypto.mac) {
    throw new KeyDerivationError();
  }

  const seed = await decrypt$2( hexToBytes$1(json.crypto.ciphertext), derivedKey.slice(0, 16), hexToBytes$1(json.crypto.cipherparams.iv) );

  return privateKeyToAccount(seed);
};

const encrypt$1 = async (privateKey,	password,	options = undefined) => {
  const privateKeyUint8Array = parseAndValidatePrivateKey(privateKey);

    // if given salt or iv is a string, convert it to a Uint8Array
    let salt;
    if (options?.salt) {
      salt = typeof options.salt === 'string' ? hexToBytes$1(options.salt) : options.salt;
    } else {
      salt = randomBytes(32);
    }

    if (!(isString(password) || isUint8Array(password))) {
      throw new InvalidPasswordError();
    }

    const uint8ArrayPassword =
      typeof password === 'string' ? hexToBytes$1(utf8ToHex(password)) : password;

    let initializationVector;
    if (options?.iv) {
      initializationVector = typeof options.iv === 'string' ? hexToBytes$1(options.iv) : options.iv;
      if (initializationVector.length !== 16) {
        throw new IVLengthError();
      }
    } else {
      initializationVector = randomBytes(16);
    }

    const kdf = options?.kdf ?? 'scrypt';

    let derivedKey;
    let kdfparams;

    // derive key from key derivation function
    if (kdf === 'pbkdf2') {
      kdfparams = {
        dklen: options?.dklen ?? 32,
        salt: bytesToHex$1(salt).replace('0x', ''),
        c: options?.c ?? 262144,
        prf: 'hmac-sha256',
      };

      if (kdfparams.c < 1000) {
        // error when c < 1000, pbkdf2 is less secure with less iterations
        throw new PBKDF2IterationsError();
      }
      derivedKey = pbkdf2Sync(uint8ArrayPassword, salt, kdfparams.c, kdfparams.dklen, 'sha256');
    } else if (kdf === 'scrypt') {
      kdfparams = {
        n: options?.n ?? 8192,
        r: options?.r ?? 8,
        p: options?.p ?? 1,
        dklen: options?.dklen ?? 32,
        salt: bytesToHex$1(salt).replace('0x', ''),
      };
      derivedKey = scrypt.scrypt(
        uint8ArrayPassword,
        salt,
        kdfparams.n,
        kdfparams.p,
        kdfparams.r,
        kdfparams.dklen,
      );
    } else {
      throw new InvalidKdfError();
    }

    const cipher = await encrypt$2( privateKeyUint8Array, derivedKey.slice(0, 16), initializationVector, 'aes-128-ctr' );

    const ciphertext = bytesToHex$1(cipher).slice(2);

    const mac = sha3Raw(uint8ArrayConcat(derivedKey.slice(16, 32), cipher)).replace('0x', '');
    return {
      version: 3,
      id: uuidV4(),
      address: privateKeyToAddress(privateKeyUint8Array).toLowerCase().replace('0x', ''),
      crypto: {
        ciphertext,
        cipherparams: { iv: bytesToHex$1(initializationVector).replace('0x', '') },
        cipher: 'aes-128-ctr',
        kdf,
        kdfparams,
        mac,
      },
    };
};

const hashMessage = (message) => {
  const messageHex = isHexStrict(message) ? message : utf8ToHex(message);
  const messageBytes = hexToBytes$1(messageHex);
  const preamble = hexToBytes$1( utf8ToHex(`\x19Ethereum Signed Message:\n${messageBytes.byteLength}`) );
  const ethMessage = uint8ArrayConcat(preamble, messageBytes);
  return sha3Raw(ethMessage); // using keccak in web3-utils.sha3Raw instead of SHA3 (NIST Standard) as both are different
};

const recover = (data,	signatureOrV, prefixedOrR, s, prefixed) => {
  if (typeof data === 'object') {
    const signatureStr = `${data.r}${data.s.slice(2)}${data.v.slice(2)}`;
    return recover(data.messageHash, signatureStr, prefixedOrR);
  }
  if (typeof signatureOrV === 'string' && typeof prefixedOrR === 'string' && !isNullish(s)) {
    const signatureStr = `${prefixedOrR}${s.slice(2)}${signatureOrV.slice(2)}`;
    return recover(data, signatureStr, prefixed);
  }

  if (isNullish(signatureOrV)) throw new InvalidSignatureError('signature string undefined');

  const V_INDEX = 130; // r = first 32 bytes, s = second 32 bytes, v = last byte of signature
  const hashedMessage = prefixedOrR ? data : hashMessage(data);

  let v = parseInt(signatureOrV.substring(V_INDEX), 16); // 0x + r + s + v
  if (v > 26) {
    v -= 27;
  }

  const ecPublicKey = secp256k1.secp256k1.Signature.fromCompact(signatureOrV.slice(2, V_INDEX)).addRecoveryBit(v).recoverPublicKey(hashedMessage.replace('0x', '')).toRawBytes(false);

  const publicHash = sha3Raw(ecPublicKey.subarray(1));

  const address = toChecksumAddress(`0x${publicHash.slice(-40)}`);

  return address;
};

const recoverTransaction = (rawTransaction) => {
  if (isNullish(rawTransaction)) throw new UndefinedRawTransactionError();

  const tx = TransactionFactory.fromSerializedData(hexToBytes$1(rawTransaction));
  return toChecksumAddress(tx.getSenderAddress());
};

const sign$1 = (data, privateKey) => {
  const privateKeyUint8Array = parseAndValidatePrivateKey(privateKey);
  const hash = hashMessage(data);

  const signature = secp256k1.secp256k1.sign(hash.substring(2), privateKeyUint8Array);
  const signatureBytes = signature.toCompactRawBytes();
  const r = signature.r.toString(16).padStart(64, '0');
  const s = signature.s.toString(16).padStart(64, '0');
  const v = signature.recovery + 27;

  return {
    message: data,
    messageHash: hash,
    v: numberToHex$1(v),
    r: `0x${r}`,
    s: `0x${s}`,
    signature: `${bytesToHex$1(signatureBytes)}${v.toString(16)}`,
  };
};

const signTransaction = (transaction, privateKey) => {
  transaction = TransactionFactory.fromTxData(transaction);
  //console.log("hashedTX", bytesToHex(transaction.getMessageToSign()) )
  //const signedTx = sign(bytesToHex(transaction.getMessageToSign()), hexToBytes(privateKey));
  transaction.sign(bytesToHex$1(hexToBytes$1(privateKey)));

  if (isNullish(transaction.v) || isNullish(transaction.r) || isNullish(transaction.s))
    throw new Error('Signer Error');

  const validationErrors = transaction.validate(true);
  if (validationErrors.length > 0) {
    let errorString = 'Signer Error ';
    for (const validationError of validationErrors) {
      errorString += `${errorString} ${validationError}.`;
    }
    throw new Error(errorString);
  }

  const rawTx = bytesToHex$1(transaction.serialize());
  const txHash = sha3Raw(rawTx); // using keccak in web3-utils.sha3Raw instead of SHA3 (NIST Standard) as both are different
  return {
    messageHash: transaction.getMessageToSign(),
    v: `0x${transaction.v.toString(16)}`,
    r: `${transaction.r.toString(16).padStart(64, '0')}`,
    s: `${transaction.s.toString(16).padStart(64, '0')}`,
    rawTransaction: rawTx,
    transactionHash: bytesToHex$1(txHash),
  };
};

const format = () => "1";

const keccak256Wrapper = () => "1";

const mergeDeep = () => "1";



/*
export const hexToBytes = (hex) => {
  let bytes = [];
  for (let c = 0; c < hex.length; c += 2)
      bytes.push(parseInt(hex.substr(c, 2), 16));
  return bytes;
}

//export bytesToHex;
/*
export const bytesToHex = (value) => {
  let hex = [];
  for (let i = 0; i < bytes.length; i++) {
      let current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
      hex.push((current >>> 4).toString(16));
      hex.push((current & 0xF).toString(16));
  }
  return hex.join("");
}*/

const fromDecimal = (value) => toHex$1(value);
const fromUtf8 = (value) => utf8ToHex(value);
//const numberToHex = (value) => toHex(value)
const stringToHex = (value) => toHex$1(value);

var Utils = /*#__PURE__*/Object.freeze({
  __proto__: null,
  asciiToHex: asciiToHex,
  bytesToHex: bytesToHex$1,
  bytesToUint8Array: bytesToUint8Array,
  checkAddressCheckSum: checkAddressCheckSum,
  convert: convert,
  convertScalarValue: convertScalarValue,
  ecrecover: ecrecover,
  encodePacked: encodePacked,
  format: format,
  fromAscii: fromAscii,
  fromDecimal: fromDecimal,
  fromTwosComplement: fromTwosComplement,
  fromUtf8: fromUtf8,
  fromWei: fromWei,
  getStorageSlotNumForLongString: getStorageSlotNumForLongString,
  hexToAscii: hexToAscii,
  hexToBytes: hexToBytes$1,
  hexToNumber: hexToNumber,
  hexToNumberString: hexToNumberString,
  hexToString: hexToString,
  hexToUtf8: hexToUtf8,
  isAddress: isAddress,
  isContractInitOptions: isContractInitOptions,
  isDataFormat: isDataFormat,
  isHex: isHex,
  isHexStrict: isHexStrict,
  isNullish: isNullish,
  isPromise: isPromise,
  isUint8Array: isUint8Array,
  keccak256Wrapper: keccak256Wrapper,
  leftPad: leftPad,
  mergeDeep: mergeDeep,
  numberToHex: numberToHex$1,
  padLeft: padLeft,
  padRight: padRight,
  randomBytes: utils.randomBytes,
  randomHex: randomHex,
  rightPad: rightPad,
  sha3: sha3,
  sha3Raw: sha3Raw,
  soliditySha3: soliditySha3,
  soliditySha3Raw: soliditySha3Raw,
  stringToHex: stringToHex,
  toAscii: toAscii,
  toBigInt: toBigInt,
  toBool: toBool$1,
  toChecksumAddress: toChecksumAddress,
  toDecimal: toDecimal,
  toHex: toHex$1,
  toNumber: toNumber,
  toTwosComplement: toTwosComplement,
  toUtf8: toUtf8,
  toWei: toWei,
  utf8ToBytes: utils.utf8ToBytes,
  utf8ToHex: utf8ToHex,
  uuidV4: uuidV4
});

const rpcSend = async (wallet, method, args = [], chain = null) => { //blockNumber = "latest"
  var rawResponse = await fetch(wallet.provider.provider, { method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
    body: JSON.stringify({
      id: uuidV4(),
      jsonrpc: "2.0",
      method: method,
      params: args,
      ...(chain && {chain: chain})
    })
  });
  var content = await rawResponse?.json();
  return content ? content : {err: "RPC Not Active"}
};

const rpcSendAbi = async (wallet, address, method, abi, args, chain = null) => {
  /*
  from: DATA, 20 Bytes - The address the transaction is sent from.
  to: DATA, 20 Bytes - (optional when creating new contract) The address the transaction is directed to.
  gas: QUANTITY - (optional, default: 90000) Integer of the gas provided for the transaction execution. It will return unused gas.
  gasPrice: QUANTITY - (optional, default: To-Be-Determined) Integer of the gasPrice used for each paid gas.
  value: QUANTITY - (optional) Integer of the value sent with this transaction.
  input: DATA - The compiled code of a contract OR the hash of the invoked method signature and encoded parameters.
  nonce: QUANTITY - (optional) Integer of a nonce. This allows to overwrite your own pending transactions that use the same nonce.

  getNonce(){
    var rawResponse = fetch(this.provider, {method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
      body: JSON.stringify({ id: Utils.randomHex(16), jsonrpc: "2.0", method: "eth_nonce" })
    }).then(res => res.json()).then((res) => {
      this.nonce = Number(res.result)
    })
  }
  */

  var options = {};
  if(args && args.length > 0 && typeof args[args.length - 1] == "object"){
    options = args[args.length - 1];
    args.pop();
  }

  var privateKey;
  if(wallet.provider.provider != "http://localhost:8484/pyre" && method == "eth_sendTransaction"){ // !!! USE THE TX BUILDER HERE - YOU NEED MORE DATA FOR THIS KIND OF CALL
    if(wallet.walletList.length != 0){
      if(options.from && wallet.walletList.find((e) => e.address == options.from)){
        privateKey = wallet.walletList.find((e) => e.address == options.from).privateKey;
        method = "eth_sendSignedTransaction";
      }
      else if(!options.from){
        privateKey = wallet.walletList[wallet.defaultWallet].privateKey;
        method = "eth_sendSignedTransaction";
      }
      else {
        throw new Error("Invalid From Address")
      }
    }
    else {
      throw new Error("Invalid From Address")
    }
  }

  var data = encodeFunctionCall(abi, args);

  if(privateKey){
    data = sign(data, privateKey);
  }

  var rawResponse = await fetch(wallet.provider.provider, { method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
    body: JSON.stringify({
      id: uuidV4(),
      jsonrpc: "2.0",
      method: method,
      abiData: abi,
      inputs: args,
      params: [{to: address, from: wallet.defaultAccount, value: "0", ...options, input: data}, "latest"],
      ...(chain && {chain: chain})
    })
  }).catch((err) => {
    console.log(err);
  });



  var content = await rawResponse?.json();

  if(!content){
    return {err: "RPC Not Active"}
    //throw new Error("RPC Not Active")
  }
  if(content.error){
    throw new Error(content.error.message)
  }

  var params = abi.outputs.map((e) => { return({type: e.type, name: e.name}) });

  if(params.length > 1){
    Object.keys(params).map((keys, i) =>
      {
        if(params[i].type.includes("int")){
          try{
            content.result[keys] = padLeft(content.result[keys], 64);
          }
          catch(err){
            //console.log(err)
          }
        }
      }
    );
    content.result = decodeParameters(params, content.result);
  }
  else if(params.length == 1){
    if(params[0].type.includes("int")){
      content.result = padLeft(content.result, 64);
    }
    content.result = decodeParameter(params[0], content.result);
  }
  //MAKE SURE BIGNUMBER IS CAST TO STRING INSTEAD- BN IS ANNOYING FOR USERS
  return(content.result)
};

class Accounts{
	constructor(wallet){
		this.wallet = wallet;
		this.Transaction = Transaction;
	}

	create = () => create();

	parseAndValidatePrivateKey = (privateKey) => parseAndValidatePrivateKey(privateKey);

	decrypt = async (keystore, password, nonStrict) => await decrypt$1(keystore, password, nonStrict)

	encrypt = async (privateKey,	password,	options = undefined) => await encrypt$1(privateKey,	password,	options)

	hashMessage = (message) => hashMessage(message)

	privateKeyToAccount = (privateKey, ignoreLength) => privateKeyToAccount(privateKey, ignoreLength);
	privateKeyToAddress = (privateKey) => privateKeyToAddress(privateKey);
	privateKeyToPublicKey = (privateKey, isCompressed) => privateKeyToPublicKey(privateKey, isCompressed);

	recover = (data,	signatureOrV, prefixedOrR, s, prefixed) => recover(data,	signatureOrV, prefixedOrR, s, prefixed)

	recoverTransaction = (rawTransaction) => recoverTransaction(rawTransaction)

	sign = (data, privateKey) => sign$1(data, privateKey);

	signTransaction = (transaction, privateKey) => signTransaction(transaction, privateKey);
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

class Eth {
  constructor(wallet){
    this.wallet = wallet;
    this.abi = Abi;
    this.accounts = new Accounts(this.wallet);
    //this.Contract = (abi, address) => new Contract(abi, address, this.wallet);
    this.Contract.prototype.connectedWallet = this.wallet;
  }

  Contract = class {
    constructor(abi, address) {
      this.abi = abi;
      this.address = address;
      this.methods = {};
      this.estimateGas = {};
      this.initContract();
    }

    initContract() { //make private internal function
      var newMethods = this.abi.filter((e) => e.type == 'function');
      for(let x = 0; x < newMethods.length; x++){
        if(newMethods[x].stateMutability == "view"){
          this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args]);
          this.methods[newMethods[x].name] = (...args) => {return({
            call: async (options = {}) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args, options])
          })};
        }
        else {
          this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args]);
          this.methods[newMethods[x].name] = (...args) => {return({
            send: async (options = {}) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args, options])
          })};
        }
        this.estimateGas[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_estimateGas", newMethods[x], [...args]);
      }
    }
  }

  config = {
    provider: "http://localhost:7545",
    defaultAccount: null,
  }

  setProvider = (newProvider) => {
    this.wallet.setProvider(newProvider);
  }

  givenProvider = () => {
    return config.provider
  }

  currentProvider = () => {
    return config.provider
  }

  BatchRequest = () => {
    console.log("Mot Implemented Yet");
  }

  extend = () => {
    console.log("Mot Implemented Yet");
  }

  defaultAccount = () => {
    console.log("Mot Implemented Yet");
  }

  defaultHardfork = () => {
    console.log("Mot Implemented Yet");
  }

  defaultChain = () => {
    console.log("Mot Implemented Yet");
  }

  defaultCommon = () => {
    console.log("Mot Implemented Yet");
  }

  transactionBlockTimeout = () => {
    console.log("Mot Implemented Yet");
  }

  blockHeaderTimeout = () => {
    console.log("Mot Implemented Yet");
  }

  transactionConfirmationBlocks = () => {
    console.log("Mot Implemented Yet");
  }

  transactionPollingTimeout = () => {
    console.log("Mot Implemented Yet");
  }


  transactionPollingInterval = () => {
    console.log("Mot Implemented Yet");
  }

  handleRevert = () => {
    console.log("Mot Implemented Yet");
  }

  maxListenersWarningThreshold = () => {
    console.log("Mot Implemented Yet");
  }

  getProtocolVersion = () => {
    return rpcSend(this.wallet, "eth_protocolVersion")
  }

  isSyncing = () => {
    return rpcSend(this.wallet, "eth_syncing")
  }

  getCoinbase = () => {
    console.log("Mot Implemented Yet");
  }

  isMining = () => {
    return rpcSend(this.wallet, "eth_mining")
  }

  getHashrate = () => {
    return rpcSend(this.wallet, "eth_hashrate")
  }

  getGasPrice = async () => {
   var result = await rpcSend(this.wallet, "eth_gasPrice");
   if(result.result){
     return(hexToNumberString(result.result))
   }
   throw Error("Invalid Response")
  }

  getFeeHistory = (blockCount, newestBlock, sampleArray) => {
    return rpcSend(this.wallet, "eth_feeHistory", [blockCount, newestBlock, sampleArray])
  }

  getAccounts = () => {
    return rpcSend(this.wallet, "eth_accounts")
  }

  getBlockNumber = async () => {
    var result = await rpcSend(this.wallet, "eth_blockNumber");
    if(result.result){
      return(hexToNumberString(result.result))
    }
    throw Error("Invalid Response")
  }

  getBalance = async (address, tag = "latest") => {
    var result = await rpcSend(this.wallet, "eth_getBalance", [address]);
    if(result.result){
      return(hexToNumberString(result.result))
    }
    throw Error("Invalid Response")
  }

  getStorageAt = (address, storageSlot, blockNumber = "latest") => {
    return rpcSend(this.wallet, "eth_getStorageAt", [address, storageSlot, blockNumber])
  }

  getCode = (address, blockNumber = "latest") => {
    return rpcSend(this.wallet, "eth_getCode", [address, blockNumber])
  }

  getBlock = (block, txDetails) => {
    if(isNaN(Number(block))){
      return rpcSend(this.wallet, "eth_getBlockByHash", [block, txDetails])
    }
    else {
      return rpcSend(this.wallet, "eth_getBlockByNumber", [block, txDetails])
    }
  }

  getBlockTransactionCount = (block) => {
    if(isNaN(Number(block))){
      return rpcSend(this.wallet, "eth_getBlockTransactionCountByHash", [block])
    }
    else {
      return rpcSend(this.wallet, "eth_getBlockTransactionCountByNumber", [block])
    }
  }

  getBlockUncleCount = (block) => {
    if(isNaN(Number(block))){
      return rpcSend(this.wallet, "eth_getUncleCountByBlockHash", [block])
    }
    else {
      return rpcSend(this.wallet, "eth_getUncleCountByBlockNumber", [block])
    }
  }

  getUncle = (block, index) => {
    if(isNaN(Number(block))){
      return rpcSend(this.wallet, "eth_getUncleByBlockHashAndIndex", [block, index])
    }
    else {
      return rpcSend(this.wallet, "eth_getUncleByBlockNumberAndIndex", [block, index])
    }
  }

  getTransaction = (hash) => {
    return rpcSend(this.wallet, "eth_getTransactionByHash", hash)
  }

  getPendingTransactions = () => {
    return rpcSend(this.wallet, "eth_getPendingTransactions")
  }

  getTransactionFromBlock = (block, index) => {
    if(isNaN(Number(block))){
      return rpcSend(this.wallet, "eth_getTransactionByBlockHashAndIndex", [block, index])
    }
    else {
      return rpcSend(this.wallet, "eth_getTransactionByBlockNumberAndIndex", [block, index])
    }
  }

  getTransactionReceipt = (transactionHash) => {
    return rpcSend(this.wallet, "eth_getTransactionReceipt", [transactionHash])
  }

  getTransactionCount = (address, blockNumber) => {
    return rpcSend(this.wallet, "eth_getTransactionCount", [address, blockNumber])
  }

  sendTransaction = (transaction) => {
    return rpcSend(this.wallet, "eth_sendTransaction", [transaction])
  }

  sendSignedTransaction = (transaction) => {
    return rpcSend(this.wallet, "eth_sendRawTransaction", [transaction])
  }

  sign = async (message, address) => {
    var result = await rpcSend(this.wallet, "eth_sign", [address, message]);
    if(result.error){
      throw new Error(result.error)
    }
    return result.result
  }

  signTransaction = (transaction) => {
    return rpcSend(this.wallet, "eth_signTransaction", [transaction])
  }

  call = (transaction, blockNumber = " latest") => {
    return rpcSend(this.wallet, "eth_call", [transaction, blockNumber])
  }

  estimateGas = async (transaction, blockNumber = " latest") => {
    var result = await rpcSend(this.wallet, "eth_estimateGas", [transaction, blockNumber]);
    if(result.result){
      return(hexToNumberString(result.result))
    }
    throw Error("Invalid Response")
  }

  getPastLogs = (filter) => {
    return rpcSend(this.wallet, "eth_getLogs", [filter])
  }

  getChainId = async () => {
    var result = await rpcSend(this.wallet, "eth_chainId");
    if(result.result){
      return(hexToNumberString(result.result))
    }
    throw Error("Invalid Response")
  }

  getWork = () => {
    return rpcSend(this.wallet, "eth_getWork")
  }

  getProof = () => {
    return rpcSend(this.wallet, "eth_getProof")
  }

}

var Dot = /*#__PURE__*/Object.freeze({
  __proto__: null
});

const mailAddress = "0x6Da27A8F027cf8733455c4965486C890361099A2";

const sendMailAbi = {
  inputs: [
    { internalType: 'address', name: 'receiver', type: 'address' },
    { internalType: 'string', name: 'title', type: 'string' },
    { internalType: 'string', name: 'message', type: 'string' },
    { internalType: 'address', name: 'token', type: 'address' },
    { internalType: 'uint256', name: 'tokenValue', type: 'uint256' }
  ],
  name: 'sendMail',
  outputs: [],
  stateMutability: 'payable',
  type: 'function'
};

const payAbi = {
  inputs: [
    { internalType: 'address', name: 'user', type: 'address' },
    { internalType: 'uint256', name: 'productID', type: 'uint256' },
    { internalType: 'string', name: 'description', type: 'string' }
  ],
  name: 'pay',
  outputs: [],
  stateMutability: 'payable',
  type: 'function'
};

const mailPriceAbi = {
  inputs: [ { internalType: 'address', name: '', type: 'address' } ],
  name: 'mailPrice',
  outputs: [ { internalType: 'uint256', name: '', type: 'uint256' } ],
  stateMutability: 'view',
  type: 'function'
};

const payDataAbi = {
  inputs: [
    { internalType: 'address', name: '', type: 'address' },
    { internalType: 'string', name: '', type: 'string' },
    { internalType: 'uint256', name: 'productID', type: 'uint256' }
  ],
  name: 'paymentData',
  outputs: [
    { internalType: 'string', name: 'title', type: 'string' },
    { internalType: 'string', name: 'description', type: 'string' },
    { internalType: 'string', name: 'imageLink', type: 'string' },
    { internalType: 'address', name: 'currency', type: 'address' },
    { internalType: 'uint256', name: 'price', type: 'uint256' }
  ],
  stateMutability: 'view',
  type: 'function'
};

(BigInt(1) << BigInt(256)) / BigInt(2);

class Mail {
  constructor(wallet){
    this.wallet = wallet;
  }

  sendMail = async (receiver, title, message, value = 0, options = {}) => {
    options.chain = "DEV";
    var mailPrice = await rpcSendAbi(this.wallet, mailAddress, "eth_call", mailPriceAbi, [receiver], options);
    options.value = (value != 0 ? toWei(value, "ether") : options.value);
    options.value = (options.value ? BigInt(options.value) + BigInt(mailPrice) : mailPrice);
    return await rpcSendAbi(this.wallet, "eth_transfer", sendMailAbi, [receiver, title, message, "0x0000000000000000000000000000000000000000", 0], options);
  }

  sendMailToken = async (receiver, title, message, token, tokenValue, options = {}) => {
    options.chain = "DEV";
    var mailPrice = await rpcSendAbi(this.wallet, mailAddress, "eth_call", mailPriceAbi, [receiver], options);
    options.value = (options.value ? BigInt(options.value) + BigInt(mailPrice) : mailPrice);
    //APPROVE CONTRACT ERC20
    return await rpcSendAbi(this.wallet, mailAddress, "eth_transfer", sendMailAbi, [receiver, title, message, token, tokenValue], options);
  }

  encrypt = async (address, message) => {
    var encryptedMessage = await rpcSend(this.wallet, mailAddress, "eth_encrypt", [address, message], options);
    return encryptedMessage;
  }

  decrypt = async (message) => {
    var decryptedMessage = await rpcSend(this.wallet, mailAddress, "eth_decrypt", [message], options);
    return decryptedMessage;
  }

  pay = async (user, productID, message, options = {}) => {
    options.chain = "DEV";
    var productData = await rpcSendAbi(this.wallet, mailAddress, "eth_call", payDataAbi, [receiver], options);
    if(productData.currency == "0x0000000000000000000000000000000000000000"){
      options.value = productData.price;
      return await rpcSendAbi(this.wallet, mailAddress, "eth_transfer", payAbi, [user, productID, message], options);
    }
    else {
      //APPROVE CONTRACT ERC20
      return await rpcSendAbi(this.wallet, mailAddress, "eth_transfer", payAbi, [user, productID, message], options);
    }
  }

}

buffer.Buffer.from('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex');
buffer.Buffer.alloc(32, 0);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

function equalConstTime(b1, b2) {
  if (b1.length !== b2.length) {
    return false;
  }
  var res = 0;
  for (var i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i];  // jshint ignore:line
  }
  return res === 0;
}

function hmacSha256(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest();
}
/*
function sha512(msg) {
  return crypto.createHash("sha512").update(msg).digest();
}*/

function aes256CbcEncrypt(iv, key, plaintext) {
  var cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(plaintext);
  var secondChunk = cipher.final();
  return buffer.Buffer.concat([firstChunk, secondChunk]);
}

function aes256CbcDecrypt(iv, key, ciphertext) {
  var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(ciphertext);
  var secondChunk = cipher.final();
  return buffer.Buffer.concat([firstChunk, secondChunk]);
}

function getPublic(privateKey) {
  //assert(privateKey.length === 32, "Bad private key");
  //assert(isValidPrivateKey(privateKey), "Bad private key");
  //var compressed = secp256k1.publicKeyCreate(privateKey);
  return secp256k1.secp256k1.getPublicKey(privateKey, false);
}
const derive = (privateKeyA, publicKeyB) => {
  return new Promise(function(resolve) {
    //assert(privateKeyA.length === 32, "Bad private key");
    //assert(isValidPrivateKey(privateKeyA), "Bad private key");
    //resolve(ecdh.derive(privateKeyA, publicKeyB));
    resolve(secp256k1.secp256k1.getSharedSecret(privateKeyA, publicKeyB));
  });
};

const encrypt = (publicKeyTo, msg, opts) => {
  opts = opts || {};
  // Tmp variable to save context from flat promises;
  var ephemPublicKey;
  return new Promise(function(resolve) {
    //secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey())
    var ephemPrivateKey = opts.ephemPrivateKey || secp256k1.secp256k1.utils.randomPrivateKey();//Buffer.from(randomBytes(32));
    if(publicKeyTo?.constructor?.name !== 'Uint8Array'){
      if(publicKeyTo.substr(0, 2) == "0x"){
        publicKeyTo = publicKeyTo.slice(2);
      }
      publicKeyTo = hexToUint8Array(publicKeyTo);
    }

    /*
    if(!isValidPrivateKey(ephemPrivateKey)){
      console.log("INVALID KEY")
      return "INVALID KEY"
    }
    while(!isValidPrivateKey(ephemPrivateKey)) {
      ephemPrivateKey = opts.ephemPrivateKey || secp256k1.utils.randomPrivateKey()//Buffer.from(randomBytes(32));
    }*/
    ephemPublicKey = getPublic(ephemPrivateKey);
    resolve(derive(ephemPrivateKey, publicKeyTo));
  }).then(function(Px) {
    var hash = sha512.sha512(Px);
    var iv = opts.iv || buffer.Buffer.from(utils.randomBytes(16));
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var ciphertext = aes256CbcEncrypt(iv, encryptionKey, msg);
    var dataToMac = buffer.Buffer.concat([iv, ephemPublicKey, ciphertext]);
    let mac = hmacSha256(macKey, dataToMac);
    return { iv: iv, ephemPublicKey: ephemPublicKey, ciphertext: ciphertext, mac: mac };
  });
};

const decrypt = (privateKey, opts) => {
  privateKey = privateKey.substr(-64);
  return derive(privateKey, opts.ephemPublicKey).then(function(Px) {
    assert(privateKey.length === 64, "Bad private key");
    var hash = sha512.sha512(Px);
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var dataToMac = buffer.Buffer.concat([ opts.iv, opts.ephemPublicKey, opts.ciphertext]);
    var realMac = hmacSha256(macKey, dataToMac);
    assert(equalConstTime(opts.mac, realMac), "Bad MAC"); return aes256CbcDecrypt(opts.iv, encryptionKey, opts.ciphertext).toString();
  });
};

const onChange = (provider, options) => {

};

class Wallet{
  constructor(provider){
    this.provider = provider;
    this.walletList = [];
    this.add = (privateKey) => this.walletList.push(privateKeyToAccount(privateKey));
    this.clear = () => this.walletList = [];
    this.create = (count = 1) => {for(var x = 0; x < count; x++){this.walletList.push(create());}};
    this.decrypt = () => "WIP";
    this.encrypt = () => "WIP";
    this.get = () => "WIP";
    this.load = () => "WIP";
    this.remove = () => "WIP";
    this.save = () => "WIP";
    this.getStorage = () => "WIP";
  }

  setDefaultAccount(address){
    this.defaultAccount = address;
  }
}

class Provider{
  constructor(provider){
    this.provider = provider;
    this.url = provider;
    this.modules = {
      Eth: "Eth(provider)",
      Net: "Net(provider)",
      Personal: "Personal(provider)"
    };
    this.version = "1.0.0";
    this.getChainId();
    this.getDefaultGasPrice();
  }

  setProvider(newProvider) {
    this.provider = newProvider;
    this.url = provider;
    this.getChainId();
    this.getDefaultGasPrice();
  }

  getChainId(){
    fetch(this.provider, {method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
      body: JSON.stringify({ id: randomHex(16), jsonrpc: "2.0", method: "eth_chainId" })
    }).then(res => res.json()).then((res) => {
      this.chainId = Number(res.result);
    });
  }

  getDefaultGasPrice(){
    fetch(this.provider, {method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
      body: JSON.stringify({ id: randomHex(16), jsonrpc: "2.0", method: "eth_gasPrice" })
    }).then(res => res.json()).then((res) => {
      this.gasprice = Number(res.result);
    });
  }
}

class Contract {
  constructor(abi, address, wallet) {
    this.abi = abi;
    this.address = address;
    this.methods = {};
    this.connectedWallet = wallet;
    this.estimateGas = {};
    this.initContract();
  }

  initContract() { //make private internal function
    var newMethods = this.abi.filter((e) => e.type == 'function');
    for(let x = 0; x < newMethods.length; x++){
      if(newMethods[x].stateMutability == "view"){
        this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args]);
        this.methods[newMethods[x].name] = (...args) => {return({
          call: async (options = {}) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args, options])
        })};
      }
      else {
        this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args]);
        this.methods[newMethods[x].name] = (...args) => {return({
          send: async (options = {}) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args, options])
        })};
      }
      this.estimateGas[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_estimateGas", newMethods[x], [...args]);
    }
  }
}

class Pyre {
  constructor(provider) {
    this.provider = new Provider(typeof provider == "string" ? provider : "http://localhost:8484/pyre");
    this.testBN = BigInt(55);
    this.wallet = new Wallet(this.provider);
    this.utils = Utils;
    this.eth = new Eth(this.wallet);
    this.mail = new Mail(this.wallet);
    this.dot = Dot;
    this.onChange = onChange;
    this.pay = this.mail.pay;
    this.payToken = this.mail.payToken;
    //this.quote = quote;
    this.encrypt = encrypt;
    this.decrypt = decrypt;
    this.Contract = (abi, address) => new Contract(abi, address, this.wallet);
  }

  connect = async (provider, options) => {
    var rawResponse = await fetch("http://localhost:8484/pyre", {
      method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
      body: JSON.stringify({ id: randomHex(16), jsonrpc: "2.0", method: "eth_enable", chain: options })
    });
    var content = await rawResponse?.json();
    if(!content){
      return {err: "RPC Not Active"}
    }
    if(!content.error){
      this.wallet.setDefaultAccount(content.result);
    }
    return(content.result)
  }

  setProvider = (newProvider, options) => {
    this.provider.setProvider(newProvider);
    //this.eth.Contract.setProvider(newProvider);
  }

  request = async (data) => {
    if(data.method == "eth_requestAccounts"){
      return [await this.connect()];
    }
  }

  send = async (address, amount, chain = null) => { //opts can include chain variable
    var res = await rpcSend(this.wallet, "eth_sendTransaction", {to: address, from: this.wallet.defaultAccount, value: amount}, chain);
    return(res)
  }



/*
  swap = (from, amount, to, opts = {amountOutMin: 0, amountInMax: null, deadline: Math.floor(new Date().getTime() + 60000 / 1000) }) => {
    var swapContract = Contract(swapAbi, swapAddress);
    var res;
    if(amountInMin){
      res = swapContract.swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline)
    }
    else{
      res = swapContract.swapTokensForExactTokens(amountOut, amountInMax, path, to, deadline)
    }
    return res;
  }*/

  quote = (provider, options) => {
    //call quote function from Uniswap
  }

  addAddress = async (address) => {
    var res = await rpcSend(this.wallet, "eth_addAddressBook", {address: address});
    return(res)
  }

  Contract = class {
    constructor(abi, address) {
      this.abi = abi;
      this.address = address;
      this.methods = {};
      this.estimateGas = {};
      this.initContract();
    }

    initContract() { //make private internal function
      var newMethods = this.abi.filter((e) => e.type == 'function');
      for(let x = 0; x < newMethods.length; x++){
        if(newMethods[x].stateMutability == "view"){
          this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args]);
          this.methods[newMethods[x].name] = (...args) => {return({
            call: async (options = {}) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args, options])
          })};
        }
        else {
          this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args]);
          this.methods[newMethods[x].name] = (...args) => {return({
            send: async (options = {}) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args, options])
          })};
        }
        this.estimateGas[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_estimateGas", newMethods[x], [...args]);
      }
    }
  }

}

module.exports = Pyre;
