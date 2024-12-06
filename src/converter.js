import { utf8ToBytes } from "@noble/hashes/utils";
import { InvalidNumberError, NibbleWidthError, InvalidBytesError, InvalidBooleanError, HexProcessingError, TypeError, ValidationError } from './errors.js'
import { isUint8Array, isHex, isHexStrict, isAddress, isInt, isUInt, ensureIfUint8Array, isHexPrefixed, isHexString } from './validator.js'
import { padLeft } from './string.js'
import { keccak_256 as keccak256 } from '@noble/hashes/sha3';
import { SHA3_EMPTY_BYTES, ETHER_UNITS, charCodeMap } from './enums.js'
import { sha3 } from './hashes.js'

export { utf8ToBytes }
const WORD_SIZE = 32;
const mask = BigInt(1) << BigInt(256);

BigInt.prototype.toWei = function(unit = "ether"){
  var val = toWei(this, unit);
  return val.toString();
}

BigInt.prototype.fromWei = function(unit = "ether"){
  var val = fromWei(this, unit);
  return val.toString();
}

BigInt.prototype.add = function(val){
  val = BigInt(val) + this;
  return val.toString();
}

BigInt.prototype.sub = function(val){
  val = BigInt(val) - this;
  return val.toString();
}

BigInt.prototype.toHex = function(unit = "ether"){
  return this.toString(16)
}

String.prototype.toWei = function(unit = "ether"){
  var val = toWei(this, unit);
  return val.toString();
}

String.prototype.fromWei = function(unit = "ether"){
  var val = fromWei(this, unit);
  return val.toString();
}

String.prototype.add = function(val){
  val = BigInt(val) + BigInt(this);
  return val.toString();
}

String.prototype.sub = function(val){
  val = BigInt(val) - BigInt(this);
  return val.toString();
}

function charCodeToBase16(char) {
  if (char >= charCodeMap.zero && char <= charCodeMap.nine)
    return char - charCodeMap.zero
  if (char >= charCodeMap.A && char <= charCodeMap.F)
    return char - (charCodeMap.A - 10)
  if (char >= charCodeMap.a && char <= charCodeMap.f)
    return char - (charCodeMap.a - 10)
  return undefined
}

export const numberToHex = (value) => {
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
		return numberToHex(BigInt(value));
	}

	throw new InvalidNumberError(value);
};

export const asciiToHex = (str) => {
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

export const bytesToHex = (bytes) => uint8ArrayToHexString(bytesToUint8Array(bytes));

export const bytesToUint8Array = (data) => {
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

export const bytesToUtf8 = (data) => {
  if (!(data instanceof Uint8Array)) {
    throw new TypeError(`bytesToUtf8 expected Uint8Array, got ${typeof data}`);
  }
  return new TextDecoder().decode(data);
}

export const convert = () => "1";

export const convertScalarValue = () => "1";

export const fromAscii = asciiToHex;

export const fromTwosComplement = (value, nibbleWidth = 64) => {
	const val = toNumber(value);
	if (val < 0) return val;
	const largestBit = Math.ceil(Math.log(Number(val)) / Math.log(2));
	if (largestBit > nibbleWidth * 4)
		throw new NibbleWidthError(`value: "${value}", nibbleWidth: "${nibbleWidth}"`);

	if (nibbleWidth * 4 !== largestBit) return val;
	const complement = BigInt(2) ** BigInt(nibbleWidth * 4);
	return toNumber(BigInt(val) - complement);
};

export const utf8ToHex = (str) => {
  typeof str === "string" || ValidationError(`Invalid String ${typeof str} ${JSON.stringify(str)}`); //toHex(str, true)
	let strWithoutNullCharacter = str.replace(/^(?:\u0000)/, '');
	strWithoutNullCharacter = strWithoutNullCharacter.replace(/(?:\u0000)$/, '');
	return bytesToHex(new TextEncoder().encode(strWithoutNullCharacter));
};

export const getStorageSlotNumForLongString = (mainSlotNumber) => sha3( `0x${(typeof mainSlotNumber === 'number' ? mainSlotNumber.toString() : mainSlotNumber ).padStart(64, '0')}`,)

export const hexToBytes = (bytes) => (typeof bytes === 'string' && bytes.slice(0, 2).toLowerCase() !== '0x') ? bytesToUint8Array(`0x${bytes}`) : bytesToUint8Array(bytes);

export const hexToUtf8 = (hex) => bytesToUtf8(hexToBytes(hex));
//decodeURIComponent(hex.replace(/\s+/g, '').replace(/[0-9a-f]{2}/g, '%$&'));

export const hexToString = hexToUtf8;

export const hexToUint8Array = (hex) => {
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
	  const nibbleLeft = charCodeToBase16(hex.charCodeAt(j++))
	  const nibbleRight = charCodeToBase16(hex.charCodeAt(j++))
	  if (nibbleLeft === undefined || nibbleRight === undefined) {
		   throw new Error(`Invalid byte sequence ("${hex[j - 2]}${ hex[j - 1] }" in "${hex}").` )
	  }
	  bytes[index] = nibbleLeft * 16 + nibbleRight
	}
	return bytes
}

export const hexToAscii = (value) => {
  var hex = '';
  for (var i = 0, l = value.length; i < l; i++) {
    var hexx = Number(value.charCodeAt(i)).toString(16);
    hex += (hexx.length > 1 && hexx || '0' + hexx);
  }
  return hex;
}

export const toAscii = hexToAscii;

export const toBigInt = (value) => {
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

export const hexToNumber = (value) => {
  return(parseInt(value, 16))
}

export const toDecimal = hexToNumber;

export const toUtf8 = (input) => {
	if (typeof input === 'string') {
		return hexToUtf8(input);
	}
	return bytesToUtf8(input);
};

export const hexToNumberString = (value) => {
  return(parseInt(value, 16).toString())
}

export const toNumber = (value) => {
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

export const toWei = (parsedNumber, unit = "ether") => {
  if(!ETHER_UNITS[unit]){
    throw new Error("Invalid Unit")
  }
  parsedNumber = parsedNumber.toString()
  var denomination = BigInt(ETHER_UNITS[unit]);
  const [integer, fraction] = parsedNumber.split('.').concat('');

  const value = BigInt(`${integer}${fraction}`);
  const updatedValue = value * denomination;
  const decimals = fraction.length;
  if (decimals === 0) {
    return updatedValue.toString();
  }
  return updatedValue.toString().slice(0, -decimals);
}

export const fromWei = (number, unit = "ether") => {
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
}

export const toChecksumAddress = (address) => {
  if (!isAddress(address, false)) {
		throw new Error("Invalid address: " + address);
	}

	const lowerCaseAddress = address.toLowerCase().replace(/^0x/i, '');
	const hash = uint8ArrayToHexString( keccak256( ensureIfUint8Array(utf8ToBytes(lowerCaseAddress))) );

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
}

export const toTwosComplement = (value, nibbleWidth = 64) => {
  //const val = Number(value);
	const val = toNumber(value);
	if (val >= 0) return padLeft(toHex(val), nibbleWidth);

	const largestBit = BigInt.pow(2, nibbleWidth * 4)
	if (-val >= largestBit) {
		throw new NibbleWidthError(`value: ${value}, nibbleWidth: ${nibbleWidth}`);
	}
	const updatedVal = BigInt(val);
	const complement = updatedVal + largestBit;

	return padLeft(numberToHex(complement), nibbleWidth);
}

export const uint8ArrayToHexString = (uint8Array) => {
	let hexString = '0x';
	for (const e of uint8Array) {
		const hex = e.toString(16);
		hexString += hex.length === 1 ? `0${hex}` : hex;
	}
	return hexString;
}

export const stripHexPrefix = (str) => {
	if (typeof str !== 'string')
		throw new Error(`[stripHexPrefix] input must be type 'string', received ${typeof str}`);

	return isHexPrefixed(str) ? str.slice(2) : str;
};

export function padToEven(value) {
	let a = value;
	if (typeof a !== 'string') {
		throw new Error(`[padToEven] value must be type 'string', received ${typeof a}`);
	}
	if (a.length % 2) a = `0${a}`;
	return a;
}

export const bigIntToHex = (num) => `0x${num.toString(16)}`;

export const toUint8Array = function (v) {
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
		return hexToBytes(padToEven(stripHexPrefix(v)));
	}

	if (typeof v === 'number') {
		return toUint8Array(numberToHex(v));
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

export function uint8ArrayToBigInt(buf) {
	const hex = bytesToHex(buf);
	if (hex === '0x') {
		return BigInt(0);
	}
	return BigInt(hex);
}

export function bigIntToUint8Array(value, byteLength = WORD_SIZE) {
  let hexValue = (value < 0 ? (mask + value).toString(16) : value.toString(16));
  hexValue = padLeft(hexValue, byteLength * 2);
	return hexToUint8Array(hexValue);
}

export function uint8ArrayConcat(...parts) {
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

export const toHex = (value, returnType) => {
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
		return numberToHex(value);
	}
  if(Array.isArray(value)){
    uint8ArrayToHexString(bytesToUint8Array(value))
  }
  if(value instanceof Uint8Array){
    uint8ArrayToHexString(value)
  }
  if (typeof value === 'object' && !!value) {
    return utf8ToHex(JSON.stringify(value));
  }

  if (typeof value === 'string') {
    if (value.substr(0, 3) === '-0x' || value.substr(0, 3) === '-0X') {
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
}
