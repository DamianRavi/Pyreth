import { randomBytes } from "@noble/hashes/utils";
import { leftPad, padLeft, padRight, rightPad } from '../../string.js'
import { ensureIfUint8Array, isAddress, isContractInitOptions, isDataFormat, isHex, isHexStrict, isNullish, isPromise, isUint8Array, uint8ArrayEquals } from '../../validator.js'
import {
  bytesToHex, bytesToUint8Array, convert, convertScalarValue, fromAscii, fromTwosComplement, fromWei, getStorageSlotNumForLongString, hexToAscii,
  hexToBytes, hexToNumber, hexToNumberString, hexToString, hexToUtf8, numberToHex, toAscii, toBigInt, toWei, toBool, toChecksumAddress, toDecimal,
  toHex, toNumber, toTwosComplement, toUtf8, utf8ToBytes, utf8ToHex, asciiToHex
} from '../../converter.js'
import { encodePacked } from '../../hashes/solidityPack.js';
import { sha3, sha3Raw, soliditySha3, soliditySha3Raw  } from '../../hashes.js'
import { uuidV4, randomHex, checkAddressCheckSum, ecrecover } from '../../encoders.js'

const format = () => "1"

const keccak256Wrapper = () => "1"

const mergeDeep = () => "1"



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

const fromDecimal = (value) => toHex(value)
const fromUtf8 = (value) => utf8ToHex(value)
//const numberToHex = (value) => toHex(value)
const stringToHex = (value) => toHex(value)

export {
  bytesToHex, bytesToUint8Array, checkAddressCheckSum, convert, convertScalarValue, ecrecover, encodePacked, format,
  fromAscii, fromDecimal, fromTwosComplement, fromUtf8, fromWei, getStorageSlotNumForLongString, hexToAscii, hexToBytes, hexToNumber, hexToNumberString,
  hexToString, hexToUtf8, isAddress, isContractInitOptions, isDataFormat, isHex, isHexStrict, isNullish,
  isPromise, isUint8Array, keccak256Wrapper, leftPad, mergeDeep, numberToHex, padLeft, padRight,
  //pollTillDefined, pollTillDefinedAndReturnIntervalId, processSolidityEncodePackedArgs,
  randomBytes, randomHex,
  //rejectIfConditionAtInterval, rejectIfTimeout,
  rightPad,
  sha3, sha3Raw, soliditySha3, soliditySha3Raw,
  stringToHex, toAscii, toBigInt, toBool, toChecksumAddress, toDecimal, toHex, toNumber, toTwosComplement, toUtf8, toWei,
  //uint8ArrayConcat, uint8ArrayEquals,
  utf8ToBytes, utf8ToHex, uuidV4, asciiToHex
  //waitWithTimeout
}
