import {ETHER_UNITS} from './enums.js'

BigInt.prototype.toWei = function(unit = "ether"){
  return ETHER_UNITS[unit].times(this);
}

BigInt.prototype.fromWei = function(unit = "ether"){
  return new BigInt(this) / (ETHER_UNITS[unit]);
}
//bigIntToUnpaddedUint8Array
//bigIntToHex

BigInt.prototype.toU8A = function(unit = "ether"){
  //return new BigInt(this) / (ETHER_UNITS[unit]);
}

BigInt.prototype.toUnpaddedU8A = function(unit = "ether"){
  //return new BigInt(this) / (ETHER_UNITS[unit]);
}

BigInt.prototype.toHex = function(unit = "ether"){
  return this.toString(16)
}
