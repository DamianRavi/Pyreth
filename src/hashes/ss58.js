import assert from 'assert'
import base58 from 'bs58'
import blake2b from 'blake2b'
//import { blake2b } from '@noble/hashes/blake2b';
import { Buffer } from 'buffer';
import { hexToUint8Array } from '../converter.js'
const HASH_PREFIX = Buffer.from('SS58PRE')
const HASH_BUF = Buffer.alloc(64)


export function decode(s) {
    let buf = base58.decodeUnsafe(s)
    if (buf == null || buf.length < 3) throw invalidAddress(s)
    let b0 = buf[0]
    let offset
    let prefix
    if (b0 < 64) {
        prefix = b0
        offset = 1
    } else if (b0 < 128) {
        let b1 = buf[1]
        let lower = ((b0 << 2) | (b1 >> 6)) & 0b11111111
        let upper = b1 & 0b00111111
        prefix = lower | (upper << 8)
        offset = 2
    } else {
        throw invalidAddress(s)
    }
    let hashLen;
    switch(buf.length - offset) {
        case 34:
        case 35:
            hashLen = 2
            break
        case 9:
        case 5:
        case 3:
        case 2:
            hashLen = 1
            break
        default:
            throw invalidAddress(s)
    }
    computeHash(buf, hashLen)
    for (let i = 0; i < hashLen; i++) {
        if (HASH_BUF[i] != buf[buf.length - hashLen + i]) {
            throw invalidAddress(s)
        }
    }
    return {
        prefix,
        bytes: buf.subarray(offset, buf.length - hashLen)
    }
}

export function encode(address) {
    const prefix = 0;
    const bytes = hexToUint8Array(address)

    assert(Number.isInteger(prefix) && prefix >= 0 && prefix < 16384, 'invalid prefix')
    let len = bytes.length
    let hashLen;
    switch(len) {
        case 1:
        case 2:
        case 4:
        case 8:
            hashLen = 1
            break
        case 32:
        case 33:
            hashLen = 2
            break
        default:
            assert(false, 'invalid address length')
    }
    let buf
    let offset
    if (prefix < 64) {
        buf = Buffer.allocUnsafe(1 + hashLen + len)
        buf[0] = prefix
        offset = 1
    } else {
        buf = Buffer.allocUnsafe(2 + hashLen + len)
        buf[0] = ((prefix & 0b1111_1100) >> 2) | 0b01000000
        buf[1] = (prefix >> 8) | ((prefix & 0b11) << 6)
        offset = 2
    }
    buf.set(bytes, offset)
    computeHash(buf, hashLen)
    for (let i = 0; i < hashLen; i++) {
        buf[offset + len + i] = HASH_BUF[i]
    }
    return base58.encode(buf)
}


function computeHash(buf, len) {
    let hash = blake2b(64)
    hash.update(HASH_PREFIX)
    hash.update(buf.subarray(0, buf.length - len))
    hash.digest(HASH_BUF)
}


function invalidAddress(s) {
    return new Error('Invalid ss58 address: ' + s)
}
