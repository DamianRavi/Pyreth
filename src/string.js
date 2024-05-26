import { isHexStrict } from './validator.js'

const numberToHex = (value) => {
  return("0x" + Number(value).toString(16))
}

export const padLeft = (value, characterAmount, sign = "0") => {
  if (typeof value === 'string' && !isHexStrict(value)) {
    return value.padStart(characterAmount, sign);
  }
  const hex = typeof value === 'string' && isHexStrict(value) ? value : numberToHex(value);
  const [prefix, hexValue] = hex.startsWith('-') ? ['-0x', hex.slice(3)] : ['0x', hex.slice(2)];
  return `${prefix}${hexValue.padStart(characterAmount, sign)}`;
}

export const leftPad = (value, characterAmount, sign) => padLeft(value, characterAmount, sign);

export const padRight = (value, characterAmount, sign = "0") => {
  if (typeof value === 'string' && !isHexStrict(value)) {
		return value.padEnd(characterAmount, sign);
	}
	//validator.validate(['int'], [value]);
	const hexString = typeof value === 'string' && isHexStrict(value) ? value : numberToHex(value);
	const prefixLength = hexString.startsWith('-') ? 3 : 2;
	return hexString.padEnd(characterAmount + prefixLength, sign);
}

export const rightPad = (value, characterAmount, sign) => padRight(value, characterAmount, sign);
