import { bytesToHex, toUint8Array } from '../../../converter.js';
import { isUint8Array } from '../../../validator.js';


export const bigIntToHex = (num) => `0x${num.toString(16)}`;

export function assertIsUint8Array(input) {
	if (!isUint8Array(input)) {
		const msg = `This method only supports Uint8Array but input was: ${input}`;
		throw new Error(msg);
	}
}

export function stripZeros(a) {
	let first = a[0];
	while (a.length > 0 && first.toString() === '0') {
		a = a.slice(1);
		first = a[0];
	}
	return a;
}

export const unpadUint8Array = function (a) {
	assertIsUint8Array(a);
	return stripZeros(a);
};

export function bigIntToUnpaddedUint8Array(value) {
	return unpadUint8Array(bigIntToUint8Array(value));
}

export function bigIntToUint8Array(num) {
	return toUint8Array(`0x${num.toString(16)}`);
}

export const zeros = function (bytes) {
	return new Uint8Array(bytes).fill(0);
};

const setLength = function (msg, length, right) {
	const buf = zeros(length);
	if (right) {
		if (msg.length < length) {
			buf.set(msg);
			return buf;
		}
		return msg.subarray(0, length);
	}
	if (msg.length < length) {
		buf.set(msg, length - msg.length);
		return buf;
	}
	return msg.subarray(-length);
};

const setLengthLeft = function (msg, length) {
	assertIsUint8Array(msg);
	return setLength(msg, length, false);
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

export function isAccessList(input) {
	return !isAccessListUint8Array(input); // This is exactly the same method, except the output is negated.
}

export const checkMaxInitCodeSize = (common, length) => {
	const maxInitCodeSize = common.param('vm', 'maxInitCodeSize');
	if (maxInitCodeSize && BigInt(length) > maxInitCodeSize) {
		throw new Error(
			`the initcode size of this transaction is too large: it is ${length} while the max is ${common.param(
				'vm',
				'maxInitCodeSize',
			)}`,
		);
	}
};

export const getAccessListData = (accessList) => {
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
			const address = bytesToHex(data[0]);
			const storageKeys = [];
			// eslint-disable-next-line @typescript-eslint/prefer-for-of
			for (let item = 0; item < data[1].length; item += 1) {
				storageKeys.push(bytesToHex(data[1][item]));
			}
			const jsonItem = {address, storageKeys};
			json.push(jsonItem);
		}
		AccessListJSON = json;
	}

	return {AccessListJSON, accessList: uint8arrayAccessList };
};

export const verifyAccessList = (accessList) => {
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

export const getAccessListJSON = (accessList) => {
	const accessListJSON = [];
	for (let index = 0; index < accessList.length; index += 1) {
		const item = accessList[index];
		const JSONItem = {address: bytesToHex(setLengthLeft(new Uint8Array([item[0], 20]))), storageKeys: []};
		const storageSlots = item && item[1];
		for (let slot = 0; slot < storageSlots.length; slot += 1) {
			const storageSlot = storageSlots[slot];
			JSONItem.storageKeys.push(bytesToHex(setLengthLeft(storageSlot, 32)));
		}
		accessListJSON.push(JSONItem);
	}
	return accessListJSON;
};

export const getDataFeeEIP2930 = (accessList, common) => {
	const accessListStorageKeyCost = common.param('gasPrices', 'accessListStorageKeyCost');
	const accessListAddressCost = common.param('gasPrices', 'accessListAddressCost');

	let slots = 0;
	// eslint-disable-next-line @typescript-eslint/prefer-for-of
	for (let index = 0; index < accessList.length; index += 1) {
		const item = accessList[index];
		const storageSlots = item[1];
		slots += storageSlots.length;
	}

	const addresses = accessList.length;
	return addresses * Number(accessListAddressCost) + slots * Number(accessListStorageKeyCost);
};
