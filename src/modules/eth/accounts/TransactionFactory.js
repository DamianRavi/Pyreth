import { isUint8Array } from '../../../validator.js';
import { toUint8Array, uint8ArrayToBigInt } from '../../../converter.js';
import { FeeMarketEIP1559Transaction } from './Eip1559Transaction.js';
//import { AccessListEIP2930Transaction } from './Eip2930Transaction.js';
import { Transaction } from './LegacyTransaction.js'

export default class TransactionFactory {

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
