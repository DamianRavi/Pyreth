/*
emit
getMaxListeners
listenerCount
listeners
off
on
once
removeAllListeners

extend
*/
/*
ecRecover
getAccounts
importRawKey
lockAccount
newAccount
sendTransaction
setConfig
setProvider
sign
signTransaction
unlockAccount

export const provider;
export const config;

export const setProvider = (password) => {

}

export const setConfig = (password) => {

}

export const newAccount = (password) => {

}

export const sign = (data, address, passphrase) => {

}

export const ecrecover = ( signedData, signature ) => {
  var r = signature.substr(2, 66);
  var s = signature.substr(66, 130);
  var v = signature.substr(130, 132);
  chainId = 1;
	const recovery = calculateSigRecovery(v, chainId);
	if (!isValidSigRecovery(recovery)) {
		throw new Error('Invalid signature v value');
	}
	const senderPubKey = new secp256k1.Signature(uint8ArrayToBigInt(r), uint8ArrayToBigInt(s)).addRecoveryBit(Number(recovery)).recoverPublicKey(msgHash).toRawBytes(false);
	return senderPubKey.slice(1);
};


export const signTransaction = (tx, passphrase) => {

}

export const sendTransaction = (tx, passphrase) => {

}

export const unlockAccount = (address, password, unlockDuration) => {

}

export const lockAccount = (address) => {

}

export const getAccounts = () => {

}

export const importRawKey = (keyData, passphrase) => {

}
*/
