import { rpcSend, rpcSendAbi } from "../../rpc.js"
import { toWei } from "../../converter.js"
export const mailAddress = "0x6Da27A8F027cf8733455c4965486C890361099A2";
export const mailAbi = [{"inputs":[],"stateMutability":"payable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"info","type":"string"}],"name":"MessageSent","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"index","type":"uint256"},{"indexed":false,"internalType":"string","name":"category","type":"string"},{"indexed":false,"internalType":"string","name":"title","type":"string"},{"indexed":false,"internalType":"string","name":"description","type":"string"},{"indexed":false,"internalType":"string","name":"imageLink","type":"string"},{"indexed":false,"internalType":"address","name":"token","type":"address"},{"indexed":false,"internalType":"uint256","name":"price","type":"uint256"}],"name":"NewProduct","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"username","type":"string"},{"indexed":false,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnerChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"username","type":"string"},{"indexed":false,"internalType":"uint256","name":"newPrice","type":"uint256"}],"name":"PriceChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"username","type":"string"},{"indexed":false,"internalType":"address","name":"newOwner","type":"address"},{"indexed":false,"internalType":"uint256","name":"price","type":"uint256"}],"name":"Purchase","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"namePrice","type":"uint256"},{"indexed":false,"internalType":"uint256","name":"messagePrice","type":"uint256"}],"name":"SettingsChanged","type":"event"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"bio","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"username","type":"string"},{"internalType":"uint256","name":"newMessagePrice","type":"uint256"}],"name":"buyName","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"namePrice","type":"uint256"},{"internalType":"uint256","name":"messagePrice","type":"uint256"}],"name":"changeDefaults","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"username","type":"string"},{"internalType":"addresspayable","name":"newOwner","type":"address"}],"name":"changeNameOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"changeOwner","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"category","type":"string"},{"internalType":"string","name":"title","type":"string"},{"internalType":"string","name":"description","type":"string"},{"internalType":"string","name":"imageLink","type":"string"},{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"price","type":"uint256"}],"name":"createProduct","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"defaultMessagePrice","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"defaultNamePrice","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"deleteMail","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"},{"internalType":"string","name":"category","type":"string"},{"internalType":"string","name":"title","type":"string"},{"internalType":"string","name":"description","type":"string"},{"internalType":"string","name":"imageLink","type":"string"},{"internalType":"uint256","name":"price","type":"uint256"},{"internalType":"address","name":"token","type":"address"}],"name":"editProduct","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"mailPrice","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"messageCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"uint256","name":"","type":"uint256"}],"name":"messages","outputs":[{"internalType":"address","name":"sender","type":"address"},{"internalType":"string","name":"username","type":"string"},{"internalType":"string","name":"title","type":"string"},{"internalType":"string","name":"message","type":"string"},{"internalType":"uint256","name":"cost","type":"uint256"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"tokenValue","type":"uint256"},{"internalType":"uint256","name":"timestamp","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"addresspayable","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"user","type":"address"},{"internalType":"uint256","name":"productID","type":"uint256"},{"internalType":"string","name":"description","type":"string"}],"name":"pay","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"user","type":"address"},{"internalType":"string","name":"category","type":"string"},{"internalType":"uint256","name":"productID","type":"uint256"},{"internalType":"string","name":"description","type":"string"}],"name":"payment","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"}],"name":"paymentCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"},{"internalType":"string","name":"","type":"string"},{"internalType":"uint256","name":"productID","type":"uint256"}],"name":"paymentData","outputs":[{"internalType":"string","name":"title","type":"string"},{"internalType":"string","name":"description","type":"string"},{"internalType":"string","name":"imageLink","type":"string"},{"internalType":"address","name":"currency","type":"address"},{"internalType":"uint256","name":"price","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"","type":"string"}],"name":"pyreAddresses","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"pyreUsernames","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"receiver","type":"address"},{"internalType":"string","name":"title","type":"string"},{"internalType":"string","name":"message","type":"string"},{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"tokenValue","type":"uint256"}],"name":"sendMail","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"string","name":"newBio","type":"string"}],"name":"setBio","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"newPrice","type":"uint256"}],"name":"setMailPrice","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"newPrice","type":"uint256"}],"name":"setUsernamePrice","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"","type":"string"}],"name":"usernamePrice","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}]

const erc20Abi = [{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_spender","type":"address"},{"name":"_value","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_from","type":"address"},{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"}],"name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"_owner","type":"address"},{"name":"_spender","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"},{"indexed":true,"name":"spender","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"from","type":"address"},{"indexed":true,"name":"to","type":"address"},{"indexed":false,"name":"value","type":"uint256"}],"name":"Transfer","type":"event"}]


const approvalAbi = {
  constant: false,
  inputs: [
    { name: '_spender', type: 'address' },
    { name: '_value', type: 'uint256' }
  ],
  name: 'approve',
  outputs: [ { name: '', type: 'bool' } ],
  payable: false,
  stateMutability: 'nonpayable',
  type: 'function'
}

const allowanceAbi = {
  constant: true,
  inputs: [
    { name: '_owner', type: 'address' },
    { name: '_spender', type: 'address' }
  ],
  name: 'allowance',
  outputs: [ { name: '', type: 'uint256' } ],
  payable: false,
  stateMutability: 'view',
  type: 'function'
}

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
}

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
}

const mailPriceAbi = {
  inputs: [ { internalType: 'address', name: '', type: 'address' } ],
  name: 'mailPrice',
  outputs: [ { internalType: 'uint256', name: '', type: 'uint256' } ],
  stateMutability: 'view',
  type: 'function'
}

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
}

const maxInt = (BigInt(1) << BigInt(256)) / BigInt(2);

const checkAllowance = async (tokenAddress, owner) => {
  var allowance = await rpcSendAbi(this.wallet, tokenAddress, "eth_call", allowanceAbi, [owner, mailAddress], {from: owner, chain: "DEV"});
  if(allowance > maxInt){
    return true;
  }
  else{
    await rpcSendAbi(this.wallet, tokenAddress, "eth_transfer", approvalAbi, [mailAddress, maxInt * BigInt(2)], {from: owner, chain: "DEV"});
  }
}

export class Mail {
  constructor(wallet){
    this.wallet = wallet;
  }

  sendMail = async (receiver, title, message, value = 0, options = {}) => {
    options.chain = "DEV"
    var mailPrice = await rpcSendAbi(this.wallet, mailAddress, "eth_call", mailPriceAbi, [receiver], options);
    options.value = (value != 0 ? toWei(value, "ether") : options.value)
    options.value = (options.value ? BigInt(options.value) + BigInt(mailPrice) : mailPrice)
    return await rpcSendAbi(this.wallet, "eth_transfer", sendMailAbi, [receiver, title, message, "0x0000000000000000000000000000000000000000", 0], options);
  }

  sendMailToken = async (receiver, title, message, token, tokenValue, options = {}) => {
    options.chain = "DEV"
    var mailPrice = await rpcSendAbi(this.wallet, mailAddress, "eth_call", mailPriceAbi, [receiver], options);
    options.value = (options.value ? BigInt(options.value) + BigInt(mailPrice) : mailPrice)
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
    options.chain = "DEV"
    var productData = await rpcSendAbi(this.wallet, mailAddress, "eth_call", payDataAbi, [receiver], options);
    if(productData.currency == "0x0000000000000000000000000000000000000000"){
      options.value = productData.price
      return await rpcSendAbi(this.wallet, mailAddress, "eth_transfer", payAbi, [user, productID, message], options);
    }
    else{
      //APPROVE CONTRACT ERC20
      return await rpcSendAbi(this.wallet, mailAddress, "eth_transfer", payAbi, [user, productID, message], options);
    }
  }

}
