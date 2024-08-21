import { rpcSend, rpcSign, rpcSendAbi } from '../../rpc.js'
import * as Abi from './abi/index.js'
import { Accounts } from './accounts/index.js'
import { hexToNumberString } from '../../converter.js'

export class Eth {
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
      var newMethods = this.abi.filter((e) => e.type == 'function')
      for(let x = 0; x < newMethods.length; x++){
        if(newMethods[x].stateMutability == "view"){
          this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args]);
          this.methods[newMethods[x].name] = (...args) => {return({
            call: async (options = {}) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args, options])
          })}
        }
        else{
          this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args]);
          this.methods[newMethods[x].name] = (...args) => {return({
            send: async (options = {}) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args, options])
          })}
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
    console.log("Mot Implemented Yet")
  }

  extend = () => {
    console.log("Mot Implemented Yet")
  }

  defaultAccount = () => {
    console.log("Mot Implemented Yet")
  }

  defaultHardfork = () => {
    console.log("Mot Implemented Yet")
  }

  defaultChain = () => {
    console.log("Mot Implemented Yet")
  }

  defaultCommon = () => {
    console.log("Mot Implemented Yet")
  }

  transactionBlockTimeout = () => {
    console.log("Mot Implemented Yet")
  }

  blockHeaderTimeout = () => {
    console.log("Mot Implemented Yet")
  }

  transactionConfirmationBlocks = () => {
    console.log("Mot Implemented Yet")
  }

  transactionPollingTimeout = () => {
    console.log("Mot Implemented Yet")
  }


  transactionPollingInterval = () => {
    console.log("Mot Implemented Yet")
  }

  handleRevert = () => {
    console.log("Mot Implemented Yet")
  }

  maxListenersWarningThreshold = () => {
    console.log("Mot Implemented Yet")
  }

  getProtocolVersion = () => {
    return rpcSend(this.wallet, "eth_protocolVersion")
  }

  isSyncing = () => {
    return rpcSend(this.wallet, "eth_syncing")
  }

  getCoinbase = () => {
    return rpcSend(this.wallet, "eth_coinbase")
  }

  isMining = () => {
    return rpcSend(this.wallet, "eth_mining")
  }

  getHashrate = () => {
    return rpcSend(this.wallet, "eth_hashrate")
  }

  getGasPrice = async () => {
   var result = await rpcSend(this.wallet, "eth_gasPrice")
   if(result.result){
     return(hexToNumberString(result.result))
   }
   throw Error("Invalid Response")
  }

  getFeeHistory = () => {
    return rpcSend(this.wallet, "eth_feeHistory")
  }

  getAccounts = () => {
    return rpcSend(this.wallet, "eth_accounts")
  }

  getBlockNumber = async () => {
    var result = await rpcSend(this.wallet, "eth_blockNumber")
    if(result.result){
      return(hexToNumberString(result.result))
    }
    throw Error("Invalid Response")
  }

  getBalance = async (address, tag) => {
    var result = await rpcSend(this.wallet, "eth_getBalance", address)
    if(result.result){
      return(hexToNumberString(result.result))
    }
    throw Error("Invalid Response")
  }

  getStorageAt = (address, storageSlot, blockNumber = "latest") => {
    return rpcSend(this.wallet, "eth_getStorageAt", [address, storageSlot], blockNumber)
  }

  getCode = (address, blockNumber) => {
    return rpcSend(this.wallet, "eth_getCode", [address], blockNumber)
  }

  getBlock = (block) => {
    if(isNaN(Number(block))){
      return rpcSend(this.wallet, "eth_getBlockByHash", [block])
    }
    else{
      return rpcSend(this.wallet, "eth_getBlockByNumber", [block])
    }
  }

  getBlockTransactionCount = (block) => {
    if(isNaN(Number(block))){
      return rpcSend(this.wallet, "eth_getBlockTransactionCountByHash", [block])
    }
    else{
      return rpcSend(this.wallet, "eth_getBlockTransactionCountByNumber", [block])
    }
  }

  getBlockUncleCount = (block) => {
    if(isNaN(Number(block))){
      return rpcSend(this.wallet, "eth_getUncleCountByBlockHash", [block])
    }
    else{
      return rpcSend(this.wallet, "eth_getUncleCountByBlockNumber", [block])
    }
  }

  getUncle = (block, index) => {
    if(isNaN(Number(block))){
      return rpcSend(this.wallet, "eth_getUncleByBlockHashAndIndex", [block])
    }
    else{
      return rpcSend(this.wallet, "eth_getUncleByBlockNumberAndIndex", [block])
    }
  }

  getTransaction = (hash) => {
    return rpcSend(this.wallet, "eth_getTransactionByHash", hash, null)
  }

  getPendingTransactions = () => {
    return rpcSend(this.wallet, "eth_getPendingTransactions")
  }

  getTransactionFromBlock = (block, index) => {
    if(isNaN(Number(block))){
      return rpcSend(this.wallet, "eth_getTransactionByBlockHashAndIndex", [block, index])
    }
    else{
      return rpcSend(this.wallet, "eth_getTransactionByBlockNumberAndIndex", [block, index])
    }
  }

  getTransactionReceipt = (transactionHash) => {
    return rpcSend(this.wallet, "eth_getTransactionReceipt", transactionHash)
  }

  getTransactionCount = (address, blockNumber) => {
    return rpcSend(this.wallet, "eth_getTransactionCount", address, blockNumber)
  }

  sendTransaction = (transaction) => {
    return rpcSend(this.wallet, "eth_sendTransaction", transaction)
  }

  sendSignedTransaction = (transaction) => {
    return rpcSend(this.wallet, "eth_sendRawTransaction", transaction)
  }

  sign = (message, address) => {
    return rpcSign(this.wallet, "eth_sign", [address, message])
  }

  signTransaction = (transaction) => {
    return rpcSend(this.wallet, "eth_signTransaction", transaction)
  }

  call = (transaction, blockNumber) => {
    return rpcSend(this.wallet, "eth_call", transaction, blockNumber)
  }

  estimateGas = async (transaction, blockNumber) => {
    var result = await rpcSend(this.wallet, "eth_estimateGas", transaction, blockNumber)
    if(result.result){
      return(hexToNumberString(result.result))
    }
    throw Error("Invalid Response")
  }

  getPastLogs = (filter) => {
    return rpcSend(this.wallet, "eth_getLogs", [filter])
  }

  getChainId = async () => {
    var result = await rpcSend(this.wallet, "eth_chainId")
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
