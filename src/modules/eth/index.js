import { rpcSend, rpcSendAbi } from '../../rpc.js'
import * as Abi from './abi/index.js'
import { Accounts } from './accounts/index.js'

class Contract {
  constructor(abi, address, wallet) {
    this.abi = abi;
    this.address = address;
    this.methods = {};
    this.connectedWallet = wallet;
    this.estimateGas = {};
    this.initContract();
  }

  initContract() { //make private internal function
    var newMethods = this.abi.filter((e) => e.type == 'function')
    for(let x = 0; x < newMethods.length; x++){
      if(newMethods[x].stateMutability == "view"){
        this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args]);
      }
      else{
        this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args]);
      }
      this.estimateGas[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_estimateGas", newMethods[x], [...args]);
    }
  }
}


export class Eth {
  constructor(wallet){
    this.wallet = wallet;
    this.abi = Abi;
    this.accounts = new Accounts(this.wallet);
    this.Contract = (abi, address) => new Contract(abi, address, this.wallet);
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

  getGasPrice = () => {
   return rpcSend(this.wallet, "eth_gasPrice")
  }

  getFeeHistory = () => {
    return rpcSend(this.wallet, "eth_feeHistory")
  }

  getAccounts = () => {
    return rpcSend(this.wallet, "eth_accounts")
  }

  getBlockNumber = () => {
    return rpcSend(this.wallet, "eth_blockNumber")
  }

  getBalance = (address, tag) => {
    return rpcSend(this.wallet, "eth_getBalance", address)
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

  sign = (address, message) => {
    return rpcSend(this.wallet, "eth_sign", [address, message])
  }

  signTransaction = (transaction) => {
    return rpcSend(this.wallet, "eth_signTransaction", transaction)
  }

  call = (transaction, blockNumber) => {
    return rpcSend(this.wallet, "eth_call", transaction, blockNumber)
  }

  estimateGas = (transaction, blockNumber) => {
    return rpcSend(this.wallet, "eth_estimateGas", transaction, blockNumber)
  }

  getPastLogs = (filter) => {
    return rpcSend(this.wallet, "eth_getLogs", [filter])
  }

  getChainId = () => {
    return rpcSend(this.wallet, "eth_chainId")
  }

  getWork = () => {
    return rpcSend(this.wallet, "eth_getWork")
  }

  getProof = () => {
    return rpcSend(this.wallet, "eth_getProof")
  }

}
