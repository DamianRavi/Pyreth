
import { Eth } from './src/modules/eth/index.js'
import * as Dot from './src/modules/dot/index.js'
//import * as Personal from './modules/eth/personal'
import * as Utils from './src/modules/utils/index.js'
import { Mail } from './src/modules/mail/index.js'
import { encrypt, decrypt } from "./src/hashes/ecEncrypt.js"
import { rpcSendAbi, rpcSend } from './src/rpc.js'
import { createSS58, privateKeyToAccount, create } from "./src/encoders.js"

const onChange = (provider, options) => {

}

class Wallet{
  constructor(provider){
    this.provider = provider
    this.walletList = []
    this.add = (privateKey) => this.walletList.push(privateKeyToAccount(privateKey));
    this.clear = () => this.walletList = [];
    this.create = (count = 1) => {for(var x = 0; x < count; x++){this.walletList.push(create())}};
    this.decrypt = () => "WIP";
    this.encrypt = () => "WIP";
    this.get = () => "WIP";
    this.load = () => "WIP";
    this.remove = () => "WIP";
    this.save = () => "WIP";
    this.getStorage = () => "WIP";
  }

  setDefaultAccount(address){
    this.defaultAccount = address;
  }
}

class Provider{
  constructor(provider){
    this.provider = provider;
    this.url = provider;
    this.modules = {
      Eth: "Eth(provider)",
      Net: "Net(provider)",
      Personal: "Personal(provider)"
    }
    this.version = "1.0.0";
    this.getChainId()
    this.getDefaultGasPrice()
  }

  setProvider(newProvider) {
    this.provider = newProvider;
    this.url = provider;
    this.getChainId()
    this.getDefaultGasPrice()
  }

  getChainId(){
    var rawResponse = fetch(this.provider, {method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
      body: JSON.stringify({ id: Utils.randomHex(16), jsonrpc: "2.0", method: "eth_chainId" })
    }).then(res => res.json()).then((res) => {
      this.chainId = Number(res.result)
    })
  }

  getDefaultGasPrice(){
    var rawResponse = fetch(this.provider, {method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
      body: JSON.stringify({ id: Utils.randomHex(16), jsonrpc: "2.0", method: "eth_gasPrice" })
    }).then(res => res.json()).then((res) => {
      this.gasprice = Number(res.result)
    })
  }
}

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
    var newMethods = this.abi.filter((e) => e.type == 'function');
    for(let x = 0; x < newMethods.length; x++){
      if(newMethods[x].stateMutability == "view"){
        this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args]);
        this.methods[newMethods[x].name] = (...args) => {return({
          call: async (options = {}) => await rpcSendAbi(this.connectedWallet, this.address, "eth_call", newMethods[x], [...args, options])
        })}
      }
      else {
        this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args]);
        this.methods[newMethods[x].name] = (...args) => {return({
          send: async (options = {}) => await rpcSendAbi(this.connectedWallet, this.address, "eth_sendTransaction", newMethods[x], [...args, options])
        })}
      }
      this.estimateGas[newMethods[x].name] = async (...args) => await rpcSendAbi(this.connectedWallet, this.address, "eth_estimateGas", newMethods[x], [...args]);
    }
  }
}

class Pyre {
  constructor(provider) {
    this.provider = new Provider(typeof provider == "string" ? provider : "http://localhost:8484/pyre")
    this.testBN = BigInt(55)
    this.wallet = new Wallet(this.provider)
    this.utils = Utils;
    this.eth = new Eth(this.wallet)
    this.mail = new Mail(this.wallet);
    this.dot = Dot;
    this.onChange = onChange;
    this.pay = this.mail.pay;
    this.payToken = this.mail.payToken;
    //this.quote = quote;
    this.encrypt = encrypt;
    this.decrypt = decrypt;
    this.Contract = (abi, address) => new Contract(abi, address, this.wallet);
  }

  connect = async (provider, options) => {
    var rawResponse = await fetch("http://localhost:8484/pyre", {
      method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
      body: JSON.stringify({ id: Utils.randomHex(16), jsonrpc: "2.0", method: "eth_enable", chain: options })
    })
    var content = await rawResponse?.json();
    if(!content){
      return {err: "RPC Not Active"}
    }
    if(!content.error){
      this.wallet.setDefaultAccount(content.result)
    }
    return(content.result)
  }

  setProvider = (newProvider, options) => {
    this.provider.setProvider(newProvider);
    //this.eth.Contract.setProvider(newProvider);
  }

  request = async (data) => {
    if(data.method == "eth_requestAccounts"){
      return [await this.connect()];
    }
  }

  send = async (address, amount, chain = null) => { //opts can include chain variable
    var res = await rpcSend(this.wallet, "eth_sendTransaction", {to: address, from: this.wallet.defaultAccount, value: amount}, chain)
  }



/*
  swap = (from, amount, to, opts = {amountOutMin: 0, amountInMax: null, deadline: Math.floor(new Date().getTime() + 60000 / 1000) }) => {
    var swapContract = Contract(swapAbi, swapAddress);
    var res;
    if(amountInMin){
      res = swapContract.swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline)
    }
    else{
      res = swapContract.swapTokensForExactTokens(amountOut, amountInMax, path, to, deadline)
    }
    return res;
  }*/

  quote = (provider, options) => {
    //call quote function from Uniswap
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

}

export default Pyre
