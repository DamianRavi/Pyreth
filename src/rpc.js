import {decodeParameter, decodeParameters, encodeFunctionCall, encodeParameter} from "./modules/eth/abi/index.js"
import { padLeft } from './string.js'
import { uuidV4 } from "./modules/utils/index.js"

export const rpcSend = async (wallet, method, args, blockNumber = "latest") => {
  var rawResponse = await fetch(wallet.provider.provider, { method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
    body: JSON.stringify({
      id: uuidV4(),
      jsonrpc: "2.0",
      method: method,
      params: [args, blockNumber]
    })
  })
  var content = await rawResponse?.json();
  return content ? content : {err: "RPC Not Active"}
}

export const rpcSign = async (wallet, method, args) => {
  var rawResponse = await fetch(wallet.provider.provider, { method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
    body: JSON.stringify({
      id: uuidV4(),
      jsonrpc: "2.0",
      method: method,
      params: args
    })
  })
  var content = await rawResponse?.json();
  return content ? content : {err: "RPC Not Active"}
}

export const rpcSendAbi = async (wallet, address, method, abi, args) => {
  /*
  from: DATA, 20 Bytes - The address the transaction is sent from.
  to: DATA, 20 Bytes - (optional when creating new contract) The address the transaction is directed to.
  gas: QUANTITY - (optional, default: 90000) Integer of the gas provided for the transaction execution. It will return unused gas.
  gasPrice: QUANTITY - (optional, default: To-Be-Determined) Integer of the gasPrice used for each paid gas.
  value: QUANTITY - (optional) Integer of the value sent with this transaction.
  input: DATA - The compiled code of a contract OR the hash of the invoked method signature and encoded parameters.
  nonce: QUANTITY - (optional) Integer of a nonce. This allows to overwrite your own pending transactions that use the same nonce.

  getNonce(){
    var rawResponse = fetch(this.provider, {method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
      body: JSON.stringify({ id: Utils.randomHex(16), jsonrpc: "2.0", method: "eth_nonce" })
    }).then(res => res.json()).then((res) => {
      this.nonce = Number(res.result)
    })
  }
  */

  var options = {};
  if(args && args.length > 0 && typeof args[args.length - 1] == "object"){
    options = args[args.length - 1]
    args.pop();
  }

  var privateKey;
  if(wallet.provider.provider != "http://localhost:8484/pyre" && method == "eth_sendTransaction"){ // !!! USE THE TX BUILDER HERE - YOU NEED MORE DATA FOR THIS KIND OF CALL
    if(wallet.walletList.length != 0){
      if(options.from && wallet.walletList.find((e) => e.address == options.from)){
        privateKey = wallet.walletList.find((e) => e.address == options.from).privateKey
        method = "eth_sendSignedTransaction"
      }
      else if(!options.from){
        privateKey = wallet.walletList[wallet.defaultWallet].privateKey
        method = "eth_sendSignedTransaction"
      }
      else{
        throw new Error("Invalid From Address")
      }
    }
    else{
      throw new Error("Invalid From Address")
    }
  }

  var data = encodeFunctionCall(abi, args)

  if(privateKey){
    data = sign(data, privateKey)
  }

  var rawResponse = await fetch(wallet.provider.provider, { method: "POST", headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
    body: JSON.stringify({
      id: uuidV4(),
      jsonrpc: "2.0",
      method: method,
      abiData: abi,
      inputs: args,
      params: [{to: address, from: wallet.defaultAccount, value: "0", ...options, input: data}, "latest"]
    })
  }).catch((err) => console.log(err))
  var content = await rawResponse?.json();

  if(!content){
    return {err: "RPC Not Active"}
  }
  if(content.error){
    return {err: content.error.message}
  }

  var params = abi.outputs.map((e) => { return({type: e.type, name: e.name}) })

  if(params.length > 1){
    Object.keys(params).map((keys, i) =>
      {
        if(params[i].type.includes("int")){
          try{
            content.result[keys] = padLeft(content.result[keys], 64)
          }
          catch(err){
            //console.log(err)
          }
        }
      }
    )
    content.result = decodeParameters(params, content.result);
  }
  else if(params.length == 1){
    if(params[0].type.includes("int")){
      content.result = padLeft(content.result, 64)
    }
    content.result = decodeParameter(params[0], content.result);
  }
  //MAKE SURE BIGNUMBER IS CAST TO STRING INSTEAD- BN IS ANNOYING FOR USERS
  return(content.result)
}
