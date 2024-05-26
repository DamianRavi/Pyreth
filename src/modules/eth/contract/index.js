import { rpcSendAbi } from '../../../rpc.js'


export const createContractClass = (wallet) => {
  var contractInstance = class Contract {
    constructor(abi, address) {
      this.abi = abi;
      this.address = address;
      this.methods = {};
      this.wallet = wallet;
      this.estimateGas = {};
      this.provider = this.wallet.provider;
      this.initContract();
    }

    //get provider(){ this.wallet.provider }

    initContract() { //make private internal function
      var newMethods = this.abi.filter((e) => e.type == 'function')
      for(let x = 0; x < newMethods.length; x++){
        if(newMethods[x].stateMutability == "view"){
          this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.wallet, this.address, "eth_call", newMethods[x], [...args]);
        }
        else{
          this[newMethods[x].name] = async (...args) => await rpcSendAbi(this.wallet, this.address, "eth_sendTransaction", newMethods[x], [...args]);
        }
        this.estimateGas[newMethods[x].name] = async (...args) => await rpcSendAbi(this.wallet, this.address, "eth_estimateGas", newMethods[x], [...args]);
      }
    }
  }

  return contractInstance;
}
