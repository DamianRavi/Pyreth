import { uuidV4 } from "../utils/index.js"
import { toUint8Array, toHex, asciiToHex, uint8ArrayToHexString } from "../../converter.js"


class Dot{
  constructor(){

  }
  stake = async () => {
    rpcSendAbi(provider, address, "dot_call", abi, args, instance)
  }

  call = (provider, options) => {
    rpcSendAbi(provider, address, "dot_call", abi, args, instance)
  }

  transfer = (provider, options) => {
    rpcSendAbi(provider, address, "dot_transfernh", abi, args, instance)
  }

  balance = (provider, options) => {
    rpcSendAbi(provider, address, "dot_balance", abi, args, instance)
  }

  XCM = (provider, options) => {
    rpcSendAbi(provider, address, "dot_xcm", abi, args, instance)
  }
}
