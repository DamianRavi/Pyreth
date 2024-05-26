
export const chainList = [
  {
    name: 'Moonbase Alpha', id: 1287, decimals: 18, symbol: 'DEV', chainType: "EVM",
    rpc: { http: ['https://rpc.api.moonbase.moonbeam.network'], webSocket: ['wss://wss.api.moonbase.moonbeam.network'] },
    blockExplorer: { name: 'Moonscan', url: 'https://moonbase.moonscan.io', apiUrl: 'https://moonbase.moonscan.io/api' },
    contracts: {
      multicall3: { address: '0xcA11bde05977b3631167028862bE2a173976CA11' },
      swap: { address: '0xcA11bde05977b3631167028862bE2a173976CA11' },
      bridge: { address: '0xcA11bde05977b3631167028862bE2a173976CA11' },
    },
    testnet: true
  },
  {
    name: 'Polygon Mumbai', id: 80_001, symbol: 'MATIC', decimals: 18,
    rpcUrls: { http: ['https://rpc.ankr.com/polygon_mumbai'] },
    blockExplorers: { name: 'PolygonScan', url: 'https://mumbai.polygonscan.com', apiUrl: 'https://api-testnet.polygonscan.com/api' },
    contracts: {
      multicall3: { address: '0xca11bde05977b3631167028862be2a173976ca11' },
      swap: { address: '0xcA11bde05977b3631167028862bE2a173976CA11' },
      bridge: { address: '0xcA11bde05977b3631167028862bE2a173976CA11' },
    },
    testnet: true,
  },
  {
    name: 'Astar', id: 80_001, symbol: 'AST', decimals: 18,
    rpcUrls: { http: ['https://rpc.ankr.com/polygon_mumbai'] },
    blockExplorers: { name: 'PolygonScan', url: 'https://mumbai.polygonscan.com', apiUrl: 'https://api-testnet.polygonscan.com/api' },
    contracts: {
      multicall3: { address: '0xca11bde05977b3631167028862be2a173976ca11' },
      swap: { address: '0xcA11bde05977b3631167028862bE2a173976CA11' },
      bridge: { address: '0xcA11bde05977b3631167028862bE2a173976CA11' },
    },
    testnet: true,
  },
  {
    name: 'Polkadot', id: 80_001, symbol: 'DOT', decimals: 18,
    rpcUrls: { http: ['https://rpc.ankr.com/polygon_mumbai'] },
    blockExplorers: { name: 'PolygonScan', url: 'https://mumbai.polygonscan.com', apiUrl: 'https://api-testnet.polygonscan.com/api' },
    contracts: {
      multicall3: { address: '0xca11bde05977b3631167028862be2a173976ca11' },
      swap: { address: '0xcA11bde05977b3631167028862bE2a173976CA11' },
      bridge: { address: '0xcA11bde05977b3631167028862bE2a173976CA11' },
    },
    testnet: true,
  },


]
