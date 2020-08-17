<h1 align=center> Eth Relayer </h1>

Eth Relayer is an important character of Poly cross-chain interactive protocol which is responsible for relaying cross-chain transaction from and to Ethereum.

## Build From Source

### Prerequisites

- [Golang](https://golang.org/doc/install) version 1.14 or later

### Build

```shell
git clone https://github.com/polynetwork/eth_relayer.git
cd eth_relayer
go build -o eth_relayer main.go
```

After building the source code successfully,  you should see the executable program `eth_relayer`. 

## Run Relayer

Before you can run the relayer you will need to create a wallet file of PolyNetwork. After creation, you need to register it as a Relayer to Poly net and get consensus nodes approving your registeration. And then you can send transaction to Poly net and start relaying.

Before running, you need feed the configuration file `config.json`.

```
{
  "MultiChainConfig":{
    "RestURL":"http://poly_ip:20336", // address of Poly
    "EntranceContractAddress":"0300000000000000000000000000000000000000", // CrossChainManagerContractAddress on Poly
    "WalletFile":"./wallet.dat", // your poly wallet
    "WalletPwd":"pwd" //password
  },
  "ETHConfig":{
    "RestURL":"http://etheruem:port", // your ethereum node 
    "ECCMContractAddress":"ethereum_cross_chain_contract", 
    "ECCDContractAddress":"ethereum_cross_chain_data_contract",
    "CapitalOwnersPath": "./capital-owners", // path to store your ethereum wallet
    "CapitalPassword": "pwd", // password to protect your ethereum wallet
    "BlockConfig": 12 // blocks to confirm a ethereum tx
  },
  "BoltDbPath": "./db" // DB path
}
```

After that, make sure you already have a ethereum wallet with ETH. The wallet file is like `UTC--2020-08-17T03-44-00.191825735Z--d12ecafcb772bd7c774a2db3c54ccacf91ca364d` and you can use [geth](https://github.com/ethereum/go-ethereum) to create one( `./geth accounts add` ). Put it under `CapitalOwnersPath`

Now, you can start relayer as follow: 

```shell
./eth_relayer --cliconfig=./config.json 
```

It will generate logs under `./Log` and check relayer status by view log file.

