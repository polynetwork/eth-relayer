# Eth Relayer

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
    "RestURL":"http://poly_ip:20336",         														// address of Poly
    "EntranceContractAddress":"0300000000000000000000000000000000000000", // CrossChainManagerContractAddress on Poly
    "WalletFile":"./wallet.dat", 																					// your poly wallet
    "WalletPwd":"pwd" 																										//password
  },
  "ETHConfig":{
    "RestURL":"http://etheruem:port", 																		// your ethereum node 
    "ECCMContractAddress":"ethereum_cross_chain_contract", 
    "ECCDContractAddress":"ethereum_cross_chain_data_contract",
    "PrivateKey":"your_eth_private_key",
    "Signer":"your_eth_address",
    "CapitalOwnersPath": "./capital-owners", 															// path to create and store your ethereum wallet
    "CapitalPassword": "pwd", 																					// password to protect your ethereum wallet
    "BlockConfig": 12 																										// blocks to confirm a ethereum tx
  },
  "BoltDbPath": "./db" 																										// DB path
}
```

Now, you can start relayer as follow: 

```shell
./eth_relayer --cliconfig=./config.json 
```

It will generate logs under `./Log` and check relayer status by view log file.