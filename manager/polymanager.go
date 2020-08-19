/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
package manager

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/polynetwork/eth-contracts/go_abi/eccd_abi"
	"github.com/polynetwork/eth-contracts/go_abi/eccm_abi"
	"github.com/polynetwork/eth_relayer/config"
	"github.com/polynetwork/eth_relayer/db"
	"github.com/polynetwork/eth_relayer/log"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/common/password"
	"github.com/polynetwork/poly/consensus/vbft/config"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"math/rand"
	"strconv"
	"strings"

	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/polynetwork/eth_relayer/tools"

	polytypes "github.com/polynetwork/poly/core/types"
)

const (
	ChanLen = 64
)

type PolyManager struct {
	config        *config.ServiceConfig
	polySdk       *sdk.PolySdk
	currentHeight uint32
	contractAbi   *abi.ABI
	exitChan      chan int
	db            *db.BoltDB
	ethClient     *ethclient.Client
	senders       []*EthSender
}

func NewPolyManager(servCfg *config.ServiceConfig, startblockHeight uint32, polySdk *sdk.PolySdk, ethereumsdk *ethclient.Client, boltDB *db.BoltDB) (*PolyManager, error) {
	contractabi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return nil, err
	}
	ks := tools.NewEthKeyStore(servCfg.ETHConfig)
	accArr := ks.GetAccounts()

	if len(servCfg.ETHConfig.KeyStorePwdSet) == 0 {
		fmt.Println("please input the passwords for ethereum keystore: ")
		for _, v := range accArr {
			fmt.Printf("For address %s. ", v.Address.String())
			raw, err := password.GetPassword()
			if err != nil {
				log.Fatalf("failed to input password: %v", err)
				panic(err)
			}
			servCfg.ETHConfig.KeyStorePwdSet[v.Address.String()] = string(raw)
		}
	}

	senders := make([]*EthSender, len(accArr))
	for i, v := range senders {
		v = &EthSender{}
		v.acc = accArr[i]
		pwd, ok := servCfg.ETHConfig.KeyStorePwdSet[strings.ToLower(v.acc.Address.String())]
		if !ok {
			fmt.Printf("Password for address %s is not found in configuration, please input ", v.acc.Address.String())
			raw, err := password.GetPassword()
			if err != nil {
				log.Fatalf("failed to input password: %v", err)
				panic(err)
			}
			pwd = string(raw)
		}
		v.ethClient = ethereumsdk
		v.keyStore = ks
		v.pwd = pwd
		v.config = servCfg
		v.polySdk = polySdk
		v.contractAbi = &contractabi
		v.nonceManager = tools.NewNonceManager(ethereumsdk)
		v.cmap = make(map[string]chan *EthTxInfo)

		senders[i] = v
	}
	return &PolyManager{
		exitChan:      make(chan int),
		config:        servCfg,
		polySdk:       polySdk,
		currentHeight: startblockHeight,
		contractAbi:   &contractabi,
		db:            boltDB,
		ethClient:     ethereumsdk,
		senders:       senders,
	}, nil
}

func (this *PolyManager) findLatestHeight() uint32 {
	address := ethcommon.HexToAddress(this.config.ETHConfig.ECCDContractAddress)
	instance, err := eccd_abi.NewEthCrossChainData(address, this.ethClient)
	if err != nil {
		log.Errorf("findLatestHeight - new eth cross chain failed: %s", err.Error())
		return 0
	}
	height, err := instance.GetCurEpochStartHeight(nil)
	if err != nil {
		log.Errorf("findLatestHeight - GetLatestHeight failed: %s", err.Error())
		return 0
	}
	return uint32(height)
}

func (this *PolyManager) init() bool {
	if this.currentHeight > 0 {
		return true
	}
	this.currentHeight = this.db.GetPolyHeight()
	latestHeight := this.findLatestHeight()
	if latestHeight > this.currentHeight {
		this.currentHeight = latestHeight
		log.Infof("init - latest height from ECCM: %d", this.currentHeight)
		return true
	}
	log.Infof("init - latest height from DB: %d", this.currentHeight)
	//block, err := this.polySdk.GetBlockByHeight(uint32(this.currentHeight))
	//if err != nil {
	//	log.Errorf("init - GetNodeHeader on height :%d failed", 0)
	//	return false
	//}
	//if !this.commitGenesisHeader(block.Header) {
	//	return false
	//}
	return true
}

func (this *PolyManager) MonitorChain() {
	ret := this.init()
	if ret == false {
		log.Errorf("MonitorChain - init failed\n")
	}
	monitorTicker := time.NewTicker(config.ONT_MONITOR_INTERVAL)
	var blockHandleResult bool
	for {
		select {
		case <-monitorTicker.C:
			latestheight, err := this.polySdk.GetCurrentBlockHeight()
			if err != nil {
				log.Errorf("MonitorChain - get poly chain block height error: %s", err)
				continue
			}
			log.Infof("MonitorChain - poly chain current height: %d", latestheight)
			latestheight--
			if latestheight-this.currentHeight < config.ONT_USEFUL_BLOCK_NUM {
				continue
			}
			blockHandleResult = true
			for this.currentHeight <= latestheight-config.ONT_USEFUL_BLOCK_NUM {
				blockHandleResult = this.handleDepositEvents(this.currentHeight)
				if blockHandleResult == false {
					break
				}
				this.currentHeight++
			}
			if err = this.db.UpdatePolyHeight(this.currentHeight - 1); err != nil {
				log.Errorf("MonitorChain - failed to save height of poly: %v", err)
			}
		case <-this.exitChan:
			return
		}
	}
}

func (this *PolyManager) handleDepositEvents(height uint32) bool {
	lastEpoch := this.findLatestHeight()
	hdr, err := this.polySdk.GetHeaderByHeight(height + 1)
	if err != nil {
		log.Errorf("handleBlockHeader - GetNodeHeader on height :%d failed", height)
		return false
	}
	isCurr := lastEpoch < height+1
	isEpoch := hdr.NextBookkeeper != common.ADDRESS_EMPTY
	var (
		anchor *polytypes.Header
		hp     string
	)
	if !isCurr {
		anchor, _ = this.polySdk.GetHeaderByHeight(lastEpoch + 1)
		proof, _ := this.polySdk.GetMerkleProof(height+1, lastEpoch+1)
		hp = proof.AuditPath
	} else if isEpoch {
		anchor, _ = this.polySdk.GetHeaderByHeight(height + 2)
		proof, _ := this.polySdk.GetMerkleProof(height+1, height+2)
		hp = proof.AuditPath
	}

	cnt := 0
	events, err := this.polySdk.GetSmartContractEventByBlock(height)
	for err != nil {
		log.Errorf("handleDepositEvents - get block event at height:%d error: %s", height, err.Error())
		return false
	}
	for _, event := range events {
		for _, notify := range event.Notify {
			if notify.ContractAddress == this.config.PolyConfig.EntranceContractAddress {
				states := notify.States.([]interface{})
				method, _ := states[0].(string)
				if method != "makeProof" {
					continue
				}
				tchainid := uint32(states[2].(float64))
				if tchainid != 2 {
					continue
				}
				cnt++
				sender := this.selectSender()
				log.Infof("sender %s is handling poly tx %s", sender.acc.Address.String(), event.TxHash)
				return sender.commitDepositEventsWithHeader(hdr, []byte(states[5].(string)), hp, anchor)
			}
		}
	}
	if cnt == 0 && isEpoch && isCurr {
		sender := this.selectSender()
		return sender.commitHeader(hdr)
	}

	return true
}

func (this *PolyManager) selectSender() *EthSender {
	sum := big.NewInt(0)
	balArr := make([]*big.Int, len(this.senders))
	for i, v := range this.senders {
	RETRY:
		bal, err := v.Balance()
		if err != nil {
			log.Errorf("failed to get balance for %s: %v", v.acc.Address.String(), err)
			time.Sleep(time.Second)
			goto RETRY
		}
		sum.Add(sum, bal)
		balArr[i] = big.NewInt(sum.Int64())
	}
	sum.Rand(rand.New(rand.NewSource(time.Now().Unix())), sum)
	for i, v := range balArr {
		res := v.Cmp(sum)
		if res == 1 || res == 0 {
			return this.senders[i]
		}
	}
	return this.senders[0]
}

func (this *PolyManager) Stop() {
	this.exitChan <- 1
	close(this.exitChan)
	log.Infof("multi chain manager exit.")
}

type EthSender struct {
	pwd          string
	acc          accounts.Account
	keyStore     *tools.EthKeyStore
	cmap         map[string]chan *EthTxInfo
	nonceManager *tools.NonceManager
	ethClient    *ethclient.Client
	polySdk      *sdk.PolySdk
	config       *config.ServiceConfig
	contractAbi  *abi.ABI
}

func (this *EthSender) sendTxToEth(info *EthTxInfo) bool {
	nonce := this.nonceManager.GetAddressNonce(this.acc.Address)
	tx := types.NewTransaction(nonce, info.contractAddr, big.NewInt(0), info.gasLimit, info.gasPrice, info.txData)
	signedtx, err := this.keyStore.SignTransaction(tx, this.pwd)
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - sign raw tx error and return nonce %d: %v", nonce, err)
		this.nonceManager.ReturnNonce(this.acc.Address, nonce)
		return false
	}
	err = this.ethClient.SendTransaction(context.Background(), signedtx)
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - send transaction error and return nonce %d: %v\n", nonce, err)
		this.nonceManager.ReturnNonce(this.acc.Address, nonce)
		return false
	}

	this.waitTransactionConfirm(signedtx.Hash())
	return true
}

func (this *EthSender) commitDepositEventsWithHeader(header *polytypes.Header, key []byte, headerProof string, anchorHeader *polytypes.Header) bool {
	var (
		sigs       []byte
		auditpath  []byte
		headerData []byte
	)
	if anchorHeader != nil && headerProof != "" {
		for _, sig := range anchorHeader.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	} else {
		for _, sig := range header.SigData {
			temp := make([]byte, len(sig))
			copy(temp, sig)
			newsig, _ := signature.ConvertToEthCompatible(temp)
			sigs = append(sigs, newsig...)
		}
	}
	proof, err := this.polySdk.GetCrossStatesProof(header.Height-1, string(key))
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - err: %v", err)
		return false
	}
	auditpath, _ = hex.DecodeString(proof.AuditPath)
	value, _, _, _ := tools.ParseAuditpath(auditpath)
	param := &common2.ToMerkleValue{}
	if err := param.Deserialization(common.NewZeroCopySource(value)); err != nil {
		log.Errorf("commitDepositEventsWithHeader - failed to deserialize MakeTxParam: %v", err)
		return false
	}

	eccdAddr := ethcommon.HexToAddress(this.config.ETHConfig.ECCDContractAddress)
	eccd, err := eccd_abi.NewEthCrossChainData(eccdAddr, this.ethClient)
	if err != nil {
		panic(fmt.Errorf("failed to new eccm: %v", err))
	}
	fromTx := [32]byte{}
	copy(fromTx[:], param.TxHash[:32])
	res, _ := eccd.CheckIfFromChainTxExist(nil, param.FromChainID, fromTx)
	if res {
		log.Debugf("already relayed to eth: ( from_chain_id: %d, from_txhash: %x,  param.Txhash: %x)",
			param.FromChainID, param.TxHash, param.MakeTxParam.TxHash)
		return true
	}
	log.Infof("poly proof with header, height: %d, key: %s, proof: %s", header.Height-1, string(key), proof.AuditPath)

	rawProof, _ := hex.DecodeString(headerProof)
	var rawAnchor []byte
	if anchorHeader != nil {
		rawAnchor = anchorHeader.ToArray()
	}
	headerData = header.GetMessage()
	txData, err := this.contractAbi.Pack("verifyHeaderAndExecuteTx", auditpath, headerData, rawProof, rawAnchor, sigs)
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - err:" + err.Error())
		return false
	}

	gasPrice, err := this.ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - get suggest sas price failed error: %s", err.Error())
		return false
	}
	contractaddr := ethcommon.HexToAddress(this.config.ETHConfig.ECCMContractAddress)
	callMsg := ethereum.CallMsg{
		From: this.acc.Address, To: &contractaddr, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(0), Data: txData,
	}
	gasLimit, err := this.ethClient.EstimateGas(context.Background(), callMsg)
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - estimate gas limit error: %s", err.Error())
		return false
	}

	k := this.getRouter()
	c, ok := this.cmap[k]
	if !ok {
		c = make(chan *EthTxInfo, ChanLen)
		this.cmap[k] = c
		go func() {
			for v := range c {
				if !this.sendTxToEth(v) {
					log.Errorf("failed to send tx to ethereum: txData: %s", hex.EncodeToString(v.txData))
				}
			}
		}()
	}
	//TODO: could be blocked
	c <- &EthTxInfo{
		txData:       txData,
		contractAddr: contractaddr,
		gasPrice:     gasPrice,
		gasLimit:     gasLimit,
	}
	return true
}

func (this *EthSender) commitHeader(header *polytypes.Header) bool {
	headerdata := header.GetMessage()
	var (
		txData      []byte
		txErr       error
		bookkeepers []keypair.PublicKey
		sigs        []byte
	)
	gasPrice, err := this.ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Errorf("commitHeader - get suggest sas price failed error: %s", err.Error())
		return false
	}
	for _, sig := range header.SigData {
		temp := make([]byte, len(sig))
		copy(temp, sig)
		newsig, _ := signature.ConvertToEthCompatible(temp)
		sigs = append(sigs, newsig...)
	}

	blkInfo := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(header.ConsensusPayload, blkInfo); err != nil {
		log.Errorf("commitHeader - unmarshal blockInfo error: %s", err)
		return false
	}

	for _, peer := range blkInfo.NewChainConfig.Peers {
		keystr, _ := hex.DecodeString(peer.ID)
		key, _ := keypair.DeserializePublicKey(keystr)
		bookkeepers = append(bookkeepers, key)
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)
	publickeys := make([]byte, 0)
	for _, key := range bookkeepers {
		publickeys = append(publickeys, tools.GetNoCompresskey(key)...)
	}
	txData, txErr = this.contractAbi.Pack("changeBookKeeper", headerdata, publickeys, sigs)
	if txErr != nil {
		log.Errorf("commitHeader - err:" + err.Error())
		return false
	}

	contractaddr := ethcommon.HexToAddress(this.config.ETHConfig.ECCMContractAddress)
	callMsg := ethereum.CallMsg{
		From: this.acc.Address, To: &contractaddr, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(0), Data: txData,
	}

	gasLimit, err := this.ethClient.EstimateGas(context.Background(), callMsg)
	if err != nil {
		log.Errorf("commitHeader - estimate gas limit error: %s", err.Error())
		return false
	}

	nonce := this.nonceManager.GetAddressNonce(this.acc.Address)
	tx := types.NewTransaction(nonce, contractaddr, big.NewInt(0), gasLimit, gasPrice, txData)
	signedtx, err := this.keyStore.SignTransaction(tx, this.pwd)
	if err != nil {
		log.Errorf("commitHeader - sign raw tx error: %s", err.Error())
		return false
	}

	err = this.ethClient.SendTransaction(context.Background(), signedtx)
	if err != nil {
		log.Errorf("commitHeader - send transaction error:%s\n", err.Error())
		return false
	}

	this.waitTransactionConfirm(signedtx.Hash())
	return true
}

func (this *EthSender) getRouter() string {
	return strconv.FormatInt(rand.Int63n(this.config.RoutineNum), 10)
}

func (this *EthSender) Balance() (*big.Int, error) {
	balance, err := this.ethClient.BalanceAt(context.Background(), this.acc.Address, nil)
	if err != nil {
		return nil, err
	}
	return balance, nil
}

func (this *EthSender) waitTransactionConfirm(hash ethcommon.Hash) {
	errNum := 0
	for errNum < 100 {
		time.Sleep(time.Second * 1)
		_, ispending, err := this.ethClient.TransactionByHash(context.Background(), hash)
		log.Infof("transaction %s is pending: %d\n", hash.String(), ispending)
		if err != nil {
			errNum++
			continue
		}
		if ispending == true {
			continue
		} else {
			break
		}
	}
}

type EthTxInfo struct {
	txData       []byte
	gasLimit     uint64
	gasPrice     *big.Int
	contractAddr ethcommon.Address
}
