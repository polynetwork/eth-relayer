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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ontio/ontology/smartcontract/service/native/cross_chain/cross_chain_manager"
	"github.com/polynetwork/eth-contracts/go_abi/eccm_abi"
	"github.com/polynetwork/eth_relayer/config"
	"github.com/polynetwork/eth_relayer/db"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"math/big"
	"strings"
	"time"

	"context"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/polynetwork/eth_relayer/log"
	"github.com/polynetwork/eth_relayer/tools"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/native/service/cross_chain_manager/eth"
	scom "github.com/polynetwork/poly/native/service/header_sync/common"
	autils "github.com/polynetwork/poly/native/service/utils"
)

type CrossTransfer struct {
	txIndex string
	txId    []byte
	value   []byte
	toChain uint32
	height  uint64
}

func (this *CrossTransfer) Serialization(sink *common.ZeroCopySink) {
	sink.WriteString(this.txIndex)
	sink.WriteVarBytes(this.txId)
	sink.WriteVarBytes(this.value)
	sink.WriteUint32(this.toChain)
	sink.WriteUint64(this.height)
}

func (this *CrossTransfer) Deserialization(source *common.ZeroCopySource) error {
	txIndex, eof := source.NextString()
	if eof {
		return fmt.Errorf("Waiting deserialize txIndex error")
	}
	txId, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("Waiting deserialize txId error")
	}
	value, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("Waiting deserialize value error")
	}
	toChain, eof := source.NextUint32()
	if eof {
		return fmt.Errorf("Waiting deserialize toChain error")
	}
	height, eof := source.NextUint64()
	if eof {
		return fmt.Errorf("Waiting deserialize height error")
	}
	this.txIndex = txIndex
	this.txId = txId
	this.value = value
	this.toChain = toChain
	this.height = height
	return nil
}

type EthereumManager struct {
	config         *config.ServiceConfig
	restClient     *tools.RestClient
	client         *ethclient.Client
	currentHeight  uint64
	forceHeight    uint64
	lockerContract *bind.BoundContract
	polySdk        *sdk.PolySdk
	polySigner     *sdk.Account
	exitChan       chan int
	header4sync    [][]byte
	crosstx4sync   []*CrossTransfer
	db             *db.BoltDB
}

func NewEthereumManager(servconfig *config.ServiceConfig, startheight uint64, startforceheight uint64, ontsdk *sdk.PolySdk, client *ethclient.Client, boltDB *db.BoltDB) (*EthereumManager, error) {
	var wallet *sdk.Wallet
	var err error
	if !common.FileExisted(servconfig.PolyConfig.WalletFile) {
		wallet, err = ontsdk.CreateWallet(servconfig.PolyConfig.WalletFile)
		if err != nil {
			return nil, err
		}
	} else {
		wallet, err = ontsdk.OpenWallet(servconfig.PolyConfig.WalletFile)
		if err != nil {
			log.Errorf("NewETHManager - wallet open error: %s", err.Error())
			return nil, err
		}
	}
	signer, err := wallet.GetDefaultAccount([]byte(servconfig.PolyConfig.WalletPwd))
	if err != nil || signer == nil {
		signer, err = wallet.NewDefaultSettingAccount([]byte(servconfig.PolyConfig.WalletPwd))
		if err != nil {
			log.Errorf("NewETHManager - wallet password error")
			return nil, err
		}

		err = wallet.Save()
		if err != nil {
			return nil, err
		}
	}
	log.Infof("NewETHManager - poly address: %s", signer.Address.ToBase58())

	mgr := &EthereumManager{
		config:        servconfig,
		exitChan:      make(chan int),
		currentHeight: startheight,
		forceHeight:   startforceheight,
		restClient:    tools.NewRestClient(),
		client:        client,
		polySdk:       ontsdk,
		polySigner:    signer,
		header4sync:   make([][]byte, 0),
		crosstx4sync:  make([]*CrossTransfer, 0),
		db:            boltDB,
	}
	err = mgr.init()
	if err != nil {
		return nil, err
	} else {
		return mgr, nil
	}
}

func (this *EthereumManager) MonitorChain() {
	fetchBlockTicker := time.NewTicker(time.Duration(this.config.ETHConfig.MonitorInterval) * time.Second)
	var blockHandleResult bool
	for {
		select {
		case <-fetchBlockTicker.C:
			height, err := tools.GetNodeHeight(this.config.ETHConfig.RestURL, this.restClient)
			if err != nil {
				log.Infof("MonitorChain - cannot get node height, err: %s", err)
				continue
			}
			if height-this.currentHeight <= config.ETH_USEFUL_BLOCK_NUM {
				continue
			}
			log.Infof("MonitorChain - eth height is %d", height)
			blockHandleResult = true
			for this.currentHeight < height-config.ETH_USEFUL_BLOCK_NUM {
				if this.currentHeight%10 == 0 {
					log.Infof("handle confirmed eth Block height: %d", this.currentHeight)
				}
				blockHandleResult = this.handleNewBlock(this.currentHeight + 1)
				if blockHandleResult == false {
					break
				}
				this.currentHeight++
				// try to commit header if more than 50 headers needed to be syned
				if len(this.header4sync) >= this.config.ETHConfig.HeadersPerBatch {
					if res := this.commitHeader(); res != 0 {
						blockHandleResult = false
						break
					}
				}
			}
			if blockHandleResult && len(this.header4sync) > 0 {
				this.commitHeader()
			}
		case <-this.exitChan:
			return
		}
	}
}
func (this *EthereumManager) init() error {
	// get latest height
	latestHeight := this.findLastestHeight()
	if latestHeight == 0 {
		return fmt.Errorf("init - the genesis block has not synced!")
	}
	if this.forceHeight > 0 && this.forceHeight < latestHeight {
		this.currentHeight = this.forceHeight
	} else {
		this.currentHeight = latestHeight
	}
	log.Infof("EthereumManager init - start height: %d", this.currentHeight)
	return nil
}

func (this *EthereumManager) findLastestHeight() uint64 {
	// try to get key
	var sideChainIdBytes [8]byte
	binary.LittleEndian.PutUint64(sideChainIdBytes[:], this.config.ETHConfig.SideChainId)
	contractAddress := autils.HeaderSyncContractAddress
	key := append([]byte(scom.CURRENT_HEADER_HEIGHT), sideChainIdBytes[:]...)
	// try to get storage
	result, err := this.polySdk.GetStorage(contractAddress.ToHexString(), key)
	if err != nil {
		return 0
	}
	if result == nil || len(result) == 0 {
		return 0
	} else {
		return binary.LittleEndian.Uint64(result)
	}
}

func (this *EthereumManager) handleNewBlock(height uint64) bool {
	ret := this.handleBlockHeader(height)
	if !ret {
		log.Errorf("handleNewBlock - handleBlockHeader on height :%d failed", height)
		return false
	}
	ret = this.fetchLockDepositEvents(height, this.client)
	if !ret {
		log.Errorf("handleNewBlock - fetchLockDepositEvents on height :%d failed", height)
	}
	return true
}

func (this *EthereumManager) handleBlockHeader(height uint64) bool {
	hdr, err := this.client.HeaderByNumber(context.Background(), big.NewInt(int64(height)))
	if err != nil {
		log.Errorf("handleBlockHeader - GetNodeHeader on height :%d failed", height)
		return false
	}
	rawHdr, _ := hdr.MarshalJSON()
	raw, _ := this.polySdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
		append(append([]byte(scom.MAIN_CHAIN), autils.GetUint64Bytes(this.config.ETHConfig.SideChainId)...), autils.GetUint64Bytes(height)...))
	if len(raw) == 0 || !bytes.Equal(raw, hdr.Hash().Bytes()) {
		this.header4sync = append(this.header4sync, rawHdr)
	}
	return true
}

func (this *EthereumManager) fetchLockDepositEvents(height uint64, client *ethclient.Client) bool {
	lockAddress := ethcommon.HexToAddress(this.config.ETHConfig.ECCMContractAddress)
	lockContract, err := eccm_abi.NewEthCrossChainManager(lockAddress, client)
	if err != nil {
		return false
	}
	opt := &bind.FilterOpts{
		Start:   height,
		End:     &height,
		Context: context.Background(),
	}
	events, err := lockContract.FilterCrossChainEvent(opt, nil)
	if err != nil {
		log.Errorf("fetchLockDepositEvents - FilterCrossChainEvent error :%s", err.Error())
		return false
	}
	if events == nil {
		log.Infof("fetchLockDepositEvents - no events found on FilterCrossChainEvent")
		return false
	}

	for events.Next() {
		evt := events.Event
		var isTarget bool
		if len(this.config.TargetContracts) > 0 {
			toContractStr := evt.ProxyOrAssetContract.String()
			for _, v := range this.config.TargetContracts {
				toChainIdArr, ok := v[toContractStr]
				if ok {
					if len(toChainIdArr["outbound"]) == 0 {
						isTarget = true
						break
					}
					for _, id := range toChainIdArr["outbound"] {
						if id == evt.ToChainId {
							isTarget = true
							break
						}
					}
					if isTarget {
						break
					}
				}
			}
			if !isTarget {
				continue
			}
		}
		param := &common2.MakeTxParam{}
		_ = param.Deserialization(common.NewZeroCopySource([]byte(evt.Rawdata)))
		raw, _ := this.polySdk.GetStorage(autils.CrossChainManagerContractAddress.ToHexString(),
			append(append([]byte(cross_chain_manager.DONE_TX), autils.GetUint64Bytes(this.config.ETHConfig.SideChainId)...), param.CrossChainID...))
		if len(raw) != 0 {
			log.Debugf("fetchLockDepositEvents - ccid %s (tx_hash: %s) already on poly",
				hex.EncodeToString(param.CrossChainID), evt.Raw.TxHash.Hex())
			continue
		}
		index := big.NewInt(0)
		index.SetBytes(evt.TxId)
		crossTx := &CrossTransfer{
			txIndex: tools.EncodeBigInt(index),
			txId:    evt.Raw.TxHash.Bytes(),
			toChain: uint32(evt.ToChainId),
			value:   []byte(evt.Rawdata),
			height:  height,
		}
		sink := common.NewZeroCopySink(nil)
		crossTx.Serialization(sink)
		err = this.db.PutRetry(sink.Bytes())
		if err != nil {
			log.Errorf("fetchLockDepositEvents - this.db.PutRetry error: %s", err)
		}
		log.Infof("fetchLockDepositEvent -  height: %d", height)
	}
	return true
}

func (this *EthereumManager) commitHeader() int {
	tx, err := this.polySdk.Native.Hs.SyncBlockHeader(
		this.config.ETHConfig.SideChainId,
		this.polySigner.Address,
		this.header4sync,
		this.polySigner,
	)
	if err != nil {
		errDesc := err.Error()
		if strings.Contains(errDesc, "get the parent block failed") || strings.Contains(errDesc, "missing required field") {
			log.Warnf("commitHeader - send transaction to poly chain err: %s", errDesc)
			this.rollBackToCommAncestor()
			return 0
		} else {
			log.Errorf("commitHeader - send transaction to poly chain err: %s", errDesc)
			return 1
		}
	}
	tick := time.NewTicker(100 * time.Millisecond)
	var h uint32
	for range tick.C {
		h, _ = this.polySdk.GetBlockHeightByTxHash(tx.ToHexString())
		curr, _ := this.polySdk.GetCurrentBlockHeight()
		if h > 0 && curr > h {
			break
		}
	}
	log.Infof("commitHeader - send transaction %s to poly chain and confirmed on height %d", tx.ToHexString(), h)
	this.header4sync = make([][]byte, 0)
	return 0
}

func (this *EthereumManager) rollBackToCommAncestor() {
	for ; ; this.currentHeight-- {
		raw, err := this.polySdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
			append(append([]byte(scom.MAIN_CHAIN), autils.GetUint64Bytes(this.config.ETHConfig.SideChainId)...), autils.GetUint64Bytes(this.currentHeight)...))
		if len(raw) == 0 || err != nil {
			continue
		}
		hdr, err := this.client.HeaderByNumber(context.Background(), big.NewInt(int64(this.currentHeight)))
		if err != nil {
			log.Errorf("rollBackToCommAncestor - failed to get header by number, so we wait for one second to retry: %v", err)
			time.Sleep(time.Second)
			this.currentHeight++
		}
		if bytes.Equal(hdr.Hash().Bytes(), raw) {
			log.Infof("rollBackToCommAncestor - find the common ancestor: %s(number: %d)", hdr.Hash().String(), this.currentHeight)
			break
		}
	}
	this.header4sync = make([][]byte, 0)
}

func (this *EthereumManager) MonitorDeposit() {
	monitorTicker := time.NewTicker(time.Duration(this.config.ETHConfig.MonitorInterval) * time.Second)
	for {
		select {
		case <-monitorTicker.C:
			height, err := tools.GetNodeHeight(this.config.ETHConfig.RestURL, this.restClient)
			if err != nil {
				log.Infof("MonitorDeposit - cannot get eth node height, err: %s", err)
				continue
			}
			snycheight := this.findLastestHeight()
			log.Log.Info("MonitorDeposit from eth - snyced eth height", snycheight, "eth height", height, "diff", height-snycheight)
			this.handleLockDepositEvents(snycheight)
		case <-this.exitChan:
			return
		}
	}
}
func (this *EthereumManager) handleLockDepositEvents(refHeight uint64) error {
	retryList, err := this.db.GetAllRetry()
	if err != nil {
		return fmt.Errorf("handleLockDepositEvents - this.db.GetAllRetry error: %s", err)
	}
	for _, v := range retryList {
		time.Sleep(time.Second * 1)
		crosstx := new(CrossTransfer)
		err := crosstx.Deserialization(common.NewZeroCopySource(v))
		if err != nil {
			log.Errorf("handleLockDepositEvents - retry.Deserialization error: %s", err)
			continue
		}
		//1. decode events
		key := crosstx.txIndex
		keyBytes, err := eth.MappingKeyAt(key, "01")
		if err != nil {
			log.Errorf("handleLockDepositEvents - MappingKeyAt error:%s\n", err.Error())
			continue
		}
		if refHeight <= crosstx.height+this.config.ETHConfig.BlockConfig {
			continue
		}
		height := int64(refHeight - this.config.ETHConfig.BlockConfig)
		heightHex := hexutil.EncodeBig(big.NewInt(height))
		proofKey := hexutil.Encode(keyBytes)
		//2. get proof
		proof, err := tools.GetProof(this.config.ETHConfig.RestURL, this.config.ETHConfig.ECCDContractAddress, proofKey, heightHex, this.restClient)
		if err != nil {
			log.Errorf("handleLockDepositEvents - error :%s\n", err.Error())
			continue
		}
		//3. commit proof to poly
		txHash, err := this.commitProof(uint32(height), proof, crosstx.value, crosstx.txId)
		if err != nil {
			if strings.Contains(err.Error(), "chooseUtxos, current utxo is not enough") {
				log.Infof("handleLockDepositEvents - invokeNativeContract error: %s", err)
				continue
			} else {
				if err := this.db.DeleteRetry(v); err != nil {
					log.Errorf("handleLockDepositEvents - this.db.DeleteRetry error: %s", err)
				}
				if strings.Contains(err.Error(), "tx already done") {
					log.Debugf("handleLockDepositEvents - eth_tx %s already on poly", ethcommon.BytesToHash(crosstx.txId).String())
				} else {
					log.Errorf("handleLockDepositEvents - invokeNativeContract error for eth_tx %s: %s", ethcommon.BytesToHash(crosstx.txId).String(), err)
				}
				continue
			}
		}
		//4. put to check db for checking
		err = this.db.PutCheck(txHash, v)
		if err != nil {
			log.Errorf("handleLockDepositEvents - this.db.PutCheck error: %s", err)
		}
		err = this.db.DeleteRetry(v)
		if err != nil {
			log.Errorf("handleLockDepositEvents - this.db.PutCheck error: %s", err)
		}
		log.Infof("handleLockDepositEvents - syncProofToAlia txHash is %s", txHash)
	}
	return nil
}

func (this *EthereumManager) commitProof(height uint32, proof []byte, value []byte, txhash []byte) (string, error) {
	log.Debugf("commit proof, height: %d, proof: %s, value: %s, txhash: %s", height, string(proof), hex.EncodeToString(value), hex.EncodeToString(txhash))
	tx, err := this.polySdk.Native.Ccm.ImportOuterTransfer(
		this.config.ETHConfig.SideChainId,
		value,
		height,
		proof,
		ethcommon.Hex2Bytes(this.polySigner.Address.ToHexString()),
		[]byte{},
		this.polySigner)
	if err != nil {
		return "", err
	} else {
		log.Infof("commitProof - send transaction to poly chain: ( poly_txhash: %s, eth_txhash: %s, height: %d )",
			tx.ToHexString(), ethcommon.BytesToHash(txhash).String(), height)
		return tx.ToHexString(), nil
	}
}
func (this *EthereumManager) parserValue(value []byte) []byte {
	source := common.NewZeroCopySource(value)
	txHash, eof := source.NextVarBytes()
	if eof {
		fmt.Printf("parserValue - deserialize txHash error")
	}
	return txHash
}
func (this *EthereumManager) CheckDeposit() {
	checkTicker := time.NewTicker(time.Duration(this.config.ETHConfig.MonitorInterval) * time.Second)
	for {
		select {
		case <-checkTicker.C:
			// try to check deposit
			this.checkLockDepositEvents()
		case <-this.exitChan:
			return
		}
	}
}
func (this *EthereumManager) checkLockDepositEvents() error {
	checkMap, err := this.db.GetAllCheck()
	if err != nil {
		return fmt.Errorf("checkLockDepositEvents - this.db.GetAllCheck error: %s", err)
	}
	for k, v := range checkMap {
		event, err := this.polySdk.GetSmartContractEvent(k)
		if err != nil {
			log.Errorf("checkLockDepositEvents - this.aliaSdk.GetSmartContractEvent error: %s", err)
			continue
		}
		if event == nil {
			continue
		}
		if event.State != 1 {
			log.Infof("checkLockDepositEvents - state of poly tx %s is not success", k)
			err := this.db.PutRetry(v)
			if err != nil {
				log.Errorf("checkLockDepositEvents - this.db.PutRetry error:%s", err)
			}
		}
		err = this.db.DeleteCheck(k)
		if err != nil {
			log.Errorf("checkLockDepositEvents - this.db.DeleteRetry error:%s", err)
		}
	}
	return nil
}
