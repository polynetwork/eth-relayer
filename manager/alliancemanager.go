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
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ontio/ontology-crypto/ec"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology-crypto/sm2"
	"github.com/polynetwork/eth_relayer/config"
	"github.com/polynetwork/eth_relayer/contractabi/eccd_abi"
	"github.com/polynetwork/eth_relayer/contractabi/eccm_abi"
	"github.com/polynetwork/eth_relayer/db"
	"github.com/polynetwork/eth_relayer/log"
	sdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/consensus/vbft/config"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"golang.org/x/crypto/ed25519"
	"strings"

	"bytes"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/polynetwork/eth_relayer/tools"

	onttypes "github.com/polynetwork/poly/core/types"
)

type AllianceManager struct {
	config        *config.ServiceConfig
	multiSdk      *sdk.PolySdk
	currentHeight uint32
	ethClient     *ethclient.Client
	contractAbi   *abi.ABI
	nonceManager  *tools.NonceManager
	ethSigner     *tools.ETHSigner
	exitChan      chan int
	db            *db.BoltDB
	contracts map[string]chan *EthTxInfo
}

func NewAllianceManager(servCfg *config.ServiceConfig, startblockHeight uint32, alliancesdk *sdk.PolySdk, ethereumsdk *ethclient.Client, boltDB *db.BoltDB) (*AllianceManager, error) {
	contractabi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return nil, err
	}
	return &AllianceManager{
		exitChan:      make(chan int),
		config:        servCfg,
		multiSdk:      alliancesdk,
		currentHeight: startblockHeight,
		contractAbi:   &contractabi,
		ethClient:     ethereumsdk,
		nonceManager:  tools.NewNonceManager(ethereumsdk),
		ethSigner:     tools.NewETHSigner(servCfg.ETHConfig),
		db:            boltDB,
		contracts: make(map[string]chan *EthTxInfo),
	}, nil
}

func (this *AllianceManager) findLatestHeight() uint32 {
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

func (this *AllianceManager) init() bool {
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
	//block, err := this.multiSdk.GetBlockByHeight(uint32(this.currentHeight))
	//if err != nil {
	//	log.Errorf("init - GetNodeHeader on height :%d failed", 0)
	//	return false
	//}
	//if !this.commitGenesisHeader(block.Header) {
	//	return false
	//}
	return true
}

func (this *AllianceManager) MonitorChain() {
	ret := this.init()
	if ret == false {
		log.Errorf("MonitorChain - init failed\n")
	}
	monitorTicker := time.NewTicker(config.ONT_MONITOR_INTERVAL)
	var blockHandleResult bool
	for {
		select {
		case <-monitorTicker.C:
			latestheight, err := this.multiSdk.GetCurrentBlockHeight()
			if err != nil {
				log.Errorf("MonitorChain - get alliance chain block height error: %s", err)
				continue
			}
			log.Infof("MonitorChain - alliance chain current height: %d", latestheight)
			latestheight--
			if latestheight-this.currentHeight < config.ONT_USEFUL_BLOCK_NUM {
				continue
			}
			blockHandleResult = true
			for this.currentHeight <= latestheight-config.ONT_USEFUL_BLOCK_NUM {
				blockHandleResult = this.handleNewBlock(this.currentHeight)
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

func (this *AllianceManager) handleNewBlock(height uint32) bool {
	ret := this.handleDepositEvents(height)
	if !ret {
		log.Errorf("handleNewBlock - handleDeposit on height: %d failed", height)
	}
	return true
}

func (this *AllianceManager) commitGenesisHeader(header *onttypes.Header) bool {
	headerdata := header.GetMessage()
	gasPrice, err := this.ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Errorf("commitGenesisHeader - get suggest sas price failed error: %s", err.Error())
		return false
	}
	blkInfo := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(header.ConsensusPayload, blkInfo); err != nil {
		log.Errorf("commitGenesisHeader - unmarshal blockInfo error: %s", err)
		return false
	}
	var bookkeepers []keypair.PublicKey
	if blkInfo.NewChainConfig != nil {
		for _, peer := range blkInfo.NewChainConfig.Peers {
			keystr, _ := hex.DecodeString(peer.ID)
			key, _ := keypair.DeserializePublicKey(keystr)
			bookkeepers = append(bookkeepers, key)
		}
	} else {
		log.Errorf("commitGenesisHeader - there is no public key list in genesis header")
		return false
	}
	bookkeepers = keypair.SortPublicKeys(bookkeepers)

	publickeys := make([]byte, 0)
	for _, key := range bookkeepers {
		publickeys = append(publickeys, this.getontnocompresskey(key)...)
	}

	txData, err := this.contractAbi.Pack("initGenesisBlock", headerdata, publickeys)
	log.Infof("header data: %s", hex.EncodeToString(headerdata))
	if err != nil {
		log.Errorf("commitGenesisHeader - err:" + err.Error())
		return false
	}

	accArr := this.ethSigner.GetAccounts()
	contractaddr := ethcommon.HexToAddress(this.config.ETHConfig.ECCMContractAddress)
	callMsg := ethereum.CallMsg{
		From: accArr[0].Address, To: &contractaddr, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(0), Data: txData,
	}

	gasLimit, err := this.ethClient.EstimateGas(context.Background(), callMsg)
	if err != nil {
		log.Errorf("commitGenesisHeader - estimate gas limit error: %s", err.Error())
		return false
	}

	nounce := this.nonceManager.GetAddressNonce(accArr[0].Address)
	tx := types.NewTransaction(nounce, contractaddr, big.NewInt(0), gasLimit, gasPrice, txData)
	signedtx, err := this.ethSigner.SignTransaction(tx)
	if err != nil {
		log.Errorf("commitGenesisHeader - sign raw tx error: %s", err.Error())
		return false
	}

	err = this.ethClient.SendTransaction(context.Background(), signedtx)
	if err != nil {
		log.Errorf("commitGenesisHeader - send transaction error:%s\n", err.Error())
		return false
	}

	this.waitTransactionConfirm(this.ethClient, signedtx.Hash())
	return true
}

func (this *AllianceManager) commitHeader(header *onttypes.Header) bool {
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
		publickeys = append(publickeys, this.getontnocompresskey(key)...)
	}
	txData, txErr = this.contractAbi.Pack("changeBookKeeper", headerdata, publickeys, sigs)
	if txErr != nil {
		log.Errorf("commitHeader - err:" + err.Error())
		return false
	}

	accArr := this.ethSigner.GetAccounts()
	contractaddr := ethcommon.HexToAddress(this.config.ETHConfig.ECCMContractAddress)
	callMsg := ethereum.CallMsg{
		From: accArr[0].Address, To: &contractaddr, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(0), Data: txData,
	}

	gasLimit, err := this.ethClient.EstimateGas(context.Background(), callMsg)
	if err != nil {
		log.Errorf("commitHeader - estimate gas limit error: %s", err.Error())
		return false
	}

	nonce := this.nonceManager.GetAddressNonce(accArr[0].Address)
	tx := types.NewTransaction(nonce, contractaddr, big.NewInt(0), gasLimit, gasPrice, txData)
	signedtx, err := this.ethSigner.SignTransaction(tx)
	if err != nil {
		log.Errorf("commitHeader - sign raw tx error: %s", err.Error())
		return false
	}

	err = this.ethClient.SendTransaction(context.Background(), signedtx)
	if err != nil {
		log.Errorf("commitHeader - send transaction error:%s\n", err.Error())
		return false
	}

	this.waitTransactionConfirm(this.ethClient, signedtx.Hash())
	return true
}

func (this *AllianceManager) handleDepositEvents(height uint32) bool {
	lastEpoch := this.findLatestHeight()
	hdr, err := this.multiSdk.GetHeaderByHeight(height + 1)
	if err != nil {
		log.Errorf("handleBlockHeader - GetNodeHeader on height :%d failed", height)
		return false
	}
	isCurr := lastEpoch < height+1
	isEpoch := hdr.NextBookkeeper != common.ADDRESS_EMPTY
	var (
		anchor *onttypes.Header
		hp     string
	)
	if !isCurr {
		anchor, _ = this.multiSdk.GetHeaderByHeight(lastEpoch + 1)
		proof, _ := this.multiSdk.GetMerkleProof(height+1, lastEpoch+1)
		hp = proof.AuditPath
	} else if isEpoch {
		anchor, _ = this.multiSdk.GetHeaderByHeight(height + 2)
		proof, _ := this.multiSdk.GetMerkleProof(height+1, height+2)
		hp = proof.AuditPath
	}

	cnt := 0
	events, err := this.multiSdk.GetSmartContractEventByBlock(height)
	for err != nil {
		log.Errorf("handleDepositEvents - get block event at height:%d error: %s", height, err.Error())
		return false
	}
	for _, event := range events {
		for _, notify := range event.Notify {
			if notify.ContractAddress == this.config.MultiChainConfig.EntranceContractAddress {
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
				log.Infof("alliance tx hash: %s", event.TxHash)
				if !this.commitDepositEventsWithHeader(hdr, []byte(states[5].(string)), hp, anchor) {
					return false
				}
			}
		}
	}
	if cnt == 0 && isEpoch && isCurr {
		return this.commitHeader(hdr)
	}

	return true
}

func (this *AllianceManager) commitDepositEventsWithHeader(header *onttypes.Header, key []byte, headerProof string, anchorHeader *onttypes.Header) bool {
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
	proof, err := this.multiSdk.GetCrossStatesProof(header.Height-1, string(key))
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - err:" + err.Error())
		return false
	}
	auditpath, _ = hex.DecodeString(proof.AuditPath)
	value, _, _, _ := this.parseAuditpath(auditpath)
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
	log.Infof("alliance proof with header, height: %d, key: %s, proof: %s", header.Height-1, string(key), proof.AuditPath)

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
	accArr := this.ethSigner.GetAccounts()
	signerAddress := accArr[0].Address
	gasPrice, err := this.ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - get suggest sas price failed error: %s", err.Error())
		return false
	}
	contractaddr := ethcommon.HexToAddress(this.config.ETHConfig.ECCMContractAddress)
	callMsg := ethereum.CallMsg{
		From: signerAddress, To: &contractaddr, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(0), Data: txData,
	}
	gasLimit, err := this.ethClient.EstimateGas(context.Background(), callMsg)
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - estimate gas limit error: %s", err.Error())
		return false
	}

	k := this.getRouter(param.MakeTxParam.Args)
	c, ok := this.contracts[k]
	if !ok {
		c = make(chan *EthTxInfo, 64)
		this.contracts[k] = c
		go func() {
			for v := range c {
				if !this.sendTxToEth(v) {
					log.Errorf("failed to send tx to ethereum: txData: %s", hex.EncodeToString(v.txData))
				}
			}
		}()
	}
	c <- &EthTxInfo{
		txData: txData,
		contractAddr: contractaddr,
		gasPrice: gasPrice,
		gasLimit: gasLimit,
	}
	return true
}

func (this *AllianceManager) getRouter(args []byte) string {
	source := common.NewZeroCopySource(args)
	if this.config.RoutineNum == 0 {
		return "other"
	}
	_, eof := source.NextVarBytes()
	if eof {
		return "other"
	}
	addr, eof := source.NextVarBytes()
	if eof {
		return "other"
	}
	num := big.NewInt(0)
	hash := sha256.Sum256(addr)
	num.SetBytes(hash[:])
	mod := num.Mod(num, big.NewInt(this.config.RoutineNum))
	return mod.String()
}

func (this *AllianceManager) sendTxToEth(info *EthTxInfo) bool {
	accArr := this.ethSigner.GetAccounts()
	nounce := this.nonceManager.GetAddressNonce(accArr[0].Address)
	tx := types.NewTransaction(nounce, info.contractAddr, big.NewInt(0), info.gasLimit, info.gasPrice, info.txData)
	signedtx, err := this.ethSigner.SignTransaction(tx)
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - sign raw tx error: %s", err.Error())
		return false
	}
	err = this.ethClient.SendTransaction(context.Background(), signedtx)
	if err != nil {
		log.Errorf("commitDepositEventsWithHeader - send transaction error:%s\n", err.Error())
		return false
	}

	this.waitTransactionConfirm(this.ethClient, signedtx.Hash())
	return true
}

func (this *AllianceManager) commitDepositEvents(height uint32, key []byte) bool {
	accArr := this.ethSigner.GetAccounts()
	gasPrice, err := this.ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Errorf("commitDepositEvents - get suggest sas price failed error: %s", err.Error())
		return false
	}

	proof, err := this.multiSdk.GetCrossStatesProof(height, string(key))
	if err != nil {
		log.Errorf("commitDepositEvents - err:" + err.Error())
		return false
	}

	auditpath, _ := hex.DecodeString(proof.AuditPath)
	value, pos, hashs, _ := this.parseAuditpath(auditpath)
	log.Infof("alliance proof with header, height: %d, key: %s, value: %s, proof: %s", height, string(key), hex.EncodeToString(value), proof.AuditPath)
	//
	txData, err := this.contractAbi.Pack("verifyAndExecuteTx", hashs, pos, value, uint64(height+1))
	if err != nil {
		log.Errorf("commitDepositEvents - err:" + err.Error())
		return false
	}
	//
	contractaddr := ethcommon.HexToAddress(this.config.ETHConfig.ECCMContractAddress)
	callMsg := ethereum.CallMsg{
		From: accArr[0].Address, To: &contractaddr, Gas: 0, GasPrice: gasPrice,
		Value: big.NewInt(0), Data: txData,
	}
	gasLimit, err := this.ethClient.EstimateGas(context.Background(), callMsg)
	if err != nil {
		log.Errorf("commitDepositEvents - estimate gas limit error: %s", err.Error())
		return false
	}
	nounce := this.nonceManager.GetAddressNonce(accArr[0].Address)
	tx := types.NewTransaction(nounce, contractaddr, big.NewInt(0), gasLimit, gasPrice, txData)
	signedtx, err := this.ethSigner.SignTransaction(tx)
	if err != nil {
		log.Errorf("commitDepositEvents - sign raw tx error: %s", err.Error())
		return false
	}

	err = this.ethClient.SendTransaction(context.Background(), signedtx)
	if err != nil {
		log.Errorf("commitDepositEvents - send transaction error:%s\n", err.Error())
		return false
	}

	this.waitTransactionConfirm(this.ethClient, signedtx.Hash())
	return true
}

func (this *AllianceManager) waitTransactionConfirm(ethclient *ethclient.Client, hash ethcommon.Hash) {
	//
	errNum := 0
	for errNum < 100 {
		time.Sleep(time.Second * 1)
		_, ispending, err := ethclient.TransactionByHash(context.Background(), hash)
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

func (this *AllianceManager) parseAuditpath(path []byte) ([]byte, []byte, [][32]byte, error) {
	source := common.NewZeroCopySource(path)
	/*
		l, eof := source.NextUint64()
		if eof {
			return nil, nil, nil, nil
		}
	*/
	value, eof := source.NextVarBytes()
	if eof {
		return nil, nil, nil, nil
	}
	size := int((source.Size() - source.Pos()) / common.UINT256_SIZE)
	pos := make([]byte, 0)
	hashs := make([][32]byte, 0)
	for i := 0; i < size; i++ {
		f, eof := source.NextByte()
		if eof {
			return nil, nil, nil, nil
		}
		pos = append(pos, f)

		v, eof := source.NextHash()
		if eof {
			return nil, nil, nil, nil
		}
		var onehash [32]byte
		copy(onehash[:], (v.ToArray())[0:32])
		hashs = append(hashs, onehash)
	}

	return value, pos, hashs, nil
}

func (this *AllianceManager) Stop() {
	this.exitChan <- 1
	close(this.exitChan)
	log.Infof("multi chain manager exit.")
}

func (this *AllianceManager) getontnocompresskey(key keypair.PublicKey) []byte {
	var buf bytes.Buffer
	switch t := key.(type) {
	case *ec.PublicKey:
		switch t.Algorithm {
		case ec.ECDSA:
			// Take P-256 as a special case
			if t.Params().Name == elliptic.P256().Params().Name {
				return ec.EncodePublicKey(t.PublicKey, false)
			}
			buf.WriteByte(byte(0x12))
		case ec.SM2:
			buf.WriteByte(byte(0x13))
		}
		label, err := this.GetCurveLabel(t.Curve.Params().Name)
		if err != nil {
			panic(err)
		}
		buf.WriteByte(label)
		buf.Write(ec.EncodePublicKey(t.PublicKey, false))
	case ed25519.PublicKey:
		panic("err")
	default:
		panic("err")
	}
	return buf.Bytes()
}

func (this *AllianceManager) GetCurveLabel(name string) (byte, error) {
	switch strings.ToUpper(name) {
	case strings.ToUpper(elliptic.P224().Params().Name):
		return 1, nil
	case strings.ToUpper(elliptic.P256().Params().Name):
		return 2, nil
	case strings.ToUpper(elliptic.P384().Params().Name):
		return 3, nil
	case strings.ToUpper(elliptic.P521().Params().Name):
		return 4, nil
	case strings.ToUpper(sm2.SM2P256V1().Params().Name):
		return 20, nil
	case strings.ToUpper(btcec.S256().Name):
		return 5, nil
	default:
		panic("err")
	}
}

type EthTxInfo struct {
	txData []byte
	gasLimit uint64
	gasPrice *big.Int
	contractAddr ethcommon.Address
}