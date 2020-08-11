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
package tools

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	ethComm "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/polynetwork/eth_relayer/config"
	"github.com/polynetwork/eth_relayer/log"
)

type ETHSigner struct {
	capitalKeyStore *keystore.KeyStore
	sigConfig       *config.ETHConfig
}

func NewETHSigner(sigConfig *config.ETHConfig) *ETHSigner {
	service := &ETHSigner{}
	capitalKeyStore := keystore.NewKeyStore(sigConfig.CapitalOwnersPath, keystore.StandardScryptN,
		keystore.StandardScryptP)
	service.capitalKeyStore = capitalKeyStore

	key, err := crypto.HexToECDSA(sigConfig.PrivateKey)
	if err != nil {
		log.Errorf("cannot decode private key")
		return nil
	}

	addr := ethComm.HexToAddress(sigConfig.Signer)
	if !capitalKeyStore.HasAddress(addr) {
		account, err := capitalKeyStore.ImportECDSA(key, sigConfig.CapitalPassword)
		if err != nil {
			log.Errorf("import failed, err: %s", err)
		} else {
			log.Infof("import success, path: %s", account.URL.Path)
		}
	}

	service.sigConfig = sigConfig
	return service
}

func (this *ETHSigner) SignRawTx(rawtx string) (*types.Transaction, error) {

	signer := this.sigConfig.Signer
	signedTx, err := this.signCapitalTransaction(rawtx, signer)
	if err != nil {
		err = fmt.Errorf("SignRawTx: err: %s", err)
		log.Error(err)
		return nil, err
	}

	return signedTx, nil
}

func (this *ETHSigner) signCapitalTx(rawTx string, signer string) (signedRawTx, hash string, err error) {
	unsignedTx, err := deserializeTx(rawTx)
	if err != nil {
		return "", "", fmt.Errorf("signCapitalTx: failed, err: %s", err)
	}
	account := accounts.Account{Address: ethComm.HexToAddress(signer)}
	err = this.capitalKeyStore.TimedUnlock(account, this.sigConfig.CapitalPassword, config.KEY_UNLOCK_TIME)
	if err != nil {
		return "", "", fmt.Errorf("signCapitalTx: unlock account %s failed: %s", signer, err)
	}
	signedTx, err := this.capitalKeyStore.SignTx(account, unsignedTx, nil)
	if err != nil {
		return "", "", fmt.Errorf("signCapitalTx: sign tx failed, err: %s", err)
	}
	log.Infof("signAccountTx: use account %s sign", signer)
	signedRawTx, err = serializeTx(signedTx)
	if err != nil {
		return "", "", fmt.Errorf("signCapitalTx: failed, err: %s", err)
	}
	return signedRawTx, signedTx.Hash().String(), nil
}

func (this *ETHSigner) signCapitalTransaction(rawTx string, signer string) (*types.Transaction, error) {
	unsignedTx, err := deserializeTx(rawTx)
	if err != nil {
		return nil, err
	}
	account := accounts.Account{Address: ethComm.HexToAddress(signer)}
	err = this.capitalKeyStore.TimedUnlock(account, this.sigConfig.CapitalPassword, config.KEY_UNLOCK_TIME)
	if err != nil {
		return nil, err
	}
	signedTx, err := this.capitalKeyStore.SignTx(account, unsignedTx, nil)
	if err != nil {
		return nil, err
	}
	log.Infof("signAccountTx: use account %s sign", signer)

	return signedTx, nil
}

func deserializeTx(rawTx string) (*types.Transaction, error) {
	txData := ethComm.FromHex(rawTx)
	tx := &types.Transaction{}
	err := rlp.DecodeBytes(txData, tx)
	if err != nil {
		return nil, fmt.Errorf("deserializeTx: err: %s", err)
	}
	return tx, nil
}

func serializeTx(tx *types.Transaction) (string, error) {
	bf := new(bytes.Buffer)
	err := rlp.Encode(bf, tx)
	if err != nil {
		return "", fmt.Errorf("signTx: encode signed tx err: %s", err)
	}
	signedRawTx := hexutil.Encode(bf.Bytes())
	return signedRawTx, nil
}
