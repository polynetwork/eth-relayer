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
	"fmt"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
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

	accArr := capitalKeyStore.Accounts()
	if len(accArr) == 0 {
		log.Fatal("relayer has no account")
		panic(fmt.Errorf("relayer has no account"))
	}
	str := ""
	for i, v := range accArr {
		str += fmt.Sprintf("(no.%d acc: %s), ", i+1, v.Address.String())
	}
	log.Infof("relayer are using accounts: [ %s ]", str)

	service.capitalKeyStore = capitalKeyStore
	service.sigConfig = sigConfig
	return service
}

// TODO: only use the first one now. Will add a account manager in the future.
func (this *ETHSigner) SignTransaction(tx *types.Transaction) (*types.Transaction, error) {
	accArr := this.capitalKeyStore.Accounts()
	if len(accArr) == 0 {
		return nil, fmt.Errorf("length of accounts is zero")
	}
	tx, err := this.capitalKeyStore.SignTxWithPassphrase(accArr[0], this.sigConfig.CapitalPassword, tx, nil)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (this *ETHSigner) GetAccounts() []accounts.Account {
	return this.capitalKeyStore.Accounts()
}