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
	"math/big"
	"strings"
)

type EthKeyStore struct {
	ks      *keystore.KeyStore
	chainId *big.Int
}

func NewEthKeyStore(sigConfig *config.ETHConfig, chainId *big.Int) *EthKeyStore {
	service := &EthKeyStore{}
	capitalKeyStore := keystore.NewKeyStore(sigConfig.KeyStorePath, keystore.StandardScryptN,
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
	service.ks = capitalKeyStore
	service.chainId = chainId
	return service
}

func (this *EthKeyStore) UnlockKeys(sigConfig *config.ETHConfig) error {
	for _, v := range this.GetAccounts() {
		err := this.ks.Unlock(v, sigConfig.KeyStorePwdSet[strings.ToLower(v.Address.String())])
		if err != nil {
			return fmt.Errorf("failed to unlock eth acc %s: %v", v.Address.String(), err)
		}
	}
	return nil
}

func (this *EthKeyStore) SignTransaction(tx *types.Transaction, acc accounts.Account) (*types.Transaction, error) {
	tx, err := this.ks.SignTx(acc, tx, this.chainId)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (this *EthKeyStore) GetAccounts() []accounts.Account {
	return this.ks.Accounts()
}

func (this *EthKeyStore) TestPwd(acc accounts.Account, pwd string) error {
	if err := this.ks.Unlock(acc, pwd); err != nil {
		return err
	}
	_ = this.ks.Lock(acc.Address)
	return nil
}

func (this *EthKeyStore) GetChainId() uint64 {
	return this.chainId.Uint64()
}
