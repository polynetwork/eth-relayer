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
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/eth_relayer/config"
	"testing"
)

func TestETHSigner_SignRawTx(t *testing.T) {

	data := "000000000000000000000000000000000000001032323433653139323364353532326665376330333432613137376365333265633436316237313163623638373066373161376233313336343233363033383937"

	cfg := config.NewServiceConfig("../config.json")
	ethsigner := NewETHSigner(cfg.ETHConfig)
	s, err := ethsigner.SignRawTx(data)
	if err != nil {
		fmt.Printf("err:%s\n", err.Error())
		t.Fatal(err)
	}
	fmt.Printf("signed tx :%v\n", s)

	client, err := ethclient.Dial("http://139.219.131.74:10331")
	if err != nil {
		return
	}

	//signedTx := &types.Transaction{}
	//txdata, err := hexutil.Decode(s)
	//if err != nil {
	//	return
	//}
	//
	//err = rlp.DecodeBytes(txdata, signedTx)
	//if err != nil {
	//	fmt.Printf("[signOEP4Tx]rlp.DecodeBytes error:%s\n", err.Error())
	//	return
	//}
	fmt.Println("before send....")
	err = client.SendTransaction(context.Background(), s)
	if err != nil {
		fmt.Printf("[signOEP4Tx]SendTransaction error:%s\n", err.Error())
		return
	}
	fmt.Println("after send....")

}
