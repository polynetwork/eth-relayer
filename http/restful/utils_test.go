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
package restful

import (
	"encoding/hex"
	"encoding/json"
	"github.com/ontio/ontology-crypto/keypair"
	"github.com/stretchr/testify/assert"
	"github.com/walletsvr/walletcommon/http/types"
	"testing"
)

var (
	myPrivKey        keypair.PrivateKey
	accountSysPubKey keypair.PublicKey
)

func TestInitKey(t *testing.T) {
	pubKeyData, err := hex.DecodeString("02a5eeb3c4d15c16f36e999c14bbd09cad781decf9c73b040c5b5b1d870c9e10ff")
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := keypair.DeserializePublicKey(pubKeyData)
	if err != nil {
		t.Fatal(err)
	}
	accountSysPubKey = pubKey

	privKey, err := keypair.WIF2Key([]byte("KzVv1r2D3gFcLgXmKso8nGjKpdhgN7JAgN1EpsS61BbsKFiQgfHd"))
	if err != nil {
		t.Fatal(err)
	}
	myPrivKey = privKey
}

func TestGetRespCode(t *testing.T) {
	isAllSuccess := false
	isAllFailed := false
	assert.Equal(t, GetRespCode(isAllSuccess, isAllFailed), PARTIAL_SUCCESS)
	isAllSuccess = true
	isAllFailed = false
	assert.Equal(t, GetRespCode(isAllSuccess, isAllFailed), SUCCESS)
	isAllSuccess = true
	isAllFailed = true
	assert.Equal(t, GetRespCode(isAllSuccess, isAllFailed), SUCCESS)
	isAllSuccess = false
	isAllFailed = true
	assert.Equal(t, GetRespCode(isAllSuccess, isAllFailed), FAILED)
}

func TestRefactorResp(t *testing.T) {
	resp := &types.NodeStatusResp{
		MsgId:   "1",
		Code:    SUCCESS,
		Message: "aaa",
	}
	refactorResp, err := RefactorResp(resp)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, resp.MsgId, refactorResp["msgId"])
	assert.Equal(t, resp.Message, refactorResp["message"])
	assert.Equal(t, float64(resp.Code), refactorResp["code"])
}

func TestRefactorSecureResp(t *testing.T) {
	TestInitKey(t)

	resp := &types.NodeStatusResp{
		MsgId:   "1",
		Code:    SUCCESS,
		Message: "aaa",
	}
	params, err := RefactorSecureResp(resp, myPrivKey)

	if err != nil {
		t.Fatal(err)
	}
	t.Logf("hash: %s, data: %s, sig: %s", params["hash"], params["data"], params["signature"])
}

func TestParseReqFromSecureCommParams(t *testing.T) {
	TestInitKey(t)

	params := make(map[string]interface{})
	params["data"] = "7b226d73674964223a2231313131222c22636f696e54797065223a22455448222c2268617368223a22616761646661" +
		"6b6768616a6b646e766a6b6168666977222c2266726f6d41646472223a22222c2265786368616e6765436f696e4164647222" +
		"3a22222c227265636861726765416d6f756e74223a223139222c22726563686172676554696d65223a22222c227265636861" +
		"726765537461747573223a22227d"
	params["hash"] = "934a8394d958d4df4240b5ae3a65d468afff7bb919779a839530ac4059d56e16"
	params["signature"] = "e6e5a6766b9a0ece85ead7dc174f6e71abb82f9ab53329cf08d831aea9b229d97b3d1a46579c983a6b46a7e6050cb0" +
		"694a643c6f231b2973684ae2467f286ab9"

	dest := &types.ReportingDepositReq{}
	err := ParseReqFromSecureCommParams(dest, params, myPrivKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("msgId %s, coin %s, hash %s, amount %s", dest.MsgId, dest.CoinType, dest.Hash, dest.RechargeAmount)
}

func TestParseToSecureComm(t *testing.T) {
	TestInitKey(t)

	depositReport := &types.ReportingDepositReq{
		MsgId:          "1111",
		CoinType:       "ETH",
		Hash:           "agadfakghajkdnvjkahfiw",
		RechargeAmount: "19",
	}
	communication, err := ParseToSecureComm(depositReport, myPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("hash %s, data: %s, sig: %s", communication.Hash, communication.Data, communication.Signature)
}

func TestParseResFromSecureCommData(t *testing.T) {
	TestInitKey(t)

	communication := &types.SecureCommunication{
		Hash: "934a8394d958d4df4240b5ae3a65d468afff7bb919779a839530ac4059d56e16",
		Data: "7b226d73674964223a2231313131222c22636f696e54797065223a22455448222c2268617368223a22616761646661" +
			"6b6768616a6b646e766a6b6168666977222c2266726f6d41646472223a22222c2265786368616e6765436f696e4164647222" +
			"3a22222c227265636861726765416d6f756e74223a223139222c22726563686172676554696d65223a22222c227265636861" +
			"726765537461747573223a22227d",
		Signature: "e6e5a6766b9a0ece85ead7dc174f6e71abb82f9ab53329cf08d831aea9b229d97b3d1a46579c983a6b46a7e6050cb0" +
			"694a643c6f231b2973684ae2467f286ab9",
	}
	jsonData, err := json.Marshal(communication)
	if err != nil {
		t.Fatal(err)
	}
	depositReport := &types.ReportingDepositReq{}
	err = ParseRespFromSecureCommData(depositReport, jsonData, myPrivKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("msgId %s, coin %s, hash %s, amount %s", depositReport.MsgId, depositReport.CoinType,
		depositReport.Hash, depositReport.RechargeAmount)
}
