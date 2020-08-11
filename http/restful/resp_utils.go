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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	crypto "github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/ontology/core/signature"
	"github.com/paxont/http/types"
	"strings"
)

func GetRespCode(isAllSuccess, isAllFailed bool) uint32 {
	if isAllSuccess { // all success
		return SUCCESS
	}
	if isAllFailed { // all failed
		return FAILED
	}
	if !isAllSuccess && !isAllFailed { // partial success
		return PARTIAL_SUCCESS
	}
	return FAILED
}

func RefactorResp(resp interface{}) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	data, err := json.Marshal(resp)
	if err != nil {
		return m, fmt.Errorf("refactorResp: marshal resp failed, err: %s", err)
	}
	err = json.Unmarshal(data, &m)
	if err != nil {
		return m, fmt.Errorf("refactorResp: unmarshal data failed, err: %s", err)
	}
	return m, nil
}

// parse decrypt response to secure communication resp
func RefactorSecureResp(resp interface{}, privKey keypair.PrivateKey) (map[string]interface{}, error) {
	communication, err := ParseToSecureComm(resp, privKey)
	if err != nil {
		return nil, fmt.Errorf("RefactorSecureResp: parse to secure failed, err: %s", err)
	}
	result, err := RefactorResp(communication)
	if err != nil {
		return nil, fmt.Errorf("RefactorSecureResp: failed, err: %s")
	}
	return result, nil
}

// parse decrypt data to secure communication req or resp
func ParseToSecureComm(data interface{}, privKey keypair.PrivateKey) (*types.SecureCommunication, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("ParseToSecureComm: marshal data failed, err: %s", err)
	}
	hash := sha256.Sum256(jsonData)
	hashData := sha256.Sum256(hash[:])
	sig, err := crypto.Sign(crypto.SHA256withECDSA, privKey, hashData[:], nil)
	if err != nil {
		return nil, fmt.Errorf("ParseToSecureComm: sign failed, err: %s", err)
	}
	sigData, err := crypto.Serialize(sig)
	if err != nil {
		return nil, fmt.Errorf("ParseToSecureComm: serialized sig data failed, err: %s", err)
	}
	communication := &types.SecureCommunication{
		Data:      fmt.Sprintf("%x", jsonData),
		Hash:      fmt.Sprintf("%x", hashData),
		Signature: fmt.Sprintf("%x", sigData),
	}
	return communication, nil
}

// parse secure communication req to decrypt req
func ParseReqFromSecureCommParams(dest interface{}, params map[string]interface{}, pubKey keypair.PublicKey) error {
	paramData, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("ParseReqFromSecureCommParams: marshal params failed, err: %s", err)
	}
	reqData, err := fetchSecureData(paramData, pubKey)
	if err != nil {
		return fmt.Errorf("ParseReqFromSecureCommParams: failed, err: %s", err)
	}
	err = json.Unmarshal(reqData, dest)
	if err != nil {
		return fmt.Errorf("ParseReqFromSecureCommParams: unmarshal dest failed, err: %s", err)
	}
	return nil
}

// parse secure communication resp to decrypt resp
func ParseRespFromSecureCommData(dest interface{}, data []byte, pubKey keypair.PublicKey) error {
	respData, err := fetchSecureData(data, pubKey)
	if err != nil {
		return fmt.Errorf("ParseRespFromSecureCommData: failed, err: %s", err)
	}
	err = json.Unmarshal(respData, dest)
	if err != nil {
		return fmt.Errorf("ParseRespFromSecureCommData: unmarshal dest failed, err: %s", err)
	}
	return nil
}

func fetchSecureData(data []byte, pubKey keypair.PublicKey) ([]byte, error) {
	communication := &types.SecureCommunication{}
	err := json.Unmarshal(data, communication)
	if err != nil {
		return nil, fmt.Errorf("fetchSecureData: unmarshal data failed, err: %s", err)
	}
	reqData, err := hex.DecodeString(communication.Data)
	if err != nil {
		return nil, fmt.Errorf("fetchSecureData: decode data failed err: %s", err)
	}
	hash := sha256.Sum256(reqData)
	hashData := sha256.Sum256(hash[:])
	verifyHash := fmt.Sprintf("%x", hashData)
	if strings.ToUpper(verifyHash) != strings.ToUpper(communication.Hash) {
		return nil, fmt.Errorf("fetchSecureData: data hash unmatch")
	}
	sigData, err := hex.DecodeString(communication.Signature)
	if err != nil {
		return nil, fmt.Errorf("fetchSecureData: decode sig data failed err: %s", err)
	}
	err = signature.Verify(pubKey, hashData[:], sigData)
	if err != nil {
		return nil, fmt.Errorf("fetchSecureData: sig verify failed, err: %s", err)
	}
	return reqData, nil
}
