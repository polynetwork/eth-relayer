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

type EventsCondition struct {
	Txhash     string
	EthAddress string
	OntAddress string
	Amount     string
	Status     int
	Pagesize   int
	Pageno     int
}

type Events struct {
	Txhash     string
	EthAddress string
	OntAddress string
	Amount     string
	Status     int
	Updated    string
}

type SignsCondition struct {
	Txhash   string
	Status   int
	ErrCode  int
	ErrInfo  string
	Pagesize int
	Pageno   int
}

type Signs struct {
	Txhash  string
	SigData string
	Status  int
	ErrCode int
	ErrInfo string
	Updated string
}

type ResultCondition struct {
	EthTxhash string
	OntTxhash string
	Confirmed int
	ErrCode   int
	Pagesize  int
	Pageno    int
}

type Results struct {
	EthTxhash string
	OntTxhash string
	Confirmed int
	ErrCode   int
	ErrInfo   string
	Updated   string
}

type ApprovalCondition struct {
	Txhash     string
	EthAddress string
	OntAddress string
	Amount     string
	Status     int
	Pagesize   int
	Pageno     int
}

type Approvals struct {
	Txhash     string
	EthAddress string
	OntAddress string
	Amount     string
	RawTxdata  string
	Status     int
	Updated    string
}

type WhiteListCondition struct {
	EthAddress    string
	OntAddress    string
	TransferLimit string
	Pagesize      int
	Pageno        int
}

type WhiteList struct {
	EthAddress    string
	OntAddress    string
	TransferLimit string
}

type PaxServiceInterface interface {
	QueryEvents(conditions map[string]interface{}) map[string]interface{}
	QuerySigns(conditions map[string]interface{}) map[string]interface{}
	QueryResults(conditions map[string]interface{}) map[string]interface{}
	QueryApprovals(conditions map[string]interface{}) map[string]interface{}
	QueryEthHeight(conditions map[string]interface{}) map[string]interface{}
	QueryOntHeight(conditions map[string]interface{}) map[string]interface{}
	LockApprovals(conditions map[string]interface{}) map[string]interface{}
	UnlockApprovals(conditions map[string]interface{}) map[string]interface{}
	QueryWhiteList(conditions map[string]interface{}) map[string]interface{}
	AddWhiteList(wl map[string]interface{}) map[string]interface{}
	UpdateWhiteList(wl map[string]interface{}) map[string]interface{}
	DeleteWhiteList(wl map[string]interface{}) map[string]interface{}
	ResetEvents(wl map[string]interface{}) map[string]interface{}
	ValidateTx(wl map[string]interface{}) map[string]interface{}
	AddApproval(conditions map[string]interface{}) map[string]interface{}

	ResponsePack
}

type ResponsePack interface {
	PackResponse(code uint32) map[string]interface{}
}
