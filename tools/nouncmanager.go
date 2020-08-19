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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/eth_relayer/log"
	"sort"
	"sync"
	"time"
)

const clear_nonce_interval = 10 * time.Minute

type NonceManager struct {
	addressNonce  map[common.Address]uint64
	returnedNonce map[common.Address]SortedNonceArr
	ethClient     *ethclient.Client
	lock          sync.Mutex
}

func NewNonceManager(ethClient *ethclient.Client) *NonceManager {
	nonceManager := &NonceManager{
		addressNonce:  make(map[common.Address]uint64),
		ethClient:     ethClient,
		returnedNonce: make(map[common.Address]SortedNonceArr),
	}
	go nonceManager.clearNonce()
	return nonceManager
}

// return account nonce, and than nonce++
func (this *NonceManager) GetAddressNonce(address common.Address) uint64 {
	this.lock.Lock()
	defer this.lock.Unlock()

	if this.returnedNonce[address].Len() > 0 {
		nonce := this.returnedNonce[address][0]
		this.returnedNonce[address] = this.returnedNonce[address][1:]
		return nonce
	}

	// return a new point
	nonce, ok := this.addressNonce[address]
	if !ok {
		// get nonce from eth network
		uintNonce, err := this.ethClient.PendingNonceAt(context.Background(), address)
		if err != nil {
			log.Errorf("GetAddressNonce: cannot get account %s nonce, err: %s, set it to nil!",
				address, err)
		}
		this.addressNonce[address] = uintNonce
		nonce = uintNonce
	}
	// increase record
	this.addressNonce[address]++
	return nonce
}

func (this *NonceManager) ReturnNonce(addr common.Address, nonce uint64) {
	arr, ok := this.returnedNonce[addr]
	if !ok {
		arr = make([]uint64, 0)
	}
	arr = append(arr, nonce)
	sort.Sort(arr)
	this.returnedNonce[addr] = arr
}

func (this *NonceManager) DecreaseAddressNonce(address common.Address) {
	this.lock.Lock()
	defer this.lock.Unlock()

	nonce, ok := this.addressNonce[address]
	if ok && nonce > 0 {
		this.addressNonce[address]--
	}
}

// clear nonce per
func (this *NonceManager) clearNonce() {
	for {
		<-time.After(clear_nonce_interval)
		this.lock.Lock()
		for addr, _ := range this.addressNonce {
			delete(this.addressNonce, addr)
		}
		this.lock.Unlock()
		//log.Infof("clearNonce: clear all cache nonce")
	}
}

type SortedNonceArr []uint64

func (arr SortedNonceArr) Less(i, j int) bool {
	return arr[i] < arr[j]
}

func (arr SortedNonceArr) Len() int { return len(arr) }

func (arr SortedNonceArr) Swap(i, j int) { arr[i], arr[j] = arr[j], arr[i] }
