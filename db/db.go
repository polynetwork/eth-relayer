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
package db

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/boltdb/bolt"
)

const MAX_NUM = 1000

var (
	BKTCheck  = []byte("Check")
	BKTRetry  = []byte("Retry")
	BKTHeight = []byte("Height")
)

type BoltDB struct {
	rwlock   *sync.RWMutex
	db       *bolt.DB
	filePath string
}

func NewBoltDB(filePath string) (*BoltDB, error) {
	if !strings.Contains(filePath, ".bin") {
		filePath = path.Join(filePath, "bolt.bin")
	}
	w := new(BoltDB)
	db, err := bolt.Open(filePath, 0644, &bolt.Options{InitialMmapSize: 500000})
	if err != nil {
		return nil, err
	}
	w.db = db
	w.rwlock = new(sync.RWMutex)
	w.filePath = filePath

	if err = db.Update(func(btx *bolt.Tx) error {
		_, err := btx.CreateBucketIfNotExists(BKTCheck)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	if err = db.Update(func(btx *bolt.Tx) error {
		_, err := btx.CreateBucketIfNotExists(BKTRetry)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	if err = db.Update(func(btx *bolt.Tx) error {
		_, err := btx.CreateBucketIfNotExists(BKTHeight)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *BoltDB) PutCheck(txHash string, v []byte) error {
	w.rwlock.Lock()
	defer w.rwlock.Unlock()

	k, err := hex.DecodeString(txHash)
	if err != nil {
		return err
	}
	return w.db.Update(func(btx *bolt.Tx) error {
		bucket := btx.Bucket(BKTCheck)
		err := bucket.Put(k, v)
		if err != nil {
			return err
		}

		return nil
	})
}

func (w *BoltDB) DeleteCheck(txHash string) error {
	w.rwlock.Lock()
	defer w.rwlock.Unlock()

	k, err := hex.DecodeString(txHash)
	if err != nil {
		return err
	}
	return w.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BKTCheck)
		err := bucket.Delete(k)
		if err != nil {
			return err
		}
		return nil
	})
}

func (w *BoltDB) PutRetry(k []byte) error {
	w.rwlock.Lock()
	defer w.rwlock.Unlock()

	return w.db.Update(func(btx *bolt.Tx) error {
		bucket := btx.Bucket(BKTRetry)
		err := bucket.Put(k, []byte{0x00})
		if err != nil {
			return err
		}

		return nil
	})
}

func (w *BoltDB) DeleteRetry(k []byte) error {
	w.rwlock.Lock()
	defer w.rwlock.Unlock()

	return w.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(BKTRetry)
		err := bucket.Delete(k)
		if err != nil {
			return err
		}
		return nil
	})
}

func (w *BoltDB) GetAllCheck() (map[string][]byte, error) {
	w.rwlock.Lock()
	defer w.rwlock.Unlock()

	checkMap := make(map[string][]byte)
	err := w.db.Update(func(tx *bolt.Tx) error {
		bw := tx.Bucket(BKTCheck)
		bw.ForEach(func(k, v []byte) error {
			_k := make([]byte, len(k))
			_v := make([]byte, len(v))
			copy(_k, k)
			copy(_v, v)
			checkMap[hex.EncodeToString(_k)] = _v
			if len(checkMap) >= MAX_NUM {
				return fmt.Errorf("max num")
			}
			return nil
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return checkMap, nil
}

func (w *BoltDB) GetAllRetry() ([][]byte, error) {
	w.rwlock.Lock()
	defer w.rwlock.Unlock()

	retryList := make([][]byte, 0)
	err := w.db.Update(func(tx *bolt.Tx) error {
		bw := tx.Bucket(BKTRetry)
		bw.ForEach(func(k, _ []byte) error {
			_k := make([]byte, len(k))
			copy(_k, k)
			retryList = append(retryList, _k)
			if len(retryList) >= MAX_NUM {
				return fmt.Errorf("max num")
			}
			return nil
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return retryList, nil
}

func (w *BoltDB) UpdatePolyHeight(h uint32) error {
	w.rwlock.Lock()
	defer w.rwlock.Unlock()

	raw := make([]byte, 4)
	binary.LittleEndian.PutUint32(raw, h)

	return w.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(BKTHeight)
		return bkt.Put([]byte("poly_height"), raw)
	})
}

func (w *BoltDB) GetPolyHeight() uint32 {
	w.rwlock.RLock()
	defer w.rwlock.RUnlock()

	var h uint32
	_ = w.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(BKTHeight)
		raw := bkt.Get([]byte("poly_height"))
		if len(raw) == 0 {
			h = 0
			return nil
		}
		h = binary.LittleEndian.Uint32(raw)
		return nil
	})
	return h
}

func (w *BoltDB) Close() {
	w.rwlock.Lock()
	w.db.Close()
	w.rwlock.Unlock()
}
