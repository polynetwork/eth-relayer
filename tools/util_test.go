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
	"github.com/polynetwork/eth_relayer/http/utils"
	"testing"
)

func TestGetProof(t *testing.T) {
	client := utils.NewRestClient()
	res, err := GetProof("http://139.219.131.74:10331",
		"0xf6dc652e2f7ab7a20d1cc4156d5a7122a9e966a5",
		"0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d",
		"0x5e852e",
		client)
	if err != nil {
		fmt.Printf("err:%s\n", err)
		return
	}
	fmt.Printf("res is :%s\n", res)
}
