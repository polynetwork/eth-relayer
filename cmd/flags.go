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
package cmd

import (
	"strings"

	"github.com/polynetwork/eth_relayer/config"
	"github.com/urfave/cli"
)

var (
	LogLevelFlag = cli.UintFlag{
		Name:  "loglevel",
		Usage: "Set the log level to `<level>` (0~6). 0:Trace 1:Debug 2:Info 3:Warn 4:Error 5:Fatal 6:MaxLevel",
		Value: config.DEFAULT_LOG_LEVEL,
	}

	//CliWalletDirFlag = cli.StringFlag{
	//	Name:  "walletdir",
	//	Usage: "Wallet data `<path>`",
	//	Value: config.DEFAULT_WALLET_PATH,
	//}

	//CliAddressFlag = cli.StringFlag{
	//	Name:  "cliaddress",
	//	Usage: "Rpc bind `<address>`",
	//	Value: config.DEFUALT_CLI_RPC_ADDRESS,
	//}

	//CliRpcPortFlag = cli.UintFlag{
	//	Name:  "cliport",
	//	Usage: "Rpc bind port `<number>`",
	//	Value: config.DEFAULT_CLI_RPC_PORT,
	//}

	ConfigPathFlag = cli.StringFlag{
		Name:  "cliconfig",
		Usage: "Server config file `<path>`",
		Value: config.DEFAULT_CONFIG_FILE_NAME,
	}

	EthStartFlag = cli.Uint64Flag{
		Name:  "ethereum",
		Usage: "eth start block height ",
		Value: uint64(0),
	}

	EthStartForceFlag = cli.Uint64Flag{
		Name:  "ethereumforce",
		Usage: "eth start block height ",
		Value: uint64(0),
	}

	MCStartFlag = cli.Uint64Flag{
		Name:  "poly",
		Usage: "poly start block height ",
		Value: uint64(0),
	}

	LogDir = cli.StringFlag{
		Name:  "logdir",
		Usage: "log directory",
		Value: "./Log/",
	}

	//EncryptFlag = cli.StringFlag{
	//	Name:  "encrypt",
	//	Usage: "encrypt string `pwd`",
	//	Value: "",
	//}
)

//GetFlagName deal with short flag, and return the flag name whether flag name have short name
func GetFlagName(flag cli.Flag) string {
	name := flag.GetName()
	if name == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(name, ",")[0])
}
