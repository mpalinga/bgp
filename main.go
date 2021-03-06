//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//	 Unless required by applicable law or agreed to in writing, software
//	 distributed under the License is distributed on an "AS IS" BASIS,
//	 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	 See the License for the specific language governing permissions and
//	 limitations under the License.
//
// _______  __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  |
// |  |__   |  |     |  |__   \  V  /     |   (----` \   \/    \/   /  |  | `---|  |----`|  ,----'|  |__|  |
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   |
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  |
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__|
//

// main.go
package main

import (
	"flag"
	"fmt"
	"l3/bgp/api"
	"l3/bgp/flexswitch"
	"l3/bgp/ovs"
	bgppolicy "l3/bgp/policy"
	"l3/bgp/rpc"
	"l3/bgp/server"
	"l3/bgp/utils"
	"utils/dbutils"
	"utils/keepalive"
	"utils/logging"
	"utils/statedbclient"
)

const (
	IP          string = "10.1.10.229"
	BGPPort     string = "179"
	CONF_PORT   string = "2001"
	BGPConfPort string = "4050"
	RIBConfPort string = "5000"

	OVSDB_PLUGIN = "ovsdb"
)

func main() {
	fmt.Println("Starting bgp daemon")
	paramsDir := flag.String("params", "./params", "Params directory")
	flag.Parse()
	fileName := *paramsDir
	if fileName[len(fileName)-1] != '/' {
		fileName = fileName + "/"
	}
	fmt.Println("Start logger")
	logger, err := logging.NewLogger("bgpd", "BGP", true)
	if err != nil {
		fmt.Println("Failed to start the logger. Nothing will be logged...")
	}
	logger.Info("Started the logger successfully.")
	utils.SetLogger(logger)

	// Start DB Util
	dbUtil := dbutils.NewDBUtil(logger)
	err = dbUtil.Connect()
	if err != nil {
		logger.Err(fmt.Sprintf("DB connect failed with error %s. Exiting!!", err))
		return
	}

	// Start keepalive routine
	go keepalive.InitKeepAlive("bgpd", fileName)

	// @FIXME: Plugin name should come for json readfile...
	//plugin := OVSDB_PLUGIN
	plugin := ""
	switch plugin {
	case OVSDB_PLUGIN:
		// if plugin used is ovs db then lets start ovsdb client listener
		quit := make(chan bool)
		rMgr := ovsMgr.NewOvsRouteMgr()
		pMgr := ovsMgr.NewOvsPolicyMgr()
		iMgr := ovsMgr.NewOvsIntfMgr()
		bMgr := ovsMgr.NewOvsBfdMgr()
		sDBMgr, err := statedbclient.NewStateDBClient(statedbclient.OVSPlugin, logger)
		if err != nil {
			logger.Info(fmt.Sprintln("Starting OVDB state DB client failed ERROR:", err))
			return
		}

		// starting bgp policy engine...
		logger.Info(fmt.Sprintln("Starting BGP policy engine..."))
		bgpPolicyMgr := bgppolicy.NewPolicyManager(logger, pMgr)
		go bgpPolicyMgr.StartPolicyEngine()

		bgpServer := server.NewBGPServer(logger, bgpPolicyMgr, iMgr, rMgr, bMgr, sDBMgr)
		go bgpServer.StartServer()

		logger.Info(fmt.Sprintln("Starting config listener..."))
		confIface := rpc.NewBGPHandler(bgpServer, bgpPolicyMgr, logger, dbUtil, fileName)
		dbUtil.Disconnect()

		// create and start ovsdb handler
		ovsdbManager, err := ovsMgr.NewBGPOvsdbHandler(logger, confIface)
		if err != nil {
			logger.Info(fmt.Sprintln("Starting OVDB client failed ERROR:", err))
			return
		}
		err = ovsdbManager.StartMonitoring()
		if err != nil {
			logger.Info(fmt.Sprintln("OVSDB Serve failed ERROR:", err))
			return
		}

		<-quit
	default:
		// flexswitch plugin lets connect to clients first and then
		// start flexswitch client listener
		iMgr, err := FSMgr.NewFSIntfMgr(logger, fileName)
		if err != nil {
			return
		}
		rMgr, err := FSMgr.NewFSRouteMgr(logger, fileName)
		if err != nil {
			return
		}
		bMgr, err := FSMgr.NewFSBfdMgr(logger, fileName)
		if err != nil {
			return
		}
		pMgr := FSMgr.NewFSPolicyMgr(logger, fileName)
		sDBMgr, err := statedbclient.NewStateDBClient(statedbclient.FlexSwitchPlugin, logger)
		if err != nil {
			return
		}
		// starting bgp policy engine...
		logger.Info(fmt.Sprintln("Starting BGP policy engine..."))
		bgpPolicyMgr := bgppolicy.NewPolicyManager(logger, pMgr)
		go bgpPolicyMgr.StartPolicyEngine()

		logger.Info(fmt.Sprintln("Starting BGP Server..."))

		bgpServer := server.NewBGPServer(logger, bgpPolicyMgr, iMgr, rMgr, bMgr, sDBMgr)
		go bgpServer.StartServer()

		api.InitPolicy(bgpPolicyMgr)
		api.Init(bgpServer)

		// Start keepalive routine
		go keepalive.InitKeepAlive("bgpd", fileName)

		logger.Info(fmt.Sprintln("Starting config listener..."))
		confIface := rpc.NewBGPHandler(bgpServer, bgpPolicyMgr, logger, dbUtil, fileName)
		dbUtil.Disconnect()

		rpc.StartServer(logger, confIface, fileName)
	}
}
