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
//  _______  __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  |
// |  |__   |  |     |  |__   \  V  /     |   (----` \   \/    \/   /  |  | `---|  |----`|  ,----'|  |__|  |
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   |
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  |
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__|
//

// server.go
package server

import (
	"errors"
	"fmt"
	"l3/bgp/config"
	"l3/bgp/fsm"
	"l3/bgp/packet"
	bgppolicy "l3/bgp/policy"
	bgprib "l3/bgp/rib"
	"l3/bgp/utils"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"utils/dbutils"
	"utils/eventUtils"
	"utils/logging"
	"utils/netUtils"
	"utils/patriciaDB"
	utilspolicy "utils/policy"
	"utils/policy/policyCommonDefs"
	"utils/statedbclient"
)

type GlobalUpdate struct {
	OldConfig config.GlobalConfig
	NewConfig config.GlobalConfig
	AttrSet   []bool
}

type PeerUpdate struct {
	OldPeer config.NeighborConfig
	NewPeer config.NeighborConfig
	AttrSet []bool
}

type PeerGroupUpdate struct {
	OldGroup config.PeerGroupConfig
	NewGroup config.PeerGroupConfig
	AttrSet  []bool
}

type AggUpdate struct {
	OldAgg  config.BGPAggregate
	NewAgg  config.BGPAggregate
	AttrSet []bool
}

type PolicyParams struct {
	CreateType      int
	DeleteType      int
	route           *bgprib.Route
	dest            *bgprib.Destination
	updated         *(map[uint32]map[*bgprib.Path][]*bgprib.Destination)
	withdrawn       *([]*bgprib.Destination)
	updatedAddPaths *([]*bgprib.Destination)
}

type BGPServer struct {
	logger           *logging.Writer
	policyManager    *bgppolicy.BGPPolicyManager
	locRibPE         *bgppolicy.LocRibPolicyEngine
	ribInPE          *bgppolicy.AdjRibPPolicyEngine
	ribOutPE         *bgppolicy.AdjRibPPolicyEngine
	listener         *net.TCPListener
	ifaceMgr         *utils.InterfaceMgr
	BgpConfig        config.Bgp
	GlobalConfigCh   chan GlobalUpdate
	AddPeerCh        chan PeerUpdate
	RemPeerCh        chan string
	AddPeerGroupCh   chan PeerGroupUpdate
	RemPeerGroupCh   chan string
	AddAggCh         chan AggUpdate
	RemAggCh         chan string
	PeerFSMConnCh    chan fsm.PeerFSMConn
	PeerConnEstCh    chan string
	PeerConnBrokenCh chan string
	PeerCommandCh    chan config.PeerCommand
	ReachabilityCh   chan config.ReachabilityInfo
	BGPPktSrcCh      chan *packet.BGPPktSrc
	BfdCh            chan config.BfdInfo
	IntfCh           chan config.IntfStateInfo
	RoutesCh         chan *config.RouteCh
	acceptCh         chan *net.TCPConn
	GlobalCfgDone    bool

	NeighborMutex  sync.RWMutex
	PeerMap        map[string]*Peer
	Neighbors      []*Peer
	LocRib         *bgprib.LocRib
	ConnRoutesPath *bgprib.Path
	IfacePeerMap   map[int32][]string
	ifaceIP        net.IP
	actionFuncMap  map[int]bgppolicy.PolicyActionFunc
	AddPathCount   int
	// all managers
	IntfMgr    config.IntfStateMgrIntf
	routeMgr   config.RouteMgrIntf
	bfdMgr     config.BfdMgrIntf
	stateDBMgr statedbclient.StateDBClient
	eventDbHdl *dbutils.DBUtil
}

func NewBGPServer(logger *logging.Writer, policyManager *bgppolicy.BGPPolicyManager, iMgr config.IntfStateMgrIntf,
	rMgr config.RouteMgrIntf, bMgr config.BfdMgrIntf, sDBMgr statedbclient.StateDBClient) *BGPServer {
	bgpServer := &BGPServer{}
	bgpServer.logger = logger
	bgpServer.policyManager = policyManager
	bgpServer.ifaceMgr = utils.NewInterfaceMgr(logger)
	bgpServer.BgpConfig = config.Bgp{}
	bgpServer.GlobalCfgDone = false
	bgpServer.GlobalConfigCh = make(chan GlobalUpdate)
	bgpServer.AddPeerCh = make(chan PeerUpdate)
	bgpServer.RemPeerCh = make(chan string)
	bgpServer.AddPeerGroupCh = make(chan PeerGroupUpdate)
	bgpServer.RemPeerGroupCh = make(chan string)
	bgpServer.AddAggCh = make(chan AggUpdate)
	bgpServer.RemAggCh = make(chan string)
	bgpServer.PeerFSMConnCh = make(chan fsm.PeerFSMConn, 50)
	bgpServer.PeerConnEstCh = make(chan string)
	bgpServer.PeerConnBrokenCh = make(chan string)
	bgpServer.PeerCommandCh = make(chan config.PeerCommand)
	bgpServer.ReachabilityCh = make(chan config.ReachabilityInfo)
	bgpServer.BGPPktSrcCh = make(chan *packet.BGPPktSrc)
	bgpServer.BfdCh = make(chan config.BfdInfo)
	bgpServer.IntfCh = make(chan config.IntfStateInfo)
	bgpServer.RoutesCh = make(chan *config.RouteCh)

	bgpServer.NeighborMutex = sync.RWMutex{}
	bgpServer.PeerMap = make(map[string]*Peer)
	bgpServer.Neighbors = make([]*Peer, 0)
	bgpServer.IntfMgr = iMgr
	bgpServer.routeMgr = rMgr
	bgpServer.bfdMgr = bMgr
	bgpServer.stateDBMgr = sDBMgr
	bgpServer.LocRib = bgprib.NewLocRib(logger, rMgr, sDBMgr, &bgpServer.BgpConfig.Global.Config)
	bgpServer.IfacePeerMap = make(map[int32][]string)
	bgpServer.ifaceIP = nil
	bgpServer.actionFuncMap = make(map[int]bgppolicy.PolicyActionFunc)
	bgpServer.AddPathCount = 0

	var aggrActionFunc bgppolicy.PolicyActionFunc
	aggrActionFunc.ApplyFunc = bgpServer.ApplyAggregateAction
	aggrActionFunc.UndoFunc = bgpServer.UndoAggregateAction

	bgpServer.actionFuncMap[policyCommonDefs.PolicyActionTypeAggregate] = aggrActionFunc

	locRibPE := bgppolicy.NewLocRibPolicyEngine(logger)
	bgpServer.logger.Info(fmt.Sprintf("BGPServer: actionfuncmap=%v", bgpServer.actionFuncMap))
	locRibPE.SetEntityUpdateFunc(bgpServer.UpdateRouteAndPolicyDB)
	locRibPE.SetIsEntityPresentFunc(bgpServer.DoesRouteExist)
	locRibPE.SetActionFuncs(bgpServer.actionFuncMap)
	locRibPE.SetTraverseFuncs(bgpServer.TraverseAndApplyBGPRib, bgpServer.TraverseAndReverseBGPRib)
	bgpServer.locRibPE = locRibPE
	bgpServer.policyManager.AddPolicyEngine(bgpServer.locRibPE)

	return bgpServer
}

func (server *BGPServer) createListener() (*net.TCPListener, error) {
	proto := "tcp4"
	addr := ":" + config.BGPPort
	server.logger.Info(fmt.Sprintf("Listening for incomig connections on %s\n", addr))
	tcpAddr, err := net.ResolveTCPAddr(proto, addr)
	if err != nil {
		server.logger.Info(fmt.Sprintln("ResolveTCPAddr failed with", err))
		return nil, err
	}

	listener, err := net.ListenTCP(proto, tcpAddr)
	if err != nil {
		server.logger.Info(fmt.Sprintln("ListenTCP failed with", err))
		return nil, err
	}

	return listener, nil
}

func (server *BGPServer) listenForPeers(listener *net.TCPListener, acceptCh chan *net.TCPConn) {
	for {
		server.logger.Info(fmt.Sprintln("Waiting for peer connections..."))
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			server.logger.Info(fmt.Sprintln("AcceptTCP failed with", err))
			continue
		}
		server.logger.Info(fmt.Sprintln("Got a peer connection from %s", tcpConn.RemoteAddr()))
		server.acceptCh <- tcpConn
	}
}

func (server *BGPServer) IsPeerLocal(peerIp string) bool {
	return server.PeerMap[peerIp].NeighborConf.RunningConf.PeerAS == server.BgpConfig.Global.Config.AS
}

func (server *BGPServer) SendUpdate(updated map[uint32]map[*bgprib.Path][]*bgprib.Destination, withdrawn,
	updatedAddPaths []*bgprib.Destination) {
	for _, peer := range server.PeerMap {
		peer.SendUpdate(updated, withdrawn, updatedAddPaths)
	}
}

func (server *BGPServer) DoesRouteExist(params interface{}) bool {
	policyParams := params.(PolicyParams)
	dest := policyParams.dest
	if dest == nil {
		server.logger.Info(fmt.Sprintln("BGPServer:DoesRouteExist - dest not found for ip",
			policyParams.route.Dest.BGPRouteState.Network, "prefix length",
			policyParams.route.Dest.BGPRouteState.CIDRLen))
		return false
	}

	locRibRoute := dest.GetLocRibPathRoute()
	if policyParams.route == locRibRoute {
		return true
	}

	return false
}

func (server *BGPServer) getAggPrefix(conditionsList []interface{}) *packet.IPPrefix {
	server.logger.Info(fmt.Sprintln("BGPServer:getAggPrefix"))
	var ipPrefix *packet.IPPrefix
	var err error
	for _, condition := range conditionsList {
		switch condition.(type) {
		case utilspolicy.MatchPrefixConditionInfo:
			server.logger.Info(fmt.Sprintln("BGPServer:getAggPrefix -",
				"PolicyConditionTypeDstIpPrefixMatch case"))
			matchPrefix := condition.(utilspolicy.MatchPrefixConditionInfo)
			server.logger.Info(fmt.Sprintln(
				"BGPServer:getAggPrefix - exact prefix match conditiontype"))
			ipPrefix, err = packet.ConstructIPPrefixFromCIDR(matchPrefix.Prefix.IpPrefix)
			if err != nil {
				server.logger.Info(fmt.Sprintln(
					"BGPServer:getAggPrefix - ipPrefix invalid "))
				return nil
			}
			break
		default:
			server.logger.Info(fmt.Sprintln(
				"BGPServer:getAggPrefix - Not a known condition type"))
			break
		}
	}
	return ipPrefix
}

func (server *BGPServer) setUpdatedAddPaths(policyParams *PolicyParams,
	updatedAddPaths []*bgprib.Destination) {
	if len(updatedAddPaths) > 0 {
		addPathsMap := make(map[*bgprib.Destination]bool)
		for _, dest := range *(policyParams.updatedAddPaths) {
			addPathsMap[dest] = true
		}

		for _, dest := range updatedAddPaths {
			if !addPathsMap[dest] {
				(*policyParams.updatedAddPaths) =
					append((*policyParams.updatedAddPaths), dest)
			}
		}
	}
}

func (server *BGPServer) setWithdrawnWithAggPaths(policyParams *PolicyParams, withdrawn []*bgprib.Destination,
	sendSummaryOnly bool, updatedAddPaths []*bgprib.Destination) {
	destMap := make(map[*bgprib.Destination]bool)
	for _, dest := range *policyParams.withdrawn {
		destMap[dest] = true
	}

	aggDestMap := make(map[*bgprib.Destination]bool)
	for _, aggDestination := range withdrawn {
		aggDestMap[aggDestination] = true
		if !destMap[aggDestination] {
			server.logger.Info(fmt.Sprintf("setWithdrawnWithAggPaths: add agg dest %+v to withdrawn",
				aggDestination.NLRI.GetPrefix()))
			(*policyParams.withdrawn) = append((*policyParams.withdrawn), aggDestination)
		}
	}

	// There will be only one destination per aggregated path.
	// So, break out of the loop as soon as we find it.
	for protoFamily, pathDestMap := range *policyParams.updated {
		for path, destinations := range pathDestMap {
			for idx, dest := range destinations {
				if aggDestMap[dest] {
					(*policyParams.updated)[protoFamily][path][idx] = nil
					server.logger.Info(fmt.Sprintf("setWithdrawnWithAggPaths: remove dest %+v from withdrawn",
						dest.NLRI.GetPrefix()))
				}
			}
		}
	}

	if sendSummaryOnly {
		if policyParams.DeleteType == utilspolicy.Valid {
			for idx, dest := range *policyParams.withdrawn {
				if dest == policyParams.dest {
					server.logger.Info(fmt.Sprintf("setWithdrawnWithAggPaths: remove dest %+v from withdrawn",
						dest.NLRI.GetPrefix()))
					(*policyParams.withdrawn)[idx] = nil
				}
			}
		} else if policyParams.CreateType == utilspolicy.Invalid {
			if policyParams.dest != nil && policyParams.dest.LocRibPath != nil {
				found := false
				protoFamily := policyParams.dest.GetProtocolFamily()
				if destinations, ok :=
					(*policyParams.updated)[protoFamily][policyParams.dest.LocRibPath]; ok {
					for _, dest := range destinations {
						if dest == policyParams.dest {
							found = true
						}
					}
				} else {
					(*policyParams.updated)[protoFamily][policyParams.dest.LocRibPath] = make([]*bgprib.Destination, 0)
				}
				if !found {
					server.logger.Info(fmt.Sprintf("setWithdrawnWithAggPaths: add dest %+v to update",
						policyParams.dest.NLRI.GetPrefix()))
					(*policyParams.updated)[protoFamily][policyParams.dest.LocRibPath] = append(
						(*policyParams.updated)[protoFamily][policyParams.dest.LocRibPath], policyParams.dest)
				}
			}
		}
	}

	server.setUpdatedAddPaths(policyParams, updatedAddPaths)
}

func (server *BGPServer) setUpdatedWithAggPaths(policyParams *PolicyParams,
	updated map[uint32]map[*bgprib.Path][]*bgprib.Destination, sendSummaryOnly bool, ipPrefix *packet.IPPrefix,
	protoFamily uint32, updatedAddPaths []*bgprib.Destination) {
	var routeDest *bgprib.Destination
	var ok bool
	if routeDest, ok = server.LocRib.GetDest(ipPrefix, protoFamily, false); !ok {
		server.logger.Err(fmt.Sprintln("setUpdatedWithAggPaths: Did not find destination for ip", ipPrefix))
		if policyParams.dest != nil {
			routeDest = policyParams.dest
		} else {
			sendSummaryOnly = false
		}
	}

	withdrawMap := make(map[*bgprib.Destination]bool, len(*policyParams.withdrawn))
	if sendSummaryOnly {
		for _, dest := range *policyParams.withdrawn {
			withdrawMap[dest] = true
		}
	}

	for aggFamily, aggPathDestMap := range updated {
		for aggPath, aggDestinations := range aggPathDestMap {
			destMap := make(map[*bgprib.Destination]bool)
			ppUpdated := *policyParams.updated
			if _, ok := ppUpdated[aggFamily][aggPath]; !ok {
				ppUpdated[aggFamily][aggPath] = make([]*bgprib.Destination, 0)
			} else {
				for _, dest := range ppUpdated[aggFamily][aggPath] {
					destMap[dest] = true
				}
			}

			for _, dest := range aggDestinations {
				if !destMap[dest] {
					server.logger.Info(fmt.Sprintf("setUpdatedWithAggPaths: add agg dest %+v to updated",
						dest.NLRI.GetPrefix()))
					ppUpdated[aggFamily][aggPath] = append(ppUpdated[aggFamily][aggPath], dest)
				}
			}

			if sendSummaryOnly {
				if policyParams.CreateType == utilspolicy.Valid {
					if pathDestMap, ok := ppUpdated[protoFamily]; ok {
						for path, destinations := range pathDestMap {
							for idx, dest := range destinations {
								if routeDest == dest {
									ppUpdated[protoFamily][path][idx] = nil
									server.logger.Info(fmt.Sprintf("setUpdatedWithAggPaths: summaryOnly, remove dest %+v"+
										" from updated\n", dest.NLRI.GetPrefix()))
								}
							}
						}
					}
				} else if policyParams.DeleteType == utilspolicy.Invalid {
					if !withdrawMap[routeDest] {
						server.logger.Info(fmt.Sprintf("setUpdatedWithAggPaths: summaryOnly, add dest %+v to withdrawn\n",
							routeDest.NLRI.GetPrefix()))
						(*policyParams.withdrawn) = append((*policyParams.withdrawn), routeDest)
					}
				}
			}
		}
	}

	server.setUpdatedAddPaths(policyParams, updatedAddPaths)
}

func (server *BGPServer) UndoAggregateAction(actionInfo interface{},
	conditionList []interface{}, params interface{}, policyStmt utilspolicy.PolicyStmt) {
	policyParams := params.(PolicyParams)
	ipPrefix := packet.NewIPPrefix(net.ParseIP(policyParams.route.Dest.BGPRouteState.Network),
		uint8(policyParams.route.Dest.BGPRouteState.CIDRLen))
	protoFamily := policyParams.route.Dest.GetProtocolFamily()
	aggPrefix := server.getAggPrefix(conditionList)
	aggActions := actionInfo.(utilspolicy.PolicyAggregateActionInfo)
	bgpAgg := config.BGPAggregate{
		GenerateASSet:   aggActions.GenerateASSet,
		SendSummaryOnly: aggActions.SendSummaryOnly,
	}

	server.logger.Info(fmt.Sprintf("UndoAggregateAction: ipPrefix=%+v, aggPrefix=%+v\n",
		ipPrefix.Prefix, aggPrefix.Prefix))
	var updated map[uint32]map[*bgprib.Path][]*bgprib.Destination
	var withdrawn []*bgprib.Destination
	var updatedAddPaths []*bgprib.Destination
	var origDest *bgprib.Destination
	if policyParams.dest != nil {
		origDest = policyParams.dest
	}
	updated, withdrawn, updatedAddPaths = server.LocRib.RemoveRouteFromAggregate(ipPrefix, aggPrefix,
		server.BgpConfig.Global.Config.RouterId.String(), protoFamily, &bgpAgg, origDest, server.AddPathCount)

	server.logger.Info(fmt.Sprintf("UndoAggregateAction: aggregate result update=%+v, withdrawn=%+v\n", updated,
		withdrawn))
	server.setWithdrawnWithAggPaths(&policyParams, withdrawn, aggActions.SendSummaryOnly, updatedAddPaths)
	server.logger.Info(fmt.Sprintf("UndoAggregateAction: after updating withdraw agg paths, update=%+v, withdrawn=%+v,",
		"policyparams.update=%+v, policyparams.withdrawn=%+v\n", updated, withdrawn, *policyParams.updated,
		*policyParams.withdrawn))
	return
}

func (server *BGPServer) ApplyAggregateAction(actionInfo interface{},
	conditionInfo []interface{}, params interface{}) {
	policyParams := params.(PolicyParams)
	ipPrefix := packet.NewIPPrefix(net.ParseIP(policyParams.route.Dest.BGPRouteState.Network),
		uint8(policyParams.route.Dest.BGPRouteState.CIDRLen))
	protoFamily := policyParams.route.Dest.GetProtocolFamily()
	aggPrefix := server.getAggPrefix(conditionInfo)
	aggActions := actionInfo.(utilspolicy.PolicyAggregateActionInfo)
	bgpAgg := config.BGPAggregate{
		GenerateASSet:   aggActions.GenerateASSet,
		SendSummaryOnly: aggActions.SendSummaryOnly,
	}

	server.logger.Info(fmt.Sprintf("ApplyAggregateAction: ipPrefix=%+v, aggPrefix=%+v\n", ipPrefix.Prefix, aggPrefix.Prefix))
	var updated map[uint32]map[*bgprib.Path][]*bgprib.Destination
	var withdrawn []*bgprib.Destination
	var updatedAddPaths []*bgprib.Destination
	if (policyParams.CreateType == utilspolicy.Valid) ||
		(policyParams.DeleteType == utilspolicy.Invalid) {
		server.logger.Info(fmt.Sprintf("ApplyAggregateAction: CreateType= Valid or DeleteType = Invalid"))
		updated, withdrawn, updatedAddPaths = server.LocRib.AddRouteToAggregate(ipPrefix, aggPrefix,
			server.BgpConfig.Global.Config.RouterId.String(), protoFamily, server.ifaceIP, &bgpAgg, server.AddPathCount)
	} else if policyParams.DeleteType == utilspolicy.Valid {
		server.logger.Info(fmt.Sprintf("ApplyAggregateAction: DeleteType = Valid"))
		origDest := policyParams.dest
		updated, withdrawn, updatedAddPaths = server.LocRib.RemoveRouteFromAggregate(ipPrefix, aggPrefix,
			server.BgpConfig.Global.Config.RouterId.String(), protoFamily, &bgpAgg, origDest, server.AddPathCount)
	}

	server.logger.Info(fmt.Sprintf("ApplyAggregateAction: aggregate result update=%+v, withdrawn=%+v", updated, withdrawn))
	server.setUpdatedWithAggPaths(&policyParams, updated, aggActions.SendSummaryOnly, ipPrefix, protoFamily,
		updatedAddPaths)
	server.logger.Info(fmt.Sprintf("ApplyAggregateAction: after updating agg paths, update=%+v, withdrawn=%+v, ",
		"policyparams.update=%+v, policyparams.withdrawn=%+v", updated, withdrawn, *policyParams.updated,
		*policyParams.withdrawn))
	return
}

func (server *BGPServer) CheckForAggregation(updated map[uint32]map[*bgprib.Path][]*bgprib.Destination, withdrawn,
	updatedAddPaths []*bgprib.Destination) (map[uint32]map[*bgprib.Path][]*bgprib.Destination, []*bgprib.Destination,
	[]*bgprib.Destination) {
	server.logger.Info(fmt.Sprintf("BGPServer:checkForAggregate - start, updated %v withdrawn %v", updated, withdrawn))

	for _, dest := range withdrawn {
		if dest == nil || dest.LocRibPath == nil || dest.LocRibPath.IsAggregate() {
			continue
		}

		route := dest.GetLocRibPathRoute()
		if route == nil {
			server.logger.Info(fmt.Sprintf("BGPServer:checkForAggregate - route not found withdraw dest %s",
				dest.NLRI.GetPrefix().String()))
			continue
		}
		peEntity := utilspolicy.PolicyEngineFilterEntityParams{
			DestNetIp:  route.Dest.BGPRouteState.Network + "/" + strconv.Itoa(int(route.Dest.BGPRouteState.CIDRLen)),
			NextHopIp:  route.PathInfo.NextHop,
			DeletePath: true,
		}
		server.logger.Info(fmt.Sprintf("BGPServer:checkForAggregate - withdraw dest %s policylist %v hit %v before ",
			"applying delete policy", dest.NLRI.GetPrefix().String(), route.PolicyList, route.PolicyHitCounter))
		callbackInfo := PolicyParams{
			CreateType:      utilspolicy.Invalid,
			DeleteType:      utilspolicy.Valid,
			route:           route,
			dest:            dest,
			updated:         &updated,
			withdrawn:       &withdrawn,
			updatedAddPaths: &updatedAddPaths,
		}
		server.locRibPE.PolicyEngine.PolicyEngineFilter(peEntity, policyCommonDefs.PolicyPath_Export, callbackInfo)
	}

	for _, pathDestMap := range updated {
		for _, destinations := range pathDestMap {
			server.logger.Info(fmt.Sprintf("BGPServer:checkForAggregate - update destinations %+v", destinations))
			for _, dest := range destinations {
				server.logger.Info(fmt.Sprintf("BGPServer:checkForAggregate - update dest %+v", dest.NLRI.GetPrefix()))
				if dest == nil || dest.LocRibPath == nil || dest.LocRibPath.IsAggregate() {
					continue
				}
				route := dest.GetLocRibPathRoute()
				server.logger.Info(fmt.Sprintf("BGPServer:checkForAggregate - update dest %s policylist %v hit %v before ",
					"applying create policy\n", dest.NLRI.GetPrefix().String(), route.PolicyList, route.PolicyHitCounter))
				if route != nil {
					peEntity := utilspolicy.PolicyEngineFilterEntityParams{
						DestNetIp:  route.Dest.BGPRouteState.Network + "/" + strconv.Itoa(int(route.Dest.BGPRouteState.CIDRLen)),
						NextHopIp:  route.PathInfo.NextHop,
						CreatePath: true,
					}
					callbackInfo := PolicyParams{
						CreateType:      utilspolicy.Valid,
						DeleteType:      utilspolicy.Invalid,
						route:           route,
						dest:            dest,
						updated:         &updated,
						withdrawn:       &withdrawn,
						updatedAddPaths: &updatedAddPaths,
					}
					server.locRibPE.PolicyEngine.PolicyEngineFilter(peEntity, policyCommonDefs.PolicyPath_Export, callbackInfo)
					server.logger.Info(fmt.Sprintf("BGPServer:checkForAggregate - update dest %s policylist %v hit %v ",
						"after applying create policy\n", dest.NLRI.GetPrefix().String(), route.PolicyList,
						route.PolicyHitCounter))
				}
			}
		}
	}

	server.logger.Info(fmt.Sprintf("BGPServer:checkForAggregate - complete, updated %v withdrawn %v\n",
		updated, withdrawn))
	return updated, withdrawn, updatedAddPaths
}

func (server *BGPServer) UpdateRouteAndPolicyDB(policyDetails utilspolicy.PolicyDetails, params interface{}) {
	policyParams := params.(PolicyParams)
	var op int
	if policyParams.DeleteType != bgppolicy.Invalid {
		op = bgppolicy.Del
	} else {
		if policyDetails.EntityDeleted == false {
			server.logger.Info(fmt.Sprintln("Reject action was not applied, so add this policy to the route"))
			op = bgppolicy.Add
			bgppolicy.UpdateRoutePolicyState(policyParams.route, op, policyDetails.Policy, policyDetails.PolicyStmt)
		}
		policyParams.route.PolicyHitCounter++
	}
	server.locRibPE.UpdatePolicyRouteMap(policyParams.route, policyDetails.Policy, op)
}

func (server *BGPServer) TraverseAndApplyBGPRib(data interface{}, updateFunc utilspolicy.PolicyApplyfunc) {
	server.logger.Info(fmt.Sprintf("BGPServer:TraverseRibForPolicies - start"))
	policy := data.(utilspolicy.ApplyPolicyInfo)
	updated := make(map[uint32]map[*bgprib.Path][]*bgprib.Destination, 10)
	withdrawn := make([]*bgprib.Destination, 0, 10)
	updatedAddPaths := make([]*bgprib.Destination, 0)
	locRib := server.LocRib.GetLocRib()
	for _, pathDestMap := range locRib {
		for path, destinations := range pathDestMap {
			for _, dest := range destinations {
				if !path.IsAggregatePath() {
					route := dest.GetLocRibPathRoute()
					if route == nil {
						continue
					}
					peEntity := utilspolicy.PolicyEngineFilterEntityParams{
						DestNetIp: route.Dest.BGPRouteState.Network + "/" +
							strconv.Itoa(int(route.Dest.BGPRouteState.CIDRLen)),
						NextHopIp:  route.PathInfo.NextHop,
						PolicyList: route.PolicyList,
					}
					callbackInfo := PolicyParams{
						route:           route,
						dest:            dest,
						updated:         &updated,
						withdrawn:       &withdrawn,
						updatedAddPaths: &updatedAddPaths,
					}

					updateFunc(peEntity, policy, callbackInfo)
				}
			}
		}
	}
	server.logger.Info(fmt.Sprintf("BGPServer:TraverseRibForPolicies - updated %v withdrawn %v",
		updated, withdrawn))
	server.SendUpdate(updated, withdrawn, updatedAddPaths)
}

func (server *BGPServer) TraverseAndReverseBGPRib(policyData interface{}) {
	policy := policyData.(utilspolicy.Policy)
	server.logger.Info(fmt.Sprintln("BGPServer:TraverseAndReverseBGPRib - policy",
		policy.Name))
	policyExtensions := policy.Extensions.(bgppolicy.PolicyExtensions)
	if len(policyExtensions.RouteList) == 0 {
		fmt.Println("No route affected by this policy, so nothing to do")
		return
	}

	updated := make(map[uint32]map[*bgprib.Path][]*bgprib.Destination, 10)
	withdrawn := make([]*bgprib.Destination, 0, 10)
	updatedAddPaths := make([]*bgprib.Destination, 0)
	var route *bgprib.Route
	for idx := 0; idx < len(policyExtensions.RouteInfoList); idx++ {
		route = policyExtensions.RouteInfoList[idx]
		dest := server.LocRib.GetDestFromIPAndLen(route.Dest.GetProtocolFamily(), route.Dest.BGPRouteState.Network,
			uint32(route.Dest.BGPRouteState.CIDRLen))
		callbackInfo := PolicyParams{
			route:           route,
			dest:            dest,
			updated:         &updated,
			withdrawn:       &withdrawn,
			updatedAddPaths: &updatedAddPaths,
		}
		peEntity := utilspolicy.PolicyEngineFilterEntityParams{
			DestNetIp: route.Dest.BGPRouteState.Network + "/" + strconv.Itoa(int(route.Dest.BGPRouteState.CIDRLen)),
			NextHopIp: route.PathInfo.NextHop,
		}

		ipPrefix, err := bgppolicy.GetNetworkPrefixFromCIDR(route.Dest.BGPRouteState.Network + "/" +
			strconv.Itoa(int(route.Dest.BGPRouteState.CIDRLen)))
		if err != nil {
			server.logger.Info(fmt.Sprintln("Invalid route ", ipPrefix))
			continue
		}
		server.locRibPE.PolicyEngine.PolicyEngineUndoPolicyForEntity(peEntity, policy, callbackInfo)
		server.locRibPE.DeleteRoutePolicyState(route, policy.Name)
		server.locRibPE.PolicyEngine.DeletePolicyEntityMapEntry(peEntity, policy.Name)
	}
}

func (server *BGPServer) ProcessUpdate(pktInfo *packet.BGPPktSrc) {
	peer, ok := server.PeerMap[pktInfo.Src]
	if !ok {
		server.logger.Err(fmt.Sprintln("BgpServer:ProcessUpdate - Peer not found, address:", pktInfo.Src))
		return
	}

	atomic.AddUint32(&peer.NeighborConf.Neighbor.State.Queues.Input, ^uint32(0))
	peer.NeighborConf.Neighbor.State.Messages.Received.Update++
	updated, withdrawn, updatedAddPaths, addedAllPrefixes := server.LocRib.ProcessUpdate(
		peer.NeighborConf, pktInfo, server.AddPathCount)
	if !addedAllPrefixes {
		peer.MaxPrefixesExceeded()
	}
	updated, withdrawn, updatedAddPaths = server.CheckForAggregation(updated, withdrawn, updatedAddPaths)
	server.SendUpdate(updated, withdrawn, updatedAddPaths)
}

func (server *BGPServer) convertDestIPToIPPrefix(routes []*config.RouteInfo) map[uint32][]packet.NLRI {
	pfNLRI := make(map[uint32][]packet.NLRI)
	for _, r := range routes {
		ip := net.ParseIP(r.IPAddr)
		if ip == nil {
			server.logger.Err(fmt.Sprintf("Connected route %s/%s is not a valid IP", r.IPAddr, r.Mask))
			continue
		}

		var protoFamily uint32
		if ip.To4() != nil {
			protoFamily = packet.GetProtocolFamily(packet.AfiIP, packet.SafiUnicast)
		} else {
			protoFamily = packet.GetProtocolFamily(packet.AfiIP6, packet.SafiUnicast)
		}

		server.logger.Info(fmt.Sprintf("Connected route: addr %s netmask %s", r.IPAddr, r.Mask))
		if _, ok := pfNLRI[protoFamily]; !ok {
			pfNLRI[protoFamily] = make([]packet.NLRI, 0)
		}

		ipPrefix := packet.ConstructIPPrefix(r.IPAddr, r.Mask)
		pfNLRI[protoFamily] = append(pfNLRI[protoFamily], ipPrefix)
	}
	return pfNLRI
}

func (server *BGPServer) ProcessConnectedRoutes(installedRoutes, withdrawnRoutes []*config.RouteInfo) {
	server.logger.Info(fmt.Sprintln("valid routes:", installedRoutes, "invalid routes:", withdrawnRoutes))
	valid := server.convertDestIPToIPPrefix(installedRoutes)
	invalid := server.convertDestIPToIPPrefix(withdrawnRoutes)
	server.logger.Info(fmt.Sprintln("pfNLRI valid:", valid, "invalid:", invalid))
	routerId := server.BgpConfig.Global.Config.RouterId.String()
	updated, withdrawn, updatedAddPaths := server.LocRib.ProcessConnectedRoutes(routerId, server.ConnRoutesPath, valid,
		invalid, server.AddPathCount)
	updated, withdrawn, updatedAddPaths = server.CheckForAggregation(updated, withdrawn, updatedAddPaths)
	server.SendUpdate(updated, withdrawn, updatedAddPaths)
}

func (server *BGPServer) ProcessIntfStates(intfs []*config.IntfStateInfo) {
	for _, ifState := range intfs {
		if ifState.State == config.INTF_CREATED {
			server.ifaceMgr.AddIface(ifState.Idx, ifState.IPAddr)
		} else if ifState.State == config.INTF_DELETED {
			server.ifaceMgr.RemoveIface(ifState.Idx, ifState.IPAddr)
		}
	}
}

func (server *BGPServer) ProcessRemoveNeighbor(peerIp string, peer *Peer) {
	updated, withdrawn, updatedAddPaths := server.LocRib.RemoveUpdatesFromNeighbor(peerIp, peer.NeighborConf,
		server.AddPathCount)
	server.logger.Info(fmt.Sprintf("ProcessRemoveNeighbor - Neighbor %s, send updated paths %v, withdrawn paths %v\n",
		peerIp, updated, withdrawn))
	updated, withdrawn, updatedAddPaths = server.CheckForAggregation(updated, withdrawn, updatedAddPaths)
	server.SendUpdate(updated, withdrawn, updatedAddPaths)
}

func (server *BGPServer) SendAllRoutesToPeer(peer *Peer) {
	withdrawn := make([]*bgprib.Destination, 0)
	updatedAddPaths := make([]*bgprib.Destination, 0)
	updated := server.LocRib.GetLocRib()
	server.SendUpdate(updated, withdrawn, updatedAddPaths)
}

func (server *BGPServer) RemoveRoutesFromAllNeighbor() {
	server.LocRib.RemoveUpdatesFromAllNeighbors(server.AddPathCount)
}

func (server *BGPServer) addPeerToList(peer *Peer) {
	server.Neighbors = append(server.Neighbors, peer)
}

func (server *BGPServer) removePeerFromList(peer *Peer) {
	for idx, item := range server.Neighbors {
		if item == peer {
			server.Neighbors[idx] = server.Neighbors[len(server.Neighbors)-1]
			server.Neighbors[len(server.Neighbors)-1] = nil
			server.Neighbors = server.Neighbors[:len(server.Neighbors)-1]
			break
		}
	}
}

func (server *BGPServer) StopPeersByGroup(groupName string) []*Peer {
	peers := make([]*Peer, 0)
	for peerIP, peer := range server.PeerMap {
		if peer.NeighborConf.Group != nil && peer.NeighborConf.Group.Name == groupName {
			server.logger.Info(fmt.Sprintln("Clean up peer", peerIP))
			peer.Cleanup()
			server.ProcessRemoveNeighbor(peerIP, peer)
			peers = append(peers, peer)

			runtime.Gosched()
		}
	}

	return peers
}

func (server *BGPServer) UpdatePeerGroupInPeers(groupName string, peerGroup *config.PeerGroupConfig) {
	peers := server.StopPeersByGroup(groupName)
	for _, peer := range peers {
		peer.UpdatePeerGroup(peerGroup)
		peer.Init()
	}
}

func (server *BGPServer) SetupRedistribution(gConf config.GlobalConfig) {
	server.logger.Info("SetUpRedistribution")
	if gConf.Redistribution == nil || len(gConf.Redistribution) == 0 {
		server.logger.Info("No redistribution policies configured")
		return
	}
	conditions := make([]*config.ConditionInfo, 0)
	for i := 0; i < len(gConf.Redistribution); i++ {
		server.logger.Info(fmt.Sprintln("Sources: ", gConf.Redistribution[i].Sources))
		sources := make([]string, 0)
		sources = strings.Split(gConf.Redistribution[i].Sources, ",")
		server.logger.Info(fmt.Sprintf("Setting up %s as redistribution policy for source(s): ", gConf.Redistribution[i].Policy))
		for j := 0; j < len(sources); j++ {
			server.logger.Info(fmt.Sprintf("%s ", sources[j]))
			if sources[j] == "" {
				continue
			}
			conditions = append(conditions, &config.ConditionInfo{ConditionType: "MatchProtocol", Protocol: sources[j]})
		}
		server.logger.Info(fmt.Sprintln(""))
		server.routeMgr.ApplyPolicy("BGP", gConf.Redistribution[i].Policy, "Redistribution", conditions)
	}
}

func (server *BGPServer) DeleteAgg(ipPrefix string) error {
	server.locRibPE.DeletePolicyDefinition(ipPrefix)
	server.locRibPE.DeletePolicyStmt(ipPrefix)
	server.locRibPE.DeletePolicyCondition(ipPrefix)
	return nil
}

func (server *BGPServer) AddOrUpdateAgg(oldConf config.BGPAggregate, newConf config.BGPAggregate, attrSet []bool) error {
	server.logger.Info("AddOrUpdateAgg")
	var err error

	if oldConf.IPPrefix != "" {
		// Delete the policy
		server.DeleteAgg(oldConf.IPPrefix)
	}

	if newConf.IPPrefix != "" {
		// Create the policy
		name := newConf.IPPrefix
		tokens := strings.Split(newConf.IPPrefix, "/")
		prefixLen := tokens[1]
		prefixLenInt, err := strconv.Atoi(prefixLen)
		if err != nil {
			server.logger.Err(fmt.Sprintf("Failed to convert prefex len %s to int with error %s", prefixLen, err))
			return err
		}

		cond := utilspolicy.PolicyConditionConfig{
			Name:          name,
			ConditionType: "MatchDstIpPrefix",
			MatchDstIpPrefixConditionInfo: utilspolicy.PolicyDstIpMatchPrefixSetCondition{
				Prefix: utilspolicy.PolicyPrefix{
					IpPrefix:        newConf.IPPrefix,
					MasklengthRange: prefixLen + "-32",
				},
			},
		}

		_, err = server.locRibPE.CreatePolicyCondition(cond)
		if err != nil {
			server.logger.Err(fmt.Sprintf("Failed to create policy condition for aggregate %s with error %s", name, err))
			return err
		}

		stmt := utilspolicy.PolicyStmtConfig{Name: name, MatchConditions: "all"}
		stmt.Conditions = make([]string, 1)
		stmt.Conditions[0] = name
		stmt.Actions = make([]string, 1)
		stmt.Actions[0] = "permit"
		err = server.locRibPE.CreatePolicyStmt(stmt)
		if err != nil {
			server.logger.Err(fmt.Sprintf("Failed to create policy statement for aggregate %s with error %s", name, err))
			server.locRibPE.DeletePolicyCondition(name)
			return err
		}

		def := utilspolicy.PolicyDefinitionConfig{Name: name, Precedence: prefixLenInt, MatchType: "all"}
		def.PolicyDefinitionStatements = make([]utilspolicy.PolicyDefinitionStmtPrecedence, 1)
		policyDefinitionStatement := utilspolicy.PolicyDefinitionStmtPrecedence{
			Precedence: 1,
			Statement:  name,
		}
		def.PolicyDefinitionStatements[0] = policyDefinitionStatement
		def.Extensions = bgppolicy.PolicyExtensions{}
		err = server.locRibPE.CreatePolicyDefinition(def)
		if err != nil {
			server.logger.Err(fmt.Sprintf("Failed to create policy definition for aggregate %s with error %s", name, err))
			server.locRibPE.DeletePolicyStmt(name)
			server.locRibPE.DeletePolicyCondition(name)
			return err
		}

		err = server.UpdateAggPolicy(name, server.locRibPE, newConf)
		return err
	}
	return err
}

func (server *BGPServer) UpdateAggPolicy(policyName string, pe bgppolicy.BGPPolicyEngine, aggConf config.BGPAggregate) error {
	server.logger.Debug(fmt.Sprintln("UpdateApplyPolicy"))
	var err error
	var policyAction utilspolicy.PolicyAction
	conditionNameList := make([]string, 0)

	policyEngine := pe.GetPolicyEngine()
	policyDB := policyEngine.PolicyDB

	nodeGet := policyDB.Get(patriciaDB.Prefix(policyName))
	if nodeGet == nil {
		server.logger.Err(fmt.Sprintln("Policy ", policyName, " not defined"))
		return errors.New(fmt.Sprintf("Policy %s not found in policy engine", policyName))
	}
	node := nodeGet.(utilspolicy.Policy)

	aggregateActionInfo := utilspolicy.PolicyAggregateActionInfo{aggConf.GenerateASSet, aggConf.SendSummaryOnly}
	policyAction = utilspolicy.PolicyAction{
		Name:       aggConf.IPPrefix,
		ActionType: policyCommonDefs.PolicyActionTypeAggregate,
		ActionInfo: aggregateActionInfo,
	}

	server.logger.Debug(fmt.Sprintln("Calling applypolicy with conditionNameList: ", conditionNameList))
	pe.UpdateApplyPolicy(utilspolicy.ApplyPolicyInfo{node, policyAction, conditionNameList}, true)
	return err
}

func (server *BGPServer) copyGlobalConf(gConf config.GlobalConfig) {
	server.BgpConfig.Global.Config.AS = gConf.AS
	server.BgpConfig.Global.Config.RouterId = gConf.RouterId
	server.BgpConfig.Global.Config.UseMultiplePaths = gConf.UseMultiplePaths
	server.BgpConfig.Global.Config.EBGPMaxPaths = gConf.EBGPMaxPaths
	server.BgpConfig.Global.Config.EBGPAllowMultipleAS = gConf.EBGPAllowMultipleAS
	server.BgpConfig.Global.Config.IBGPMaxPaths = gConf.IBGPMaxPaths
}

func (server *BGPServer) handleBfdNotifications(oper config.Operation, DestIp string,
	State bool) {
	if peer, ok := server.PeerMap[DestIp]; ok {
		if !State && peer.NeighborConf.Neighbor.State.BfdNeighborState == "up" {
			peer.NeighborConf.BfdFaultSet()
			peer.Command(int(fsm.BGPEventManualStop), fsm.BGPCmdReasonNone)
		}
		if State && peer.NeighborConf.Neighbor.State.BfdNeighborState == "down" {
			peer.NeighborConf.BfdFaultCleared()
			peer.Command(int(fsm.BGPEventManualStart), fsm.BGPCmdReasonNone)
		}
		server.logger.Info(fmt.Sprintln("Bfd state of peer ",
			peer.NeighborConf.Neighbor.NeighborAddress, " is ",
			peer.NeighborConf.Neighbor.State.BfdNeighborState))
	}
}

func (server *BGPServer) setInterfaceMapForPeer(peerIP string, peer *Peer) {
	server.logger.Info(fmt.Sprintln("Server: setInterfaceMapForPeer Peer", peer,
		"calling GetRouteReachabilityInfo"))
	reachInfo, err := server.routeMgr.GetNextHopInfo(peerIP)
	server.logger.Info(fmt.Sprintln("Server: setInterfaceMapForPeer Peer",
		peer, "GetRouteReachabilityInfo returned", reachInfo))
	if err != nil {
		server.logger.Info(fmt.Sprintf("Server: Peer %s is not reachable", peerIP))
	} else {
		// @TODO: jgheewala think of something better for ovsdb....
		ifIdx := server.IntfMgr.GetIfIndex(int(reachInfo.NextHopIfIndex),
			int(reachInfo.NextHopIfType))
		///		ifIdx := asicdCommonDefs.GetIfIndexFromIntfIdAndIntfType(int(reachInfo.NextHopIfIndex), int(reachInfo.NextHopIfType))
		server.logger.Info(fmt.Sprintf("Server: Peer %s IfIdx %d", peerIP, ifIdx))
		if _, ok := server.IfacePeerMap[ifIdx]; !ok {
			server.IfacePeerMap[ifIdx] = make([]string, 0)
		}
		server.IfacePeerMap[ifIdx] = append(server.IfacePeerMap[ifIdx], peerIP)
		peer.setIfIdx(ifIdx)
	}
}

func (server *BGPServer) clearInterfaceMapForPeer(peerIP string, peer *Peer) {
	ifIdx := peer.getIfIdx()
	server.logger.Info(fmt.Sprintf("Server: Peer %s FSM connection broken ifIdx %v", peerIP, ifIdx))
	if peerList, ok := server.IfacePeerMap[ifIdx]; ok {
		for idx, ip := range peerList {
			if ip == peerIP {
				server.IfacePeerMap[ifIdx] = append(server.IfacePeerMap[ifIdx][:idx],
					server.IfacePeerMap[ifIdx][idx+1:]...)
				if len(server.IfacePeerMap[ifIdx]) == 0 {
					delete(server.IfacePeerMap, ifIdx)
				}
				break
			}
		}
	}
	peer.setIfIdx(-1)
}

func (server *BGPServer) constructBGPGlobalState(gConf *config.GlobalConfig) {
	server.BgpConfig.Global.State.AS = gConf.AS
	server.BgpConfig.Global.State.RouterId = gConf.RouterId
	server.BgpConfig.Global.State.UseMultiplePaths = gConf.UseMultiplePaths
	server.BgpConfig.Global.State.EBGPMaxPaths = gConf.EBGPMaxPaths
	server.BgpConfig.Global.State.EBGPAllowMultipleAS = gConf.EBGPAllowMultipleAS
	server.BgpConfig.Global.State.IBGPMaxPaths = gConf.IBGPMaxPaths
}

func (server *BGPServer) listenChannelUpdates() {
	for {
		select {
		case globalUpdate := <-server.GlobalConfigCh:
			for peerIP, peer := range server.PeerMap {
				server.logger.Info(fmt.Sprintf("Cleanup peer %s", peerIP))
				peer.Cleanup()
			}
			server.logger.Info(fmt.Sprintf("Giving up CPU so that all peer FSMs",
				"will get cleaned up"))
			runtime.Gosched()

			gConf := globalUpdate.NewConfig
			packet.SetNextHopPathAttrs(server.ConnRoutesPath.PathAttrs, gConf.RouterId)
			server.RemoveRoutesFromAllNeighbor()
			server.copyGlobalConf(gConf)
			server.constructBGPGlobalState(&gConf)
			for _, peer := range server.PeerMap {
				peer.Init()
			}
			server.SetupRedistribution(gConf)

		case peerUpdate := <-server.AddPeerCh:
			server.logger.Info("message received on AddPeerCh")
			oldPeer := peerUpdate.OldPeer
			newPeer := peerUpdate.NewPeer
			var peer *Peer
			var ok bool
			if oldPeer.NeighborAddress != nil {
				if peer, ok = server.PeerMap[oldPeer.NeighborAddress.String()]; ok {
					server.logger.Info(fmt.Sprintln("Clean up peer", oldPeer.NeighborAddress.String()))
					peer.Cleanup()
					server.ProcessRemoveNeighbor(oldPeer.NeighborAddress.String(), peer)
					if peer.NeighborConf.RunningConf.AuthPassword != "" {
						err := netUtils.SetTCPListenerMD5(server.listener, oldPeer.NeighborAddress.String(), "")
						if err != nil {
							server.logger.Info(fmt.Sprintln("Failed to add MD5 authentication for old neighbor",
								newPeer.NeighborAddress.String(), "with error", err))
						}
					}
					peer.UpdateNeighborConf(newPeer, &server.BgpConfig)

					runtime.Gosched()
				} else {
					server.logger.Info(fmt.Sprintln("Can't find neighbor with old address",
						oldPeer.NeighborAddress.String()))
				}
			}

			if !ok {
				_, ok = server.PeerMap[newPeer.NeighborAddress.String()]
				if ok {
					server.logger.Info(fmt.Sprintln("Failed to add neighbor.",
						"Neighbor at that address already exists,",
						newPeer.NeighborAddress.String()))
					break
				}

				var groupConfig *config.PeerGroupConfig
				if newPeer.PeerGroup != "" {
					if group, ok :=
						server.BgpConfig.PeerGroups[newPeer.PeerGroup]; !ok {
						server.logger.Info(fmt.Sprintln("Peer group", newPeer.PeerGroup,
							"not created yet, creating peer", newPeer.NeighborAddress.String(), "without the group"))
					} else {
						groupConfig = &group.Config
					}
				}
				server.logger.Info(fmt.Sprintln("Add neighbor, ip:", newPeer.NeighborAddress.String()))
				peer = NewPeer(server, server.LocRib, &server.BgpConfig.Global.Config, groupConfig, newPeer)
				if peer.NeighborConf.RunningConf.AuthPassword != "" {
					err := netUtils.SetTCPListenerMD5(server.listener, newPeer.NeighborAddress.String(),
						peer.NeighborConf.RunningConf.AuthPassword)
					if err != nil {
						server.logger.Info(fmt.Sprintln("Failed to add MD5 authentication for neighbor",
							newPeer.NeighborAddress.String(), "with error", err))
					}
				}
				server.PeerMap[newPeer.NeighborAddress.String()] = peer
				server.NeighborMutex.Lock()
				server.addPeerToList(peer)
				server.NeighborMutex.Unlock()
			}
			peer.Init()

		case remPeer := <-server.RemPeerCh:
			server.logger.Info(fmt.Sprintln("Remove Peer:", remPeer))
			peer, ok := server.PeerMap[remPeer]
			if !ok {
				server.logger.Info(fmt.Sprintln("Failed to remove peer.",
					"Peer at that address does not exist,", remPeer))
				break
			}
			server.NeighborMutex.Lock()
			server.removePeerFromList(peer)
			server.NeighborMutex.Unlock()
			delete(server.PeerMap, remPeer)
			peer.Cleanup()
			server.ProcessRemoveNeighbor(remPeer, peer)

		case groupUpdate := <-server.AddPeerGroupCh:
			oldGroupConf := groupUpdate.OldGroup
			newGroupConf := groupUpdate.NewGroup
			server.logger.Info(fmt.Sprintln("Peer group update old:",
				oldGroupConf, "new:", newGroupConf))
			var ok bool

			if oldGroupConf.Name != "" {
				if _, ok = server.BgpConfig.PeerGroups[oldGroupConf.Name]; !ok {
					server.logger.Err(fmt.Sprintln("Could not find peer group",
						oldGroupConf.Name))
					break
				}
			}

			if _, ok = server.BgpConfig.PeerGroups[newGroupConf.Name]; !ok {
				server.logger.Info(fmt.Sprintln("Add new peer group with name",
					newGroupConf.Name))
				peerGroup := config.PeerGroup{
					Config: newGroupConf,
				}
				server.BgpConfig.PeerGroups[newGroupConf.Name] = &peerGroup
			}
			server.UpdatePeerGroupInPeers(newGroupConf.Name, &newGroupConf)

		case groupName := <-server.RemPeerGroupCh:
			server.logger.Info(fmt.Sprintln("Remove Peer group:", groupName))
			if _, ok := server.BgpConfig.PeerGroups[groupName]; !ok {
				server.logger.Info(fmt.Sprintln("Peer group", groupName, "not found"))
				break
			}
			delete(server.BgpConfig.PeerGroups, groupName)
			server.UpdatePeerGroupInPeers(groupName, nil)

		case aggUpdate := <-server.AddAggCh:
			oldAgg := aggUpdate.OldAgg
			newAgg := aggUpdate.NewAgg
			if newAgg.IPPrefix != "" {
				server.AddOrUpdateAgg(oldAgg, newAgg, aggUpdate.AttrSet)
			}

		case ipPrefix := <-server.RemAggCh:
			server.DeleteAgg(ipPrefix)

		case tcpConn := <-server.acceptCh:
			server.logger.Info(fmt.Sprintln("Connected to", tcpConn.RemoteAddr().String()))
			host, _, _ := net.SplitHostPort(tcpConn.RemoteAddr().String())
			peer, ok := server.PeerMap[host]
			if !ok {
				server.logger.Info(fmt.Sprintln("Can't accept connection.",
					"Peer is not configured yet", host))
				tcpConn.Close()
				server.logger.Info(fmt.Sprintln("Closed connection from", host))
				break
			}
			peer.AcceptConn(tcpConn)

		case peerCommand := <-server.PeerCommandCh:
			server.logger.Info(fmt.Sprintln("Peer Command received", peerCommand))
			peer, ok := server.PeerMap[peerCommand.IP.String()]
			if !ok {
				server.logger.Info(fmt.Sprintf("Failed to apply command %s.",
					"Peer at that address does not exist, %v\n",
					peerCommand.Command, peerCommand.IP))
			}
			peer.Command(peerCommand.Command, fsm.BGPCmdReasonNone)

		case peerFSMConn := <-server.PeerFSMConnCh:
			server.logger.Info(fmt.Sprintf("Server: Peer %s FSM established/broken",
				"channel\n", peerFSMConn.PeerIP))
			peer, ok := server.PeerMap[peerFSMConn.PeerIP]
			if !ok {
				server.logger.Info(fmt.Sprintf("Failed to process FSM connection",
					"success, Peer %s does not exist\n", peerFSMConn.PeerIP))
				break
			}

			if peerFSMConn.Established {
				peer.PeerConnEstablished(peerFSMConn.Conn)
				addPathsMaxTx := peer.getAddPathsMaxTx()
				if addPathsMaxTx > server.AddPathCount {
					server.AddPathCount = addPathsMaxTx
				}
				server.setInterfaceMapForPeer(peerFSMConn.PeerIP, peer)
				server.SendAllRoutesToPeer(peer)
			} else {
				peer.PeerConnBroken(true)
				addPathsMaxTx := peer.getAddPathsMaxTx()
				if addPathsMaxTx < server.AddPathCount {
					server.AddPathCount = 0
					for _, otherPeer := range server.PeerMap {
						addPathsMaxTx = otherPeer.getAddPathsMaxTx()
						if addPathsMaxTx > server.AddPathCount {
							server.AddPathCount = addPathsMaxTx
						}
					}
				}
				server.clearInterfaceMapForPeer(peerFSMConn.PeerIP, peer)
				server.ProcessRemoveNeighbor(peerFSMConn.PeerIP, peer)
			}

		case peerIP := <-server.PeerConnEstCh:
			server.logger.Info(fmt.Sprintf("Server: Peer %s FSM connection",
				"established", peerIP))
			peer, ok := server.PeerMap[peerIP]
			if !ok {
				server.logger.Info(fmt.Sprintf("Failed to process FSM",
					"connection success,",
					"Peer %s does not exist", peerIP))
				break
			}
			reachInfo, err := server.routeMgr.GetNextHopInfo(peerIP)
			if err != nil {
				server.logger.Info(fmt.Sprintf(
					"Server: Peer %s is not reachable", peerIP))
			} else {
				// @TODO: jgheewala think of something better for ovsdb....
				ifIdx := server.IntfMgr.GetIfIndex(int(reachInfo.NextHopIfIndex),
					int(reachInfo.NextHopIfType))
				server.logger.Info(fmt.Sprintf("Server: Peer %s IfIdx %d",
					peerIP, ifIdx))
				if _, ok := server.IfacePeerMap[ifIdx]; !ok {
					server.IfacePeerMap[ifIdx] = make([]string, 0)
					//ifIdx := asicdCommonDefs.GetIfIndexFromIntfIdAndIntfType(int(reachInfo.NextHopIfIndex), int(reachInfo.NextHopIfType))
				}
				server.IfacePeerMap[ifIdx] = append(server.IfacePeerMap[ifIdx],
					peerIP)
				peer.setIfIdx(ifIdx)
			}

			server.SendAllRoutesToPeer(peer)

		case peerIP := <-server.PeerConnBrokenCh:
			server.logger.Info(fmt.Sprintf("Server: Peer %s FSM connection broken",
				peerIP))
			peer, ok := server.PeerMap[peerIP]
			if !ok {
				server.logger.Info(fmt.Sprintf("Failed to process FSM",
					"connection failure,",
					"Peer %s does not exist", peerIP))
				break
			}
			ifIdx := peer.getIfIdx()
			server.logger.Info(fmt.Sprintf("Server: Peer %s FSM connection broken ifIdx %v",
				peerIP, ifIdx))
			if peerList, ok := server.IfacePeerMap[ifIdx]; ok {
				for idx, ip := range peerList {
					if ip == peerIP {
						server.IfacePeerMap[ifIdx] =
							append(server.IfacePeerMap[ifIdx][:idx],
								server.IfacePeerMap[ifIdx][idx+1:]...)
						if len(server.IfacePeerMap[ifIdx]) == 0 {
							delete(server.IfacePeerMap, ifIdx)
						}
						break
					}
				}
			}
			peer.setIfIdx(-1)
			server.ProcessRemoveNeighbor(peerIP, peer)

		case pktInfo := <-server.BGPPktSrcCh:
			server.logger.Info(fmt.Sprintln("Received BGP message from peer %s",
				pktInfo.Src))
			server.ProcessUpdate(pktInfo)

		case reachabilityInfo := <-server.ReachabilityCh:
			server.logger.Info(fmt.Sprintln("Server: Reachability info for ip",
				reachabilityInfo.IP))

			_, err := server.routeMgr.GetNextHopInfo(reachabilityInfo.IP)
			if err != nil {
				reachabilityInfo.ReachableCh <- false
			} else {
				reachabilityInfo.ReachableCh <- true
			}
		case bfdNotify := <-server.BfdCh:
			server.handleBfdNotifications(bfdNotify.Oper,
				bfdNotify.DestIp, bfdNotify.State)
		case ifState := <-server.IntfCh:
			if ifState.State == config.INTF_STATE_DOWN {
				if peerList, ok := server.IfacePeerMap[ifState.Idx]; ok {
					for _, peerIP := range peerList {
						if peer, ok := server.PeerMap[peerIP]; ok {
							peer.StopFSM("Interface Down")
						}
					}
				}
			} else if ifState.State == config.INTF_CREATED {
				server.ifaceMgr.AddIface(ifState.Idx, ifState.IPAddr)
			} else if ifState.State == config.INTF_DELETED {
				server.ifaceMgr.RemoveIface(ifState.Idx, ifState.IPAddr)
			}
		case routeInfo := <-server.RoutesCh:
			server.ProcessConnectedRoutes(routeInfo.Add, routeInfo.Remove)
		}
	}

}

func (server *BGPServer) InitBGPEvent() {
	// Start DB Util
	server.eventDbHdl = dbutils.NewDBUtil(server.logger)
	err := server.eventDbHdl.Connect()
	if err != nil {
		server.logger.Err(fmt.Sprintf("DB connect failed with error %s. Exiting!!", err))
		return
	}
	err = eventUtils.InitEvents("BGPD", server.eventDbHdl, server.logger, 1000)
	if err != nil {
		server.logger.Err(fmt.Sprintln("Unable to initialize events", err))
	}
}

func (server *BGPServer) StartServer() {
	// Initialize Event Handler
	server.InitBGPEvent()

	globalUpdate := <-server.GlobalConfigCh
	gConf := globalUpdate.NewConfig
	server.GlobalCfgDone = true
	server.logger.Info(fmt.Sprintln("Recieved global conf:", gConf))
	server.BgpConfig.Global.Config = gConf
	server.constructBGPGlobalState(&gConf)
	server.BgpConfig.PeerGroups = make(map[string]*config.PeerGroup)

	pathAttrs := packet.ConstructPathAttrForConnRoutes(gConf.RouterId, gConf.AS)
	server.ConnRoutesPath = bgprib.NewPath(server.LocRib, nil, pathAttrs, nil, bgprib.RouteTypeConnected)

	server.logger.Info("Setting up Peer connections")
	// channel for accepting connections
	server.acceptCh = make(chan *net.TCPConn)

	server.listener, _ = server.createListener()
	go server.listenForPeers(server.listener, server.acceptCh)

	server.logger.Info("Start all managers and initialize API Layer")
	server.IntfMgr.Start()
	server.routeMgr.Start()
	server.bfdMgr.Start()
	server.SetupRedistribution(gConf)

	/*  ALERT: StartServer is a go routine and hence do not have any other go routine where
	 *	   you are making calls to other client. FlexSwitch uses thrift for rpc and hence
	 *	   on return it will not know which go routine initiated the thrift call.
	 */
	// Get routes from the route manager
	add, remove := server.routeMgr.GetRoutes()
	if add != nil && remove != nil {
		server.ProcessConnectedRoutes(add, remove)
	}

	intfs := server.IntfMgr.GetIPv4Intfs()
	server.ProcessIntfStates(intfs)

	server.listenChannelUpdates()
}

func (s *BGPServer) GetBGPGlobalState() config.GlobalState {
	return s.BgpConfig.Global.State
}

func (s *BGPServer) GetBGPNeighborState(neighborIP string) *config.NeighborState {
	peer, ok := s.PeerMap[neighborIP]
	if !ok {
		s.logger.Err(fmt.Sprintf("GetBGPNeighborState - Neighbor not found for address:%s",
			neighborIP))
		return nil
	}
	return &peer.NeighborConf.Neighbor.State
}

func (s *BGPServer) BulkGetBGPNeighbors(index int, count int) (int, int, []*config.NeighborState) {
	defer s.NeighborMutex.RUnlock()

	s.NeighborMutex.RLock()
	if index+count > len(s.Neighbors) {
		count = len(s.Neighbors) - index
	}

	result := make([]*config.NeighborState, count)
	for i := 0; i < count; i++ {
		result[i] = &s.Neighbors[i+index].NeighborConf.Neighbor.State
	}

	index += count
	if index >= len(s.Neighbors) {
		index = 0
	}
	return index, count, result
}

func (svr *BGPServer) VerifyBgpGlobalConfig() bool {
	return svr.GlobalCfgDone
}
