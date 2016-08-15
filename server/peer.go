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

// peer.go
package server

import (
	"fmt"
	"l3/bgp/baseobjects"
	"l3/bgp/config"
	"l3/bgp/fsm"
	"l3/bgp/packet"
	bgprib "l3/bgp/rib"
	"net"
	"sync/atomic"
	"utils/logging"
)

type Peer struct {
	server       *BGPServer
	logger       *logging.Writer
	locRib       *bgprib.LocRib
	NeighborConf *base.NeighborConf
	fsmManager   *fsm.FSMManager
	ifIdx        int32
	ribIn        map[uint32]map[string]map[uint32]*bgprib.AdjRIBRoute
	ribOut       map[uint32]map[string]map[uint32]*bgprib.AdjRIBRoute
}

func NewPeer(server *BGPServer, locRib *bgprib.LocRib, globalConf *config.GlobalConfig,
	peerGroup *config.PeerGroupConfig, peerConf config.NeighborConfig) *Peer {
	peer := Peer{
		server: server,
		logger: server.logger,
		locRib: locRib,
		ifIdx:  -1,
		ribIn:  make(map[uint32]map[string]map[uint32]*bgprib.AdjRIBRoute),
		ribOut: make(map[uint32]map[string]map[uint32]*bgprib.AdjRIBRoute),
	}

	peer.NeighborConf = base.NewNeighborConf(peer.logger, globalConf, peerGroup, peerConf)
	peer.fsmManager = fsm.NewFSMManager(peer.logger, peer.NeighborConf, server.BGPPktSrcCh,
		server.PeerFSMConnCh, server.ReachabilityCh)
	return &peer
}

func (p *Peer) UpdatePeerGroup(peerGroup *config.PeerGroupConfig) {
	p.NeighborConf.UpdatePeerGroup(peerGroup)
}

func (p *Peer) UpdateNeighborConf(nConf config.NeighborConfig, bgp *config.Bgp) {
	p.NeighborConf.UpdateNeighborConf(nConf, bgp)
}

func (p *Peer) initAdjRIBTables() {
	for protoFamily, ok := range p.NeighborConf.AfiSafiMap {
		if ok {
			p.ribIn[protoFamily] = make(map[string]map[uint32]*bgprib.AdjRIBRoute)
			p.ribOut[protoFamily] = make(map[string]map[uint32]*bgprib.AdjRIBRoute)
		}
	}
}

func (p *Peer) IsBfdStateUp() bool {
	up := true
	if p.NeighborConf.Neighbor.State.UseBfdState {
		if p.NeighborConf.RunningConf.BfdEnable &&
			p.NeighborConf.Neighbor.State.BfdNeighborState == "down" {
			p.logger.Info(fmt.Sprintf("Neighbor's bfd state is down for %s\n",
				p.NeighborConf.Neighbor.NeighborAddress))
			up = false
		}
	}
	return up
}

func (p *Peer) Init() {
	if p.fsmManager == nil {
		p.logger.Info(fmt.Sprintf("Instantiating new FSM Manager for neighbor %s\n",
			p.NeighborConf.Neighbor.NeighborAddress))
		p.fsmManager = fsm.NewFSMManager(p.logger, p.NeighborConf, p.server.BGPPktSrcCh,
			p.server.PeerFSMConnCh, p.server.ReachabilityCh)
	}

	go p.fsmManager.Init()
	p.ProcessBfd(true)
}

func (p *Peer) Cleanup() {
	p.ProcessBfd(false)
	p.fsmManager.CloseCh <- true
	p.fsmManager = nil
}

func (p *Peer) StopFSM(msg string) {
	p.fsmManager.StopFSMCh <- msg
}

func (p *Peer) MaxPrefixesExceeded() {
	if p.NeighborConf.RunningConf.MaxPrefixesDisconnect {
		p.Command(int(fsm.BGPEventAutoStop), fsm.BGPCmdReasonMaxPrefixExceeded)
	}
}
func (p *Peer) setIfIdx(ifIdx int32) {
	p.ifIdx = ifIdx
}

func (p *Peer) getIfIdx() int32 {
	return p.ifIdx
}

func (p *Peer) AcceptConn(conn *net.TCPConn) {
	if p.fsmManager == nil {
		p.logger.Info(fmt.Sprintf("FSM Manager is not instantiated yet for neighbor %s\n",
			p.NeighborConf.Neighbor.NeighborAddress))
		(*conn).Close()
		return
	}
	p.fsmManager.AcceptCh <- conn
}

func (p *Peer) Command(command int, reason int) {
	if p.fsmManager == nil {
		p.logger.Info(fmt.Sprintf("FSM Manager is not instantiated yet for neighbor %s\n",
			p.NeighborConf.Neighbor.NeighborAddress))
		return
	}
	p.fsmManager.CommandCh <- fsm.PeerFSMCommand{command, reason}
}

func (p *Peer) getAddPathsMaxTx() int {
	return int(p.NeighborConf.Neighbor.State.AddPathsMaxTx)
}

func (p *Peer) clearRibOut() {
	p.ribIn = nil
	p.ribOut = nil
	p.ribIn = make(map[uint32]map[string]map[uint32]*bgprib.AdjRIBRoute)
	p.ribOut = make(map[uint32]map[string]map[uint32]*bgprib.AdjRIBRoute)
	p.initAdjRIBTables()
}

func (p *Peer) ProcessBfd(add bool) {
	ipAddr := p.NeighborConf.Neighbor.NeighborAddress.String()
	sessionParam := p.NeighborConf.RunningConf.BfdSessionParam
	if add && p.NeighborConf.RunningConf.BfdEnable {
		p.logger.Info(fmt.Sprintln("Bfd enabled on", p.NeighborConf.Neighbor.NeighborAddress))
		ret, err := p.server.bfdMgr.CreateBfdSession(ipAddr, sessionParam)
		if !ret {
			p.logger.Info(fmt.Sprintln("BfdSessionConfig FAILED, ret:", ret, "err:", err))
		} else {
			p.logger.Info(fmt.Sprintln("Bfd session configured: ", ipAddr, " param: ", sessionParam))
			p.NeighborConf.Neighbor.State.BfdNeighborState = "up"
		}
	} else {
		if p.NeighborConf.Neighbor.State.BfdNeighborState != "" {
			p.logger.Info(fmt.Sprintln("Bfd disabled on", p.NeighborConf.Neighbor.NeighborAddress))
			ret, err := p.server.bfdMgr.DeleteBfdSession(ipAddr)
			if !ret {
				p.logger.Info(fmt.Sprintln("BfdSessionConfig FAILED, ret:", ret, "err:", err))
			} else {
				p.logger.Info(fmt.Sprintln("Bfd session removed for", p.NeighborConf.Neighbor.NeighborAddress))
				p.NeighborConf.Neighbor.State.BfdNeighborState = ""
			}
		}
	}

}

func (p *Peer) PeerConnEstablished(conn *net.Conn) {
	host, _, err := net.SplitHostPort((*conn).LocalAddr().String())
	if err != nil {
		p.logger.Err(fmt.Sprintf("Neighbor %s: Can't find local address from the peer connection: %s",
			p.NeighborConf.Neighbor.NeighborAddress, (*conn).LocalAddr()))
		return
	}
	p.NeighborConf.Neighbor.Transport.Config.LocalAddress = net.ParseIP(host)
	p.NeighborConf.PeerConnEstablished()
	p.clearRibOut()
	//p.Server.PeerConnEstCh <- p.Neighbor.NeighborAddress.String()
}

func (p *Peer) PeerConnBroken(fsmCleanup bool) {
	if p.NeighborConf.Neighbor.Transport.Config.LocalAddress != nil {
		p.NeighborConf.Neighbor.Transport.Config.LocalAddress = nil
		//p.Server.PeerConnBrokenCh <- p.Neighbor.NeighborAddress.String()
	}
	p.NeighborConf.PeerConnBroken()
	p.clearRibOut()
}

func (p *Peer) ReceiveUpdate(msg *packet.BGPMessage) {
	var pathIdRouteMap map[uint32]*bgprib.AdjRIBRoute
	var ok bool

	update := msg.Body.(*packet.BGPUpdate)
	if packet.HasASLoop(update.PathAttributes, p.NeighborConf.RunningConf.LocalAS) {
		p.logger.Info(fmt.Sprintf("Neighbor %s: Recived Update message has AS loop",
			p.NeighborConf.Neighbor.NeighborAddress))
		return
	}

	protoFamily := packet.GetProtocolFamily(packet.AfiIP, packet.SafiUnicast)
	for _, nlri := range update.WithdrawnRoutes {
		ip := nlri.GetPrefix().String()
		if pathIdRouteMap, ok = p.ribIn[protoFamily][ip]; !ok {
			p.logger.Err(fmt.Sprintf("Neighbor %s: Withdraw Prefix %s not found in RIB-In",
				p.NeighborConf.Neighbor.NeighborAddress, ip))
			continue
		}

		if _, ok = pathIdRouteMap[nlri.GetPathId()]; !ok {
			p.logger.Err(fmt.Sprintf("Neighbor %s: Withdraw Prefix %s Path id %d not found in RIB-In",
				p.NeighborConf.Neighbor.NeighborAddress, ip, nlri.GetPathId()))
			continue
		}

		delete(p.ribIn[protoFamily][ip], nlri.GetPathId())
		if len(p.ribIn[protoFamily][ip]) == 0 {
			delete(p.ribIn[protoFamily], ip)
		}
	}

	if len(update.NLRI) > 0 {
		path := bgprib.NewPath(p.locRib, p.NeighborConf, update.PathAttributes, nil, bgprib.RouteTypeEGP)
		for _, nlri := range update.NLRI {
			ip := nlri.GetPrefix().String()
			if _, ok = p.ribIn[protoFamily][ip]; !ok {
				p.ribIn[protoFamily][ip] = make(map[uint32]*bgprib.AdjRIBRoute)
			}
			p.ribIn[protoFamily][ip][nlri.GetPathId()] = bgprib.NewAdjRIBRoute(nlri, path, nlri.GetPathId())
		}
	}
}

func (p *Peer) updatePathAttrs(bgpMsg *packet.BGPMessage, path *bgprib.Path) bool {
	if p.NeighborConf.Neighbor.Transport.Config.LocalAddress == nil {
		p.logger.Err(fmt.Sprintf("Neighbor %s: Can't send Update message, FSM is not",
			"in Established state\n", p.NeighborConf.Neighbor.NeighborAddress))
		return false
	}

	if bgpMsg == nil || bgpMsg.Body.(*packet.BGPUpdate).PathAttributes == nil {
		p.logger.Err(fmt.Sprintf("Neighbor %s: Path attrs not found in BGP Update message\n",
			p.NeighborConf.Neighbor.NeighborAddress))
		return false
	}

	updateMsg := bgpMsg.Body.(*packet.BGPUpdate)
	if len(updateMsg.NLRI) == 0 && !packet.HasMPReachNLRI(updateMsg.PathAttributes) {
		return true
	}

	if p.NeighborConf.ASSize == 2 {
		packet.Convert4ByteTo2ByteASPath(bgpMsg)
	}

	removeRRPathAttrs := true
	if p.NeighborConf.IsInternal() {
		if path.NeighborConf != nil && (path.NeighborConf.IsRouteReflectorClient() ||
			p.NeighborConf.IsRouteReflectorClient()) {
			removeRRPathAttrs = false
			packet.AddOriginatorId(bgpMsg, path.NeighborConf.BGPId)
			packet.AddClusterId(bgpMsg, path.NeighborConf.RunningConf.RouteReflectorClusterId)
		} else {
			packet.SetLocalPref(bgpMsg, path.GetPreference())
		}
	} else {
		// Do change these path attrs for local routes
		if path.NeighborConf != nil {
			packet.RemoveMultiExitDisc(bgpMsg)
		}
		packet.PrependAS(bgpMsg, p.NeighborConf.RunningConf.LocalAS, p.NeighborConf.ASSize)
		if updateMsg.NLRI != nil && len(updateMsg.NLRI) > 0 {
			packet.SetNextHop(bgpMsg, p.NeighborConf.Neighbor.Transport.Config.LocalAddress)
		} else if len(updateMsg.PathAttributes) > 0 {
			packet.RemoveNextHop(&(updateMsg.PathAttributes))
		}
		packet.RemoveLocalPref(bgpMsg)
	}

	if removeRRPathAttrs {
		packet.RemoveOriginatorId(bgpMsg)
		packet.RemoveClusterList(bgpMsg)
	}

	return true
}

func (p *Peer) sendUpdateMsg(msg *packet.BGPMessage, path *bgprib.Path) {
	if path != nil && path.NeighborConf != nil {
		if path.NeighborConf.IsInternal() {

			if p.NeighborConf.IsInternal() && !path.NeighborConf.IsRouteReflectorClient() &&
				!p.NeighborConf.IsRouteReflectorClient() {
				return
			}
		}

		// Don't send the update to the peer that sent the update.
		if p.NeighborConf.RunningConf.NeighborAddress.String() ==
			path.NeighborConf.RunningConf.NeighborAddress.String() {
			return
		}
	}

	if p.updatePathAttrs(msg, path) {
		atomic.AddUint32(&p.NeighborConf.Neighbor.State.Queues.Output, 1)
		p.fsmManager.SendUpdateMsg(msg)
	}

}

func (p *Peer) isAdvertisable(path *bgprib.Path) bool {
	if path != nil && path.NeighborConf != nil {
		if path.NeighborConf.IsInternal() {

			if p.NeighborConf.IsInternal() && !path.NeighborConf.IsRouteReflectorClient() &&
				!p.NeighborConf.IsRouteReflectorClient() {
				return false
			}
		}

		// Don't send the update to the peer that sent the update.
		if p.NeighborConf.RunningConf.NeighborAddress.String() ==
			path.NeighborConf.RunningConf.NeighborAddress.String() {
			return false
		}
	}

	return true
}

func (p *Peer) calculateAddPathsAdvertisements(dest *bgprib.Destination, path *bgprib.Path,
	newUpdated map[*bgprib.Path]map[uint32][]packet.NLRI, withdrawList map[uint32][]packet.NLRI, addPathsTx int) (
	map[*bgprib.Path]map[uint32][]packet.NLRI, map[uint32][]packet.NLRI) {
	pathIdMap := make(map[uint32]*bgprib.Path)
	ip := dest.NLRI.GetPrefix().String()
	protoFamily := dest.GetProtocolFamily()

	if _, ok := p.ribOut[protoFamily][ip]; !ok {
		p.logger.Info(fmt.Sprintf("Neighbor %s: calculateAddPathsAdvertisements - processing updates, dest %s not",
			"found in rib out", p.NeighborConf.Neighbor.NeighborAddress, ip))
		p.ribOut[protoFamily][ip] = make(map[uint32]*bgprib.AdjRIBRoute)
	}

	pathAdded := false
	protoFamilyAdded := false
	if _, ok := newUpdated[path]; ok {
		pathAdded = true
		if _, ok := newUpdated[path][protoFamily]; ok {
			protoFamilyAdded = true
		}
	}

	if p.isAdvertisable(path) {
		route := dest.LocRibPathRoute
		if path != nil { // Loc-RIB path changed
			if !pathAdded {
				newUpdated[path] = make(map[uint32][]packet.NLRI)
				pathAdded = true
			}
			if !protoFamilyAdded {
				newUpdated[path][protoFamily] = make([]packet.NLRI, 0)
				protoFamilyAdded = true
			}
			nlri := packet.NewExtNLRI(route.OutPathId, dest.NLRI.GetIPPrefix())
			newUpdated[path][protoFamily] = append(newUpdated[path][protoFamily], nlri)
		} else {
			path = dest.LocRibPath
		}
		pathIdMap[route.OutPathId] = path
	}

	for i := 0; i < len(dest.AddPaths) && len(pathIdMap) < (addPathsTx-1); i++ {
		route := dest.GetPathRoute(dest.AddPaths[i])
		if route != nil && p.isAdvertisable(dest.AddPaths[i]) {
			pathIdMap[route.OutPathId] = dest.AddPaths[i]
		}
	}

	ribPathMap, _ := p.ribOut[protoFamily][ip]
	for ribPathId, ribRoute := range ribPathMap {
		if path, ok := pathIdMap[ribPathId]; !ok {
			nlri := packet.NewExtNLRI(ribPathId, dest.NLRI.GetIPPrefix())
			withdrawList[protoFamily] = append(withdrawList[protoFamily], nlri)
			delete(p.ribOut[protoFamily][ip], ribPathId)
		} else if ribRoute.Path == path {
			delete(pathIdMap, ribPathId)
		} else if ribRoute.Path != path {
			if !pathAdded {
				newUpdated[path] = make(map[uint32][]packet.NLRI)
				pathAdded = true
			}
			if !protoFamilyAdded {
				newUpdated[path][protoFamily] = make([]packet.NLRI, 0)
				protoFamilyAdded = true
			}
			nlri := packet.NewExtNLRI(ribPathId, dest.NLRI.GetIPPrefix())
			newUpdated[path][protoFamily] = append(newUpdated[path][protoFamily], nlri)
			p.ribOut[protoFamily][ip][ribPathId] = bgprib.NewAdjRIBRoute(nlri, path, ribPathId)
			delete(pathIdMap, ribPathId)
		}
	}

	for pathId, path := range pathIdMap {
		if !pathAdded {
			newUpdated[path] = make(map[uint32][]packet.NLRI)
			pathAdded = true
		}
		if !protoFamilyAdded {
			newUpdated[path][protoFamily] = make([]packet.NLRI, 0)
			protoFamilyAdded = true
		}
		nlri := packet.NewExtNLRI(pathId, dest.NLRI.GetIPPrefix())
		newUpdated[path][protoFamily] = append(newUpdated[path][protoFamily], nlri)
		p.ribOut[protoFamily][ip][pathId] = bgprib.NewAdjRIBRoute(nlri, path, pathId)
		delete(pathIdMap, pathId)
	}

	return newUpdated, withdrawList
}

func (p *Peer) SendUpdate(updated map[uint32]map[*bgprib.Path][]*bgprib.Destination, withdrawn,
	updatedAddPaths []*bgprib.Destination) {
	p.logger.Info(fmt.Sprintf("Neighbor %s: Send update message valid routes:%v, withdraw routes:%v",
		p.NeighborConf.Neighbor.NeighborAddress, updated, withdrawn))
	if p.NeighborConf.Neighbor.Transport.Config.LocalAddress == nil {
		p.logger.Err(fmt.Sprintf("Neighbor %s: Can't send Update message, FSM is not in Established state",
			p.NeighborConf.Neighbor.NeighborAddress))
		return
	}

	addPathsTx := p.getAddPathsMaxTx()
	withdrawList := make(map[uint32][]packet.NLRI)
	newUpdated := make(map[*bgprib.Path]map[uint32][]packet.NLRI)
	if len(withdrawn) > 0 {
		for _, dest := range withdrawn {
			if dest != nil {
				protoFamily := dest.GetProtocolFamily()
				if _, ok := withdrawList[protoFamily]; !ok {
					withdrawList[protoFamily] = make([]packet.NLRI, 0)
				}
				ip := dest.NLRI.GetPrefix().String()
				if p.ribOut[protoFamily] != nil && p.ribOut[protoFamily][ip] != nil &&
					p.NeighborConf.AfiSafiMap[protoFamily] {
					if addPathsTx > 0 {
						pathIdMap, ok := p.ribOut[protoFamily][ip]
						if !ok {
							p.logger.Err(fmt.Sprintf("Neighbor %s: processing withdraws, dest %s not found in rib out",
								p.NeighborConf.Neighbor.NeighborAddress, ip))
							continue
						}
						for pathId, _ := range pathIdMap {
							nlri := packet.NewExtNLRI(pathId, dest.NLRI.GetIPPrefix())
							withdrawList[protoFamily] = append(withdrawList[protoFamily], nlri)
						}
						delete(p.ribOut[protoFamily], ip)
					} else {
						withdrawList[protoFamily] = append(withdrawList[protoFamily], dest.NLRI)
						delete(p.ribOut[protoFamily], ip)
					}
				}
			}
		}
	}

	for protoFamily, pathDestMap := range updated {
		if !p.NeighborConf.AfiSafiMap[protoFamily] {
			continue
		}
		if _, ok := p.ribOut[protoFamily]; !ok {
			p.ribOut[protoFamily] = make(map[string]map[uint32]*bgprib.AdjRIBRoute)
		}
		if _, ok := withdrawList[protoFamily]; !ok {
			withdrawList[protoFamily] = make([]packet.NLRI, 0)
		}
		for path, destinations := range pathDestMap {
			for _, dest := range destinations {
				if dest == nil {
					continue
				}
				ip := dest.NLRI.GetPrefix().String()
				if addPathsTx > 0 {
					newUpdated, withdrawList = p.calculateAddPathsAdvertisements(dest, path, newUpdated,
						withdrawList, addPathsTx)
				} else {
					if !p.isAdvertisable(path) {
						if p.ribOut[protoFamily][ip] != nil {
							withdrawList[protoFamily] = append(withdrawList[protoFamily], dest.NLRI)
							delete(p.ribOut[protoFamily], ip)
						}
					} else {
						route := dest.LocRibPathRoute
						pathId := route.OutPathId
						if _, ok := p.ribOut[protoFamily][ip]; !ok {
							p.ribOut[protoFamily][ip] = make(map[uint32]*bgprib.AdjRIBRoute)
						}
						for ribPathId, _ := range p.ribOut[protoFamily][ip] {
							if pathId != ribPathId {
								delete(p.ribOut[protoFamily][ip], ribPathId)
							}
						}
						if ribRoute, ok := p.ribOut[protoFamily][ip][pathId]; !ok ||
							ribRoute.Path != path {
							if _, ok := newUpdated[path]; !ok {
								newUpdated[path] = make(map[uint32][]packet.NLRI)
							}
							if _, ok := newUpdated[path][protoFamily]; !ok {
								newUpdated[path][protoFamily] = make([]packet.NLRI, 0)
							}
							newUpdated[path][protoFamily] = append(newUpdated[path][protoFamily], dest.NLRI)
						}
						p.ribOut[protoFamily][ip][pathId] = bgprib.NewAdjRIBRoute(dest.NLRI.GetIPPrefix(),
							path, pathId)
					}
				}
			}
		}
	}

	if addPathsTx > 0 {
		for _, dest := range updatedAddPaths {
			newUpdated, withdrawList = p.calculateAddPathsAdvertisements(dest, nil, newUpdated, withdrawList,
				addPathsTx)
		}
	}

	if withdrawList != nil {
		p.logger.Info(fmt.Sprintf("Neighbor %s: Send update message withdraw routes:%+v",
			p.NeighborConf.Neighbor.NeighborAddress, withdrawList))
		var updateMsg *packet.BGPMessage
		var ipv4List []packet.NLRI
		protoFamily := packet.GetProtocolFamily(packet.AfiIP, packet.SafiUnicast)
		if nlriList, ok := withdrawList[protoFamily]; ok {
			ipv4List = nlriList
			delete(withdrawList, protoFamily)
		}
		for protoFamily, nlriList := range withdrawList {
			if len(nlriList) > 0 {
				afi, safi := packet.GetAfiSafi(protoFamily)
				mpUnreachNLRI := packet.NewBGPPathAttrMPUnreachNLRI()
				mpUnreachNLRI.AFI = afi
				mpUnreachNLRI.SAFI = safi
				mpUnreachNLRI.AddNLRIList(nlriList)
				pathAtts := make([]packet.BGPPathAttr, 0)
				pathAtts = append(pathAtts, mpUnreachNLRI)
				updateMsg = packet.NewBGPUpdateMessage(ipv4List, pathAtts, nil)
				p.sendUpdateMsg(updateMsg.Clone(), nil)
				ipv4List = nil
			}
		}
		if ipv4List != nil {
			updateMsg = packet.NewBGPUpdateMessage(ipv4List, nil, nil)
			p.sendUpdateMsg(updateMsg.Clone(), nil)
		}
	}

	p.logger.Info(fmt.Sprintf("Neighbor %s: new updated routes:%+v",
		p.NeighborConf.Neighbor.NeighborAddress, newUpdated))
	for path, pfNLRIMap := range newUpdated {
		var updateMsg *packet.BGPMessage
		var ipv4List []packet.NLRI
		protoFamily := packet.GetProtocolFamily(packet.AfiIP, packet.SafiUnicast)
		if nlriList, ok := pfNLRIMap[protoFamily]; ok {
			if len(nlriList) > 0 {
				ipv4List = nlriList
				delete(pfNLRIMap, protoFamily)
			}
		}

		for protoFamily, nlriList := range pfNLRIMap {
			if len(nlriList) > 0 {
				afi, safi := packet.GetAfiSafi(protoFamily)
				pa := packet.CopyPathAttrs(path.PathAttrs)
				mpReachNLRI := packet.NewBGPPathAttrMPReachNLRI()
				mpReachNLRI.AFI = afi
				mpReachNLRI.SAFI = safi
				mpNextHop := packet.NewMPNextHopIP()
				mpNextHop.SetNextHop(p.NeighborConf.Neighbor.Transport.Config.LocalAddress)
				mpReachNLRI.SetNextHop(mpNextHop)
				mpReachNLRI.SetNLRIList(nlriList)
				pa = packet.AddMPReachNLRIToPathAttrs(pa, mpReachNLRI)
				updateMsg = packet.NewBGPUpdateMessage(nil, pa, ipv4List)
				p.logger.Info(fmt.Sprintf("Neighbor %s: Send update message valid routes:%+v, path attrs:%+v",
					p.NeighborConf.Neighbor.NeighborAddress, nlriList, path.PathAttrs))
				p.sendUpdateMsg(updateMsg.Clone(), path)
				ipv4List = nil
			}
		}

		if ipv4List != nil {
			p.logger.Info(fmt.Sprintf("Neighbor %s: Send update message valid routes:%+v, path attrs:%+v",
				p.NeighborConf.Neighbor.NeighborAddress, ipv4List, path.PathAttrs))
			updateMsg := packet.NewBGPUpdateMessage(make([]packet.NLRI, 0), path.PathAttrs, ipv4List)
			p.sendUpdateMsg(updateMsg.Clone(), path)
		}
	}
}
