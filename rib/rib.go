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

// rib.go
package rib

import (
	"bgpd"
	"fmt"
	"l3/bgp/baseobjects"
	"l3/bgp/config"
	"l3/bgp/packet"
	"models/objects"
	"net"
	"sync"
	"time"
	"utils/logging"
	"utils/statedbclient"
)

var totalRoutes int

const ResetTime int = 120
const AggregatePathId uint32 = 0

type ReachabilityInfo struct {
	NextHop       string
	NextHopIfType int32
	NextHopIfIdx  int32
	Metric        int32
}

func NewReachabilityInfo(nextHop string, nhIfType, nhIfIdx, metric int32) *ReachabilityInfo {
	return &ReachabilityInfo{
		NextHop:       nextHop,
		NextHopIfType: nhIfType,
		NextHopIfIdx:  nhIfIdx,
		Metric:        metric,
	}
}

type LocRib struct {
	logger           *logging.Writer
	gConf            *config.GlobalConfig
	routeMgr         config.RouteMgrIntf
	stateDBMgr       statedbclient.StateDBClient
	destPathMap      map[uint32]map[string]*Destination
	reachabilityMap  map[string]*ReachabilityInfo
	unreachablePaths map[string]map[*Path]map[*Destination][]uint32
	routeList        []*Destination
	routeMutex       sync.RWMutex
	routeListDirty   bool
	activeGet        bool
	timer            *time.Timer
}

func NewLocRib(logger *logging.Writer, rMgr config.RouteMgrIntf, sDBMgr statedbclient.StateDBClient,
	gConf *config.GlobalConfig) *LocRib {
	rib := &LocRib{
		logger:           logger,
		gConf:            gConf,
		routeMgr:         rMgr,
		stateDBMgr:       sDBMgr,
		destPathMap:      make(map[uint32]map[string]*Destination),
		reachabilityMap:  make(map[string]*ReachabilityInfo),
		unreachablePaths: make(map[string]map[*Path]map[*Destination][]uint32),
		routeList:        make([]*Destination, 0),
		routeListDirty:   false,
		activeGet:        false,
		routeMutex:       sync.RWMutex{},
	}

	rib.timer = time.AfterFunc(time.Duration(100)*time.Second, rib.ResetRouteList)
	rib.timer.Stop()

	return rib
}

func isIpInList(prefixes []packet.NLRI, ip packet.NLRI) bool {
	for _, nlri := range prefixes {
		if nlri.GetPathId() == ip.GetPathId() &&
			nlri.GetPrefix().Equal(ip.GetPrefix()) {
			return true
		}
	}
	return false
}

func (l *LocRib) GetReachabilityInfo(ipStr string) *ReachabilityInfo {
	if reachabilityInfo, ok := l.reachabilityMap[ipStr]; ok {
		return reachabilityInfo
	}

	l.logger.Info(fmt.Sprintf("GetReachabilityInfo: Reachability info not cached for Next hop %s", ipStr))
	ribdReachabilityInfo, err := l.routeMgr.GetNextHopInfo(ipStr)
	if err != nil {
		l.logger.Info(fmt.Sprintf("NEXT_HOP[%s] is not reachable", ipStr))
		return nil
	}
	nextHop := ribdReachabilityInfo.NextHopIp
	if nextHop == "" || nextHop[0] == '0' {
		l.logger.Info(fmt.Sprintf("Next hop for %s is %s. Using %s as the next hop", ipStr, nextHop, ipStr))
		nextHop = ipStr
	}

	reachabilityInfo := NewReachabilityInfo(nextHop, ribdReachabilityInfo.NextHopIfType,
		ribdReachabilityInfo.NextHopIfIndex, ribdReachabilityInfo.Metric)
	l.reachabilityMap[ipStr] = reachabilityInfo
	return reachabilityInfo
}

func (l *LocRib) GetDestFromIPAndLen(protoFamily uint32, ip string, cidrLen uint32) *Destination {
	if nlriDestMap, ok := l.destPathMap[protoFamily]; ok {
		if dest, ok := nlriDestMap[ip]; ok {
			return dest
		}
	}

	return nil
}

func (l *LocRib) GetDest(nlri packet.NLRI, protoFamily uint32, createIfNotExist bool) (dest *Destination, ok bool) {
	nlriDestMap, ok := l.destPathMap[protoFamily]
	if ok || createIfNotExist {
		if !ok {
			l.destPathMap[protoFamily] = make(map[string]*Destination)
			nlriDestMap = l.destPathMap[protoFamily]
		}
		dest, ok = nlriDestMap[nlri.GetPrefix().String()]
		if !ok && createIfNotExist {
			dest = NewDestination(l, nlri, protoFamily, l.gConf)
			l.destPathMap[protoFamily][nlri.GetPrefix().String()] = dest
			l.addRoutesToRouteList(dest)
		}
	}

	return dest, ok
}

func (l *LocRib) updateRibOutInfo(action RouteAction, addPathsMod bool, addRoutes, updRoutes, delRoutes []*Route,
	dest *Destination, updated map[uint32]map[*Path][]*Destination, withdrawn, updatedAddPaths []*Destination) (
	map[uint32]map[*Path][]*Destination, []*Destination, []*Destination) {
	if action == RouteActionAdd || action == RouteActionReplace {
		if _, ok := updated[dest.protoFamily]; !ok {
			updated[dest.protoFamily] = make(map[*Path][]*Destination)
		}
		if _, ok := updated[dest.protoFamily][dest.LocRibPath]; !ok {
			updated[dest.protoFamily][dest.LocRibPath] = make([]*Destination, 0)
		}
		updated[dest.protoFamily][dest.LocRibPath] = append(updated[dest.protoFamily][dest.LocRibPath], dest)
	} else if action == RouteActionDelete {
		withdrawn = append(withdrawn, dest)
	} else if addPathsMod {
		updatedAddPaths = append(updatedAddPaths, dest)
	}

	return updated, withdrawn, updatedAddPaths
}

func (l *LocRib) GetRouteStateConfigObj(route *bgpd.BGPRouteState) objects.ConfigObj {
	var dbObj objects.BGPRouteState
	objects.ConvertThriftTobgpdBGPRouteStateObj(route, &dbObj)
	return &dbObj
}

func (l *LocRib) ProcessRoutes(peerIP string, add, rem []packet.NLRI, addPath, remPath *Path, addPathCount int,
	protoFamily uint32, updated map[uint32]map[*Path][]*Destination, withdrawn []*Destination,
	updatedAddPaths []*Destination) (map[uint32]map[*Path][]*Destination, []*Destination, []*Destination, bool) {
	addedAllPrefixes := true

	// process withdrawn routes
	for _, nlri := range rem {
		if !isIpInList(add, nlri) {
			l.logger.Info(fmt.Sprintln("Processing withdraw destination", nlri.GetPrefix().String()))
			dest, ok := l.GetDest(nlri, protoFamily, false)
			if !ok {
				l.logger.Warning(fmt.Sprintln("Can't process withdraw field, Destination does not exist, Dest:",
					nlri.GetPrefix().String()))
				continue
			}
			op := l.stateDBMgr.UpdateObject
			oldPath := dest.RemovePath(peerIP, nlri.GetPathId(), remPath)
			if oldPath != nil && !oldPath.IsReachable(dest.protoFamily) {
				nextHop := oldPath.GetNextHop(dest.protoFamily)
				if nextHop != nil {
					nextHopStr := nextHop.String()
					if _, ok := l.unreachablePaths[nextHopStr]; ok {
						if _, ok := l.unreachablePaths[nextHopStr][oldPath]; ok {
							if pathIds, ok := l.unreachablePaths[nextHopStr][oldPath][dest]; ok {
								for idx, pathId := range pathIds {
									if pathId == nlri.GetPathId() {
										l.unreachablePaths[nextHopStr][oldPath][dest][idx] = pathIds[len(pathIds)-1]
										l.unreachablePaths[nextHopStr][oldPath][dest] =
											l.unreachablePaths[nextHopStr][oldPath][dest][:len(pathIds)-1]
										break
									}
								}
								if len(l.unreachablePaths[nextHopStr][oldPath][dest]) == 0 {
									delete(l.unreachablePaths[nextHopStr][oldPath], dest)
								}
							}
							if len(l.unreachablePaths[nextHopStr][oldPath]) == 0 {
								delete(l.unreachablePaths[nextHopStr], oldPath)
							}
						}
						if len(l.unreachablePaths[nextHopStr]) == 0 {
							delete(l.unreachablePaths, nextHopStr)
						}
					}
				}
			}
			action, addPathsMod, addRoutes, updRoutes, delRoutes := dest.SelectRouteForLocRib(addPathCount)
			updated, withdrawn, updatedAddPaths = l.updateRibOutInfo(action, addPathsMod, addRoutes, updRoutes,
				delRoutes, dest, updated, withdrawn, updatedAddPaths)

			if oldPath != nil && remPath != nil {
				if neighborConf := remPath.GetNeighborConf(); neighborConf != nil {
					l.logger.Info(fmt.Sprintf("Decrement prefix count for destination %s from Peer %s",
						nlri.GetPrefix().String(), peerIP))
					neighborConf.DecrPrefixCount()
				}
			}
			if action == RouteActionDelete {
				if dest.IsEmpty() {
					op = l.stateDBMgr.DeleteObject
					l.removeRoutesFromRouteList(dest)
					delete(l.destPathMap[protoFamily], nlri.GetPrefix().String())
				}
			}
			op(l.GetRouteStateConfigObj(dest.GetBGPRoute()))
		} else {
			l.logger.Info(fmt.Sprintln("Can't withdraw destination", nlri.GetPrefix().String(),
				"Destination is part of NLRI in the UDPATE"))
		}
	}

	nextHopStr := addPath.GetNextHop(protoFamily).String()
	for _, nlri := range add {
		if nlri.GetPrefix().String() == "0.0.0.0" {
			l.logger.Info(fmt.Sprintf("Can't process NLRI 0.0.0.0"))
			continue
		}

		l.logger.Info(fmt.Sprintln("Processing nlri", nlri.GetPrefix().String()))
		op := l.stateDBMgr.UpdateObject
		dest, alreadyCreated := l.GetDest(nlri, protoFamily, true)
		if !alreadyCreated {
			op = l.stateDBMgr.AddObject
		}
		if oldPath := dest.getPathForIP(peerIP, nlri.GetPathId()); oldPath == nil && addPath.NeighborConf != nil {
			if !addPath.NeighborConf.CanAcceptNewPrefix() {
				l.logger.Info(fmt.Sprintf("Max prefixes limit reached for peer %s, can't process %s", peerIP,
					nlri.GetPrefix().String()))
				addedAllPrefixes = false
				continue
			}
			l.logger.Info(fmt.Sprintf("Increment prefix count for destination %s from Peer %s",
				nlri.GetPrefix().String(), peerIP))
			addPath.NeighborConf.IncrPrefixCount()
		}

		dest.AddOrUpdatePath(peerIP, nlri.GetPathId(), addPath)
		if !addPath.IsReachable(protoFamily) {
			if _, ok := l.unreachablePaths[nextHopStr][addPath][dest]; !ok {
				l.unreachablePaths[nextHopStr][addPath][dest] = make([]uint32, 0)
			}

			l.unreachablePaths[nextHopStr][addPath][dest] = append(l.unreachablePaths[nextHopStr][addPath][dest],
				nlri.GetPathId())
			continue
		}

		action, addPathsMod, addRoutes, updRoutes, delRoutes := dest.SelectRouteForLocRib(addPathCount)
		updated, withdrawn, updatedAddPaths = l.updateRibOutInfo(action, addPathsMod, addRoutes, updRoutes, delRoutes,
			dest, updated, withdrawn, updatedAddPaths)
		op(l.GetRouteStateConfigObj(dest.GetBGPRoute()))
	}

	return updated, withdrawn, updatedAddPaths, addedAllPrefixes
}

func (l *LocRib) ProcessRoutesForReachableRoutes(nextHop string, reachabilityInfo *ReachabilityInfo, addPathCount int,
	updated map[uint32]map[*Path][]*Destination, withdrawn []*Destination, updatedAddPaths []*Destination) (
	map[uint32]map[*Path][]*Destination, []*Destination, []*Destination) {
	if _, ok := l.unreachablePaths[nextHop]; ok {
		for path, destinations := range l.unreachablePaths[nextHop] {
			path.SetReachabilityForNextHop(nextHop, reachabilityInfo)
			peerIP := path.GetPeerIP()
			if peerIP == "" {
				l.logger.Err(fmt.Sprintf("ProcessRoutesForReachableRoutes: nexthop %s peer ip not found for path %+v",
					nextHop, path))
				continue
			}

			for dest, pathIds := range destinations {
				l.logger.Info(fmt.Sprintln("Processing dest", dest.NLRI.GetPrefix().String()))
				for _, pathId := range pathIds {
					dest.AddOrUpdatePath(peerIP, pathId, path)
				}
				action, addPathsMod, addRoutes, updRoutes, delRoutes := dest.SelectRouteForLocRib(addPathCount)
				updated, withdrawn, updatedAddPaths = l.updateRibOutInfo(action, addPathsMod, addRoutes, updRoutes,
					delRoutes, dest, updated, withdrawn, updatedAddPaths)
				l.stateDBMgr.AddObject(l.GetRouteStateConfigObj(dest.GetBGPRoute()))
			}
		}
	}

	return updated, withdrawn, updatedAddPaths
}

func (l *LocRib) TestNHAndProcessRoutes(peerIP string, add, remove []packet.NLRI, addPath, remPath *Path,
	addPathCount int, protoFamily uint32, updated map[uint32]map[*Path][]*Destination, withdrawn,
	updatedAddPaths []*Destination) (map[uint32]map[*Path][]*Destination, []*Destination, []*Destination, bool) {
	nextHop := addPath.GetNextHop(protoFamily)
	if nextHop == nil {
		l.logger.Err(fmt.Sprintf("RIB - Next hop not found for protocol family %d", protoFamily))
		return updated, withdrawn, updatedAddPaths, true
	}
	nextHopStr := nextHop.String()
	reachabilityInfo := l.GetReachabilityInfo(nextHopStr)
	addPath.SetReachabilityForFamily(protoFamily, reachabilityInfo)

	//addPath.GetReachabilityInfo()
	if !addPath.IsValid() {
		l.logger.Info(fmt.Sprintf("Received a update with our cluster id %d, Discarding the update.",
			addPath.NeighborConf.RunningConf.RouteReflectorClusterId))
		return updated, withdrawn, updatedAddPaths, true
	}

	if reachabilityInfo == nil {
		l.logger.Info(fmt.Sprintf("ProcessUpdate - next hop %s is not reachable", nextHopStr))

		if _, ok := l.unreachablePaths[nextHopStr]; !ok {
			l.unreachablePaths[nextHopStr] = make(map[*Path]map[*Destination][]uint32)
		}

		if _, ok := l.unreachablePaths[nextHopStr][addPath]; !ok {
			l.unreachablePaths[nextHopStr][addPath] = make(map[*Destination][]uint32)
		}
	}

	updated, withdrawn, updatedAddPaths, addedAllPrefixes := l.ProcessRoutes(peerIP, add, remove, addPath, remPath,
		addPathCount, protoFamily, updated, withdrawn, updatedAddPaths)

	if reachabilityInfo != nil {
		l.logger.Info(fmt.Sprintf("ProcessUpdate - next hop %s is reachable, so process previously unreachable routes",
			nextHopStr))
		updated, withdrawn, updatedAddPaths = l.ProcessRoutesForReachableRoutes(nextHopStr, reachabilityInfo,
			addPathCount, updated, withdrawn, updatedAddPaths)
	}
	return updated, withdrawn, updatedAddPaths, addedAllPrefixes
}

func (l *LocRib) ProcessUpdate(neighborConf *base.NeighborConf, pktInfo *packet.BGPPktSrc, addPathCount int) (
	map[uint32]map[*Path][]*Destination, []*Destination, []*Destination, bool) {
	body := pktInfo.Msg.Body.(*packet.BGPUpdate)
	updated := make(map[uint32]map[*Path][]*Destination)
	withdrawn := make([]*Destination, 0)
	updatedAddPaths := make([]*Destination, 0)
	addedAllPrefixes := true

	mpReach, mpUnreach := packet.RemoveMPAttrs(&body.PathAttributes)
	remPath := NewPath(l, neighborConf, body.PathAttributes, mpReach, RouteTypeEGP)
	addPath := NewPath(l, neighborConf, body.PathAttributes, mpReach, RouteTypeEGP)

	if len(body.NLRI) > 0 || len(body.WithdrawnRoutes) > 0 {
		protoFamily := packet.GetProtocolFamily(packet.AfiIP, packet.SafiUnicast)
		updated, withdrawn, updatedAddPaths, addedAllPrefixes = l.TestNHAndProcessRoutes(pktInfo.Src, body.NLRI,
			body.WithdrawnRoutes, addPath, remPath, addPathCount, protoFamily, updated, withdrawn, updatedAddPaths)
	}

	reachNLRIDone := false
	if mpUnreach != nil {
		var reachNLRI []packet.NLRI
		if mpReach != nil && mpReach.AFI == mpUnreach.AFI && mpReach.SAFI == mpUnreach.SAFI {
			reachNLRIDone = true
			reachNLRI = mpReach.NLRI
		}
		protoFamily := packet.GetProtocolFamily(mpUnreach.AFI, mpUnreach.SAFI)
		updated, withdrawn, updatedAddPaths, addedAllPrefixes = l.TestNHAndProcessRoutes(pktInfo.Src, reachNLRI,
			mpUnreach.NLRI, addPath, remPath, addPathCount, protoFamily, updated, withdrawn, updatedAddPaths)
	}

	if !reachNLRIDone && mpReach != nil {
		protoFamily := packet.GetProtocolFamily(mpReach.AFI, mpReach.SAFI)
		updated, withdrawn, updatedAddPaths, addedAllPrefixes = l.TestNHAndProcessRoutes(pktInfo.Src, mpReach.NLRI,
			nil, addPath, remPath, addPathCount, protoFamily, updated, withdrawn, updatedAddPaths)
	}
	return updated, withdrawn, updatedAddPaths, addedAllPrefixes
}

func (l *LocRib) ProcessConnectedRoutes(src string, path *Path, add, remove map[uint32][]packet.NLRI,
	addPathCount int) (map[uint32]map[*Path][]*Destination, []*Destination, []*Destination) {
	var removePath *Path
	var addedAllPrefixes bool
	removePath = path.Clone()
	updated := make(map[uint32]map[*Path][]*Destination)
	withdrawn := make([]*Destination, 0)
	updatedAddPaths := make([]*Destination, 0)

	for protoFamily, withdrawnNLRI := range remove {
		updated, withdrawn, updatedAddPaths, addedAllPrefixes = l.ProcessRoutes(src, add[protoFamily], withdrawnNLRI,
			path, removePath, addPathCount, protoFamily, updated, withdrawn, updatedAddPaths)
		delete(add, protoFamily)
		if !addedAllPrefixes {
			l.logger.Err(fmt.Sprintf("Failed to add connected routes... max prefixes exceeded for connected routes!"))
		}
	}

	for protoFamily, updatedNLRI := range add {
		updated, withdrawn, updatedAddPaths, addedAllPrefixes = l.ProcessRoutes(src, updatedNLRI, nil, path,
			removePath, addPathCount, protoFamily, updated, withdrawn, updatedAddPaths)
		if !addedAllPrefixes {
			l.logger.Err(fmt.Sprintf("Failed to add connected routes... max prefixes exceeded for connected routes!"))
		}
	}
	return updated, withdrawn, updatedAddPaths
}

func (l *LocRib) RemoveUpdatesFromNeighbor(peerIP string, neighborConf *base.NeighborConf, addPathCount int) (
	map[uint32]map[*Path][]*Destination, []*Destination, []*Destination) {
	remPath := NewPath(l, neighborConf, nil, nil, RouteTypeEGP)
	withdrawn := make([]*Destination, 0)
	updated := make(map[uint32]map[*Path][]*Destination)
	updatedAddPaths := make([]*Destination, 0)

	for protoFamily, ipDestMap := range l.destPathMap {
		for destIP, dest := range ipDestMap {
			op := l.stateDBMgr.UpdateObject
			dest.RemoveAllPaths(peerIP, remPath)
			action, addPathsMod, addRoutes, updRoutes, delRoutes := dest.SelectRouteForLocRib(addPathCount)
			l.logger.Info(fmt.Sprintln("RemoveUpdatesFromNeighbor - dest", dest.NLRI.GetPrefix().String(),
				"SelectRouteForLocRib returned action", action, "addRoutes", addRoutes, "updRoutes", updRoutes,
				"delRoutes", delRoutes))
			updated, withdrawn, updatedAddPaths = l.updateRibOutInfo(action, addPathsMod, addRoutes, updRoutes,
				delRoutes, dest, updated, withdrawn, updatedAddPaths)
			if action == RouteActionDelete && dest.IsEmpty() {
				l.logger.Info(fmt.Sprintln("All routes removed for dest", dest.NLRI.GetPrefix().String()))
				l.removeRoutesFromRouteList(dest)
				delete(l.destPathMap[protoFamily], destIP)
				op = l.stateDBMgr.DeleteObject
			}
			op(l.GetRouteStateConfigObj(dest.GetBGPRoute()))
		}
	}

	if neighborConf != nil {
		neighborConf.SetPrefixCount(0)
	}
	return updated, withdrawn, updatedAddPaths
}

func (l *LocRib) RemoveUpdatesFromAllNeighbors(addPathCount int) {
	withdrawn := make([]*Destination, 0)
	updated := make(map[uint32]map[*Path][]*Destination)
	updatedAddPaths := make([]*Destination, 0)

	for protoFamily, ipDestMap := range l.destPathMap {
		for destIP, dest := range ipDestMap {
			op := l.stateDBMgr.UpdateObject
			dest.RemoveAllNeighborPaths()
			action, addPathsMod, addRoutes, updRoutes, delRoutes := dest.SelectRouteForLocRib(addPathCount)
			l.updateRibOutInfo(action, addPathsMod, addRoutes, updRoutes, delRoutes, dest, updated, withdrawn,
				updatedAddPaths)
			if action == RouteActionDelete && dest.IsEmpty() {
				l.removeRoutesFromRouteList(dest)
				delete(l.destPathMap[protoFamily], destIP)
				op = l.stateDBMgr.DeleteObject
			}
			op(l.GetRouteStateConfigObj(dest.GetBGPRoute()))
		}
	}
}

func (l *LocRib) GetLocRib() map[uint32]map[*Path][]*Destination {
	updated := make(map[uint32]map[*Path][]*Destination)
	for protoFamily, ipDestMap := range l.destPathMap {
		if _, ok := updated[protoFamily]; !ok {
			updated[protoFamily] = make(map[*Path][]*Destination)
		}
		for _, dest := range ipDestMap {
			if dest.LocRibPath != nil {
				updated[protoFamily][dest.LocRibPath] = append(updated[protoFamily][dest.LocRibPath], dest)
			}
		}
	}

	return updated
}

func (l *LocRib) RemoveRouteFromAggregate(ip *packet.IPPrefix, aggIP *packet.IPPrefix, srcIP string,
	protoFamily uint32, bgpAgg *config.BGPAggregate, ipDest *Destination, addPathCount int) (
	map[uint32]map[*Path][]*Destination, []*Destination, []*Destination) {
	var aggPath *Path
	var dest *Destination
	var aggDest *Destination
	var ok bool
	withdrawn := make([]*Destination, 0)
	updated := make(map[uint32]map[*Path][]*Destination)
	updatedAddPaths := make([]*Destination, 0)

	l.logger.Info(fmt.Sprintf("LocRib:RemoveRouteFromAggregate - ip %v, aggIP %v", ip, aggIP))
	if dest, ok = l.GetDest(ip, protoFamily, false); !ok {
		if ipDest == nil {
			l.logger.Info(fmt.Sprintln("RemoveRouteFromAggregate: routes ip", ip, "not found"))
			return updated, withdrawn, nil
		}
		dest = ipDest
	}
	l.logger.Info(fmt.Sprintln("RemoveRouteFromAggregate: locRibPath", dest.LocRibPath, "locRibRoutePath",
		dest.LocRibPathRoute.path))
	op := l.stateDBMgr.UpdateObject

	if aggDest, ok = l.GetDest(aggIP, protoFamily, false); !ok {
		l.logger.Info(fmt.Sprintf("LocRib:RemoveRouteFromAggregate - dest not found for aggIP %v", aggIP))
		return updated, withdrawn, nil
	}

	if aggPath = aggDest.getPathForIP(srcIP, AggregatePathId); aggPath == nil {
		l.logger.Info(fmt.Sprintf("LocRib:RemoveRouteFromAggregate - path not found for dest, aggIP %v", aggIP))
		return updated, withdrawn, nil
	}

	aggPath.removePathFromAggregate(ip.Prefix.String(), bgpAgg.GenerateASSet)
	if aggPath.isAggregatePathEmpty() {
		aggDest.RemovePath(srcIP, AggregatePathId, aggPath)
	} else {
		aggDest.setUpdateAggPath(srcIP, AggregatePathId)
	}
	aggDest.removeAggregatedDests(ip.Prefix.String())
	action, addPathsMod, addRoutes, updRoutes, delRoutes := aggDest.SelectRouteForLocRib(addPathCount)
	updated, withdrawn, updatedAddPaths = l.updateRibOutInfo(action, addPathsMod, addRoutes, updRoutes, delRoutes,
		aggDest, updated, withdrawn, updatedAddPaths)
	if action == RouteActionAdd || action == RouteActionReplace {
		dest.aggPath = aggPath
	}
	if action == RouteActionDelete && aggDest.IsEmpty() {
		l.removeRoutesFromRouteList(dest)
		delete(l.destPathMap[protoFamily], aggIP.Prefix.String())
		op = l.stateDBMgr.DeleteObject
	}
	op(l.GetRouteStateConfigObj(dest.GetBGPRoute()))

	return updated, withdrawn, updatedAddPaths
}

func (l *LocRib) AddRouteToAggregate(ip *packet.IPPrefix, aggIP *packet.IPPrefix, srcIP string, protoFamily uint32,
	ifaceIP net.IP, bgpAgg *config.BGPAggregate, addPathCount int) (map[uint32]map[*Path][]*Destination,
	[]*Destination, []*Destination) {
	var aggPath, path *Path
	var dest *Destination
	var aggDest *Destination
	var ok bool
	withdrawn := make([]*Destination, 0)
	updated := make(map[uint32]map[*Path][]*Destination)
	updatedAddPaths := make([]*Destination, 0)

	l.logger.Info(fmt.Sprintf("LocRib:AddRouteToAggregate - ip %v, aggIP %v", ip, aggIP))
	if dest, ok = l.GetDest(ip, protoFamily, false); !ok {
		l.logger.Info(fmt.Sprintln("AddRouteToAggregate: routes ip", ip, "not found"))
		return updated, withdrawn, nil
	}
	path = dest.LocRibPath

	op := l.stateDBMgr.UpdateObject
	if aggDest, ok = l.GetDest(aggIP, protoFamily, true); ok {
		aggPath = aggDest.getPathForIP(srcIP, AggregatePathId)
		l.logger.Info(fmt.Sprintf("LocRib:AddRouteToAggregate - aggIP %v found in dest, agg path %v", aggIP, aggPath))
	}

	if aggPath != nil {
		l.logger.Info(fmt.Sprintf("LocRib:AddRouteToAggregate - aggIP %v, agg path found, update path attrs", aggIP))
		aggPath.addPathToAggregate(ip.Prefix.String(), path, bgpAgg.GenerateASSet)
		aggDest.setUpdateAggPath(srcIP, AggregatePathId)
		aggDest.addAggregatedDests(ip.Prefix.String(), dest)
	} else {
		l.logger.Info(fmt.Sprintf("LocRib:AddRouteToAggregate - aggIP %v, agg path NOT found, create new path", aggIP))
		op = l.stateDBMgr.AddObject
		pathAttrs := packet.ConstructPathAttrForAggRoutes(path.PathAttrs, bgpAgg.GenerateASSet)
		if ifaceIP != nil {
			packet.SetNextHopPathAttrs(pathAttrs, ifaceIP)
		}
		packet.SetPathAttrAggregator(pathAttrs, l.gConf.AS, l.gConf.RouterId)
		aggPath = NewPath(path.rib, nil, pathAttrs, nil, RouteTypeAgg)
		aggPath.setAggregatedPath(ip.Prefix.String(), path)
		aggDest, _ := l.GetDest(aggIP, protoFamily, true)
		aggDest.AddOrUpdatePath(srcIP, AggregatePathId, aggPath)
		aggDest.addAggregatedDests(ip.Prefix.String(), dest)
	}

	nextHopStr := aggPath.GetNextHop(protoFamily).String()
	reachabilityInfo := l.GetReachabilityInfo(nextHopStr)
	aggPath.SetReachabilityForFamily(protoFamily, reachabilityInfo)

	if reachabilityInfo == nil {
		l.logger.Info(fmt.Sprintf("ProcessUpdate - next hop %s is not reachable", nextHopStr))

		if _, ok := l.unreachablePaths[nextHopStr]; !ok {
			l.unreachablePaths[nextHopStr] = make(map[*Path]map[*Destination][]uint32)
		}

		if _, ok := l.unreachablePaths[nextHopStr][aggPath]; !ok {
			l.unreachablePaths[nextHopStr][aggPath] = make(map[*Destination][]uint32)
		}
	}

	action, addPathsMod, addRoutes, updRoutes, delRoutes := aggDest.SelectRouteForLocRib(addPathCount)
	updated, withdrawn, updatedAddPaths = l.updateRibOutInfo(action, addPathsMod, addRoutes, updRoutes, delRoutes,
		aggDest, updated, withdrawn, updatedAddPaths)
	if action == RouteActionAdd || action == RouteActionReplace {
		dest.aggPath = aggPath
	}

	if reachabilityInfo != nil {
		l.logger.Info(fmt.Sprintf("ProcessUpdate - next hop %s is reachable, so process previously unreachable routes",
			nextHopStr))
		updated, withdrawn, updatedAddPaths = l.ProcessRoutesForReachableRoutes(nextHopStr, reachabilityInfo,
			addPathCount, updated, withdrawn, updatedAddPaths)
	}

	op(l.GetRouteStateConfigObj(dest.GetBGPRoute()))
	return updated, withdrawn, updatedAddPaths
}

func (l *LocRib) removeRoutesFromRouteList(dest *Destination) {
	defer l.routeMutex.Unlock()
	l.routeMutex.Lock()
	idx := dest.routeListIdx
	if idx != -1 {
		l.logger.Info(fmt.Sprintln("removeRoutesFromRouteList: remove dest at idx", idx))
		if !l.activeGet {
			l.routeList[idx] = l.routeList[len(l.routeList)-1]
			l.routeList[idx].routeListIdx = idx
			l.routeList[len(l.routeList)-1] = nil
			l.routeList = l.routeList[:len(l.routeList)-1]
		} else {
			l.routeList[idx] = nil
			l.routeListDirty = true
		}
	}
}

func (l *LocRib) addRoutesToRouteList(dest *Destination) {
	defer l.routeMutex.Unlock()
	l.routeMutex.Lock()
	l.routeList = append(l.routeList, dest)
	l.logger.Info(fmt.Sprintln("addRoutesToRouteList: added dest at idx", len(l.routeList)-1))
	dest.routeListIdx = len(l.routeList) - 1
}

func (l *LocRib) ResetRouteList() {
	defer l.routeMutex.Unlock()
	l.routeMutex.Lock()
	l.activeGet = false

	if !l.routeListDirty {
		return
	}

	lastIdx := len(l.routeList) - 1
	var modIdx, idx int
	for idx = 0; idx < len(l.routeList); idx++ {
		if l.routeList[idx] == nil {
			for modIdx = lastIdx; modIdx > idx && l.routeList[modIdx] == nil; modIdx-- {
			}
			if modIdx <= idx {
				lastIdx = idx
				break
			}
			l.routeList[idx] = l.routeList[modIdx]
			l.routeList[idx].routeListIdx = idx
			l.routeList[modIdx] = nil
			lastIdx = modIdx
		}
	}
	l.routeList = l.routeList[:idx]
	l.routeListDirty = false
}

func (l *LocRib) GetBGPRoute(prefix string) *bgpd.BGPRouteState {
	defer l.routeMutex.RUnlock()
	l.routeMutex.RLock()

	for _, ipDestMap := range l.destPathMap {
		if dest, ok := ipDestMap[prefix]; ok {
			return dest.GetBGPRoute()
		}
	}

	return nil
}

func (l *LocRib) BulkGetBGPRoutes(index int, count int) (int, int, []*bgpd.BGPRouteState) {
	l.timer.Stop()
	if index == 0 && l.activeGet {
		l.ResetRouteList()
	}
	l.activeGet = true

	defer l.routeMutex.RUnlock()
	l.routeMutex.RLock()

	var i int
	n := 0
	result := make([]*bgpd.BGPRouteState, count)
	for i = index; i < len(l.routeList) && n < count; i++ {
		if l.routeList[i] != nil && len(l.routeList[i].BGPRouteState.Paths) > 0 {
			result[n] = l.routeList[i].GetBGPRoute()
			n++
		}
	}
	result = result[:n]

	if i >= len(l.routeList) {
		i = 0
	}

	l.timer.Reset(time.Duration(ResetTime) * time.Second)
	return i, n, result
}
