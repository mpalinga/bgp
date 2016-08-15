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

// conn_test.go
package packet

import (
	"net"
	"testing"
)

func TestBGPUpdateMessageWithdrawnRoutesLenMoreThanMaxAllowed(t *testing.T) {
	bgpMsgs := make([]*BGPMessage, 0)
	prefix := []byte{0x0A, 0x00, 0x00}
	numWithdrawnRoutes := []int{1018, 1019, 2036, 2037, 2038, 3054, 3055}
	numMsgs := []int{1, 2, 2, 3, 3, 3, 4}
	if len(numWithdrawnRoutes) != len(numMsgs) {
		t.Fatal("TestBGPUpdateMessageWithdrawnRoutesLenMoreThanMaxAllowed input slices are not the same size.",
			"withdrawn routes slice len =", len(numWithdrawnRoutes), "Number of messages slice len =", len(numMsgs))
	}
	for _, num := range numWithdrawnRoutes {
		withdrawnRoutes := make([]NLRI, 0)
		for i := 0; i < num; i++ {
			ip := make([]byte, 4)
			prefix[len(prefix)-1] += 1
			if prefix[len(prefix)-1] == 0 {
				prefix[len(prefix)-2] += 1
			}
			copy(ip, prefix)
			withdrawnRoutes = append(withdrawnRoutes, NewIPPrefix(ip, uint8(len(prefix)*8)))
		}
		bgpMsgs = append(bgpMsgs, NewBGPUpdateMessage(withdrawnRoutes, nil, nil))
	}

	for idx, _ := range bgpMsgs {
		updateMsgs := ConstructMaxSizedUpdatePackets(bgpMsgs[idx])
		if len(updateMsgs) != numMsgs[idx] {
			t.Error("ConstructMaxSizedUpdatePackets called... expected", numMsgs[idx], "update messages, got", len(updateMsgs))
		} else {
			t.Log("ConstructMaxSizedUpdatePackets called... expected", numMsgs[idx], "update messages, got", len(updateMsgs))
		}
	}
}

func TestBGPUpdateMessageNLRILenMoreThanMaxAllowed(t *testing.T) {
	pathAttrs := ConstructPathAttrForConnRoutes(net.ParseIP("10.1.10.10"), 12345)
	bgpMsg := NewBGPUpdateMessage(nil, pathAttrs, nil)
	PrependAS(bgpMsg, 12345, 4)
	updateMsg := bgpMsg.Body.(*BGPUpdate)
	pathAttrs = updateMsg.PathAttributes

	bgpMsgs := make([]*BGPMessage, 0)
	prefix := []byte{0x0A, 0x00, 0x00}
	numNLRIs := []int{1013, 1014, 2026, 2027, 2028, 3039, 3040}
	numMsgs := []int{1, 2, 2, 3, 3, 3, 4}
	if len(numNLRIs) != len(numMsgs) {
		t.Fatal("TestBGPUpdateMessageWithdrawnRoutesLenMoreThanMaxAllowed input slices are not the same size.",
			"NLRIs slice len =", len(numNLRIs), "Number of messages slice len =", len(numMsgs))
	}
	for _, num := range numNLRIs {
		nlris := make([]NLRI, 0)
		for i := 0; i < num; i++ {
			ip := make([]byte, 4)
			prefix[len(prefix)-1] += 1
			if prefix[len(prefix)-1] == 0 {
				prefix[len(prefix)-2] += 1
			}
			copy(ip, prefix)
			nlris = append(nlris, NewIPPrefix(ip, uint8(len(prefix)*8)))
		}
		bgpMsgs = append(bgpMsgs, NewBGPUpdateMessage(nil, pathAttrs, nlris))
	}

	for idx, _ := range bgpMsgs {
		updateMsgs := ConstructMaxSizedUpdatePackets(bgpMsgs[idx])
		if len(updateMsgs) != numMsgs[idx] {
			t.Error("ConstructMaxSizedUpdatePackets called... expected", numMsgs[idx], "update messages, got", len(updateMsgs))
		} else {
			t.Log("ConstructMaxSizedUpdatePackets called... expected", numMsgs[idx], "update messages, got", len(updateMsgs))
		}
	}
}

func TestBGPUpdateForConnectedRoutes(t *testing.T) {
	ip := net.ParseIP("10.1.10.1")
	pa := ConstructPathAttrForConnRoutes(ip, 1234)
	nlri := make([]NLRI, 0)
	dest := ConstructIPPrefix("20.1.20.0", "255.255.255.0")
	nlri = append(nlri, dest)
	dest, err := ConstructIPPrefixFromCIDR("30.1.10.10/16")
	if err != nil {
		t.Error("ConstructIPPrefixFromCIDR failed with error:", err)
	}
	nlri = append(nlri, dest)
	NewBGPUpdateMessage(make([]NLRI, 0), pa, nlri)
}
