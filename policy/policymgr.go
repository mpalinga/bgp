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

// policy.go
package policy

import (
	"fmt"
	"l3/bgp/config"
	"utils/logging"
	utilspolicy "utils/policy"
)

var PolicyManager *BGPPolicyManager

type BGPPolicyManager struct {
	logger          *logging.Writer
	policyEngines   []BGPPolicyEngine
	ConditionCfgCh  chan utilspolicy.PolicyConditionConfig
	ActionCfgCh     chan utilspolicy.PolicyActionConfig
	StmtCfgCh       chan utilspolicy.PolicyStmtConfig
	DefinitionCfgCh chan utilspolicy.PolicyDefinitionConfig
	ConditionDelCh  chan string
	ActionDelCh     chan string
	StmtDelCh       chan string
	DefinitionDelCh chan string
	policyPlugin    config.PolicyMgrIntf
}

func NewPolicyManager(logger *logging.Writer, pMgr config.PolicyMgrIntf) *BGPPolicyManager {
	if PolicyManager == nil {
		policyManager := &BGPPolicyManager{}
		policyManager.logger = logger
		policyManager.policyEngines = make([]BGPPolicyEngine, 0)
		policyManager.ConditionCfgCh = make(chan utilspolicy.PolicyConditionConfig)
		policyManager.ActionCfgCh = make(chan utilspolicy.PolicyActionConfig)
		policyManager.StmtCfgCh = make(chan utilspolicy.PolicyStmtConfig)
		policyManager.DefinitionCfgCh = make(chan utilspolicy.PolicyDefinitionConfig)
		policyManager.ConditionDelCh = make(chan string)
		policyManager.ActionDelCh = make(chan string)
		policyManager.StmtDelCh = make(chan string)
		policyManager.DefinitionDelCh = make(chan string)
		policyManager.policyPlugin = pMgr
		PolicyManager = policyManager
	}

	return PolicyManager
}

func (eng *BGPPolicyManager) AddPolicyEngine(bgpPE BGPPolicyEngine) {
	eng.policyEngines = append(eng.policyEngines, bgpPE)
}

func (eng *BGPPolicyManager) StartPolicyEngine() {
	eng.policyPlugin.Start()
	for {
		select {
		case condCfg := <-eng.ConditionCfgCh:
			eng.logger.Info(fmt.Sprintln("BGPPolicyEngine - create condition", condCfg.Name))
			for _, pe := range eng.policyEngines {
				pe.CreatePolicyCondition(condCfg)
			}

		case actionCfg := <-eng.ActionCfgCh:
			eng.logger.Info(fmt.Sprintln("BGPPolicyEngine - create action", actionCfg.Name))
			for _, pe := range eng.policyEngines {
				pe.CreatePolicyAction(actionCfg)
			}

		case stmtCfg := <-eng.StmtCfgCh:
			eng.logger.Info(fmt.Sprintln("BGPPolicyEngine - create statement", stmtCfg.Name))
			for _, pe := range eng.policyEngines {
				pe.CreatePolicyStmt(stmtCfg)
			}

		case defCfg := <-eng.DefinitionCfgCh:
			eng.logger.Info(fmt.Sprintln("BGPPolicyEngine - create policy", defCfg.Name))
			for _, pe := range eng.policyEngines {
				pe.CreatePolicyDefinition(defCfg)
			}

		case conditionName := <-eng.ConditionDelCh:
			eng.logger.Info(fmt.Sprintln("BGPPolicyEngine - delete condition", conditionName))
			for _, pe := range eng.policyEngines {
				pe.DeletePolicyCondition(conditionName)
			}

		case actionName := <-eng.ActionDelCh:
			eng.logger.Info(fmt.Sprintln("BGPPolicyEngine - delete action", actionName))
			for _, pe := range eng.policyEngines {
				pe.DeletePolicyAction(actionName)
			}

		case stmtName := <-eng.StmtDelCh:
			eng.logger.Info(fmt.Sprintln("BGPPolicyEngine - delete statment", stmtName))
			for _, pe := range eng.policyEngines {
				pe.DeletePolicyStmt(stmtName)
			}

		case policyName := <-eng.DefinitionDelCh:
			eng.logger.Info(fmt.Sprintln("BGPPolicyEngine - delete statment", policyName))
			for _, pe := range eng.policyEngines {
				pe.DeletePolicyDefinition(policyName)
			}
		}
	}
}
