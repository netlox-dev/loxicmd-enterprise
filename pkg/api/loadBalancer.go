/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package api

import (
	"fmt"
	"sort"
)

type LoadBalancer struct {
	CommonAPI
}

type EpSelect uint
type LbMode int32
type LbOP int32
type LbSec int32

type LbRuleModGet struct {
	LbRules []LoadBalancerModel `json:"lbAttr"`
}

type LoadBalancerModel struct {
	Service      LoadBalancerService    `json:"serviceArguments" yaml:"serviceArguments"`
	SecondaryIPs []LoadBalancerSecIp    `json:"secondaryIPs" yaml:"secondaryIPs"`
	SrcIPs       []LbAllowedSrcIPArg    `json:"allowedSources" yaml:"allowedSources"`
	Endpoints    []LoadBalancerEndpoint `json:"endpoints" yaml:"endpoints"`
}

type LoadBalancerService struct {
	ExternalIP           string   `json:"externalIP"         yaml:"externalIP"`
	Port                 uint16   `json:"port"               yaml:"port"`
	PortMax              uint16   `json:"portMax,omitempty"  yaml:"portmax"`
	Protocol             string   `json:"protocol"           yaml:"protocol"`
	Sel                  EpSelect `json:"sel"                yaml:"sel"`
	Mode                 LbMode   `json:"mode"               yaml:"mode"`
	BGP                  bool     `json:"BGP"                yaml:"BGP"`
	Monitor              bool     `json:"Monitor"            yaml:"Monitor"`
	Timeout              uint32   `json:"inactiveTimeOut"    yaml:"inactiveTimeOut"`
	Block                uint32   `json:"block"              yaml:"block"`
	Managed              bool     `json:"managed,omitempty"  yaml:"managed"`
	Name                 string   `json:"name,omitempty"     yaml:"name"`
	Snat                 bool     `json:"snat,omitempty"`
	Oper                 LbOP     `json:"oper,omitempty"`
	Security             LbSec    `json:"security,omitempty" yaml:"security"`
	Host                 string   `json:"host,omitempty"     yaml:"path"`
	PpV2                 bool     `json:"proxyprotocolv2"    yaml:"proxyprotocolv2"`
	Egress               bool     `json:"egress"             yaml:"egress"`
	LLMType              string   `json:"llmType,omitempty" yaml:"llmType"`
	TraceType            string   `json:"traceType,omitempty" yaml:"traceType"`
	PathPrefix           string   `json:"pathPrefix,omitempty"    yaml:"pathPrefix"`
	PathMatchMode        string   `json:"pathMatchMode,omitempty" yaml:"pathMatchMode"`
	BackendProtocol      string   `json:"backendProtocol,omitempty" yaml:"backendProtocol"`
	SessionHeaderName    string   `json:"sessionHeaderName,omitempty" yaml:"sessionHeaderName"`
	ChwblPrefixHashLevel int      `json:"chwblPrefixHashLevel,omitempty" yaml:"chwblPrefixHashLevel"`
	ChwblPrefixHashFlags int      `json:"chwblPrefixHashFlags,omitempty" yaml:"chwblPrefixHashFlags"`
	ChwblMeanLoadFactor  int      `json:"chwblMeanLoadFactor,omitempty" yaml:"chwblMeanLoadFactor"`
	ChwblReplication     int      `json:"chwblReplication,omitempty" yaml:"chwblReplication"`
	ChwblEnableCacheSalt bool     `json:"chwblEnableCacheSalt,omitempty" yaml:"chwblEnableCacheSalt"`
	// Deprecated fields - to be removed eventually
	LLMTypeOld              string `json:"llm_type,omitempty" yaml:"llm_type" deprecated:"Use llmType instead of llm_type"`
	TraceTypeOld            string `json:"trace_type,omitempty" yaml:"trace_type" deprecated:"Use traceType instead of trace_type"`
	PathPrefixOld           string `json:"path_prefix,omitempty"    yaml:"path_prefix" deprecated:"Use pathPrefix instead of path_prefix"`
	PathMatchModeOld        string `json:"path_match_mode,omitempty" yaml:"path_match_mode" deprecated:"Use pathMatchMode instead of path_match_mode"`
	BackendProtocolOld      string `json:"backend_protocol,omitempty" yaml:"backend_protocol" deprecated:"Use backendProtocol instead of backend_protocol"`
	SessionHeaderNameOld    string `json:"session_header_name,omitempty" yaml:"session_header_name" deprecated:"Use sessionHeaderName instead of session_header_name"`
	ChwblPrefixHashLevelOld int    `json:"chwbl_prefix_hash_level,omitempty" yaml:"chwbl_prefix_hash_level" deprecated:"Use chwblPrefixHashLevel instead of chwbl_prefix_hash_level"`
	ChwblPrefixHashFlagsOld int    `json:"chwbl_prefix_hash_flags,omitempty" yaml:"chwbl_prefix_hash_flags" deprecated:"Use chwblPrefixHashFlags instead of chwbl_prefix_hash_flags"`
	ChwblMeanLoadFactorOld  int    `json:"chwbl_mean_load_factor,omitempty" yaml:"chwbl_mean_load_factor" deprecated:"Use chwblMeanLoadFactor instead of chwbl_mean_load_factor"`
	ChwblReplicationOld     int    `json:"chwbl_replication,omitempty" yaml:"chwbl_replication" deprecated:"Use chwblReplication instead of chwbl_replication"`
	ChwblEnableCacheSaltOld bool   `json:"chwbl_enable_cache_salt,omitempty" yaml:"chwbl_enable_cache_salt" deprecated:"Use chwblEnableCacheSalt instead of chwbl_enable_cache_salt"`
}

type LoadBalancerEndpoint struct {
	EndpointIP string `json:"endpointIP" yaml:"endpointIP"`
	TargetPort uint16 `json:"targetPort" yaml:"targetPort"`
	Weight     uint8  `json:"weight"     yaml:"weight"`
	State      string `json:"state"      yaml:"state"`
	Counter    string `json:"counter"    yaml:"counter"`
}

type LoadBalancerSecIp struct {
	SecondaryIP string `json:"secondaryIP" yaml:"secondaryIP"`
}

type LbAllowedSrcIPArg struct {
	// Prefix - Allowed Prefix
	Prefix string `json:"prefix" yaml:"prefix"`
}

type ConfigurationLBFile struct {
	TypeMeta   `yaml:",inline"`
	ObjectMeta `yaml:"metadata,omitempty"`
	Spec       LoadBalancerModel `yaml:"spec"`
}

func (service LoadBalancerService) Key() string {
	return fmt.Sprintf("%s|%05d|%s", service.ExternalIP, service.Port, service.Protocol)
}

func (lbresp LbRuleModGet) Sort() {
	sort.Slice(lbresp.LbRules, func(i, j int) bool {
		return lbresp.LbRules[i].Service.Key() < lbresp.LbRules[j].Service.Key()
	})
}
