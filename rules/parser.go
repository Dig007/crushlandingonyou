package rules

import (
	"fmt"

	C "github.com/Dreamacro/clash/constant"
	RC "github.com/Dreamacro/clash/rules/common"
	RP "github.com/Dreamacro/clash/rules/provider"
)

func ParseRule(tp, payload, target string, params []string) (parsed C.Rule, parseErr error) {
	switch tp {
	case "DOMAIN":
		parsed = RC.NewDomain(payload, target)
	case "DOMAIN-SUFFIX":
		parsed = RC.NewDomainSuffix(payload, target)
	case "DOMAIN-KEYWORD":
		parsed = RC.NewDomainKeyword(payload, target)
	case "GEOIP":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewGEOIP(payload, target, noResolve)
	case "IP-CIDR", "IP-CIDR6":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RC.NewIPCIDR(payload, target, RC.WithIPCIDRNoResolve(noResolve))
	case "SRC-IP-CIDR":
		parsed, parseErr = RC.NewIPCIDR(payload, target, RC.WithIPCIDRSourceIP(true), RC.WithIPCIDRNoResolve(true))
	case "SRC-PORT":
		parsed, parseErr = RC.NewPort(payload, target, true)
	case "DST-PORT":
		parsed, parseErr = RC.NewPort(payload, target, false)
	case "PROCESS-NAME":
		parsed, parseErr = RC.NewProcess(payload, target, true)
	case "RULE-SET":
		noResolve := RC.HasNoResolve(params)
		parsed, parseErr = RP.NewRuleSet(payload, target, noResolve, ParseRule)
	case "MATCH":
		parsed = RC.NewMatch(target)
		parseErr = nil
	default:
		parseErr = fmt.Errorf("unsupported rule type %s", tp)
	}

	if parseErr != nil {
		return nil, parseErr
	}

	return
}
