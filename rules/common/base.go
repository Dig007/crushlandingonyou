package common

import (
	"errors"
	"net/netip"
	"strings"
)

var (
	errPayload = errors.New("payload error")
	noResolve  = "no-resolve"
)

func HasNoResolve(params []string) bool {
	for _, p := range params {
		if p == noResolve {
			return true
		}
	}
	return false
}

func FindSourceIPs(params []string) []*netip.Prefix {
	var ips []*netip.Prefix
	for _, p := range params {
		if p == noResolve || len(p) < 7 {
			continue
		}
		ipnet, err := netip.ParsePrefix(p)
		if err != nil {
			continue
		}
		ips = append(ips, &ipnet)
	}

	if len(ips) > 0 {
		return ips
	}
	return nil
}

func FindProcessName(params []string) []string {
	var processNames []string
	for _, p := range params {
		if strings.HasPrefix(p, "P:") {
			processNames = append(processNames, strings.TrimPrefix(p, "P:"))
		}
	}

	if len(processNames) > 0 {
		return processNames
	}
	return nil
}
