package provider

import (
	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
)

type domainStrategy struct {
	count       int
	domainRules *trie.DomainTrie
}

func (d *domainStrategy) Match(metadata *C.Metadata) bool {
	return d.domainRules != nil && d.domainRules.Search(metadata.Host) != nil
}

func (d *domainStrategy) Count() int {
	return d.count
}

func (d *domainStrategy) ShouldResolveIP() bool {
	return false
}

func (d *domainStrategy) ShouldFindProcess() bool {
	return false
}

func (d *domainStrategy) OnUpdate(rules []string) {
	domainTrie := trie.New()
	count := 0
	for _, rule := range rules {
		err := domainTrie.Insert(rule, true)
		if err != nil {
			log.Warnln("invalid domain:[%s]", rule)
		} else {
			count++
		}
	}

	d.domainRules = domainTrie
	d.count = count
}

func NewDomainStrategy() *domainStrategy {
	return &domainStrategy{}
}
