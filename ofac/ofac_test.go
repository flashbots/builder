package ofac

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestCheckCompliance(t *testing.T) {
	UpdateComplianceLists(
		map[string]ComplianceList{
			"blacklist": {
				common.HexToAddress("0x0"): {},
				common.HexToAddress("0x1"): {},
			},
		},
	)
	if CheckCompliance("blacklist", []common.Address{common.HexToAddress("0x2"), common.HexToAddress("0x0")}) == true {
		t.Error("CheckCompliance failed")
	}
	if CheckCompliance("blacklist", []common.Address{common.HexToAddress("0x2"), common.HexToAddress("0x1")}) == true {
		t.Error("CheckCompliance failed")
	}
	if CheckCompliance("random", []common.Address{common.HexToAddress("0x2"), common.HexToAddress("0x3")}) == false {
		t.Error("CheckCompliance failed")
	}
}
