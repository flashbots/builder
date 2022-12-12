package miner

import (
	"encoding/hex"
)

// Contracts used for testing.
var (
	// Always revert and consume all gas.
	//
	// pc    op       bytecode
	// 0x00  INVALID  0xfe
	contractRevert = parseCode("0xfe")
)

// parseCode converts a hex bytecode to a byte slice, or panics if the hex
// bytecode is invalid.
func parseCode(hexStr string) []byte {
	if hexStr[0] == '0' && (hexStr[1] == 'x' || hexStr[1] == 'X') {
		hexStr = hexStr[2:]
	}
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return data
}
