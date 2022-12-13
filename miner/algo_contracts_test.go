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

	// Send the entire balance of the contract to the caller or revert and
	// consume all gas, if the contracts balance is zero.
	//
	// pc    op           stack                  bytecode
	// 0x00  SELFBALANCE  bal                    0x47
	// 0x01  PUSH1 0x05   0x05 bal               0x6005
	// 0x03  JUMPI        .                      0x57
	// 0x04  INVALID      .                      0xfe
	// 0x05  JUMPDEST     .                      0x5b
	//
	// 0x06  MSIZE        0                      0x59
	// 0x07  MSIZE        0 0                    0x59
	// 0x08  MSIZE        0 0 0                  0x59
	// 0x09  MSIZE        0 0 0 0                0x59
	// 0x0a  SELFBALANCE  bal 0 0 0 0 0          0x47
	// 0x0b  CALLER       clr bal 0 0 0 0 0      0x33
	// 0x0c  GAS          gas clr bal 0 0 0 0 0  0x5a
	// 0x0d  CALL         .                      0xf1
	contractSendBalance = parseCode("0x47600557fe5b5959595947335af100")
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
