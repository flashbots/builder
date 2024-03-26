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
	// contractSendBalance = parseCode("0x47600557fe5b5959595947335af100")

	// Send the entire balance of the contract to a blacklist address 0xff and
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
	// 0x0a  SELFBALANCE  bal 0 0 0 0            0x47
	// 0x0b  PUSH1 0xff   0xff bal 0 0 0 0       0x60ff
	// 0x0d  GAS          gas 0xff bal 0 0 0 0   0x5a
	// 0x0e  CALL         suc                    0xf1
	// 0x0f  PUSH1 0x13   0x13 suc               0x6013
	// 0x11  JUMPI        .                      0x57
	// 0x12  INVALID      .                      0xfe
	// 0x13  JUMPDEST     .                      0x5b
	// 0x14  PUSH1 0xff   0xff                   0x60ff //Debug code to check the balance of 0xff
	// 0x15  BALANCE      0xffbal                0x31 //Debug code to check the balance of 0xff
	// 0x16  STOP         .                      0x00
	contractSend0xff = parseCode("0x47600557fe5b595959594760ff5af1601357fe5b60ff3100")
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
