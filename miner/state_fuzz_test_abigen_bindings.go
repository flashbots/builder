// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package miner

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// StatefuzztestMetaData contains all meta data concerning the Statefuzztest contract.
var StatefuzztestMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"balances\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"newBalance\",\"type\":\"uint256\"}],\"name\":\"changeBalance\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"key\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"newValue\",\"type\":\"bytes\"}],\"name\":\"changeStorage\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"key\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"value\",\"type\":\"bytes\"}],\"name\":\"createObject\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"isSelfDestructed\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"key\",\"type\":\"bytes32\"}],\"name\":\"resetObject\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"selfDestruct\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"storageData\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
	Bin: "0x608060405234801561001057600080fd5b50610b1f806100206000396000f3fe608060405234801561001057600080fd5b50600436106100885760003560e01c8063b0d50e381161005b578063b0d50e38146100ff578063c522de441461012f578063d58010651461015f578063f529d4481461017b57610088565b806327e235e31461008d5780637a5ae62e146100bd5780639cb8a26a146100d9578063a2601e0a146100e3575b600080fd5b6100a760048036038101906100a29190610462565b610197565b6040516100b491906104a8565b60405180910390f35b6100d760048036038101906100d291906104f9565b6101af565b005b6100e16101d1565b005b6100fd60048036038101906100f8919061066c565b610242565b005b61011960048036038101906101149190610462565b610267565b60405161012691906106e3565b60405180910390f35b610149600480360381019061014491906104f9565b610287565b604051610156919061077d565b60405180910390f35b6101796004803603810190610174919061066c565b610327565b005b610195600480360381019061019091906107cb565b61034c565b005b60006020528060005260406000206000915090505481565b6001600082815260200190815260200160002060006101ce9190610393565b50565b6001600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055503373ffffffffffffffffffffffffffffffffffffffff16ff5b806001600084815260200190815260200160002090816102629190610a17565b505050565b60026020528060005260406000206000915054906101000a900460ff1681565b600160205280600052604060002060009150905080546102a69061083a565b80601f01602080910402602001604051908101604052809291908181526020018280546102d29061083a565b801561031f5780601f106102f45761010080835404028352916020019161031f565b820191906000526020600020905b81548152906001019060200180831161030257829003601f168201915b505050505081565b806001600084815260200190815260200160002090816103479190610a17565b505050565b806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505050565b50805461039f9061083a565b6000825580601f106103b157506103d0565b601f0160209004906000526020600020908101906103cf91906103d3565b5b50565b5b808211156103ec5760008160009055506001016103d4565b5090565b6000604051905090565b600080fd5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061042f82610404565b9050919050565b61043f81610424565b811461044a57600080fd5b50565b60008135905061045c81610436565b92915050565b600060208284031215610478576104776103fa565b5b60006104868482850161044d565b91505092915050565b6000819050919050565b6104a28161048f565b82525050565b60006020820190506104bd6000830184610499565b92915050565b6000819050919050565b6104d6816104c3565b81146104e157600080fd5b50565b6000813590506104f3816104cd565b92915050565b60006020828403121561050f5761050e6103fa565b5b600061051d848285016104e4565b91505092915050565b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61057982610530565b810181811067ffffffffffffffff8211171561059857610597610541565b5b80604052505050565b60006105ab6103f0565b90506105b78282610570565b919050565b600067ffffffffffffffff8211156105d7576105d6610541565b5b6105e082610530565b9050602081019050919050565b82818337600083830152505050565b600061060f61060a846105bc565b6105a1565b90508281526020810184848401111561062b5761062a61052b565b5b6106368482856105ed565b509392505050565b600082601f83011261065357610652610526565b5b81356106638482602086016105fc565b91505092915050565b60008060408385031215610683576106826103fa565b5b6000610691858286016104e4565b925050602083013567ffffffffffffffff8111156106b2576106b16103ff565b5b6106be8582860161063e565b9150509250929050565b60008115159050919050565b6106dd816106c8565b82525050565b60006020820190506106f860008301846106d4565b92915050565b600081519050919050565b600082825260208201905092915050565b60005b8381101561073857808201518184015260208101905061071d565b60008484015250505050565b600061074f826106fe565b6107598185610709565b935061076981856020860161071a565b61077281610530565b840191505092915050565b600060208201905081810360008301526107978184610744565b905092915050565b6107a88161048f565b81146107b357600080fd5b50565b6000813590506107c58161079f565b92915050565b600080604083850312156107e2576107e16103fa565b5b60006107f08582860161044d565b9250506020610801858286016107b6565b9150509250929050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b6000600282049050600182168061085257607f821691505b6020821081036108655761086461080b565b5b50919050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b6000600883026108cd7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82610890565b6108d78683610890565b95508019841693508086168417925050509392505050565b6000819050919050565b600061091461090f61090a8461048f565b6108ef565b61048f565b9050919050565b6000819050919050565b61092e836108f9565b61094261093a8261091b565b84845461089d565b825550505050565b600090565b61095761094a565b610962818484610925565b505050565b5b818110156109865761097b60008261094f565b600181019050610968565b5050565b601f8211156109cb5761099c8161086b565b6109a584610880565b810160208510156109b4578190505b6109c86109c085610880565b830182610967565b50505b505050565b600082821c905092915050565b60006109ee600019846008026109d0565b1980831691505092915050565b6000610a0783836109dd565b9150826002028217905092915050565b610a20826106fe565b67ffffffffffffffff811115610a3957610a38610541565b5b610a43825461083a565b610a4e82828561098a565b600060209050601f831160018114610a815760008415610a6f578287015190505b610a7985826109fb565b865550610ae1565b601f198416610a8f8661086b565b60005b82811015610ab757848901518255600182019150602085019450602081019050610a92565b86831015610ad45784890151610ad0601f8916826109dd565b8355505b6001600288020188555050505b50505050505056fea26469706673582212202f3e2761204e887bab7c8f092e2346bad94e865f80979db9a6915f9d2bdbc03c64736f6c63430008130033",
}

// StatefuzztestABI is the input ABI used to generate the binding from.
// Deprecated: Use StatefuzztestMetaData.ABI instead.
var StatefuzztestABI = StatefuzztestMetaData.ABI

// StatefuzztestBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use StatefuzztestMetaData.Bin instead.
var StatefuzztestBin = StatefuzztestMetaData.Bin

// DeployStatefuzztest deploys a new Ethereum contract, binding an instance of Statefuzztest to it.
func DeployStatefuzztest(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *Statefuzztest, error) {
	parsed, err := StatefuzztestMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(StatefuzztestBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &Statefuzztest{StatefuzztestCaller: StatefuzztestCaller{contract: contract}, StatefuzztestTransactor: StatefuzztestTransactor{contract: contract}, StatefuzztestFilterer: StatefuzztestFilterer{contract: contract}}, nil
}

// Statefuzztest is an auto generated Go binding around an Ethereum contract.
type Statefuzztest struct {
	StatefuzztestCaller     // Read-only binding to the contract
	StatefuzztestTransactor // Write-only binding to the contract
	StatefuzztestFilterer   // Log filterer for contract events
}

// StatefuzztestCaller is an auto generated read-only Go binding around an Ethereum contract.
type StatefuzztestCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StatefuzztestTransactor is an auto generated write-only Go binding around an Ethereum contract.
type StatefuzztestTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StatefuzztestFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type StatefuzztestFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StatefuzztestSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type StatefuzztestSession struct {
	Contract     *Statefuzztest    // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// StatefuzztestCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type StatefuzztestCallerSession struct {
	Contract *StatefuzztestCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts        // Call options to use throughout this session
}

// StatefuzztestTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type StatefuzztestTransactorSession struct {
	Contract     *StatefuzztestTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts        // Transaction auth options to use throughout this session
}

// StatefuzztestRaw is an auto generated low-level Go binding around an Ethereum contract.
type StatefuzztestRaw struct {
	Contract *Statefuzztest // Generic contract binding to access the raw methods on
}

// StatefuzztestCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type StatefuzztestCallerRaw struct {
	Contract *StatefuzztestCaller // Generic read-only contract binding to access the raw methods on
}

// StatefuzztestTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type StatefuzztestTransactorRaw struct {
	Contract *StatefuzztestTransactor // Generic write-only contract binding to access the raw methods on
}

// NewStatefuzztest creates a new instance of Statefuzztest, bound to a specific deployed contract.
func NewStatefuzztest(address common.Address, backend bind.ContractBackend) (*Statefuzztest, error) {
	contract, err := bindStatefuzztest(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Statefuzztest{StatefuzztestCaller: StatefuzztestCaller{contract: contract}, StatefuzztestTransactor: StatefuzztestTransactor{contract: contract}, StatefuzztestFilterer: StatefuzztestFilterer{contract: contract}}, nil
}

// NewStatefuzztestCaller creates a new read-only instance of Statefuzztest, bound to a specific deployed contract.
func NewStatefuzztestCaller(address common.Address, caller bind.ContractCaller) (*StatefuzztestCaller, error) {
	contract, err := bindStatefuzztest(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &StatefuzztestCaller{contract: contract}, nil
}

// NewStatefuzztestTransactor creates a new write-only instance of Statefuzztest, bound to a specific deployed contract.
func NewStatefuzztestTransactor(address common.Address, transactor bind.ContractTransactor) (*StatefuzztestTransactor, error) {
	contract, err := bindStatefuzztest(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &StatefuzztestTransactor{contract: contract}, nil
}

// NewStatefuzztestFilterer creates a new log filterer instance of Statefuzztest, bound to a specific deployed contract.
func NewStatefuzztestFilterer(address common.Address, filterer bind.ContractFilterer) (*StatefuzztestFilterer, error) {
	contract, err := bindStatefuzztest(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &StatefuzztestFilterer{contract: contract}, nil
}

// bindStatefuzztest binds a generic wrapper to an already deployed contract.
func bindStatefuzztest(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := StatefuzztestMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Statefuzztest *StatefuzztestRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Statefuzztest.Contract.StatefuzztestCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Statefuzztest *StatefuzztestRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Statefuzztest.Contract.StatefuzztestTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Statefuzztest *StatefuzztestRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Statefuzztest.Contract.StatefuzztestTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Statefuzztest *StatefuzztestCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Statefuzztest.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Statefuzztest *StatefuzztestTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Statefuzztest.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Statefuzztest *StatefuzztestTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Statefuzztest.Contract.contract.Transact(opts, method, params...)
}

// Balances is a free data retrieval call binding the contract method 0x27e235e3.
//
// Solidity: function balances(address ) view returns(uint256)
func (_Statefuzztest *StatefuzztestCaller) Balances(opts *bind.CallOpts, arg0 common.Address) (*big.Int, error) {
	var out []interface{}
	err := _Statefuzztest.contract.Call(opts, &out, "balances", arg0)

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// Balances is a free data retrieval call binding the contract method 0x27e235e3.
//
// Solidity: function balances(address ) view returns(uint256)
func (_Statefuzztest *StatefuzztestSession) Balances(arg0 common.Address) (*big.Int, error) {
	return _Statefuzztest.Contract.Balances(&_Statefuzztest.CallOpts, arg0)
}

// Balances is a free data retrieval call binding the contract method 0x27e235e3.
//
// Solidity: function balances(address ) view returns(uint256)
func (_Statefuzztest *StatefuzztestCallerSession) Balances(arg0 common.Address) (*big.Int, error) {
	return _Statefuzztest.Contract.Balances(&_Statefuzztest.CallOpts, arg0)
}

// IsSelfDestructed is a free data retrieval call binding the contract method 0xb0d50e38.
//
// Solidity: function isSelfDestructed(address ) view returns(bool)
func (_Statefuzztest *StatefuzztestCaller) IsSelfDestructed(opts *bind.CallOpts, arg0 common.Address) (bool, error) {
	var out []interface{}
	err := _Statefuzztest.contract.Call(opts, &out, "isSelfDestructed", arg0)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// IsSelfDestructed is a free data retrieval call binding the contract method 0xb0d50e38.
//
// Solidity: function isSelfDestructed(address ) view returns(bool)
func (_Statefuzztest *StatefuzztestSession) IsSelfDestructed(arg0 common.Address) (bool, error) {
	return _Statefuzztest.Contract.IsSelfDestructed(&_Statefuzztest.CallOpts, arg0)
}

// IsSelfDestructed is a free data retrieval call binding the contract method 0xb0d50e38.
//
// Solidity: function isSelfDestructed(address ) view returns(bool)
func (_Statefuzztest *StatefuzztestCallerSession) IsSelfDestructed(arg0 common.Address) (bool, error) {
	return _Statefuzztest.Contract.IsSelfDestructed(&_Statefuzztest.CallOpts, arg0)
}

// StorageData is a free data retrieval call binding the contract method 0xc522de44.
//
// Solidity: function storageData(bytes32 ) view returns(bytes)
func (_Statefuzztest *StatefuzztestCaller) StorageData(opts *bind.CallOpts, arg0 [32]byte) ([]byte, error) {
	var out []interface{}
	err := _Statefuzztest.contract.Call(opts, &out, "storageData", arg0)

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// StorageData is a free data retrieval call binding the contract method 0xc522de44.
//
// Solidity: function storageData(bytes32 ) view returns(bytes)
func (_Statefuzztest *StatefuzztestSession) StorageData(arg0 [32]byte) ([]byte, error) {
	return _Statefuzztest.Contract.StorageData(&_Statefuzztest.CallOpts, arg0)
}

// StorageData is a free data retrieval call binding the contract method 0xc522de44.
//
// Solidity: function storageData(bytes32 ) view returns(bytes)
func (_Statefuzztest *StatefuzztestCallerSession) StorageData(arg0 [32]byte) ([]byte, error) {
	return _Statefuzztest.Contract.StorageData(&_Statefuzztest.CallOpts, arg0)
}

// ChangeBalance is a paid mutator transaction binding the contract method 0xf529d448.
//
// Solidity: function changeBalance(address account, uint256 newBalance) returns()
func (_Statefuzztest *StatefuzztestTransactor) ChangeBalance(opts *bind.TransactOpts, account common.Address, newBalance *big.Int) (*types.Transaction, error) {
	return _Statefuzztest.contract.Transact(opts, "changeBalance", account, newBalance)
}

// ChangeBalance is a paid mutator transaction binding the contract method 0xf529d448.
//
// Solidity: function changeBalance(address account, uint256 newBalance) returns()
func (_Statefuzztest *StatefuzztestSession) ChangeBalance(account common.Address, newBalance *big.Int) (*types.Transaction, error) {
	return _Statefuzztest.Contract.ChangeBalance(&_Statefuzztest.TransactOpts, account, newBalance)
}

// ChangeBalance is a paid mutator transaction binding the contract method 0xf529d448.
//
// Solidity: function changeBalance(address account, uint256 newBalance) returns()
func (_Statefuzztest *StatefuzztestTransactorSession) ChangeBalance(account common.Address, newBalance *big.Int) (*types.Transaction, error) {
	return _Statefuzztest.Contract.ChangeBalance(&_Statefuzztest.TransactOpts, account, newBalance)
}

// ChangeStorage is a paid mutator transaction binding the contract method 0xa2601e0a.
//
// Solidity: function changeStorage(bytes32 key, bytes newValue) returns()
func (_Statefuzztest *StatefuzztestTransactor) ChangeStorage(opts *bind.TransactOpts, key [32]byte, newValue []byte) (*types.Transaction, error) {
	return _Statefuzztest.contract.Transact(opts, "changeStorage", key, newValue)
}

// ChangeStorage is a paid mutator transaction binding the contract method 0xa2601e0a.
//
// Solidity: function changeStorage(bytes32 key, bytes newValue) returns()
func (_Statefuzztest *StatefuzztestSession) ChangeStorage(key [32]byte, newValue []byte) (*types.Transaction, error) {
	return _Statefuzztest.Contract.ChangeStorage(&_Statefuzztest.TransactOpts, key, newValue)
}

// ChangeStorage is a paid mutator transaction binding the contract method 0xa2601e0a.
//
// Solidity: function changeStorage(bytes32 key, bytes newValue) returns()
func (_Statefuzztest *StatefuzztestTransactorSession) ChangeStorage(key [32]byte, newValue []byte) (*types.Transaction, error) {
	return _Statefuzztest.Contract.ChangeStorage(&_Statefuzztest.TransactOpts, key, newValue)
}

// CreateObject is a paid mutator transaction binding the contract method 0xd5801065.
//
// Solidity: function createObject(bytes32 key, bytes value) returns()
func (_Statefuzztest *StatefuzztestTransactor) CreateObject(opts *bind.TransactOpts, key [32]byte, value []byte) (*types.Transaction, error) {
	return _Statefuzztest.contract.Transact(opts, "createObject", key, value)
}

// CreateObject is a paid mutator transaction binding the contract method 0xd5801065.
//
// Solidity: function createObject(bytes32 key, bytes value) returns()
func (_Statefuzztest *StatefuzztestSession) CreateObject(key [32]byte, value []byte) (*types.Transaction, error) {
	return _Statefuzztest.Contract.CreateObject(&_Statefuzztest.TransactOpts, key, value)
}

// CreateObject is a paid mutator transaction binding the contract method 0xd5801065.
//
// Solidity: function createObject(bytes32 key, bytes value) returns()
func (_Statefuzztest *StatefuzztestTransactorSession) CreateObject(key [32]byte, value []byte) (*types.Transaction, error) {
	return _Statefuzztest.Contract.CreateObject(&_Statefuzztest.TransactOpts, key, value)
}

// ResetObject is a paid mutator transaction binding the contract method 0x7a5ae62e.
//
// Solidity: function resetObject(bytes32 key) returns()
func (_Statefuzztest *StatefuzztestTransactor) ResetObject(opts *bind.TransactOpts, key [32]byte) (*types.Transaction, error) {
	return _Statefuzztest.contract.Transact(opts, "resetObject", key)
}

// ResetObject is a paid mutator transaction binding the contract method 0x7a5ae62e.
//
// Solidity: function resetObject(bytes32 key) returns()
func (_Statefuzztest *StatefuzztestSession) ResetObject(key [32]byte) (*types.Transaction, error) {
	return _Statefuzztest.Contract.ResetObject(&_Statefuzztest.TransactOpts, key)
}

// ResetObject is a paid mutator transaction binding the contract method 0x7a5ae62e.
//
// Solidity: function resetObject(bytes32 key) returns()
func (_Statefuzztest *StatefuzztestTransactorSession) ResetObject(key [32]byte) (*types.Transaction, error) {
	return _Statefuzztest.Contract.ResetObject(&_Statefuzztest.TransactOpts, key)
}

// SelfDestruct is a paid mutator transaction binding the contract method 0x9cb8a26a.
//
// Solidity: function selfDestruct() returns()
func (_Statefuzztest *StatefuzztestTransactor) SelfDestruct(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Statefuzztest.contract.Transact(opts, "selfDestruct")
}

// SelfDestruct is a paid mutator transaction binding the contract method 0x9cb8a26a.
//
// Solidity: function selfDestruct() returns()
func (_Statefuzztest *StatefuzztestSession) SelfDestruct() (*types.Transaction, error) {
	return _Statefuzztest.Contract.SelfDestruct(&_Statefuzztest.TransactOpts)
}

// SelfDestruct is a paid mutator transaction binding the contract method 0x9cb8a26a.
//
// Solidity: function selfDestruct() returns()
func (_Statefuzztest *StatefuzztestTransactorSession) SelfDestruct() (*types.Transaction, error) {
	return _Statefuzztest.Contract.SelfDestruct(&_Statefuzztest.TransactOpts)
}
