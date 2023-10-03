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
	ABI: "[{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"amount\",\"type\":\"uint256\"}],\"name\":\"addThenWithdrawRefund\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"balances\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"account\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"newBalance\",\"type\":\"uint256\"}],\"name\":\"changeBalance\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"key\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"newValue\",\"type\":\"bytes\"}],\"name\":\"changeStorage\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"key\",\"type\":\"bytes32\"},{\"internalType\":\"bytes\",\"name\":\"value\",\"type\":\"bytes\"}],\"name\":\"createObject\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"}],\"name\":\"isSelfDestructed\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"key\",\"type\":\"bytes32\"}],\"name\":\"resetObject\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"selfDestruct\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"storageData\",\"outputs\":[{\"internalType\":\"bytes\",\"name\":\"\",\"type\":\"bytes\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"contractAddress\",\"type\":\"address\"}],\"name\":\"touchContract\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"codeHash\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
	Bin: "0x608060405234801561001057600080fd5b50610d4e806100206000396000f3fe6080604052600436106100915760003560e01c8063a2601e0a11610059578063a2601e0a1461016c578063b0d50e3814610195578063c522de44146101d2578063d58010651461020f578063f529d4481461023857610091565b806327e235e3146100965780633e978173146100d3578063798d40e3146100ef5780637a5ae62e1461012c5780639cb8a26a14610155575b600080fd5b3480156100a257600080fd5b506100bd60048036038101906100b891906105d7565b610261565b6040516100ca919061061d565b60405180910390f35b6100ed60048036038101906100e89190610664565b610279565b005b3480156100fb57600080fd5b50610116600480360381019061011191906105d7565b610319565b60405161012391906106aa565b60405180910390f35b34801561013857600080fd5b50610153600480360381019061014e91906106f1565b610324565b005b34801561016157600080fd5b5061016a610346565b005b34801561017857600080fd5b50610193600480360381019061018e9190610864565b6103b7565b005b3480156101a157600080fd5b506101bc60048036038101906101b791906105d7565b6103dc565b6040516101c991906108db565b60405180910390f35b3480156101de57600080fd5b506101f960048036038101906101f491906106f1565b6103fc565b6040516102069190610975565b60405180910390f35b34801561021b57600080fd5b5061023660048036038101906102319190610864565b61049c565b005b34801561024457600080fd5b5061025f600480360381019061025a9190610997565b6104c1565b005b60006020528060005260406000206000915090505481565b80600360003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546102c89190610a06565b925050819055503373ffffffffffffffffffffffffffffffffffffffff166108fc829081150290604051600060405180830381858888f19350505050158015610315573d6000803e3d6000fd5b5050565b6000813f9050919050565b6001600082815260200190815260200160002060006103439190610508565b50565b6001600260003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060006101000a81548160ff0219169083151502179055503373ffffffffffffffffffffffffffffffffffffffff16ff5b806001600084815260200190815260200160002090816103d79190610c46565b505050565b60026020528060005260406000206000915054906101000a900460ff1681565b6001602052806000526040600020600091509050805461041b90610a69565b80601f016020809104026020016040519081016040528092919081815260200182805461044790610a69565b80156104945780601f1061046957610100808354040283529160200191610494565b820191906000526020600020905b81548152906001019060200180831161047757829003601f168201915b505050505081565b806001600084815260200190815260200160002090816104bc9190610c46565b505050565b806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505050565b50805461051490610a69565b6000825580601f106105265750610545565b601f0160209004906000526020600020908101906105449190610548565b5b50565b5b80821115610561576000816000905550600101610549565b5090565b6000604051905090565b600080fd5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006105a482610579565b9050919050565b6105b481610599565b81146105bf57600080fd5b50565b6000813590506105d1816105ab565b92915050565b6000602082840312156105ed576105ec61056f565b5b60006105fb848285016105c2565b91505092915050565b6000819050919050565b61061781610604565b82525050565b6000602082019050610632600083018461060e565b92915050565b61064181610604565b811461064c57600080fd5b50565b60008135905061065e81610638565b92915050565b60006020828403121561067a5761067961056f565b5b60006106888482850161064f565b91505092915050565b6000819050919050565b6106a481610691565b82525050565b60006020820190506106bf600083018461069b565b92915050565b6106ce81610691565b81146106d957600080fd5b50565b6000813590506106eb816106c5565b92915050565b6000602082840312156107075761070661056f565b5b6000610715848285016106dc565b91505092915050565b600080fd5b600080fd5b6000601f19601f8301169050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b61077182610728565b810181811067ffffffffffffffff821117156107905761078f610739565b5b80604052505050565b60006107a3610565565b90506107af8282610768565b919050565b600067ffffffffffffffff8211156107cf576107ce610739565b5b6107d882610728565b9050602081019050919050565b82818337600083830152505050565b6000610807610802846107b4565b610799565b90508281526020810184848401111561082357610822610723565b5b61082e8482856107e5565b509392505050565b600082601f83011261084b5761084a61071e565b5b813561085b8482602086016107f4565b91505092915050565b6000806040838503121561087b5761087a61056f565b5b6000610889858286016106dc565b925050602083013567ffffffffffffffff8111156108aa576108a9610574565b5b6108b685828601610836565b9150509250929050565b60008115159050919050565b6108d5816108c0565b82525050565b60006020820190506108f060008301846108cc565b92915050565b600081519050919050565b600082825260208201905092915050565b60005b83811015610930578082015181840152602081019050610915565b60008484015250505050565b6000610947826108f6565b6109518185610901565b9350610961818560208601610912565b61096a81610728565b840191505092915050565b6000602082019050818103600083015261098f818461093c565b905092915050565b600080604083850312156109ae576109ad61056f565b5b60006109bc858286016105c2565b92505060206109cd8582860161064f565b9150509250929050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000610a1182610604565b9150610a1c83610604565b9250828201905080821115610a3457610a336109d7565b5b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b60006002820490506001821680610a8157607f821691505b602082108103610a9457610a93610a3a565b5b50919050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b600060088302610afc7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82610abf565b610b068683610abf565b95508019841693508086168417925050509392505050565b6000819050919050565b6000610b43610b3e610b3984610604565b610b1e565b610604565b9050919050565b6000819050919050565b610b5d83610b28565b610b71610b6982610b4a565b848454610acc565b825550505050565b600090565b610b86610b79565b610b91818484610b54565b505050565b5b81811015610bb557610baa600082610b7e565b600181019050610b97565b5050565b601f821115610bfa57610bcb81610a9a565b610bd484610aaf565b81016020851015610be3578190505b610bf7610bef85610aaf565b830182610b96565b50505b505050565b600082821c905092915050565b6000610c1d60001984600802610bff565b1980831691505092915050565b6000610c368383610c0c565b9150826002028217905092915050565b610c4f826108f6565b67ffffffffffffffff811115610c6857610c67610739565b5b610c728254610a69565b610c7d828285610bb9565b600060209050601f831160018114610cb05760008415610c9e578287015190505b610ca88582610c2a565b865550610d10565b601f198416610cbe86610a9a565b60005b82811015610ce657848901518255600182019150602085019450602081019050610cc1565b86831015610d035784890151610cff601f891682610c0c565b8355505b6001600288020188555050505b50505050505056fea2646970667358221220bf0fddc0e0582d2115c83591396205edb56de333d7cc4ef10f8a3d740b137fc464736f6c63430008130033",
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

// TouchContract is a free data retrieval call binding the contract method 0x798d40e3.
//
// Solidity: function touchContract(address contractAddress) view returns(bytes32 codeHash)
func (_Statefuzztest *StatefuzztestCaller) TouchContract(opts *bind.CallOpts, contractAddress common.Address) ([32]byte, error) {
	var out []interface{}
	err := _Statefuzztest.contract.Call(opts, &out, "touchContract", contractAddress)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// TouchContract is a free data retrieval call binding the contract method 0x798d40e3.
//
// Solidity: function touchContract(address contractAddress) view returns(bytes32 codeHash)
func (_Statefuzztest *StatefuzztestSession) TouchContract(contractAddress common.Address) ([32]byte, error) {
	return _Statefuzztest.Contract.TouchContract(&_Statefuzztest.CallOpts, contractAddress)
}

// TouchContract is a free data retrieval call binding the contract method 0x798d40e3.
//
// Solidity: function touchContract(address contractAddress) view returns(bytes32 codeHash)
func (_Statefuzztest *StatefuzztestCallerSession) TouchContract(contractAddress common.Address) ([32]byte, error) {
	return _Statefuzztest.Contract.TouchContract(&_Statefuzztest.CallOpts, contractAddress)
}

// AddThenWithdrawRefund is a paid mutator transaction binding the contract method 0x3e978173.
//
// Solidity: function addThenWithdrawRefund(uint256 amount) payable returns()
func (_Statefuzztest *StatefuzztestTransactor) AddThenWithdrawRefund(opts *bind.TransactOpts, amount *big.Int) (*types.Transaction, error) {
	return _Statefuzztest.contract.Transact(opts, "addThenWithdrawRefund", amount)
}

// AddThenWithdrawRefund is a paid mutator transaction binding the contract method 0x3e978173.
//
// Solidity: function addThenWithdrawRefund(uint256 amount) payable returns()
func (_Statefuzztest *StatefuzztestSession) AddThenWithdrawRefund(amount *big.Int) (*types.Transaction, error) {
	return _Statefuzztest.Contract.AddThenWithdrawRefund(&_Statefuzztest.TransactOpts, amount)
}

// AddThenWithdrawRefund is a paid mutator transaction binding the contract method 0x3e978173.
//
// Solidity: function addThenWithdrawRefund(uint256 amount) payable returns()
func (_Statefuzztest *StatefuzztestTransactorSession) AddThenWithdrawRefund(amount *big.Int) (*types.Transaction, error) {
	return _Statefuzztest.Contract.AddThenWithdrawRefund(&_Statefuzztest.TransactOpts, amount)
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
