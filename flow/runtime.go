//go:build wasm
// +build wasm

package flow

import (
	"encoding/hex"
	"fmt"
	"syscall/js"
	"time"

	"github.com/onflow/atree"
	"github.com/onflow/cadence"
	"github.com/onflow/cadence/runtime"
	"github.com/onflow/cadence/runtime/common"
	"github.com/onflow/cadence/runtime/interpreter"
	"github.com/onflow/cadence/runtime/stdlib"
	"go.opentelemetry.io/otel/attribute"
)

type JSRuntime struct {
	network            *Network
	runtime            js.Value
	programs           map[common.Location]*interpreter.Program
	interpreterState   *interpreter.SharedState
	runningTransaction *Transaction
	storageIndex       atree.StorageIndex
	uuid               uint64
}

func NewJSRuntime(runtime js.Value) *JSRuntime {
	return &JSRuntime{
		runtime:  runtime,
		programs: make(map[common.Location]*interpreter.Program),
	}
}

func (j *JSRuntime) SetNetwork(network *Network) {
	j.network = network
}

func (j *JSRuntime) MeterMemory(usage common.MemoryUsage) error {
	return nil
}

// MeterComputation is a callback method for metering computation, it returns error
// when computation passes the limit (set by the environment)
func (j *JSRuntime) MeterComputation(operationType common.ComputationKind, intensity uint) error {
	return nil
}

// ComputationUsed returns the total computation used in the current runtime.
func (j *JSRuntime) ComputationUsed() (uint64, error) {
	return 0, nil
}

// MemoryUsed returns the total memory (estimate) used in the current runtime.
func (j *JSRuntime) MemoryUsed() (uint64, error) {
	return 0, nil
}

// InteractionUsed returns the total storage interaction used in the current runtime.
func (j *JSRuntime) InteractionUsed() (uint64, error) {
	return 0, nil
}

// ResolveLocation resolves an import location.
func (j *JSRuntime) ResolveLocation(identifiers []runtime.Identifier, location runtime.Location) ([]runtime.ResolvedLocation, error) {
	addressLocation, isAddress := location.(common.AddressLocation)
	// if the location is not an address location, e.g. an identifier location
	// (`import Crypto`), then return a single resolved location which declares
	// all identifiers.
	if !isAddress {
		return []runtime.ResolvedLocation{
			{
				Location:    location,
				Identifiers: identifiers,
			},
		}, nil
	}

	// if the location is an address,
	// and no specific identifiers where requested in the import statement,
	// then fetch all identifiers at this address

	//TODO: multiple import from account

	// return one resolved location per identifier.
	// each resolved location is an address contract location

	resolvedLocations := make([]runtime.ResolvedLocation, len(identifiers))
	for i := range resolvedLocations {
		identifier := identifiers[i]
		resolvedLocations[i] = runtime.ResolvedLocation{
			Location: common.AddressLocation{
				Address: addressLocation.Address,
				Name:    identifier.Identifier,
			},
			Identifiers: []runtime.Identifier{identifier},
		}
	}
	return resolvedLocations, nil
}

// GetCode returns the code at a given location
func (j *JSRuntime) GetCode(location runtime.Location) ([]byte, error) {
	contractLocation, ok := location.(common.AddressLocation)
	if !ok {
		return nil, fmt.Errorf("invalid location: %v", location)
	}

	data, err := j.GetValue(contractLocation.Address.Bytes(), []byte(fmt.Sprintf("code.%s", contractLocation.Name)))

	if err != nil {
		return nil, err
	}

	return data, nil
}

// GetOrLoadProgram returns the program for the given location, if available,
// or sets the program by calling the given load function.
//
// For implementations:
//   - Perform a lookup for the location and return the program if it exists.
//   - If the program does not exist, call load, and store the result,
//     *EVEN IF loading failed* (program is nil / error is non-nil)!
//   - During execution of a high-level program (e.g. script, transaction, etc.),
//     this function MUST always return the *same* program,
//     i.e. it may NOT return a different program,
//     an elaboration in the program that is not annotating the AST in the program;
//     or a program/elaboration and then nothing in a subsequent call.
//   - This function MUST also return exactly what was previously returned from load,
//     *EVEN IF loading failed* (program is nil / error is non-nil),
//     and it may NOT return something different
//   - Do NOT implement this as a cache!
func (j *JSRuntime) GetOrLoadProgram(
	location runtime.Location,
	load func() (*interpreter.Program, error),
) (*interpreter.Program, error) {
	program, ok := j.programs[location]
	if ok {
		return program, nil
	}
	program, err := load()
	if err != nil {
		return nil, err
	}
	j.programs[location] = program
	return program, nil
}

// SetInterpreterSharedState sets the shared state of all interpreters.
func (j *JSRuntime) SetInterpreterSharedState(state *interpreter.SharedState) {
	j.interpreterState = state
}

// GetInterpreterSharedState gets the shared state of all interpreters.
// May return nil if none is available or use is not applicable.
func (j *JSRuntime) GetInterpreterSharedState() *interpreter.SharedState {
	return j.interpreterState
}

// GetValue gets a value for the given key in the storage, owned by the given account.
func (j *JSRuntime) GetValue(owner, key []byte) (value []byte, err error) {
	ownerString := hex.EncodeToString(owner)
	keyString := hex.EncodeToString(key)

	jsValue := j.runtime.Call("getValue", js.ValueOf(string(ownerString)), js.ValueOf(string(keyString)))
	if jsValue.IsNull() {
		return nil, nil
	}
	v, _ := hex.DecodeString(jsValue.String())

	return []byte(v), nil
}

// SetValue sets a value for the given key in the storage, owned by the given account.
func (j *JSRuntime) SetValue(owner, key, value []byte) (err error) {
	ownerString := hex.EncodeToString(owner)
	keyString := hex.EncodeToString(key)
	valueString := hex.EncodeToString(value)

	j.runtime.Call("setValue", js.ValueOf(string(ownerString)), js.ValueOf(string(keyString)), js.ValueOf(string(valueString)))
	return nil
}

// ValueExists returns true if the given key exists in the storage, owned by the given account.
func (j *JSRuntime) ValueExists(owner, key []byte) (exists bool, err error) {
	v, err := j.GetValue(owner, key)
	if err != nil {
		return false, err
	}
	if v == nil {
		return false, nil
	}
	return true, nil
}

// AllocateStorageIndex allocates a new storage index under the given account.
func (j *JSRuntime) AllocateStorageIndex(owner []byte) (atree.StorageIndex, error) {
	return j.storageIndex.Next(), nil
}

// CreateAccount creates a new account.
func (j *JSRuntime) CreateAccount(payer common.Address) (address common.Address, err error) {
	panic("implement me")
}

// AddAccountKey appends a key to an account.
func (j *JSRuntime) AddAccountKey(address common.Address, publicKey *runtime.PublicKey, hashAlgo runtime.HashAlgorithm, weight int) (*runtime.AccountKey, error) {
	return &runtime.AccountKey{
		PublicKey: &runtime.PublicKey{},
		HashAlgo:  runtime.HashAlgorithmSHA2_256,
		Weight:    1000,
		IsRevoked: false,
	}, nil
}

// GetAccountKey retrieves a key from an account by index.
func (j *JSRuntime) GetAccountKey(address common.Address, index int) (*runtime.AccountKey, error) {
	//all accounts have same key
	return &runtime.AccountKey{
		PublicKey: &runtime.PublicKey{},
		HashAlgo:  runtime.HashAlgorithmSHA2_256,
		Weight:    1000,
		IsRevoked: false,
	}, nil
}
func (j *JSRuntime) AccountKeysCount(address common.Address) (uint64, error) {
	return 1, nil
}

// RevokeAccountKey removes a key from an account by index.
func (j *JSRuntime) RevokeAccountKey(address common.Address, index int) (*runtime.AccountKey, error) {
	return &runtime.AccountKey{
		PublicKey: &runtime.PublicKey{},
		HashAlgo:  runtime.HashAlgorithmSHA2_256,
		Weight:    1000,
		IsRevoked: true, //dummy
	}, nil
}

// UpdateAccountContractCode updates the code associated with an account contract.
func (j *JSRuntime) UpdateAccountContractCode(location common.AddressLocation, code []byte) (err error) {
	j.SetValue(location.Address.Bytes(), []byte(fmt.Sprintf("code.%s", location.Name)), code)
	return nil
}

// GetAccountContractCode returns the code associated with an account contract.
func (j *JSRuntime) GetAccountContractCode(location common.AddressLocation) (code []byte, err error) {
	data, err := j.GetValue(location.Address.Bytes(), []byte(fmt.Sprintf("code.%s", location.Name)))
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	return data, nil
}

// RemoveAccountContractCode removes the code associated with an account contract.
func (j *JSRuntime) RemoveAccountContractCode(location common.AddressLocation) (err error) {
	j.SetValue(location.Address.Bytes(), []byte(fmt.Sprintf("code.%s", location.Name)), nil)
	return nil
}

// GetSigningAccounts returns the signing accounts.
func (j *JSRuntime) GetSigningAccounts() ([]common.Address, error) {
	var signers []common.Address
	for _, authorizer := range j.runningTransaction.Authorizers {
		signers = append(signers, common.Address(authorizer))
	}
	return signers, nil
}

// ProgramLog logs program logs.
func (j *JSRuntime) ProgramLog(log string) error {
	j.runtime.Call("log", js.ValueOf(log))
	return nil
}

// EmitEvent is called when an event is emitted by the runtime.
func (j *JSRuntime) EmitEvent(event cadence.Event) error {
	fmt.Println("Event:", event)
	j.runningTransaction.TransactionResult.Events = append(j.runningTransaction.TransactionResult.Events, event)
	return nil
}

// GenerateUUID is called to generate a UUID.
func (j *JSRuntime) GenerateUUID() (uint64, error) {
	j.uuid++
	return j.uuid, nil
}

// DecodeArgument decodes a transaction/script argument against the given type.
func (j *JSRuntime) DecodeArgument(argument []byte, argumentType cadence.Type) (cadence.Value, error) {

	panic("implement me")
}

// GetCurrentBlockHeight returns the current block height.
func (j *JSRuntime) GetCurrentBlockHeight() (uint64, error) {
	height := len(j.network.Blocks) + 1
	return uint64(height), nil
}

// GetBlockAtHeight returns the block at the given height.
func (j *JSRuntime) GetBlockAtHeight(height uint64) (runtime.Block, bool, error) {
	if len(j.network.Blocks) > int(height) {
		return runtime.Block{}, false, nil
	}
	block := j.network.Blocks[height]
	return stdlib.Block{
		Height: uint64(block.Header.Height),
		View:   uint64(block.Header.View),
		Hash:   stdlib.BlockHash(block.Header.ID().Bytes()),
	}, true, nil
}

// ReadRandom reads pseudo-random bytes into the input slice, using distributed randomness.
func (j *JSRuntime) ReadRandom(r []byte) error {
	r[0] = 42
	return nil
}

// VerifySignature returns true if the given signature was produced by signing the given tag + data
// using the given public key, signature algorithm, and hash algorithm.
func (j *JSRuntime) VerifySignature(
	signature []byte,
	tag string,
	signedData []byte,
	publicKey []byte,
	signatureAlgorithm runtime.SignatureAlgorithm,
	hashAlgorithm runtime.HashAlgorithm,
) (bool, error) {
	//always true
	return true, nil
}

// Hash returns the digest of hashing the given data with using the given hash algorithm
func (j *JSRuntime) Hash(data []byte, tag string, hashAlgorithm runtime.HashAlgorithm) ([]byte, error) {
	return []byte{}, nil
}

// GetAccountBalance gets accounts default flow token balance.
func (j *JSRuntime) GetAccountBalance(address common.Address) (value uint64, err error) {
	//TODO: implement
	return 4200000000, nil
}

// GetAccountAvailableBalance gets accounts default flow token balance - balance that is reserved for storage.
func (j *JSRuntime) GetAccountAvailableBalance(address common.Address) (value uint64, err error) {
	//TODO: implement
	return 4200000000, nil
}

// GetStorageUsed gets storage used in bytes by the address at the moment of the function call.
func (j *JSRuntime) GetStorageUsed(address common.Address) (value uint64, err error) {
	//TODO: implement
	return 0, nil
}

// GetStorageCapacity gets storage capacity in bytes on the address.
func (j *JSRuntime) GetStorageCapacity(address common.Address) (value uint64, err error) {
	return 0xFFFFFF, nil
}

// ImplementationDebugLog logs implementation log statements on a debug-level
func (j *JSRuntime) ImplementationDebugLog(message string) error {
	fmt.Println("Debug:", message)
	return nil
}

// ValidatePublicKey verifies the validity of a public key.
func (j *JSRuntime) ValidatePublicKey(key *runtime.PublicKey) error {
	return nil
}

// GetAccountContractNames returns the names of all contracts deployed in an account.
func (j *JSRuntime) GetAccountContractNames(address common.Address) ([]string, error) {
	//TODO: implement
	return []string{}, nil
}

// RecordTrace records an opentelemetry trace.
func (j *JSRuntime) RecordTrace(operation string, location runtime.Location, duration time.Duration, attrs []attribute.KeyValue) {
}

// BLSVerifyPOP verifies a proof of possession (PoP) for the receiver public key.
func (j *JSRuntime) BLSVerifyPOP(publicKey *runtime.PublicKey, signature []byte) (bool, error) {
	return true, nil
}

// BLSAggregateSignatures aggregate multiple BLS signatures into one.
func (j *JSRuntime) BLSAggregateSignatures(signatures [][]byte) ([]byte, error) {

	panic("implement me")
}

// BLSAggregatePublicKeys aggregate multiple BLS public keys into one.
func (j *JSRuntime) BLSAggregatePublicKeys(publicKeys []*runtime.PublicKey) (*runtime.PublicKey, error) {
	return &runtime.PublicKey{}, nil
}

// ResourceOwnerChanged gets called when a resource's owner changed (if enabled)
func (j *JSRuntime) ResourceOwnerChanged(
	interpreter *interpreter.Interpreter,
	resource *interpreter.CompositeValue,
	oldOwner common.Address,
	newOwner common.Address,
) {
	fmt.Println("ResourceOwnerChanged", oldOwner, newOwner)
}

// GenerateAccountID generates a new, *non-zero*, unique ID for the given account.
func (j *JSRuntime) GenerateAccountID(address common.Address) (uint64, error) {
	panic("implement me")
}
