//go:build wasm
// +build wasm

package flow

import (
	"crypto/sha256"
	"fmt"
	"syscall/js"

	"github.com/onflow/cadence"
	"github.com/onflow/cadence/runtime"
	"github.com/onflow/cadence/runtime/common"

	"encoding/hex"
	"time"
)

const IdentifierLength uint = 32
const AddressLength uint = 8
const PublicKeyLength uint = 65

type LedgerKey struct {
	Address string
	Key     string
}

type Account struct {
	Address        Address
	PublicKeys     []PublicKey
	PublicKeyCount uint64
	SequenceNumber uint64
}

type Identifier [IdentifierLength]byte

func (i Identifier) Bytes() []byte {
	return i[:]
}

type Address [AddressLength]byte

func HexToAddress(address string) Address {
	var flowAddress Address
	bytes, err := hex.DecodeString(address)
	if err != nil {
		panic(err)
	}
	copy(flowAddress[:], bytes)
	return flowAddress
}

type PublicKey [PublicKeyLength]byte

type Signature struct {
	Address     Address
	SignerIndex int
	KeyIndex    uint64
	Signature   []byte
}

type ProposalKey struct {
	Address        Address
	KeyIndex       uint64
	SequenceNumber uint64
}

type Transaction struct {
	ReferenceBlockID   Identifier
	Script             []byte
	Arguments          [][]byte
	GasLimit           uint64
	ProposalKey        ProposalKey
	Payer              Address
	Authorizers        []Address
	PayloadSignatures  []Signature
	EnvelopeSignatures []Signature
	TransactionResult  TransactionResult
}

func (transaction *Transaction) ID() Identifier {
	return sha256.Sum256(transaction.Script)
}

type LedgerChange struct {
	Address []byte
	Key     []byte
	Value   []byte
}

type TransactionResult struct {
	Status        uint64
	Error         error
	LedgerChanges []*LedgerChange
	Events        []cadence.Event
}

type Collection struct {
	Transactions []*Transaction
}

type Header struct {
	ChainID     string
	ParentID    Identifier
	Height      uint64
	PayloadHash Identifier
	Timestamp   time.Time
	View        uint64
	ParentView  uint64
}

func (header *Header) ID() Identifier {
	return [32]byte{}
}

type Block struct {
	Header             *Header
	Collections        []*Collection
	TransactionResults []*TransactionResult
}

func GenesisBlock() *Block {
	return &Block{
		Header: &Header{
			ChainID:   "tinyFlow",
			ParentID:  [32]byte{},
			Height:    0,
			Timestamp: time.Now(),
		},
		Collections: []*Collection{},
	}
}

type CadenceRuntime struct {
	runtime.Runtime
}

type Ledger interface {
	GetValue(owner, key []byte) (value []byte, err error)
	SetValue(owner, key, value []byte) (err error)
}

type Network struct {
	Runtime      CadenceRuntime
	JSRuntime    *JSRuntime
	Blocks       []*Block
	pendingBlock *Block
}

func NewNetwork(jsRuntime js.Value) *Network {
	network := &Network{
		Runtime: CadenceRuntime{
			runtime.NewInterpreterRuntime(
				runtime.Config{},
			),
		},
		Blocks: []*Block{
			GenesisBlock(),
		},
		JSRuntime: NewJSRuntime(jsRuntime),
		pendingBlock: &Block{
			Header: &Header{
				ChainID:  "tinyFlow",
				ParentID: GenesisBlock().Header.ID(),
				Height:   1,
			},
		},
	}

	network.JSRuntime.SetNetwork(network)

	return network
}
func (n *Network) executeTransaction(transaction *Transaction) *TransactionResult {
	n.JSRuntime.runningTransaction = transaction
	fmt.Println(string(transaction.Script))

	err := n.Runtime.ExecuteTransaction(runtime.Script{
		Source: transaction.Script,
	}, runtime.Context{
		Interface:   n.JSRuntime,
		Location:    common.NewTransactionLocation(nil, transaction.ID().Bytes()),
		Environment: runtime.NewBaseInterpreterEnvironment(runtime.Config{}),
	})

	n.JSRuntime.runningTransaction = nil
	fmt.Println(err)
	return &TransactionResult{}
}

func (n *Network) CommitLedgerChange(ledgerChange *LedgerChange) {
	n.JSRuntime.SetValue(ledgerChange.Address, ledgerChange.Key, ledgerChange.Value)
}

func (n *Network) ExecuteTransaction(transaction *Transaction) {
	collection := &Collection{}
	collection.Transactions = append(collection.Transactions, transaction)
	n.pendingBlock.Collections = append(n.pendingBlock.Collections, collection)
	n.ExecuteAndCommitBlock()
}

func (n *Network) ExecuteAndCommitBlock() {

	block := n.pendingBlock

	var transactionResults []*TransactionResult
	for _, collection := range block.Collections {
		for _, transaction := range collection.Transactions {
			transactionResult := n.executeTransaction(transaction)
			transactionResults = append(transactionResults, transactionResult)
		}
	}

	for _, transactionResult := range transactionResults {
		for _, ledgerChange := range transactionResult.LedgerChanges {
			// Commit ledger change
			n.CommitLedgerChange(ledgerChange)
		}
	}

	block.TransactionResults = transactionResults
	block.Header.Timestamp = time.Now()
	n.Blocks = append(n.Blocks, block)

	n.pendingBlock = &Block{
		Header: &Header{
			ChainID:   "tinyFlow",
			ParentID:  block.Header.ID(),
			Height:    block.Header.Height + 1,
			Timestamp: time.Now(),
		},
		Collections:        []*Collection{},
		TransactionResults: transactionResults,
	}
}
