//go:build wasm
// +build wasm

package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/bluesign/tinyFlow/flow"
)

var network *flow.Network

func sendTransaction(this js.Value, args []js.Value) interface{} {
	transaction := args[0]
	proposerAddr, _ := hex.DecodeString(transaction.Get("proposalKey").Get("address").String())

	authorizers := []flow.Address{}
	for i := 0; i < transaction.Get("authorizers").Length(); i++ {
		authorizerString := transaction.Get("authorizers").Index(i)
		authorizer, _ := hex.DecodeString(authorizerString.String())
		authorizers = append(authorizers, flow.Address(authorizer))
	}

	flowTransaction := &flow.Transaction{
		Script:           []byte(transaction.Get("script").String()),
		Arguments:        [][]byte{},
		ReferenceBlockID: flow.Identifier{},
		ProposalKey: flow.ProposalKey{
			Address:        flow.Address(proposerAddr),
			KeyIndex:       uint64(transaction.Get("proposalKey").Get("keyIndex").Int()),
			SequenceNumber: uint64(transaction.Get("proposalKey").Get("sequenceNumber").Int()),
		},
		Authorizers: authorizers,
	}
	network.ExecuteTransaction(flowTransaction)
	return nil
}

func main() {

	network = flow.NewNetwork(js.Global().Get("runtime"))
	c := make(chan struct{}, 0)
	js.Global().Set("sendTransaction", js.FuncOf(sendTransaction))
	<-c
}
