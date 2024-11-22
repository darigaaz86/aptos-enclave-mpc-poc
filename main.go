package main

import (
	"fmt"
	"log"
	"math/big"
	"encoding/hex"

	"golang.org/x/crypto/sha3"
	"github.com/aptos-labs/aptos-go-sdk"
	"github.com/aptos-labs/aptos-go-sdk/bcs"
	"github.com/ethereum/go-ethereum/crypto"
	aptc "github.com/aptos-labs/aptos-go-sdk/crypto"
)

const(
	publicKeyHex = "042f673c184267b4af64957b12ecd78a6900d4e0a6f3924e8bde8e44271fdabcf9d42cd0eda4d8f9de80830b894907f4f51691418cbfdd3d95be447cf685923a34"
	pk = "71176ce8880a53026287f2373165e57b9ee1b59f91ba8cc8bde6ae11eb18e0e3"
	rHex = "a82c0f7ebaf83c2094ffc89a194aa801ac401c53597a592d3345e05d75a8820d"
	sHex = "6083e51643436ecbee68bb2683116ad22dea00dfe8ffff7eba6b6d81b4596e41"
	vInt = 0
	signingMessageHex = "b5e97db07fa0bd0e5598aa3643a9bc6f6693bddc1a9fec9e674a461eaa00b1938686cc0ed1cfb555c2f37ea9a4cde7fd4107350494c79db03fc1a419af90d90e00000000000000000200000000000000000000000000000000000000000000000000000000000000010d6170746f735f6163636f756e74087472616e73666572000220000000000000000000000000000000000000000000000000000000000000beef086400000000000000a0860100000000006400000000000000a1de3f6700000000a2"
)


func Secp256k1SignAndBroadcast(networkConfig aptos.NetworkConfig) {
	// Create a client for Aptos
	client, err := aptos.NewClient(networkConfig)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Generate secp256k1 key pair
	privateKey := &aptc.Secp256k1PrivateKey{}
	err = privateKey.FromHex(pk)
	signer := aptc.NewSingleSigner(privateKey)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Fund the sender with the faucet to create it on-chain
	accountAddress := aptos.AccountAddress{}
	accountAddress.FromAuthKey(signer.AuthKey())
	err = client.Fund(accountAddress, 100_000_000)
	if err != nil {
		log.Fatalf("Failed to fund sender: %v", err)
	}
	fmt.Printf("We fund the signer account %s with the faucet\n", accountAddress.String())

	// Prepare arguments for the transfer
	receiver := aptos.AccountAddress{}
	err = receiver.ParseStringRelaxed("0xBEEF")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	amount := uint64(100)
	payload, err := aptos.CoinTransferPayload(nil, receiver, amount)
	if err != nil {
		log.Fatalf("Failed to build payload: %v", err)
	}

	// Build the unsigned transaction
	rawTxn, err := client.BuildTransaction(accountAddress,
		aptos.TransactionPayload{Payload: payload},
	)
	if err != nil {
		log.Fatalf("Failed to build raw transaction: %v", err)
	}

	// Sign the transaction message
	signingMessage, err := rawTxn.SigningMessage()
	if err != nil {
		log.Fatalf("Failed to build signing message: %v", err)
	}
	fmt.Printf("signingMessage: %x\n", signingMessage)

	// Sign using the external signer (secp256k1)
	auth, err := signer.Sign(signingMessage)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}

	// Create the signed transaction
	signedTxn, err := rawTxn.SignedTransactionWithAuthenticator(auth)
	if err != nil {
		log.Fatalf("Failed to convert transaction authenticator: %v", err)
	}

	// Submit the signed transaction
	submitResult, err := client.SubmitTransaction(signedTxn)
	if err != nil {
		log.Fatalf("Failed to submit transaction: %v", err)
	}
	txnHash := submitResult.Hash

	// Wait for the transaction to be processed
	fmt.Printf("We wait for the transaction %s to complete...\n", txnHash)
	// nodeClient, _ := aptos.NewNodeClient(networkConfig.NodeUrl, networkConfig.ChainId)
	// userTxn, _ := nodeClient.TransactionByHash(txnHash)
	userTxn, err := client.WaitForTransaction(txnHash)
	if err != nil {
		log.Fatalf("Failed to wait for transaction: %v", err)
	}

	fmt.Printf("The transaction completed with hash: %s and version %d\n", userTxn.Hash, userTxn.Version)
}

func Secp256k1SignAndBroadcastWithCryptoSign(networkConfig aptos.NetworkConfig) {
	// Create a client for Aptos
	client, err := aptos.NewClient(networkConfig)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Generate secp256k1 key pair
	privateKey := &aptc.Secp256k1PrivateKey{}
	err = privateKey.FromHex(pk)
	signer := aptc.NewSingleSigner(privateKey)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Fund the sender with the faucet to create it on-chain
	accountAddress := aptos.AccountAddress{}
	accountAddress.FromAuthKey(signer.AuthKey())
	err = client.Fund(accountAddress, 100_000_000)
	if err != nil {
		log.Fatalf("Failed to fund sender: %v", err)
	}
	fmt.Printf("We fund the signer account %s with the faucet\n", accountAddress.String())

	// Prepare arguments for the transfer
	receiver := aptos.AccountAddress{}
	err = receiver.ParseStringRelaxed("0xBEEF")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	amount := uint64(100)
	payload, err := aptos.CoinTransferPayload(nil, receiver, amount)
	if err != nil {
		log.Fatalf("Failed to build payload: %v", err)
	}

	// Build the unsigned transaction
	rawTxn, err := client.BuildTransaction(accountAddress,
		aptos.TransactionPayload{Payload: payload},
	)
	if err != nil {
		log.Fatalf("Failed to build raw transaction: %v", err)
	}

	// Sign the transaction message
	signingMessage, err := rawTxn.SigningMessage()
	if err != nil {
		log.Fatalf("Failed to build signing message: %v", err)
	}
	fmt.Printf("signingMessage: %x\n", signingMessage)

	// Sign using the external signer (secp256k1)
	hash := Sha3256Hash([][]byte{signingMessage})
	signature, err := crypto.Sign(hash, privateKey.Inner)
	if err != nil {
		log.Fatalf("Failed to sign message: %v", err)
	}
	secpSig := &aptc.Secp256k1Signature{}
	copy(secpSig.Inner[:], signature[:aptc.Secp256k1SignatureLength])

	anySign := &aptc.AnySignature{Variant: signer.SignatureVariant(), Signature: secpSig}

	sauth := &aptc.SingleKeyAuthenticator{}
	sauth.PubKey = signer.PubKey().(*aptc.AnyPublicKey)
	sauth.Sig = anySign
	auth := &aptc.AccountAuthenticator{Variant: aptc.AccountAuthenticatorSingleSender, Auth: sauth}

	// Create the signed transaction
	signedTxn, err := rawTxn.SignedTransactionWithAuthenticator(auth)
	if err != nil {
		log.Fatalf("Failed to convert transaction authenticator: %v", err)
	}

	// Submit the signed transaction
	submitResult, err := client.SubmitTransaction(signedTxn)
	if err != nil {
		log.Fatalf("Failed to submit transaction: %v", err)
	}
	txnHash := submitResult.Hash

	// Wait for the transaction to be processed
	fmt.Printf("We wait for the transaction %s to complete...\n", txnHash)
	userTxn, err := client.WaitForTransaction(txnHash)
	if err != nil {
		log.Fatalf("Failed to wait for transaction: %v", err)
	}

	fmt.Printf("The transaction completed with hash: %s and version %d\n", userTxn.Hash, userTxn.Version)
}

func Sha3256Hash(bytes [][]byte) (output []byte) {
	hasher := sha3.New256()
	for _, b := range bytes {
		hasher.Write(b)
	}
	return hasher.Sum([]byte{})
}

func main() {
	// Secp256k1SignAndBroadcast(aptos.DevnetConfig)
	Secp256k1SignAndBroadcastWithCryptoSign(aptos.DevnetConfig)

	// GenerateSigningMsg(aptos.DevnetConfig)
	// SignWithRSV(aptos.DevnetConfig)
}

func GenerateSigningMsg(networkConfig aptos.NetworkConfig) {
	// Create a client for Aptos
	client, err := aptos.NewClient(networkConfig)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Generate secp256k1 key pair
	publicKey := &aptc.Secp256k1PublicKey{}
	err = publicKey.FromHex(publicKeyHex)
	if err != nil {
		log.Fatalf("Failed to create publicKey: %v", err)
	}


	// Fund the sender with the faucet to create it on-chain
	anyPublicKey, err := aptc.ToAnyPublicKey(publicKey)
	if err != nil {
		log.Fatalf("Failed to convert publicKey: %v", err)
	}
	authKey := anyPublicKey.AuthKey()
	accountAddress := aptos.AccountAddress{}
	accountAddress.FromAuthKey(authKey)
	err = client.Fund(accountAddress, 100_000_000)
	if err != nil {
		log.Fatalf("Failed to fund sender: %v", err)
	}
	fmt.Printf("We fund the signer account %s with the faucet\n", accountAddress.String())

	// Prepare arguments for the transfer
	receiver := aptos.AccountAddress{}
	err = receiver.ParseStringRelaxed("0xBEEF")
	if err != nil {
		log.Fatalf("Failed to parse address: %v", err)
	}
	amount := uint64(100)
	payload, err := aptos.CoinTransferPayload(nil, receiver, amount)
	if err != nil {
		log.Fatalf("Failed to build payload: %v", err)
	}

	// Build the unsigned transaction
	rawTxn, err := client.BuildTransaction(accountAddress,
		aptos.TransactionPayload{Payload: payload},
	)
	if err != nil {
		log.Fatalf("Failed to build raw transaction: %v", err)
	}

	// Sign the transaction message
	signingMessage, err := rawTxn.SigningMessage()
	if err != nil {
		log.Fatalf("Failed to build signing message: %v", err)
	}
	fmt.Printf("signingMessage: %x\n", signingMessage)
	hash := Sha3256Hash([][]byte{signingMessage})
	fmt.Printf("signingMessage after sha3: %x\n", hash)
}

func SignWithRSV(networkConfig aptos.NetworkConfig) {
	// Create a client for Aptos
	client, err := aptos.NewClient(networkConfig)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// Build the unsigned transaction
	signingMessage, _ := hex.DecodeString(signingMessageHex)
	rawTxn, err := RevertSigningMessage(signingMessage)
	if err != nil {
		log.Fatalf("Failed to build raw transaction: %v", err)
	}

	// Convert r and s from hex string to *big.Int
	r := new(big.Int)
	s := new(big.Int)
	r.SetString(rHex, 16)
	s.SetString(sHex, 16)
	v := uint8(vInt)

	signature := append(r.Bytes(), append(s.Bytes(), v)...)
	secpSig := &aptc.Secp256k1Signature{}
	copy(secpSig.Inner[:], signature[:aptc.Secp256k1SignatureLength])
	anySign := &aptc.AnySignature{Variant: aptc.AnySignatureVariantSecp256k1, Signature: secpSig}
	sauth := &aptc.SingleKeyAuthenticator{}
	publicKey := &aptc.Secp256k1PublicKey{}
	err = publicKey.FromHex(publicKeyHex)
	if err != nil {
		log.Fatalf("Failed to create publicKey: %v", err)
	}
	anyPublicKey, _ := aptc.ToAnyPublicKey(publicKey)
	sauth.PubKey = anyPublicKey
	sauth.Sig = anySign
	auth := &aptc.AccountAuthenticator{Variant: aptc.AccountAuthenticatorSingleSender, Auth: sauth}

	// Create the signed transaction
	signedTxn, err := rawTxn.SignedTransactionWithAuthenticator(auth)
	if err != nil {
		log.Fatalf("Failed to convert transaction authenticator: %v", err)
	}

	// Submit the signed transaction
	submitResult, err := client.SubmitTransaction(signedTxn)
	if err != nil {
		log.Fatalf("Failed to submit transaction: %v", err)
	}
	txnHash := submitResult.Hash

	// Wait for the transaction to be processed
	fmt.Printf("We wait for the transaction %s to complete...\n", txnHash)
	userTxn, err := client.WaitForTransaction(txnHash)
	if err != nil {
		log.Fatalf("Failed to wait for transaction: %v", err)
	}

	fmt.Printf("The transaction completed with hash: %s and version %d\n", userTxn.Hash, userTxn.Version)
}

func RevertSigningMessage(signingMessage []byte) (*aptos.RawTransaction, error) {
	// Define the prehash (RawTransactionPrehash)
	prehash := aptos.RawTransactionPrehash()

	// Verify signing message starts with prehash
	if len(signingMessage) < len(prehash) || string(signingMessage[:len(prehash)]) != string(prehash) {
		return nil, fmt.Errorf("invalid signing message: prehash mismatch")
	}

	// Extract the serialized raw transaction bytes
	rawTxnBytes := signingMessage[len(prehash):]

	// Create a deserializer
	deserializer := bcs.NewDeserializer(rawTxnBytes)

	// Deserialize into a RawTransaction
	var rawTxn aptos.RawTransaction
	rawTxn.UnmarshalBCS(deserializer)

	return &rawTxn, nil
}