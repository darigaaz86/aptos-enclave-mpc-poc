# Aptos PoC for Enclave MPC

This repository contains proof-of-concept (PoC) implementations for working with Aptos blockchain transactions, with a focus on signing mechanisms including traditional signing, Go-Ethereum-based signing, and C++ enclave-based signing. The examples demonstrate different approaches to signing and broadcasting transactions using the Aptos Golang SDK.

---

## Samples Overview

### 1. **Secp256k1SignAndBroadcast**
This sample demonstrates how to use the Aptos Golang SDK to create and broadcast transactions.

#### Key Features:
- Generates a raw transaction.
- Signs the transaction using the Aptos Golang SDK.
- Broadcasts the transaction to the Aptos network.

#### Usage:
Run this sample to understand the basic flow of transaction creation and submission on Aptos.

---

### 2. **Secp256k1SignAndBroadcastWithCryptoSign**
An updated version of `Secp256k1SignAndBroadcast`, where the signing process utilizes the Go-Ethereum (`go-eth`) library to sign the transaction instead of the Aptos Golang SDK.

#### Key Features:
- Demonstrates interoperability between Aptos transactions and Go-Ethereum signing tools.
- Offers a flexible signing solution for users familiar with Ethereum-style cryptographic libraries.

#### Usage:
Run this sample if you prefer or require Ethereum-compatible signing mechanisms.

---

### 3. **GenerateSigningMsg and SignWithRSV**
These two functions work together to facilitate transaction signing using an external C++ enclave.

#### Workflow:
1. **GenerateSigningMsg**: Produces a signing message that serves as input to the C++ enclave.
2. **SignWithRSV**: Accepts the output (`r`, `s`, and `v`) from the enclave and applies them to sign the transaction.

#### Key Features:
- Supports custom signing workflows involving secure enclaves.
- Designed for internal use cases requiring enhanced security.

---

## Technologies Used

- **Programming Language**: Go (Golang)
- **Dependencies**:
  - Aptos Go SDK
  - Go-Ethereum (`go-eth`) library
  - Custom C++ enclave for signing

---
