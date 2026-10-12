# PeerID

[![](https://img.shields.io/badge/made%20by-Breth-blue.svg?style=flat-square)](https://breth.app)
[![](https://img.shields.io/badge/project-multiformats-blue.svg?style=flat-square)](https://github.com/multiformats/multiformats)
[![Swift Package Manager compatible](https://img.shields.io/badge/SPM-compatible-blue.svg?style=flat-square)](https://github.com/apple/swift-package-manager)
![Build & Test (macos and linux)](https://github.com/swift-libp2p/swift-peer-id/actions/workflows/build+test.yml/badge.svg)

> An API / abstraction for managing libp2p public/private key pairs and identities

## Table of Contents

- [Overview](#overview)
- [Install](#install)
- [Usage](#usage)
  - [Example](#example)
  - [API](#api)
- [Contributing](#contributing)
- [Credits](#credits)
- [License](#license)

## Overview
Libp2p uses cryptographic key pairs to sign & verify messages and derive unique peer identities (Peer ID's). This library wraps a public / private key pair in a PeerID object that exposes certain functionality for use with Libp2p nodes.

A Peer ID is the multihash of a peer's (protobuf-marshaled) public key. Keys whose marshaled form is ≤ 42 bytes (Ed25519, Secp256k1) are inlined verbatim using the `identity` multihash, larger keys (ex: RSA, ECDSA) are hashed with SHA-256.

The public key is a protobuf containing a key type and the key material (e.g. the DER buffer for an RSA key).

| Key Type | Key Sizes | Multihash | Example b58String |
|---|---|---|---|
| Ed25519 | 256 bits | `identity` (public key is recoverable from the id) | `12D3KooW…` |
| Secp256k1 | 256 bits | `identity` (public key is recoverable from the id) | `16Uiu2HA…` |
| RSA | 2048 - 8192 bits | `sha2-256` | `Qm…` |
| ECDSA | P-256, P-384, P-521 | `sha2-256` | `Qm…` |

When decoding, only `sha2-256` and `identity` multihashes are accepted. An `identity` multihash must inline a valid, canonically encoded public key of 42 bytes or less. PeerID strings beginning with `Qm` or `1` are decoded as base58btc multihashes, and all other strings are decoded as multibase CIDv1s using the `libp2p-key` codec.

> [!NOTE]
> PeerID equality (and hashing) treats an embedded (`identity`) PeerID and the traditional (`sha2-256`) PeerID of the same key as equal.

#### Note:
- For more information check out the [PeerID Spec](https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md)

## Install

Include the following dependency in your Package.swift file
```Swift
let package = Package(
    ...
    dependencies: [
        ...
        .package(url: "https://github.com/swift-libp2p/swift-peer-id.git", .upToNextMinor(from: "0.3.0"))
    ],
    ...
        .target(
            ...
            dependencies: [
                ...
                .product(name: "PeerID", package: "swift-peer-id"),
            ]),
    ...
)
```

## Usage

### Example 
check out the [tests](https://github.com/swift-libp2p/swift-peer-id/blob/main/Tests/PeerIDTests/PeerIDTests.swift) for more examples

```Swift

import PeerID

/// Generate a new PeerID
let peerID = try PeerID(.ed25519)       // or .secp256k1, .rsa(bits: .b2048), .ecdsa(curve: .p256)

peerID.b58String                        // -> 12D3KooWBtg3aaRMjxwedh83aGiUkwSxDwUZkzuJcfaqUmo7R3pq (libp2p PeerID standard)
peerID.cidString                        // -> bafzaajaiaejcahwr5d5ofrfbis4l5d6uwr57hu5tjodrypfm6yaq6dsc2r2pzyt6
peerID.description                      // -> <peer.ID 12*o7R3pq>
peerID.keyPair                          // Access to the underlying key pair
peerID.keyPair?.keyType == .ed25519     // The type of Key
peerID.keyPair?.privateKey              // Access to the private key (for signing)
peerID.keyPair?.publicKey               // Access to the public key (for verifying signatures)

/// If you want to reuse the same PeerID between sessions, you can... 
        
/// Export a PeerID as an Encrypted PEM String that you can store... 
let encryptedPEM = try peerID.exportKeyPair(as: .privatePEMString(encryptedWithPassword: "mypassword"))

/// And then load the PeerID from and encrypted PEM String later
let peerID = try PeerID(pem: "ENCRYPTED_PEM_String", password: "mypassword")
```

### API
```Swift
/// Initializers
/// Generate a new PeerID with an underlying Key Pair (defaults to 2048 bit RSA)
PeerID.init(_ keyType:LibP2PCrypto.Keys.KeyPairType = .rsa(bits: .b2048)) throws

/// Use an existing Key Pair to instantiate a PeerID
PeerID.init(keyPair:LibP2PCrypto.Keys.KeyPair) throws

/// Inits a `PeerID` from a hex encoded multihash (embedded Ed25519 / Secp256k1 public keys are recovered)
PeerID.init(fromHexID hex:String) throws

/// Inits a `PeerID` from a binary multihash (embedded Ed25519 / Secp256k1 public keys are recovered)
PeerID.init(fromBytesID bytes:[UInt8]) throws

/// Inits a `PeerID` from a base58btc (`Qm…` / `1…`) string or a multibase encoded v1 libp2p-key CID string
PeerID.init(cid:String) throws

/// Inits a `PeerID` from a v0 dag-pb or v1 libp2p-key CID
PeerID.init(cid:CID) throws 

/// Inits a `PeerID` from a marshaled `PeerID` string
PeerID.init(marshaledPeerID:String, base: BaseEncoding? = nil) throws

/// Inits a `PeerID` from a marshaled `PeerID`
PeerID.init(marshaledPeerID data:Data) throws

/// Inits a `PeerID` from a marshaled public key string
PeerID.init(marshaledPublicKey str:String, base:BaseEncoding) throws

/// Inits a `PeerID` from a marshaled public key
PeerID.init(marshaledPublicKey key:Data) throws

/// Inits a `PeerID` from a marshaled private key string
PeerID.init(marshaledPrivateKey str:String, base:BaseEncoding) throws

/// Inits a `PeerID` from a marshaled private key
PeerID.init(marshaledPrivateKey data:Data) throws

/// Inits a `PeerID` from a PEM String
PeerID.init(pem: String, password: String? = nil) throws

/// Properties
/// Returns the PeerID's id as a base58 string (multihash/CIDv0).
PeerID.b58String:String

/// Returns the PeerID's id as a hex string.
PeerID.hexString:String

/// A base32 encoded, version 1 CID, representing this PeerID
PeerID.cidString:String

/// A simple way of checking a PeerID's type (id only, public key & id, or private key, public key and id)
PeerID.type:PeerType

/// Returns the id of this PeerID as bytes
PeerID.id:[UInt8] 

/// A short, loggable, description matching go-libp2p's `ShortString` (ex: <peer.ID 12*o7R3pq>)
PeerID.description:String


/// Methods
/// Returns a protocol-buffers encoded version of the id, public key and, if `includingPrivateKey` is set to `true`, the private key.
PeerID.marshal(includingPrivateKey:Bool = false) throws -> [UInt8] 

/// Exports our PeerID as a JSON object
PeerID.toJSON(includingPrivateKey:Bool = false) throws -> Data

/// Exports our PeerID as a JSON string
PeerID.toJSONString(includingPrivateKey:Bool = false) throws -> String?

/// Exports our PeerID as a PEM String
PeerID.exportKeyPair(as: PeerID.ExportType) throws -> String

/// Signing and Verifying
// Signs data using this PeerID's private key. This signature can then be verified by a remote peer using this PeerID's public key
PeerID.signature(for msg:Data) throws -> Data

// Using this PeerID's public key, this method checks to see if the signature data was in fact signed by this peer and is a valid signature for the expected data
PeerID.isValidSignature(_ signature:Data, for expectedData:Data) throws -> Bool 

/// Returns `true` if this PeerID was derived from the provided public key
PeerID.matches(publicKey: any CommonPublicKey) -> Bool

```

## Contributing

Contributions are welcomed! This code is very much a proof of concept. I can guarantee you there's a better / safer way to accomplish the same results. Any suggestions, improvements, or even just critiques, are welcome! 

Let's make this code better together! 🤝

## Credits

- [The JS PeerID implementation](https://github.com/libp2p/js-peer-id) 
- [PeerID Spec](https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md) 

## License

[MIT](LICENSE) © 2026 Breth Inc.
























