//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2025 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

import Foundation
import LibP2PCrypto
import Multibase

/// - MARK: Marshaled Imports and Exports
extension PeerID {
    /// Inits a `PeerID` from a marshaled `PeerID` string
    /// - Note: `base` can be left `nil` if the marshaledPeerID String is `Multibase` compliant (includes the multibase prefix) otherwise, you must specify the ecoded base of the string...
    public convenience init(marshaledPeerID: String, base: BaseEncoding? = nil) throws {
        let marshaledData: Data
        if let base = base {
            marshaledData = try BaseEncoding.decode(marshaledPeerID, as: base).data
        } else {
            marshaledData = try BaseEncoding.decode(marshaledPeerID).data
        }
        try self.init(marshaledPeerID: marshaledData)
    }

    /// Inits a `PeerID` from a marshaled `PeerID`
    public convenience init(marshaledPeerID data: Data) throws {
        // Attampt to instantiate a PeerIdProto with the raw, marshaled, data
        let protoPeerID = try PeerIdProto(contiguousBytes: data)

        //print(protoPeerID.id.asString(base: .base64))
        //print("Has PubKey: \(protoPeerID.hasPubKey)")
        //print(protoPeerID.pubKey.asString(base: .base64))
        //print("Has PrivKey: \(protoPeerID.hasPrivKey)")
        //print(protoPeerID.privKey.asString(base: .base64))

        // Enusre the Marshaled data included at least a public key (is this necessary, would we ever need to unmarshal an ID only?)
        guard protoPeerID.hasPubKey || protoPeerID.hasPrivKey else {
            throw NSError(domain: "No Public or Private Key Found in marshaled data", code: 0, userInfo: nil)
        }

        // If we have a private key, attempt to instantiate the PeerID via the private key, otherwise, try the public key...
        if protoPeerID.hasPrivKey {
            try self.init(marshaledPrivateKey: protoPeerID.privKey)
        } else if protoPeerID.hasPubKey {
            try self.init(marshaledPublicKey: protoPeerID.pubKey)
        } else {
            throw NSError(domain: "No Public or Private Key Found in marshaled data", code: 0, userInfo: nil)
        }
    }

    /// Inits a `PeerID` from a marshaled public key string
    public convenience init(marshaledPublicKey str: String, base: BaseEncoding) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: str, base: base))
    }

    /// Inits a `PeerID` from a marshaled public key
    public convenience init(marshaledPublicKey key: Data) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: key))
    }

    /// Inits a `PeerID` from a marshaled private key string
    public convenience init(marshaledPrivateKey str: String, base: BaseEncoding) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: str, base: base))
    }

    /// Inits a `PeerID` from a marshaled private key
    public convenience init(marshaledPrivateKey data: Data) throws {
        try self.init(keyPair: LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: data))
    }

    //    private static func computeDigest(pubKey:SecKey) throws -> [UInt8] {
    //        let bytes = try pubKey.rawRepresentation()
    //        return try self.computeDigest(rawPubKey: bytes)
    //    }
    //
    //    /// - Note: We need to marshal the raw public key before multihashing it....
    //    private static func computeDigest(rawPubKey bytes:Data) throws -> [UInt8] {
    //        let marshaled = try LibP2PCrypto.Keys.marshalPublicKey(raw: bytes, keyType: .RSA(bits: .B1024))
    //        //print(marshaled.asString(base: .base64Pad))
    //        if marshaled.count <= 42 {
    //            return try Multihash(raw: marshaled, hashedWith: .identity).value
    //        } else {
    //            //let mh = try Multihash(raw: bytes, hashedWith: .sha2_256)
    //            //print("Value: \(mh.value.asString(base: .base16))")
    //            //print("Hex: \(mh.hexString)")
    //            //print("Digest: \(mh.digest?.asString(base: .base16) ?? "NIL")")
    //            return try Multihash(raw: marshaled, hashedWith: .sha2_256).value //pubKey.hash()
    //        }
    //    }

    /// Returns a protocol-buffers encoded version of the id, public key and, if `includingPrivateKey` is set to `true`, the private key.
    public func marshal(includingPrivateKey: Bool = false) throws -> [UInt8] {
        var pid = PeerIdProto()
        pid.id = Data(self.id)
        pid.pubKey = try self.keyPair?.publicKey.marshal() ?? Data()
        if includingPrivateKey, let privKey = self.keyPair?.privateKey {
            pid.privKey = try privKey.marshal()
        }
        return try pid.serializedData().bytes
    }

    public func marshalPrivateKey() throws -> [UInt8] {
        guard let privKey = self.keyPair?.privateKey else {
            throw NSError(domain: "This PeerID doesn't have a Private Key to Marshal", code: 0, userInfo: nil)
        }
        return try privKey.marshal().bytes
    }

    public func marshalPublicKey() throws -> [UInt8] {
        guard let pubKey = self.keyPair?.publicKey else {
            throw NSError(domain: "This PeerID doesn't have a Public Key to Marshal", code: 0, userInfo: nil)
        }
        return try pubKey.marshal().bytes
    }
}
